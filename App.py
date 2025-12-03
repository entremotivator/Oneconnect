import base64
import random
import re
import string
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

import requests
import streamlit as st

# =========================================================
# Helpers
# =========================================================

def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def make_20i_bearer(general_api_key: str) -> str:
    """
    20i: Authorization: Bearer <base64(general_api_key)>
    """
    return f"Bearer {b64(general_api_key.strip())}"


def generate_strong_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(length))


def normalize_subdomain_name(name: str) -> str:
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9-]", "-", name)
    name = re.sub(r"-{2,}", "-", name)
    name = name.strip("-")
    return name or "wp-site"


def update_wp_config(config_content: str, db_name: str, db_user: str, db_password: str) -> str:
    """
    Replace DB_NAME / DB_USER / DB_PASSWORD in a wp-config.php text.
    """
    patterns = {
        "DB_NAME": r"(define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
        "DB_USER": r"(define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
        "DB_PASSWORD": r"(define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
    }
    repl = {"DB_NAME": db_name, "DB_USER": db_user, "DB_PASSWORD": db_password}
    new_content = config_content
    for const, pat in patterns.items():
        val = repl[const]
        new_content = re.sub(pat, r"\g<1>" + val + r"\g<2>", new_content, flags=re.IGNORECASE)
    return new_content


# =========================================================
# 20i Client – packages + simple list handling
# =========================================================

class TwentyIClient:
    """
    Minimal 20i API client focused on:
    - Auth with general API key
    - Listing packages and domains
    """

    def __init__(self, general_api_key: str, base_url: str = "https://api.20i.com") -> None:
        self.general_api_key = general_api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": make_20i_bearer(self.general_api_key),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request(self, path: str, method: str = "GET") -> Any:
        url = f"{self.base_url}{path}"
        r = requests.request(method, url, headers=self.headers, timeout=30)
        r.raise_for_status()
        if not r.text:
            return {}
        return r.json()

    def list_packages(self) -> Dict[str, Any]:
        """
        Normalise into {"packages": [...]} regardless of whether 20i
        returns a list or an object.
        """
        raw = self._request("/package", method="GET")
        if isinstance(raw, list):
            return {"packages": raw}
        return raw

    @staticmethod
    def build_domain_choices(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        From {"packages": [ {...}, ... ]} produce:
        [
          { "label": "aitocrm.com (pkg 2091638)", "domain": "aitocrm.com", "package_id": "2091638" },
          ...
        ]
        using your sample JSON structure.
        """
        choices: List[Dict[str, Any]] = []

        packages = raw.get("packages")
        if not isinstance(packages, list):
            return []

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue

            pkg_id = str(pkg.get("id", ""))
            names = pkg.get("names") or []
            if not isinstance(names, list):
                continue

            for d in names:
                if not isinstance(d, str):
                    continue
                label = f"{d} (pkg {pkg_id})"
                choices.append({"label": label, "domain": d, "package_id": pkg_id})

        choices.sort(key=lambda c: c["domain"])
        return choices


# =========================================================
# Session state
# =========================================================

def init_session_state() -> None:
    defaults = {
        "twentyi_client": None,
        "packages_raw": None,
        "domain_choices": [],
        "selected_choice": None,
        "selected_domain": "",
        "docroot": "",
        "upload_filename": "",
        "db_details": {},
        "debug_mode": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# =========================================================
# UI steps
# =========================================================

def sidebar_auth_and_packages() -> None:
    st.header("20i Connection")

    key = st.text_input(
        "20i General API key",
        type="password",
        help="Use the 'general API key' from your 20i account.",
        key="general_api_key",
    )

    st.session_state.debug_mode = st.checkbox(
        "Debug / dry-run mode",
        value=st.session_state.debug_mode,
        help="Shows more info and never calls destructive endpoints."
    )

    if st.button("Connect & List Packages", use_container_width=True):
        if not key:
            st.warning("Enter your 20i general API key.")
            return

        try:
            client = TwentyIClient(key)
            st.session_state.twentyi_client = client

            with st.spinner("Fetching packages from 20i..."):
                raw = client.list_packages()
            st.session_state.packages_raw = raw
            st.session_state.domain_choices = TwentyIClient.build_domain_choices(raw)

            if not st.session_state.domain_choices:
                st.error(
                    "Connected to 20i but no domains were extracted.\n"
                    "Check the raw JSON below and adjust build_domain_choices if necessary."
                )
            else:
                st.success(f"Found {len(st.session_state.domain_choices)} package/domain entries.")
        except Exception as e:
            st.error(f"20i connection failed: {e}")

    if st.session_state.packages_raw is not None:
        with st.expander("Raw 20i packages JSON (debug)", expanded=False):
            st.json(st.session_state.packages_raw)


def step_select_domain() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    st.subheader("1. 🌐 Select 20i Package / Domain")

    choices = st.session_state.domain_choices or []
    if not choices:
        st.warning("No domains available yet. Connect and list packages in the sidebar.")
        return None, None

    labels = [c["label"] for c in choices]
    idx = st.selectbox(
        "Select a WordPress package / domain",
        list(range(len(labels))),
        format_func=lambda i: labels[i],
        key="domain_choice_idx",
    )

    choice = choices[idx]
    domain = choice["domain"]

    st.session_state.selected_choice = choice
    st.session_state.selected_domain = domain

    st.info(f"Selected domain: `{domain}` (package ID {choice['package_id']})")
    return choice, domain


def step_upload_zip() -> Optional[BytesIO]:
    st.subheader("2. 📤 Upload WordPress ZIP Backup")

    up = st.file_uploader("Upload backup (.zip)", type=["zip"], key="zip_uploader")
    if not up:
        st.info("Waiting for a ZIP file...")
        return None

    st.session_state.upload_filename = up.name
    buf = BytesIO(up.read())
    buf.seek(0)

    st.success(f"Loaded `{up.name}` into memory.")
    return buf


def step_docroot_input(domain: str) -> str:
    st.subheader("3. 📁 Target Document Root")

    default_path = f"/home/stackcp/{domain}/public_html"
    docroot = st.text_input(
        "Document root path on 20i (where WordPress lives)",
        value=st.session_state.docroot or default_path,
        help="Adjust to the actual path if it differs.",
        key="docroot_input",
    )
    st.session_state.docroot = docroot
    st.info(f"Using docroot: `{docroot}`")
    return docroot


def step_configure_db(domain: str) -> bool:
    st.subheader("4. 🗄️ Database Credentials")

    if not st.session_state.db_details:
        base = domain.split(".")[0].replace("-", "_")[:7] or "wp_site"
        st.session_state.db_details = {
            "short": base,
            "pass": generate_strong_password(),
            "created": False,
        }

    short = st.text_input(
        "DB name / user (short identifier)",
        value=st.session_state.db_details["short"],
        help="You will create this DB and user manually in 20i / phpMyAdmin.",
        key="db_short",
    )
    pwd = st.text_input(
        "DB user password",
        value=st.session_state.db_details["pass"],
        type="password",
        key="db_pass",
    )

    st.session_state.db_details["short"] = short
    st.session_state.db_details["pass"] = pwd

    st.info(
        "Because 20i does not expose a simple DB UAPI in this example, "
        "this app will treat DB creation/import as manual steps and only "
        "track the credentials for injecting into wp-config.php."
    )

    if st.button("Mark DB as ready (manual creation done)", key="btn_db_ready"):
        st.session_state.db_details.update(
            {
                "created": True,
                "full_db": short,
                "full_user": short,
                "pass": pwd,
            }
        )
        st.success("Marked DB and user as ready.")
        return True

    return bool(st.session_state.db_details.get("created"))


def step_restore_plan(buf: BytesIO) -> None:
    st.subheader("5. ⚙️ Restore Plan / Commands")

    choice = st.session_state.selected_choice
    domain = st.session_state.selected_domain
    docroot = st.session_state.docroot
    dbd = st.session_state.db_details
    filename = st.session_state.upload_filename or "backup.zip"

    if not (choice and domain and docroot and dbd.get("created")):
        st.warning("Complete all previous steps first.")
        return

    pkg_id = choice["package_id"]

    st.info(
        "20i does not publish a generic file manager API like cPanel's Fileman. "
        "In practice, you will use SSH, SFTP, or the StackCP file manager. "
        "Below is a concrete sequence of shell commands you can run on the server "
        "once you have SSH access, plus the wp-config.php changes."
    )

    st.markdown("### Shell commands (example via SSH)")

    st.code(
        f"""
# 1. Upload backup.zip into {docroot}
#    - Use SFTP or the StackCP file manager to place {filename} there.

# 2. SSH into the 20i host and run:

cd {docroot}

# Extract the ZIP
unzip {filename}

# Remove the ZIP when done
rm {filename}

# 3. Edit wp-config.php (you can also do this via this app if you add a file-API layer)
#    Search for DB_NAME, DB_USER, DB_PASSWORD and change them to:

define('DB_NAME', '{dbd["full_db"]}');
define('DB_USER', '{dbd["full_user"]}');
define('DB_PASSWORD', '{dbd["pass"]}');

# 4. Import your SQL dump into the new DB (via phpMyAdmin or mysql CLI)
# Example CLI (if available):
# mysql -u {dbd["full_user"]} -p'{dbd["pass"]}' {dbd["full_db"]} < backup.sql
        """,
        language="bash",
    )

    st.markdown("### wp-config.php patch (for reference)")

    st.code(
        f"""
DB_NAME: {dbd["full_db"]}
DB_USER: {dbd["full_user"]}
DB_PASSWORD: {dbd["pass"]}
        """,
        language="bash",
    )

    st.success(
        f"Plan prepared for domain `{domain}` (package {pkg_id}) at docroot `{docroot}`.\n"
        "Once you run those commands and import the DB, update `siteurl` and `home` in `wp_options` to point to your domain."
    )


# =========================================================
# Main app
# =========================================================

def main() -> None:
    st.set_page_config(
        page_title="20i WordPress Restore Planner",
        layout="wide",
        page_icon="🚀",
    )
    init_session_state()

    st.title("🚀 20i WordPress Restore Planner")
    st.write(
        "Connect with your 20i general API key, pick a WordPress package/domain, "
        "upload a ZIP backup, define DB credentials, and get exact shell / config "
        "instructions to complete the restore."
    )
    st.markdown("---")

    with st.sidebar:
        sidebar_auth_and_packages()

    client: Optional[TwentyIClient] = st.session_state.twentyi_client
    if not client:
        st.info("Use the sidebar to enter your 20i general API key and fetch packages.")
        return

    if not st.session_state.domain_choices:
        st.warning("No domains extracted yet. Check the raw JSON in the sidebar.")
        return

    choice, domain = step_select_domain()
    if not choice:
        return

    buf = step_upload_zip()
    if not buf:
        return

    docroot = step_docroot_input(domain)
    if not docroot:
        return

    if not step_configure_db(domain):
        return

    step_restore_plan(buf)


if __name__ == "__main__":
    main()
