import base64
import json
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
    Per 20i docs, the Bearer token is base64 of the general API key.
    [web:29][web:33]
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
    patterns = {
        "DB_NAME": r"(define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
        "DB_USER": r"(define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
        "DB_PASSWORD": r"(define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
    }
    rep = {"DB_NAME": db_name, "DB_USER": db_user, "DB_PASSWORD": db_password}
    new_content = config_content
    for c, p in patterns.items():
        v = rep[c]
        new_content = re.sub(p, r"\g<1>" + v + r"\g<2>", new_content, flags=re.IGNORECASE)
    return new_content


# =========================================================
# Base client
# =========================================================

class BaseHostingClient:
    def list_sites(self) -> Dict[str, Any]:
        raise NotImplementedError

    def extract_site_choices(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Return list of choices: { label, domain, docroot, package_id }.
        """
        raise NotImplementedError

    def upload_file(self, target_dir: str, filename: str, content: bytes, package_id: Optional[str], domain: Optional[str]) -> Dict[str, Any]:
        raise NotImplementedError

    def extract_archive(self, file_path: str, target_dir: str, package_id: Optional[str], domain: Optional[str]) -> Dict[str, Any]:
        raise NotImplementedError

    def delete_file(self, file_path: str, package_id: Optional[str], domain: Optional[str]) -> Dict[str, Any]:
        raise NotImplementedError

    def get_file_content(self, path: str, package_id: Optional[str], domain: Optional[str]) -> str:
        raise NotImplementedError

    def save_file_content(self, path: str, content: str, package_id: Optional[str], domain: Optional[str]) -> Dict[str, Any]:
        raise NotImplementedError

    def create_database(self, short_name: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError

    def create_db_user(self, short_name: str, password: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError

    def set_db_privileges(self, full_db: str, full_user: str) -> Dict[str, Any]:
        raise NotImplementedError

    def describe(self) -> str:
        raise NotImplementedError


# =========================================================
# 20i client (real focus for you now)
# =========================================================

class TwentyIAPIClient(BaseHostingClient):
    """
    20i Reseller API client tuned for:
    - Bearer base64(general_api_key) auth [web:29][web:33]
    - Listing hosting packages and deriving domain+docroot from them [web:30]
    """

    def __init__(self, general_api_key: str, base_url: str = "https://api.20i.com") -> None:
        self.general_api_key = general_api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": make_20i_bearer(self.general_api_key),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request(
        self,
        path: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            if method == "GET":
                r = requests.get(url, headers=self.headers, params=params, timeout=30)
            else:
                r = requests.post(url, headers=self.headers, params=params, json=data, timeout=30)
            r.raise_for_status()
            if not r.text:
                return {}
            return r.json()
        except Exception as e:
            raise Exception(f"20i API error ({method} {path}): {e}")

    def describe(self) -> str:
        return f"20i API ({self.general_api_key[:8]}...)"

    # ---------- Hosting/package / domains ----------

    def list_sites(self) -> Dict[str, Any]:
        """
        Use 20i's hosting package / cloud hosting endpoints to list packages.
        Exact endpoint names can differ, but /package-like endpoints are shown
        in their docs as the main hosting concept. [web:29][web:30]
        """
        # Example: you may need /package or /reseller/{id}/packages; adjust to your console.
        return self._request("/package", method="GET")

    def extract_site_choices(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        From 20i JSON, derive list:
            [
              {"label": "...", "domain": "example.org", "docroot": "/path", "package_id": "123"},
              ...
            ]

        20i hosting packages include:
        - domain_name (primary domain)
        - extra_domain_names (aliases)
        - documentRoots: { "example.org": "/path" } [web:30]
        """
        choices: List[Dict[str, Any]] = []

        # Example shapes:
        # 1) { "result": [ { "id": "...", "domain_name": "...", "extra_domain_names": [...], "documentRoots": {...}, "label": "..." }, ... ] }
        # 2) { "packages": [ ... ] }
        packages = []
        if isinstance(raw.get("result"), list):
            packages = raw["result"]
        elif isinstance(raw.get("packages"), list):
            packages = raw["packages"]

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            pkg_id = str(pkg.get("id") or pkg.get("package_id") or "")
            domain_name = pkg.get("domain_name")
            extra = pkg.get("extra_domain_names") or []
            docroots = pkg.get("documentRoots") or {}
            label = pkg.get("label") or domain_name or pkg_id

            if not isinstance(docroots, dict):
                docroots = {}

            # Primary domain
            if isinstance(domain_name, str):
                docroot = docroots.get(domain_name)
                choices.append(
                    {
                        "label": f"{label} ({domain_name})",
                        "domain": domain_name,
                        "docroot": docroot or "",
                        "package_id": pkg_id,
                    }
                )

            # Extra domains as well
            if isinstance(extra, list):
                for d in extra:
                    if not isinstance(d, str):
                        continue
                    docroot = docroots.get(d)
                    choices.append(
                        {
                            "label": f"{label} ({d})",
                            "domain": d,
                            "docroot": docroot or "",
                            "package_id": pkg_id,
                        }
                    )

        return choices

    # ---------- File ops ----------
    # NOTE: 20i does not expose a generic Fileman like cPanel. The pattern is:
    # - Use browser dev tools on StackCP to capture API paths per package+domain [web:32]
    # - Then call those endpoints here (upload, extract, delete, etc.).

    def upload_file(self, target_dir: str, filename: str, content: bytes, package_id: Optional[str], domain: Optional[str]) -> Dict[str, Any]:
        raise NotImplementedError("Wire this to the specific 20i package file-upload endpoint you capture from StackCP. [web:32]")

    def extract_archive(self, file_path: str, target_dir: str, package_id: Optional[str], domain: Optional[str]) -> Dict[str, Any]:
        raise NotImplementedError("Wire this to the specific 20i archive extract endpoint for that package/domain. [web:32]")

    def delete_file(self, file_path: str, package_id: Optional[str], domain: Optional[str]) -> Dict[str, Any]:
        raise NotImplementedError("Wire this to the specific 20i file delete endpoint for that package/domain. [web:32]")

    def get_file_content(self, path: str, package_id: Optional[str], domain: Optional[str]) -> str:
        raise NotImplementedError("Wire this to the 20i API path that reads a file for a package/domain. [web:32]")

    def save_file_content(self, path: str, content: str, package_id: Optional[str], domain: Optional[str]) -> Dict[str, Any]:
        raise NotImplementedError("Wire this to the 20i API path that writes a file for a package/domain. [web:32]")

    # ---------- Database ops ----------
    # 20i has endpoints for provisioning hosting and related resources; DB endpoints
    # must be pulled from your 20i console in the same way (Network tab). [web:29][web:32]

    def create_database(self, short_name: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError("Implement DB creation by calling the appropriate 20i endpoint you capture. [web:29][web:32]")

    def create_db_user(self, short_name: str, password: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError("Implement DB user creation using the proper 20i endpoint. [web:29][web:32]")

    def set_db_privileges(self, full_db: str, full_user: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement DB privilege assignment using 20i endpoints. [web:29][web:32]")


# =========================================================
# Session + UI for 20i
# =========================================================

def init_session_state() -> None:
    defaults = {
        "twentyi_client": None,
        "twentyi_sites_raw": None,
        "twentyi_site_choices": [],
        "selected_site": None,
        "selected_domain": "",
        "selected_docroot": "",
        "upload_filename": "",
        "db_details": {},
        "debug_mode": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def sidebar_20i_auth() -> None:
    st.header("20i Authentication")

    general_api_key = st.text_input(
        "20i General API key",
        type="password",
        help="Use the general API key from your 20i Reseller API screen. It will be base64-encoded into a Bearer token. [web:29][web:33]",
        key="twentyi_general_key_input",
    )

    col1, col2 = st.columns(2)
    with col1:
        st.session_state.debug_mode = st.checkbox(
            "Debug / dry run", value=st.session_state.debug_mode, help="Simulate destructive actions where possible."
        )

    with col2:
        if st.button("Connect / List hosting packages"):
            if not general_api_key:
                st.warning("Please enter your 20i general API key.")
                return
            client = TwentyIAPIClient(general_api_key)
            st.session_state.twentyi_client = client

            try:
                with st.spinner("Listing hosting packages from 20i..."):
                    raw = client.list_sites()
                st.session_state.twentyi_sites_raw = raw
                choices = client.extract_site_choices(raw)
                st.session_state.twentyi_site_choices = choices
                if not choices:
                    st.error(
                        "Connected to 20i, but no hosting packages / domains could be derived.\n\n"
                        "Open your 20i API documentation or the API console to confirm the exact JSON shape for /package "
                        "and adjust extract_site_choices accordingly. [web:29][web:30][web:33]"
                    )
                else:
                    st.success(f"Found {len(choices)} domains/sites.")
            except Exception as e:
                st.error(f"20i connection failed: {e}")

    if st.session_state.twentyi_sites_raw:
        with st.expander("Raw 20i JSON (debug)", expanded=False):
            st.json(st.session_state.twentyi_sites_raw)


def step_select_target_twentyi() -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    st.subheader("1. 🌐 Select 20i Package / Domain")

    choices = st.session_state.twentyi_site_choices or []
    if not choices:
        st.warning("No 20i hosting packages/domains found yet. Use the sidebar to connect and fetch packages.")
        return None, None, None

    labels = [c["label"] for c in choices]
    idx = st.selectbox("Select hosting package / domain", list(range(len(labels))), format_func=lambda i: labels[i])
    choice = choices[idx]
    st.session_state.selected_site = choice
    domain = choice["domain"]
    docroot = choice["docroot"] or "/"

    st.info(f"Selected domain: `{domain}`\n\nDocument root (from 20i package): `{docroot}`")

    return choice, domain, docroot


def step_upload_zip() -> Optional[BytesIO]:
    st.subheader("2. 📤 Upload WordPress ZIP")

    up = st.file_uploader("Upload WordPress backup (.zip)", type=["zip"])
    if not up:
        st.info("Waiting for a ZIP file...")
        return None
    st.session_state.upload_filename = up.name
    buf = BytesIO(up.read())
    buf.seek(0)
    st.success(f"Loaded `{up.name}`.")
    return buf


def step_configure_db_twentyi(selected_domain: Optional[str]) -> bool:
    st.subheader("3. 🗄️ Database configuration (20i)")

    if not st.session_state.db_details:
        base = "wp_site"
        if selected_domain:
            base = selected_domain.split(".")[0].replace("-", "_")[:7] or "wp_site"
        st.session_state.db_details = {
            "short": base,
            "pass": generate_strong_password(),
            "created": False,
        }

    short = st.text_input("DB/user short name", value=st.session_state.db_details["short"], max_chars=32)
    pwd = st.text_input("DB user password", value=st.session_state.db_details["pass"], type="password")
    st.session_state.db_details["short"] = short
    st.session_state.db_details["pass"] = pwd

    st.info(
        "20i DB endpoints are not wired in this example. You need to capture the correct DB endpoints from the browser Network tab "
        "when creating DBs in StackCP and call them here. [web:29][web:32]"
    )

    if st.button("Mark DB as ready (manual)"):
        st.session_state.db_details.update(
            {
                "created": True,
                "full_db": short,
                "full_user": short,
                "pass": pwd,
            }
        )
        st.success("Flagged DB as ready (you will create/import it manually).")
        return True

    return bool(st.session_state.db_details.get("created"))


def step_execute_restore_twentyi(buf: BytesIO) -> None:
    st.subheader("4. ⚙️ Execute restoration (20i)")

    client: TwentyIAPIClient = st.session_state.twentyi_client
    site = st.session_state.selected_site
    dbd = st.session_state.db_details
    debug = st.session_state.debug_mode
    filename = st.session_state.upload_filename or "backup.zip"

    if not (client and site and dbd.get("created")):
        st.warning("Complete target selection, upload, and DB configuration first.")
        return

    domain = site["domain"]
    docroot = site["docroot"] or "/"
    package_id = site["package_id"]

    st.info(
        "The 20i API does not expose a generic Fileman-like interface. "
        "You must capture specific upload/extract/delete endpoints from StackCP (Network tab) "
        "and plug them into TwentyIAPIClient.upload_file / extract_archive / delete_file / get_file_content / save_file_content. [web:32]"
    )

    if st.button("Start restore (placeholder)"):
        st.warning(
            "This button is a placeholder for calling those 20i file/DB endpoints.\n\n"
            "Once you have the real endpoints, wire them into the TwentyIAPIClient methods and call them here."
        )

        # Pseudocode once endpoints are known:
        # 1. upload_file(docroot, filename, buf.read(), package_id, domain)
        # 2. extract_archive(path, docroot, package_id, domain)
        # 3. read wp-config.php, update DB creds via update_wp_config, save back
        # 4. delete_file(zip_path, package_id, domain)

        st.code(
            f"""
Planned steps for {domain} (package {package_id}):

1. Upload {filename} into {docroot}
2. Extract ZIP
3. Read and patch wp-config.php with:
   DB_NAME = {dbd['full_db']}
   DB_USER = {dbd['full_user']}
   DB_PASSWORD = {dbd['pass']}
4. Delete uploaded ZIP

Implement these by wiring 20i endpoints into TwentyIAPIClient.
            """,
            language="bash",
        )


# =========================================================
# Main app
# =========================================================

def main() -> None:
    st.set_page_config(
        page_title="20i WordPress Restore Helper",
        layout="wide",
        page_icon="🚀",
    )
    init_session_state()

    st.title("🚀 20i WordPress Restore Helper")
    st.write(
        "This version is focused on the 20i Reseller API. "
        "It uses Bearer base64(general API key) authentication and lists hosting packages/domains "
        "using their package API. File and DB actions are left as clearly marked hooks so you can "
        "paste in the real 20i endpoints captured from StackCP. [web:29][web:30][web:32][web:33]"
    )
    st.markdown("---")

    with st.sidebar:
        sidebar_20i_auth()

    client: Optional[TwentyIAPIClient] = st.session_state.twentyi_client
    if not client:
        st.info("Enter your 20i general API key and click 'Connect / List hosting packages' to begin.")
        return

    if not st.session_state.twentyi_site_choices:
        st.warning("No packages/domains yet. Check the raw JSON in the sidebar and adjust extract_site_choices if needed.")
        return

    # Step 1: choose package/domain
    choice, domain, docroot = step_select_target_twentyi()
    if not choice:
        return
    st.session_state.selected_domain = domain
    st.session_state.selected_docroot = docroot

    # Step 2: upload ZIP
    buf = step_upload_zip()
    if not buf:
        return

    # Step 3: DB config (manual for now)
    if not step_configure_db_twentyi(domain):
        return

    # Step 4: restore (placeholder until you wire concrete endpoints)
    step_execute_restore_twentyi(buf)


if __name__ == "__main__":
    main()
