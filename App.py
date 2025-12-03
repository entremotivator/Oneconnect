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
# Auth & utility
# =========================================================

def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def make_20i_bearer(api_key: str) -> str:
    return f"Bearer {b64(api_key)}"


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
# Base client + implementations
# =========================================================

class BaseHostingClient:
    def list_domains(self) -> Dict[str, Any]:
        raise NotImplementedError

    def extract_domain_names(self, raw: Dict[str, Any]) -> List[str]:
        """
        Try several shapes to find domains and return flat list of domain names.
        Handles variations in cPanel UAPI DomainInfo::list_domains output.
        """
        names: List[str] = []

        # cPanel typical: { "data": { "main_domains": [...], "sub_domains": [...], ... } }
        data = raw.get("data")
        if isinstance(data, dict):
            for key in ["main_domains", "sub_domains", "addon_domains", "parked_domains", "domain"]:
                value = data.get(key)
                if isinstance(value, list):
                    # either list[str] or list[dict]
                    if value and isinstance(value[0], str):
                        names.extend(value)
                    elif value and isinstance(value[0], dict):
                        for item in value:
                            d = item.get("domain")
                            if isinstance(d, str):
                                names.append(d)

        # fallback: some APIs might just return {"domains": [...]} or similar
        for key in ["domains", "items"]:
            v = raw.get(key)
            if isinstance(v, list):
                if v and isinstance(v[0], str):
                    names.extend(v)
                elif v and isinstance(v[0], dict):
                    for item in v:
                        d = item.get("domain") or item.get("name")
                        if isinstance(d, str):
                            names.append(d)

        # dedupe
        return sorted(list({n for n in names if isinstance(n, str) and n.strip()}))

    def get_document_root(self, domain: str, raw: Dict[str, Any]) -> Optional[str]:
        raise NotImplementedError

    def upload_file(self, target_dir: str, filename: str, content: bytes) -> Dict[str, Any]:
        raise NotImplementedError

    def extract_archive(self, file_path: str, target_dir: str) -> Dict[str, Any]:
        raise NotImplementedError

    def delete_file(self, file_path: str) -> Dict[str, Any]:
        raise NotImplementedError

    def get_file_content(self, path: str) -> str:
        raise NotImplementedError

    def save_file_content(self, path: str, content: str) -> Dict[str, Any]:
        raise NotImplementedError

    def create_database(self, short_name: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError

    def create_db_user(self, short_name: str, password: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError

    def set_db_privileges(self, full_db: str, full_user: str) -> Dict[str, Any]:
        raise NotImplementedError

    def describe(self) -> str:
        raise NotImplementedError


class CPanelAPIClient(BaseHostingClient):
    def __init__(
        self,
        host: str,
        user: str,
        token: str,
        port: int = 2083,
        verify_ssl: bool = False,
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.user = user
        self.base_url = f"https://{host}:{port}/execute"
        self.headers = {
            "Authorization": f"cpanel {user}:{token}",
            "Accept": "application/json",
        }
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def _request(
        self,
        module: str,
        function: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/{module}/{function}"
        try:
            if method == "GET":
                r = requests.get(url, headers=self.headers, params=data, verify=self.verify_ssl, timeout=self.timeout)
            else:
                r = requests.post(url, headers=self.headers, data=data, files=files, verify=self.verify_ssl, timeout=self.timeout)
            r.raise_for_status()
            result = r.json()
            if result.get("status") == 0:
                msg = (result.get("errors") or ["Unknown cPanel error"])[0]
                raise Exception(msg)
            return result
        except Exception as e:
            raise Exception(f"cPanel request failed: {e}")

    def list_domains(self) -> Dict[str, Any]:
        return self._request("DomainInfo", "list_domains")

    def get_document_root(self, domain: str, raw: Dict[str, Any]) -> Optional[str]:
        data = raw.get("data", {})
        keys = ["main_domains", "sub_domains", "addon_domains", "parked_domains", "domain"]
        items: List[Dict[str, Any]] = []
        for k in keys:
            v = data.get(k)
            if isinstance(v, list):
                items.extend([x for x in v if isinstance(x, dict)])

        for entry in items:
            if entry.get("domain") == domain:
                return entry.get("documentroot") or entry.get("docroot")
        return None

    def upload_file(self, target_dir: str, filename: str, content: bytes) -> Dict[str, Any]:
        files = {"file-1": (filename, content)}
        data = {"dir": target_dir}
        return self._request("Fileman", "upload_files", method="POST", data=data, files=files)

    def extract_archive(self, file_path: str, target_dir: str) -> Dict[str, Any]:
        data = {"file": file_path, "dir": target_dir}
        return self._request("Fileman", "extract_archive", method="POST", data=data)

    def delete_file(self, file_path: str) -> Dict[str, Any]:
        data = {"path": file_path}
        return self._request("Fileman", "delete", method="POST", data=data)

    def get_file_content(self, path: str) -> str:
        data = {"path": path}
        res = self._request("Fileman", "get_file_content", method="GET", data=data)
        return res.get("data", {}).get("content", "") or ""

    def save_file_content(self, path: str, content: str) -> Dict[str, Any]:
        data = {"path": path, "content": content}
        return self._request("Fileman", "save_file_content", method="POST", data=data)

    def _full_name(self, short: str) -> str:
        short = short[:7]
        return f"{self.user}_{short}"

    def create_database(self, short_name: str) -> Tuple[str, Dict[str, Any]]:
        short_name = short_name[:7]
        res = self._request("Mysql", "create_database", method="POST", data={"name": short_name})
        return self._full_name(short_name), res

    def create_db_user(self, short_name: str, password: str) -> Tuple[str, Dict[str, Any]]:
        short_name = short_name[:7]
        res = self._request("Mysql", "create_user", method="POST", data={"name": short_name, "password": password})
        return self._full_name(short_name), res

    def set_db_privileges(self, full_db: str, full_user: str) -> Dict[str, Any]:
        data = {"database": full_db, "user": full_user, "privileges": "ALL"}
        return self._request("Mysql", "set_privileges_on_database", method="POST", data=data)

    def describe(self) -> str:
        return f"cPanel @{self.host} ({self.user})"


class TwentyIAPIClient(BaseHostingClient):
    """
    20i-style API client with Bearer base64(api_key).
    For now, only auth + “no domains” behavior are wired.
    """

    def __init__(self, combined_key: str, base_url: str = "https://api.20i.com/") -> None:
        self.api_key = combined_key.strip()
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": make_20i_bearer(self.api_key),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _request(self, path: str, method: str = "GET") -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            r = requests.request(method, url, headers=self.headers, timeout=30)
            r.raise_for_status()
            if not r.text:
                return {}
            return r.json()
        except Exception as e:
            raise Exception(f"20i API error ({method} {path}): {e}")

    def list_domains(self) -> Dict[str, Any]:
        # Placeholder; you will map to real 20i endpoints.
        # Return an empty structure but explain in UI.
        return {"data": {}}

    def get_document_root(self, domain: str, raw: Dict[str, Any]) -> Optional[str]:
        return None

    def upload_file(self, target_dir: str, filename: str, content: bytes) -> Dict[str, Any]:
        raise NotImplementedError("Implement 20i file upload here.")

    def extract_archive(self, file_path: str, target_dir: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement 20i archive extract here.")

    def delete_file(self, file_path: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement 20i delete file here.")

    def get_file_content(self, path: str) -> str:
        raise NotImplementedError("Implement 20i get_file_content here.")

    def save_file_content(self, path: str, content: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement 20i save_file_content here.")

    def create_database(self, short_name: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError("Implement 20i DB creation here.")

    def create_db_user(self, short_name: str, password: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError("Implement 20i DB user creation here.")

    def set_db_privileges(self, full_db: str, full_user: str) -> Dict[str, Any]:
        raise NotImplementedError("Implement 20i DB privileges here.")

    def describe(self) -> str:
        return f"20i API ({self.api_key[:8]}...)"


# =========================================================
# Session + account management
# =========================================================

def init_session_state() -> None:
    defaults = {
        "accounts": {},          # name -> {"client": BaseHostingClient, "domains_data": Dict, "connected": bool}
        "active_account": None,
        "debug_mode": False,
        "db_details": {},
        "selected_path": "",
        "selected_domain": "",
        "upload_filename": "",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def add_cpanel_account_ui() -> None:
    st.subheader("➕ Add cPanel Account")
    with st.expander("Add new cPanel connection"):
        host = st.text_input("cPanel host", key="cp_host")
        user = st.text_input("cPanel username", key="cp_user")
        token = st.text_input("cPanel API token", type="password", key="cp_token")
        verify_ssl = st.checkbox("Verify SSL", value=False, key="cp_verify_ssl")

        if st.button("Save cPanel account"):
            if not (host and user and token):
                st.warning("Host, user, and token are required.")
                return
            name = f"{user}@{host}"
            client = CPanelAPIClient(host=host, user=user, token=token, verify_ssl=verify_ssl)
            st.session_state.accounts[name] = {
                "client": client,
                "domains_data": None,
                "connected": False,
            }
            st.session_state.active_account = name
            st.success(f"Added cPanel account '{name}'.")


def add_20i_account_ui() -> None:
    st.subheader("➕ Add 20i API Account")
    with st.expander("Add new 20i connection"):
        general = st.text_input("General API key", key="twentyi_general")
        oauth = st.text_input("OAuth client key", key="twentyi_oauth")
        combined_default = f"{general}+{oauth}" if general and oauth else ""
        combined = st.text_input(
            "Combined API key (general+oauth)",
            value=combined_default,
            key="twentyi_combined",
            help="Matches the 'combined API key' format in 20i docs.",
        )
        if st.button("Save 20i account"):
            if not combined:
                st.warning("Please enter a combined API key.")
                return
            name = f"20i:{combined[:8]}..."
            client = TwentyIAPIClient(combined_key=combined)
            st.session_state.accounts[name] = {
                "client": client,
                "domains_data": None,
                "connected": False,
            }
            st.session_state.active_account = name
            st.success(f"Added 20i API account '{name}'.")


def sidebar_accounts() -> None:
    st.header("Accounts")
    if not st.session_state.accounts:
        st.info("No accounts configured yet.")
        return

    names = list(st.session_state.accounts.keys())
    active_default = 0
    if st.session_state.active_account in names:
        active_default = names.index(st.session_state.active_account)

    current = st.selectbox("Active account", names, index=active_default)
    st.session_state.active_account = current
    meta = st.session_state.accounts[current]
    client: BaseHostingClient = meta["client"]

    st.caption(client.describe())

    st.session_state.debug_mode = st.checkbox(
        "Debug / dry-run",
        value=st.session_state.debug_mode,
        help="Simulate destructive actions and show extra logging.",
    )

    if st.button("Connect / Refresh domains"):
        try:
            with st.spinner("Listing domains for this account..."):
                raw = client.list_domains()
            meta["domains_data"] = raw
            meta["connected"] = True
            st.success("Domains fetched.")
            # Show raw for debugging domain shape
            with st.expander("Raw domains JSON (debug)", expanded=False):
                st.json(raw)
        except Exception as e:
            meta["domains_data"] = None
            meta["connected"] = False
            st.error(f"Failed to load domains: {e}")


# =========================================================
# Restore workflow
# =========================================================

def step_select_target(client: BaseHostingClient, raw_domains: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    st.subheader("1. 🌐 Select Target Location")

    domain_names = client.extract_domain_names(raw_domains)
    if not domain_names:
        st.error(
            "No domains returned for this account. "
            "Check the domains JSON in the sidebar expander to see what the API is sending."
        )
        return None, None

    choice = st.radio(
        "Where should the WordPress site be restored?",
        ["Existing domain/subdomain", "Create new subdomain (cPanel only)"],
        key="choice_target",
    )

    selected_domain: Optional[str] = None
    docroot: Optional[str] = None

    if choice == "Existing domain/subdomain":
        selected_domain = st.selectbox("Select domain", domain_names, key="existing_domain")
        if selected_domain:
            docroot = client.get_document_root(selected_domain, raw_domains)
            if docroot:
                st.info(f"Document root for {selected_domain}: `{docroot}`")
            else:
                st.warning("No document root found. You may have to inspect the server structure manually.")

    else:
        if not isinstance(client, CPanelAPIClient):
            st.warning("Subdomain creation is currently supported only for cPanel accounts.")
            return None, None

        main_only = domain_names  # for simplicity assume all are allowed
        col1, col2 = st.columns(2)
        with col1:
            raw = st.text_input("Subdomain label (e.g. staging)", key="new_sub_label")
        with col2:
            base = st.selectbox("Base domain", main_only, key="base_domain")

        normalized = normalize_subdomain_name(raw) if raw else ""
        if normalized:
            st.caption(f"Normalized subdomain: `{normalized}`")

        if st.button("Create subdomain"):
            if not (normalized and base):
                st.warning("Subdomain and base domain required.")
            else:
                docroot = f"public_html/{normalized}"
                if st.session_state.debug_mode:
                    st.info(f"[DRY RUN] Would create {normalized}.{base} with docroot {docroot}")
                else:
                    try:
                        client.add_subdomain(normalized, base, docroot)  # type: ignore[attr-defined]
                    except Exception as e:
                        st.error(f"Failed to create subdomain: {e}")
                        return None, None
                selected_domain = f"{normalized}.{base}"
                st.success(f"Created subdomain {selected_domain}")
                st.info(f"Docroot: `{docroot}`")

    return selected_domain, docroot


def step_upload_zip() -> Optional[BytesIO]:
    st.subheader("2. 📤 Upload WordPress ZIP")
    up = st.file_uploader("Upload backup .zip", type=["zip"], key="zip_uploader")
    if not up:
        st.info("Waiting for a ZIP file...")
        return None
    st.session_state.upload_filename = up.name
    buf = BytesIO(up.read())
    buf.seek(0)
    st.success(f"Loaded `{up.name}` into memory.")
    return buf


def step_configure_db(client: BaseHostingClient, selected_domain: Optional[str]) -> bool:
    st.subheader("3. 🗄️ Database configuration")

    if not st.session_state.db_details:
        base = "wp_site"
        if selected_domain:
            base = selected_domain.split(".")[0].replace("-", "_")[:7] or "wp_site"
        st.session_state.db_details = {
            "short": base,
            "pass": generate_strong_password(),
            "created": False,
        }

    short = st.text_input("DB/user short name (max 7 chars)", value=st.session_state.db_details["short"], max_chars=7)
    pwd = st.text_input("DB user password", value=st.session_state.db_details["pass"], type="password")
    st.session_state.db_details["short"] = short
    st.session_state.db_details["pass"] = pwd

    if isinstance(client, CPanelAPIClient):
        full_db = client._full_name(short)  # type: ignore[attr-defined]
        full_user = client._full_name(short)  # type: ignore[attr-defined]
        st.markdown(f"**Will use DB:** `{full_db}`  \n**Will use user:** `{full_user}`")
    else:
        full_db, full_user = short, short
        st.info("Using generic DB/user names for this provider.")

    if st.button("Create DB and user") or st.session_state.db_details["created"]:
        if not st.session_state.db_details["created"]:
            try:
                if st.session_state.debug_mode:
                    st.info("[DRY RUN] Would create DB, user, and grant privileges.")
                else:
                    full_db, _ = client.create_database(short)
                    full_user, _ = client.create_db_user(short, pwd)
                    client.set_db_privileges(full_db, full_user)

                st.session_state.db_details.update(
                    {
                        "created": True,
                        "full_db": full_db,
                        "full_user": full_user,
                        "pass": pwd,
                    }
                )
                st.success("Database and user ready.")
                st.experimental_rerun()
            except Exception as e:
                st.error(f"DB setup failed: {e}")
                return False
        else:
            st.success("Database and user already created.")

    return bool(st.session_state.db_details.get("created"))


def step_execute_restore(client: BaseHostingClient, buf: BytesIO) -> None:
    st.subheader("4. ⚙️ Execute restoration")

    dom = st.session_state.selected_domain
    path = st.session_state.selected_path
    dbd = st.session_state.db_details
    debug = st.session_state.debug_mode
    name = st.session_state.upload_filename or "backup.zip"

    if not (dom and path and dbd.get("created")):
        st.warning("Complete previous steps first.")
        return

    progress = st.empty()

    if st.button("Start restore"):
        try:
            # 4.1 upload
            progress.info(f"4.1 Uploading `{name}` to `{path}`...")
            buf.seek(0)
            if debug:
                st.info(f"[DRY RUN] Would upload {name} to {path}")
            else:
                client.upload_file(path, name, buf.read())
            uploaded_path = f"{path}/{name}"
            progress.success("4.1 Upload complete.")

            # 4.2 extract
            progress.info("4.2 Extracting archive...")
            if debug:
                st.info(f"[DRY RUN] Would extract {uploaded_path} into {path}")
            else:
                client.extract_archive(uploaded_path, path)
            progress.success("4.2 Extraction complete.")

            # 4.3 wp-config
            wp_path = f"{path}/wp-config.php"
            progress.info(f"4.3 Updating `{wp_path}`...")
            if debug:
                st.info("[DRY RUN] Would read and patch wp-config.php.")
            else:
                cfg = client.get_file_content(wp_path)
                if not cfg:
                    raise Exception("wp-config.php missing or empty.")
                new_cfg = update_wp_config(cfg, dbd["full_db"], dbd["full_user"], dbd["pass"])
                client.save_file_content(wp_path, new_cfg)
            progress.success("4.3 wp-config.php updated.")

            # 4.4 cleanup
            progress.info("4.4 Cleaning up uploaded ZIP...")
            if debug:
                st.info(f"[DRY RUN] Would delete {uploaded_path}")
            else:
                client.delete_file(uploaded_path)
            progress.success("4.4 Cleanup complete.")

            st.balloons()
            st.success(
                f"🎉 Restore complete for {dom}\n\n"
                f"Import your SQL into `{dbd['full_db']}` and update `siteurl`/`home` in `wp_options`."
            )
        except Exception as e:
            progress.error(f"Restore failed: {e}")


# =========================================================
# Main app
# =========================================================

def main() -> None:
    st.set_page_config(
        page_title="Multi-Account WP Restore",
        layout="wide",
        page_icon="🚀",
    )
    init_session_state()

    st.title("🚀 Multi-Account WordPress Restore (cPanel + 20i auth format)")
    st.write(
        "Restore WordPress backups across multiple hosting accounts. "
        "Supports cPanel UAPI directly and accepts 20i-style Bearer auth for future extension."
    )
    st.markdown("---")

    with st.sidebar:
        sidebar_accounts()
        st.markdown("---")
        add_cpanel_account_ui()
        add_20i_account_ui()

    if not st.session_state.accounts or not st.session_state.active_account:
        st.info("Add and select an account from the sidebar.")
        return

    meta = st.session_state.accounts[st.session_state.active_account]
    client: BaseHostingClient = meta["client"]

    if not meta.get("connected") or meta.get("domains_data") is None:
        st.warning("Click 'Connect / Refresh domains' in the sidebar for the active account.")
        return

    raw_domains = meta["domains_data"]

    # Step 1
    selected_domain, docroot = step_select_target(client, raw_domains)
    if not docroot:
        st.warning("Select or create a valid target first.")
        return
    st.session_state.selected_domain = selected_domain
    st.session_state.selected_path = docroot

    # Step 2
    buf = step_upload_zip()
    if not buf:
        return

    # Step 3
    if not step_configure_db(client, selected_domain):
        return

    # Step 4
    step_execute_restore(client, buf)


if __name__ == "__main__":
    main()
