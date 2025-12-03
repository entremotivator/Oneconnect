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
# Auth models & helpers (cPanel + 20i style)
# =========================================================

class AuthMethod:
    CPANEL = "cPanel UAPI (cpanel user:token)"
    TWENTYI_API = "20i Reseller API (Bearer token)"
    CUSTOM_BEARER = "Generic Bearer token"


def b64(s: str) -> str:
    """Base64-encode a UTF‑8 string."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def make_20i_bearer(api_key: str) -> str:
    """
    Build an Authorization: Bearer <base64> header for 20i.

    Per your example:
    - General API key: cbed8b5d17b3ed4fd
    - OAuth client key: cbd1f37b39f284148
    - Combined: cbed8b5d17b3ed4fd+cbd1f37b39f284148
    Header uses base64 of the relevant token.
    """
    return f"Bearer {b64(api_key)}"


def generate_strong_password(length: int = 16) -> str:
    """Generate a strong random password."""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(length))


def normalize_subdomain_name(name: str) -> str:
    """Normalize subdomain name into DNS-safe, cPanel-friendly form."""
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9-]", "-", name)
    name = re.sub(r"-{2,}", "-", name)
    name = name.strip("-")
    return name or "wp-site"


def update_wp_config(config_content: str, db_name: str, db_user: str, db_password: str) -> str:
    """Patch DB_NAME / DB_USER / DB_PASSWORD defines in wp-config.php text."""
    patterns = {
        "DB_NAME": r"(define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
        "DB_USER": r"(define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
        "DB_PASSWORD": r"(define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
    }
    replacements = {
        "DB_NAME": db_name,
        "DB_USER": db_user,
        "DB_PASSWORD": db_password,
    }

    new_content = config_content
    for const, pattern in patterns.items():
        val = replacements[const]
        new_content = re.sub(pattern, r"\g<1>" + val + r"\g<2>", new_content, flags=re.IGNORECASE)
    return new_content


# =========================================================
# API client abstractions (cPanel + 20i)
# =========================================================

class BaseHostingClient:
    """
    Abstract base for different hosting providers.
    Concrete implementations: cPanel, 20i.
    """

    def list_domains(self) -> Dict[str, Any]:
        raise NotImplementedError

    def get_document_root(self, domain: str, domains_data: Dict[str, Any]) -> Optional[str]:
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
        """Short label for UI."""
        raise NotImplementedError


class CPanelAPIClient(BaseHostingClient):
    """
    cPanel UAPI client for a single account.
    Uses Authorization: cpanel <user>:<token>
    """

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
        self.port = port
        self.base_url = f"https://{host}:{port}/execute"
        self.headers = {
            "Authorization": f"cpanel {user}:{token}",
            "Accept": "application/json",
        }
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    # -------- low-level request --------

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
                r = requests.get(
                    url,
                    headers=self.headers,
                    params=data,
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                )
            else:
                r = requests.post(
                    url,
                    headers=self.headers,
                    data=data,
                    files=files,
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                )
            r.raise_for_status()
            result = r.json()
            if result.get("status") == 0:
                msg = (result.get("errors") or ["Unknown cPanel API error"])[0]
                raise Exception(f"cPanel API error: {msg}")
            return result
        except Exception as e:
            raise Exception(f"cPanel request failed ({module}/{function}): {e}")

    # -------- meta --------

    def test_connection(self) -> bool:
        try:
            self.list_domains()
            return True
        except Exception:
            return False

    def describe(self) -> str:
        return f"cPanel @{self.host} ({self.user})"

    # -------- domain / docroot --------

    def list_domains(self) -> Dict[str, Any]:
        return self._request("DomainInfo", "list_domains")

    def get_document_root(self, domain: str, domains_data: Dict[str, Any]) -> Optional[str]:
        data = domains_data.get("data", {})
        keys = ["main_domains", "sub_domains", "addon_domains", "parked_domains", "domain"]
        items: List[Dict[str, Any]] = []
        for k in keys:
            if isinstance(data.get(k), list):
                items.extend(data[k])

        for d in items:
            if d.get("domain") == domain:
                return d.get("documentroot") or d.get("docroot")
        return None

    # -------- file ops --------

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

    # -------- DB ops --------

    def _full_name(self, short: str) -> str:
        short = short[:7]
        return f"{self.user}_{short}"

    def create_database(self, short_name: str) -> Tuple[str, Dict[str, Any]]:
        short_name = short_name[:7]
        res = self._request("Mysql", "create_database", method="POST", data={"name": short_name})
        return self._full_name(short_name), res

    def create_db_user(self, short_name: str, password: str) -> Tuple[str, Dict[str, Any]]:
        short_name = short_name[:7]
        res = self._request(
            "Mysql",
            "create_user",
            method="POST",
            data={"name": short_name, "password": password},
        )
        return self._full_name(short_name), res

    def set_db_privileges(self, full_db: str, full_user: str) -> Dict[str, Any]:
        data = {"database": full_db, "user": full_user, "privileges": "ALL"}
        return self._request("Mysql", "set_privileges_on_database", method="POST", data=data)


class TwentyIAPIClient(BaseHostingClient):
    """
    20i Reseller API client (simplified).

    - Auth: Authorization: Bearer <base64(api_key or combined_key)>
    - Base URL: https://api.20i.com/
    - For the UI, it plugs into same methods as cPanel, but implementations differ.
    """

    def __init__(self, api_key: str, base_url: str = "https://api.20i.com/") -> None:
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": make_20i_bearer(self.api_key),
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
        key_preview = self.api_key[:6] + "..." if self.api_key else "no-key"
        return f"20i API ({key_preview})"

    # Below are “adapter” methods so the main workflow can treat this like cPanel.
    # In a real app, you’d call the exact 20i endpoints for domains, hosting, etc.

    def list_domains(self) -> Dict[str, Any]:
        """
        Example adapter; you would map to:
        GET /domain or similar 20i endpoint.
        """
        # Placeholder structure: adapt to real 20i JSON shape.
        # For now, return empty; UI will handle lack of domains gracefully.
        return {"data": {"main_domains": [], "sub_domains": []}}

    def get_document_root(self, domain: str, domains_data: Dict[str, Any]) -> Optional[str]:
        # This depends entirely on how 20i exposes hosting docroots.
        return None

    def upload_file(self, target_dir: str, filename: str, content: bytes) -> Dict[str, Any]:
        raise NotImplementedError("File upload not wired for 20i demo client yet.")

    def extract_archive(self, file_path: str, target_dir: str) -> Dict[str, Any]:
        raise NotImplementedError("Archive extract not wired for 20i demo client yet.")

    def delete_file(self, file_path: str) -> Dict[str, Any]:
        raise NotImplementedError("Delete file not wired for 20i demo client yet.")

    def get_file_content(self, path: str) -> str:
        raise NotImplementedError("get_file_content not wired for 20i demo client yet.")

    def save_file_content(self, path: str, content: str) -> Dict[str, Any]:
        raise NotImplementedError("save_file_content not wired for 20i demo client yet.")

    def create_database(self, short_name: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError("DB creation not wired for 20i demo client yet.")

    def create_db_user(self, short_name: str, password: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError("DB user creation not wired for 20i demo client yet.")

    def set_db_privileges(self, full_db: str, full_user: str) -> Dict[str, Any]:
        raise NotImplementedError("DB privileges not wired for 20i demo client yet.")


# =========================================================
# Multi-account / multi-provider manager
# =========================================================

def init_session_state() -> None:
    defaults = {
        "accounts": {},          # name -> dict(meta, client)
        "active_account": None,  # account name (key)
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
        host = st.text_input("cPanel Host", key="cp_host")
        user = st.text_input("cPanel Username", key="cp_user")
        token = st.text_input("cPanel API Token", type="password", key="cp_token")
        col1, col2 = st.columns(2)
        with col1:
            verify_ssl = st.checkbox("Verify SSL", value=False, key="cp_verify_ssl")
        with col2:
            port = st.number_input("Port", min_value=1, max_value=65535, value=2083, key="cp_port")

        if st.button("Save cPanel Connection", key="btn_add_cpanel"):
            if not (host and user and token):
                st.warning("Host, user, and token are required.")
                return
            name = f"{user}@{host}"
            client = CPanelAPIClient(
                host=host,
                user=user,
                token=token,
                port=int(port),
                verify_ssl=verify_ssl,
            )
            st.session_state.accounts[name] = {
                "type": AuthMethod.CPANEL,
                "client": client,
                "domains_data": None,
                "connected": False,
            }
            st.session_state.active_account = name
            st.success(f"cPanel account '{name}' added.")


def add_20i_account_ui() -> None:
    st.subheader("➕ Add 20i Account / API Key")

    with st.expander("Add new 20i API connection"):
        general_key = st.text_input("General API key", key="twentyi_general")
        oauth_key = st.text_input("OAuth client key", key="twentyi_oauth")
        combined_example = ""
        if general_key and oauth_key:
            combined_example = general_key + "+" + oauth_key
        combined = st.text_input(
            "Combined key (general+oauth)",
            value=combined_example,
            help="Matches your panel format: general+oauth",
            key="twentyi_combined",
        )

        if st.button("Save 20i Connection", key="btn_add_20i"):
            if not combined:
                st.warning("Please provide the combined API key.")
                return
            name = f"20i:{combined[:8]}..."
            client = TwentyIAPIClient(api_key=combined)
            st.session_state.accounts[name] = {
                "type": AuthMethod.TWENTYI_API,
                "client": client,
                "domains_data": None,
                "connected": False,
            }
            st.session_state.active_account = name
            st.success(f"20i API account '{name}' added.")


def sidebar_accounts() -> None:
    st.header("Accounts")
    accounts = st.session_state.accounts

    if accounts:
        names = list(accounts.keys())
        current = st.selectbox("Active account", names, index=names.index(st.session_state.active_account) if st.session_state.active_account in names else 0)
        st.session_state.active_account = current
        meta = accounts[current]
        st.caption(f"Active: {meta['client'].describe()}")

        if st.button("Remove active account"):
            del st.session_state.accounts[current]
            st.session_state.active_account = None
            st.session_state.selected_domain = ""
            st.session_state.selected_path = ""
            st.session_state.db_details = {}
            st.warning(f"Removed account {current}")
            return

        st.session_state.debug_mode = st.checkbox(
            "Debug / dry-run mode",
            value=st.session_state.debug_mode,
            help="Simulate destructive actions where possible and show more logging.",
        )

        if st.button("Connect / Refresh domains"):
            client: BaseHostingClient = meta["client"]
            try:
                with st.spinner("Fetching domains for this account..."):
                    domains_data = client.list_domains()
                meta["domains_data"] = domains_data
                meta["connected"] = True
                st.success("Domains retrieved.")
            except Exception as e:
                meta["domains_data"] = None
                meta["connected"] = False
                st.error(f"Failed to list domains: {e}")
    else:
        st.info("No accounts configured yet. Add one below.")


# =========================================================
# Per-account restore flow (domain → upload → DB → restore)
# =========================================================

def select_target_location(client: BaseHostingClient, domains_data: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    st.subheader("1. 🌐 Select Target Location")

    data = domains_data.get("data", {})
    main_domains = data.get("main_domains", []) or []
    sub_domains = data.get("sub_domains", []) or []

    def to_names(items):
        if not items:
            return []
        if isinstance(items[0], str):
            return items
        return [x.get("domain") for x in items if x.get("domain")]

    main_names = to_names(main_domains)
    sub_names = to_names(sub_domains)
    all_domains = main_names + sub_names

    if not all_domains:
        st.error("No domains returned for this account.")
        return None, None

    choice = st.radio(
        "Where do you want to restore?",
        ["Existing Domain/Subdomain", "Create New Subdomain (cPanel only)"],
        key="restore_choice",
    )

    selected_domain = None
    path = None

    if choice == "Existing Domain/Subdomain":
        selected_domain = st.selectbox("Existing domain", all_domains, key="existing_domain")
        if selected_domain:
            path = client.get_document_root(selected_domain, domains_data)
            if path:
                st.info(f"Target docroot: `{path}`")
            else:
                st.warning("Could not determine document root; check hosting control panel.")

    else:
        if not isinstance(client, CPanelAPIClient):
            st.warning("Subdomain creation is currently implemented only for cPanel accounts.")
            return None, None

        col1, col2 = st.columns(2)
        with col1:
            raw = st.text_input("Subdomain name (e.g., staging)", key="new_sub")
        with col2:
            base = st.selectbox("Base domain", main_names, key="new_base_domain")

        normalized = normalize_subdomain_name(raw) if raw else ""
        if normalized:
            st.caption(f"Normalized: `{normalized}`")

        if st.button("Create subdomain"):
            if not (normalized and base):
                st.warning("Subdomain and base domain are required.")
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
                path = docroot
                st.success(f"Subdomain created: {selected_domain}")
                st.info(f"Target docroot: `{path}`")

    return selected_domain, path


def upload_backup_zip() -> Optional[BytesIO]:
    st.subheader("2. 📤 Upload WordPress .zip Backup")
    up = st.file_uploader("Upload ZIP backup", type=["zip"], key="zip_uploader")
    if not up:
        st.info("Waiting for ZIP file...")
        return None
    st.session_state.upload_filename = up.name
    buf = BytesIO(up.read())
    buf.seek(0)
    st.success(f"Loaded `{up.name}` into memory.")
    return buf


def configure_database(client: BaseHostingClient, selected_domain: Optional[str]) -> bool:
    st.subheader("3. 🗄️ Database Configuration")

    if not st.session_state.db_details:
        base = "wp_site"
        if selected_domain:
            base = selected_domain.split(".")[0].replace("-", "_")[:7] or "wp_site"
        st.session_state.db_details = {
            "db_short": base,
            "db_pass": generate_strong_password(),
            "created": False,
        }

    db_short = st.text_input(
        "Database/User short name (max 7 chars)",
        value=st.session_state.db_details["db_short"],
        max_chars=7,
    )
    db_pass = st.text_input(
        "Database user password",
        value=st.session_state.db_details["db_pass"],
        type="password",
    )

    st.session_state.db_details["db_short"] = db_short
    st.session_state.db_details["db_pass"] = db_pass

    if isinstance(client, CPanelAPIClient):
        full_db_name = client._full_name(db_short)  # type: ignore[attr-defined]
        full_db_user = client._full_name(db_short)  # type: ignore[attr-defined]
        st.markdown(
            f"**Full DB name:** `{full_db_name}`  \n"
            f"**Full DB user:** `{full_db_user}`"
        )
    else:
        full_db_name = db_short
        full_db_user = db_short
        st.info("DB naming for this provider is generic; customize as needed.")

    if st.button("Create DB + user") or st.session_state.db_details["created"]:
        if not st.session_state.db_details["created"]:
            try:
                if st.session_state.debug_mode:
                    st.info("[DRY RUN] Would create DB and DB user, then grant ALL privileges.")
                else:
                    full_db_name, _ = client.create_database(db_short)
                    full_db_user, _ = client.create_db_user(db_short, db_pass)
                    client.set_db_privileges(full_db_name, full_db_user)

                st.session_state.db_details.update(
                    {
                        "created": True,
                        "full_db_name": full_db_name,
                        "full_db_user": full_db_user,
                        "db_pass": db_pass,
                    }
                )
                st.success("Database and user are ready.")
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Database setup failed: {e}")
                return False
        else:
            st.success("Database and user already created.")

    return bool(st.session_state.db_details.get("created"))


def execute_restore(client: BaseHostingClient, buf: BytesIO) -> None:
    st.subheader("4. ⚙️ Execute Restoration")

    selected_domain = st.session_state.selected_domain
    selected_path = st.session_state.selected_path
    dbd = st.session_state.db_details
    debug = st.session_state.debug_mode
    name = st.session_state.upload_filename or "backup.zip"

    if not (selected_domain and selected_path and dbd.get("created")):
        st.warning("Complete previous steps (domain, upload, DB) first.")
        return

    progress = st.empty()

    if st.button("Start full restore", key="btn_restore"):
        try:
            # 4.1 upload
            progress.info(f"4.1 Uploading `{name}` to `{selected_path}`...")
            buf.seek(0)
            if debug:
                st.info(f"[DRY RUN] Would upload {name} to {selected_path}")
            else:
                client.upload_file(selected_path, name, buf.read())
            uploaded_path = f"{selected_path}/{name}"
            progress.success("4.1 Upload complete.")

            # 4.2 extract
            progress.info("4.2 Extracting archive...")
            if debug:
                st.info(f"[DRY RUN] Would extract {uploaded_path} into {selected_path}")
            else:
                client.extract_archive(uploaded_path, selected_path)
            progress.success("4.2 Extraction complete.")

            # 4.3 wp-config
            wp_path = f"{selected_path}/wp-config.php"
            progress.info(f"4.3 Updating `{wp_path}` with DB credentials...")
            if debug:
                st.info("[DRY RUN] Would read and patch wp-config.php.")
            else:
                cfg = client.get_file_content(wp_path)
                if not cfg:
                    raise Exception("wp-config.php not found or empty.")
                new_cfg = update_wp_config(
                    cfg,
                    dbd["full_db_name"],
                    dbd["full_db_user"],
                    dbd["db_pass"],
                )
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
                f"""
                ## 🎉 Restore finished for {selected_domain}

                1. Import your SQL dump into `{dbd["full_db_name"]}`.
                2. In `wp_options`, set `siteurl` and `home` to your final URL.
                3. Test frontend and wp-admin.
                """
            )
        except Exception as e:
            progress.error(f"❌ Restore failed: {e}")


# =========================================================
# Main Streamlit app
# =========================================================

def main() -> None:
    st.set_page_config(
        page_title="Multi-Account WordPress Restore (cPanel + 20i-style)",
        layout="wide",
        page_icon="🚀",
    )
    init_session_state()

    st.title("🚀 Multi-Account WordPress Restore")
    st.markdown(
        "Connect to multiple hosting backends (cPanel now, 20i-style auth wired for later) "
        "and run a guided WordPress restore from a ZIP backup."
    )
    st.markdown("---")

    # Sidebar: account manager
    with st.sidebar:
        sidebar_accounts()
        st.markdown("---")
        add_cpanel_account_ui()
        add_20i_account_ui()

    # Main workflow uses active account
    if not st.session_state.accounts or not st.session_state.active_account:
        st.info("Add and select an account on the left to start.")
        return

    meta = st.session_state.accounts[st.session_state.active_account]
    client: BaseHostingClient = meta["client"]

    if not meta.get("connected") or meta.get("domains_data") is None:
        st.warning("Connect / refresh domains for this account using the sidebar.")
        return

    # Step 1: select domain / docroot
    selected_domain, selected_path = select_target_location(client, meta["domains_data"])
    if not selected_path:
        st.warning("Select or create a valid target first.")
        return
    st.session_state.selected_domain = selected_domain
    st.session_state.selected_path = selected_path

    # Step 2: upload backup
    buf = upload_backup_zip()
    if not buf:
        return

    # Step 3: DB config
    if not configure_database(client, selected_domain):
        return

    # Step 4: restore
    execute_restore(client, buf)


if __name__ == "__main__":
    main()
