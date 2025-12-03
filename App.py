import streamlit as st
import requests
import json
import os
import re
import random
import string
from io import BytesIO
from typing import Dict, Any, Optional, List, Tuple

# =========================
# cPanel API Client
# =========================

class CPanelAPIClient:
    """
    Modular client for interacting with the cPanel UAPI (Universal API).

    Encapsulates connection details and exposes methods for:
    - domain and subdomain management
    - file upload / extraction / deletion
    - MySQL database and user operations
    """

    def __init__(
        self,
        host: str,
        user: str,
        token: str,
        port: int = 2083,
        verify_ssl: bool = False,
        timeout: int = 30,
    ):
        """
        Initialize the client with cPanel connection details.

        Args:
            host: cPanel hostname or IP.
            user: cPanel username.
            token: cPanel API token (UAPI).
            port: cPanel port, usually 2083.
            verify_ssl: Whether to verify SSL certificates.
            timeout: Request timeout in seconds.
        """
        self.base_url = f"https://{host}:{port}/execute"
        self.headers = {
            "Authorization": f"cpanel {user}:{token}",
            "Accept": "application/json",
        }
        self.verify_ssl = verify_ssl
        self.user = user
        self.host = host
        self.timeout = timeout

    # ---- Internal HTTP helper ----

    def _request(
        self,
        module: str,
        function: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Internal method to handle all API requests and error parsing.
        """
        url = f"{self.base_url}/{module}/{function}"

        try:
            if method == "GET":
                response = requests.get(
                    url,
                    headers=self.headers,
                    params=data,
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                )
            elif method == "POST":
                response = requests.post(
                    url,
                    headers=self.headers,
                    data=data,
                    files=files,
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()

            result = response.json()

            # cPanel UAPI status check
            if result.get("status") == 0:
                error_message = (result.get("errors") or ["Unknown cPanel API error"])[0]
                raise Exception(f"cPanel API Error: {error_message}")

            return result

        except requests.exceptions.HTTPError as e:
            try:
                error_details = e.response.json()
                error_message = (error_details.get("errors") or [str(e)])[0]
            except (json.JSONDecodeError, AttributeError):
                status = e.response.status_code if e.response is not None else "?"
                text_preview = e.response.text[:200] if e.response is not None else ""
                error_message = f"HTTP Error {status}: {text_preview}..."
            raise Exception(f"Connection Error: {error_message}") from e

        except requests.exceptions.RequestException as e:
            raise Exception(
                f"Network Error: Could not connect to {self.host}. Details: {e}"
            ) from e

        except Exception as e:
            # Let higher-level code handle it
            raise e

    # ---- General helpers ----

    def test_connection(self) -> bool:
        """
        Tests the connection by listing domains.

        Returns:
            True if connection and auth are valid, False otherwise.
        """
        try:
            self.list_domains()
            return True
        except Exception:
            return False

    def get_host(self) -> str:
        """Return cPanel host."""
        return self.host

    def get_cpanel_user(self) -> str:
        """Return the cPanel username."""
        return self.user

    # ---- Domain operations ----

    def list_domains(self) -> Dict[str, Any]:
        """Fetch a list of all domains and subdomains."""
        return self._request("DomainInfo", "list_domains")

    def add_subdomain(self, subdomain: str, rootdomain: str, docroot: str) -> Dict[str, Any]:
        """Create a new subdomain."""
        data = {
            "domain": subdomain,
            "rootdomain": rootdomain,
            "dir": docroot,
        }
        return self._request("SubDomain", "addsubdomain", method="POST", data=data)

    def get_document_root(self, domain: str, domains_data: Dict[str, Any]) -> Optional[str]:
        """
        Find the document root for a given domain from the list_domains response.

        Args:
            domain: The domain name.
            domains_data: Raw output of DomainInfo::list_domains.

        Returns:
            Document root path or None.
        """
        # cPanel list_domains data shape can vary, so be defensive
        data = domains_data.get("data", {})

        # main_domains and sub_domains are often separate
        domain_items: List[Dict[str, Any]] = []
        for key in ["main_domains", "sub_domains", "addon_domains", "parked_domains", "domain"]:
            if isinstance(data.get(key), list):
                domain_items.extend(data.get(key, []))

        for d in domain_items:
            if d.get("domain") == domain:
                # common key names:
                if "documentroot" in d:
                    return d["documentroot"]
                if "docroot" in d:
                    return d["docroot"]

        return None

    # ---- File operations ----

    def upload_file(self, target_dir: str, filename: str, file_content: bytes) -> Dict[str, Any]:
        """Upload a file to the specified directory."""
        files = {
            "file-1": (filename, file_content),
        }
        data = {
            "dir": target_dir,
        }
        return self._request("Fileman", "upload_files", method="POST", data=data, files=files)

    def extract_archive(self, file_path: str, target_dir: str) -> Dict[str, Any]:
        """Extract a compressed archive file."""
        data = {
            "file": file_path,
            "dir": target_dir,
        }
        return self._request("Fileman", "extract_archive", method="POST", data=data)

    def delete_file(self, file_path: str) -> Dict[str, Any]:
        """Delete a file or directory."""
        data = {
            "path": file_path,
        }
        return self._request("Fileman", "delete", method="POST", data=data)

    def get_file_content(self, file_path: str) -> str:
        """Read the content of a file on the server."""
        data = {"path": file_path}
        response = self._request("Fileman", "get_file_content", method="GET", data=data)
        return response.get("data", {}).get("content", "")

    def save_file_content(self, file_path: str, content: str) -> Dict[str, Any]:
        """Write content to a file on the server."""
        data = {
            "path": file_path,
            "content": content,
        }
        return self._request("Fileman", "save_file_content", method="POST", data=data)

    # ---- Database operations ----

    def create_database(self, db_name: str) -> Dict[str, Any]:
        """Create a new MySQL database."""
        data = {"name": db_name}
        return self._request("Mysql", "create_database", method="POST", data=data)

    def create_user(self, user_name: str, password: str) -> Dict[str, Any]:
        """Create a new MySQL database user."""
        data = {"name": user_name, "password": password}
        return self._request("Mysql", "create_user", method="POST", data=data)

    def set_privileges(self, db_name: str, user_name: str, privileges: str = "ALL") -> Dict[str, Any]:
        """Grant privileges to a user on a database."""
        data = {
            "database": db_name,
            "user": user_name,
            "privileges": privileges,
        }
        return self._request("Mysql", "set_privileges_on_database", method="POST", data=data)

    # ---- Name helpers ----

    def get_full_db_name(self, short_name: str) -> str:
        """Return the full cPanel-prefixed database name."""
        short_name = short_name[:7]
        return f"{self.user}_{short_name}"

    def get_full_db_user(self, short_name: str) -> str:
        """Return the full cPanel-prefixed database user name."""
        short_name = short_name[:7]
        return f"{self.user}_{short_name}"


# =========================
# Utility functions
# =========================

def generate_strong_password(length: int = 16) -> str:
    """Generate a strong, random password."""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choice(characters) for _ in range(length))


def update_wp_config(config_content: str, db_name: str, db_user: str, db_password: str) -> str:
    """
    Update the DB_NAME, DB_USER, and DB_PASSWORD constants in wp-config.php content.
    """
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
    for constant, pattern in patterns.items():
        replacement_value = replacements[constant]
        new_content = re.sub(
            pattern,
            r"\g<1>" + replacement_value + r"\g<2>",
            new_content,
            flags=re.IGNORECASE,
        )

    return new_content


def validate_zip_filename(uploaded_file_name: str) -> bool:
    """Simple validation for uploaded ZIP file name."""
    return uploaded_file_name.lower().endswith(".zip")


def normalize_subdomain_name(name: str) -> str:
    """
    Normalize subdomain name to be DNS and cPanel friendly.
    """
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9-]", "-", name)
    name = re.sub(r"-{2,}", "-", name)
    return name.strip("-") or "wp-site"


# =========================
# Streamlit application
# =========================

def init_session_state():
    """Initialize Streamlit session state variables."""
    defaults = {
        "client": None,
        "connected": False,
        "domains_data": None,
        "selected_path": "",
        "selected_domain": "",
        "db_details": {},
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def sidebar_connection():
    """Render the cPanel connection section in the sidebar and handle connect logic."""
    with st.sidebar:
        st.header("🔐 cPanel Connection")
        cpanel_host = st.text_input("cPanel Host (e.g., myserver.com)", key="host")
        cpanel_user = st.text_input("cPanel Username", key="user")
        cpanel_token = st.text_input("cPanel API Token", type="password", key="token")

        col1, col2 = st.columns(2)
        with col1:
            verify_ssl = st.checkbox("Verify SSL", value=False, help="Enable if your certificate is valid.")

        with col2:
            timeout = st.number_input(
                "Timeout (sec)",
                min_value=5,
                max_value=120,
                value=30,
                step=5,
                help="Request timeout for API calls.",
            )

        if st.button("Connect & Fetch Domains", use_container_width=True):
            if cpanel_host and cpanel_user and cpanel_token:
                try:
                    client = CPanelAPIClient(
                        host=cpanel_host,
                        user=cpanel_user,
                        token=cpanel_token,
                        verify_ssl=verify_ssl,
                        timeout=int(timeout),
                    )

                    with st.spinner("Testing connection and fetching domains..."):
                        if not client.test_connection():
                            raise Exception("Unable to validate credentials or fetch domains.")

                        domains_data = client.list_domains()

                    st.session_state.client = client
                    st.session_state.connected = True
                    st.session_state.domains_data = domains_data
                    st.success("Connected to cPanel and fetched domain list ✔️")
                except Exception as e:
                    st.session_state.connected = False
                    st.session_state.domains_data = None
                    st.error(f"❌ Connection Failed: {e}")
            else:
                st.warning("Please fill in all connection details.")

        if st.session_state.connected and st.session_state.client:
            st.success(f"Status: Connected to {st.session_state.client.get_host()}")
        else:
            st.info("Enter your cPanel details above to begin.")


def select_target_location() -> Tuple[Optional[str], Optional[str]]:
    """
    Step 1: Domain / subdomain selection.

    Returns:
        (selected_domain, selected_path)
    """
    st.subheader("1. 🌐 Select Target Location")

    domains_data = st.session_state.domains_data or {}
    data = domains_data.get("data", {})

    main_domains = data.get("main_domains", []) or []
    subdomains = data.get("sub_domains", []) or []

    # cPanel often stores domain names as strings in those lists
    def extract_domain_names(items):
        if not items:
            return []
        # If list of strings
        if isinstance(items[0], str):
            return items
        # If list of dicts
        return [item.get("domain") for item in items if item.get("domain")]

    main_domain_names = extract_domain_names(main_domains)
    subdomain_names = extract_domain_names(subdomains)
    all_domains = main_domain_names + subdomain_names

    if not all_domains:
        st.error("No domains found in this cPanel account. Please check permissions.")
        return None, None

    choice = st.radio(
        "Choose where to restore:",
        ["Existing Domain/Subdomain", "Create New Subdomain"],
        key="domain_choice",
    )

    selected_domain = None
    selected_path = None

    if choice == "Existing Domain/Subdomain":
        selected_domain = st.selectbox("Select Existing Domain:", all_domains, key="existing_domain")
        if selected_domain:
            selected_path = st.session_state.client.get_document_root(selected_domain, domains_data)
            if selected_path:
                st.info(f"Target Directory: `{selected_path}`")
            else:
                st.warning("Could not auto-detect document root for that domain. Please verify in cPanel.")

    else:
        col1, col2 = st.columns(2)
        with col1:
            new_sub = st.text_input("Subdomain Name (e.g., staging)", key="new_sub_name")
        with col2:
            base_domain = st.selectbox("Select Base Domain:", main_domain_names, key="base_domain")

        normalized_sub = normalize_subdomain_name(new_sub) if new_sub else ""

        st.caption(f"Normalized subdomain: `{normalized_sub}`" if normalized_sub else "")

        if st.button("Create Subdomain", use_container_width=True):
            if normalized_sub and base_domain:
                try:
                    # You can customize docroot strategy here.
                    docroot = f"public_html/{normalized_sub}"

                    with st.spinner(f"Creating subdomain {normalized_sub}.{base_domain}..."):
                        st.session_state.client.add_subdomain(normalized_sub, base_domain, docroot)

                    selected_domain = f"{normalized_sub}.{base_domain}"
                    selected_path = docroot

                    st.session_state.selected_domain = selected_domain
                    st.session_state.selected_path = selected_path

                    st.success(f"Subdomain created: **{selected_domain}**")
                    st.info(f"Target Directory: `{selected_path}`")
                except Exception as e:
                    st.error(f"Failed to create subdomain: {e}")
            else:
                st.warning("Please enter a subdomain name and select a base domain.")

    if selected_domain and selected_path:
        st.session_state.selected_domain = selected_domain
        st.session_state.selected_path = selected_path

    return st.session_state.selected_domain, st.session_state.selected_path


def upload_backup_zip() -> Optional[BytesIO]:
    """
    Step 2: Upload WordPress ZIP file.

    Returns:
        BytesIO object with file contents or None.
    """
    st.subheader("2. 📤 Upload WordPress .zip File")
    uploaded_file = st.file_uploader(
        "Upload your WordPress backup (.zip)",
        type=["zip"],
        key="uploaded_file",
    )

    if not uploaded_file:
        st.info("Waiting for file upload...")
        return None

    if not validate_zip_filename(uploaded_file.name):
        st.error("Uploaded file must be a .zip archive.")
        return None

    file_buffer = BytesIO()
    uploaded_file.seek(0)
    file_buffer.write(uploaded_file.read())
    file_buffer.seek(0)

    st.success(f"File `{uploaded_file.name}` is ready for upload.")
    return file_buffer


def configure_database(selected_domain: Optional[str]) -> bool:
    """
    Step 3: Configure and create database + user.

    Returns:
        True if DB and user are created and stored in session_state, otherwise False.
    """
    st.subheader("3. 🗄️ Database Configuration")

    if not st.session_state.db_details:
        suggested_db_name = "wp_site"
        if selected_domain:
            suggested_db_name = selected_domain.split(".")[0].replace("-", "_")[:7] or "wp_site"

        st.session_state.db_details = {
            "db_short_name": suggested_db_name,
            "db_password": generate_strong_password(),
            "created": False,
        }

    db_short_name = st.text_input(
        "Database/User Short Name (Max 7 chars):",
        st.session_state.db_details["db_short_name"],
        max_chars=7,
    )
    db_password = st.text_input(
        "Database User Password:",
        st.session_state.db_details["db_password"],
        type="password",
        help="You can change this, but make sure to store it securely.",
    )

    st.session_state.db_details["db_short_name"] = db_short_name
    st.session_state.db_details["db_password"] = db_password

    client: CPanelAPIClient = st.session_state.client
    full_db_name = client.get_full_db_name(db_short_name)
    full_db_user = client.get_full_db_user(db_short_name)

    st.markdown(
        f"""
        **Full Database Name:** `{full_db_name}`  
        **Full Database User:** `{full_db_user}`
        """
    )

    if st.button("Create Database and User", use_container_width=True) or st.session_state.db_details["created"]:
        if not st.session_state.db_details["created"]:
            try:
                with st.spinner("Creating database and user..."):
                    client.create_database(db_short_name)
                    client.create_user(db_short_name, db_password)
                    client.set_privileges(full_db_name, full_db_user, "ALL")

                st.session_state.db_details.update(
                    {
                        "created": True,
                        "full_db_name": full_db_name,
                        "full_db_user": full_db_user,
                        "db_password": db_password,
                    }
                )
                st.success("Database and user are ready for restoration.")
                st.experimental_rerun()
            except Exception as e:
                st.error(f"Database setup failed: {e}")
                return False
        else:
            st.success("Database and user are ready for restoration.")

    return st.session_state.db_details.get("created", False)


def execute_restore(file_buffer: BytesIO):
    """
    Step 4: Full restore workflow:
    - Upload ZIP
    - Extract archive
    - Update wp-config.php
    - Delete ZIP
    """
    st.subheader("4. ⚙️ Execute Restoration")

    client: CPanelAPIClient = st.session_state.client
    selected_path: str = st.session_state.selected_path
    selected_domain: str = st.session_state.selected_domain
    db_details = st.session_state.db_details

    if not (client and selected_path and selected_domain and db_details.get("created")):
        st.warning("Please complete previous steps before starting restoration.")
        return

    uploaded_file_name = st.session_state.get("uploaded_file") or "wordpress_backup.zip"

    if st.button("Start Full Restore Process", key="start_restore", use_container_width=True):
        restore_placeholder = st.empty()

        try:
            # --- 4.1: Upload file ---
            restore_placeholder.info(
                f"4.1: Uploading file `{uploaded_file_name}` to `{selected_path}`..."
            )

            file_buffer.seek(0)
            client.upload_file(selected_path, uploaded_file_name, file_buffer.read())
            restore_placeholder.success("4.1: File uploaded successfully.")

            uploaded_file_path = f"{selected_path}/{uploaded_file_name}"

            # --- 4.2: Extract archive ---
            restore_placeholder.info(
                f"4.2: Extracting archive `{uploaded_file_name}`..."
            )
            client.extract_archive(uploaded_file_path, selected_path)
            restore_placeholder.success("4.2: Archive extracted successfully.")

            # --- 4.3: Update wp-config.php ---
            wp_config_path = f"{selected_path}/wp-config.php"
            restore_placeholder.info(
                f"4.3: Reading `{wp_config_path}` for configuration update..."
            )

            config_content = client.get_file_content(wp_config_path)
            if not config_content:
                raise Exception(
                    "wp-config.php not found or is empty. "
                    "Make sure your backup is a WordPress site at the root of the ZIP."
                )

            new_config_content = update_wp_config(
                config_content,
                db_details["full_db_name"],
                db_details["full_db_user"],
                db_details["db_password"],
            )
            client.save_file_content(wp_config_path, new_config_content)
            restore_placeholder.success(
                "4.3: `wp-config.php` updated with new database credentials."
            )

            # --- 4.4: Cleanup ---
            restore_placeholder.info(
                f"4.4: Cleaning up uploaded ZIP file `{uploaded_file_name}`..."
            )
            client.delete_file(uploaded_file_path)
            restore_placeholder.success("4.4: Cleanup complete. Original ZIP file deleted.")

            # --- Final success ---
            st.balloons()
            st.success(
                f"""
                ## 🎉 Restoration Complete!
                Your WordPress site has been successfully restored to **{selected_domain}**.

                **Next Steps:**
                1. Database Import: Manually import your SQL backup into the new database: `{db_details["full_db_name"]}`.
                2. Site URL Update: In `wp_options`, update `siteurl` and `home` to `{selected_domain}`.
                3. Login: Visit the site and log in to verify everything.
                """
            )

            st.markdown("### Database Credentials (Keep Secure!)")
            st.code(
                f"""
DB_NAME: {db_details["full_db_name"]}
DB_USER: {db_details["full_db_user"]}
DB_PASSWORD: {db_details["db_password"]}
                """,
                language="bash",
            )

        except Exception as e:
            restore_placeholder.error(f"❌ Restoration Failed at a critical step: {e}")
            st.error("Please review the error message and try again.")


def main():
    """Main function for the Streamlit application."""
    st.set_page_config(
        page_title="Advanced WordPress Restore for cPanel",
        layout="wide",
        page_icon="🚀",
    )

    init_session_state()

    st.title("🚀 Advanced WordPress Backup Restoration for cPanel")
    st.markdown("---")
    st.write(
        """
        Automate restoring a WordPress site from a ZIP backup to a cPanel hosting account.
        This tool handles file upload, extraction, database creation, and wp-config.php updates.
        """
    )

    # Sidebar: connection
    sidebar_connection()

    if not st.session_state.connected or not st.session_state.client:
        # Stop if not connected
        return

    # Step 1: domain selection
    selected_domain, selected_path = select_target_location()
    if not selected_path:
        st.warning("Please select or create a target domain/subdomain to proceed.")
        return

    # Step 2: file upload
    file_buffer = upload_backup_zip()
    if not file_buffer:
        return

    # Step 3: DB configuration
    db_ready = configure_database(selected_domain)
    if not db_ready:
        return

    # Step 4: restore
    execute_restore(file_buffer)


if __name__ == "__main__":
    main()
