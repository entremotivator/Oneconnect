import streamlit as st
import requests
import json
import os
import re
import random
import string
from io import BytesIO
from typing import Dict, Any, Optional

# --- CPanelAPIClient Class (Modular and Robust) ---

class CPanelAPIClient:
    """
    A modular client for interacting with the cPanel UAPI (Universal API).
    Encapsulates connection details and provides methods for common operations.
    """

    def __init__(self, host: str, user: str, token: str, port: int = 2083, verify_ssl: bool = False):
        """
        Initializes the client with cPanel connection details.
        """
        self.base_url = f"https://{host}:{port}/execute"
        self.headers = {
            "Authorization": f"cpanel {user}:{token}",
            "Accept": "application/json"
        }
        self.verify_ssl = verify_ssl
        self.user = user
        self.host = host

    def _request(self, module: str, function: str, method: str = "GET", data: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Internal method to handle all API requests and error parsing.
        """
        url = f"{self.base_url}/{module}/{function}"
        
        try:
            if method == "GET":
                response = requests.get(url, headers=self.headers, params=data, verify=self.verify_ssl)
            elif method == "POST":
                response = requests.post(url, headers=self.headers, data=data, files=files, verify=self.verify_ssl)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            
            result = response.json()
            
            # Check for UAPI-specific errors
            if result.get("status") == 0:
                error_message = result.get("errors", ["Unknown cPanel API error"])[0]
                raise Exception(f"cPanel API Error: {error_message}")

            return result

        except requests.exceptions.HTTPError as e:
            try:
                error_details = e.response.json()
                error_message = error_details.get("errors", [str(e)])[0]
            except json.JSONDecodeError:
                error_message = f"HTTP Error {e.response.status_code}: {e.response.text[:100]}..."
            raise Exception(f"Connection Error: {error_message}")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Network Error: Could not connect to {self.host}. Details: {e}")
        except Exception as e:
            raise e

    def test_connection(self) -> bool:
        """Tests the connection by listing domains."""
        try:
            self.list_domains()
            return True
        except Exception:
            return False

    def list_domains(self) -> Dict[str, Any]:
        """Fetches a list of all domains and subdomains."""
        return self._request("DomainInfo", "list_domains")

    def add_subdomain(self, subdomain: str, rootdomain: str, docroot: str) -> Dict[str, Any]:
        """Creates a new subdomain."""
        data = {
            "domain": subdomain,
            "rootdomain": rootdomain,
            "dir": docroot
        }
        return self._request("SubDomain", "addsubdomain", method="POST", data=data)

    def upload_file(self, target_dir: str, filename: str, file_content: bytes) -> Dict[str, Any]:
        """Uploads a file to the specified directory."""
        files = {
            "file-1": (filename, file_content)
        }
        data = {
            "dir": target_dir
        }
        return self._request("Fileman", "upload_files", method="POST", data=data, files=files)

    def extract_archive(self, file_path: str, target_dir: str) -> Dict[str, Any]:
        """Extracts a compressed archive file."""
        data = {
            "file": file_path,
            "dir": target_dir
        }
        return self._request("Fileman", "extract_archive", method="POST", data=data)

    def delete_file(self, file_path: str) -> Dict[str, Any]:
        """Deletes a file or directory."""
        data = {
            "path": file_path
        }
        return self._request("Fileman", "delete", method="POST", data=data)

    def change_file_permissions(self, file_path: str, permissions: str) -> Dict[str, Any]:
        """Changes the permissions of a file or directory (e.g., '0644', '0755')."""
        data = {
            "path": file_path,
            "permissions": permissions
        }
        return self._request("Fileman", "chmod", method="POST", data=data)

    # --- SSL Operations (New Feature) ---

    def install_ssl_for_domain(self, domain: str) -> Dict[str, Any]:
        """
        Attempts to install an AutoSSL certificate for the given domain.
        Note: This typically triggers the AutoSSL process, which runs asynchronously.
        """
        data = {
            "domain": domain
        }
        # The function name might vary, but this is a common UAPI endpoint for AutoSSL
        return self._request("SSL", "install_autossl", method="POST", data=data)

    # --- Database Operations ---

    def create_database(self, db_name: str) -> Dict[str, Any]:
        """Creates a new MySQL database."""
        data = {"name": db_name}
        return self._request("Mysql", "create_database", method="POST", data=data)

    def create_user(self, user_name: str, password: str) -> Dict[str, Any]:
        """Creates a new MySQL database user."""
        data = {"name": user_name, "password": password}
        return self._request("Mysql", "create_user", method="POST", data=data)

    def set_privileges(self, db_name: str, user_name: str, privileges: str = "ALL") -> Dict[str, Any]:
        """Grants privileges to a user on a database."""
        data = {
            "database": db_name,
            "user": user_name,
            "privileges": privileges
        }
        return self._request("Mysql", "set_privileges_on_database", method="POST", data=data)

    # --- Email Operations (New Feature) ---

    def list_email_accounts(self, domain: str) -> Dict[str, Any]:
        """Lists all email accounts for a given domain."""
        data = {"domain": domain}
        return self._request("Email", "list_pops_for_domain", method="GET", data=data)

    def create_email_account(self, email: str, password: str, domain: str, quota: int = 0) -> Dict[str, Any]:
        """Creates a new email account."""
        data = {
            "email": email,
            "password": password,
            "domain": domain,
            "quota": quota
        }
        return self._request("Email", "add_pop", method="POST", data=data)

    def change_email_password(self, email: str, password: str, domain: str) -> Dict[str, Any]:
        """Changes the password for an existing email account."""
        data = {
            "email": email,
            "password": password,
            "domain": domain
        }
        return self._request("Email", "passwd_pop", method="POST", data=data)

    def get_file_content(self, file_path: str) -> str:
        """Reads the content of a file on the server."""
        data = {"path": file_path}
        response = self._request("Fileman", "get_file_content", method="GET", data=data)
        # Assuming the content is returned in the 'data' field of the response
        return response.get("data", {}).get("content", "")

    def save_file_content(self, file_path: str, content: str) -> Dict[str, Any]:
        """Writes content to a file on the server."""
        data = {
            "path": file_path,
            "content": content
        }
        return self._request("Fileman", "save_file_content", method="POST", data=data)

    def insert_content_into_file(self, file_path: str, content: str, marker: str) -> Dict[str, Any]:
        """
        Reads a file, inserts content before a marker, and saves the file.
        Common markers: </head>, </body>
        """
        original_content = self.get_file_content(file_path)
        if marker not in original_content:
            raise Exception(f"Marker '{marker}' not found in file: {file_path}")
        
        new_content = original_content.replace(marker, content + "\n" + marker)
        return self.save_file_content(file_path, new_content)

    # --- Utility Methods ---

    def get_document_root(self, domain: str, domains_data: Dict[str, Any]) -> Optional[str]:
        """
        Finds the document root for a given domain from the list_domains response.
        """
        for d in domains_data.get("data", {}).get("domain", []):
            if d.get("domain") == domain:
                return d.get("documentroot")
        return None

    def get_full_db_name(self, short_name: str) -> str:
        """Returns the full cPanel-prefixed database name."""
        # cPanel limits DB/User names to 7 characters after the prefix
        short_name = short_name[:7]
        return f"{self.user}_{short_name}"

    def get_full_db_user(self, short_name: str) -> str:
        """Returns the full cPanel-prefixed database user name."""
        short_name = short_name[:7]
        return f"{self.user}_{short_name}"

    def get_cpanel_user(self) -> str:
        """Returns the cPanel username."""
        return self.user

# --- Utility Functions ---

def generate_strong_password(length=16):
    """Generates a strong, random password."""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(random.choice(characters) for i in range(length))
    return password

def update_wp_config(config_content: str, db_name: str, db_user: str, db_password: str) -> str:
    """
    Updates the DB_NAME, DB_USER, and DB_PASSWORD constants in wp-config.php content.
    """
    # Regex pattern to find and replace the DB constants
    patterns = {
        "DB_NAME": r"(define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
        "DB_USER": r"(define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]).*?(['\"]\s*\);)",
        "DB_PASSWORD": r"(define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]).*?(['\"]\s*\);)"
    }

    replacements = {
        "DB_NAME": db_name,
        "DB_USER": db_user,
        "DB_PASSWORD": db_password
    }

    new_content = config_content
    for constant, pattern in patterns.items():
        replacement_value = replacements[constant]
        # Construct the replacement string: group 1 (prefix) + new value + group 2 (suffix)
        new_content = re.sub(pattern, r"\g<1>" + replacement_value + r"\g<2>", new_content, flags=re.IGNORECASE)
    
    return new_content

# --- Streamlit Application Logic ---

def main():
    """Main function for the Streamlit application."""
    st.set_page_config(page_title="Advanced WordPress Restore for cPanel", layout="wide")

    # Initialize session state variables
    if 'client' not in st.session_state:
        st.session_state.client = None
    if 'connected' not in st.session_state:
        st.session_state.connected = False
    if 'domains_data' not in st.session_state:
        st.session_state.domains_data = None
    if 'selected_path' not in st.session_state:
        st.session_state.selected_path = ""
    if 'db_details' not in st.session_state:
        st.session_state.db_details = {}

    st.title("🚀 Advanced WordPress Backup Restoration for cPanel")
    st.markdown("---")
    st.write("""
        This tool automates the complex process of restoring a WordPress site from a ZIP backup
        to a cPanel hosting environment. It handles file upload, extraction, database creation,
        and `wp-config.php` configuration updates.
    """)

    # -------------------------------
    # Sidebar Connection & Status
    # -------------------------------
    with st.sidebar:
        st.header("🔐 cPanel Connection")
        cpanel_host = st.text_input("cPanel Host (e.g., myserver.com)", key="host")
        cpanel_user = st.text_input("cPanel Username", key="user")
        cpanel_token = st.text_input("cPanel API Token", type="password", key="token")

        if st.button("Connect & Fetch Domains"):
            if cpanel_host and cpanel_user and cpanel_token:
                try:
                    client = CPanelAPIClient(cpanel_host, cpanel_user, cpanel_token)
                    domains_data = client.list_domains()
                    
                    st.session_state.client = client
                    st.session_state.connected = True
                    st.session_state.domains_data = domains_data
                    st.success("Connected to cPanel and fetched domain list ✔️")
                except Exception as e:
                    st.session_state.connected = False
                    st.error(f"❌ Connection Failed: {e}")
            else:
                st.warning("Please fill in all connection details.")

        if st.session_state.connected:
            st.success(f"Status: Connected to {st.session_state.client.get_host()}")
        else:
            st.info("Enter your cPanel details above to begin.")
            return # Stop execution if not connected

    # -------------------------------
    # Step 1: Domain Selection
    # -------------------------------
    st.subheader("1. 🌐 Select Target Location")
    
    domains_data = st.session_state.domains_data
    main_domains = domains_data.get("data", {}).get("main_domains", [])
    subdomains = domains_data.get("data", {}).get("sub_domains", [])
    all_domains = main_domains + subdomains

    existing_choice = st.radio(
        "Choose where to restore:", 
        ["Existing Domain/Subdomain", "Create New Subdomain"],
        key="domain_choice"
    )

    selected_domain = None
    
    if existing_choice == "Existing Domain/Subdomain":
        selected_domain = st.selectbox("Select Existing Domain:", all_domains, key="existing_domain")
        if selected_domain:
            st.session_state.selected_path = st.session_state.client.get_document_root(selected_domain, domains_data)
            st.info(f"Target Directory: `{st.session_state.selected_path}`")

    elif existing_choice == "Create New Subdomain":
        col1, col2 = st.columns(2)
        with col1:
            new_sub = st.text_input("Subdomain Name (e.g., staging)", key="new_sub_name")
        with col2:
            base_domain = st.selectbox("Select Base Domain:", main_domains, key="base_domain")

        if st.button("Create Subdomain"):
            if new_sub and base_domain:
                try:
                    docroot = f"public_html/{new_sub}"
                    with st.spinner(f"Creating subdomain {new_sub}.{base_domain}..."):
                        st.session_state.client.add_subdomain(new_sub, base_domain, docroot)
                    
                    st.success(f"Subdomain created: **{new_sub}.{base_domain}**")
                    st.session_state.selected_path = docroot
                    selected_domain = f"{new_sub}.{base_domain}"
                    st.info(f"Target Directory: `{st.session_state.selected_path}`")
                except Exception as e:
                    st.error(f"Failed to create subdomain: {e}")
            else:
                st.warning("Please enter a subdomain name and select a base domain.")

    if not st.session_state.selected_path:
        st.warning("Please select or create a target domain/subdomain to proceed.")
        return

    # -------------------------------
    # Step 2: File Upload
    # -------------------------------
    st.subheader("2. 📤 Upload WordPress .zip File")
    uploaded_file = st.file_uploader("Upload your WordPress backup (.zip)", type=["zip"], key="uploaded_file")

    if not uploaded_file:
        st.info("Waiting for file upload...")
        return

    # -------------------------------
    # Step 3: Database Setup
    # -------------------------------
    st.subheader("3. 🗄️ Database Configuration")
    
    if not st.session_state.db_details:
        # Suggest a DB name based on the subdomain
        suggested_db_name = selected_domain.split('.')[0].replace('-', '_') if selected_domain else "wp_restore"
        
        st.session_state.db_details = {
            "db_short_name": suggested_db_name,
            "db_password": generate_strong_password(),
            "created": False
        }

    db_short_name = st.text_input("Database/User Short Name (Max 7 chars):", st.session_state.db_details["db_short_name"], max_chars=7)
    db_password = st.text_input("Database User Password:", st.session_state.db_details["db_password"], type="password")
    
    st.session_state.db_details["db_short_name"] = db_short_name
    st.session_state.db_details["db_password"] = db_password

    full_db_name = st.session_state.client.get_full_db_name(db_short_name)
    full_db_user = st.session_state.client.get_full_db_user(db_short_name)

    st.markdown(f"""
        **Full Database Name:** `{full_db_name}`  
        **Full Database User:** `{full_db_user}`
    """)

    if st.button("Create Database and User") or st.session_state.db_details["created"]:
        if not st.session_state.db_details["created"]:
            try:
                with st.spinner("Creating database and user..."):
                    # 1. Create Database
                    st.session_state.client.create_database(db_short_name)
                    st.success(f"Database created: `{full_db_name}`")

                    # 2. Create User
                    st.session_state.client.create_user(db_short_name, db_password)
                    st.success(f"User created: `{full_db_user}`")

                    # 3. Grant Privileges
                    st.session_state.client.set_privileges(full_db_name, full_db_user, "ALL")
                    st.success(f"All privileges granted to `{full_db_user}` on `{full_db_name}`")

                    st.session_state.db_details["created"] = True
                    st.session_state.db_details["full_db_name"] = full_db_name
                    st.session_state.db_details["full_db_user"] = full_db_user
                    st.session_state.db_details["db_password"] = db_password
                    st.experimental_rerun() # Rerun to update UI state
            except Exception as e:
                st.error(f"Database setup failed: {e}")
                return
        else:
            st.success("Database and user are ready for restoration.")

    if not st.session_state.db_details.get("created"):
        return

    # -------------------------------
    # Step 4: Restore Files and Configure
    # -------------------------------
    st.subheader("4. ⚙️ Execute Restoration")
    
    if st.button("Start Full Restore Process", key="start_restore"):
        restore_placeholder = st.empty()
        
        try:
            # --- Sub-Step 4.1: Upload File ---
            restore_placeholder.info(f"4.1: Uploading file `{uploaded_file.name}` to `{st.session_state.selected_path}`...")
            
            # Reset file pointer to the beginning before reading
            uploaded_file.seek(0)
            file_content = uploaded_file.read()
            
            st.session_state.client.upload_file(
                st.session_state.selected_path, 
                uploaded_file.name, 
                file_content
            )
            restore_placeholder.success("4.1: File uploaded successfully.")
            
            uploaded_file_path = f"{st.session_state.selected_path}/{uploaded_file.name}"

            # --- Sub-Step 4.2: Extract Archive ---
            restore_placeholder.info(f"4.2: Extracting archive `{uploaded_file.name}`...")
            st.session_state.client.extract_archive(uploaded_file_path, st.session_state.selected_path)
            restore_placeholder.success("4.2: Archive extracted successfully.")

            # --- Sub-Step 4.3: Update wp-config.php ---
            wp_config_path = f"{st.session_state.selected_path}/wp-config.php"
            restore_placeholder.info(f"4.3: Reading `{wp_config_path}` for configuration update...")
            
            # Read current config
            config_content = st.session_state.client.get_file_content(wp_config_path)
            
            # Update content with new DB details
            new_config_content = update_wp_config(
                config_content,
                st.session_state.db_details["full_db_name"],
                st.session_state.db_details["full_db_user"],
                st.session_state.db_details["db_password"]
            )
            
            # Save updated config
            st.session_state.client.save_file_content(wp_config_path, new_config_content)
            restore_placeholder.success("4.3: `wp-config.php` updated with new database credentials.")

            # --- Sub-Step 4.4: Cleanup ---
            restore_placeholder.info(f"4.4: Cleaning up uploaded ZIP file `{uploaded_file.name}`...")
            st.session_state.client.delete_file(uploaded_file_path)
            restore_placeholder.success("4.4: Cleanup complete. Original ZIP file deleted.")

            # --- Final Success ---
            st.session_state.restore_complete = True
            st.experimental_rerun()

        except Exception as e:
            restore_placeholder.error(f"❌ Restoration Failed at a critical step: {e}")
            st.error("Please review the error message and try again.")
            return

    if st.session_state.get("restore_complete"):
        
        # -------------------------------
        # Step 5: Email Account Setup (New Feature)
        # -------------------------------
        st.subheader("5. 📧 Email Account Setup (Optional)")
        
        st.info("You can optionally create a new email account for this domain, e.g., for a new WordPress admin.")
        
        email_col, pass_col = st.columns(2)
        
        with email_col:
            email_user = st.text_input("New Email Username (e.g., admin)", key="new_email_user")
        
        with pass_col:
            email_pass = st.text_input("New Email Password", type="password", key="new_email_pass", value=generate_strong_password())
            
        if st.button(f"Create Email Account: {email_user}@{selected_domain}", key="create_email_btn"):
            if email_user and email_pass:
                try:
                    with st.spinner(f"Creating email account {email_user}@{selected_domain}..."):
                        st.session_state.client.create_email_account(
                            email=email_user,
                            password=email_pass,
                            domain=selected_domain.split('.', 1)[-1] # Use the main domain part
                        )
                    st.success(f"Email account **{email_user}@{selected_domain}** created successfully!")
                    st.markdown(f"**Password:** `{email_pass}` (Please save this securely)")
                except Exception as e:
                    st.error(f"Failed to create email account: {e}")
            else:
                st.warning("Please enter a username and password for the new email account.")

        # -------------------------------
        # Step 6: Marketing & SEO Setup (New Feature)
        # -------------------------------
        st.subheader("6. 📈 Marketing & SEO Setup (Optional)")
        
        ga_id = st.text_input("Google Analytics 4 Measurement ID (e.g., G-XXXXXXXXXX)", key="ga_id")
        
        if ga_id:
            # Construct the standard GA4 tracking code
            ga_script = f"""<!-- Google tag (gtag.js) -->
<script async src="https://www.googletagmanager.com/gtag/js?id={ga_id}"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){{dataLayer.push(arguments);}}
  gtag('js', new Date());
  gtag('config', '{ga_id}');
</script>"""
            
            # Default path for header.php in a common theme (e.g., twenty-twenty-three)
            # This is a best-effort attempt, as the theme name is unknown.
            default_header_path = f"{st.session_state.selected_path}/wp-content/themes/twentytwentythree/header.php"
            
            header_path = st.text_input(
                "Path to theme's header.php (Adjust if theme is different)", 
                value=default_header_path, 
                key="header_path"
            )
            
            if st.button("Inject GA Tracking Code", key="inject_ga_btn"):
                try:
                    with st.spinner(f"Injecting GA code into `{header_path}`..."):
                        # Attempt to insert the script before the closing </head> tag
                        st.session_state.client.insert_content_into_file(
                            file_path=header_path,
                            content=ga_script,
                            marker="</head>"
                        )
                    st.success(f"Google Analytics code ({ga_id}) successfully injected into `{header_path}`.")
                    st.info("Note: For best practice, consider using a dedicated WordPress plugin for tracking code management.")
                except Exception as e:
                    st.error(f"Failed to inject GA code: {e}")
                    st.warning("You may need to manually edit the file or use a plugin. Check the file path and theme name.")

        # -------------------------------
        # Step 7: Security & Optimization (New Feature)
        # -------------------------------
        st.subheader("7. 🔒 Security & Optimization (Optional)")

        # --- File Permissions ---
        st.markdown("#### File Permissions Check")
        st.info("WordPress best practice suggests specific permissions for security.")
        
        col_perm, col_path = st.columns(2)
        with col_perm:
            perm_files = st.selectbox("Select File Permission:", ["0644 (Files)", "0755 (Directories)"], key="perm_files")
        with col_path:
            perm_path = st.text_input("Path to apply permissions (e.g., public_html/wp-content)", value=f"{st.session_state.selected_path}/wp-content", key="perm_path")

        if st.button("Apply Permissions to Path", key="apply_perm_btn"):
            try:
                # Note: cPanel UAPI chmod only works on a single file/directory.
                # Applying recursively is complex and best left to a shell script or manual action.
                # We will apply to the single path provided.
                permission_code = perm_files.split(" ")[0]
                with st.spinner(f"Applying permission {permission_code} to `{perm_path}`..."):
                    st.session_state.client.change_file_permissions(
                        file_path=perm_path,
                        permissions=permission_code
                    )
                st.success(f"Permission **{permission_code}** applied to `{perm_path}`.")
                st.warning("For recursive changes, please use the cPanel File Manager or SSH.")
            except Exception as e:
                st.error(f"Failed to change permissions: {e}")

        # --- SSL Management ---
        st.markdown("#### SSL Certificate Management")
        st.info("Ensure your site is secure with HTTPS.")
        
        if st.button(f"Request AutoSSL for {selected_domain}", key="request_ssl_btn"):
            try:
                with st.spinner(f"Requesting AutoSSL for `{selected_domain}`..."):
                    st.session_state.client.install_ssl_for_domain(selected_domain)
                st.success(f"AutoSSL request submitted for **{selected_domain}**. Check cPanel for status.")
                st.warning("SSL issuance is an asynchronous process and may take a few minutes.")
            except Exception as e:
                st.error(f"Failed to request AutoSSL: {e}")

        # -------------------------------
        # Step 8: Final Marketing Summary
        # -------------------------------
        st.subheader("8. ✅ Final Restoration Summary")
        st.balloons()
        st.success(f"""
            ## 🎉 Restoration & Setup Complete!
            Your WordPress site has been successfully restored to **{selected_domain}**.
            
            **Next Steps for the Marketer:**
            1. **Database Import:** You must manually import your SQL backup file into the new database: `{full_db_name}`.
            2. **Site URL Update:** After import, update the `siteurl` and `home` options in the `wp_options` table to point to `{selected_domain}`.
            3. **Login:** Visit your new site and log in to verify.
            4. **SEO Check:** Verify `robots.txt` and search engine visibility settings in WordPress are correct.
            5. **Sitemap:** Submit your sitemap to Google Search Console.
            6. **Speed:** Run a Google PageSpeed Insights test to check performance.
        """)
        
        # Display DB details for manual import
        st.markdown("### Database Credentials (Keep Secure!)")
        st.code(f"""
            DB_NAME: {st.session_state.db_details["full_db_name"]}
            DB_USER: {st.session_state.db_details["full_db_user"]}
            DB_PASSWORD: {st.session_state.db_details["db_password"]}
        """)

if __name__ == "__main__":
    main()
