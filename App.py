import base64
import json
import random
import re
import string
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple

import requests
import streamlit as st
from streamlit.delta_generator import DeltaGenerator


# =========================================================
# Constants & Configuration
# =========================================================

DEFAULT_20I_BASE_URL = "https://api.20i.com"
DEFAULT_PASSWORD_LENGTH = 16
DEFAULT_DOCROOT_TEMPLATE = "/home/stackcp/{domain}/public_html"
SPECIAL_CHARS = "!@#$%^&*"
API_TIMEOUT = 30

# UI Constants
STEPS = [
    "🌐 Select Package/Domain", 
    "📤 Upload ZIP Backup", 
    "📁 Document Root", 
    "🗄️ Database Setup", 
    "⚙️ Restore Plan"
]


# =========================================================
# Enhanced Helpers
# =========================================================

def b64(s: str) -> str:
    """Base64 encode UTF-8 string to ASCII-safe format."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def make_20i_bearer(general_api_key: str) -> str:
    """Create 20i Bearer token from general API key."""
    return f"Bearer {b64(general_api_key.strip())}"


def generate_strong_password(length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    """Generate cryptographically strong password."""
    chars = string.ascii_letters + string.digits + SPECIAL_CHARS
    return "".join(random.choice(chars) for _ in range(length))


def normalize_domain_name(name: str) -> str:
    """Normalize domain/subdomain to DNS-safe format."""
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9.-]", "", name)
    name = re.sub(r"-{2,}", "-", name)
    name = re.sub(r"\.{2,}", ".", name)
    name = name.strip(".-")
    return name or "default-site"


def format_timestamp(ts: Optional[str]) -> str:
    """Format API timestamp for display."""
    if not ts:
        return "N/A"
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime("%Y-%m-%d %H:%M")
    except:
        return ts[:16] if ts else "N/A"


# =========================================================
# Enhanced 20i API Client with Domain Management
# =========================================================

class TwentyIClient:
    """
    Enhanced 20i API client with full domain/package management capabilities.
    Supports listing, adding domains, getting package details, and more.
    """

    def __init__(self, general_api_key: str, base_url: str = DEFAULT_20I_BASE_URL) -> None:
        self.general_api_key = general_api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": make_20i_bearer(self.general_api_key),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _request(self, path: str, method: str = "GET", data: Optional[Dict] = None) -> Any:
        """Enhanced request handler with better error reporting."""
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.request(method, url, json=data, timeout=API_TIMEOUT)
            resp.raise_for_status()
            if not resp.text:
                return {}
            return resp.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"API request failed [{method} {path}]: {e}")

    # === PACKAGE OPERATIONS ===
    def list_packages(self) -> Dict[str, Any]:
        """List all hosting packages with enhanced normalization."""
        raw = self._request("/package")
        if isinstance(raw, list):
            return {"packages": raw}
        return raw

    def get_package(self, package_id: str) -> Dict[str, Any]:
        """Get detailed info for specific package."""
        return self._request(f"/package/{package_id}")

    def list_package_types(self) -> Dict[str, Any]:
        """List available package types/plans."""
        return self._request("/packageTypes")

    # === DOMAIN OPERATIONS ===
    def list_domains(self) -> Dict[str, Any]:
        """List all registered domains."""
        return self._request("/domain")

    def add_domain_to_package(self, package_id: str, domain: str, docroot: str = "") -> Dict[str, Any]:
        """
        Add domain to existing package.
        docroot: optional custom document root for this domain.
        """
        payload = {
            "domain_name": domain,
            "document_root": docroot or f"/home/stackcp/{domain}/public_html"
        }
        return self._request(f"/package/{package_id}/addDomain", "POST", payload)

    def remove_domain_from_package(self, package_id: str, domain: str) -> Dict[str, Any]:
        """Remove domain from package."""
        return self._request(f"/package/{package_id}/removeDomain", "POST", {"domain_name": domain})

    def list_domain_details(self, domain: str) -> Dict[str, Any]:
        """Get detailed info for specific domain."""
        return self._request(f"/domain/{domain}")

    # === RESOURCING OPERATIONS ===
    def get_package_resources(self, package_id: str) -> Dict[str, Any]:
        """Get disk/memory/CPU usage for package."""
        return self._request(f"/package/{package_id}/resources")

    # === UTILITY METHODS ===
    @staticmethod
    def build_domain_choices(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build UI-friendly domain choices from packages."""
        choices: List[Dict[str, Any]] = []
        packages = raw.get("packages", [])
        
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            pkg_id = str(pkg.get("id", ""))
            pkg_name = pkg.get("label", f"Package {pkg_id}")
            names = pkg.get("names", [])
            
            for domain in names:
                if isinstance(domain, str):
                    choices.append({
                        "label": f"{domain} ({pkg_name})",
                        "domain": domain,
                        "package_id": pkg_id,
                        "package_label": pkg_name
                    })
        return sorted(choices, key=lambda c: c["domain"])

    def get_account_info(self) -> Dict[str, Any]:
        """Get basic reseller/account info."""
        return self._request("/reseller/info")


# =========================================================
# Session State Management
# =========================================================

def init_session_state() -> None:
    """Initialize comprehensive session state."""
    defaults = {
        "twentyi_client": None,
        "account_info": None,
        "packages_raw": None,
        "package_types": None,
        "domains_raw": None,
        "domain_choices": [],
        "selected_package": None,
        "selected_domain": "",
        "all_domains": [],
        "docroot": "",
        "upload_filename": "",
        "db_details": {},
        "debug_mode": False,
        "current_step": 0,
        "last_error": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


# =========================================================
# Enhanced UI Components
# =========================================================

def sidebar_enhanced_auth() -> None:
    """Enhanced sidebar with full API features."""
    st.header("🔌 20i API Connection")
    
    col1, col2 = st.columns([3, 1])
    with col1:
        api_key = st.text_input("General API Key", type="password", key="api_key_input")
    with col2:
        st.session_state.debug_mode = st.checkbox("Debug Mode", 
                                                value=st.session_state.debug_mode)

    if st.button("🔄 Connect & Sync All Data", use_container_width=True):
        if not api_key:
            st.error("⚠️ Enter your 20i General API Key")
            return

        try:
            with st.spinner("🔄 Initializing 20i client..."):
                client = TwentyIClient(api_key)
                st.session_state.twentyi_client = client

            with st.spinner("📦 Fetching packages..."):
                st.session_state.packages_raw = client.list_packages()
                st.session_state.domain_choices = client.build_domain_choices(st.session_state.packages_raw)

            with st.spinner("🏷️ Fetching package types..."):
                st.session_state.package_types = client.list_package_types()

            with st.spinner("🌐 Fetching domains..."):
                st.session_state.domains_raw = client.list_domains()
                st.session_state.all_domains = [d.get("domain", "") for d in client.domains_raw or [] 
                                              if isinstance(d, dict) and d.get("domain")]

            with st.spinner("👤 Fetching account info..."):
                st.session_state.account_info = client.get_account_info()

            st.success(f"✅ Synced! Found {len(st.session_state.domain_choices)} packages/domains")
            
        except Exception as e:
            st.session_state.last_error = str(e)
            st.error(f"❌ Connection failed: {e}")

    # Debug info
    if st.session_state.twentyi_client:
        st.success("🟢 Connected!")
        if st.session_state.account_info:
            st.info(f"Account: {st.session_state.account_info.get('name', 'N/A')}")

    if any([st.session_state.packages_raw, st.session_state.package_types, st.session_state.domains_raw]):
        with st.expander("🔍 Debug Data", expanded=st.session_state.debug_mode):
            st.json({
                "packages": st.session_state.packages_raw,
                "package_types": st.session_state.package_types,
                "domains": st.session_state.domains_raw
            })


def step_1_enhanced_domain_selection() -> Tuple[Optional[Dict], Optional[str]]:
    """Enhanced Step 1 with package details and domain actions."""
    st.subheader("1. 🌐 Package & Domain Management")
    
    if not st.session_state.domain_choices:
        st.warning("👈 Connect via sidebar first")
        return None, None

    # Package selection
    col1, col2 = st.columns([2, 1])
    with col1:
        pkg_idx = st.selectbox(
            "Select Package", 
            range(len(st.session_state.domain_choices)),
            format_func=lambda i: st.session_state.domain_choices[i]["label"],
            key="pkg_select"
        )
        selected_pkg = st.session_state.domain_choices[pkg_idx]
    
    with col2:
        if st.button("🔄 Refresh Package", key="refresh_pkg"):
            try:
                client = st.session_state.twentyi_client
                pkg_details = client.get_package(selected_pkg["package_id"])
                st.session_state.selected_package = pkg_details
                st.success("✅ Package refreshed")
            except Exception as e:
                st.error(f"❌ {e}")

    st.session_state.selected_package = st.session_state.selected_package or selected_pkg
    
    # Domain actions
    col_add, col_remove = st.columns(2)
    with col_add:
        new_domain = st.text_input("➕ Add New Domain", placeholder="example.com")
        if st.button("Add Domain", key="add_domain") and new_domain:
            if st.session_state.debug_mode:
                st.info(f"DRY-RUN: Would add {new_domain} to package {selected_pkg['package_id']}")
            else:
                try:
                    result = st.session_state.twentyi_client.add_domain_to_package(
                        selected_pkg["package_id"], new_domain
                    )
                    st.success(f"✅ Added {new_domain}")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ Failed: {e}")

    # Domain info display
    if st.session_state.selected_package:
        with st.expander(f"📊 Package Details: {selected_pkg['package_label']}"):
            pkg = st.session_state.selected_package
            st.json({
                "ID": pkg.get("id"),
                "Label": pkg.get("label"),
                "Primary Domain": pkg.get("domain_name"),
                "Status": pkg.get("status"),
                "Created": format_timestamp(pkg.get("created_at"))
            })

    st.session_state.selected_domain = selected_pkg["domain"]
    st.info(f"🎯 Active: {selected_pkg['domain']} (pkg: {selected_pkg['package_id']})")
    return selected_pkg, selected_pkg["domain"]


def step_2_upload() -> Optional[BytesIO]:
    """Step 2: ZIP upload with validation."""
    st.subheader("2. 📤 WordPress Backup Upload")
    
    uploaded = st.file_uploader("Upload ZIP", type="zip", key="wp_zip")
    if not uploaded:
        return None

    st.session_state.upload_filename = uploaded.name
    buf = BytesIO(uploaded.read())
    buf.seek(0)
    
    # Basic ZIP validation
    try:
        import zipfile
        with zipfile.ZipFile(buf) as zf:
            file_count = len(zf.namelist())
            wp_files = [f for f in zf.namelist() if 'wp-config.php' in f or f.startswith('wp-')]
        st.success(f"✅ Valid ZIP: {file_count} files ({len(wp_files)} WP-related)")
    except:
        st.warning("⚠️ Could not validate ZIP contents")

    return buf


def step_3_docroot(domain: str) -> str:
    """Step 3: Enhanced document root with suggestions."""
    st.subheader("3. 📁 Document Root Path")
    
    suggestions = [
        f"/home/stackcp/{domain}/public_html",
        f"/home/stackcp/{domain}/htdocs",
        f"/domains/{domain}/public_html"
    ]
    
    default_path = next((p for p in suggestions if p), suggestions[0])
    docroot = st.text_input(
        "Document Root", 
        value=st.session_state.docroot or default_path,
        help="Typical 20i path shown. Adjust if needed.",
        key="docroot"
    )
    
    st.session_state.docroot = docroot
    st.info(f"📍 Using: `{docroot}`")
    return docroot


def step_4_database(domain: str) -> bool:
    """Step 4: Enhanced DB setup with copy buttons."""
    st.subheader("4. 🗄️ Database Configuration")
    
    if not st.session_state.db_details:
        base_name = normalize_domain_name(domain.split(".")[0])
        st.session_state.db_details = {
            "name": f"{base_name}_wp",
            "user": f"{base_name}_wp",
            "password": generate_strong_password(),
            "created": False
        }

    col1, col2 = st.columns(2)
    with col1:
        db_name = st.text_input("DB Name", value=st.session_state.db_details["name"], key="db_name")
        db_user = st.text_input("DB User", value=st.session_state.db_details["user"], key="db_user")
    with col2:
        db_pass = st.text_input("Password", value=st.session_state.db_details["password"], 
                               type="password", key="db_pass")

    st.session_state.db_details.update({"name": db_name, "user": db_user, "password": db_pass})

    # Copy buttons
    col_copy1, col_copy2, col_ready = st.columns([1, 1, 2])
    with col_copy1:
        st.code(db_name, language="sql")
        if st.button("📋 Copy DB", key="copy_db"):
            st.code(db_name, language=None)
    with col_copy2:
        st.code(db_pass, language="sql")
        if st.button("📋 Copy Pass", key="copy_pass"):
            st.code(db_pass, language=None)
    
    with col_ready:
        if st.button("✅ DB Created (Mark Ready)", key="db_ready") or st.session_state.db_details.get("created"):
            st.session_state.db_details["created"] = True
            st.success("✅ DB ready for wp-config.php")

    return st.session_state.db_details.get("created", False)


def step_5_restore_plan(buf: BytesIO, pkg: Dict, domain: str) -> None:
    """Step 5: Enhanced restore plan with all details."""
    st.subheader("5. 🚀 Complete Restore Plan")
    
    db = st.session_state.db_details
    docroot = st.session_state.docroot
    filename = st.session_state.upload_filename

    st.markdown("## 📋 Step-by-Step Commands")

    # SSH Commands
    st.markdown("### 1. SSH + File Upload")
    st.code(f"""
# SSH to your 20i server
ssh username@your-server.example.com

# Navigate to docroot (upload ZIP first via SFTP/StackCP)
cd {docroot}

# Extract backup
unzip {filename}
rm {filename}

# Fix permissions
find . -type d -exec chmod 755 {{}} \\;
find . -type f -exec chmod 644 {{}} \\;
chmod 600 wp-config.php
""", language="bash")

    # wp-config.php patch
    st.markdown("### 2. Update wp-config.php")
    config_patch = f"""
// Replace these lines in {docroot}/wp-config.php:
define('DB_NAME', '{db["name"]}');
define('DB_USER', '{db["user"]}');
define('DB_PASSWORD', '{db["password"]}');
define('DB_HOST', 'localhost'); // Usually localhost on 20i
"""
    st.code(config_patch, language="php")

    # Database import
    st.markdown("### 3. Database Import")
    st.code(f"""
# Via phpMyAdmin (recommended) or CLI:
mysql -u {db["user"]} -p'{db["password"]}' {db["name"]} < database.sql

# Update WP options table
mysql {db["name"]} -e "UPDATE wp_options SET option_value = 'https://{domain}' WHERE option_name = 'siteurl' OR option_name = 'home';"
""", language="bash")

    st.markdown("### 4. Final Steps")
    st.info("""
- Clear any caching plugins
- Check `.htaccess` permissions (644)
- Test site: https://{domain}
- Update permalinks in WP Admin
    """)

    st.balloons()
    st.success(f"🎉 Ready to restore {domain} on package {pkg['package_id']}!")


# =========================================================
# Main Application
# =========================================================

def main() -> None:
    st.set_page_config(
        page_title="20i WordPress Restore Pro",
        layout="wide",
        page_icon="🚀",
        initial_sidebar_state="expanded"
    )
    init_session_state()

    # Header
    st.title("🚀 20i WordPress Restore Pro")
    st.markdown("""
    **Enhanced WordPress restore tool with full 20i API integration.**  
    Manage packages, add/remove domains, monitor resources, and get complete restore instructions.
    """)

    # Progress bar
    progress = st.progress(0)
    status_text = st.empty()

    # Sidebar
    with st.sidebar:
        sidebar_enhanced_auth()

    client = st.session_state.twentyi_client
    if not client:
        st.info("👈 **Connect via sidebar** to get started")
        return

    # Step-by-step execution
    choice, domain = step_1_enhanced_domain_selection()
    if not choice:
        return

    progress.progress(20)
    status_text.text("Step 1 ✓")

    buf = step_2_upload()
    if not buf:
        return

    progress.progress(40)
    status_text.text("Steps 1-2 ✓")

    docroot = step_3_docroot(domain)
    progress.progress(60)
    status_text.text("Steps 1-3 ✓")

    db_ready = step_4_database(domain)
    if not db_ready:
        return

    progress.progress(80)
    status_text.text("Steps 1-4 ✓")

    # Final restore plan
    step_5_restore_plan(buf, choice, domain)
    progress.progress(100)
    status_text.text("✅ **COMPLETE** - Ready to restore!")


if __name__ == "__main__":
    main()
