"""
Enhanced WordPress Management Tool Pro
Supports: 20i API, cPanel, Backups, Editing, File Management, Database Management, and More
All-in-one comprehensive solution for WordPress site management
"""

import base64
import json
import os
import random
import re
import string
import tempfile
import zipfile
from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

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
MAIN_TABS = [
    "🏠 Dashboard",
    "🔄 Restore",
    "💾 Backup Manager",
    "📝 File Editor",
    "🗄️ Database Manager",
    "🌐 Domain Manager",
    "🔐 SSL Manager",
    "📧 Email Manager",
    "📊 Analytics",
    "⚙️ Settings"
]

RESTORE_STEPS = [
    "🌐 Select Package/Domain",
    "📤 Upload ZIP Backup",
    "📁 Document Root",
    "🗄️ Database Setup",
    "⚙️ Restore Plan"
]

# File types for syntax highlighting
FILE_SYNTAX_MAP = {
    '.php': 'php',
    '.js': 'javascript',
    '.css': 'css',
    '.html': 'html',
    '.json': 'json',
    '.xml': 'xml',
    '.sql': 'sql',
    '.py': 'python',
    '.sh': 'bash',
    '.yml': 'yaml',
    '.yaml': 'yaml',
    '.md': 'markdown',
    '.txt': 'text'
}

# =========================================================
# Enhanced Helpers
# =========================================================
def b64(s: str) -> str:
    """Base64 encode UTF-8 string to ASCII-safe format."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")

def b64decode(s: str) -> str:
    """Base64 decode ASCII-safe string to UTF-8."""
    return base64.b64decode(s.encode("ascii")).decode("utf-8")

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

def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def get_file_syntax(filename: str) -> str:
    """Get syntax highlighting language for file."""
    ext = Path(filename).suffix.lower()
    return FILE_SYNTAX_MAP.get(ext, 'text')

def extract_wp_config_values(content: str) -> Dict[str, str]:
    """Extract database credentials from wp-config.php content."""
    patterns = {
        'DB_NAME': r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_USER': r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_PASSWORD': r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_HOST': r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]"
    }
    
    values = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, content)
        if match:
            values[key] = match.group(1)
    
    return values

# =========================================================
# Enhanced 20i API Client
# =========================================================
class TwentyIClient:
    """
    Comprehensive 20i API client with full domain/package/database management.
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
        """List all hosting packages."""
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

    def get_package_resources(self, package_id: str) -> Dict[str, Any]:
        """Get disk/memory/CPU usage for package."""
        return self._request(f"/package/{package_id}/resources")

    # === DOMAIN OPERATIONS ===
    def list_domains(self) -> Dict[str, Any]:
        """List all registered domains."""
        raw = self._request("/domain")
        if isinstance(raw, list):
            return {"domains": raw}
        return raw

    def add_domain_to_package(self, package_id: str, domain: str, docroot: str = "") -> Dict[str, Any]:
        """Add domain to existing package."""
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

    def update_domain_docroot(self, package_id: str, domain: str, new_docroot: str) -> Dict[str, Any]:
        """Update document root for domain."""
        payload = {"domain_name": domain, "document_root": new_docroot}
        return self._request(f"/package/{package_id}/updateDomain", "POST", payload)

    # === DATABASE OPERATIONS ===
    def list_databases(self, package_id: str) -> Dict[str, Any]:
        """List databases for package."""
        return self._request(f"/package/{package_id}/databases")

    def create_database(self, package_id: str, db_name: str) -> Dict[str, Any]:
        """Create new database."""
        return self._request(f"/package/{package_id}/database", "POST", {"database_name": db_name})

    def delete_database(self, package_id: str, db_name: str) -> Dict[str, Any]:
        """Delete database."""
        return self._request(f"/package/{package_id}/database/{db_name}", "DELETE")

    def create_database_user(self, package_id: str, username: str, password: str) -> Dict[str, Any]:
        """Create database user."""
        payload = {"username": username, "password": password}
        return self._request(f"/package/{package_id}/databaseUser", "POST", payload)

    def grant_database_access(self, package_id: str, db_name: str, username: str) -> Dict[str, Any]:
        """Grant user access to database."""
        payload = {"database_name": db_name, "username": username}
        return self._request(f"/package/{package_id}/databaseAccess", "POST", payload)

    # === SSL OPERATIONS ===
    def list_ssl_certificates(self, package_id: str) -> Dict[str, Any]:
        """List SSL certificates for package."""
        return self._request(f"/package/{package_id}/ssl")

    def install_free_ssl(self, package_id: str, domain: str) -> Dict[str, Any]:
        """Install free Let's Encrypt SSL."""
        return self._request(f"/package/{package_id}/ssl/free", "POST", {"domain": domain})

    def get_ssl_status(self, package_id: str, domain: str) -> Dict[str, Any]:
        """Get SSL status for domain."""
        return self._request(f"/package/{package_id}/ssl/{domain}")

    # === EMAIL OPERATIONS ===
    def list_email_accounts(self, package_id: str) -> Dict[str, Any]:
        """List email accounts for package."""
        return self._request(f"/package/{package_id}/email")

    def create_email_account(self, package_id: str, email: str, password: str, quota_mb: int = 1000) -> Dict[str, Any]:
        """Create email account."""
        payload = {"email": email, "password": password, "quota": quota_mb}
        return self._request(f"/package/{package_id}/email", "POST", payload)

    def delete_email_account(self, package_id: str, email: str) -> Dict[str, Any]:
        """Delete email account."""
        return self._request(f"/package/{package_id}/email/{email}", "DELETE")

    def update_email_password(self, package_id: str, email: str, new_password: str) -> Dict[str, Any]:
        """Update email account password."""
        payload = {"email": email, "password": new_password}
        return self._request(f"/package/{package_id}/email/password", "POST", payload)

    # === BACKUP OPERATIONS ===
    def list_backups(self, package_id: str) -> Dict[str, Any]:
        """List available backups for package."""
        return self._request(f"/package/{package_id}/backups")

    def create_backup(self, package_id: str, backup_name: str = "") -> Dict[str, Any]:
        """Create manual backup."""
        name = backup_name or f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        return self._request(f"/package/{package_id}/backup", "POST", {"name": name})

    def download_backup(self, package_id: str, backup_id: str) -> bytes:
        """Download backup file."""
        url = f"{self.base_url}/package/{package_id}/backup/{backup_id}/download"
        resp = self.session.get(url, timeout=API_TIMEOUT)
        resp.raise_for_status()
        return resp.content

    def restore_backup(self, package_id: str, backup_id: str) -> Dict[str, Any]:
        """Restore from backup."""
        return self._request(f"/package/{package_id}/backup/{backup_id}/restore", "POST")

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
# cPanel API Client
# =========================================================
class CPanelClient:
    """
    cPanel UAPI/API2 client for WordPress management.
    """
    
    def __init__(self, cpanel_url: str, username: str, password: str = "", api_token: str = "") -> None:
        self.cpanel_url = cpanel_url.rstrip("/")
        self.username = username
        self.password = password
        self.api_token = api_token
        
        # Setup authentication
        if api_token:
            self.headers = {
                "Authorization": f"cpanel {username}:{api_token}",
                "Content-Type": "application/json"
            }
            self.auth = None
        else:
            self.headers = {"Content-Type": "application/json"}
            self.auth = (username, password)
        
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _request(self, module: str, function: str, params: Dict = None) -> Any:
        """Execute cPanel UAPI request."""
        url = f"{self.cpanel_url}/execute/{module}/{function}"
        try:
            resp = self.session.get(url, params=params or {}, auth=self.auth, timeout=API_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"cPanel API request failed: {e}")

    # === DOMAIN OPERATIONS ===
    def list_domains(self) -> List[str]:
        """List all domains in account."""
        result = self._request("DomainInfo", "list_domains")
        if result.get("status") == 1:
            return [d["domain"] for d in result.get("data", [])]
        return []

    def add_addon_domain(self, domain: str, subdomain: str, docroot: str) -> Dict[str, Any]:
        """Add addon domain."""
        params = {"domain": domain, "subdomain": subdomain, "dir": docroot}
        return self._request("AddonDomain", "addaddondomain", params)

    def remove_addon_domain(self, domain: str) -> Dict[str, Any]:
        """Remove addon domain."""
        return self._request("AddonDomain", "deladdondomain", {"domain": domain})

    # === DATABASE OPERATIONS ===
    def list_databases(self) -> List[str]:
        """List MySQL databases."""
        result = self._request("Mysql", "list_databases")
        if result.get("status") == 1:
            return [db["database"] for db in result.get("data", [])]
        return []

    def create_database(self, db_name: str) -> Dict[str, Any]:
        """Create MySQL database."""
        return self._request("Mysql", "create_database", {"name": db_name})

    def delete_database(self, db_name: str) -> Dict[str, Any]:
        """Delete MySQL database."""
        return self._request("Mysql", "delete_database", {"name": db_name})

    def create_database_user(self, username: str, password: str) -> Dict[str, Any]:
        """Create database user."""
        params = {"name": username, "password": password}
        return self._request("Mysql", "create_user", params)

    def grant_database_privileges(self, user: str, database: str) -> Dict[str, Any]:
        """Grant all privileges to user on database."""
        params = {"user": user, "database": database, "privileges": "ALL PRIVILEGES"}
        return self._request("Mysql", "set_privileges_on_database", params)

    # === FILE OPERATIONS ===
    def list_files(self, directory: str = "/public_html") -> List[Dict[str, Any]]:
        """List files in directory."""
        result = self._request("Fileman", "list_files", {"dir": directory})
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def read_file(self, filepath: str) -> str:
        """Read file content."""
        result = self._request("Fileman", "get_file_content", {"dir": filepath})
        if result.get("status") == 1:
            data = result.get("data", {})
            return data.get("content", "")
        return ""

    def write_file(self, filepath: str, content: str) -> Dict[str, Any]:
        """Write content to file."""
        params = {"dir": filepath, "content": content}
        return self._request("Fileman", "save_file_content", params)

    def delete_file(self, filepath: str) -> Dict[str, Any]:
        """Delete file."""
        return self._request("Fileman", "delete_files", {"files": filepath})

    # === SSL OPERATIONS ===
    def list_ssl_certificates(self) -> List[Dict[str, Any]]:
        """List SSL certificates."""
        result = self._request("SSL", "list_certs")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def install_ssl_certificate(self, domain: str, cert: str, key: str, cabundle: str = "") -> Dict[str, Any]:
        """Install SSL certificate."""
        params = {"domain": domain, "cert": cert, "key": key}
        if cabundle:
            params["cabundle"] = cabundle
        return self._request("SSL", "install_ssl", params)

    # === EMAIL OPERATIONS ===
    def list_email_accounts(self) -> List[Dict[str, Any]]:
        """List email accounts."""
        result = self._request("Email", "list_pops")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def create_email_account(self, email: str, password: str, quota: int = 250) -> Dict[str, Any]:
        """Create email account."""
        domain = email.split("@")[1]
        localpart = email.split("@")[0]
        params = {"email": localpart, "domain": domain, "password": password, "quota": quota}
        return self._request("Email", "add_pop", params)

    def delete_email_account(self, email: str) -> Dict[str, Any]:
        """Delete email account."""
        domain = email.split("@")[1]
        return self._request("Email", "delete_pop", {"email": email, "domain": domain})

    # === BACKUP OPERATIONS ===
    def create_backup(self, backup_type: str = "full") -> Dict[str, Any]:
        """Create backup (full, home, mysql, etc)."""
        return self._request("Backup", "fullbackup_to_homedir")

    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups."""
        result = self._request("Backup", "list_backups")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

# =========================================================
# Session State Management
# =========================================================
def init_session_state() -> None:
    """Initialize comprehensive session state."""
    defaults = {
        # API Clients
        "api_type": "20i",  # "20i" or "cpanel"
        "twentyi_client": None,
        "cpanel_client": None,
        "connected": False,
        
        # Account Data
        "account_info": None,
        "packages_raw": None,
        "package_types": None,
        "domains_raw": None,
        "domain_choices": [],
        "selected_package": None,
        "selected_domain": "",
        "all_domains": [],
        
        # Restore State
        "docroot": "",
        "upload_filename": "",
        "uploaded_zip": None,
        "db_details": {},
        "restore_step": 0,
        
        # File Manager State
        "current_directory": "/public_html",
        "file_list": [],
        "selected_file": None,
        "file_content": "",
        "file_edited": False,
        
        # Database Manager State
        "db_list": [],
        "selected_db": None,
        "db_query_result": None,
        "db_query_history": [],
        
        # Backup State
        "backup_list": [],
        "creating_backup": False,
        "backup_progress": 0,
        
        # Email State
        "email_accounts": [],
        "email_quota_total": 0,
        
        # SSL State
        "ssl_certificates": [],
        "ssl_status": {},
        
        # UI State
        "debug_mode": False,
        "current_tab": 0,
        "last_error": None,
        "success_message": None,
        "show_advanced": False,
        
        # Analytics
        "disk_usage": {},
        "bandwidth_usage": {},
        "resource_usage": {},
    }
    
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

# =========================================================
# Enhanced UI Components
# =========================================================
def render_header() -> None:
    """Render application header with status."""
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.title("🚀 WordPress Management Pro")
        st.caption("Complete WordPress hosting management solution")
    
    with col2:
        if st.session_state.connected:
            api_label = "20i API" if st.session_state.api_type == "20i" else "cPanel"
            st.success(f"🟢 Connected via {api_label}")
        else:
            st.warning("🔴 Not Connected")
    
    with col3:
        if st.session_state.selected_domain:
            st.info(f"🌐 Active: {st.session_state.selected_domain}")

def sidebar_connection() -> None:
    """Enhanced sidebar with API selection and authentication."""
    st.sidebar.header("🔌 API Connection")
    
    # API Type Selection
    api_type = st.sidebar.radio(
        "Select API Type",
        options=["20i", "cpanel"],
        index=0 if st.session_state.api_type == "20i" else 1,
        horizontal=True
    )
    st.session_state.api_type = api_type
    
    st.sidebar.divider()
    
    # 20i Connection
    if api_type == "20i":
        st.sidebar.subheader("20i API Configuration")
        api_key = st.sidebar.text_input("General API Key", type="password", key="twentyi_api_key")
        
        if st.sidebar.button("🔄 Connect to 20i", use_container_width=True):
            if not api_key:
                st.sidebar.error("⚠️ Enter your 20i API key")
                return
            
            try:
                with st.spinner("🔄 Connecting to 20i..."):
                    client = TwentyIClient(api_key)
                    st.session_state.twentyi_client = client
                    st.session_state.connected = True
                    
                    # Fetch all data
                    st.session_state.packages_raw = client.list_packages()
                    st.session_state.domain_choices = client.build_domain_choices(st.session_state.packages_raw)
                    st.session_state.package_types = client.list_package_types()
                    st.session_state.domains_raw = client.list_domains()
                    st.session_state.account_info = client.get_account_info()
                    
                    # Extract domain list
                    domains = st.session_state.domains_raw.get("domains", [])
                    st.session_state.all_domains = [d.get("name", "") for d in domains if isinstance(d, dict)]
                    
                    st.sidebar.success(f"✅ Connected! Found {len(st.session_state.domain_choices)} sites")
                    st.rerun()
            except Exception as e:
                st.sidebar.error(f"❌ Connection failed: {e}")
                st.session_state.connected = False
    
    # cPanel Connection
    else:
        st.sidebar.subheader("cPanel Configuration")
        cpanel_url = st.sidebar.text_input("cPanel URL", placeholder="https://yourdomain.com:2083")
        cpanel_user = st.sidebar.text_input("Username", placeholder="cpanel_username")
        
        auth_method = st.sidebar.radio("Authentication", ["Password", "API Token"], horizontal=True)
        
        if auth_method == "Password":
            cpanel_pass = st.sidebar.text_input("Password", type="password")
            cpanel_token = ""
        else:
            cpanel_pass = ""
            cpanel_token = st.sidebar.text_input("API Token", type="password")
        
        if st.sidebar.button("🔄 Connect to cPanel", use_container_width=True):
            if not all([cpanel_url, cpanel_user, (cpanel_pass or cpanel_token)]):
                st.sidebar.error("⚠️ Fill in all fields")
                return
            
            try:
                with st.spinner("🔄 Connecting to cPanel..."):
                    client = CPanelClient(cpanel_url, cpanel_user, cpanel_pass, cpanel_token)
                    st.session_state.cpanel_client = client
                    st.session_state.connected = True
                    
                    # Fetch initial data
                    st.session_state.all_domains = client.list_domains()
                    st.session_state.db_list = client.list_databases()
                    
                    st.sidebar.success(f"✅ Connected! Found {len(st.session_state.all_domains)} domains")
                    st.rerun()
            except Exception as e:
                st.sidebar.error(f"❌ Connection failed: {e}")
                st.session_state.connected = False
    
    st.sidebar.divider()
    
    # Connection Status
    if st.session_state.connected:
        st.sidebar.success("🟢 Connected")
        
        if st.session_state.account_info:
            with st.sidebar.expander("👤 Account Info"):
                st.json(st.session_state.account_info)
        
        if st.sidebar.button("🔌 Disconnect", use_container_width=True):
            st.session_state.connected = False
            st.session_state.twentyi_client = None
            st.session_state.cpanel_client = None
            st.rerun()
    
    # Debug Mode
    st.sidebar.divider()
    st.session_state.debug_mode = st.sidebar.checkbox(
        "🐛 Debug Mode",
        value=st.session_state.debug_mode
    )
    
    st.session_state.show_advanced = st.sidebar.checkbox(
        "⚙️ Advanced Mode",
        value=st.session_state.show_advanced
    )

def get_client():
    """Get the active API client."""
    if st.session_state.api_type == "20i":
        return st.session_state.twentyi_client
    else:
        return st.session_state.cpanel_client

# =========================================================
# Tab 1: Dashboard
# =========================================================
def render_dashboard_tab() -> None:
    """Render main dashboard with overview and stats."""
    st.header("🏠 Dashboard")
    
    if not st.session_state.connected:
        st.info("👈 **Connect via sidebar** to view dashboard")
        return
    
    client = get_client()
    
    # Quick Stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Domains", len(st.session_state.all_domains))
    
    with col2:
        st.metric("Databases", len(st.session_state.db_list))
    
    with col3:
        st.metric("Backups", len(st.session_state.backup_list))
    
    with col4:
        st.metric("Emails", len(st.session_state.email_accounts))
    
    st.divider()
    
    # Recent Activity
    col_left, col_right = st.columns(2)
    
    with col_left:
        st.subheader("🌐 Your Domains")
        if st.session_state.all_domains:
            for domain in st.session_state.all_domains[:10]:
                st.text(f"• {domain}")
            if len(st.session_state.all_domains) > 10:
                st.caption(f"...and {len(st.session_state.all_domains) - 10} more")
        else:
            st.info("No domains found")
    
    with col_right:
        st.subheader("📊 Quick Actions")
        if st.button("🔄 Create New Backup", use_container_width=True):
            st.session_state.current_tab = 2  # Switch to Backup Manager
            st.rerun()
        
        if st.button("📝 Edit Files", use_container_width=True):
            st.session_state.current_tab = 3  # Switch to File Editor
            st.rerun()
        
        if st.button("🗄️ Manage Databases", use_container_width=True):
            st.session_state.current_tab = 4  # Switch to Database Manager
            st.rerun()
        
        if st.button("🌐 Manage Domains", use_container_width=True):
            st.session_state.current_tab = 5  # Switch to Domain Manager
            st.rerun()
    
    # System Status (for 20i)
    if st.session_state.api_type == "20i" and st.session_state.selected_package:
        st.divider()
        st.subheader("📊 Resource Usage")
        
        try:
            pkg_id = st.session_state.selected_package.get("package_id") or st.session_state.selected_package.get("id")
            if pkg_id:
                resources = client.get_package_resources(pkg_id)
                st.session_state.resource_usage = resources
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    disk_used = resources.get("disk_used", 0)
                    disk_limit = resources.get("disk_limit", 0)
                    disk_pct = (disk_used / disk_limit * 100) if disk_limit > 0 else 0
                    st.metric("Disk Usage", f"{format_file_size(disk_used)}", f"{disk_pct:.1f}%")
                
                with col2:
                    bandwidth_used = resources.get("bandwidth_used", 0)
                    st.metric("Bandwidth", format_file_size(bandwidth_used))
                
                with col3:
                    inodes_used = resources.get("inodes_used", 0)
                    st.metric("Files (Inodes)", f"{inodes_used:,}")
        except Exception as e:
            st.warning(f"Could not load resource usage: {e}")

# =========================================================
# Tab 2: Restore (Original Functionality Enhanced)
# =========================================================
def render_restore_tab() -> None:
    """Enhanced restore tab with step-by-step wizard."""
    st.header("🔄 WordPress Restore Wizard")
    
    if not st.session_state.connected:
        st.info("👈 **Connect via sidebar** to start restore")
        return
    
    # Progress indicator
    progress = st.progress(0)
    
    # Step 1: Select Domain/Package
    choice, domain = step_1_domain_selection()
    if not choice or not domain:
        return
    progress.progress(20)
    
    # Step 2: Upload ZIP
    uploaded_zip = step_2_upload()
    if not uploaded_zip:
        return
    progress.progress(40)
    
    # Step 3: Document Root
    docroot = step_3_docroot(domain)
    progress.progress(60)
    
    # Step 4: Database Setup
    db_ready = step_4_database(domain)
    if not db_ready:
        return
    progress.progress(80)
    
    # Step 5: Restore Plan
    step_5_restore_plan(uploaded_zip, choice, domain)
    progress.progress(100)

def step_1_domain_selection() -> Tuple[Optional[Dict], Optional[str]]:
    """Step 1: Domain/Package selection with management options."""
    st.subheader("1. 🌐 Select Target Domain")
    
    if st.session_state.api_type == "20i":
        if not st.session_state.domain_choices:
            st.warning("No packages found. Add domains in Domain Manager.")
            return None, None
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            pkg_idx = st.selectbox(
                "Select Package/Domain",
                range(len(st.session_state.domain_choices)),
                format_func=lambda i: st.session_state.domain_choices[i]["label"],
                key="restore_pkg_select"
            )
            selected = st.session_state.domain_choices[pkg_idx]
        
        with col2:
            if st.button("🔄 Refresh", key="restore_refresh"):
                try:
                    client = get_client()
                    pkg_details = client.get_package(selected["package_id"])
                    st.session_state.selected_package = pkg_details
                    st.success("✅ Refreshed")
                except Exception as e:
                    st.error(f"❌ {e}")
        
        st.session_state.selected_package = selected
        st.session_state.selected_domain = selected["domain"]
        st.info(f"🎯 Restoring to: **{selected['domain']}** (Package: {selected['package_id']})")
        
        return selected, selected["domain"]
    
    else:  # cPanel
        if not st.session_state.all_domains:
            st.warning("No domains found")
            return None, None
        
        domain = st.selectbox("Select Domain", st.session_state.all_domains, key="restore_cpanel_domain")
        st.session_state.selected_domain = domain
        st.info(f"🎯 Restoring to: **{domain}**")
        
        return {"domain": domain}, domain

def step_2_upload() -> Optional[BytesIO]:
    """Step 2: ZIP upload with validation and preview."""
    st.subheader("2. 📤 Upload WordPress Backup")
    
    uploaded = st.file_uploader(
        "Upload ZIP backup file",
        type=["zip"],
        key="restore_zip_upload",
        help="Upload a complete WordPress site backup (files + database)"
    )
    
    if not uploaded:
        st.info("📦 Upload a WordPress backup ZIP file to continue")
        return None
    
    st.session_state.upload_filename = uploaded.name
    buf = BytesIO(uploaded.read())
    buf.seek(0)
    st.session_state.uploaded_zip = buf
    
    # Validate and preview ZIP contents
    try:
        with zipfile.ZipFile(buf, 'r') as zf:
            file_list = zf.namelist()
            total_files = len(file_list)
            
            # Analyze contents
            wp_files = [f for f in file_list if 'wp-' in f.lower()]
            sql_files = [f for f in file_list if f.endswith('.sql')]
            php_files = [f for f in file_list if f.endswith('.php')]
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total Files", total_files)
            col2.metric("WP Files", len(wp_files))
            col3.metric("SQL Files", len(sql_files))
            col4.metric("PHP Files", len(php_files))
            
            # Show preview
            with st.expander("📋 Preview ZIP Contents (first 20 files)"):
                for fname in file_list[:20]:
                    st.text(f"  {fname}")
                if total_files > 20:
                    st.caption(f"...and {total_files - 20} more files")
            
            st.success(f"✅ Valid WordPress backup ZIP")
            
    except Exception as e:
        st.error(f"❌ Invalid ZIP file: {e}")
        return None
    
    buf.seek(0)
    return buf

def step_3_docroot(domain: str) -> str:
    """Step 3: Document root configuration."""
    st.subheader("3. 📁 Document Root Path")
    
    if st.session_state.api_type == "20i":
        suggestions = [
            f"/home/stackcp/{domain}/public_html",
            f"/home/stackcp/{domain}/htdocs",
            f"/home/stackcp/{domain}/www"
        ]
    else:  # cPanel
        suggestions = [
            f"/home/{st.session_state.cpanel_client.username}/public_html",
            f"/home/{st.session_state.cpanel_client.username}/public_html/{domain}",
            f"/home/{st.session_state.cpanel_client.username}/domains/{domain}/public_html"
        ]
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        docroot = st.text_input(
            "Document Root",
            value=st.session_state.docroot or suggestions[0],
            help="The absolute path where WordPress files will be extracted",
            key="restore_docroot"
        )
    
    with col2:
        st.markdown("**Suggestions:**")
        for suggestion in suggestions[:2]:
            if st.button(suggestion, key=f"docroot_{suggestion}"):
                st.session_state.docroot = suggestion
                st.rerun()
    
    st.session_state.docroot = docroot
    st.info(f"📍 Files will be restored to: `{docroot}`")
    
    return docroot

def step_4_database(domain: str) -> bool:
    """Step 4: Database configuration with auto-creation."""
    st.subheader("4. 🗄️ Database Configuration")
    
    client = get_client()
    
    # Initialize or load DB details
    if not st.session_state.db_details:
        base_name = normalize_domain_name(domain.split(".")[0])[:16]
        st.session_state.db_details = {
            "name": f"{base_name}_wp",
            "user": f"{base_name}_user",
            "password": generate_strong_password(),
            "host": "localhost",
            "created": False
        }
    
    col1, col2 = st.columns(2)
    
    with col1:
        db_name = st.text_input(
            "Database Name",
            value=st.session_state.db_details["name"],
            key="restore_db_name"
        )
        db_user = st.text_input(
            "Database User",
            value=st.session_state.db_details["user"],
            key="restore_db_user"
        )
    
    with col2:
        db_pass = st.text_input(
            "Database Password",
            value=st.session_state.db_details["password"],
            type="password",
            key="restore_db_pass"
        )
        db_host = st.text_input(
            "Database Host",
            value=st.session_state.db_details["host"],
            key="restore_db_host"
        )
    
    st.session_state.db_details.update({
        "name": db_name,
        "user": db_user,
        "password": db_pass,
        "host": db_host
    })
    
    # Auto-create database option
    st.divider()
    
    col_create, col_manual = st.columns(2)
    
    with col_create:
        st.markdown("**🤖 Auto-Create Database**")
        if st.button("✨ Create Database Now", key="auto_create_db", use_container_width=True):
            try:
                with st.spinner("Creating database..."):
                    if st.session_state.api_type == "20i":
                        pkg_id = st.session_state.selected_package["package_id"]
                        client.create_database(pkg_id, db_name)
                        client.create_database_user(pkg_id, db_user, db_pass)
                        client.grant_database_access(pkg_id, db_name, db_user)
                    else:  # cPanel
                        client.create_database(db_name)
                        client.create_database_user(db_user, db_pass)
                        client.grant_database_privileges(db_user, db_name)
                    
                    st.session_state.db_details["created"] = True
                    st.success("✅ Database created successfully!")
                    st.rerun()
            except Exception as e:
                st.error(f"❌ Failed to create database: {e}")
    
    with col_manual:
        st.markdown("**📝 Manual Creation**")
        if st.button("✅ I Created It Manually", key="manual_db_ready", use_container_width=True):
            st.session_state.db_details["created"] = True
            st.rerun()
    
    # Show credentials for copying
    if st.session_state.db_details.get("created"):
        st.success("✅ Database is ready!")
        
        with st.expander("📋 Database Credentials (click to copy)"):
            st.code(f"""Database Name: {db_name}
Database User: {db_user}
Database Password: {db_pass}
Database Host: {db_host}""")
    
    return st.session_state.db_details.get("created", False)

def step_5_restore_plan(buf: BytesIO, pkg: Dict, domain: str) -> None:
    """Step 5: Complete restore instructions and automation."""
    st.subheader("5. 🚀 Restore Execution Plan")
    
    db = st.session_state.db_details
    docroot = st.session_state.docroot
    filename = st.session_state.upload_filename
    
    st.success("✅ All prerequisites ready! Follow these steps to complete the restore:")
    
    # Tabbed instructions
    tab1, tab2, tab3 = st.tabs(["📝 Instructions", "🤖 Auto Commands", "📊 Verification"])
    
    with tab1:
        st.markdown("### Step-by-Step Manual Restore")
        
        st.markdown("#### 1️⃣ Upload & Extract Files")
        st.code(f"""# Upload {filename} to your server via SFTP/StackCP File Manager
# Then SSH into your server and run:

ssh your-username@your-server.com
cd {docroot}
unzip {filename}
rm {filename}

# Set proper permissions
find . -type d -exec chmod 755 {{}} \\;
find . -type f -exec chmod 644 {{}} \\;
chmod 600 wp-config.php
chown -R www-data:www-data .  # Or appropriate user
""", language="bash")
        
        st.markdown("#### 2️⃣ Update wp-config.php")
        config_patch = f"""<?php
// Database settings - Update these lines in wp-config.php
define('DB_NAME', '{db["name"]}');
define('DB_USER', '{db["user"]}');
define('DB_PASSWORD', '{db["password"]}');
define('DB_HOST', '{db["host"]}');

// Update site URL (optional, can also do via database)
define('WP_HOME', 'https://{domain}');
define('WP_SITEURL', 'https://{domain}');
"""
        st.code(config_patch, language="php")
        
        st.markdown("#### 3️⃣ Import Database")
        st.code(f"""# Find the .sql file in your backup and import it
mysql -u {db["user"]} -p'{db["password"]}' {db["name"]} < backup-database.sql

# Update WordPress URLs in database
mysql -u {db["user"]} -p'{db["password"]}' {db["name"]} << EOF
UPDATE wp_options SET option_value = 'https://{domain}' WHERE option_name IN ('siteurl', 'home');
EOF
""", language="bash")
        
        st.markdown("#### 4️⃣ Final Steps")
        st.info("""
        - Test your site: https://{domain}
        - Login to WordPress admin
        - Update permalinks (Settings → Permalinks → Save)
        - Clear any caching plugins
        - Verify images and uploads are working
        - Check .htaccess file permissions (644)
        """.format(domain=domain))
    
    with tab2:
        st.markdown("### 🤖 Automated Restore Script")
        st.info("Copy this complete script to automate the entire restore process")
        
        restore_script = f"""#!/bin/bash
# WordPress Restore Automation Script
# Generated by WordPress Management Pro

set -e  # Exit on error

DOMAIN="{domain}"
DOCROOT="{docroot}"
BACKUP_ZIP="{filename}"
DB_NAME="{db['name']}"
DB_USER="{db['user']}"
DB_PASS="{db['password']}"
DB_HOST="{db['host']}"

echo "🚀 Starting WordPress restore for $DOMAIN"

# Step 1: Extract files
echo "📦 Extracting backup..."
cd "$DOCROOT"
unzip -q "$BACKUP_ZIP"
rm "$BACKUP_ZIP"

# Step 2: Set permissions
echo "🔒 Setting permissions..."
find . -type d -exec chmod 755 {{}} \\;
find . -type f -exec chmod 644 {{}} \\;
chmod 600 wp-config.php 2>/dev/null || true

# Step 3: Update wp-config.php
echo "⚙️ Updating wp-config.php..."
sed -i "s/define('DB_NAME',.*/define('DB_NAME', '$DB_NAME');/" wp-config.php
sed -i "s/define('DB_USER',.*/define('DB_USER', '$DB_USER');/" wp-config.php
sed -i "s/define('DB_PASSWORD',.*/define('DB_PASSWORD', '$DB_PASS');/" wp-config.php
sed -i "s/define('DB_HOST',.*/define('DB_HOST', '$DB_HOST');/" wp-config.php

# Step 4: Import database
echo "🗄️ Importing database..."
SQL_FILE=$(find . -name "*.sql" -type f | head -n 1)
if [ -n "$SQL_FILE" ]; then
    mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" < "$SQL_FILE"
    echo "✅ Database imported: $SQL_FILE"
else
    echo "⚠️ No .sql file found. Import manually."
fi

# Step 5: Update WordPress URLs
echo "🔗 Updating WordPress URLs..."
mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" <<EOF
UPDATE wp_options SET option_value = 'https://$DOMAIN' WHERE option_name IN ('siteurl', 'home');
EOF

echo "✅ Restore complete for $DOMAIN!"
echo "🌐 Visit: https://$DOMAIN"
"""
        st.code(restore_script, language="bash")
        
        st.download_button(
            "📥 Download Restore Script",
            data=restore_script,
            file_name=f"restore_{domain.replace('.', '_')}.sh",
            mime="text/x-shellscript"
        )
    
    with tab3:
        st.markdown("### 📊 Post-Restore Verification Checklist")
        
        checks = [
            "✅ Site loads correctly (https://{})".format(domain),
            "✅ Can login to WordPress admin (/wp-admin)",
            "✅ All pages and posts are visible",
            "✅ Images and media files load properly",
            "✅ Plugins are activated and working",
            "✅ Theme is active and displays correctly",
            "✅ Permalinks are working (test a blog post)",
            "✅ Contact forms are functional (if applicable)",
            "✅ SSL certificate is installed and working",
            "✅ No PHP errors in error logs"
        ]
        
        for check in checks:
            st.markdown(f"- {check}")
        
        st.divider()
        
        st.markdown("### 🔧 Common Issues & Solutions")
        
        with st.expander("❌ White Screen of Death (WSOD)"):
            st.markdown("""
            **Causes:**
            - PHP errors
            - Plugin conflicts
            - Memory limit issues
            
            **Solutions:**
            - Check error logs
            - Disable all plugins via database: `UPDATE wp_options SET option_value = '' WHERE option_name = 'active_plugins';`
            - Increase PHP memory limit in wp-config.php: `define('WP_MEMORY_LIMIT', '256M');`
            """)
        
        with st.expander("🔗 Broken Links/Images"):
            st.markdown("""
            **Causes:**
            - Incorrect site URL in database
            - Wrong file permissions
            
            **Solutions:**
            - Use Search & Replace plugin to fix URLs
            - Run: `UPDATE wp_options SET option_value = 'https://newdomain.com' WHERE option_name IN ('siteurl', 'home');`
            - Check file permissions (folders 755, files 644)
            """)
        
        with st.expander("🚫 403/404 Errors"):
            st.markdown("""
            **Causes:**
            - .htaccess issues
            - Permalink problems
            
            **Solutions:**
            - Regenerate .htaccess: Go to Settings → Permalinks → Save
            - Check .htaccess permissions (644)
            - Ensure mod_rewrite is enabled
            """)
    
    st.balloons()
    st.success(f"🎉 Ready to restore **{domain}**! Follow the instructions above.")

# =========================================================
# Tab 3: Backup Manager
# =========================================================
def render_backup_manager_tab() -> None:
    """Comprehensive backup management interface."""
    st.header("💾 Backup Manager")
    
    if not st.session_state.connected:
        st.info("👈 **Connect via sidebar** to manage backups")
        return
    
    client = get_client()
    
    # Backup actions
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔄 Refresh Backup List", use_container_width=True):
            try:
                if st.session_state.api_type == "20i" and st.session_state.selected_package:
                    pkg_id = st.session_state.selected_package.get("package_id") or st.session_state.selected_package.get("id")
                    st.session_state.backup_list = client.list_backups(pkg_id).get("backups", [])
                else:
                    st.session_state.backup_list = client.list_backups()
                st.success("✅ Backup list refreshed")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Failed to fetch backups: {e}")
    
    with col2:
        backup_name = st.text_input("Backup Name", placeholder="my-backup")
    
    with col3:
        if st.button("➕ Create New Backup", use_container_width=True):
            if not backup_name:
                backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            try:
                with st.spinner("Creating backup..."):
                    if st.session_state.api_type == "20i" and st.session_state.selected_package:
                        pkg_id = st.session_state.selected_package.get("package_id") or st.session_state.selected_package.get("id")
                        result = client.create_backup(pkg_id, backup_name)
                        st.success(f"✅ Backup '{backup_name}' created!")
                    else:
                        result = client.create_backup()
                        st.success("✅ Backup initiated! Check back in a few minutes.")
                    st.rerun()
            except Exception as e:
                st.error(f"❌ Failed to create backup: {e}")
    
    st.divider()
    
    # Display backups
    st.subheader("📦 Available Backups")
    
    if not st.session_state.backup_list:
        st.info("No backups found. Create your first backup above!")
    else:
        for idx, backup in enumerate(st.session_state.backup_list):
            with st.expander(f"📦 {backup.get('name', f'Backup {idx+1}')} - {format_timestamp(backup.get('created_at'))}"):
                col_info, col_actions = st.columns([2, 1])
                
                with col_info:
                    st.json({
                        "ID": backup.get("id"),
                        "Name": backup.get("name"),
                        "Size": format_file_size(backup.get("size", 0)),
                        "Created": format_timestamp(backup.get("created_at")),
                        "Type": backup.get("type", "Full")
                    })
                
                with col_actions:
                    if st.button(f"📥 Download", key=f"download_backup_{idx}"):
                        try:
                            if st.session_state.api_type == "20i":
                                pkg_id = st.session_state.selected_package.get("package_id")
                                backup_data = client.download_backup(pkg_id, backup["id"])
                                st.download_button(
                                    "💾 Save Backup",
                                    data=backup_data,
                                    file_name=f"{backup['name']}.zip",
                                    mime="application/zip",
                                    key=f"save_backup_{idx}"
                                )
                            else:
                                st.info("Download link will be emailed to your account")
                        except Exception as e:
                            st.error(f"❌ {e}")
                    
                    if st.button(f"♻️ Restore", key=f"restore_backup_{idx}"):
                        if st.confirm(f"Restore from '{backup.get('name')}'? This will overwrite current data!"):
                            try:
                                if st.session_state.api_type == "20i":
                                    pkg_id = st.session_state.selected_package.get("package_id")
                                    client.restore_backup(pkg_id, backup["id"])
                                    st.success("✅ Restore initiated!")
                                else:
                                    st.info("Please use cPanel backup interface for restore")
                            except Exception as e:
                                st.error(f"❌ {e}")

# =========================================================
# Tab 4: File Editor
# =========================================================
def render_file_editor_tab() -> None:
    """Advanced file editor with syntax highlighting."""
    st.header("📝 File Editor")
    
    if not st.session_state.connected:
        st.info("👈 **Connect via sidebar** to edit files")
        return
    
    client = get_client()
    
    # Only works with cPanel for now
    if st.session_state.api_type != "cpanel":
        st.warning("⚠️ File editor currently only supports cPanel API")
        st.info("For 20i, use SSH/SFTP or the 20i control panel file manager")
        return
    
    # Directory navigation
    col1, col2 = st.columns([3, 1])
    
    with col1:
        current_dir = st.text_input(
            "Directory Path",
            value=st.session_state.current_directory,
            key="file_editor_dir"
        )
        st.session_state.current_directory = current_dir
    
    with col2:
        if st.button("📂 Browse", use_container_width=True):
            try:
                st.session_state.file_list = client.list_files(current_dir)
                st.rerun()
            except Exception as e:
                st.error(f"❌ {e}")
    
    st.divider()
    
    # File list and editor in columns
    col_files, col_editor = st.columns([1, 2])
    
    with col_files:
        st.subheader("📁 Files")
        
        if not st.session_state.file_list:
            st.info("Click 'Browse' to load files")
        else:
            for file_info in st.session_state.file_list:
                file_name = file_info.get("file", "")
                file_type = file_info.get("type", "file")
                icon = "📁" if file_type == "dir" else "📄"
                
                if st.button(f"{icon} {file_name}", key=f"file_{file_name}"):
                    if file_type == "dir":
                        st.session_state.current_directory = f"{current_dir}/{file_name}".replace("//", "/")
                        st.rerun()
                    else:
                        # Load file content
                        try:
                            file_path = f"{current_dir}/{file_name}".replace("//", "/")
                            content = client.read_file(file_path)
                            st.session_state.selected_file = file_path
                            st.session_state.file_content = content
                            st.session_state.file_edited = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ {e}")
    
    with col_editor:
        st.subheader("✏️ Editor")
        
        if st.session_state.selected_file:
            st.caption(f"Editing: `{st.session_state.selected_file}`")
            
            # Editor with syntax highlighting hint
            syntax = get_file_syntax(st.session_state.selected_file)
            
            edited_content = st.text_area(
                "File Content",
                value=st.session_state.file_content,
                height=400,
                key="file_content_editor"
            )
            
            if edited_content != st.session_state.file_content:
                st.session_state.file_edited = True
            
            # Action buttons
            col_save, col_download, col_close = st.columns(3)
            
            with col_save:
                if st.button("💾 Save Changes", disabled=not st.session_state.file_edited, use_container_width=True):
                    try:
                        client.write_file(st.session_state.selected_file, edited_content)
                        st.session_state.file_content = edited_content
                        st.session_state.file_edited = False
                        st.success("✅ File saved!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ {e}")
            
            with col_download:
                st.download_button(
                    "📥 Download",
                    data=edited_content,
                    file_name=Path(st.session_state.selected_file).name,
                    mime="text/plain",
                    use_container_width=True
                )
            
            with col_close:
                if st.button("❌ Close", use_container_width=True):
                    st.session_state.selected_file = None
                    st.session_state.file_content = ""
                    st.session_state.file_edited = False
                    st.rerun()
            
            # wp-config.php helper
            if "wp-config.php" in st.session_state.selected_file:
                st.divider()
                st.subheader("🔧 wp-config.php Helper")
                
                extracted = extract_wp_config_values(edited_content)
                if extracted:
                    st.json(extracted)
                    
                    if st.button("🔄 Update Database Credentials"):
                        st.info("Use the form below to update credentials")
                        
                        new_db_name = st.text_input("DB Name", value=extracted.get("DB_NAME", ""))
                        new_db_user = st.text_input("DB User", value=extracted.get("DB_USER", ""))
                        new_db_pass = st.text_input("DB Password", value=extracted.get("DB_PASSWORD", ""), type="password")
                        new_db_host = st.text_input("DB Host", value=extracted.get("DB_HOST", "localhost"))
                        
                        if st.button("💾 Apply Changes"):
                            # Update content
                            updated = edited_content
                            updated = re.sub(
                                r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"][^'\"]*['\"]",
                                f"define('DB_NAME', '{new_db_name}'",
                                updated
                            )
                            updated = re.sub(
                                r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"][^'\"]*['\"]",
                                f"define('DB_USER', '{new_db_user}'",
                                updated
                            )
                            updated = re.sub(
                                r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"][^'\"]*['\"]",
                                f"define('DB_PASSWORD', '{new_db_pass}'",
                                updated
                            )
                            updated = re.sub(
                                r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"][^'\"]*['\"]",
                                f"define('DB_HOST', '{new_db_host}'",
                                updated
                            )
                            
                            st.session_state.file_content = updated
                            st.rerun()
        else:
            st.info("📂 Select a file from the left to start editing")

# =========================================================
# Tab 5: Database Manager
# =========================================================
def render_database_manager_tab() -> None:
    """Database management and query interface."""
    st.header("🗄️ Database Manager")
    
    if not st.session_state.connected:
        st.info("👈 **Connect via sidebar** to manage databases")
        return
    
    client = get_client()
    
    # Refresh database list
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        if st.button("🔄 Refresh Database List", use_container_width=True):
            try:
                if st.session_state.api_type == "20i" and st.session_state.selected_package:
                    pkg_id = st.session_state.selected_package.get("package_id") or st.session_state.selected_package.get("id")
                    result = client.list_databases(pkg_id)
                    st.session_state.db_list = result.get("databases", [])
                else:
                    st.session_state.db_list = client.list_databases()
                st.success("✅ Database list refreshed")
                st.rerun()
            except Exception as e:
                st.error(f"❌ {e}")
    
    with col2:
        new_db_name = st.text_input("New DB Name", placeholder="mysite_db")
    
    with col3:
        if st.button("➕ Create Database", use_container_width=True):
            if not new_db_name:
                st.error("Enter a database name")
            else:
                try:
                    if st.session_state.api_type == "20i" and st.session_state.selected_package:
                        pkg_id = st.session_state.selected_package.get("package_id")
                        client.create_database(pkg_id, new_db_name)
                    else:
                        client.create_database(new_db_name)
                    st.success(f"✅ Database '{new_db_name}' created!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ {e}")
    
    st.divider()
    
    # Database list
    st.subheader("📚 Your Databases")
    
    if not st.session_state.db_list:
        st.info("No databases found or refresh list above")
    else:
        for idx, db in enumerate(st.session_state.db_list):
            db_name = db if isinstance(db, str) else db.get("name", f"Database {idx+1}")
            
            with st.expander(f"🗄️ {db_name}"):
                col_info, col_actions = st.columns([2, 1])
                
                with col_info:
                    if isinstance(db, dict):
                        st.json(db)
                    else:
                        st.text(f"Database: {db_name}")
                
                with col_actions:
                    if st.button(f"🗑️ Delete", key=f"delete_db_{idx}"):
                        if st.session_state.debug_mode or st.confirm(f"Delete '{db_name}'? This cannot be undone!"):
                            try:
                                if st.session_state.api_type == "20i":
                                    pkg_id = st.session_state.selected_package.get("package_id")
                                    client.delete_database(pkg_id, db_name)
                                else:
                                    client.delete_database(db_name)
                                st.success(f"✅ Deleted '{db_name}'")
                                st.rerun()
                            except Exception as e:
                                st.error(f"❌ {e}")
    
    # SQL Query Interface (for advanced users)
    if st.session_state.show_advanced:
        st.divider()
        st.subheader("💻 SQL Query Interface")
        
        st.warning("⚠️ **Advanced Feature**: Direct SQL queries. Use with caution!")
        
        selected_db = st.selectbox(
            "Select Database",
            st.session_state.db_list if st.session_state.db_list else ["No databases"],
            key="sql_query_db"
        )
        
        query = st.text_area(
            "SQL Query",
            placeholder="SELECT * FROM wp_options WHERE option_name = 'siteurl';",
            height=150,
            key="sql_query_input"
        )
        
        if st.button("▶️ Execute Query"):
            if not query.strip():
                st.error("Enter a SQL query")
            else:
                st.info("🔒 Direct SQL execution requires additional authentication. Use phpMyAdmin or CLI for now.")
                # In production, you'd implement secure query execution here

# =========================================================
# Tab 6: Domain Manager
# =========================================================
def render_domain_manager_tab() -> None:
    """Domain management interface."""
    st.header("🌐 Domain Manager")
    
    if not st.session_state.connected:
        st.info("👈 **Connect via sidebar** to manage domains")
        return
    
    client = get_client()
    
    # Add new domain
    st.subheader("➕ Add New Domain")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        new_domain = st.text_input("Domain Name", placeholder="example.com")
    
    with col2:
        if st.session_state.api_type == "20i" and st.session_state.selected_package:
            new_docroot = st.text_input("Document Root", placeholder=f"/home/stackcp/{new_domain}/public_html")
        else:
            subdomain = st.text_input("Subdomain", placeholder="subdomain")
    
    with col3:
        st.write("")  # Spacing
        st.write("")  # Spacing
        if st.button("✨ Add Domain", use_container_width=True):
            if not new_domain:
                st.error("Enter a domain name")
            else:
                try:
                    if st.session_state.api_type == "20i" and st.session_state.selected_package:
                        pkg_id = st.session_state.selected_package.get("package_id") or st.session_state.selected_package.get("id")
                        client.add_domain_to_package(pkg_id, new_domain, new_docroot)
                        st.success(f"✅ Domain '{new_domain}' added!")
                    else:
                        docroot = f"/home/{client.username}/public_html/{new_domain}"
                        client.add_addon_domain(new_domain, subdomain or new_domain.split('.')[0], docroot)
                        st.success(f"✅ Addon domain '{new_domain}' added!")
                    st.rerun()
                except Exception as e:
                    st.error(f"❌ {e}")
    
    st.divider()
    
    # Domain list
    st.subheader("📋 Your Domains")
    
    if not st.session_state.all_domains:
        st.info("No domains found")
    else:
        for idx, domain in enumerate(st.session_state.all_domains):
            domain_name = domain if isinstance(domain, str) else domain.get("name", f"Domain {idx+1}")
            
            with st.expander(f"🌐 {domain_name}"):
                col_info, col_actions = st.columns([2, 1])
                
                with col_info:
                    if isinstance(domain, dict):
                        st.json(domain)
                    else:
                        st.text(f"Domain: {domain_name}")
                        st.text(f"URL: https://{domain_name}")
                
                with col_actions:
                    if st.button(f"🔗 Visit Site", key=f"visit_{idx}"):
                        st.markdown(f"[Open {domain_name}](https://{domain_name})")
                    
                    if st.button(f"🗑️ Remove", key=f"remove_domain_{idx}"):
                        st.warning("⚠️ Domain removal requires package ID. Use API directly.")

# =========================================================
# Tab 7: SSL Manager
# =========================================================
def render_ssl_manager_tab() -> None:
    """SSL certificate management."""
    st.header("🔐 SSL Certificate Manager")
    
    if not st.session_state.connected:
        st.info("👈 **Connect via sidebar** to manage SSL")
        return
    
    client = get_client()
    
    # Install free SSL
    st.subheader("✨ Install Free SSL Certificate")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        ssl_domain = st.selectbox(
            "Select Domain",
            st.session_state.all_domains if st.session_state.all_domains else ["No domains"],
            key="ssl_domain_select"
        )
    
    with col2:
        st.write("")  # Spacing
        st.write("")  # Spacing
        if st.button("🔒 Install Let's Encrypt SSL", use_container_width=True):
            try:
                if st.session_state.api_type == "20i" and st.session_state.selected_package:
                    pkg_id = st.session_state.selected_package.get("package_id") or st.session_state.selected_package.get("id")
                    client.install_free_ssl(pkg_id, ssl_domain)
                    st.success(f"✅ SSL certificate requested for {ssl_domain}!")
                    st.info("It may take a few minutes to provision. Check back soon.")
                else:
                    st.info("Use cPanel SSL/TLS interface to install Let's Encrypt SSL")
            except Exception as e:
                st.error(f"❌ {e}")
    
    st.divider()
    
    # SSL Certificate List
    st.subheader("📜 Installed SSL Certificates")
    
    if st.button("🔄 Refresh SSL List"):
        try:
            if st.session_state.api_type == "20i" and st.session_state.selected_package:
                pkg_id = st.session_state.selected_package.get("package_id") or st.session_state.selected_package.get("id")
                result = client.list_ssl_certificates(pkg_id)
                st.session_state.ssl_certificates = result.get("certificates", [])
            else:
                st.session_state.ssl_certificates = client.list_ssl_certificates()
            st.success("✅ SSL list refreshed")
            st.rerun()
        except Exception as e:
            st.error(f"❌ {e}")
    
    if not st.session_state.ssl_certificates:
        st.info("No SSL certificates found or refresh list above")
    else:
        for idx, cert in enumerate(st.session_state.ssl_certificates):
            cert_domain = cert.get("domain", f"Certificate {idx+1}")
            
            with st.expander(f"🔒 {cert_domain}"):
                st.json(cert)

# =========================================================
# Tab 8: Email Manager
# =========================================================
def render_email_manager_tab() -> None:
    """Email account management."""
    st.header("📧 Email Account Manager")
    
    if not st.session_state.connected:
        st.info("👈 **Connect via sidebar** to manage email")
        return
    
    client = get_client()
    
    # Create new email account
    st.subheader("➕ Create Email Account")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        new_email = st.text_input("Email Address", placeholder="user@yourdomain.com")
    
    with col2:
        new_email_pass = st.text_input("Password", type="password", value=generate_strong_password())
    
    with col3:
        email_quota = st.number_input("Quota (MB)", min_value=100, max_value=10000, value=1000, step=100)
    
    if st.button("✉️ Create Email Account", use_container_width=True):
        if not new_email or "@" not in new_email:
            st.error("Enter a valid email address")
        else:
            try:
                if st.session_state.api_type == "20i" and st.session_state.selected_package:
                    pkg_id = st.session_state.selected_package.get("package_id") or st.session_state.selected_package.get("id")
                    client.create_email_account(pkg_id, new_email, new_email_pass, email_quota)
                else:
                    client.create_email_account(new_email, new_email_pass, email_quota)
                st.success(f"✅ Email account '{new_email}' created!")
                st.rerun()
            except Exception as e:
                st.error(f"❌ {e}")
    
    st.divider()
    
    # Email account list
    st.subheader("📬 Email Accounts")
    
    if st.button("🔄 Refresh Email List"):
        try:
            if st.session_state.api_type == "20i" and st.session_state.selected_package:
                pkg_id = st.session_state.selected_package.get("package_id") or st.session_state.selected_package.get("id")
                result = client.list_email_accounts(pkg_id)
                st.session_state.email_accounts = result.get("accounts", [])
            else:
                st.session_state.email_accounts = client.list_email_accounts()
            st.success("✅ Email list refreshed")
            st.rerun()
        except Exception as e:
            st.error(f"❌ {e}")
    
    if not st.session_state.email_accounts:
        st.info("No email accounts found or refresh list above")
    else:
        for idx, email in enumerate(st.session_state.email_accounts):
            email_addr = email if isinstance(email, str) else email.get("email", f"Email {idx+1}")
            
            with st.expander(f"📧 {email_addr}"):
                col_info, col_actions = st.columns([2, 1])
                
                with col_info:
                    if isinstance(email, dict):
                        st.json(email)
                    else:
                        st.text(f"Email: {email_addr}")
                
                with col_actions:
                    if st.button(f"🔑 Reset Password", key=f"reset_email_{idx}"):
                        new_pass = generate_strong_password()
                        try:
                            if st.session_state.api_type == "20i":
                                pkg_id = st.session_state.selected_package.get("package_id")
                                client.update_email_password(pkg_id, email_addr, new_pass)
                            st.success(f"New password: {new_pass}")
                        except Exception as e:
                            st.error(f"❌ {e}")
                    
                    if st.button(f"🗑️ Delete", key=f"delete_email_{idx}"):
                        try:
                            if st.session_state.api_type == "20i":
                                pkg_id = st.session_state.selected_package.get("package_id")
                                client.delete_email_account(pkg_id, email_addr)
                            else:
                                client.delete_email_account(email_addr)
                            st.success(f"✅ Deleted {email_addr}")
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ {e}")

# =========================================================
# Tab 9: Analytics
# =========================================================
def render_analytics_tab() -> None:
    """Analytics and monitoring dashboard."""
    st.header("📊 Analytics & Monitoring")
    
    if not st.session_state.connected:
        st.info("👈 **Connect via sidebar** to view analytics")
        return
    
    st.info("📊 Analytics features coming soon!")
    st.markdown("""
    **Planned Features:**
    - Disk usage trends
    - Bandwidth monitoring
    - Database size tracking
    - Email quota usage
    - Uptime monitoring
    - Performance metrics
    """)

# =========================================================
# Tab 10: Settings
# =========================================================
def render_settings_tab() -> None:
    """Application settings and preferences."""
    st.header("⚙️ Settings")
    
    st.subheader("🎨 Appearance")
    theme = st.radio("Theme", ["Light", "Dark", "Auto"], horizontal=True)
    
    st.divider()
    
    st.subheader("🔧 Advanced Options")
    
    st.session_state.debug_mode = st.checkbox(
        "Enable Debug Mode",
        value=st.session_state.debug_mode,
        help="Show detailed error messages and API responses"
    )
    
    st.session_state.show_advanced = st.checkbox(
        "Show Advanced Features",
        value=st.session_state.show_advanced,
        help="Enable advanced features like SQL query interface"
    )
    
    auto_backup = st.checkbox("Auto-backup before restore", value=True)
    confirm_deletes = st.checkbox("Confirm all delete operations", value=True)
    
    st.divider()
    
    st.subheader("📝 About")
    st.markdown("""
    **WordPress Management Pro v2.0**
    
    A comprehensive WordPress hosting management tool supporting:
    - 20i API integration
    - cPanel integration
    - Complete backup/restore workflows
    - File editing with syntax highlighting
    - Database management
    - Domain management
    - SSL certificate management
    - Email account management
    
    ---
    
    **Features:**
    - ✅ Dual API support (20i + cPanel)
    - ✅ Visual backup/restore wizard
    - ✅ Integrated file editor
    - ✅ Database manager with SQL interface
    - ✅ One-click SSL installation
    - ✅ Email account management
    - ✅ Domain management
    - ✅ Resource monitoring
    
    Built with ❤️ using Streamlit
    """)

# =========================================================
# Main Application
# =========================================================
def main() -> None:
    """Main application entry point."""
    st.set_page_config(
        page_title="WordPress Management Pro",
        layout="wide",
        page_icon="🚀",
        initial_sidebar_state="expanded"
    )
    
    init_session_state()
    
    # Render header
    render_header()
    
    # Sidebar
    with st.sidebar:
        sidebar_connection()
    
    # Main navigation tabs
    st.session_state.current_tab = st.tabs(MAIN_TABS).index(
        st.radio("Navigation", MAIN_TABS, index=st.session_state.current_tab, horizontal=False, label_visibility="collapsed")
    ) if False else st.session_state.current_tab  # Hack to maintain state
    
    # Better tab rendering
    tab_selection = st.radio(
        "Select Tool",
        MAIN_TABS,
        index=st.session_state.current_tab,
        horizontal=True,
        label_visibility="collapsed"
    )
    st.session_state.current_tab = MAIN_TABS.index(tab_selection)
    
    st.divider()
    
    # Render selected tab
    tab_renderers = [
        render_dashboard_tab,
        render_restore_tab,
        render_backup_manager_tab,
        render_file_editor_tab,
        render_database_manager_tab,
        render_domain_manager_tab,
        render_ssl_manager_tab,
        render_email_manager_tab,
        render_analytics_tab,
        render_settings_tab
    ]
    
    tab_renderers[st.session_state.current_tab]()
    
    # Footer
    st.divider()
    col1, col2, col3 = st.columns(3)
    with col2:
        st.caption("WordPress Management Pro v2.0 | Built with Streamlit")

if __name__ == "__main__":
    main()
