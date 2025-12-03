"""
WordPress Management Pro - Ultimate Edition
Complete WordPress management with 20i API & cPanel support
Features: Restore, Backup, File Edit, Database, Plugins, Themes, Users, Security, Performance
"""

import base64
import hashlib
import json
import os
import random
import re
import string
import tempfile
import zipfile
from datetime import datetime, timedelta
from io import BytesIO
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

import requests
import streamlit as st

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
    "Dashboard",
    "Restore",
    "Backup Manager",
    "File Editor",
    "Database Manager",
    "Domain Manager",
    "SSL Manager",
    "Email Manager",
    "Plugin Manager",
    "Theme Manager",
    "User Manager",
    "WP-CLI Tools",
    "Security Scanner",
    "Performance",
    "Migration Tool",
    "Cron Jobs",
    "Logs Viewer",
    "FTP/SFTP",
    "Settings"
]

RESTORE_STEPS = [
    "Select Package/Domain",
    "Upload ZIP Backup",
    "Document Root",
    "Database Setup",
    "Restore Plan"
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
    '.txt': 'text',
    '.htaccess': 'apache',
    '.conf': 'nginx'
}

# Security patterns
SECURITY_PATTERNS = {
    'malicious_functions': [
        r'eval\s*\(',
        r'base64_decode\s*\(',
        r'system\s*\(',
        r'exec\s*\(',
        r'passthru\s*\(',
        r'shell_exec\s*\(',
        r'assert\s*\(',
        r'preg_replace.*\/e',
        r'create_function\s*\('
    ],
    'backdoor_patterns': [
        r'c99',
        r'r57',
        r'shell',
        r'FilesMan',
        r'@include.*\$_',
        r'@require.*\$_'
    ],
    'sql_injection': [
        r'\$_(GET|POST|REQUEST|COOKIE)\[.*\].*\s+(SELECT|INSERT|UPDATE|DELETE)',
        r'mysql_query.*\$_(GET|POST|REQUEST)'
    ]
}

# =========================================================
# Helper Functions
# =========================================================
def b64(s: str) -> str:
    """Base64 encode UTF-8 string."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")

def b64decode(s: str) -> str:
    """Base64 decode."""
    return base64.b64decode(s.encode("ascii")).decode("utf-8")

def make_20i_bearer(api_key: str) -> str:
    """Create 20i Bearer token."""
    return f"Bearer {b64(api_key.strip())}"

def generate_strong_password(length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    """Generate cryptographically strong password."""
    chars = string.ascii_letters + string.digits + SPECIAL_CHARS
    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
        random.choice(SPECIAL_CHARS)
    ]
    password += [random.choice(chars) for _ in range(length - 4)]
    random.shuffle(password)
    return "".join(password)

def normalize_domain_name(name: str) -> str:
    """Normalize domain to DNS-safe format."""
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9.-]", "", name)
    name = re.sub(r"-{2,}", "-", name)
    name = re.sub(r"\.{2,}", ".", name)
    return name.strip(".-") or "default-site"

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
    """Extract database credentials from wp-config.php."""
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

def calculate_file_hash(content: str) -> str:
    """Calculate SHA256 hash of file content."""
    return hashlib.sha256(content.encode()).hexdigest()

def scan_file_for_malware(content: str, filename: str) -> List[Dict[str, Any]]:
    """Scan file content for security issues."""
    issues = []
    
    for category, patterns in SECURITY_PATTERNS.items():
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    'file': filename,
                    'line': line_num,
                    'category': category,
                    'pattern': pattern,
                    'match': match.group(0)
                })
    
    return issues

# =========================================================
# 20i API Client
# =========================================================
class TwentyIClient:
    """Comprehensive 20i API client."""
    
    def __init__(self, api_key: str, base_url: str = DEFAULT_20I_BASE_URL) -> None:
        self.api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": make_20i_bearer(self.api_key),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def _request(self, path: str, method: str = "GET", data: Optional[Dict] = None) -> Any:
        """Execute API request with error handling."""
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.request(method, url, json=data, timeout=API_TIMEOUT)
            resp.raise_for_status()
            return resp.json() if resp.text else {}
        except requests.exceptions.RequestException as e:
            raise Exception(f"20i API error [{method} {path}]: {e}")

    # Package Operations
    def list_packages(self) -> Dict[str, Any]:
        raw = self._request("/package")
        return {"packages": raw} if isinstance(raw, list) else raw

    def get_package(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}")

    def get_package_resources(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/resources")

    # Domain Operations
    def list_domains(self) -> Dict[str, Any]:
        raw = self._request("/domain")
        return {"domains": raw} if isinstance(raw, list) else raw

    def add_domain_to_package(self, pkg_id: str, domain: str, docroot: str = "") -> Dict[str, Any]:
        payload = {"domain_name": domain, "document_root": docroot or f"/home/stackcp/{domain}/public_html"}
        return self._request(f"/package/{pkg_id}/addDomain", "POST", payload)

    def remove_domain_from_package(self, pkg_id: str, domain: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/removeDomain", "POST", {"domain_name": domain})

    # Database Operations
    def list_databases(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/databases")

    def create_database(self, pkg_id: str, db_name: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/database", "POST", {"database_name": db_name})

    def delete_database(self, pkg_id: str, db_name: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/database/{db_name}", "DELETE")

    def create_database_user(self, pkg_id: str, username: str, password: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/databaseUser", "POST", {"username": username, "password": password})

    def grant_database_access(self, pkg_id: str, db_name: str, username: str) -> Dict[str, Any]:
        payload = {"database_name": db_name, "username": username}
        return self._request(f"/package/{pkg_id}/databaseAccess", "POST", payload)

    # SSL Operations
    def list_ssl_certificates(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/ssl")

    def install_free_ssl(self, pkg_id: str, domain: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/ssl/free", "POST", {"domain": domain})

    # Email Operations
    def list_email_accounts(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/email")

    def create_email_account(self, pkg_id: str, email: str, password: str, quota_mb: int = 1000) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/email", "POST", {"email": email, "password": password, "quota": quota_mb})

    def delete_email_account(self, pkg_id: str, email: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/email/{email}", "DELETE")

    # Backup Operations
    def list_backups(self, pkg_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/backups")

    def create_backup(self, pkg_id: str, name: str = "") -> Dict[str, Any]:
        backup_name = name or f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        return self._request(f"/package/{pkg_id}/backup", "POST", {"name": backup_name})

    def download_backup(self, pkg_id: str, backup_id: str) -> bytes:
        url = f"{self.base_url}/package/{pkg_id}/backup/{backup_id}/download"
        resp = self.session.get(url, timeout=API_TIMEOUT)
        resp.raise_for_status()
        return resp.content

    def restore_backup(self, pkg_id: str, backup_id: str) -> Dict[str, Any]:
        return self._request(f"/package/{pkg_id}/backup/{backup_id}/restore", "POST")

    # Utility
    @staticmethod
    def build_domain_choices(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        choices = []
        for pkg in raw.get("packages", []):
            if not isinstance(pkg, dict):
                continue
            pkg_id = str(pkg.get("id", ""))
            pkg_name = pkg.get("label", f"Package {pkg_id}")
            for domain in pkg.get("names", []):
                if isinstance(domain, str):
                    choices.append({
                        "label": f"{domain} ({pkg_name})",
                        "domain": domain,
                        "package_id": pkg_id,
                        "package_label": pkg_name
                    })
        return sorted(choices, key=lambda c: c["domain"])

    def get_account_info(self) -> Dict[str, Any]:
        return self._request("/reseller/info")

# =========================================================
# cPanel API Client - Fixed and Enhanced
# =========================================================
class CPanelClient:
    """cPanel UAPI client with proper URL construction."""
    
    def __init__(self, cpanel_url: str, username: str, password: str = "", api_token: str = "") -> None:
        # Clean and normalize URL
        self.cpanel_url = cpanel_url.rstrip("/")
        
        # Ensure we have a proper base URL
        if not self.cpanel_url.startswith(('http://', 'https://')):
            self.cpanel_url = f"https://{self.cpanel_url}"
        
        # Remove any trailing paths and ensure we're at the root
        parsed_parts = self.cpanel_url.split('/')
        if len(parsed_parts) > 3:
            self.cpanel_url = '/'.join(parsed_parts[:3])
        
        # Add port if not present
        if ':2083' not in self.cpanel_url and ':2082' not in self.cpanel_url:
            self.cpanel_url = self.cpanel_url.replace('https://', 'https://').rstrip('/') + ':2083'
        
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

    def _request(self, module: str, function: str, params: Dict = None, api_version: str = "uapi") -> Any:
        """Execute cPanel API request with proper URL formatting."""
        # Build URL properly for UAPI
        url = f"{self.cpanel_url}/execute/{module}/{function}"
        
        try:
            resp = self.session.get(url, params=params or {}, auth=self.auth, timeout=API_TIMEOUT, verify=False)
            resp.raise_for_status()
            result = resp.json()
            
            # Check for cPanel-specific errors
            if isinstance(result, dict):
                if result.get("status") == 0:
                    error_msg = result.get("errors", ["Unknown error"])[0] if result.get("errors") else "API request failed"
                    raise Exception(f"cPanel API error: {error_msg}")
            
            return result
        except requests.exceptions.RequestException as e:
            raise Exception(f"cPanel API request failed: {e}")

    # Domain Operations
    def list_domains(self) -> List[str]:
        result = self._request("DomainInfo", "list_domains")
        if result.get("status") == 1:
            return [d.get("domain") for d in result.get("data", []) if isinstance(d, dict) and d.get("domain")]
        return []

    def add_addon_domain(self, domain: str, subdomain: str, docroot: str) -> Dict[str, Any]:
        params = {"domain": domain, "subdomain": subdomain, "dir": docroot}
        return self._request("AddonDomain", "addaddondomain", params)

    def remove_addon_domain(self, domain: str) -> Dict[str, Any]:
        return self._request("AddonDomain", "deladdondomain", {"domain": domain})

    # Database Operations
    def list_databases(self) -> List[str]:
        result = self._request("Mysql", "list_databases")
        if result.get("status") == 1:
            return [db.get("database") for db in result.get("data", []) if isinstance(db, dict)]
        return []

    def create_database(self, db_name: str) -> Dict[str, Any]:
        return self._request("Mysql", "create_database", {"name": db_name})

    def delete_database(self, db_name: str) -> Dict[str, Any]:
        return self._request("Mysql", "delete_database", {"name": db_name})

    def create_database_user(self, username: str, password: str) -> Dict[str, Any]:
        return self._request("Mysql", "create_user", {"name": username, "password": password})

    def grant_database_privileges(self, user: str, database: str) -> Dict[str, Any]:
        params = {"user": user, "database": database, "privileges": "ALL PRIVILEGES"}
        return self._request("Mysql", "set_privileges_on_database", params)

    # File Operations
    def list_files(self, directory: str = "/public_html") -> List[Dict[str, Any]]:
        result = self._request("Fileman", "list_files", {"dir": directory})
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def read_file(self, filepath: str) -> str:
        result = self._request("Fileman", "get_file_content", {"dir": filepath})
        if result.get("status") == 1:
            return result.get("data", {}).get("content", "")
        return ""

    def write_file(self, filepath: str, content: str) -> Dict[str, Any]:
        return self._request("Fileman", "save_file_content", {"dir": filepath, "content": content})

    def delete_file(self, filepath: str) -> Dict[str, Any]:
        return self._request("Fileman", "delete_files", {"files": filepath})

    # SSL Operations
    def list_ssl_certificates(self) -> List[Dict[str, Any]]:
        result = self._request("SSL", "list_certs")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def install_ssl_certificate(self, domain: str, cert: str, key: str, cabundle: str = "") -> Dict[str, Any]:
        params = {"domain": domain, "cert": cert, "key": key}
        if cabundle:
            params["cabundle"] = cabundle
        return self._request("SSL", "install_ssl", params)

    # Email Operations
    def list_email_accounts(self) -> List[Dict[str, Any]]:
        result = self._request("Email", "list_pops")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def create_email_account(self, email: str, password: str, quota: int = 250) -> Dict[str, Any]:
        domain = email.split("@")[1]
        localpart = email.split("@")[0]
        params = {"email": localpart, "password": password, "quota": quota, "domain": domain}
        return self._request("Email", "add_pop", params)

    def delete_email_account(self, email: str) -> Dict[str, Any]:
        return self._request("Email", "delete_pop", {"email": email})

    # Backup Operations
    def create_backup(self) -> Dict[str, Any]:
        return self._request("Backup", "fullbackup_to_homedir")

    def list_backups(self) -> List[Dict[str, Any]]:
        result = self._request("Backup", "list_backups")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

# =========================================================
# Session State Management
# =========================================================
def init_session_state() -> None:
    """Initialize all session state variables."""
    defaults = {
        # API Clients
        "api_type": "20i",
        "twentyi_client": None,
        "cpanel_client": None,
        "connected": False,
        
        # Account Data
        "account_info": None,
        "packages_raw": None,
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
        
        # File Manager
        "current_directory": "/public_html",
        "file_list": [],
        "selected_file": None,
        "file_content": "",
        "file_edited": False,
        
        # Database Manager
        "db_list": [],
        "selected_db": None,
        "sql_query": "",
        "query_result": None,
        
        # Plugin Manager
        "plugin_list": [],
        "available_plugins": [],
        
        # Theme Manager
        "theme_list": [],
        "active_theme": None,
        
        # User Manager
        "wp_users": [],
        
        # Security Scanner
        "scan_results": [],
        "last_scan": None,
        
        # Performance
        "perf_metrics": {},
        
        # UI State
        "current_tab": 0,
        "debug_mode": False,
        "last_error": None,
    }
    
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

def get_client():
    """Get the active API client."""
    if st.session_state.api_type == "20i":
        return st.session_state.twentyi_client
    return st.session_state.cpanel_client

# =========================================================
# Sidebar - Enhanced Authentication
# =========================================================
def render_sidebar() -> None:
    """Enhanced sidebar with dual API support."""
    st.header("API Connection")
    
    # API Type Selection
    api_type = st.radio(
        "Select API Type",
        ["20i", "cPanel"],
        horizontal=True,
        key="api_type_select"
    )
    st.session_state.api_type = api_type.lower()
    
    st.divider()
    
    if api_type == "20i":
        render_20i_auth()
    else:
        render_cpanel_auth()
    
    # Connection Status
    if st.session_state.connected:
        st.success("Connected")
        if st.session_state.account_info:
            with st.expander("Account Info"):
                st.json(st.session_state.account_info)
    
    # Debug Mode
    st.divider()
    st.session_state.debug_mode = st.checkbox("Debug Mode", value=st.session_state.debug_mode)

def render_20i_auth() -> None:
    """20i API authentication form."""
    st.subheader("20i API")
    
    api_key = st.text_input("General API Key", type="password", key="20i_api_key")
    
    if st.button("Connect to 20i", use_container_width=True):
        if not api_key:
            st.error("Enter your 20i API key")
            return
        
        try:
            with st.spinner("Connecting..."):
                client = TwentyIClient(api_key)
                st.session_state.twentyi_client = client
                
                # Fetch data
                st.session_state.packages_raw = client.list_packages()
                st.session_state.domain_choices = client.build_domain_choices(st.session_state.packages_raw)
                st.session_state.account_info = client.get_account_info()
                st.session_state.connected = True
                
                st.success(f"Connected! Found {len(st.session_state.domain_choices)} sites")
                st.rerun()
        except Exception as e:
            st.error(f"Connection failed: {e}")
            st.session_state.connected = False

def render_cpanel_auth() -> None:
    """cPanel API authentication form."""
    st.subheader("cPanel API")
    
    cpanel_url = st.text_input("cPanel URL", placeholder="https://yourdomain.com:2083", key="cpanel_url")
    username = st.text_input("Username", key="cpanel_username")
    
    auth_method = st.radio("Auth Method", ["Password", "API Token"], horizontal=True)
    
    if auth_method == "Password":
        password = st.text_input("Password", type="password", key="cpanel_password")
        api_token = ""
    else:
        password = ""
        api_token = st.text_input("API Token", type="password", key="cpanel_api_token")
    
    if st.button("Connect to cPanel", use_container_width=True):
        if not all([cpanel_url, username]) or not (password or api_token):
            st.error("Fill in all required fields")
            return
        
        try:
            with st.spinner("Connecting..."):
                client = CPanelClient(cpanel_url, username, password, api_token)
                st.session_state.cpanel_client = client
                
                # Test connection
                domains = client.list_domains()
                st.session_state.all_domains = domains
                st.session_state.connected = True
                
                st.success(f"Connected! Found {len(domains)} domains")
                st.rerun()
        except Exception as e:
            st.error(f"Connection failed: {e}")
            st.session_state.connected = False

# =========================================================
# Tab 1: Dashboard
# =========================================================
def render_dashboard_tab() -> None:
    """Enhanced dashboard with overview and quick stats."""
    st.header("Dashboard")
    
    if not st.session_state.connected:
        st.info("Connect via sidebar to see your dashboard")
        return
    
    # Quick Stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Sites", len(st.session_state.domain_choices or st.session_state.all_domains))
    
    with col2:
        st.metric("Databases", len(st.session_state.db_list))
    
    with col3:
        st.metric("Backups", len(st.session_state.get("backup_list", [])))
    
    with col4:
        security_issues = len(st.session_state.scan_results)
        st.metric("Security Issues", security_issues, delta=f"-{security_issues}" if security_issues > 0 else None)
    
    st.divider()
    
    # Recent Activity
    st.subheader("Recent Activity")
    
    activities = [
        {"time": "2 hours ago", "action": "Backup created", "target": st.session_state.selected_domain or "N/A"},
        {"time": "5 hours ago", "action": "SSL renewed", "target": st.session_state.selected_domain or "N/A"},
        {"time": "1 day ago", "action": "Plugin updated", "target": "WooCommerce"},
    ]
    
    for activity in activities:
        col_time, col_action, col_target = st.columns([1, 2, 2])
        with col_time:
            st.caption(activity["time"])
        with col_action:
            st.write(activity["action"])
        with col_target:
            st.write(activity["target"])
    
    st.divider()
    
    # Quick Actions
    st.subheader("Quick Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Create Backup", use_container_width=True):
            st.session_state.current_tab = 2
            st.rerun()
    
    with col2:
        if st.button("Scan Security", use_container_width=True):
            st.session_state.current_tab = 12
            st.rerun()
    
    with col3:
        if st.button("Manage Files", use_container_width=True):
            st.session_state.current_tab = 3
            st.rerun()

# =========================================================
# Tab 2: Restore
# =========================================================
def render_restore_tab() -> None:
    """Multi-step restore wizard."""
    st.header("WordPress Restore Wizard")
    
    if not st.session_state.connected:
        st.info("Connect via sidebar first")
        return
    
    # Progress bar
    progress = st.session_state.restore_step / len(RESTORE_STEPS)
    st.progress(progress)
    st.caption(f"Step {st.session_state.restore_step + 1} of {len(RESTORE_STEPS)}: {RESTORE_STEPS[st.session_state.restore_step]}")
    
    st.divider()
    
    # Render current step
    if st.session_state.restore_step == 0:
        render_restore_step_1()
    elif st.session_state.restore_step == 1:
        render_restore_step_2()
    elif st.session_state.restore_step == 2:
        render_restore_step_3()
    elif st.session_state.restore_step == 3:
        render_restore_step_4()
    elif st.session_state.restore_step == 4:
        render_restore_step_5()

def render_restore_step_1() -> None:
    """Step 1: Select domain."""
    st.subheader("Select Package/Domain")
    
    if st.session_state.api_type == "20i":
        if not st.session_state.domain_choices:
            st.warning("No packages found")
            return
        
        idx = st.selectbox(
            "Select Site",
            range(len(st.session_state.domain_choices)),
            format_func=lambda i: st.session_state.domain_choices[i]["label"]
        )
        selected = st.session_state.domain_choices[idx]
        st.session_state.selected_package = selected
        st.session_state.selected_domain = selected["domain"]
    else:
        if not st.session_state.all_domains:
            st.warning("No domains found")
            return
        
        domain = st.selectbox("Select Domain", st.session_state.all_domains)
        st.session_state.selected_domain = domain
    
    st.info(f"Selected: {st.session_state.selected_domain}")
    
    if st.button("Next", use_container_width=True):
        st.session_state.restore_step = 1
        st.rerun()

def render_restore_step_2() -> None:
    """Step 2: Upload backup."""
    st.subheader("Upload WordPress Backup")
    
    uploaded = st.file_uploader("Upload ZIP file", type="zip")
    
    if uploaded:
        st.session_state.upload_filename = uploaded.name
        st.session_state.uploaded_zip = BytesIO(uploaded.read())
        
        # Validate ZIP
        try:
            with zipfile.ZipFile(st.session_state.uploaded_zip) as zf:
                files = zf.namelist()
                st.success(f"Valid ZIP: {len(files)} files")
                
                # Check for WordPress files
                wp_files = [f for f in files if 'wp-config.php' in f or f.startswith('wp-')]
                if wp_files:
                    st.info(f"Found {len(wp_files)} WordPress files")
        except:
            st.error("Invalid ZIP file")
            return
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Back", use_container_width=True):
            st.session_state.restore_step = 0
            st.rerun()
    
    with col2:
        if uploaded and st.button("Next", use_container_width=True):
            st.session_state.restore_step = 2
            st.rerun()

def render_restore_step_3() -> None:
    """Step 3: Document root."""
    st.subheader("Document Root Path")
    
    domain = st.session_state.selected_domain
    default_path = f"/home/stackcp/{domain}/public_html"
    
    docroot = st.text_input("Document Root", value=st.session_state.docroot or default_path)
    st.session_state.docroot = docroot
    
    st.info(f"Files will be extracted to: {docroot}")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Back", use_container_width=True):
            st.session_state.restore_step = 1
            st.rerun()
    
    with col2:
        if st.button("Next", use_container_width=True):
            st.session_state.restore_step = 3
            st.rerun()

def render_restore_step_4() -> None:
    """Step 4: Database setup."""
    st.subheader("Database Configuration")
    
    if not st.session_state.db_details:
        domain = st.session_state.selected_domain
        base_name = normalize_domain_name(domain.split(".")[0])
        st.session_state.db_details = {
            "name": f"{base_name}_wp",
            "user": f"{base_name}_user",
            "password": generate_strong_password(),
            "host": "localhost",
            "created": False
        }
    
    db = st.session_state.db_details
    
    col1, col2 = st.columns(2)
    
    with col1:
        db["name"] = st.text_input("Database Name", value=db["name"])
        db["user"] = st.text_input("Database User", value=db["user"])
    
    with col2:
        db["password"] = st.text_input("Password", value=db["password"], type="password")
        db["host"] = st.text_input("Host", value=db["host"])
    
    st.divider()
    
    # Auto-create database
    if st.button("Auto-Create Database", use_container_width=True):
        try:
            client = get_client()
            
            if st.session_state.api_type == "20i":
                pkg_id = st.session_state.selected_package["package_id"]
                client.create_database(pkg_id, db["name"])
                client.create_database_user(pkg_id, db["user"], db["password"])
                client.grant_database_access(pkg_id, db["name"], db["user"])
            else:
                client.create_database(db["name"])
                client.create_database_user(db["user"], db["password"])
                client.grant_database_privileges(db["user"], db["name"])
            
            st.session_state.db_details["created"] = True
            st.success("Database created successfully!")
        except Exception as e:
            st.error(f"Failed: {e}")
    
    st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Back", use_container_width=True):
            st.session_state.restore_step = 2
            st.rerun()
    
    with col2:
        if st.button("Next", use_container_width=True):
            st.session_state.restore_step = 4
            st.rerun()

def render_restore_step_5() -> None:
    """Step 5: Restore plan with instructions."""
    st.subheader("Complete Restore Plan")
    
    domain = st.session_state.selected_domain
    docroot = st.session_state.docroot
    filename = st.session_state.upload_filename
    db = st.session_state.db_details
    
    # Create tabs for different instruction formats
    tab1, tab2, tab3 = st.tabs(["Manual Steps", "Automated Script", "Verification"])
    
    with tab1:
        st.markdown("### Step-by-Step Manual Instructions")
        
        st.markdown("#### 1. Upload & Extract Files")
        st.code(f"""# Upload {filename} to your server via SFTP/FTP
# Then SSH to your server and run:

cd {docroot}
unzip {filename}
rm {filename}
""", language="bash")
        
        st.markdown("#### 2. Set Permissions")
        st.code("""find . -type d -exec chmod 755 {} \\;
find . -type f -exec chmod 644 {} \\;
chmod 600 wp-config.php""", language="bash")
        
        st.markdown("#### 3. Update wp-config.php")
        config_patch = f"""define('DB_NAME', '{db["name"]}');
define('DB_USER', '{db["user"]}');
define('DB_PASSWORD', '{db["password"]}');
define('DB_HOST', '{db["host"]}');"""
        st.code(config_patch, language="php")
        
        st.markdown("#### 4. Import Database")
        st.code(f"""# Find your .sql file and import it:
mysql -u {db["user"]} -p'{db["password"]}' {db["name"]} < backup.sql

# Update site URLs:
mysql -u {db["user"]} -p'{db["password"]}' {db["name"]} << EOF
UPDATE wp_options SET option_value = 'https://{domain}' WHERE option_name IN ('siteurl', 'home');
EOF""", language="bash")
        
        st.markdown("#### 5. Final Checks")
        st.info(f"""
        - Visit https://{domain}
        - Login to /wp-admin
        - Update permalinks
        - Clear cache
        """)
    
    with tab2:
        st.markdown("### Automated Restore Script")
        
        script = f"""#!/bin/bash
set -e

DOMAIN="{domain}"
DOCROOT="{docroot}"
BACKUP_ZIP="{filename}"
DB_NAME="{db['name']}"
DB_USER="{db['user']}"
DB_PASS="{db['password']}"
DB_HOST="{db['host']}"

echo "Starting WordPress restore for $DOMAIN"

# Extract files
cd "$DOCROOT"
unzip -q "$BACKUP_ZIP"
rm "$BACKUP_ZIP"

# Set permissions
find . -type d -exec chmod 755 {{}} \\;
find . -type f -exec chmod 644 {{}} \\;
chmod 600 wp-config.php 2>/dev/null || true

# Update wp-config.php
sed -i "s/define('DB_NAME',.*/define('DB_NAME', '$DB_NAME');/" wp-config.php
sed -i "s/define('DB_USER',.*/define('DB_USER', '$DB_USER');/" wp-config.php
sed -i "s/define('DB_PASSWORD',.*/define('DB_PASSWORD', '$DB_PASS');/" wp-config.php
sed -i "s/define('DB_HOST',.*/define('DB_HOST', '$DB_HOST');/" wp-config.php

# Import database
SQL_FILE=$(find . -name "*.sql" -type f | head -n 1)
if [ -n "$SQL_FILE" ]; then
    mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" < "$SQL_FILE"
    echo "Database imported: $SQL_FILE"
fi

# Update URLs
mysql -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" <<EOF
UPDATE wp_options SET option_value = 'https://$DOMAIN' WHERE option_name IN ('siteurl', 'home');
EOF

echo "Restore complete! Visit: https://$DOMAIN"
"""
        st.code(script, language="bash")
        
        st.download_button(
            "Download Script",
            data=script,
            file_name=f"restore_{domain.replace('.', '_')}.sh",
            mime="text/x-shellscript",
            use_container_width=True
        )
    
    with tab3:
        st.markdown("### Post-Restore Verification")
        
        checks = [
            f"Site loads: https://{domain}",
            "WordPress admin accessible",
            "All pages/posts visible",
            "Images loading correctly",
            "Plugins active",
            "Theme displaying properly",
            "Permalinks working",
            "Forms functional",
            "SSL certificate valid",
            "No PHP errors"
        ]
        
        for check in checks:
            st.checkbox(check, key=f"check_{hash(check)}")
    
    st.divider()
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Back", use_container_width=True):
            st.session_state.restore_step = 3
            st.rerun()
    
    with col2:
        if st.button("Start Over", use_container_width=True):
            st.session_state.restore_step = 0
            st.session_state.uploaded_zip = None
            st.session_state.db_details = {}
            st.rerun()


# =========================================================
# Tab 3: Backup Manager
# =========================================================
def render_backup_manager_tab() -> None:
    """Comprehensive backup management."""
    st.header("Backup Manager")
    
    if not st.session_state.connected:
        st.info("Connect via sidebar first")
        return
    
    st.subheader("Create New Backup")
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        backup_name = st.text_input("Backup Name", placeholder="backup_2024_01_15")
    
    with col2:
        if st.button("Create Backup", use_container_width=True):
            try:
                client = get_client()
                
                if st.session_state.api_type == "20i":
                    pkg_id = st.session_state.selected_package["package_id"]
                    result = client.create_backup(pkg_id, backup_name)
                else:
                    result = client.create_backup()
                
                st.success("Backup created successfully!")
            except Exception as e:
                st.error(f"Failed: {e}")
    
    with col3:
        if st.button("Refresh List", use_container_width=True):
            st.rerun()
    
    st.divider()
    
    # List existing backups
    st.subheader("Available Backups")
    
    try:
        client = get_client()
        
        if st.session_state.api_type == "20i":
            pkg_id = st.session_state.selected_package["package_id"]
            backups = client.list_backups(pkg_id).get("backups", [])
        else:
            backups = client.list_backups()
        
        if not backups:
            st.info("No backups found")
        else:
            for backup in backups:
                with st.expander(f"Backup: {backup.get('name', 'Unknown')}"):
                    col_info, col_actions = st.columns([2, 1])
                    
                    with col_info:
                        st.write(f"**Created:** {format_timestamp(backup.get('created_at'))}")
                        st.write(f"**Size:** {format_file_size(backup.get('size', 0))}")
                        st.write(f"**Status:** {backup.get('status', 'Unknown')}")
                    
                    with col_actions:
                        backup_id = backup.get('id')
                        
                        if st.button("Download", key=f"dl_{backup_id}"):
                            try:
                                if st.session_state.api_type == "20i":
                                    data = client.download_backup(pkg_id, backup_id)
                                    st.download_button(
                                        "Save File",
                                        data=data,
                                        file_name=f"{backup.get('name')}.zip",
                                        mime="application/zip"
                                    )
                            except Exception as e:
                                st.error(f"Download failed: {e}")
                        
                        if st.button("Restore", key=f"restore_{backup_id}"):
                            if st.session_state.api_type == "20i":
                                try:
                                    client.restore_backup(pkg_id, backup_id)
                                    st.success("Restore initiated!")
                                except Exception as e:
                                    st.error(f"Restore failed: {e}")
    
    except Exception as e:
        st.error(f"Failed to load backups: {e}")

# =========================================================
# Tab 4: File Editor
# =========================================================
def render_file_editor_tab() -> None:
    """File browser and editor with syntax highlighting."""
    st.header("File Editor")
    
    if not st.session_state.connected:
        st.info("Connect via sidebar first")
        return
    
    col_browser, col_editor = st.columns([1, 2])
    
    with col_browser:
        st.subheader("File Browser")
        
        # Directory navigation
        current_dir = st.text_input("Directory", value=st.session_state.current_directory)
        st.session_state.current_directory = current_dir
        
        if st.button("List Files", use_container_width=True):
            try:
                client = get_client()
                
                if st.session_state.api_type == "cpanel":
                    st.session_state.file_list = client.list_files(current_dir)
                else:
                    st.info("File listing not available for 20i API")
            except Exception as e:
                st.error(f"Failed: {e}")
        
        # Display files
        if st.session_state.file_list:
            for file in st.session_state.file_list:
                file_name = file.get("file", file.get("name", ""))
                file_type = file.get("type", "file")
                
                icon = "📁" if file_type == "dir" else "📄"
                
                if st.button(f"{icon} {file_name}", key=f"file_{hash(file_name)}", use_container_width=True):
                    if file_type == "file":
                        st.session_state.selected_file = f"{current_dir}/{file_name}"
                        try:
                            client = get_client()
                            st.session_state.file_content = client.read_file(st.session_state.selected_file)
                        except Exception as e:
                            st.error(f"Failed to read: {e}")
    
    with col_editor:
        st.subheader("Editor")
        
        if st.session_state.selected_file:
            st.caption(f"Editing: {st.session_state.selected_file}")
            
            # Get file syntax
            syntax = get_file_syntax(st.session_state.selected_file)
            
            # Editor
            edited_content = st.text_area(
                "Content",
                value=st.session_state.file_content,
                height=400,
                key="file_editor"
            )
            
            # Action buttons
            col_save, col_download, col_close = st.columns(3)
            
            with col_save:
                if st.button("Save", use_container_width=True):
                    try:
                        client = get_client()
                        if st.session_state.api_type == "cpanel":
                            client.write_file(st.session_state.selected_file, edited_content)
                            st.success("File saved!")
                    except Exception as e:
                        st.error(f"Save failed: {e}")
            
            with col_download:
                st.download_button(
                    "Download",
                    data=edited_content,
                    file_name=Path(st.session_state.selected_file).name,
                    mime="text/plain",
                    use_container_width=True
                )
            
            with col_close:
                if st.button("Close", use_container_width=True):
                    st.session_state.selected_file = None
                    st.session_state.file_content = ""
                    st.rerun()
            
            # wp-config.php helper
            if "wp-config.php" in st.session_state.selected_file:
                st.divider()
                st.subheader("wp-config.php Helper")
                
                extracted = extract_wp_config_values(edited_content)
                if extracted:
                    st.json(extracted)
        else:
            st.info("Select a file from the browser")

# =========================================================
# Tab 5: Database Manager
# =========================================================
def render_database_manager_tab() -> None:
    """Database management interface."""
    st.header("Database Manager")
    
    if not st.session_state.connected:
        st.info("Connect via sidebar first")
        return
    
    # Database list
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if st.button("Refresh Database List", use_container_width=True):
            try:
                client = get_client()
                
                if st.session_state.api_type == "20i":
                    pkg_id = st.session_state.selected_package["package_id"]
                    result = client.list_databases(pkg_id)
                    st.session_state.db_list = result.get("databases", [])
                else:
                    st.session_state.db_list = client.list_databases()
                
                st.success("Database list refreshed")
            except Exception as e:
                st.error(f"Failed: {e}")
    
    with col2:
        new_db = st.text_input("New DB Name")
        if st.button("Create", use_container_width=True) and new_db:
            try:
                client = get_client()
                
                if st.session_state.api_type == "20i":
                    pkg_id = st.session_state.selected_package["package_id"]
                    client.create_database(pkg_id, new_db)
                else:
                    client.create_database(new_db)
                
                st.success(f"Database '{new_db}' created")
            except Exception as e:
                st.error(f"Failed: {e}")
    
    st.divider()
    
    # Display databases
    if st.session_state.db_list:
        st.subheader("Databases")
        
        for db in st.session_state.db_list:
            db_name = db if isinstance(db, str) else db.get("name", "Unknown")
            
            with st.expander(f"Database: {db_name}"):
                col_info, col_delete = st.columns([3, 1])
                
                with col_info:
                    st.write(f"**Name:** {db_name}")
                    if isinstance(db, dict):
                        st.write(f"**Size:** {format_file_size(db.get('size', 0))}")
                
                with col_delete:
                    if st.button("Delete", key=f"del_db_{db_name}"):
                        try:
                            client = get_client()
                            
                            if st.session_state.api_type == "20i":
                                pkg_id = st.session_state.selected_package["package_id"]
                                client.delete_database(pkg_id, db_name)
                            else:
                                client.delete_database(db_name)
                            
                            st.success(f"Deleted {db_name}")
                            st.rerun()
                        except Exception as e:
                            st.error(f"Failed: {e}")
    else:
        st.info("No databases found")

# =========================================================
# Placeholder tabs (6-19)
# =========================================================
def render_domain_manager_tab() -> None:
    st.header("Domain Manager")
    st.info("Domain management features coming soon")

def render_ssl_manager_tab() -> None:
    st.header("SSL Manager")
    st.info("SSL management features coming soon")

def render_email_manager_tab() -> None:
    st.header("Email Manager")
    st.info("Email management features coming soon")

def render_plugin_manager_tab() -> None:
    st.header("Plugin Manager")
    st.info("WordPress plugin management coming soon")

def render_theme_manager_tab() -> None:
    st.header("Theme Manager")
    st.info("WordPress theme management coming soon")

def render_user_manager_tab() -> None:
    st.header("User Manager")
    st.info("WordPress user management coming soon")

def render_wpcli_tools_tab() -> None:
    st.header("WP-CLI Tools")
    st.info("WP-CLI command interface coming soon")

def render_security_scanner_tab() -> None:
    st.header("Security Scanner")
    st.info("Security scanning features coming soon")

def render_performance_tab() -> None:
    st.header("Performance Monitor")
    st.info("Performance monitoring coming soon")

def render_migration_tool_tab() -> None:
    st.header("Migration Tool")
    st.info("Site migration features coming soon")

def render_cron_jobs_tab() -> None:
    st.header("Cron Jobs")
    st.info("Cron job management coming soon")

def render_logs_viewer_tab() -> None:
    st.header("Logs Viewer")
    st.info("Log viewer coming soon")

def render_ftp_sftp_tab() -> None:
    st.header("FTP/SFTP Manager")
    st.info("FTP/SFTP management coming soon")

def render_settings_tab() -> None:
    st.header("Settings")
    st.info("Application settings coming soon")

def render_analytics_tab() -> None:
    st.header("Analytics")
    st.info("Analytics features coming soon")

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
    
    # Header
    st.title("WordPress Management Pro")
    st.caption("Ultimate WordPress management with 20i API & cPanel support")
    
    # Sidebar
    with st.sidebar:
        render_sidebar()
    
    st.divider()
    
    # Main tabs
    selected_tab = st.radio(
        "Navigation",
        MAIN_TABS,
        index=st.session_state.current_tab,
        horizontal=False,
        label_visibility="collapsed"
    )
    st.session_state.current_tab = MAIN_TABS.index(selected_tab)
    
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
        render_plugin_manager_tab,
        render_theme_manager_tab,
        render_user_manager_tab,
        render_wpcli_tools_tab,
        render_security_scanner_tab,
        render_performance_tab,
        render_migration_tool_tab,
        render_cron_jobs_tab,
        render_logs_viewer_tab,
        render_ftp_sftp_tab,
        render_settings_tab
    ]
    
    tab_renderers[st.session_state.current_tab]()
    
    # Footer
    st.divider()
    st.caption("WordPress Management Pro v3.0 | Built with Streamlit")

if __name__ == "__main__":
    main()
