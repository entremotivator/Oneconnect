"""
Enhanced WordPress Management Tool Pro - Ultimate Edition
Supports: 20i API, cPanel, WHM, Direct SSH, Backups, File Editing, Database Management, and Much More
Complete all-in-one solution for WordPress site management with extensive features
"""

import base64
import json
import os
import random
import re
import string
import tempfile
import zipfile
import hashlib
import subprocess
from datetime import datetime, timedelta
from io import BytesIO, StringIO
from typing import Any, Dict, List, Optional, Tuple, Union
from pathlib import Path
import threading
import time

try:
    import requests
except ImportError:
    raise ImportError("Install: pip install requests streamlit")

try:
    import streamlit as st
    from streamlit.delta_generator import DeltaGenerator
except ImportError:
    raise ImportError("Install: pip install streamlit")

# =========================================================
# Constants & Configuration
# =========================================================
VERSION = "3.0.0-Ultimate"
DEFAULT_20I_BASE_URL = "https://api.20i.com"
DEFAULT_PASSWORD_LENGTH = 16
DEFAULT_DOCROOT_TEMPLATE = "/home/stackcp/{domain}/public_html"
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
API_TIMEOUT = 60
MAX_FILE_SIZE_MB = 50
SUPPORTED_WP_VERSIONS = ["6.7", "6.6", "6.5", "6.4", "6.3"]

# UI Constants
MAIN_TABS = [
    "Dashboard",
    "Restore Wizard",
    "Backup Manager",
    "File Editor",
    "Database Manager",
    "Domain Manager",
    "SSL Manager",
    "Email Manager",
    "WP-CLI Tools",
    "Security Scanner",
    "Performance",
    "Migration Tool",
    "Cron Jobs",
    "Logs Viewer",
    "FTP/SFTP",
    "Settings"
]

# <CHANGE> Added comprehensive file syntax mappings
FILE_SYNTAX_MAP = {
    '.php': 'php',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'typescript',
    '.tsx': 'typescript',
    '.css': 'css',
    '.scss': 'scss',
    '.sass': 'sass',
    '.less': 'less',
    '.html': 'html',
    '.htm': 'html',
    '.xml': 'xml',
    '.json': 'json',
    '.sql': 'sql',
    '.py': 'python',
    '.sh': 'bash',
    '.bash': 'bash',
    '.yml': 'yaml',
    '.yaml': 'yaml',
    '.md': 'markdown',
    '.txt': 'text',
    '.conf': 'nginx',
    '.htaccess': 'apache',
    '.env': 'bash',
    '.log': 'log'
}

# Security patterns for scanning
SECURITY_PATTERNS = {
    'eval': r'eval\s*\(',
    'base64_decode': r'base64_decode\s*\(',
    'shell_exec': r'shell_exec\s*\(',
    'exec': r'exec\s*\(',
    'system': r'system\s*\(',
    'passthru': r'passthru\s*\(',
    'backdoor': r'(c99|r57|b374k|wso|shell|FilesMan)',
    'suspicious_functions': r'(assert|create_function|preg_replace.*\/e)',
}

# =========================================================
# Enhanced Helpers
# =========================================================
def b64(s: str) -> str:
    """Base64 encode UTF-8 string to ASCII-safe format."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")

def b64decode(s: str) -> str:
    """Base64 decode ASCII-safe string to UTF-8."""
    try:
        return base64.b64decode(s.encode("ascii")).decode("utf-8")
    except:
        return s

def make_20i_bearer(general_api_key: str) -> str:
    """Create 20i Bearer token from general API key."""
    return f"Bearer {b64(general_api_key.strip())}"

def generate_strong_password(length: int = DEFAULT_PASSWORD_LENGTH, include_special: bool = True) -> str:
    """Generate cryptographically strong password with options."""
    chars = string.ascii_letters + string.digits
    if include_special:
        chars += SPECIAL_CHARS
    
    # Ensure at least one of each type
    password = [
        random.choice(string.ascii_uppercase),
        random.choice(string.ascii_lowercase),
        random.choice(string.digits),
    ]
    if include_special:
        password.append(random.choice(SPECIAL_CHARS))
    
    # Fill the rest
    password.extend(random.choice(chars) for _ in range(length - len(password)))
    random.shuffle(password)
    
    return "".join(password)

def normalize_domain_name(name: str) -> str:
    """Normalize domain/subdomain to DNS-safe format."""
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9.-]", "", name)
    name = re.sub(r"-{2,}", "-", name)
    name = re.sub(r"\.{2,}", ".", name)
    name = name.strip(".-")
    return name or "default-site"

def format_timestamp(ts: Optional[Union[str, datetime]], fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format API timestamp for display with flexible input."""
    if not ts:
        return "N/A"
    
    if isinstance(ts, datetime):
        return ts.strftime(fmt)
    
    try:
        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
        return dt.strftime(fmt)
    except:
        # Try other common formats
        for date_fmt in ["%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M"]:
            try:
                dt = datetime.strptime(str(ts), date_fmt)
                return dt.strftime(fmt)
            except:
                continue
        return str(ts)[:19] if ts else "N/A"

def format_file_size(size_bytes: Union[int, float]) -> str:
    """Format file size in human-readable format."""
    try:
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    except:
        return "0 B"

def get_file_syntax(filename: str) -> str:
    """Get syntax highlighting language for file."""
    ext = Path(filename).suffix.lower()
    return FILE_SYNTAX_MAP.get(ext, 'text')

def extract_wp_config_values(content: str) -> Dict[str, str]:
    """Extract all important values from wp-config.php content."""
    patterns = {
        'DB_NAME': r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_USER': r"define\s*\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_PASSWORD': r"define\s*\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_HOST': r"define\s*\(\s*['\"]DB_HOST['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_CHARSET': r"define\s*\(\s*['\"]DB_CHARSET['\"]\s*,\s*['\"]([^'\"]+)['\"]",
        'DB_COLLATE': r"define\s*\(\s*['\"]DB_COLLATE['\"]\s*,\s*['\"]([^'\"]*)['\"]",
        'table_prefix': r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]",
        'WP_DEBUG': r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*(true|false)",
    }
    
    values = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            values[key] = match.group(1)
    
    # Extract salts
    salt_keys = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
                 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT']
    for salt_key in salt_keys:
        pattern = rf"define\s*\(\s*['\"{salt_key}['\"]\s*,\s*['\"]([^'\"]+)['\"]"
        match = re.search(pattern, content)
        if match:
            values[salt_key] = match.group(1)
    
    return values

def generate_wp_salts() -> Dict[str, str]:
    """Generate WordPress security salts."""
    salt_keys = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
                 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT']
    
    salts = {}
    for key in salt_keys:
        salts[key] = generate_strong_password(64, include_special=True)
    
    return salts

def calculate_file_hash(content: Union[str, bytes], algorithm: str = 'sha256') -> str:
    """Calculate hash of file content."""
    if isinstance(content, str):
        content = content.encode('utf-8')
    
    hasher = hashlib.new(algorithm)
    hasher.update(content)
    return hasher.hexdigest()

def is_valid_domain(domain: str) -> bool:
    """Validate domain name format."""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_email(email: str) -> bool:
    """Validate email address format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def sanitize_sql(sql: str) -> str:
    """Basic SQL sanitization for display purposes."""
    dangerous = ['DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'GRANT', 'REVOKE']
    for word in dangerous:
        if re.search(rf'\b{word}\b', sql, re.IGNORECASE):
            return f"-- WARNING: Contains {word} statement\n{sql}"
    return sql

# =========================================================
# Enhanced 20i API Client with Extended Features
# =========================================================
class TwentyIClient:
    """
    Comprehensive 20i API client with full hosting management capabilities.
    Supports packages, domains, databases, email, SSL, backups, and more.
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
        self.last_request_time = None

    def _request(self, path: str, method: str = "GET", data: Optional[Dict] = None, 
                 timeout: int = API_TIMEOUT, raw_response: bool = False) -> Any:
        """Enhanced request handler with rate limiting and retry logic."""
        url = f"{self.base_url}{path}"
        
        # Simple rate limiting
        if self.last_request_time:
            elapsed = time.time() - self.last_request_time
            if elapsed < 0.2:  # Max 5 requests per second
                time.sleep(0.2 - elapsed)
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = self.session.request(method, url, json=data, timeout=timeout)
                self.last_request_time = time.time()
                
                resp.raise_for_status()
                
                if raw_response:
                    return resp
                
                if not resp.text:
                    return {}
                
                return resp.json()
                
            except requests.exceptions.Timeout:
                if attempt == max_retries - 1:
                    raise Exception(f"Request timeout after {max_retries} attempts")
                time.sleep(1 * (attempt + 1))
                
            except requests.exceptions.RequestException as e:
                if attempt == max_retries - 1:
                    raise Exception(f"API request failed [{method} {path}]: {e}")
                time.sleep(1 * (attempt + 1))

    # === PACKAGE OPERATIONS ===
    def list_packages(self) -> Dict[str, Any]:
        """List all hosting packages with enhanced details."""
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
        """Get disk/memory/CPU/bandwidth usage for package."""
        return self._request(f"/package/{package_id}/resources")
    
    def get_package_limits(self, package_id: str) -> Dict[str, Any]:
        """Get package resource limits."""
        return self._request(f"/package/{package_id}/limits")

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
    
    def get_domain_dns(self, domain: str) -> Dict[str, Any]:
        """Get DNS records for domain."""
        return self._request(f"/domain/{domain}/dns")
    
    def update_domain_dns(self, domain: str, records: List[Dict]) -> Dict[str, Any]:
        """Update DNS records for domain."""
        return self._request(f"/domain/{domain}/dns", "POST", {"records": records})

    # === DATABASE OPERATIONS ===
    def list_databases(self, package_id: str) -> Dict[str, Any]:
        """List databases for package with usage stats."""
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

    def grant_database_access(self, package_id: str, db_name: str, username: str, 
                            privileges: str = "ALL") -> Dict[str, Any]:
        """Grant user access to database with specific privileges."""
        payload = {"database_name": db_name, "username": username, "privileges": privileges}
        return self._request(f"/package/{package_id}/databaseAccess", "POST", payload)
    
    def get_database_size(self, package_id: str, db_name: str) -> Dict[str, Any]:
        """Get database size and table count."""
        return self._request(f"/package/{package_id}/database/{db_name}/stats")

    # === SSL OPERATIONS ===
    def list_ssl_certificates(self, package_id: str) -> Dict[str, Any]:
        """List SSL certificates for package."""
        return self._request(f"/package/{package_id}/ssl")

    def install_free_ssl(self, package_id: str, domain: str, force: bool = False) -> Dict[str, Any]:
        """Install free Let's Encrypt SSL certificate."""
        payload = {"domain": domain, "force": force}
        return self._request(f"/package/{package_id}/ssl/free", "POST", payload)

    def get_ssl_status(self, package_id: str, domain: str) -> Dict[str, Any]:
        """Get SSL status and expiry for domain."""
        return self._request(f"/package/{package_id}/ssl/{domain}")
    
    def renew_ssl(self, package_id: str, domain: str) -> Dict[str, Any]:
        """Renew SSL certificate."""
        return self._request(f"/package/{package_id}/ssl/{domain}/renew", "POST")
    
    def install_custom_ssl(self, package_id: str, domain: str, cert: str, 
                          key: str, chain: str = "") -> Dict[str, Any]:
        """Install custom SSL certificate."""
        payload = {"domain": domain, "certificate": cert, "private_key": key, "chain": chain}
        return self._request(f"/package/{package_id}/ssl/custom", "POST", payload)

    # === EMAIL OPERATIONS ===
    def list_email_accounts(self, package_id: str) -> Dict[str, Any]:
        """List email accounts for package."""
        return self._request(f"/package/{package_id}/email")

    def create_email_account(self, package_id: str, email: str, password: str, 
                            quota_mb: int = 1000) -> Dict[str, Any]:
        """Create email account with quota."""
        payload = {"email": email, "password": password, "quota": quota_mb}
        return self._request(f"/package/{package_id}/email", "POST", payload)

    def delete_email_account(self, package_id: str, email: str) -> Dict[str, Any]:
        """Delete email account."""
        return self._request(f"/package/{package_id}/email/{email}", "DELETE")

    def update_email_password(self, package_id: str, email: str, new_password: str) -> Dict[str, Any]:
        """Update email account password."""
        payload = {"email": email, "password": new_password}
        return self._request(f"/package/{package_id}/email/password", "POST", payload)
    
    def update_email_quota(self, package_id: str, email: str, quota_mb: int) -> Dict[str, Any]:
        """Update email account quota."""
        payload = {"email": email, "quota": quota_mb}
        return self._request(f"/package/{package_id}/email/quota", "POST", payload)
    
    def get_email_forwarders(self, package_id: str) -> Dict[str, Any]:
        """List email forwarders."""
        return self._request(f"/package/{package_id}/email/forwarders")
    
    def create_email_forwarder(self, package_id: str, source: str, destination: str) -> Dict[str, Any]:
        """Create email forwarder."""
        payload = {"source": source, "destination": destination}
        return self._request(f"/package/{package_id}/email/forwarder", "POST", payload)

    # === BACKUP OPERATIONS ===
    def list_backups(self, package_id: str) -> Dict[str, Any]:
        """List available backups for package."""
        return self._request(f"/package/{package_id}/backups")

    def create_backup(self, package_id: str, backup_name: str = "", 
                     backup_type: str = "full") -> Dict[str, Any]:
        """Create manual backup (full, files, or database)."""
        name = backup_name or f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        payload = {"name": name, "type": backup_type}
        return self._request(f"/package/{package_id}/backup", "POST", payload)

    def download_backup(self, package_id: str, backup_id: str) -> bytes:
        """Download backup file."""
        resp = self._request(f"/package/{package_id}/backup/{backup_id}/download", 
                           raw_response=True)
        return resp.content

    def restore_backup(self, package_id: str, backup_id: str, 
                      restore_type: str = "full") -> Dict[str, Any]:
        """Restore from backup (full, files, or database)."""
        payload = {"type": restore_type}
        return self._request(f"/package/{package_id}/backup/{backup_id}/restore", "POST", payload)
    
    def delete_backup(self, package_id: str, backup_id: str) -> Dict[str, Any]:
        """Delete backup."""
        return self._request(f"/package/{package_id}/backup/{backup_id}", "DELETE")
    
    def schedule_backup(self, package_id: str, frequency: str = "daily", 
                       retention_days: int = 30) -> Dict[str, Any]:
        """Schedule automatic backups."""
        payload = {"frequency": frequency, "retention": retention_days}
        return self._request(f"/package/{package_id}/backup/schedule", "POST", payload)

    # === CRON JOB OPERATIONS ===
    def list_cron_jobs(self, package_id: str) -> Dict[str, Any]:
        """List cron jobs for package."""
        return self._request(f"/package/{package_id}/cron")
    
    def create_cron_job(self, package_id: str, command: str, schedule: str, 
                       email: str = "") -> Dict[str, Any]:
        """Create cron job."""
        payload = {"command": command, "schedule": schedule, "email": email}
        return self._request(f"/package/{package_id}/cron", "POST", payload)
    
    def delete_cron_job(self, package_id: str, cron_id: str) -> Dict[str, Any]:
        """Delete cron job."""
        return self._request(f"/package/{package_id}/cron/{cron_id}", "DELETE")

    # === FILE OPERATIONS (if supported) ===
    def list_files(self, package_id: str, directory: str) -> Dict[str, Any]:
        """List files in directory."""
        return self._request(f"/package/{package_id}/files", "GET", {"dir": directory})
    
    def read_file(self, package_id: str, filepath: str) -> str:
        """Read file content."""
        result = self._request(f"/package/{package_id}/file", "GET", {"path": filepath})
        return result.get("content", "")
    
    def write_file(self, package_id: str, filepath: str, content: str) -> Dict[str, Any]:
        """Write file content."""
        payload = {"path": filepath, "content": content}
        return self._request(f"/package/{package_id}/file", "POST", payload)

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
            pkg_status = pkg.get("status", "unknown")
            names = pkg.get("names", [])
            
            for domain in names:
                if isinstance(domain, str):
                    choices.append({
                        "label": f"{domain} ({pkg_name}) [{pkg_status}]",
                        "domain": domain,
                        "package_id": pkg_id,
                        "package_label": pkg_name,
                        "status": pkg_status
                    })
        
        return sorted(choices, key=lambda c: c["domain"])

    def get_account_info(self) -> Dict[str, Any]:
        """Get basic reseller/account info."""
        return self._request("/reseller/info")
    
    def get_account_balance(self) -> Dict[str, Any]:
        """Get account balance and billing info."""
        return self._request("/reseller/balance")

# =========================================================
# Enhanced cPanel API Client with Fixed URLs
# =========================================================
class CPanelClient:
    """
    cPanel UAPI/API2 client with proper URL handling and extended features.
    Supports all major cPanel operations for WordPress management.
    """
    
    def __init__(self, cpanel_url: str, username: str, password: str = "", 
                 api_token: str = "", port: int = 2083) -> None:
        # <CHANGE> Fixed cPanel URL parsing to handle various formats
        self.username = username
        self.password = password
        self.api_token = api_token
        
        # Parse and normalize URL
        cpanel_url = cpanel_url.strip()
        if not cpanel_url.startswith(('http://', 'https://')):
            cpanel_url = f"https://{cpanel_url}"
        
        # Remove trailing slashes
        cpanel_url = cpanel_url.rstrip('/')
        
        # Handle port
        if ':' not in cpanel_url.split('//')[1]:
            cpanel_url = f"{cpanel_url}:{port}"
        
        self.cpanel_url = cpanel_url
        self.base_url = cpanel_url  # Store base for reference
        
        # <CHANGE> Setup proper cPanel authentication
        self.session = requests.Session()
        
        if api_token:
            # Use API token authentication
            self.session.headers.update({
                "Authorization": f"cpanel {username}:{api_token}",
                "Content-Type": "application/json"
            })
            self.auth = None
        else:
            # Use basic authentication
            self.session.headers.update({"Content-Type": "application/json"})
            self.auth = (username, password)
        
        self.last_request_time = None

    def _request(self, api_type: str, module: str, function: str, 
                 params: Dict = None, method: str = "GET") -> Any:
        """
        Execute cPanel API request with proper URL structure.
        api_type: 'uapi' for UAPI, 'api2' for API2
        """
        # <CHANGE> Fixed URL construction for cPanel
        if api_type == "uapi":
            url = f"{self.cpanel_url}/execute/{module}/{function}"
        else:  # api2
            url = f"{self.cpanel_url}/json-api/cpanel"
            if not params:
                params = {}
            params.update({
                "cpanel_jsonapi_user": self.username,
                "cpanel_jsonapi_apiversion": "2",
                "cpanel_jsonapi_module": module,
                "cpanel_jsonapi_func": function
            })
        
        # Rate limiting
        if self.last_request_time:
            elapsed = time.time() - self.last_request_time
            if elapsed < 0.2:
                time.sleep(0.2 - elapsed)
        
        try:
            if method.upper() == "POST":
                resp = self.session.post(url, json=params, auth=self.auth, 
                                        timeout=API_TIMEOUT, verify=False)
            else:
                resp = self.session.get(url, params=params, auth=self.auth, 
                                       timeout=API_TIMEOUT, verify=False)
            
            self.last_request_time = time.time()
            resp.raise_for_status()
            
            result = resp.json()
            
            # Handle different response formats
            if api_type == "uapi":
                if isinstance(result, dict):
                    if result.get("status") == 1:
                        return result
                    else:
                        error = result.get("errors", ["Unknown error"])[0]
                        raise Exception(f"cPanel error: {error}")
            
            return result
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"cPanel API request failed [{module}/{function}]: {e}")

    # === DOMAIN OPERATIONS ===
    def list_domains(self) -> List[Dict[str, Any]]:
        """List all domains in account with details."""
        result = self._request("uapi", "DomainInfo", "list_domains")
        if result.get("status") == 1:
            return result.get("data", [])
        return []
    
    def get_main_domain(self) -> str:
        """Get the main domain for account."""
        result = self._request("uapi", "DomainInfo", "main_domain")
        if result.get("status") == 1:
            return result.get("data", {}).get("domain", "")
        return ""

    def add_addon_domain(self, domain: str, subdomain: str, docroot: str) -> Dict[str, Any]:
        """Add addon domain."""
        params = {"domain": domain, "subdomain": subdomain, "dir": docroot}
        return self._request("uapi", "AddonDomain", "addaddondomain", params, "POST")

    def remove_addon_domain(self, domain: str) -> Dict[str, Any]:
        """Remove addon domain."""
        return self._request("uapi", "AddonDomain", "deladdondomain", {"domain": domain}, "POST")
    
    def list_addon_domains(self) -> List[Dict[str, Any]]:
        """List all addon domains."""
        result = self._request("uapi", "AddonDomain", "list_addon_domains")
        if result.get("status") == 1:
            return result.get("data", [])
        return []
    
    def add_subdomain(self, subdomain: str, domain: str, docroot: str) -> Dict[str, Any]:
        """Add subdomain."""
        params = {"domain": subdomain, "rootdomain": domain, "dir": docroot}
        return self._request("uapi", "SubDomain", "addsubdomain", params, "POST")

    # === DATABASE OPERATIONS ===
    def list_databases(self) -> List[Dict[str, Any]]:
        """List MySQL databases with details."""
        result = self._request("uapi", "Mysql", "list_databases")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def create_database(self, db_name: str) -> Dict[str, Any]:
        """Create MySQL database."""
        return self._request("uapi", "Mysql", "create_database", {"name": db_name}, "POST")

    def delete_database(self, db_name: str) -> Dict[str, Any]:
        """Delete MySQL database."""
        return self._request("uapi", "Mysql", "delete_database", {"name": db_name}, "POST")
    
    def list_database_users(self) -> List[Dict[str, Any]]:
        """List database users."""
        result = self._request("uapi", "Mysql", "list_users")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def create_database_user(self, username: str, password: str) -> Dict[str, Any]:
        """Create database user."""
        params = {"name": username, "password": password}
        return self._request("uapi", "Mysql", "create_user", params, "POST")
    
    def delete_database_user(self, username: str) -> Dict[str, Any]:
        """Delete database user."""
        return self._request("uapi", "Mysql", "delete_user", {"name": username}, "POST")

    def grant_database_privileges(self, user: str, database: str, 
                                  privileges: str = "ALL PRIVILEGES") -> Dict[str, Any]:
        """Grant privileges to user on database."""
        params = {"user": user, "database": database, "privileges": privileges}
        return self._request("uapi", "Mysql", "set_privileges_on_database", params, "POST")
    
    def revoke_database_privileges(self, user: str, database: str) -> Dict[str, Any]:
        """Revoke all privileges from user on database."""
        params = {"user": user, "database": database}
        return self._request("uapi", "Mysql", "revoke_access_to_database", params, "POST")
    
    def get_database_size(self, db_name: str) -> Dict[str, Any]:
        """Get database size."""
        result = self._request("uapi", "Mysql", "get_database_size", {"name": db_name})
        return result

    # === FILE OPERATIONS ===
    def list_files(self, directory: str = "public_html") -> List[Dict[str, Any]]:
        """List files in directory."""
        result = self._request("uapi", "Fileman", "list_files", {"dir": directory})
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def read_file(self, filepath: str) -> str:
        """Read file content."""
        result = self._request("uapi", "Fileman", "get_file_content", {"dir": filepath})
        if result.get("status") == 1:
            data = result.get("data", {})
            if isinstance(data, dict):
                return data.get("content", "")
            return str(data)
        return ""

    def write_file(self, filepath: str, content: str, permissions: str = "0644") -> Dict[str, Any]:
        """Write content to file."""
        params = {"dir": filepath, "content": content, "perms": permissions}
        return self._request("uapi", "Fileman", "save_file_content", params, "POST")

    def delete_file(self, filepath: str) -> Dict[str, Any]:
        """Delete file or directory."""
        return self._request("uapi", "Fileman", "delete_files", {"files": filepath}, "POST")
    
    def create_directory(self, dirpath: str, permissions: str = "0755") -> Dict[str, Any]:
        """Create directory."""
        params = {"name": dirpath, "perms": permissions}
        return self._request("uapi", "Fileman", "create_directory", params, "POST")
    
    def rename_file(self, old_path: str, new_path: str) -> Dict[str, Any]:
        """Rename or move file."""
        params = {"oldname": old_path, "newname": new_path}
        return self._request("uapi", "Fileman", "rename", params, "POST")
    
    def chmod_file(self, filepath: str, permissions: str) -> Dict[str, Any]:
        """Change file permissions."""
        params = {"path": filepath, "perms": permissions}
        return self._request("uapi", "Fileman", "set_permissions", params, "POST")
    
    def get_file_info(self, filepath: str) -> Dict[str, Any]:
        """Get file information."""
        result = self._request("uapi", "Fileman", "get_file_information", {"path": filepath})
        if result.get("status") == 1:
            return result.get("data", {})
        return {}
    
    def upload_file(self, directory: str, filename: str, content: bytes) -> Dict[str, Any]:
        """Upload file (simplified - actual implementation may need multipart)."""
        # This is a simplified version; actual file upload might need different handling
        filepath = f"{directory}/{filename}"
        return self.write_file(filepath, content.decode('utf-8', errors='ignore'))

    # === SSL OPERATIONS ===
    def list_ssl_certificates(self) -> List[Dict[str, Any]]:
        """List SSL certificates."""
        result = self._request("uapi", "SSL", "list_certs")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def install_ssl_certificate(self, domain: str, cert: str, key: str, 
                                cabundle: str = "") -> Dict[str, Any]:
        """Install SSL certificate."""
        params = {"domain": domain, "cert": cert, "key": key}
        if cabundle:
            params["cabundle"] = cabundle
        return self._request("uapi", "SSL", "install_ssl", params, "POST")
    
    def generate_ssl_certificate(self, domains: List[str], email: str) -> Dict[str, Any]:
        """Generate Let's Encrypt SSL certificate."""
        params = {"domains": ",".join(domains), "email": email}
        return self._request("uapi", "LetsEncrypt", "request_certificate", params, "POST")
    
    def get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate info for domain."""
        result = self._request("uapi", "SSL", "get_ssl_info", {"domain": domain})
        return result

    # === EMAIL OPERATIONS ===
    def list_email_accounts(self) -> List[Dict[str, Any]]:
        """List email accounts."""
        result = self._request("uapi", "Email", "list_pops")
        if result.get("status") == 1:
            return result.get("data", [])
        return []

    def create_email_account(self, email: str, password: str, quota: int = 250) -> Dict[str, Any]:
        """Create email account with quota in MB."""
        local = email.split("@")[0]
        domain = email.split("@")[1] if "@" in email else ""
        params = {"email": local, "domain": domain, "password": password, "quota": quota}
        return self._request("uapi", "Email", "add_pop", params, "POST")

    def delete_email_account(self, email: str) -> Dict[str, Any]:
        """Delete email account."""
        params = {"email": email}
        return self._request("uapi", "Email", "delete_pop", params, "POST")
    
    def change_email_password(self, email: str, password: str) -> Dict[str, Any]:
        """Change email password."""
        params = {"email": email, "password": password}
        return self._request("uapi", "Email", "passwd_pop", params, "POST")
    
    def change_email_quota(self, email: str, quota: int) -> Dict[str, Any]:
        """Change email quota."""
        params = {"email": email, "quota": quota}
        return self._request("uapi", "Email", "edit_pop_quota", params, "POST")
    
    def list_email_forwarders(self, domain: str = "") -> List[Dict[str, Any]]:
        """List email forwarders."""
        params = {"domain": domain} if domain else {}
        result = self._request("uapi", "Email", "list_forwarders", params)
        if result.get("status") == 1:
            return result.get("data", [])
        return []
    
    def create_email_forwarder(self, address: str, forward_to: str, domain: str) -> Dict[str, Any]:
        """Create email forwarder."""
        params = {"address": address, "fwdopt": "fwd", "fwdemail": forward_to, "domain": domain}
        return self._request("uapi", "Email", "add_forwarder", params, "POST")

    # === BACKUP OPERATIONS ===
    def create_full_backup(self, destination: str = "homedir") -> Dict[str, Any]:
        """Create full backup."""
        return self._request("uapi", "Backup", "fullbackup_to_homedir", {}, "POST")
    
    def create_partial_backup(self, backup_type: str, destination: str = ".") -> Dict[str, Any]:
        """Create partial backup (homedir, mysql, etc)."""
        params = {"backuptype": backup_type, "destination": destination}
        return self._request("api2", "Backup", "fullbackup", params, "POST")

    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups."""
        result = self._request("uapi", "Backup", "list_backups")
        if result.get("status") == 1:
            return result.get("data", [])
        return []
    
    def restore_backup(self, backup_file: str) -> Dict[str, Any]:
        """Restore from backup."""
        params = {"backup": backup_file}
        return self._request("uapi", "Backup", "restore_file", params, "POST")

    # === CRON JOB OPERATIONS ===
    def list_cron_jobs(self) -> List[Dict[str, Any]]:
        """List cron jobs."""
        result = self._request("uapi", "Cron", "list_cron")
        if result.get("status") == 1:
            return result.get("data", [])
        return []
    
    def create_cron_job(self, command: str, minute: str = "*", hour: str = "*", 
                       day: str = "*", month: str = "*", weekday: str = "*") -> Dict[str, Any]:
        """Create cron job."""
        params = {
            "command": command,
            "minute": minute,
            "hour": hour,
            "day": day,
            "month": month,
            "weekday": weekday
        }
        return self._request("uapi", "Cron", "add_line", params, "POST")
    
    def delete_cron_job(self, line_number: int) -> Dict[str, Any]:
        """Delete cron job by line number."""
        return self._request("uapi", "Cron", "remove_line", {"line": line_number}, "POST")

    # === DISK USAGE & STATS ===
    def get_disk_usage(self) -> Dict[str, Any]:
        """Get disk usage statistics."""
        result = self._request("uapi", "Quota", "get_quota_info")
        return result
    
    def get_bandwidth_usage(self) -> Dict[str, Any]:
        """Get bandwidth usage."""
        result = self._request("api2", "Stats", "get_bandwidth")
        return result

    # === PHP & WEB SERVER ===
    def list_php_versions(self) -> List[str]:
        """List available PHP versions."""
        result = self._request("uapi", "LangPHP", "php_get_installed_versions")
        if result.get("status") == 1:
            return result.get("data", {}).get("versions", [])
        return []
    
    def get_current_php_version(self, domain: str) -> str:
        """Get current PHP version for domain."""
        result = self._request("uapi", "LangPHP", "php_get_vhost_versions", {"domain": domain})
        if result.get("status") == 1:
            return result.get("data", {}).get("version", "")
        return ""
    
    def set_php_version(self, domain: str, version: str) -> Dict[str, Any]:
        """Set PHP version for domain."""
        params = {"vhost": domain, "version": version}
        return self._request("uapi", "LangPHP", "php_set_vhost_versions", params, "POST")

    # === WP TOOLKIT (if available) ===
    def list_wordpress_installations(self) -> List[Dict[str, Any]]:
        """List WordPress installations (requires WP Toolkit)."""
        try:
            result = self._request("uapi", "WordPressManager", "list")
            if result.get("status") == 1:
                return result.get("data", [])
        except:
            pass
        return []

    def test_connection(self) -> bool:
        """Test cPanel connection."""
        try:
            self._request("uapi", "DomainInfo", "main_domain")
            return True
        except:
            return False

# =========================================================
# Session State Management
# =========================================================
def init_session_state() -> None:
    """Initialize comprehensive session state with all features."""
    defaults = {
        # API & Connection
        "api_type": "20i",  # "20i" or "cpanel"
        "twentyi_client": None,
        "cpanel_client": None,
        "connected": False,
        
        # Account & Package Data
        "account_info": None,
        "packages_raw": None,
        "package_types": None,
        "domains_raw": None,
        "domain_choices": [],
        "selected_package": None,
        "selected_domain": "",
        "all_domains": [],
        "selected_package_id": None,
        
        # Restore State
        "docroot": "",
        "upload_filename": "",
        "uploaded_zip": None,
        "db_details": {},
        "restore_step": 0,
        "restore_plan_generated": False,
        
        # File Manager State
        "current_directory": "public_html",
        "file_list": [],
        "selected_file": None,
        "file_content": "",
        "file_edited": False,
        "file_original_hash": "",
        
        # Database State
        "db_list": [],
        "selected_db": None,
        "db_tables": [],
        "sql_query": "",
        "sql_results": None,
        "db_users": [],
        
        # Backup State
        "backup_list": [],
        "backup_in_progress": False,
        "backup_type": "full",
        "scheduled_backups": [],
        
        # Email State
        "email_accounts": [],
        "email_forwarders": [],
        "selected_email": None,
        
        # SSL State
        "ssl_certificates": [],
        "ssl_status": {},
        
        # Security Scanner State
        "scan_results": [],
        "scan_in_progress": False,
        "scan_path": "",
        "vulnerabilities_found": 0,
        
        # Performance State
        "performance_metrics": {},
        "cache_enabled": False,
        "compression_enabled": False,
        
        # Migration State
        "migration_source": "",
        "migration_target": "",
        "migration_progress": 0,
        
        # Cron Jobs State
        "cron_jobs": [],
        "new_cron_command": "",
        
        # Logs State
        "error_logs": "",
        "access_logs": "",
        "selected_log_type": "error",
        
        # WP-CLI State
        "wpcli_output": "",
        "wpcli_command": "",
        "wp_plugins": [],
        "wp_themes": [],
        "wp_version": "",
        
        # UI State
        "debug_mode": False,
        "show_advanced": False,
        "active_tab": 0,
        "last_error": None,
        "last_success": None,
        "refresh_trigger": 0,
        
        # Settings
        "auto_backup": False,
        "backup_retention_days": 30,
        "notification_email": "",
        "ssh_enabled": False,
        "sftp_port": 22,
    }
    
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

# =========================================================
# Enhanced UI Components
# =========================================================
def sidebar_connection() -> None:
    """Enhanced sidebar with dual API support and comprehensive settings."""
    st.sidebar.title(f"WP Manager v{VERSION}")
    st.sidebar.caption("Ultimate WordPress Management Tool")
    
    st.sidebar.divider()
    
    # API Type Selection
    st.sidebar.subheader("Connection Type")
    api_type = st.sidebar.radio(
        "Select API",
        options=["20i", "cpanel"],
        index=0 if st.session_state.api_type == "20i" else 1,
        horizontal=True,
        help="Choose between 20i API or cPanel API"
    )
    st.session_state.api_type = api_type
    
    st.sidebar.divider()
    
    # === 20i Connection ===
    if api_type == "20i":
        st.sidebar.subheader("20i API Configuration")
        
        api_key = st.sidebar.text_input(
            "General API Key",
            type="password",
            key="twentyi_api_key",
            help="Your 20i General API key from the control panel"
        )
        
        if st.sidebar.button("Connect to 20i", use_container_width=True, type="primary"):
            if not api_key:
                st.sidebar.error("Please enter your 20i API key")
                return
            
            try:
                with st.spinner("Connecting to 20i API..."):
                    client = TwentyIClient(api_key)
                    st.session_state.twentyi_client = client
                    
                    # Test connection
                    st.session_state.account_info = client.get_account_info()
                    
                    # Fetch all data
                    st.session_state.packages_raw = client.list_packages()
                    st.session_state.domain_choices = client.build_domain_choices(
                        st.session_state.packages_raw
                    )
                    
                    try:
                        st.session_state.package_types = client.list_package_types()
                    except:
                        st.session_state.package_types = {}
                    
                    try:
                        st.session_state.domains_raw = client.list_domains()
                        domains = st.session_state.domains_raw.get("domains", [])
                        st.session_state.all_domains = [
                            d.get("name", d.get("domain", "")) 
                            for d in domains if isinstance(d, dict)
                        ]
                    except:
                        st.session_state.all_domains = []
                    
                    st.session_state.connected = True
                    st.sidebar.success(f"Connected! Found {len(st.session_state.domain_choices)} sites")
                    st.rerun()
                    
            except Exception as e:
                st.sidebar.error(f"Connection failed: {str(e)}")
                st.session_state.connected = False
                if st.session_state.debug_mode:
                    st.sidebar.exception(e)
    
    # === cPanel Connection ===
    else:
        st.sidebar.subheader("cPanel Configuration")
        
        cpanel_url = st.sidebar.text_input(
            "cPanel URL",
            placeholder="https://yourdomain.com:2083",
            help="Full cPanel URL including port (usually :2083 for HTTPS)"
        )
        
        cpanel_user = st.sidebar.text_input(
            "Username",
            placeholder="cpanel_username",
            help="Your cPanel username"
        )
        
        auth_method = st.sidebar.radio(
            "Authentication Method",
            ["Password", "API Token"],
            horizontal=True,
            help="API Token is more secure"
        )
        
        if auth_method == "Password":
            cpanel_pass = st.sidebar.text_input("Password", type="password")
            cpanel_token = ""
        else:
            cpanel_pass = ""
            cpanel_token = st.sidebar.text_input(
                "API Token",
                type="password",
                help="Generate from cPanel Security > Manage API Tokens"
            )
        
        cpanel_port = st.sidebar.number_input(
            "Port",
            min_value=1,
            max_value=65535,
            value=2083,
            help="cPanel port (2083 for HTTPS, 2082 for HTTP)"
        )
        
        if st.sidebar.button("Connect to cPanel", use_container_width=True, type="primary"):
            if not all([cpanel_url, cpanel_user, (cpanel_pass or cpanel_token)]):
                st.sidebar.error("Please fill in all required fields")
                return
            
            try:
                with st.spinner("Connecting to cPanel..."):
                    client = CPanelClient(
                        cpanel_url, 
                        cpanel_user, 
                        cpanel_pass, 
                        cpanel_token,
                        cpanel_port
                    )
                    
                    # Test connection
                    if not client.test_connection():
                        raise Exception("Connection test failed")
                    
                    st.session_state.cpanel_client = client
                    st.session_state.connected = True
                    
                    # Fetch initial data
                    try:
                        domains = client.list_domains()
                        st.session_state.all_domains = [
                            d.get("domain", d.get("name", ""))
                            for d in domains if isinstance(d, dict)
                        ]
                    except:
                        st.session_state.all_domains = []
                    
                    try:
                        dbs = client.list_databases()
                        st.session_state.db_list = [
                            d.get("database", d.get("name", ""))
                            for d in dbs if isinstance(d, dict)
                        ]
                    except:
                        st.session_state.db_list = []
                    
                    st.sidebar.success(
                        f"Connected! Found {len(st.session_state.all_domains)} domains"
                    )
                    st.rerun()
                    
            except Exception as e:
                st.sidebar.error(f"Connection failed: {str(e)}")
                st.session_state.connected = False
                if st.session_state.debug_mode:
                    st.sidebar.exception(e)
    
    st.sidebar.divider()
    
    # === Connection Status & Info ===
    if st.session_state.connected:
        st.sidebar.success("Status: Connected")
        
        # Show account info for 20i
        if st.session_state.api_type == "20i" and st.session_state.account_info:
            with st.sidebar.expander("Account Info", expanded=False):
                acc = st.session_state.account_info
                st.caption(f"**Name:** {acc.get('name', 'N/A')}")
                st.caption(f"**ID:** {acc.get('id', 'N/A')}")
                st.caption(f"**Type:** {acc.get('type', 'N/A')}")
        
        # Show connection details for cPanel
        elif st.session_state.api_type == "cpanel" and st.session_state.cpanel_client:
            with st.sidebar.expander("Connection Info", expanded=False):
                client = st.session_state.cpanel_client
                st.caption(f"**URL:** {client.base_url}")
                st.caption(f"**User:** {client.username}")
                st.caption(f"**Auth:** {'Token' if client.api_token else 'Password'}")
        
        if st.sidebar.button("Disconnect", use_container_width=True, type="secondary"):
            st.session_state.connected = False
            st.session_state.twentyi_client = None
            st.session_state.cpanel_client = None
            st.session_state.domain_choices = []
            st.session_state.all_domains = []
            st.rerun()
    else:
        st.sidebar.info("Status: Not Connected")
    
    st.sidebar.divider()
    
    # === Settings ===
    with st.sidebar.expander("Settings", expanded=False):
        st.session_state.debug_mode = st.checkbox(
            "Debug Mode",
            value=st.session_state.debug_mode,
            help="Show detailed error messages and API responses"
        )
        
        st.session_state.show_advanced = st.checkbox(
            "Advanced Mode",
            value=st.session_state.show_advanced,
            help="Show advanced options and dangerous operations"
        )
        
        st.session_state.auto_backup = st.checkbox(
            "Auto-backup before changes",
            value=st.session_state.auto_backup,
            help="Automatically create backup before destructive operations"
        )
        
        st.session_state.backup_retention_days = st.number_input(
            "Backup Retention (days)",
            min_value=1,
            max_value=365,
            value=st.session_state.backup_retention_days,
            help="How long to keep automatic backups"
        )
    
    # === Quick Actions ===
    if st.session_state.connected:
        st.sidebar.divider()
        st.sidebar.caption("Quick Actions")
        
        col1, col2 = st.sidebar.columns(2)
        
        with col1:
            if st.button("Refresh", use_container_width=True, help="Refresh all data"):
                st.session_state.refresh_trigger += 1
                st.rerun()
        
        with col2:
            if st.button("Clear Cache", use_container_width=True, help="Clear session cache"):
                # Clear cached data
                keys_to_clear = ['backup_list', 'file_list', 'db_list', 'email_accounts']
                for key in keys_to_clear:
                    if key in st.session_state:
                        st.session_state[key] = []
                st.success("Cache cleared")
    
    # === Footer ===
    st.sidebar.divider()
    st.sidebar.caption(f"Version {VERSION}")
    st.sidebar.caption("Made with Streamlit")

def get_client():
    """Get the active API client."""
    if st.session_state.api_type == "20i":
        return st.session_state.twentyi_client
    else:
        return st.session_state.cpanel_client

def show_error(message: str, exception: Exception = None) -> None:
    """Display error message consistently."""
    st.error(f"Error: {message}")
    st.session_state.last_error = message
    
    if exception and st.session_state.debug_mode:
        st.exception(exception)

def show_success(message: str) -> None:
    """Display success message consistently."""
    st.success(message)
    st.session_state.last_success = message

# =========================================================
# Tab 1: Enhanced Dashboard
# =========================================================
def render_dashboard_tab() -> None:
    """Comprehensive dashboard with stats, quick actions, and monitoring."""
    st.header("Dashboard")
    st.caption("Overview of your hosting environment")
    
    client = get_client()
    if not client:
        st.info("Connect to your hosting provider using the sidebar")
        return
    
    # === Quick Stats ===
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        domain_count = len(st.session_state.all_domains)
        st.metric("Domains", domain_count)
    
    with col2:
        if st.session_state.api_type == "20i":
            pkg_count = len(st.session_state.domain_choices)
            st.metric("Sites", pkg_count)
        else:
            db_count = len(st.session_state.db_list)
            st.metric("Databases", db_count)
    
    with col3:
        backup_count = len(st.session_state.backup_list)
        st.metric("Backups", backup_count)
    
    with col4:
        st.metric("Status", "Active", delta="Connected")
    
    st.divider()
    
    # === Recent Activity / Quick Info ===
    col_left, col_right = st.columns([2, 1])
    
    with col_left:
        st.subheader("Quick Actions")
        
        action_col1, action_col2, action_col3 = st.columns(3)
        
        with action_col1:
            if st.button("Create Backup", use_container_width=True, type="primary"):
                st.session_state.active_tab = 2  # Backup Manager tab
                st.rerun()
        
        with action_col2:
            if st.button("Browse Files", use_container_width=True):
                st.session_state.active_tab = 3  # File Editor tab
                st.rerun()
        
        with action_col3:
            if st.button("Manage Databases", use_container_width=True):
                st.session_state.active_tab = 4  # Database Manager tab
                st.rerun()
        
        st.divider()
        
        # Domain List
        st.subheader("Your Domains")
        if st.session_state.all_domains:
            for i, domain in enumerate(st.session_state.all_domains[:10]):  # Show first 10
                with st.container():
                    dom_col1, dom_col2 = st.columns([3, 1])
                    with dom_col1:
                        st.text(f"🌐 {domain}")
                    with dom_col2:
                        if st.button("Manage", key=f"manage_domain_{i}", use_container_width=True):
                            st.session_state.selected_domain = domain
                            st.session_state.active_tab = 5  # Domain Manager
                            st.rerun()
            
            if len(st.session_state.all_domains) > 10:
                st.caption(f"... and {len(st.session_state.all_domains) - 10} more domains")
        else:
            st.info("No domains found")
    
    with col_right:
        st.subheader("System Info")
        
        # Connection info
        with st.container(border=True):
            st.caption("**Connection**")
            st.text(f"Type: {st.session_state.api_type.upper()}")
            st.text(f"Status: {'Connected' if st.session_state.connected else 'Disconnected'}")
        
        # Account info for 20i
        if st.session_state.api_type == "20i" and st.session_state.account_info:
            with st.container(border=True):
                st.caption("**Account**")
                acc = st.session_state.account_info
                st.text(f"Name: {acc.get('name', 'N/A')}")
                st.text(f"ID: {acc.get('id', 'N/A')}")
        
        # Settings summary
        with st.container(border=True):
            st.caption("**Settings**")
            st.text(f"Auto-backup: {'On' if st.session_state.auto_backup else 'Off'}")
            st.text(f"Debug mode: {'On' if st.session_state.debug_mode else 'Off'}")
            st.text(f"Retention: {st.session_state.backup_retention_days}d")
    
    # === Resource Usage (if available) ===
    if st.session_state.api_type == "20i" and st.session_state.selected_package_id:
        st.divider()
        st.subheader("Resource Usage")
        
        try:
            resources = client.get_package_resources(st.session_state.selected_package_id)
            
            res_col1, res_col2, res_col3 = st.columns(3)
            
            with res_col1:
                disk_used = resources.get("disk_used", 0)
                disk_limit = resources.get("disk_limit", 1)
                disk_pct = (disk_used / disk_limit * 100) if disk_limit > 0 else 0
                st.metric("Disk Usage", f"{disk_pct:.1f}%")
                st.progress(min(disk_pct / 100, 1.0))
            
            with res_col2:
                bandwidth_used = resources.get("bandwidth_used", 0)
                bandwidth_limit = resources.get("bandwidth_limit", 1)
                bw_pct = (bandwidth_used / bandwidth_limit * 100) if bandwidth_limit > 0 else 0
                st.metric("Bandwidth", f"{bw_pct:.1f}%")
                st.progress(min(bw_pct / 100, 1.0))
            
            with res_col3:
                inodes_used = resources.get("inodes_used", 0)
                st.metric("Files (Inodes)", f"{inodes_used:,}")
        
        except Exception as e:
            if st.session_state.debug_mode:
                st.warning(f"Could not fetch resource usage: {e}")
    
    elif st.session_state.api_type == "cpanel":
        st.divider()
        st.subheader("Disk Usage")
        
        try:
            quota_info = client.get_disk_usage()
            
            if quota_info.get("status") == 1:
                data = quota_info.get("data", {})
                
                disk_used_mb = float(data.get("megabytes_used", 0))
                disk_limit_mb = float(data.get("megabytes_limit", 1))
                disk_pct = (disk_used_mb / disk_limit_mb * 100) if disk_limit_mb > 0 else 0
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.metric(
                        "Disk Used",
                        f"{format_file_size(disk_used_mb * 1024 * 1024)}",
                        delta=f"{disk_pct:.1f}% of quota"
                    )
                
                with col2:
                    st.metric("Disk Limit", f"{format_file_size(disk_limit_mb * 1024 * 1024)}")
                
                st.progress(min(disk_pct / 100, 1.0))
        
        except Exception as e:
            if st.session_state.debug_mode:
                st.warning(f"Could not fetch disk usage: {e}")

# =========================================================
# Tab 2: Enhanced Restore Wizard
# =========================================================
def render_restore_wizard_tab() -> None:
    """
    Multi-step WordPress restore wizard with comprehensive features.
    """
    st.header("WordPress Restore Wizard")
    st.caption("Automated WordPress site restoration with database setup")
    
    client = get_client()
    if not client:
        st.info("Connect to your hosting provider using the sidebar")
        return
    
    # Progress indicator
    progress_steps = ["Select Domain", "Upload Backup", "Configure Paths", "Database Setup", "Review & Execute"]
    
    current_step = st.session_state.restore_step
    
    # Show progress
    progress_cols = st.columns(len(progress_steps))
    for idx, (col, step_name) in enumerate(zip(progress_cols, progress_steps)):
        with col:
            if idx < current_step:
                st.success(f"✓ {step_name}")
            elif idx == current_step:
                st.info(f"→ {step_name}")
            else:
                st.text(f"◦ {step_name}")
    
    st.progress((current_step + 1) / len(progress_steps))
    st.divider()
    
    # === Step 1: Select Domain ===
    if current_step == 0:
        st.subheader("Step 1: Select Target Domain")
        
        if st.session_state.api_type == "20i":
            if not st.session_state.domain_choices:
                st.warning("No domains found. Add a domain first.")
                return
            
            pkg_idx = st.selectbox(
                "Select Package/Domain",
                range(len(st.session_state.domain_choices)),
                format_func=lambda i: st.session_state.domain_choices[i]["label"],
                key="restore_pkg_select"
            )
            
            selected_pkg = st.session_state.domain_choices[pkg_idx]
            st.session_state.selected_package = selected_pkg
            st.session_state.selected_package_id = selected_pkg["package_id"]
            st.session_state.selected_domain = selected_pkg["domain"]
            
            st.info(f"Selected: **{selected_pkg['domain']}** (Package: {selected_pkg['package_label']})")
            
            # Show package details
            with st.expander("Package Details"):
                try:
                    pkg_details = client.get_package(selected_pkg["package_id"])
                    st.json(pkg_details)
                except Exception as e:
                    st.warning(f"Could not fetch package details: {e}")
        
        else:  # cPanel
            if not st.session_state.all_domains:
                st.warning("No domains found. Add a domain first.")
                return
            
            selected_domain = st.selectbox(
                "Select Domain",
                st.session_state.all_domains,
                key="restore_domain_select"
            )
            
            st.session_state.selected_domain = selected_domain
            st.info(f"Selected: **{selected_domain}**")
        
        if st.button("Next: Upload Backup", type="primary"):
            st.session_state.restore_step = 1
            st.rerun()
    
    # === Step 2: Upload Backup ===
    elif current_step == 1:
        st.subheader("Step 2: Upload WordPress Backup")
        st.caption(f"Target domain: **{st.session_state.selected_domain}**")
        
        uploaded_file = st.file_uploader(
            "Upload ZIP backup file",
            type=["zip"],
            help="Upload your complete WordPress backup as a ZIP file",
            key="restore_zip_upload"
        )
        
        if uploaded_file:
            st.session_state.upload_filename = uploaded_file.name
            buf = BytesIO(uploaded_file.read())
            buf.seek(0)
            st.session_state.uploaded_zip = buf
            
            # Validate ZIP
            try:
                with zipfile.ZipFile(buf) as zf:
                    file_count = len(zf.namelist())
                    total_size = sum(info.file_size for info in zf.infolist())
                    
                    # Look for WordPress files
                    wp_files = [f for f in zf.namelist() 
                               if 'wp-config.php' in f or 'wp-content/' in f or 'wp-includes/' in f]
                    
                    st.success(f"✓ Valid ZIP: {file_count} files, {format_file_size(total_size)}")
                    st.info(f"Found {len(wp_files)} WordPress-related files")
                    
                    # Show key files
                    key_files = [f for f in zf.namelist() 
                                if any(x in f for x in ['wp-config.php', '.sql', 'database.sql'])]
                    
                    if key_files:
                        with st.expander("Key Files Detected"):
                            for f in key_files[:20]:  # Show first 20
                                st.text(f"• {f}")
                    
                    # Try to extract wp-config if exists
                    wpconfig_files = [f for f in zf.namelist() if 'wp-config.php' in f]
                    if wpconfig_files:
                        st.info(f"Found wp-config.php: {wpconfig_files[0]}")
                        
                        try:
                            with zf.open(wpconfig_files[0]) as f:
                                config_content = f.read().decode('utf-8', errors='ignore')
                                extracted_values = extract_wp_config_values(config_content)
                                
                                if extracted_values:
                                    with st.expander("Extracted Database Credentials"):
                                        st.json(extracted_values)
                                        st.session_state.db_details.update({
                                            "name": extracted_values.get("DB_NAME", ""),
                                            "user": extracted_values.get("DB_USER", ""),
                                            "password": extracted_values.get("DB_PASSWORD", ""),
                                            "host": extracted_values.get("DB_HOST", "localhost"),
                                        })
                        except Exception as e:
                            st.warning(f"Could not extract wp-config: {e}")
                
            except zipfile.BadZipFile:
                st.error("Invalid ZIP file")
                return
            except Exception as e:
                st.error(f"Error validating ZIP: {e}")
                return
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("← Back"):
                st.session_state.restore_step = 0
                st.rerun()
        
        with col2:
            if uploaded_file and st.button("Next: Configure Paths", type="primary"):
                st.session_state.restore_step = 2
                st.rerun()
    
    # === Step 3: Configure Paths ===
    elif current_step == 2:
        st.subheader("Step 3: Configure Document Root")
        st.caption(f"Domain: **{st.session_state.selected_domain}** | File: {st.session_state.upload_filename}")
        
        domain = st.session_state.selected_domain
        
        # Suggest common document roots
        if st.session_state.api_type == "20i":
            suggestions = [
                f"/home/stackcp/{domain}/public_html",
                f"/home/stackcp/{domain}/htdocs",
                f"/home/stackcp/{domain}/www",
            ]
        else:  # cPanel
            suggestions = [
                f"public_html",
                f"public_html/{domain}",
                f"{domain}/public_html",
            ]
        
        st.write("**Common Document Root Paths:**")
        for suggestion in suggestions:
            if st.button(f"Use: `{suggestion}`", key=f"docroot_suggest_{suggestion}"):
                st.session_state.docroot = suggestion
        
        docroot = st.text_input(
            "Document Root Path",
            value=st.session_state.docroot or suggestions[0],
            help="The directory where WordPress files will be extracted",
            key="restore_docroot_input"
        )
        
        st.session_state.docroot = docroot
        
        st.info(f"📁 Files will be extracted to: `{docroot}`")
        
        # Warning about existing files
        st.warning("⚠️ **Warning:** If this directory exists, files may be overwritten. Consider backing up first.")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("← Back"):
                st.session_state.restore_step = 1
                st.rerun()
        
        with col2:
            if st.button("Next: Database Setup", type="primary"):
                st.session_state.restore_step = 3
                st.rerun()
    
    # === Step 4: Database Setup ===
    elif current_step == 3:
        st.subheader("Step 4: Database Configuration")
        st.caption(f"Domain: **{st.session_state.selected_domain}**")
        
        # Initialize DB details if not exists
        if not st.session_state.db_details:
            base_name = normalize_domain_name(st.session_state.selected_domain.split(".")[0])
            st.session_state.db_details = {
                "name": f"{base_name}_wp",
                "user": f"{base_name}_user",
                "password": generate_strong_password(),
                "host": "localhost",
                "created": False,
                "user_created": False
            }
        
        st.write("**Database Credentials:**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            db_name = st.text_input(
                "Database Name",
                value=st.session_state.db_details.get("name", ""),
                key="restore_db_name"
            )
            
            db_user = st.text_input(
                "Database User",
                value=st.session_state.db_details.get("user", ""),
                key="restore_db_user"
            )
        
        with col2:
            db_password = st.text_input(
                "Database Password",
                value=st.session_state.db_details.get("password", ""),
                type="password",
                key="restore_db_pass"
            )
            
            if st.button("🔄 Generate New Password", key="restore_gen_pass"):
                st.session_state.db_details["password"] = generate_strong_password()
                st.rerun()
            
            db_host = st.text_input(
                "Database Host",
                value=st.session_state.db_details.get("host", "localhost"),
                key="restore_db_host"
            )
        
        # Update session state
        st.session_state.db_details.update({
            "name": db_name,
            "user": db_user,
            "password": db_password,
            "host": db_host
        })
        
        st.divider()
        
        # Auto-create database option
        st.write("**Automated Database Setup:**")
        
        col_create1, col_create2 = st.columns([2, 1])
        
        with col_create1:
            st.info("Automatically create database and user with proper privileges")
        
        with col_create2:
            if st.button("🔨 Create Database", type="primary", use_container_width=True):
                try:
                    with st.spinner("Creating database..."):
                        # Create database
                        client.create_database(
                            st.session_state.selected_package_id if st.session_state.api_type == "20i" else None,
                            db_name
                        )
                        st.session_state.db_details["created"] = True
                        
                        # Create user
                        client.create_database_user(
                            st.session_state.selected_package_id if st.session_state.api_type == "20i" else None,
                            db_user,
                            db_password
                        )
                        st.session_state.db_details["user_created"] = True
                        
                        # Grant privileges
                        if st.session_state.api_type == "20i":
                            client.grant_database_access(
                                st.session_state.selected_package_id,
                                db_name,
                                db_user
                            )
                        else:
                            client.grant_database_privileges(db_user, db_name)
                        
                        show_success(f"✅ Database '{db_name}' created successfully!")
                        st.rerun()
                        
                except Exception as e:
                    show_error(f"Failed to create database: {e}", e)
        
        # Status indicators
        if st.session_state.db_details.get("created"):
            st.success("✅ Database created")
        
        if st.session_state.db_details.get("user_created"):
            st.success("✅ Database user created and privileges granted")
        
        # Manual instructions
        with st.expander("Manual Database Setup Instructions"):
            st.code(f"""
-- Via phpMyAdmin or MySQL CLI:

CREATE DATABASE {db_name};
CREATE USER '{db_user}'@'{db_host}' IDENTIFIED BY '{db_password}';
GRANT ALL PRIVILEGES ON {db_name}.* TO '{db_user}'@'{db_host}';
FLUSH PRIVILEGES;
            """, language="sql")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("← Back"):
                st.session_state.restore_step = 2
                st.rerun()
        
        with col2:
            if st.button("Next: Review & Execute", type="primary"):
                st.session_state.restore_step = 4
                st.rerun()
    
    # === Step 5: Review & Generate Restore Plan ===
    elif current_step == 4:
        st.subheader("Step 5: Review & Execute Restore")
        
        # Summary
        st.write("**Restore Summary:**")
        
        summary_data = {
            "Domain": st.session_state.selected_domain,
            "Backup File": st.session_state.upload_filename,
            "Document Root": st.session_state.docroot,
            "Database Name": st.session_state.db_details.get("name"),
            "Database User": st.session_state.db_details.get("user"),
            "Database Host": st.session_state.db_details.get("host"),
        }
        
        for key, value in summary_data.items():
            st.text(f"{key}: {value}")
        
        st.divider()
        
        # Generate restore script
        st.subheader("Automated Restore Script")
        
        domain = st.session_state.selected_domain
        docroot = st.session_state.docroot
        filename = st.session_state.upload_filename
        db = st.session_state.db_details
        
        # SSH/Terminal commands
        restore_script = f"""#!/bin/bash
# WordPress Restore Script
# Generated by WP Manager v{VERSION}
# Domain: {domain}
# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

set -e  # Exit on error

echo "Starting WordPress restore for {domain}..."

# 1. Navigate to document root
cd {docroot}

# 2. Backup existing files (if any)
if [ -d "wp-content" ]; then
    echo "Backing up existing WordPress installation..."
    tar -czf backup-before-restore-$(date +%Y%m%d-%H%M%S).tar.gz .
fi

# 3. Extract backup
echo "Extracting backup archive..."
unzip -o {filename}
rm {filename}

# 4. Set permissions
echo "Setting file permissions..."
find . -type d -exec chmod 755 {{}} \\;
find . -type f -exec chmod 644 {{}} \\;
chmod 600 wp-config.php

# 5. Update wp-config.php
echo "Updating wp-config.php with new database credentials..."
sed -i "s/define( *'DB_NAME'.*/define('DB_NAME', '{db["name"]}');/" wp-config.php
sed -i "s/define( *'DB_USER'.*/define('DB_USER', '{db["user"]}');/" wp-config.php
sed -i "s/define( *'DB_PASSWORD'.*/define('DB_PASSWORD', '{db["password"]}');/" wp-config.php
sed -i "s/define( *'DB_HOST'.*/define('DB_HOST', '{db["host"]}');/" wp-config.php

# 6. Import database (if .sql file exists)
SQL_FILE=$(find . -maxdepth 2 -name "*.sql" -type f | head -n 1)
if [ -n "$SQL_FILE" ]; then
    echo "Importing database from $SQL_FILE..."
    mysql -u {db["user"]} -p'{db["password"]}' {db["name"]} < "$SQL_FILE"
    
    # Update site URL
    echo "Updating WordPress site URLs..."
    mysql -u {db["user"]} -p'{db["password"]}' {db["name"]} <<EOF
UPDATE wp_options SET option_value = 'https://{domain}' WHERE option_name = 'siteurl' OR option_name = 'home';
EOF
else
    echo "Warning: No .sql file found in backup"
fi

# 7. Clear cache if exists
if [ -d "wp-content/cache" ]; then
    echo "Clearing WordPress cache..."
    rm -rf wp-content/cache/*
fi

echo "✅ WordPress restore completed successfully!"
echo "Next steps:"
echo "1. Visit https://{domain} to verify"
echo "2. Login to WordPress admin"
echo "3. Update permalinks (Settings > Permalinks > Save)"
echo "4. Clear any caching plugins"
"""
        
        st.code(restore_script, language="bash")
        
        # Download script
        st.download_button(
            label="📥 Download Restore Script",
            data=restore_script,
            file_name=f"restore_{normalize_domain_name(domain)}.sh",
            mime="text/x-shellscript"
        )
        
        st.divider()
        
        # Manual step-by-step instructions
        st.subheader("Manual Restore Steps")
        
        with st.expander("📋 View Step-by-Step Instructions", expanded=True):
            st.markdown(f"""
### Manual WordPress Restore Instructions

#### 1. Upload ZIP File
- Upload `{filename}` to `{docroot}` via SFTP/FTP or cPanel File Manager
- Or use command: `cd {docroot} && wget YOUR_BACKUP_URL`

#### 2. Extract Backup
```bash
cd {docroot}
unzip {filename}
rm {filename}
