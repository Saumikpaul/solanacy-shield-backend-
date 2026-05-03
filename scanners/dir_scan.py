"""
Exposed Files & Directories Scanner
======================================
Checks for commonly exposed sensitive files and directories
that should never be publicly accessible.

Checks for:
  - .env files
  - .git directories
  - Admin panels
  - Backup files
  - Config files
  - Log files
  - Common sensitive paths
"""

import logging
import requests
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"

HEADERS = {
    "User-Agent": "SecurityAuditBot/1.0 (ethical-scan; authorized-test)"
}

# Paths to check — (path, severity, description)
SENSITIVE_PATHS = [
    # Git & version control (critical — exposes entire source code)
    ("/.git/config",           CRITICAL, "Git repository config exposed — source code may be downloadable."),
    ("/.git/HEAD",             CRITICAL, "Git HEAD file exposed — confirms git repo is publicly accessible."),
    ("/.svn/entries",          CRITICAL, "SVN repository exposed."),
    ("/.hg/",                  CRITICAL, "Mercurial repository exposed."),

    # Environment & secrets
    ("/.env",                  CRITICAL, "Environment file exposed — may contain API keys, DB passwords, secrets."),
    ("/.env.local",            CRITICAL, "Local environment file exposed."),
    ("/.env.production",       CRITICAL, "Production environment file exposed."),
    ("/.env.backup",           CRITICAL, "Environment backup file exposed."),

    # Config files
    ("/config.php",            CRITICAL, "PHP config file exposed — may contain DB credentials."),
    ("/wp-config.php",         CRITICAL, "WordPress config file — contains DB credentials."),
    ("/config.yml",            HIGH,     "YAML config file exposed."),
    ("/config.json",           HIGH,     "JSON config file exposed."),
    ("/settings.py",           HIGH,     "Python settings file exposed."),
    ("/database.yml",          CRITICAL, "Database config file exposed — credentials at risk."),
    ("/app/config/database.php", CRITICAL, "Database config exposed."),

    # Backup files
    ("/backup.sql",            CRITICAL, "SQL backup file exposed — full database dump accessible."),
    ("/backup.zip",            CRITICAL, "Backup archive exposed."),
    ("/dump.sql",              CRITICAL, "SQL dump exposed."),
    ("/db.sql",                CRITICAL, "Database SQL file exposed."),
    ("/backup/",               HIGH,     "Backup directory exposed."),

    # Admin panels
    ("/admin/",                HIGH,     "Admin panel directory exposed. Should be IP-restricted."),
    ("/admin/login",           HIGH,     "Admin login page exposed to internet."),
    ("/wp-admin/",             HIGH,     "WordPress admin panel exposed."),
    ("/phpmyadmin/",           HIGH,     "phpMyAdmin exposed — direct database access."),
    ("/adminer.php",           HIGH,     "Adminer database management tool exposed."),
    ("/cpanel",                HIGH,     "cPanel exposed."),

    # Log files
    ("/error.log",             HIGH,     "Error log file exposed — may reveal sensitive info."),
    ("/access.log",            MEDIUM,   "Access log file exposed."),
    ("/debug.log",             HIGH,     "Debug log exposed."),
    ("/logs/",                 HIGH,     "Logs directory exposed."),

    # Common sensitive files
    ("/robots.txt",            INFO,     "robots.txt found — check for hidden paths listed inside."),
    ("/sitemap.xml",           INFO,     "Sitemap found."),
    ("/.htaccess",             MEDIUM,   ".htaccess file exposed — reveals server configuration rules."),
    ("/server-status",         HIGH,     "Apache server-status page exposed — reveals internal server info."),
    ("/server-info",           HIGH,     "Apache server-info exposed."),
    ("/info.php",              HIGH,     "phpinfo() page exposed — reveals full PHP/server configuration."),
    ("/phpinfo.php",           HIGH,     "phpinfo() page exposed."),
    ("/test.php",              MEDIUM,   "Test PHP file found on production server."),
    ("/package.json",          MEDIUM,   "package.json exposed — reveals all dependencies and versions."),
    ("/composer.json",         MEDIUM,   "composer.json exposed — reveals PHP dependencies."),
    ("/Dockerfile",            MEDIUM,   "Dockerfile exposed — reveals server build configuration."),
    ("/docker-compose.yml",    MEDIUM,   "docker-compose.yml exposed — may contain service credentials."),
]


def check_exposed_files(url: str) -> Dict[str, Any]:
    """
    Check for exposed sensitive files and directories.
    """
    issues          = []
    score_deduction  = 0
    found_paths     = []

    if not url.startswith("http"):
        url = "https://" + url

    # Normalize base URL (remove trailing paths)
    parsed   = url.split("//", 1)
    scheme   = parsed[0] + "//"
    rest     = parsed[1].split("/")[0] if len(parsed) > 1 else ""
    base_url = scheme + rest

    for path, severity, description in SENSITIVE_PATHS:
        full_url = base_url + path
        result   = _check_path(full_url, path, severity, description)
        if result:
            found_paths.append(result)
            deduct = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}.get(severity, 5)
            issues.append({
                "title":          f"Exposed: {path}",
                "severity":       severity,
                "description":    f"{description} URL: {full_url}",
                "recommendation": _get_recommendation(path, severity),
                "url":            full_url
            })
            score_deduction += deduct

    if not found_paths:
        issues.append({
            "title":          "No Sensitive Files Exposed",
            "severity":       INFO,
            "description":    "None of the commonly exposed sensitive files/directories were found.",
            "recommendation": "Continue to audit file access permissions after every deployment."
        })
    else:
        # Sort by severity
        severity_order = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
        issues.sort(key=lambda x: severity_order.get(x["severity"], 5))

    return _build_result(issues, score_deduction, found_paths)


def _check_path(url: str, path: str, severity: str, description: str) -> dict | None:
    """Check if a path returns a 200 response (exposed)."""
    try:
        resp = requests.get(
            url,
            timeout=6,
            headers=HEADERS,
            allow_redirects=False  # Don't follow redirects — 301/302 = not directly exposed
        )

        # 200 = exposed, 403 = exists but forbidden (still note it)
        if resp.status_code == 200 and len(resp.content) > 0:
            return {
                "path":        path,
                "url":         url,
                "status_code": resp.status_code,
                "severity":    severity,
                "size_bytes":  len(resp.content)
            }

        if resp.status_code == 403 and severity in [CRITICAL, HIGH]:
            # Path exists but access denied — still worth noting
            return {
                "path":        path,
                "url":         url,
                "status_code": 403,
                "severity":    LOW,
                "note":        "Path exists but access is forbidden (403). Verify this is intentional."
            }

    except requests.exceptions.RequestException:
        pass  # Path not found or connection error — fine

    return None


def _get_recommendation(path: str, severity: str) -> str:
    """Return a specific recommendation based on the path."""
    recs = {
        "/.git":         "Remove .git directory from production server, or block access in nginx/apache config: 'location /.git { deny all; }'",
        "/.env":         "Move .env outside web root, add to .gitignore, and never commit secrets to git.",
        "/wp-config.php":"Move wp-config.php one level above web root.",
        "/admin":        "Restrict admin panel access by IP whitelist in your firewall/nginx config.",
        "/phpmyadmin":   "Remove phpMyAdmin from production, or restrict to specific IPs only.",
        "/backup":       "Never store backups in the web root. Move to a private storage bucket.",
        "/phpinfo.php":  "Delete phpinfo files from production servers immediately.",
        "/info.php":     "Delete test/info PHP files from production servers.",
    }
    for key, rec in recs.items():
        if key in path:
            return rec
    return "Restrict access to this file/directory via server configuration or remove from production."


def _build_result(issues: list, score_deduction: int, found_paths: list) -> Dict[str, Any]:
    return {
        "scanner":         "exposed_files",
        "issues":          issues,
        "score_deduction": min(score_deduction, 100),
        "details":         {"found_paths": found_paths}
    }
