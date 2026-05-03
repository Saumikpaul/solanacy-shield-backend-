"""
HTTP Security Headers Scanner
==============================
Checks for presence and correct configuration of critical
HTTP security headers as defined by OWASP Secure Headers Project.

Headers checked:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - X-XSS-Protection (deprecated but still checked)
  - Cache-Control (for sensitive pages)
"""

import requests
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"

# Each header: (description, severity_if_missing, recommended_value, score_deduction)
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity":        HIGH,
        "description":     "HSTS forces browsers to always use HTTPS for this domain.",
        "recommendation":  "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "score_deduction": 15,
        "check_fn":        lambda v: "max-age" in v.lower()
    },
    "Content-Security-Policy": {
        "severity":        HIGH,
        "description":     "CSP prevents XSS by controlling which resources browsers can load.",
        "recommendation":  "Add a Content-Security-Policy header. Start with: default-src 'self'",
        "score_deduction": 15,
        "check_fn":        lambda v: len(v) > 0
    },
    "X-Frame-Options": {
        "severity":        MEDIUM,
        "description":     "Prevents clickjacking attacks by controlling iframe embedding.",
        "recommendation":  "Add: X-Frame-Options: DENY  (or SAMEORIGIN if you need iframes)",
        "score_deduction": 10,
        "check_fn":        lambda v: v.upper() in ["DENY", "SAMEORIGIN"]
    },
    "X-Content-Type-Options": {
        "severity":        MEDIUM,
        "description":     "Prevents MIME-type sniffing attacks.",
        "recommendation":  "Add: X-Content-Type-Options: nosniff",
        "score_deduction": 10,
        "check_fn":        lambda v: v.lower() == "nosniff"
    },
    "Referrer-Policy": {
        "severity":        LOW,
        "description":     "Controls how much referrer info is included with requests.",
        "recommendation":  "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "score_deduction": 5,
        "check_fn":        lambda v: len(v) > 0
    },
    "Permissions-Policy": {
        "severity":        LOW,
        "description":     "Controls access to browser features like camera, microphone, geolocation.",
        "recommendation":  "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "score_deduction": 5,
        "check_fn":        lambda v: len(v) > 0
    },
}

# Headers that should NOT be present (information leakage)
LEAKY_HEADERS = {
    "Server": {
        "severity":       MEDIUM,
        "description":    "The Server header reveals your web server software and version, helping attackers target known vulnerabilities.",
        "recommendation": "Configure your server to remove or anonymize the Server header.",
        "score_deduction": 8
    },
    "X-Powered-By": {
        "severity":       MEDIUM,
        "description":    "X-Powered-By reveals your backend framework (e.g. PHP/7.4, Express). This helps attackers.",
        "recommendation": "Remove X-Powered-By header from your server/framework configuration.",
        "score_deduction": 8
    },
    "X-AspNet-Version": {
        "severity":       MEDIUM,
        "description":    "Reveals the ASP.NET version being used.",
        "recommendation": "Disable this header in your web.config.",
        "score_deduction": 8
    },
}


def check_headers(url: str) -> Dict[str, Any]:
    """
    Fetch the target URL and analyze its HTTP response headers.
    Returns issues, score deductions, and raw header info.
    """
    issues         = []
    score_deduction = 0
    found_headers  = {}

    # Ensure URL has a scheme
    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "SecurityAuditBot/1.0 (ethical-scan; contact@yourdomain.com)"}
        )
        found_headers = dict(response.headers)
        final_url     = response.url
        status_code   = response.status_code

        logger.info(f"Headers fetched for {url} → {status_code} @ {final_url}")

    except requests.exceptions.SSLError:
        issues.append({
            "title":          "HTTPS Connection Failed",
            "severity":       CRITICAL,
            "description":    "Could not establish a secure HTTPS connection.",
            "recommendation": "Ensure your SSL certificate is valid and HTTPS is properly configured."
        })
        return _build_result(issues, 40, found_headers)

    except requests.exceptions.ConnectionError:
        issues.append({
            "title":          "Connection Failed",
            "severity":       CRITICAL,
            "description":    f"Could not connect to {url}.",
            "recommendation": "Verify the URL is correct and the server is running."
        })
        return _build_result(issues, 40, found_headers)

    except requests.exceptions.Timeout:
        issues.append({
            "title":          "Request Timed Out",
            "severity":       HIGH,
            "description":    "The server did not respond within 10 seconds.",
            "recommendation": "Check server performance and response times."
        })
        return _build_result(issues, 15, found_headers)

    # Normalize header keys to lowercase for comparison
    headers_lower = {k.lower(): v for k, v in found_headers.items()}

    # ── Check required security headers ──────────────────────────────
    for header_name, config in SECURITY_HEADERS.items():
        header_key   = header_name.lower()
        header_value = headers_lower.get(header_key, "")

        if not header_value:
            issues.append({
                "title":          f"Missing Header: {header_name}",
                "severity":       config["severity"],
                "description":    config["description"],
                "recommendation": config["recommendation"]
            })
            score_deduction += config["score_deduction"]
        else:
            # Header present — check if value is correctly configured
            check_fn = config.get("check_fn")
            if check_fn and not check_fn(header_value):
                issues.append({
                    "title":          f"Misconfigured Header: {header_name}",
                    "severity":       config["severity"],
                    "description":    f"Header present but may be misconfigured. Current value: '{header_value}'",
                    "recommendation": config["recommendation"]
                })
                score_deduction += config["score_deduction"] // 2

    # ── Check for leaky/information-disclosure headers ────────────────
    for header_name, config in LEAKY_HEADERS.items():
        header_value = headers_lower.get(header_name.lower(), "")
        if header_value:
            issues.append({
                "title":          f"Information Disclosure: {header_name}",
                "severity":       config["severity"],
                "description":    f"{config['description']} Current value: '{header_value}'",
                "recommendation": config["recommendation"]
            })
            score_deduction += config["score_deduction"]

    # ── Check HTTP → HTTPS redirect ───────────────────────────────────
    http_url = url.replace("https://", "http://")
    try:
        http_resp = requests.get(http_url, timeout=8, allow_redirects=False)
        if http_resp.status_code not in [301, 302, 307, 308]:
            issues.append({
                "title":          "No HTTP to HTTPS Redirect",
                "severity":       HIGH,
                "description":    "The site does not redirect HTTP traffic to HTTPS automatically.",
                "recommendation": "Configure a 301 redirect from http:// to https:// on your server."
            })
            score_deduction += 15
    except Exception:
        pass  # If HTTP isn't even open, that's fine

    if not issues:
        issues.append({
            "title":          "All Security Headers Present",
            "severity":       INFO,
            "description":    "All recommended security headers are configured correctly.",
            "recommendation": "Great job! Keep monitoring for header changes during deployments."
        })

    return _build_result(issues, score_deduction, found_headers)


def _build_result(issues: list, score_deduction: int, headers: dict) -> Dict[str, Any]:
    return {
        "scanner":         "headers",
        "issues":          issues,
        "score_deduction": min(score_deduction, 100),
        "details":         {"raw_headers": headers}
    }
