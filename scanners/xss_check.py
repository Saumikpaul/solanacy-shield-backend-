"""
XSS (Cross-Site Scripting) Scanner
=====================================
Tests the target for reflected XSS vulnerabilities by:
  1. Finding URL parameters and HTML forms
  2. Injecting XSS marker payloads
  3. Checking if the marker is reflected in the response unescaped

Does NOT test for stored XSS (requires authenticated sessions).
Does NOT test for DOM-based XSS (requires browser execution).
"""

import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"

# XSS payloads — we use a unique marker to detect reflection
XSS_MARKER  = "xss7k3b"
XSS_PAYLOADS = [
    f'<script>{XSS_MARKER}</script>',
    f'"><script>{XSS_MARKER}</script>',
    f"'><script>{XSS_MARKER}</script>",
    f'<img src=x onerror="{XSS_MARKER}">',
    f'<svg onload="{XSS_MARKER}">',
    f'javascript:{XSS_MARKER}',
    f'"><img src=x onerror={XSS_MARKER}>',
]

HEADERS = {
    "User-Agent": "SecurityAuditBot/1.0 (ethical-scan; authorized-test)"
}


def check_xss(url: str) -> Dict[str, Any]:
    """
    Test a URL for reflected XSS vulnerabilities.
    """
    issues          = []
    score_deduction  = 0
    findings        = []

    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=10, headers=HEADERS)
        soup     = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        logger.error(f"XSS scanner failed to fetch {url}: {e}")
        return _build_result([{
            "title":          "Could Not Fetch Page",
            "severity":       INFO,
            "description":    f"XSS scan skipped: {str(e)}",
            "recommendation": "Ensure the URL is accessible."
        }], 0, [])

    # ── 1. Test URL Query Parameters ──────────────────────────────────
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for param_name in params:
        for payload in XSS_PAYLOADS:
            result = _test_xss_param(url, param_name, payload)
            if result:
                findings.append(result)
                issues.append({
                    "title":          f"Reflected XSS in URL Parameter: '{param_name}'",
                    "severity":       HIGH,
                    "description":    (
                        f"The URL parameter '{param_name}' reflects user input directly into the HTML response "
                        f"without proper encoding. An attacker can craft a malicious URL that executes scripts "
                        f"in victims' browsers. Payload used: {payload}"
                    ),
                    "recommendation": (
                        "Encode all output using context-appropriate escaping (HTML entity encoding). "
                        "Use a CSP header. Validate and sanitize all inputs server-side."
                    )
                })
                score_deduction += 30
                break  # One finding per param is enough

    # ── 2. Test HTML Forms ────────────────────────────────────────────
    forms = soup.find_all("form")
    for form in forms:
        form_findings = _test_form_xss(url, form)
        if form_findings:
            findings.extend(form_findings)
            for f in form_findings:
                issues.append({
                    "title":          f"Reflected XSS in Form Field: '{f['field']}'",
                    "severity":       HIGH,
                    "description":    (
                        f"Form field '{f['field']}' reflects unescaped input. "
                        f"Payload reflected: {f['payload']}"
                    ),
                    "recommendation": (
                        "Sanitize and encode all form input on the server before rendering. "
                        "Use template engines with auto-escaping enabled."
                    )
                })
                score_deduction += 30

    # ── 3. Check for CSP (partial XSS mitigation) ────────────────────
    csp = response.headers.get("Content-Security-Policy", "")
    if not csp:
        issues.append({
            "title":          "No Content-Security-Policy Header",
            "severity":       MEDIUM,
            "description":    "Without CSP, even if XSS exists, there is no browser-level mitigation.",
            "recommendation": "Add a Content-Security-Policy header to limit script execution sources."
        })
        score_deduction += 5

    if not findings:
        issues.append({
            "title":          "No Reflected XSS Detected",
            "severity":       INFO,
            "description":    "No reflected XSS vulnerabilities found in URL parameters or forms on this page.",
            "recommendation": "Continue to sanitize all user inputs and use output encoding. Implement CSP."
        })

    return _build_result(issues, score_deduction, findings)


def _test_xss_param(url: str, param_name: str, payload: str) -> dict | None:
    """Inject a payload into a URL parameter and check for reflection."""
    parsed      = urlparse(url)
    params      = parse_qs(parsed.query)
    test_params = {k: v[0] for k, v in params.items()}
    test_params[param_name] = payload

    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

    try:
        resp = requests.get(test_url, timeout=8, headers=HEADERS)
        # Check if our marker appears unencoded in response
        if XSS_MARKER in resp.text and payload in resp.text:
            return {
                "type":    "url_param",
                "param":   param_name,
                "payload": payload,
                "url":     test_url
            }
    except Exception as e:
        logger.debug(f"XSS param test error: {e}")

    return None


def _test_form_xss(page_url: str, form) -> List[dict]:
    """Inject XSS payloads into form fields and check for reflection."""
    results    = []
    action     = form.get("action", "")
    method     = form.get("method", "get").lower()
    action_url = urljoin(page_url, action) if action else page_url
    inputs     = form.find_all(["input", "textarea"])

    for payload in XSS_PAYLOADS[:3]:  # Limit for speed
        data = {}
        test_fields = []

        for inp in inputs:
            field_name = inp.get("name", "")
            field_type = inp.get("type", "text").lower()
            if not field_name or field_type in ["submit", "button", "image", "file"]:
                continue
            if field_type == "hidden":
                data[field_name] = inp.get("value", "")
            else:
                data[field_name] = payload
                test_fields.append(field_name)

        if not test_fields:
            continue

        try:
            if method == "post":
                resp = requests.post(action_url, data=data, timeout=8, headers=HEADERS)
            else:
                resp = requests.get(action_url, params=data, timeout=8, headers=HEADERS)

            if XSS_MARKER in resp.text:
                for field in test_fields:
                    results.append({
                        "type":    "form",
                        "field":   field,
                        "action":  action_url,
                        "payload": payload
                    })
                break

        except Exception as e:
            logger.debug(f"Form XSS test error: {e}")
            continue

    return results


def _build_result(issues: list, score_deduction: int, findings: list) -> Dict[str, Any]:
    return {
        "scanner":         "xss",
        "issues":          issues,
        "score_deduction": min(score_deduction, 100),
        "details":         {"findings": findings}
    }
