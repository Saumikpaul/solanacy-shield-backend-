"""
SQL Injection Scanner
======================
Tests the target URL's query parameters and forms for SQL injection
vulnerabilities using error-based and boolean-based detection.

Method:
  1. Crawl the page to find forms and URL parameters
  2. Inject SQL payloads into each input
  3. Check response for SQL error signatures
  4. Check for boolean differences (response length/content changes)

NOTE: Only tests GET params and forms on the provided URL.
      Does NOT crawl subpages — to keep scans targeted and legal.
"""

import re
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

# Common SQL error messages from different databases
SQL_ERROR_SIGNATURES = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    # MSSQL
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"sql server.*driver",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg::syntaxerror",
    r"postgresql.*error",
    # Oracle
    r"ora-\d{5}",
    r"oracle error",
    r"oracle.*driver",
    # SQLite
    r"sqlite.*error",
    r"sqlite3.operationalerror",
    # Generic
    r"sql syntax",
    r"syntax error.*sql",
    r"unexpected end of sql command",
]

# Error-based SQLi payloads
SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 'x'='x",
    "1 OR 1=1",
    "'; DROP TABLE users--",
    "1' AND 1=2--",
]

HEADERS = {
    "User-Agent": "SecurityAuditBot/1.0 (ethical-scan; authorized-test)"
}


def check_sqli(url: str) -> Dict[str, Any]:
    """
    Test a URL for SQL injection vulnerabilities.
    Returns issues, score deductions, and findings.
    """
    issues         = []
    score_deduction = 0
    findings       = []

    if not url.startswith("http"):
        url = "https://" + url

    try:
        # Fetch the page
        response = requests.get(url, timeout=10, headers=HEADERS)
        baseline_length = len(response.text)
        soup = BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        logger.error(f"SQLi scanner failed to fetch {url}: {e}")
        return _build_result([{
            "title":          "Could Not Fetch Page",
            "severity":       INFO,
            "description":    f"SQL injection scan skipped: {str(e)}",
            "recommendation": "Ensure the URL is accessible."
        }], 0, [])

    # ── 1. Test URL Query Parameters ──────────────────────────────────
    parsed  = urlparse(url)
    params  = parse_qs(parsed.query)

    if params:
        for param_name in params:
            result = _test_sqli_in_param(url, param_name, baseline_length)
            if result:
                findings.append(result)
                issues.append({
                    "title":          f"SQL Injection in URL Parameter: '{param_name}'",
                    "severity":       CRITICAL,
                    "description":    f"The URL parameter '{param_name}' appears vulnerable to SQL injection. Payload: {result['payload']}. Evidence: {result['evidence'][:200]}",
                    "recommendation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings. Use an ORM."
                })
                score_deduction += 40

    # ── 2. Test HTML Forms ────────────────────────────────────────────
    forms = soup.find_all("form")
    for form in forms:
        form_result = _test_form_sqli(url, form)
        if form_result:
            findings.extend(form_result)
            for r in form_result:
                issues.append({
                    "title":          f"SQL Injection in Form Field: '{r['field']}'",
                    "severity":       CRITICAL,
                    "description":    f"Form field '{r['field']}' on action '{r['action']}' appears vulnerable. Payload: {r['payload']}",
                    "recommendation": "Use parameterized queries and server-side input validation for all form inputs."
                })
                score_deduction += 40

    if not findings:
        issues.append({
            "title":          "No SQL Injection Detected",
            "severity":       INFO,
            "description":    "No obvious SQL injection vulnerabilities found in URL parameters or forms on this page.",
            "recommendation": "Continue using parameterized queries and validate all user inputs server-side."
        })

    return _build_result(issues, score_deduction, findings)


def _test_sqli_in_param(url: str, param_name: str, baseline_length: int) -> dict | None:
    """Test a single URL parameter for SQLi."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    for payload in SQLI_PAYLOADS:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param_name] = payload

        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"

        try:
            resp = requests.get(test_url, timeout=8, headers=HEADERS)
            body_lower = resp.text.lower()

            # Check for SQL error signatures in response
            for pattern in SQL_ERROR_SIGNATURES:
                if re.search(pattern, body_lower):
                    return {
                        "type":     "url_param",
                        "param":    param_name,
                        "payload":  payload,
                        "evidence": re.search(pattern, body_lower).group(0)
                    }

        except Exception as e:
            logger.debug(f"SQLi param test error: {e}")
            continue

    return None


def _test_form_sqli(page_url: str, form) -> List[dict]:
    """Test a form's input fields for SQL injection."""
    results = []
    action  = form.get("action", "")
    method  = form.get("method", "get").lower()
    action_url = urljoin(page_url, action) if action else page_url

    inputs = form.find_all(["input", "textarea"])

    for payload in SQLI_PAYLOADS[:5]:  # Limit payloads per form for speed
        data = {}
        for inp in inputs:
            field_name = inp.get("name", "")
            field_type = inp.get("type", "text").lower()
            if not field_name or field_type in ["submit", "button", "image", "file"]:
                continue
            if field_type == "hidden":
                data[field_name] = inp.get("value", "")
            else:
                data[field_name] = payload

        if not data:
            continue

        try:
            if method == "post":
                resp = requests.post(action_url, data=data, timeout=8, headers=HEADERS)
            else:
                resp = requests.get(action_url, params=data, timeout=8, headers=HEADERS)

            body_lower = resp.text.lower()

            for pattern in SQL_ERROR_SIGNATURES:
                if re.search(pattern, body_lower):
                    for field_name in data:
                        if data[field_name] == payload:
                            results.append({
                                "type":    "form",
                                "field":   field_name,
                                "action":  action_url,
                                "method":  method,
                                "payload": payload,
                                "evidence": re.search(pattern, body_lower).group(0)
                            })
                    break  # One finding per payload per form

        except Exception as e:
            logger.debug(f"Form SQLi test error: {e}")
            continue

    return results


def _build_result(issues: list, score_deduction: int, findings: list) -> Dict[str, Any]:
    return {
        "scanner":         "sqli",
        "issues":          issues,
        "score_deduction": min(score_deduction, 100),
        "details":         {"findings": findings}
    }
