"""
SSL/TLS Certificate Scanner
=============================
Checks the target domain's SSL certificate for:
  - Valid/expired certificate
  - Days until expiry
  - Certificate issuer and subject
  - Weak protocol versions (TLS 1.0, 1.1, SSLv3)
  - Self-signed certificate detection
"""

import ssl
import socket
import logging
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Severity levels
CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"


def check_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Perform full SSL/TLS check on a domain.

    Returns a dict with:
      - issues: list of found problems with severity
      - score_deduction: how many points to subtract from total score
      - details: raw certificate info
    """
    issues = []
    details = {}
    score_deduction = 0

    # Strip protocol and path if present
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    # ── 1. Check if HTTPS is even available ──────────────────────────
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.create_connection((clean_domain, port), timeout=10),
            server_hostname=clean_domain
        )
        cert = conn.getpeercert()
        conn.close()
    except ssl.SSLCertVerificationError as e:
        issues.append({
            "title": "SSL Certificate Verification Failed",
            "severity": CRITICAL,
            "description": f"The SSL certificate could not be verified: {str(e)}",
            "recommendation": "Obtain a valid SSL certificate from a trusted Certificate Authority (CA)."
        })
        score_deduction += 40
        return _build_result(issues, score_deduction, details)

    except ssl.SSLError as e:
        issues.append({
            "title": "SSL Error",
            "severity": HIGH,
            "description": f"SSL handshake failed: {str(e)}",
            "recommendation": "Review your server's SSL configuration."
        })
        score_deduction += 30
        return _build_result(issues, score_deduction, details)

    except (socket.timeout, ConnectionRefusedError, OSError):
        issues.append({
            "title": "HTTPS Not Available",
            "severity": CRITICAL,
            "description": f"Could not connect to {clean_domain}:{port}. HTTPS may not be enabled.",
            "recommendation": "Enable HTTPS on your server and obtain a valid SSL certificate."
        })
        score_deduction += 50
        return _build_result(issues, score_deduction, details)

    # ── 2. Parse certificate details ─────────────────────────────────
    try:
        subject    = dict(x[0] for x in cert.get("subject", []))
        issuer     = dict(x[0] for x in cert.get("issuer", []))
        not_after  = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        san        = cert.get("subjectAltName", [])

        details = {
            "common_name":  subject.get("commonName", "Unknown"),
            "issuer":       issuer.get("organizationName", "Unknown"),
            "valid_from":   not_before,
            "valid_until":  not_after,
            "san_domains":  [v for k, v in san if k == "DNS"],
        }

        # ── 3. Check expiry ──────────────────────────────────────────
        if not_after:
            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            now       = datetime.now(timezone.utc)
            days_left = (expiry_dt - now).days
            details["days_until_expiry"] = days_left

            if days_left < 0:
                issues.append({
                    "title": "SSL Certificate Expired",
                    "severity": CRITICAL,
                    "description": f"Certificate expired {abs(days_left)} days ago.",
                    "recommendation": "Renew your SSL certificate immediately. Consider using Let's Encrypt for free auto-renewal."
                })
                score_deduction += 50

            elif days_left < 15:
                issues.append({
                    "title": "SSL Certificate Expiring Very Soon",
                    "severity": HIGH,
                    "description": f"Certificate expires in {days_left} days.",
                    "recommendation": "Renew your SSL certificate immediately."
                })
                score_deduction += 20

            elif days_left < 30:
                issues.append({
                    "title": "SSL Certificate Expiring Soon",
                    "severity": MEDIUM,
                    "description": f"Certificate expires in {days_left} days.",
                    "recommendation": "Plan to renew your SSL certificate within the next week."
                })
                score_deduction += 10

        # ── 4. Self-signed check ─────────────────────────────────────
        if subject == issuer:
            issues.append({
                "title": "Self-Signed Certificate",
                "severity": HIGH,
                "description": "The certificate is self-signed and will not be trusted by browsers.",
                "recommendation": "Replace with a certificate from a trusted CA. Let's Encrypt provides free certificates."
            })
            score_deduction += 25

    except Exception as e:
        logger.error(f"SSL cert parsing error for {clean_domain}: {e}")
        details["parse_error"] = str(e)

    # ── 5. Check for weak protocol support ───────────────────────────
    weak_protocols = _check_weak_protocols(clean_domain, port)
    if weak_protocols:
        issues.append({
            "title": "Weak SSL/TLS Protocols Supported",
            "severity": HIGH,
            "description": f"Server supports outdated protocols: {', '.join(weak_protocols)}",
            "recommendation": "Disable TLS 1.0, TLS 1.1 and SSLv3 on your server. Only allow TLS 1.2 and TLS 1.3."
        })
        score_deduction += 15

    # If no issues found, that's great
    if not issues:
        issues.append({
            "title": "SSL Certificate is Valid",
            "severity": INFO,
            "description": f"Certificate is valid and expires in {details.get('days_until_expiry', '?')} days.",
            "recommendation": "No action needed. Keep auto-renewal enabled."
        })

    return _build_result(issues, score_deduction, details)


def _check_weak_protocols(domain: str, port: int) -> list:
    """Check if the server accepts weak/deprecated TLS versions."""
    weak = []
    deprecated = [
        ("SSLv3",   ssl.PROTOCOL_TLS_CLIENT),
        ("TLSv1",   ssl.PROTOCOL_TLS_CLIENT),
        ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT),
    ]
    min_versions = {
        "TLSv1":   ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    }

    for name, _ in deprecated:
        if name not in min_versions:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = min_versions[name]
            ctx.maximum_version = min_versions[name]
            with socket.create_connection((domain, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain):
                    weak.append(name)
        except Exception:
            pass  # Protocol not supported (good)

    return weak


def _build_result(issues: list, score_deduction: int, details: dict) -> Dict[str, Any]:
    return {
        "scanner":         "ssl",
        "issues":          issues,
        "score_deduction": min(score_deduction, 100),
        "details":         details
    }
