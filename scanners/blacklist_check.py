"""
Blacklist / Reputation Checker
================================
Checks if the target URL/domain is flagged in:
  - Google Safe Browsing API (malware, phishing, unwanted software)
  - Basic DNS blacklist check (DNSBL)

Google Safe Browsing API is FREE with a Google Cloud API key.
Sign up: https://developers.google.com/safe-browsing/v4/get-started
"""

import os
import logging
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)

CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"

SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Threat types to check
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",     # Phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION"
]

PLATFORM_TYPES   = ["ANY_PLATFORM"]
THREAT_ENTRY_TYPES = ["URL"]


def check_blacklist(url: str) -> Dict[str, Any]:
    """
    Check the URL against Google Safe Browsing and basic reputation checks.
    """
    issues          = []
    score_deduction  = 0
    details         = {}

    if not url.startswith("http"):
        url = "https://" + url

    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    # ── 1. Google Safe Browsing ───────────────────────────────────────
    api_key = os.environ.get("SAFE_BROWSING_API_KEY", "")

    if not api_key:
        issues.append({
            "title":          "Google Safe Browsing Check Skipped",
            "severity":       INFO,
            "description":    "SAFE_BROWSING_API_KEY not set in environment. Add your free API key to enable this check.",
            "recommendation": "Get a free API key at: https://developers.google.com/safe-browsing/v4/get-started"
        })
    else:
        gsb_result = _check_google_safe_browsing(url, api_key)
        details["google_safe_browsing"] = gsb_result

        if gsb_result.get("flagged"):
            threats = gsb_result.get("threats", [])
            threat_names = [t.get("threatType", "Unknown") for t in threats]
            issues.append({
                "title":          "Domain Flagged by Google Safe Browsing",
                "severity":       CRITICAL,
                "description":    f"Google Safe Browsing has flagged this URL. Threat types: {', '.join(threat_names)}",
                "recommendation": "Immediately investigate and clean the site. Submit for review at: https://search.google.com/search-console/security-issues"
            })
            score_deduction += 50
        else:
            issues.append({
                "title":          "Google Safe Browsing: Clean",
                "severity":       INFO,
                "description":    "Domain is not flagged in Google Safe Browsing database.",
                "recommendation": "No action needed. Re-check periodically."
            })

    # ── 2. DNSBL Check (basic spam/reputation) ────────────────────────
    dnsbl_result = _check_dnsbl(domain)
    details["dnsbl"] = dnsbl_result

    if dnsbl_result.get("listed"):
        listed_on = dnsbl_result.get("listed_on", [])
        issues.append({
            "title":          "Domain Listed on Spam/Reputation Blacklist",
            "severity":       HIGH,
            "description":    f"Domain is listed on: {', '.join(listed_on)}. This can affect email deliverability and user trust.",
            "recommendation": "Contact the blacklist providers to request removal after fixing the underlying issue."
        })
        score_deduction += 25
    else:
        issues.append({
            "title":          "Domain Not on DNSBL Blacklists",
            "severity":       INFO,
            "description":    "Domain is not listed on checked DNS blacklists.",
            "recommendation": "No action needed."
        })

    return _build_result(issues, score_deduction, details)


def _check_google_safe_browsing(url: str, api_key: str) -> dict:
    """Query Google Safe Browsing API v4."""
    payload = {
        "client": {
            "clientId":      "security-audit-tool",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes":      THREAT_TYPES,
            "platformTypes":    PLATFORM_TYPES,
            "threatEntryTypes": THREAT_ENTRY_TYPES,
            "threatEntries":    [{"url": url}]
        }
    }

    try:
        response = requests.post(
            f"{SAFE_BROWSING_API_URL}?key={api_key}",
            json=payload,
            timeout=10
        )
        data = response.json()

        if "matches" in data and data["matches"]:
            return {
                "flagged": True,
                "threats": data["matches"]
            }
        return {"flagged": False, "threats": []}

    except requests.exceptions.RequestException as e:
        logger.error(f"Google Safe Browsing API error: {e}")
        return {"flagged": False, "error": str(e)}

    except Exception as e:
        logger.error(f"Unexpected Safe Browsing error: {e}")
        return {"flagged": False, "error": str(e)}


def _check_dnsbl(domain: str) -> dict:
    """
    Check domain against common DNS-based blacklists.
    Basic check using DNS resolution trick.
    """
    import dns.resolver

    # Common DNSBL services
    DNSBL_LIST = [
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "dnsbl.sorbs.net",
    ]

    listed_on = []

    # Try to resolve the IP first
    try:
        ip = dns.resolver.resolve(domain, "A")[0].address
        # Reverse the IP for DNSBL lookup
        reversed_ip = ".".join(reversed(ip.split(".")))

        for dnsbl in DNSBL_LIST:
            lookup = f"{reversed_ip}.{dnsbl}"
            try:
                dns.resolver.resolve(lookup, "A")
                listed_on.append(dnsbl)  # Resolution success = listed
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass  # Not listed on this DNSBL
            except Exception:
                pass

    except Exception as e:
        logger.debug(f"DNSBL check error for {domain}: {e}")
        return {"listed": False, "error": str(e)}

    return {
        "listed":    len(listed_on) > 0,
        "listed_on": listed_on
    }


def _build_result(issues: list, score_deduction: int, details: dict) -> Dict[str, Any]:
    return {
        "scanner":         "blacklist",
        "issues":          issues,
        "score_deduction": min(score_deduction, 100),
        "details":         details
    }
