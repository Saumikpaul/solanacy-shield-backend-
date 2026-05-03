"""
Domain Verification Utility
============================
Verifies that a user owns the domain they want to scan.
User must add a DNS TXT record to prove ownership.

Flow:
  1. Backend generates a unique token for the user+domain
  2. User adds TXT record: security-audit-verify=<token>
  3. Backend calls verify_domain_ownership() to confirm
"""

import os
import hashlib
import logging
import dns.resolver
from typing import Tuple

logger = logging.getLogger(__name__)

# Prefix used in the TXT record value
TXT_RECORD_PREFIX = "security-audit-verify"


def generate_verification_token(user_uid: str, domain: str) -> str:
    """
    Generate a deterministic verification token for a user+domain pair.
    Same input always gives same token, so user can retry without new token.
    """
    secret = os.environ.get("SECRET_KEY", "fallback-secret")
    raw = f"{user_uid}:{domain}:{secret}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def get_expected_txt_record(user_uid: str, domain: str) -> str:
    """Return the full TXT record value the user must add to their DNS."""
    token = generate_verification_token(user_uid, domain)
    return f"{TXT_RECORD_PREFIX}={token}"


def verify_domain_ownership(user_uid: str, domain: str) -> Tuple[bool, str]:
    """
    Check if the user has added the correct TXT record to their domain.

    Returns:
        (True, "Verified")  if TXT record found and matches
        (False, reason_str) if not found or wrong value
    """
    expected = get_expected_txt_record(user_uid, domain)

    # Strip protocol if user accidentally includes it
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        answers = dns.resolver.resolve(clean_domain, "TXT")
    except dns.resolver.NXDOMAIN:
        return False, f"Domain '{clean_domain}' does not exist or cannot be resolved."
    except dns.resolver.NoAnswer:
        return False, f"No TXT records found for '{clean_domain}'."
    except dns.exception.DNSException as e:
        logger.error(f"DNS lookup error for {clean_domain}: {e}")
        return False, f"DNS lookup failed: {str(e)}"

    # Check each TXT record
    found_records = []
    for rdata in answers:
        for txt_string in rdata.strings:
            record_value = txt_string.decode("utf-8", errors="ignore").strip()
            found_records.append(record_value)
            if record_value == expected:
                logger.info(f"Domain {clean_domain} verified for user {user_uid}")
                return True, "Domain ownership verified successfully."

    logger.warning(
        f"TXT record not found for {clean_domain}. "
        f"Expected: {expected}. Found: {found_records}"
    )
    return False, (
        f"TXT record not found. Please add the following TXT record to your domain DNS:\n"
        f"Name: @ (or your domain root)\n"
        f"Value: {expected}\n"
        f"Then wait 5-10 minutes for DNS to propagate and try again."
    )


def clean_url_to_domain(url: str) -> str:
    """Extract base domain from a URL string."""
    return url.replace("https://", "").replace("http://", "").split("/")[0].strip()
