"""
Scan Route
===========
Main endpoint that:
  1. Validates the request
  2. Checks daily scan limit (free: 1/day, paid tiers: more)
  3. Checks domain ownership verification
  4. Runs all scanners in parallel (with per-scanner timeout)
  5. Calls AI report generator
  6. Saves result to Firestore
  7. Returns the full report

POST /api/scan/start
"""

import uuid
import logging
import threading
from flask import Blueprint, request, jsonify

from routes.auth          import require_auth
from utils.domain_verify  import verify_domain_ownership, clean_url_to_domain
from utils.firebase_admin import (
    save_scan_result,
    get_scan_result,
    get_today_scan_count,
    increment_scan_count,
)

from scanners.ssl_check       import check_ssl
from scanners.headers_check   import check_headers
from scanners.port_scan       import check_ports
from scanners.sqli_check      import check_sqli
from scanners.xss_check       import check_xss
from scanners.dir_scan        import check_exposed_files
from scanners.blacklist_check import check_blacklist
from ai.report_generator      import generate_report

scan_bp = Blueprint("scan", __name__)
logger  = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Plan limits (scans per day)
# ─────────────────────────────────────────────
PLAN_LIMITS = {
    "free":       1,
    "starter":    5,
    "pro":        10,
    "business":   20,
}

SCANNER_TIMEOUT = 30  # seconds per individual scanner


# ─────────────────────────────────────────────
# Helper: get user plan from Firestore (stub → free)
# Replace this later when billing is connected
# ─────────────────────────────────────────────
def get_user_plan(user_uid: str) -> str:
    """Return user's current plan. Defaults to free."""
    # TODO: fetch from Firestore users/{user_uid} when billing is live
    return "free"


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@scan_bp.route("/verify-domain", methods=["POST"])
@require_auth
def verify_domain():
    """
    Step 1: Generate DNS TXT record for domain ownership proof.
    POST body: { "url": "https://example.com" }
    """
    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify({"error": "URL is required"}), 400

    url    = data["url"].strip()
    domain = clean_url_to_domain(url)

    from utils.domain_verify import get_expected_txt_record
    txt_record = get_expected_txt_record(request.user_uid, domain)

    return jsonify({
        "domain":       domain,
        "txt_record":   txt_record,
        "instructions": (
            f"Add this TXT record to your domain '{domain}' DNS settings:\n"
            f"Name: @ (root domain)\n"
            f"Type: TXT\n"
            f"Value: {txt_record}\n\n"
            f"Wait 5–10 minutes for DNS propagation, then click 'Verify & Start Scan'."
        )
    }), 200


@scan_bp.route("/start", methods=["POST"])
@require_auth
def start_scan():
    """
    Step 2: Run the full security scan.

    POST body:
    {
      "url": "https://example.com",
      "skip_verification": false
    }
    """
    data = request.get_json()
    if not data or not data.get("url"):
        return jsonify({"error": "URL is required"}), 400

    url    = data["url"].strip()
    domain = clean_url_to_domain(url)

    if not url.startswith("http"):
        url = "https://" + url

    # ── Daily scan limit check ────────────────────────────────────────
    plan       = get_user_plan(request.user_uid)
    daily_limit = PLAN_LIMITS.get(plan, 1)
    used_today  = get_today_scan_count(request.user_uid)

    if used_today >= daily_limit:
        return jsonify({
            "error": "Daily scan limit reached.",
            "plan":  plan,
            "limit": daily_limit,
            "used":  used_today,
            "upgrade_message": (
                "Upgrade your plan to scan more times per day. "
                "Visit solanacyshield.in/pricing"
            )
        }), 429

    # ── Domain Ownership Verification ────────────────────────────────
    skip_verify = data.get("skip_verification", False)

    if not skip_verify:
        verified, reason = verify_domain_ownership(request.user_uid, domain)
        if not verified:
            return jsonify({
                "error":  "Domain ownership verification failed.",
                "reason": reason
            }), 403

    logger.info(f"Starting scan for {url} — user: {request.user_uid} — plan: {plan}")

    # ── Increment usage count BEFORE scan (prevents abuse) ───────────
    increment_scan_count(request.user_uid)

    # ── Run all scanners in parallel ──────────────────────────────────
    scan_id = str(uuid.uuid4())
    results = {}
    errors  = {}

    scanners = {
        "ssl":           (check_ssl,           domain),
        "headers":       (check_headers,       url),
        "ports":         (check_ports,         domain),
        "sqli":          (check_sqli,          url),
        "xss":           (check_xss,           url),
        "exposed_files": (check_exposed_files, url),
        "blacklist":     (check_blacklist,     url),
    }

    threads = []
    lock    = threading.Lock()

    def run_scanner(name, fn, target):
        try:
            result = fn(target)
            with lock:
                results[name] = result
        except Exception as e:
            logger.error(f"Scanner '{name}' failed: {e}")
            with lock:
                errors[name] = str(e)

    for name, (fn, target) in scanners.items():
        t = threading.Thread(target=run_scanner, args=(name, fn, target))
        t.daemon = True
        threads.append(t)
        t.start()

    # Wait for all scanners — SCANNER_TIMEOUT per scanner max
    for t in threads:
        t.join(timeout=SCANNER_TIMEOUT)

    scan_results_list = list(results.values())

    # ── Generate AI Report ────────────────────────────────────────────
    try:
        report = generate_report(url, scan_results_list, request.user_uid)
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        report = {
            "target_url":        url,
            "security_score":    0,
            "risk_level":        "Unknown",
            "executive_summary": "Report generation failed. Raw scan data is available.",
            "findings":          [],
            "top_priorities":    [],
            "positive_findings": [],
            "scan_metadata":     {},
            "error":             str(e)
        }

    # ── Build full result ─────────────────────────────────────────────
    full_result = {
        "scan_id":      scan_id,
        "url":          url,
        "domain":       domain,
        "report":       report,
        "raw_results":  results,
        "scan_errors":  errors,
        "user_uid":     request.user_uid,
        "plan":         plan,
        "scans_used_today": used_today + 1,
        "scans_remaining":  max(0, daily_limit - used_today - 1),
    }

    # ── Save to Firestore ─────────────────────────────────────────────
    try:
        save_scan_result(request.user_uid, scan_id, full_result)
    except Exception as e:
        logger.warning(f"Could not save scan to Firestore: {e}")

    logger.info(
        f"Scan {scan_id} complete — {url} — "
        f"score: {report.get('security_score', 'N/A')} — "
        f"errors: {list(errors.keys()) if errors else 'none'}"
    )
    return jsonify(full_result), 200


@scan_bp.route("/history", methods=["GET"])
@require_auth
def scan_history():
    """Get last 20 scans for the authenticated user."""
    from utils.firebase_admin import get_user_scans
    scans = get_user_scans(request.user_uid)
    return jsonify({"scans": scans}), 200


@scan_bp.route("/status/<scan_id>", methods=["GET"])
@require_auth
def scan_status(scan_id):
    """Fetch a specific scan result by ID."""
    result = get_scan_result(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404
    # Security: only owner can view
    if result.get("user_uid") != request.user_uid:
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(result), 200


@scan_bp.route("/usage", methods=["GET"])
@require_auth
def scan_usage():
    """Return today's scan usage and limit for the user."""
    plan        = get_user_plan(request.user_uid)
    daily_limit = PLAN_LIMITS.get(plan, 1)
    used_today  = get_today_scan_count(request.user_uid)

    return jsonify({
        "plan":            plan,
        "limit":           daily_limit,
        "used_today":      used_today,
        "remaining":       max(0, daily_limit - used_today),
        "limit_reached":   used_today >= daily_limit,
    }), 200
