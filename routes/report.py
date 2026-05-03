"""
Report Route
=============
Endpoints to fetch previously generated scan reports.

GET /api/report/<scan_id>   — Fetch one report by ID
GET /api/report/my          — Fetch all reports for current user
"""

import logging
from flask import Blueprint, request, jsonify
from routes.auth import require_auth
from utils.firebase_admin import get_scan_result, get_user_scans

report_bp = Blueprint("report", __name__)
logger    = logging.getLogger(__name__)


@report_bp.route("/<scan_id>", methods=["GET"])
@require_auth
def get_report(scan_id):
    """
    Fetch a specific scan report by its scan ID.
    User must own the report.
    """
    if not scan_id or len(scan_id) != 36:
        return jsonify({"error": "Invalid scan ID format"}), 400

    result = get_scan_result(scan_id)

    if not result:
        return jsonify({"error": "Report not found"}), 404

    # Verify the report belongs to the requesting user
    if result.get("user_uid") != request.user_uid:
        logger.warning(
            f"Unauthorized report access: user {request.user_uid} "
            f"tried to access report {scan_id} owned by {result.get('user_uid')}"
        )
        return jsonify({"error": "Access denied"}), 403

    return jsonify(result), 200


@report_bp.route("/my", methods=["GET"])
@require_auth
def get_my_reports():
    """
    Fetch all scan reports for the currently authenticated user.
    """
    scans = get_user_scans(request.user_uid)

    # Return lightweight list (no raw scan data, just report summaries)
    summaries = []
    for scan in scans:
        report = scan.get("report", {})
        summaries.append({
            "scan_id":        scan.get("scan_id", scan.get("id", "")),
            "url":            scan.get("url", ""),
            "domain":         scan.get("domain", ""),
            "security_score": report.get("security_score", 0),
            "risk_level":     report.get("risk_level", "Unknown"),
            "critical_count": report.get("scan_metadata", {}).get("critical_count", 0),
            "high_count":     report.get("scan_metadata", {}).get("high_count", 0),
            "created_at":     scan.get("created_at", ""),
        })

    # Sort by most recent first
    # Firestore SERVER_TIMESTAMP returns DatetimeWithNanoseconds — convert safely
    def sort_key(x):
        ts = x.get("created_at", "")
        if hasattr(ts, "timestamp"):
            return ts.timestamp()   # Firestore datetime object
        if isinstance(ts, str) and ts:
            return ts               # ISO string fallback
        return 0

    summaries.sort(key=sort_key, reverse=True)

    # Serialize created_at to ISO string for JSON response
    for s in summaries:
        ts = s.get("created_at", "")
        if hasattr(ts, "isoformat"):
            s["created_at"] = ts.isoformat()

    return jsonify({
        "user_uid": request.user_uid,
        "count":    len(summaries),
        "reports":  summaries
    }), 200
