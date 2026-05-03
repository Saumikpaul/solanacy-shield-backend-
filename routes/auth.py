"""
Auth Route
==========
Verifies Firebase ID tokens sent from the frontend.
Protects all scan and report endpoints.

Frontend must send header:
  Authorization: Bearer <firebase_id_token>
"""

import logging
from functools import wraps
from flask import Blueprint, request, jsonify
from firebase_admin import auth as firebase_auth

auth_bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Token Verification Decorator
# ─────────────────────────────────────────────

def require_auth(f):
    """
    Decorator to verify Firebase ID token on protected endpoints.
    Sets request.user_uid and request.user_email on success.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split("Bearer ")[1].strip()

        if not token:
            return jsonify({"error": "Token is empty"}), 401

        try:
            decoded_token = firebase_auth.verify_id_token(token)
            request.user_uid   = decoded_token["uid"]
            request.user_email = decoded_token.get("email", "")
            logger.info(f"Authenticated user: {request.user_uid}")
        except firebase_auth.ExpiredIdTokenError:
            return jsonify({"error": "Token has expired. Please log in again."}), 401
        except firebase_auth.InvalidIdTokenError:
            return jsonify({"error": "Invalid token. Please log in again."}), 401
        except Exception as e:
            logger.warning(f"Token verification failed: {e}")
            return jsonify({"error": "Authentication failed."}), 401

        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# Auth Status Route
# ─────────────────────────────────────────────

@auth_bp.route("/status", methods=["GET"])
def auth_status():
    """Check if auth system is live."""
    return jsonify({
        "auth_mode": "firebase",
        "message":   "Firebase Auth is active."
    }), 200
