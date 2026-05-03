"""
Firebase Admin Utility
======================
Handles Firestore read/write and Firebase Auth token verification.

Reads credentials from a single environment variable:
  FIREBASE_SERVICE_ACCOUNT = full service account JSON (as string)

Firestore collections:
  - scans/{scan_id}         → scan results
  - users/{user_uid}/usage  → daily scan count tracking
"""

import os
import json
import logging
from datetime import datetime, timezone

import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Initialization
# ─────────────────────────────────────────────

_db = None


def _init_firebase():
    global _db
    if firebase_admin._apps:
        _db = firestore.client()
        return

    raw = os.environ.get("FIREBASE_SERVICE_ACCOUNT", "")
    if not raw:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT environment variable is not set.")

    try:
        service_account_info = json.loads(raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"FIREBASE_SERVICE_ACCOUNT is not valid JSON: {e}")

    cred = credentials.Certificate(service_account_info)
    firebase_admin.initialize_app(cred)
    _db = firestore.client()
    logger.info("Firebase Admin SDK initialized successfully.")


# Initialize on import
try:
    _init_firebase()
except Exception as e:
    logger.error(f"Firebase initialization failed: {e}")
    _db = None


# ─────────────────────────────────────────────
# Auth
# ─────────────────────────────────────────────

def verify_token(id_token: str) -> dict:
    """
    Verify Firebase ID token from frontend.
    Returns decoded token dict with uid, email etc.
    Raises firebase_auth.InvalidIdTokenError if invalid.
    """
    if not id_token:
        raise ValueError("No token provided.")
    return firebase_auth.verify_id_token(id_token)


# ─────────────────────────────────────────────
# Scan Results
# ─────────────────────────────────────────────

def save_scan_result(user_uid: str, scan_id: str, result: dict) -> None:
    """Save full scan result to Firestore under scans/{scan_id}."""
    if not _db:
        logger.warning("Firestore not available. Skipping save_scan_result.")
        return
    try:
        _db.collection("scans").document(scan_id).set({
            **result,
            "user_uid":   user_uid,
            "created_at": firestore.SERVER_TIMESTAMP,
        })
        logger.info(f"Scan {scan_id} saved to Firestore.")
    except Exception as e:
        logger.error(f"Failed to save scan {scan_id}: {e}")
        raise


def get_scan_result(scan_id: str) -> dict | None:
    """Fetch a single scan result by scan_id."""
    if not _db:
        logger.warning("Firestore not available. Skipping get_scan_result.")
        return None
    try:
        doc = _db.collection("scans").document(scan_id).get()
        return doc.to_dict() if doc.exists else None
    except Exception as e:
        logger.error(f"Failed to get scan {scan_id}: {e}")
        return None


def get_user_scans(user_uid: str, limit: int = 20) -> list:
    """Get recent scans for a user, newest first."""
    if not _db:
        logger.warning("Firestore not available. Skipping get_user_scans.")
        return []
    try:
        docs = (
            _db.collection("scans")
            .where("user_uid", "==", user_uid)
            .order_by("created_at", direction=firestore.Query.DESCENDING)
            .limit(limit)
            .stream()
        )
        return [{"id": doc.id, **doc.to_dict()} for doc in docs]
    except Exception as e:
        logger.error(f"Failed to get scans for user {user_uid}: {e}")
        return []


# ─────────────────────────────────────────────
# Daily Scan Usage Tracking
# ─────────────────────────────────────────────

def get_today_scan_count(user_uid: str) -> int:
    """Return how many scans this user has done today (UTC date)."""
    if not _db:
        return 0
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        doc = _db.collection("usage").document(f"{user_uid}_{today}").get()
        if doc.exists:
            return doc.to_dict().get("count", 0)
        return 0
    except Exception as e:
        logger.error(f"Failed to get scan count for {user_uid}: {e}")
        return 0


def increment_scan_count(user_uid: str) -> int:
    """
    Increment today's scan count for a user.
    Returns new count after increment.
    """
    if not _db:
        return 1
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    doc_ref = _db.collection("usage").document(f"{user_uid}_{today}")
    try:
        doc_ref.set({
            "user_uid":   user_uid,
            "date":       today,
            "count":      firestore.Increment(1),
            "updated_at": firestore.SERVER_TIMESTAMP,
        }, merge=True)
        doc = doc_ref.get()
        return doc.to_dict().get("count", 1)
    except Exception as e:
        logger.error(f"Failed to increment scan count for {user_uid}: {e}")
        return 1
