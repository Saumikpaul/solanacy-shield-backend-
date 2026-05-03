"""
Solanacy Shield - Backend Server
==================================
Flask backend for the ethical security audit platform.
Handles scan requests, verification, and AI report generation.
"""

import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# App Initialization
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-in-production")
app.config["DEBUG"]      = os.environ.get("DEBUG", "False").lower() == "true"

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────
ALLOWED_ORIGINS = os.environ.get(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://localhost:5500"
).split(",")

CORS(app, resources={
    r"/api/*": {
        "origins":           ALLOWED_ORIGINS,
        "methods":           ["GET", "POST", "OPTIONS"],
        "allow_headers":     ["Content-Type", "Authorization"],
        "supports_credentials": False,
    }
})

# ─────────────────────────────────────────────
# Rate Limiting
# ─────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# ─────────────────────────────────────────────
# Register Blueprints
# ─────────────────────────────────────────────
from routes.ping   import ping_bp
from routes.scan   import scan_bp
from routes.report import report_bp
from routes.auth   import auth_bp

app.register_blueprint(ping_bp)
app.register_blueprint(scan_bp,   url_prefix="/api/scan")
app.register_blueprint(report_bp, url_prefix="/api/report")
app.register_blueprint(auth_bp,   url_prefix="/api/auth")

# ─────────────────────────────────────────────
# Apply strict rate limits to scan endpoints
# These are on top of the per-user daily limits
# in Firestore — double protection
# ─────────────────────────────────────────────
limiter.limit("20 per hour")(scan_bp)        # Max 20 scan requests/hour per IP
limiter.limit("3 per minute")(scan_bp)       # Max 3 scan requests/minute per IP

# ─────────────────────────────────────────────
# Error Handlers
# ─────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(429)
def rate_limit_exceeded(e):
    logger.warning(f"Rate limit exceeded from {get_remote_address()}")
    return jsonify({
        "error":       "Too many requests. Please wait before scanning again.",
        "retry_after": str(e.description)
    }), 429

@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info(f"Starting Solanacy Shield Backend on port {port}")
    app.run(host="0.0.0.0", port=port, debug=app.config["DEBUG"])
