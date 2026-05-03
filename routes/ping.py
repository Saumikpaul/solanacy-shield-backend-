"""
Ping Route
==========
Health check endpoint.
Keeps Render free-tier server alive — frontend pings every 10 min.
"""

import time
from flask import Blueprint, jsonify

ping_bp = Blueprint("ping", __name__)


@ping_bp.route("/ping", methods=["GET"])
def ping():
    return jsonify({
        "status":    "alive",
        "service":   "Solanacy Shield API",
        "timestamp": int(time.time()),
    }), 200


@ping_bp.route("/", methods=["GET"])
def root():
    return jsonify({
        "service": "Solanacy Shield API",
        "version": "1.0.0",
        "status":  "running"
    }), 200
