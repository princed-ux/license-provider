# license_admin/server.py
import os
import sqlite3
import hashlib
import uuid
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address 
import logging  
from logging.handlers import RotatingFileHandler

# ---------------- CONFIG ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "licenses.db")
PORT = int(os.environ.get("PORT", 5005))
USE_SSL = os.environ.get("USE_SSL", "0") == "1"
SSL_CERT = os.environ.get("SSL_CERT", "cert.pem")
SSL_KEY = os.environ.get("SSL_KEY", "key.pem")

# ---------------- FLASK ----------------
app = Flask(__name__)

# Rate limiting to avoid abuse
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# ---------------- LOGGING ----------------
LOG_FILE = os.path.join(BASE_DIR, "license_server.log")
handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# ---------------- DATABASE ----------------
def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            activated_at INTEGER,
            activation_id TEXT,
            revoked INTEGER DEFAULT 0,
            metadata TEXT
        );
    """)
    db.commit()
    db.close()

# ---------------- HELPERS ----------------
def hash_key(key: str):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def get_license_row_by_hash(k_hash):
    with get_db() as db:
        return db.execute("SELECT * FROM licenses WHERE key_hash=?", (k_hash,)).fetchone()

def activate_license(k_hash, install_id):
    now = int(time.time())
    with get_db() as db:
        db.execute(
            "UPDATE licenses SET activated_at=?, activation_id=? WHERE key_hash=?",
            (now, install_id, k_hash)
        )
        db.commit()

# ---------------- ROUTES ----------------
@app.route("/validate_license", methods=["POST"])
@limiter.limit("10 per minute")
def validate_license():
    data = request.get_json() or {}
    license_key = (data.get("license") or "").strip()
    install_id = (data.get("installation_id") or "").strip()

    if not license_key:
        return jsonify({"success": False, "message": "Missing license."}), 400

    k_hash = hash_key(license_key)
    row = get_license_row_by_hash(k_hash)

    if row is None:
        return jsonify({"success": False, "message": "Invalid license."}), 403

    if row["revoked"]:
        return jsonify({"success": False, "message": "License revoked."}), 403

    now = int(time.time())
    if row["expires_at"] and now > row["expires_at"]:
        return jsonify({"success": False, "message": "License expired."}), 403

    # First activation
    if row["activation_id"] is None:
        activate_license(k_hash, install_id)
        return jsonify({"success": True, "message": "License activated.", "expires_at": row["expires_at"]})

    # Same device reuse
    if row["activation_id"] == install_id:
        return jsonify({"success": True, "message": "Welcome back!", "expires_at": row["expires_at"]})

    # Different device
    return jsonify({"success": False, "message": "License already used on another device."}), 403

@app.route("/list_licenses", methods=["GET"])
def list_licenses():
    # Optional admin-only endpoint (protect with a secret in headers)
    ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change-me")
    if request.headers.get("X-ADMIN-SECRET") != ADMIN_SECRET:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    with get_db() as db:
        rows = db.execute("SELECT id, key_hash, created_at, expires_at, activated_at, activation_id, revoked, metadata FROM licenses").fetchall()
        return jsonify({"success": True, "licenses": [dict(r) for r in rows]})

# ---------------- RUN SERVER ----------------
if __name__ == "__main__":
    init_db()
    if USE_SSL and os.path.exists(SSL_CERT) and os.path.exists(SSL_KEY):
        app.logger.info("Starting License Server with SSL...")
        app.run(host="0.0.0.0", port=PORT, ssl_context=(SSL_CERT, SSL_KEY))
    else:
        app.logger.info("Starting License Server without SSL...")
        app.run(host="0.0.0.0", port=PORT)
