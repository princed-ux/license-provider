# license_admin/generate_license_online.py
import os
import sqlite3
import hashlib
import uuid
import time
from datetime import datetime, timedelta
import json

# ---------------- PATHS ----------------
# Admin-only folder (plaintext keys + JSON)
ADMIN_FOLDER = os.path.join(os.path.expanduser("~"), "LicenseMailer_admin")
os.makedirs(ADMIN_FOLDER, exist_ok=True)
ADMIN_KEYS_FILE = os.path.join(ADMIN_FOLDER, "keys.txt")
ADMIN_JSON_FILE = os.path.join(ADMIN_FOLDER, "licenses.json")

# Server DB (hashes only) - this will be uploaded to your online server
SERVER_DB = os.path.join(ADMIN_FOLDER, "server_licenses.db")

print("✅ Admin-only folder (you see plaintext keys here):", ADMIN_FOLDER)

# ---------------- HELPERS ----------------
def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

def init_db(db_path: str):
    """Create table if it doesn't exist"""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = sqlite3.connect(db_path, timeout=30)
    db.row_factory = sqlite3.Row
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

def store_hash(db_path: str, key_hash: str, days_valid: int = 30, metadata: str = None):
    """Insert the hash into server DB"""
    db = sqlite3.connect(db_path, timeout=30)
    db.row_factory = sqlite3.Row
    now = int(time.time())
    expires = int((datetime.fromtimestamp(now) + timedelta(days=days_valid)).timestamp())
    db.execute(
        "INSERT OR IGNORE INTO licenses (key_hash, created_at, expires_at, metadata) VALUES (?, ?, ?, ?)",
        (key_hash, now, expires, metadata)
    )
    db.commit()
    db.close()

def save_plain_key(plain_key: str):
    """Save plaintext key locally (admin-only)"""
    try:
        os.makedirs(ADMIN_FOLDER, exist_ok=True)
        with open(ADMIN_KEYS_FILE, "a", encoding="utf-8") as f:
            f.write(plain_key.strip() + "\n")
    except Exception as e:
        print("❌ Failed to write plaintext key:", e)

# ---------------- LICENSE GENERATION ----------------
def generate_license(metadata=None, days_valid: int = 30):
    for attempt in range(10):
        raw = uuid.uuid4().hex.upper()
        key = "-".join([raw[i:i+4] for i in range(0, 16, 4)])
        key_hash = hash_key(key)
        try:
            # Store only hash in server DB
            store_hash(SERVER_DB, key_hash, days_valid, metadata)
            # Save plaintext locally (admin-only)
            save_plain_key(key)
            print(f"✅ Generated license (you see this): {key}")
            return key
        except sqlite3.IntegrityError:
            if attempt == 9:
                raise RuntimeError("Failed to generate unique license after 10 attempts")
            continue

def bulk_generate(total=1, days_valid=30, metadata=None):
    licenses = []
    for _ in range(total):
        licenses.append(generate_license(metadata, days_valid))
    return licenses

# ---------------- MAIN ----------------
if __name__ == "__main__":
    # Init server DB
    init_db(SERVER_DB)
    print("✅ License generator ready!")

    try:
        total = int(input("How many licenses to generate? "))
    except ValueError:
        print("Invalid number, exiting.")
        exit(1)

    try:
        days_valid = int(input("Days valid for each license (default 30): ") or 30)
    except ValueError:
        days_valid = 30

    metadata = input("Enter metadata (optional): ")

    licenses = bulk_generate(total, days_valid, metadata)

    print("\nGenerated license keys (admin-only):")
    for key in licenses:
        print(key)

    # Save JSON locally (admin-only)
    try:
        with open(ADMIN_JSON_FILE, "w", encoding="utf-8") as jf:
            json.dump({"licenses": licenses, "days_valid": days_valid, "metadata": metadata}, jf, indent=4)
        print(f"\nJSON saved to {ADMIN_JSON_FILE}")
    except Exception as e:
        print("❌ Failed to save JSON:", e)

    print(f"\n✅ All {total} license(s) saved. Valid for {days_valid} days each.")
