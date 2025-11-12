import sqlite3
import os
from tabulate import tabulate
from datetime import datetime, time as dt_time 

# ---------------- CONFIG ----------------
# Possible database paths
db_paths = [
    os.path.join("license_admin", "licenses.db"),
    "licenses.db"
]

# Find the existing DB
db_file = next((p for p in db_paths if os.path.exists(p)), None)

if not db_file:
    print("⚠ No licenses database found!")
    exit()

# ---------------- CONNECT DB ----------------
conn = sqlite3.connect(db_file)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# ---------------- FILTER OPTIONS ----------------
print("\nWhich licenses would you like to check?")
print("1. All licenses")
print("2. Only activated licenses")
print("3. Only expired licenses")
print("4. Only revoked licenses")

choice = input("Enter choice (1-4, default 1): ").strip() or "1"

try:
    choice = int(choice)
except ValueError:
    choice = 1

# ---------------- BUILD QUERY ----------------
now_ts = int(datetime.now().timestamp())
query = "SELECT * FROM licenses"
params = ()

if choice == 2:
    query += " WHERE activated_at IS NOT NULL AND revoked = 0 AND expires_at > ?"
    params = (now_ts,)
elif choice == 3:
    query += " WHERE expires_at <= ? AND revoked = 0"
    params = (now_ts,)
elif choice == 4:
    query += " WHERE revoked = 1"

query += " ORDER BY created_at DESC"

# ---------------- FETCH AND DISPLAY ----------------
try:
    cur.execute(query, params)
    rows = cur.fetchall()

    if not rows:
        print("\n📭 No licenses found for the selected criteria.")
    else:
        formatted = []
        for row in rows:
            formatted.append([
                row["id"],
                row["key_hash"][:10] + "..." if row["key_hash"] else None,
                datetime.fromtimestamp(row["created_at"]).strftime("%Y-%m-%d"),
                datetime.fromtimestamp(row["expires_at"]).strftime("%Y-%m-%d"),
                datetime.fromtimestamp(row["activated_at"]).strftime("%Y-%m-%d") if row["activated_at"] else "Not activated",
                row["activation_id"] or "None",
                "Yes" if row["revoked"] else "No",
                row["metadata"] or ""
            ])

        print("\n📌 LICENSE DATABASE CONTENTS\n")
        print(tabulate(formatted, headers=[
            "ID", "Key Hash", "Created", "Expires", "Activated",
            "Activation PC ID", "Revoked", "Metadata"
        ], tablefmt="fancy_grid"))

finally:
    conn.close()
