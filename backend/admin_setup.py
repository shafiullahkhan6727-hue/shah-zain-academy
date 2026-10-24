from getpass import getpass
from pathlib import Path
import sqlite3
from werkzeug.security import generate_password_hash

BASE = Path(__file__).resolve().parent.parent
DB = BASE / "backend" / "academy.db"

print("SHAH ZAIN ACADEMY - ADMIN SETUP")
username = input("Choose admin username: ").strip().lower()
if not username or len(username) < 4:
    raise SystemExit("Username must be at least 4 characters.")

password = getpass("Create a NEW strong admin password (input hidden): ")
confirm = getpass("Confirm admin password: ")

if password != confirm:
    raise SystemExit("Passwords do not match.")
if len(password) < 12:
    raise SystemExit("Use at least 12 characters for a stronger password.")

with sqlite3.connect(DB) as con:
    con.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        )
    """)
    existing = con.execute(
        "SELECT id FROM admins WHERE username=?", (username,)
    ).fetchone()
    if existing:
        con.execute(
            "UPDATE admins SET password_hash=?, active=1 WHERE username=?",
            (generate_password_hash(password), username)
        )
        print("Admin password updated.")
    else:
        con.execute(
            "INSERT INTO admins(username,password_hash) VALUES(?,?)",
            (username, generate_password_hash(password))
        )
        print("Admin account created.")

print("Credentials stored as a password hash in the database.")
