from flask import Flask, request, jsonify, session, send_file, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3, os, secrets
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
DB = BASE / "backend" / "academy.db"
PRIVATE = BASE / "private_materials"

app = Flask(__name__)
SECRET_FILE = BASE / "backend" / ".secret_key"
app.secret_key = os.environ.get("ACADEMY_SECRET_KEY") or SECRET_FILE.read_text().strip()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

def connect():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            department TEXT NOT NULL,
            package INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            method TEXT NOT NULL,
            transaction_ref TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
    PRIVATE.mkdir(exist_ok=True)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify(error="Please log in first"), 401
        return fn(*args, **kwargs)
    return wrapper

@app.get("/api/health")
def health():
    return jsonify(status="running", message="Academy backend is online")

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if "@" not in email or len(password) < 10:
        return jsonify(error="Valid email and password of at least 10 characters required"), 400
    try:
        with connect() as con:
            cur = con.execute(
                "INSERT INTO users(email,password_hash) VALUES(?,?)",
                (email, generate_password_hash(password))
            )
            user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(error="Account already exists"), 409
    session["user_id"] = user_id
    return jsonify(message="Account created", user_id=user_id), 201

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    with connect() as con:
        user = con.execute(
            "SELECT * FROM users WHERE email=?",
            (str(data.get("email", "")).strip().lower(),)
        ).fetchone()
    if not user or not check_password_hash(user["password_hash"], str(data.get("password", ""))):
        return jsonify(error="Invalid email or password"), 401
    session["user_id"] = user["id"]
    return jsonify(message="Login successful")

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(message="Logged out")

@app.post("/api/orders")
@login_required
def create_order():
    data = request.get_json(silent=True) or {}
    department = str(data.get("department", "")).strip()
    package = data.get("package")
    method = str(data.get("method", "")).strip().lower()
    ref = str(data.get("transaction_ref", "")).strip()

    prices = {1000: 1000, 3500: 3500}
    methods = {"easypaisa", "jazzcash", "bank"}

    try:
        package = int(package)
    except (TypeError, ValueError):
        return jsonify(error="Invalid package"), 400

    if not department or package not in prices or method not in methods or not ref:
        return jsonify(error="Department, valid package, payment method and reference required"), 400

    with connect() as con:
        cur = con.execute(
            """INSERT INTO orders
            (user_id,department,package,amount,method,transaction_ref,status)
            VALUES(?,?,?,?,?,?, 'PENDING')""",
            (session["user_id"], department, package, prices[package], method, ref)
        )
        order_id = cur.lastrowid

    return jsonify(
        order_id=order_id,
        status="PENDING",
        message="Payment request received. Materials remain locked until verified."
    ), 201

@app.get("/api/my-orders")
@login_required
def my_orders():
    with connect() as con:
        rows = con.execute(
            "SELECT id,department,package,amount,method,status FROM orders WHERE user_id=? ORDER BY id DESC",
            (session["user_id"],)
        ).fetchall()
    return jsonify(orders=[dict(r) for r in rows])


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return jsonify(error="Admin login required"), 401
        return fn(*args, **kwargs)
    return wrapper

def valid_admin_csrf():
    expected = session.get("admin_csrf", "")
    supplied = request.headers.get("X-Admin-CSRF", "")
    return bool(expected and supplied and secrets.compare_digest(expected, supplied))

@app.post("/api/admin/login")
def admin_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))

    with connect() as con:
        admin = con.execute(
            "SELECT id, username, password_hash, active FROM admins WHERE username=?",
            (username,)
        ).fetchone()

    if not admin or not admin["active"] or not check_password_hash(admin["password_hash"], password):
        return jsonify(error="Invalid admin credentials"), 401

    session.clear()
    session["admin_id"] = admin["id"]
    session["admin_username"] = admin["username"]
    session["admin_csrf"] = secrets.token_urlsafe(32)
    return jsonify(message="Admin login successful",
                   username=admin["username"], csrf_token=session["admin_csrf"])

@app.post("/api/admin/logout")
@admin_required
def admin_logout():
    session.clear()
    return jsonify(message="Admin logged out")

@app.get("/api/admin/orders")
@admin_required
def admin_orders():
    with connect() as con:
        rows = con.execute("""
            SELECT o.id, u.email, o.department, o.package, o.amount,
                   o.method, o.transaction_ref, o.status
            FROM orders o JOIN users u ON u.id=o.user_id
            ORDER BY CASE WHEN o.status='PENDING' THEN 0 ELSE 1 END, o.id DESC
        """).fetchall()
    return jsonify(orders=[dict(row) for row in rows])

def review_order(order_id, status):
    if not valid_admin_csrf():
        return jsonify(error="Valid admin CSRF token required"), 403

    with connect() as con:
        order = con.execute(
            "SELECT status FROM orders WHERE id=?", (order_id,)
        ).fetchone()
        if not order:
            return jsonify(error="Order not found"), 404
        if order["status"] != "PENDING":
            return jsonify(error="Only pending orders can be reviewed"), 409
        con.execute(
            "UPDATE orders SET status=? WHERE id=? AND status='PENDING'",
            (status, order_id)
        )

    return jsonify(order_id=order_id, status=status)

@app.post("/api/admin/orders/<int:order_id>/approve")
@admin_required
def approve_order(order_id):
    return review_order(order_id, "VERIFIED")

@app.post("/api/admin/orders/<int:order_id>/reject")
@admin_required
def reject_order(order_id):
    return review_order(order_id, "REJECTED")


@app.get("/api/materials/<path:filename>")
@login_required
def protected_material(filename):
    safe_name = filename.replace("\\\\", "/").lstrip("/")
    if not safe_name or ".." in safe_name.split("/"):
        return jsonify(error="Invalid material path"), 400

    with connect() as con:
        orders = con.execute(
            """SELECT package FROM orders
               WHERE user_id=? AND status='VERIFIED'""",
            (session["user_id"],)
        ).fetchall()

    complete = any(int(row["package"]) == 3500 for row in orders)
    academic = any(int(row["package"]) == 1000 for row in orders)

    if not complete and (not academic or not safe_name.startswith("academic/")):
        return jsonify(error="Material not included in your verified package"), 403

    from flask import send_from_directory
    return send_from_directory(PRIVATE, safe_name, as_attachment=True)

@app.errorhandler(413)
def too_large(_):
    return jsonify(error="Request too large"), 413

init_db()


@app.get("/admin")
def admin_dashboard_page():
    from flask import send_file
    page = Path(__file__).resolve().parent.parent / "pages" / "admin.html"
    return send_file(page)



# Public website pages and assets
SITE_ROOT = Path(__file__).resolve().parent.parent

@app.get("/")
@app.get("/index.html")
def home_page():
    return send_file(SITE_ROOT / "index.html")

@app.get("/pages/<path:filename>")
def public_pages(filename):
    return send_from_directory(SITE_ROOT / "pages", filename)

@app.get("/assets/<path:filename>")
def public_assets(filename):
    return send_from_directory(SITE_ROOT / "assets", filename)

@app.get("/css/<path:filename>")
def public_css(filename):
    return send_from_directory(SITE_ROOT / "css", filename)

@app.get("/js/<path:filename>")
def public_js(filename):
    return send_from_directory(SITE_ROOT / "js", filename)

@app.get("/website/<path:filename>")
def website_pages(filename):
    return send_from_directory(SITE_ROOT / "website", filename)

if __name__ == "__main__":
    # Local development only; use HTTPS and a production WSGI server online.
    app.run(host="127.0.0.1", port=5000, debug=False)
