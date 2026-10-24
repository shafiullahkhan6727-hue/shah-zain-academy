from pathlib import Path
import os
import secrets
import sys

base = Path(__file__).resolve().parent.parent
app_file = base / "backend" / "app.py"
source = app_file.read_text()

marker = '@app.get("/api/materials/<path:filename>")'
error_marker = '@app.errorhandler(413)'

if marker not in source or error_marker not in source:
    sys.exit("ERROR: Expected routes not found. No changes made.")

if '@app.post("/api/admin/login")' in source:
    sys.exit("Admin routes already exist. No changes made.")

backup = base / "backups"
backup.mkdir(exist_ok=True)
backup_file = backup / "app-before-admin-routes.py"

if not backup_file.exists():
    backup_file.write_text(source)

old = 'app.secret_key = os.environ.get("ACADEMY_SECRET_KEY") or secrets.token_hex(32)'
if old not in source:
    sys.exit("ERROR: Secret-key line differs. No changes made.")

secret_file = base / "backend" / ".secret_key"
if not os.environ.get("ACADEMY_SECRET_KEY") and not secret_file.exists():
    secret_file.write_text(secrets.token_hex(48))
    try:
        secret_file.chmod(0o600)
    except OSError:
        pass

secret_code = '''SECRET_FILE = BASE / "backend" / ".secret_key"
app.secret_key = os.environ.get("ACADEMY_SECRET_KEY") or SECRET_FILE.read_text().strip()
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"'''

source = source.replace(old, secret_code, 1)

routes = '''
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

'''

source = source.replace(marker, routes + marker, 1)

start = source.index(marker)
end = source.index(error_marker, start)

material_route = '''
@app.get("/api/materials/<path:filename>")
@login_required
def protected_material(filename):
    safe_name = filename.replace("\\\\\\\\", "/").lstrip("/")
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

'''

source = source[:start] + material_route + source[end:]

temp = app_file.with_suffix(".py.new")
temp.write_text(source)
os.replace(temp, app_file)
print("Admin routes added.")
print("Package access rules added.")
print("Session secret configured.")
