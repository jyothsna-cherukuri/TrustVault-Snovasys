"""TrustVault: per-document sharing with server-side authorization and an HMAC audit chain.

Prototype note: this is an educational hackathon application, not a certified vault.
"""
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("TRUSTVAULT_DB", ROOT / "trustvault.db"))
STORAGE = Path(os.environ.get("TRUSTVAULT_STORAGE", ROOT / "storage"))
STORAGE.mkdir(parents=True, exist_ok=True)
try:
    STORAGE.chmod(0o700)
except OSError:
    pass

IS_PRODUCTION = os.environ.get("TRUSTVAULT_ENV", "development").lower() == "production"
SECRET_KEY = os.environ.get("TRUSTVAULT_SECRET_KEY")
AUDIT_KEY = os.environ.get("TRUSTVAULT_AUDIT_KEY")
if IS_PRODUCTION:
    if not SECRET_KEY or len(SECRET_KEY) < 32:
        raise RuntimeError("Production requires TRUSTVAULT_SECRET_KEY with at least 32 characters.")
    if not AUDIT_KEY or len(AUDIT_KEY) < 32 or hmac.compare_digest(AUDIT_KEY, SECRET_KEY):
        raise RuntimeError("Production requires a separate TRUSTVAULT_AUDIT_KEY (at least 32 characters).")
else:
    SECRET_KEY = SECRET_KEY or "local-development-only-secret-change-before-deployment"
    AUDIT_KEY = AUDIT_KEY or "local-development-only-audit-key-change-before-deployment"

MAX_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".csv", ".png", ".jpg", ".jpeg", ".docx", ".xlsx"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=MAX_BYTES + 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("COOKIE_SECURE", "1" if IS_PRODUCTION else "0") == "1"),
    PERMANENT_SESSION_LIFETIME=1800,
)

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')), active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS documents(
 id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
 title TEXT NOT NULL, category TEXT NOT NULL, original_name TEXT NOT NULL,
 stored_name TEXT UNIQUE NOT NULL, mime_type TEXT NOT NULL, size_bytes INTEGER NOT NULL,
 sha256 TEXT NOT NULL, created_at TEXT NOT NULL, deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS grants(
 id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL REFERENCES documents(id),
 user_id INTEGER NOT NULL REFERENCES users(id), permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
 granted_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL,
 UNIQUE(document_id,user_id)
);
CREATE TABLE IF NOT EXISTS audit_events(
 id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), actor_name TEXT NOT NULL,
 action TEXT NOT NULL, document_id INTEGER, target_user TEXT, details TEXT NOT NULL,
 created_at TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_documents_title ON documents(title);
CREATE INDEX IF NOT EXISTS idx_grants_user_document ON grants(user_id,document_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);
"""


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect_db():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = connect_db()
    con.executescript(SCHEMA)
    user_count = con.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        # Convenient seeded accounts are enabled only in local development. Production
        # must bootstrap one administrator from environment variables and then create
        # ordinary accounts through the admin UI.
        if not IS_PRODUCTION and os.environ.get("TRUSTVAULT_DEMO_MODE", "1") == "1":
            seed = [
                ("admin", "AdminDemo!2026", "admin"),
                ("owner", "OwnerDemo!2026", "owner"),
                ("viewer", "ViewerDemo!2026", "viewer"),
                ("otherowner", "OtherOwner!2026", "owner"),
            ]
            for username, password, role in seed:
                con.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                            (username, generate_password_hash(password), role))
        else:
            username = os.environ.get("TRUSTVAULT_BOOTSTRAP_ADMIN_USERNAME", "").strip()
            password = os.environ.get("TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD", "")
            if not USERNAME_RE.fullmatch(username) or len(password) < 16:
                con.close()
                raise RuntimeError(
                    "No users exist. Set TRUSTVAULT_BOOTSTRAP_ADMIN_USERNAME (3-40 safe characters) "
                    "and TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD (at least 16 characters) for first startup."
                )
            con.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?, 'admin')",
                        (username, generate_password_hash(password),))
    con.commit()
    con.close()


def audit(actor, action, document_id=None, target_user=None, details=None):
    """Serialize appends and HMAC-chain each event. External WORM export is still needed in production."""
    con = connect_db()
    try:
        con.execute("BEGIN IMMEDIATE")
        last = con.execute("SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
        previous = last["event_hash"] if last else "GENESIS"
        actor_id = actor["id"] if actor else None
        actor_name = actor["username"] if actor else "anonymous"
        detail_text = json.dumps(details or {}, sort_keys=True, separators=(",", ":"))
        created = utcnow()
        payload = {"actor_id": actor_id, "actor_name": actor_name, "action": action,
                   "document_id": document_id, "target_user": target_user, "details": detail_text,
                   "created_at": created, "previous_hash": previous}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hmac.new(AUDIT_KEY.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        con.execute("""INSERT INTO audit_events(actor_id,actor_name,action,document_id,target_user,details,
                      created_at,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?,?,?)""",
                    (actor_id, actor_name, action, document_id, target_user, detail_text, created, previous, digest))
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def current_user():
    if "user_id" not in session:
        return None
    con = connect_db()
    try:
        return con.execute("SELECT * FROM users WHERE id=? AND active=1", (session["user_id"],)).fetchone()
    finally:
        con.close()


@app.before_request
def load_user_and_check_csrf():
    # Give anonymous login forms a CSRF token too, then rotate it after authentication.
    if not session.get("csrf_token"):
        session["csrf_token"] = secrets.token_urlsafe(32)
    g.user = current_user()
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = session.get("csrf_token")
        sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not token or not sent or not hmac.compare_digest(token, sent):
            abort(400, "CSRF token missing or invalid")


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped


def roles(*allowed):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if g.user["role"] not in allowed:
                audit(g.user, "ACCESS_DENIED", details={"route": request.path, "reason": "role"})
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco


def doc_permission(doc_id, required="read"):
    """Authorize the current request against the current DB state. Admin has no content bypass."""
    con = connect_db()
    doc = con.execute("SELECT * FROM documents WHERE id=? AND deleted_at IS NULL", (doc_id,)).fetchone()
    if not doc:
        con.close()
        audit(g.user, "DOCUMENT_ACCESS_DENIED", doc_id, details={"required": required, "reason": "not_found"})
        abort(404)
    if doc["owner_id"] == g.user["id"]:
        con.close()
        return doc
    # Explicit deny: administrator privileges cover metadata and audit operations,
    # never confidential file contents, even if a stale/legacy grant row exists.
    if g.user["role"] == "admin":
        con.close()
        audit(g.user, "DOCUMENT_ACCESS_DENIED", doc_id,
              details={"required": required, "reason": "admin_metadata_only"})
        abort(403)
    grant = con.execute("SELECT permission FROM grants WHERE document_id=? AND user_id=?",
                        (doc_id, g.user["id"])).fetchone()
    con.close()
    allowed = bool(grant) and (required == "read" or grant["permission"] == "edit")
    if not allowed:
        audit(g.user, "DOCUMENT_ACCESS_DENIED", doc_id,
              details={"required": required, "reason": "no_current_grant"})
        abort(403)
    return doc


def owner_only_for_doc(doc):
    if doc["owner_id"] != g.user["id"] or g.user["role"] != "owner":
        audit(g.user, "ACCESS_DENIED", doc["id"], details={"route": request.path, "reason": "owner_only"})
        abort(403)


def verify_audit_chain():
    con = connect_db()
    try:
        rows = con.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    finally:
        con.close()
    previous = "GENESIS"
    for row in rows:
        payload = {"actor_id": row["actor_id"], "actor_name": row["actor_name"],
                   "action": row["action"], "document_id": row["document_id"],
                   "target_user": row["target_user"], "details": row["details"],
                   "created_at": row["created_at"], "previous_hash": row["previous_hash"]}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        expected = hmac.new(AUDIT_KEY.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        if row["previous_hash"] != previous or not hmac.compare_digest(expected, row["event_hash"]):
            return False
        previous = row["event_hash"]
    return True


@app.route("/")
def home():
    return redirect(url_for("documents" if g.user else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        con = connect_db()
        user = con.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        con.close()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            audit(user, "LOGIN_SUCCESS")
            return redirect(url_for("documents"))
        audit(None, "LOGIN_FAILURE", details={"username": username[:80]})
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit(g.user, "LOGOUT")
    session.clear()
    return redirect(url_for("login"))


@app.route("/documents")
@login_required
def documents():
    q = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "").strip()[:60]
    date_from = request.args.get("from", "").strip()[:10]
    date_to = request.args.get("to", "").strip()[:10]
    con = connect_db()
    params, where = [], ["d.deleted_at IS NULL"]
    if g.user["role"] != "admin":
        where.append("(d.owner_id=? OR EXISTS(SELECT 1 FROM grants gx WHERE gx.document_id=d.id AND gx.user_id=?))")
        params.extend([g.user["id"], g.user["id"]])
    if q:
        where.append("(d.title LIKE ? OR d.original_name LIKE ? OR u.username LIKE ?)")
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if category:
        where.append("d.category=?")
        params.append(category)
    if date_from:
        where.append("date(d.created_at)>=date(?)")
        params.append(date_from)
    if date_to:
        where.append("date(d.created_at)<=date(?)")
        params.append(date_to)
    rows = con.execute("""SELECT d.*,u.username AS owner_name,
      CASE WHEN d.owner_id=? THEN 'owner'
           WHEN ?='admin' THEN 'metadata only'
           ELSE COALESCE((SELECT permission FROM grants WHERE document_id=d.id AND user_id=?),'read') END AS my_permission
      FROM documents d JOIN users u ON u.id=d.owner_id WHERE """ + " AND ".join(where) +
      " ORDER BY d.created_at DESC", [g.user["id"], g.user["role"], g.user["id"]] + params).fetchall()
    users = con.execute("SELECT id,username,role FROM users WHERE active=1 AND role!='admin' ORDER BY username").fetchall()
    con.close()
    return render_template("documents.html", docs=rows, users=users, q=q, category=category,
                           date_from=date_from, date_to=date_to)


@app.route("/documents/upload", methods=["POST"])
@roles("owner")
def upload():
    f = request.files.get("file")
    title = request.form.get("title", "").strip()[:120]
    category = request.form.get("category", "").strip()[:60]
    if not f or not f.filename or not title or not category:
        flash("Choose a file and provide title and category.", "error")
        return redirect(url_for("documents"))
    original = secure_filename(f.filename)
    ext = Path(original).suffix.lower()
    if not original or ext not in ALLOWED_EXTENSIONS:
        audit(g.user, "UPLOAD_REJECTED", details={"filename": original, "reason": "extension"})
        flash("File type not allowed. Accepted: " + ", ".join(sorted(ALLOWED_EXTENSIONS)), "error")
        return redirect(url_for("documents"))
    data = f.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        audit(g.user, "UPLOAD_REJECTED", details={"filename": original, "reason": "size_or_empty"})
        flash("File is empty or exceeds the configured upload limit.", "error")
        return redirect(url_for("documents"))
    # Basic signatures are defense-in-depth, not malware scanning or full parsing.
    valid = True
    if ext == ".pdf":
        valid = data.startswith(b"%PDF-")
    elif ext == ".png":
        valid = data.startswith(b"\x89PNG\r\n\x1a\n")
    elif ext in (".jpg", ".jpeg"):
        valid = data.startswith(b"\xff\xd8\xff")
    elif ext in (".docx", ".xlsx"):
        valid = data.startswith(b"PK\x03\x04")
    if not valid:
        audit(g.user, "UPLOAD_REJECTED", details={"filename": original, "reason": "signature"})
        flash("File content does not match its extension.", "error")
        return redirect(url_for("documents"))
    stored = secrets.token_hex(24) + ext
    path = STORAGE / stored
    try:
        path.write_bytes(data)
        try:
            path.chmod(0o600)
        except OSError:
            pass
        digest = hashlib.sha256(data).hexdigest()
        con = connect_db()
        cur = con.execute("""INSERT INTO documents(owner_id,title,category,original_name,stored_name,mime_type,
                          size_bytes,sha256,created_at) VALUES(?,?,?,?,?,?,?,?,?)""",
                          (g.user["id"], title, category, original, stored,
                           mimetypes.guess_type(original)[0] or "application/octet-stream",
                           len(data), digest, utcnow()))
        doc_id = cur.lastrowid
        con.commit()
        con.close()
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    audit(g.user, "UPLOAD", doc_id, details={"title": title, "sha256": digest, "size": len(data)})
    flash("Document uploaded securely.", "success")
    return redirect(url_for("documents"))


@app.route("/documents/<int:doc_id>/download")
@login_required
def download(doc_id):
    doc = doc_permission(doc_id, "read")
    path = STORAGE / doc["stored_name"]
    if not path.is_file():
        audit(g.user, "DOWNLOAD_FAILURE", doc_id, details={"reason": "missing_storage"})
        abort(404)
    audit(g.user, "DOWNLOAD", doc_id, details={"sha256": doc["sha256"]})
    return send_file(path, as_attachment=True, download_name=doc["original_name"],
                     mimetype="application/octet-stream", conditional=False, etag=False, max_age=0)


@app.route("/documents/<int:doc_id>/edit", methods=["POST"])
@login_required
def edit_document(doc_id):
    doc = doc_permission(doc_id, "edit")
    title = request.form.get("title", "").strip()[:120]
    category = request.form.get("category", "").strip()[:60]
    if not title or not category:
        flash("Title and category are required.", "error")
        return redirect(url_for("documents"))
    con = connect_db()
    con.execute("UPDATE documents SET title=?,category=? WHERE id=? AND deleted_at IS NULL",
                (title, category, doc_id))
    con.commit()
    con.close()
    audit(g.user, "EDIT", doc_id, details={"title": title, "category": category})
    flash("Document details updated.", "success")
    return redirect(url_for("documents"))


@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    doc = doc_permission(doc_id, "edit")
    owner_only_for_doc(doc)
    con = connect_db()
    con.execute("UPDATE documents SET deleted_at=? WHERE id=? AND deleted_at IS NULL", (utcnow(), doc_id))
    con.execute("DELETE FROM grants WHERE document_id=?", (doc_id,))
    con.commit()
    con.close()
    audit(g.user, "DELETE", doc_id, details={"title": doc["title"], "mode": "soft_delete"})
    flash("Document deleted from active access.", "success")
    return redirect(url_for("documents"))


@app.route("/documents/<int:doc_id>/grant", methods=["POST"])
@login_required
def grant_access(doc_id):
    doc = doc_permission(doc_id, "edit")
    owner_only_for_doc(doc)
    try:
        target_id = int(request.form.get("user_id", ""))
    except ValueError:
        abort(400)
    permission = request.form.get("permission", "read")
    if permission not in ("read", "edit"):
        abort(400)
    con = connect_db()
    target = con.execute("SELECT * FROM users WHERE id=? AND active=1", (target_id,)).fetchone()
    if not target or target["id"] == doc["owner_id"] or target["role"] == "admin":
        con.close()
        flash("Choose an active owner/viewer account other than the document owner.", "error")
        return redirect(url_for("documents"))
    con.execute("""INSERT INTO grants(document_id,user_id,permission,granted_by,created_at)
                   VALUES(?,?,?,?,?) ON CONFLICT(document_id,user_id) DO UPDATE SET
                   permission=excluded.permission,granted_by=excluded.granted_by,created_at=excluded.created_at""",
                (doc_id, target_id, permission, g.user["id"], utcnow()))
    con.commit()
    con.close()
    audit(g.user, "PERMISSION_GRANT", doc_id, target["username"], {"permission": permission})
    flash(f"Access granted to {target['username']} ({permission}).", "success")
    return redirect(url_for("documents"))


@app.route("/documents/<int:doc_id>/revoke", methods=["POST"])
@login_required
def revoke_access(doc_id):
    doc = doc_permission(doc_id, "edit")
    owner_only_for_doc(doc)
    try:
        target_id = int(request.form.get("user_id", ""))
    except ValueError:
        abort(400)
    con = connect_db()
    target = con.execute("SELECT username FROM users WHERE id=?", (target_id,)).fetchone()
    con.execute("DELETE FROM grants WHERE document_id=? AND user_id=?", (doc_id, target_id))
    con.commit()
    con.close()
    audit(g.user, "PERMISSION_REVOKE", doc_id, target["username"] if target else None, {"user_id": target_id})
    flash("Access revoked. New requests are checked and denied immediately.", "success")
    return redirect(url_for("documents"))


@app.route("/documents/<int:doc_id>/grants")
@login_required
def list_grants(doc_id):
    doc = doc_permission(doc_id, "read")
    owner_only_for_doc(doc)
    con = connect_db()
    rows = con.execute("""SELECT g.*,u.username FROM grants g JOIN users u ON u.id=g.user_id
                          WHERE g.document_id=? ORDER BY u.username""", (doc_id,)).fetchall()
    con.close()
    return jsonify([{"username": r["username"], "permission": r["permission"], "granted_at": r["created_at"]} for r in rows])


@app.route("/admin/audit")
@roles("admin")
def admin_audit():
    con = connect_db()
    rows = con.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 500").fetchall()
    con.close()
    return render_template("audit.html", events=rows, integrity=verify_audit_chain())


@app.route("/admin/users", methods=["GET"])
@roles("admin")
def admin_users():
    con = connect_db()
    users = con.execute("SELECT id,username,role,active FROM users ORDER BY id").fetchall()
    con.close()
    return render_template("users.html", users=users)


@app.route("/admin/users/create", methods=["POST"])
@roles("admin")
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    if not USERNAME_RE.fullmatch(username) or len(password) < 12 or role not in ("owner", "viewer"):
        flash("Use a 3–40 character username (letters/numbers/._-), a password of at least 12 characters, and role owner or viewer.", "error")
        return redirect(url_for("admin_users"))
    con = connect_db()
    try:
        con.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                    (username, generate_password_hash(password), role))
        con.commit()
    except sqlite3.IntegrityError:
        con.close()
        flash("That username already exists.", "error")
        return redirect(url_for("admin_users"))
    con.close()
    audit(g.user, "USER_CREATED", details={"username": username, "role": role})
    flash(f"Created {role} account {username}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/deactivate", methods=["POST"])
@roles("admin")
def admin_deactivate_user(user_id):
    if user_id == g.user["id"]:
        flash("You cannot deactivate your own active admin account.", "error")
        return redirect(url_for("admin_users"))
    con = connect_db()
    target = con.execute("SELECT id,username,role,active FROM users WHERE id=?", (user_id,)).fetchone()
    if not target:
        con.close()
        abort(404)
    if target["role"] == "admin":
        active_admins = con.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]
        if active_admins <= 1:
            con.close()
            flash("The last active administrator cannot be deactivated.", "error")
            return redirect(url_for("admin_users"))
    con.execute("UPDATE users SET active=0 WHERE id=?", (user_id,))
    con.execute("DELETE FROM grants WHERE user_id=?", (user_id,))
    con.commit()
    con.close()
    audit(g.user, "USER_DEACTIVATED", target_user=target["username"], details={"role": target["role"]})
    flash(f"Deactivated {target['username']} and removed their document grants.", "success")
    return redirect(url_for("admin_users"))


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.errorhandler(400)
def bad_request(err):
    if request.path.startswith("/api/") or request.is_json:
        return jsonify(error="bad_request", message=str(err.description)), 400
    return render_template("error.html", code=400, message=str(err.description)), 400


@app.errorhandler(403)
def forbidden(err):
    return render_template("error.html", code=403, message="You do not have permission to perform this action."), 403


@app.errorhandler(404)
def not_found(err):
    return render_template("error.html", code=404, message="The requested resource was not found."), 404


@app.errorhandler(413)
def too_large(err):
    return render_template("error.html", code=413, message="Upload is too large. Maximum file size is 5 MB."), 413


@app.context_processor
def inject_globals():
    return {"csrf_token": session.get("csrf_token", ""), "current_user": g.get("user")}


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")), debug=False)
