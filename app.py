"""Cloud Drive: a small Google Drive clone (Flask + PostgreSQL + AWS S3)."""
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import quote

import boto3
import jwt
import psycopg2
import psycopg2.errors
import psycopg2.extras
from botocore.config import Config
from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

DB_NAME = os.environ.get("DB_NAME", "drivedb")
DB_USER = os.environ.get("DB_USER", "driveapp")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
S3_BUCKET = os.environ.get("S3_BUCKET", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
MAX_FILE_MB = int(os.environ.get("MAX_FILE_MB", "25"))
QUOTA_MB = int(os.environ.get("QUOTA_MB", "200"))

if not JWT_SECRET or not S3_BUCKET:
    raise RuntimeError("JWT_SECRET and S3_BUCKET must be set (see .env)")

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = (MAX_FILE_MB + 1) * 1024 * 1024

# The EC2 instance role supplies the AWS credentials: no keys in the code.
s3 = boto3.client("s3", region_name=AWS_REGION, config=Config(signature_version="s3v4"))

USERNAME_RE = re.compile(r"^[a-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------- helpers
def err(message, status=400):
    return jsonify({"error": message}), status


def clean(row):
    """Make a database row JSON friendly."""
    if row is None:
        return None
    return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in row.items()}


def clean_all(rows):
    return [clean(r) for r in rows]


def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(dbname=DB_NAME, user=DB_USER,
                                password=DB_PASSWORD, host=DB_HOST)
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        try:
            if exc:
                db.rollback()
        finally:
            db.close()


def q(sql, params=(), one=False, commit=False):
    """Run one parameterised query (all values are passed separately: no SQL injection)."""
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        rows = None
        if cur.description:
            rows = cur.fetchone() if one else cur.fetchall()
    if commit:
        conn.commit()
    return rows


def make_token(user_id, username):
    payload = {"sub": str(user_id), "username": username,
               "exp": datetime.now(timezone.utc) + timedelta(hours=12)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return err("Login required", 401)
        try:
            data = jwt.decode(header[7:], JWT_SECRET, algorithms=["HS256"])
            g.user = {"id": int(data["sub"]), "username": data["username"]}
        except Exception:
            return err("Invalid or expired token", 401)
        return fn(*args, **kwargs)
    return wrapper


def clean_name(name):
    name = (name or "").replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r"[\x00-\x1f]", "", name)
    return name[:255]


def bad_name(name):
    return name in ("", ".", "..")


def opt_int(value):
    if value in (None, "", "null", "undefined"):
        return None
    return int(value)


def owned_folder(folder_id, uid):
    return q("SELECT * FROM folders WHERE id=%s AND owner_id=%s", (folder_id, uid), one=True)


def get_file(file_id):
    return q("SELECT * FROM files WHERE id=%s", (file_id,), one=True)


def access_level(f, uid):
    """Return 'owner', 'edit', 'view' or None for this user and file."""
    if f is None:
        return None
    if f["owner_id"] == uid:
        return "owner"
    p = q("SELECT access FROM permissions WHERE file_id=%s AND user_id=%s",
          (f["id"], uid), one=True)
    return p["access"] if p else None


def used_bytes(owner_id):
    row = q("""SELECT COALESCE(SUM(v.size_bytes), 0) AS used
               FROM file_versions v JOIN files f ON f.id = v.file_id
               WHERE f.owner_id=%s""", (owner_id,), one=True)
    return int(row["used"])


def delete_s3_keys(keys):
    for i in range(0, len(keys), 1000):
        chunk = keys[i:i + 1000]
        s3.delete_objects(Bucket=S3_BUCKET,
                          Delete={"Objects": [{"Key": k} for k in chunk], "Quiet": True})


# ---------------------------------------------------------------- pages
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/health")
def health():
    try:
        q("SELECT 1 AS ok", one=True)
        return jsonify({"status": "ok", "database": "connected"})
    except Exception:
        return jsonify({"status": "ok", "database": "unavailable"}), 503


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.errorhandler(413)
def too_large(e):
    return err("File too large (max %d MB)" % MAX_FILE_MB, 413)


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return err("Not found", 404)
    return e


@app.errorhandler(405)
def bad_method(e):
    return err("Method not allowed", 405)


@app.errorhandler(500)
def server_error(e):
    return err("Server error", 500)


# ---------------------------------------------------------------- auth
@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not USERNAME_RE.match(username):
        return err("Username must be 3-30 letters, numbers or underscores")
    if not EMAIL_RE.match(email):
        return err("Enter a valid email address")
    if len(password) < 8:
        return err("Password must be at least 8 characters")
    try:
        row = q("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
                (username, email, generate_password_hash(password)), one=True, commit=True)
    except psycopg2.errors.UniqueViolation:
        get_db().rollback()
        return err("Username or email is already taken", 409)
    return jsonify({"token": make_token(row["id"], username),
                    "user": {"id": row["id"], "username": username}}), 201


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    ident = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    user = q("SELECT id, username, password_hash FROM users WHERE username=%s OR email=%s",
             (ident, ident), one=True)
    if not user or not check_password_hash(user["password_hash"], password):
        return err("Wrong username or password", 401)
    return jsonify({"token": make_token(user["id"], user["username"]),
                    "user": {"id": user["id"], "username": user["username"]}})


@app.get("/api/me")
@auth_required
def me():
    return jsonify(g.user)


# ---------------------------------------------------------------- folders
@app.get("/api/list")
@auth_required
def list_items():
    uid = g.user["id"]
    try:
        folder_id = opt_int(request.args.get("folder"))
    except ValueError:
        return err("Invalid folder")
    crumbs = []
    if folder_id is not None:
        cur = owned_folder(folder_id, uid)
        if not cur:
            return err("Folder not found", 404)
        while cur and len(crumbs) < 20:
            crumbs.insert(0, {"id": cur["id"], "name": cur["name"]})
            cur = owned_folder(cur["parent_id"], uid) if cur["parent_id"] else None
    folders = q("""SELECT id, name, created_at FROM folders
                   WHERE owner_id=%s AND parent_id IS NOT DISTINCT FROM %s ORDER BY name""",
                (uid, folder_id))
    files = q("""SELECT f.id, f.name, f.current_version, v.size_bytes, v.content_type,
                        v.uploaded_at,
                        (SELECT COUNT(*) FROM permissions p WHERE p.file_id = f.id) AS shared_count
                 FROM files f
                 JOIN file_versions v ON v.file_id = f.id AND v.version_no = f.current_version
                 WHERE f.owner_id=%s AND f.folder_id IS NOT DISTINCT FROM %s
                 ORDER BY f.name""", (uid, folder_id))
    return jsonify({"folder": folder_id, "breadcrumb": crumbs,
                    "folders": clean_all(folders), "files": clean_all(files)})


@app.post("/api/folders")
@auth_required
def create_folder():
    uid = g.user["id"]
    data = request.get_json(silent=True) or {}
    name = clean_name(str(data.get("name", "")))
    if bad_name(name):
        return err("Enter a folder name")
    try:
        parent_id = opt_int(data.get("parent_id"))
    except (ValueError, TypeError):
        return err("Invalid parent folder")
    if parent_id is not None and not owned_folder(parent_id, uid):
        return err("Parent folder not found", 404)
    dup = q("SELECT id FROM folders WHERE owner_id=%s AND parent_id IS NOT DISTINCT FROM %s AND name=%s",
            (uid, parent_id, name), one=True)
    if dup:
        return err("A folder with this name already exists", 409)
    row = q("INSERT INTO folders (owner_id, parent_id, name) VALUES (%s, %s, %s) RETURNING id, name",
            (uid, parent_id, name), one=True, commit=True)
    return jsonify(clean(row)), 201


@app.delete("/api/folders/<int:folder_id>")
@auth_required
def delete_folder(folder_id):
    uid = g.user["id"]
    if not owned_folder(folder_id, uid):
        return err("Folder not found", 404)
    has_sub = q("SELECT 1 AS x FROM folders WHERE parent_id=%s LIMIT 1", (folder_id,), one=True)
    has_files = q("SELECT 1 AS x FROM files WHERE folder_id=%s LIMIT 1", (folder_id,), one=True)
    if has_sub or has_files:
        return err("Folder is not empty", 409)
    q("DELETE FROM folders WHERE id=%s", (folder_id,), commit=True)
    return jsonify({"deleted": folder_id})


# ---------------------------------------------------------------- files
@app.post("/api/files")
@auth_required
def upload():
    uid = g.user["id"]
    upload_file = request.files.get("file")
    if upload_file is None or not upload_file.filename:
        return err("Choose a file to upload")
    try:
        file_id = opt_int(request.form.get("file_id"))
        folder_id = opt_int(request.form.get("folder_id"))
    except ValueError:
        return err("Invalid id")

    stream = upload_file.stream
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    if size > MAX_FILE_MB * 1024 * 1024:
        return err("File too large (max %d MB)" % MAX_FILE_MB, 413)

    if file_id is not None:                       # new version of an existing file
        f = get_file(file_id)
        level = access_level(f, uid)
        if level is None:
            return err("File not found", 404)
        if level == "view":
            return err("You have view-only access to this file", 403)
    else:                                         # new file (or new version by name)
        name = clean_name(upload_file.filename)
        if bad_name(name):
            return err("Invalid file name")
        if folder_id is not None and not owned_folder(folder_id, uid):
            return err("Folder not found", 404)
        f = q("""SELECT * FROM files WHERE owner_id=%s
                 AND folder_id IS NOT DISTINCT FROM %s AND name=%s""",
              (uid, folder_id, name), one=True)

    owner_id = f["owner_id"] if f else uid
    if used_bytes(owner_id) + size > QUOTA_MB * 1024 * 1024:
        return err("Storage quota exceeded (%d MB)" % QUOTA_MB, 413)

    key = "files/%d/%s" % (owner_id, uuid.uuid4().hex)
    ctype = upload_file.mimetype or "application/octet-stream"
    s3.upload_fileobj(stream, S3_BUCKET, key, ExtraArgs={"ContentType": ctype})
    try:
        if f is None:
            f = q("""INSERT INTO files (owner_id, folder_id, name, current_version)
                     VALUES (%s, %s, %s, 1) RETURNING id, name""",
                  (uid, folder_id, name), one=True)
            version = 1
        else:
            row = q("SELECT COALESCE(MAX(version_no), 0) + 1 AS n FROM file_versions WHERE file_id=%s",
                    (f["id"],), one=True)
            version = int(row["n"])
            q("UPDATE files SET current_version=%s WHERE id=%s", (version, f["id"]))
        q("""INSERT INTO file_versions
             (file_id, version_no, s3_key, size_bytes, content_type, uploaded_by)
             VALUES (%s, %s, %s, %s, %s, %s)""",
          (f["id"], version, key, size, ctype, uid))
        get_db().commit()
    except Exception:
        get_db().rollback()
        s3.delete_object(Bucket=S3_BUCKET, Key=key)
        raise
    return jsonify({"id": f["id"], "name": f["name"], "version": version, "size": size}), 201


@app.get("/api/files/<int:file_id>/download")
@auth_required
def download(file_id):
    f = get_file(file_id)
    if access_level(f, g.user["id"]) is None:
        return err("File not found", 404)
    version = request.args.get("version", type=int) or f["current_version"]
    v = q("SELECT * FROM file_versions WHERE file_id=%s AND version_no=%s",
          (file_id, version), one=True)
    if not v:
        return err("Version not found", 404)
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": S3_BUCKET, "Key": v["s3_key"],
                "ResponseContentDisposition": "attachment; filename*=UTF-8''" + quote(f["name"]),
                "ResponseContentType": v["content_type"] or "application/octet-stream"},
        ExpiresIn=300)
    return jsonify({"url": url, "filename": f["name"], "version": version})


@app.get("/api/files/<int:file_id>/versions")
@auth_required
def versions(file_id):
    f = get_file(file_id)
    level = access_level(f, g.user["id"])
    if level is None:
        return err("File not found", 404)
    rows = q("""SELECT v.version_no, v.size_bytes, v.content_type, v.uploaded_at,
                       u.username AS uploaded_by
                FROM file_versions v JOIN users u ON u.id = v.uploaded_by
                WHERE v.file_id=%s ORDER BY v.version_no DESC""", (file_id,))
    return jsonify({"file": {"id": f["id"], "name": f["name"],
                             "current_version": f["current_version"]},
                    "access": level, "versions": clean_all(rows)})


@app.post("/api/files/<int:file_id>/restore")
@auth_required
def restore(file_id):
    f = get_file(file_id)
    level = access_level(f, g.user["id"])
    if level is None:
        return err("File not found", 404)
    if level == "view":
        return err("You have view-only access to this file", 403)
    data = request.get_json(silent=True) or {}
    try:
        version = int(data.get("version"))
    except (TypeError, ValueError):
        return err("Choose a version")
    v = q("SELECT 1 AS x FROM file_versions WHERE file_id=%s AND version_no=%s",
          (file_id, version), one=True)
    if not v:
        return err("Version not found", 404)
    q("UPDATE files SET current_version=%s WHERE id=%s", (version, file_id), commit=True)
    return jsonify({"id": file_id, "current_version": version})


@app.patch("/api/files/<int:file_id>")
@auth_required
def rename(file_id):
    uid = g.user["id"]
    f = get_file(file_id)
    if access_level(f, uid) is None:
        return err("File not found", 404)
    if f["owner_id"] != uid:
        return err("Only the owner can rename a file", 403)
    data = request.get_json(silent=True) or {}
    name = clean_name(str(data.get("name", "")))
    if bad_name(name):
        return err("Enter a file name")
    dup = q("""SELECT id FROM files WHERE owner_id=%s AND folder_id IS NOT DISTINCT FROM %s
               AND name=%s AND id<>%s""", (uid, f["folder_id"], name, file_id), one=True)
    if dup:
        return err("A file with this name already exists here", 409)
    q("UPDATE files SET name=%s WHERE id=%s", (name, file_id), commit=True)
    return jsonify({"id": file_id, "name": name})


@app.delete("/api/files/<int:file_id>")
@auth_required
def delete_file(file_id):
    uid = g.user["id"]
    f = get_file(file_id)
    if access_level(f, uid) is None:
        return err("File not found", 404)
    if f["owner_id"] != uid:
        return err("Only the owner can delete a file", 403)
    keys = [r["s3_key"] for r in q("SELECT s3_key FROM file_versions WHERE file_id=%s", (file_id,))]
    q("DELETE FROM files WHERE id=%s", (file_id,), commit=True)
    delete_s3_keys(keys)
    return jsonify({"deleted": file_id})


# ---------------------------------------------------------------- sharing
@app.post("/api/files/<int:file_id>/share")
@auth_required
def share(file_id):
    uid = g.user["id"]
    f = get_file(file_id)
    if f is None or f["owner_id"] != uid:
        return err("File not found", 404)
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip().lower()
    access = str(data.get("access", "view"))
    if access not in ("view", "edit"):
        return err("Access must be view or edit")
    target = q("SELECT id, username FROM users WHERE username=%s", (username,), one=True)
    if not target:
        return err("No user with that username", 404)
    if target["id"] == uid:
        return err("You already own this file")
    q("""INSERT INTO permissions (file_id, user_id, access) VALUES (%s, %s, %s)
         ON CONFLICT (file_id, user_id) DO UPDATE SET access = EXCLUDED.access""",
      (file_id, target["id"], access), commit=True)
    return jsonify({"file_id": file_id, "username": target["username"], "access": access})


@app.get("/api/files/<int:file_id>/shares")
@auth_required
def list_shares(file_id):
    f = get_file(file_id)
    if f is None or f["owner_id"] != g.user["id"]:
        return err("File not found", 404)
    rows = q("""SELECT p.user_id, u.username, p.access FROM permissions p
                JOIN users u ON u.id = p.user_id WHERE p.file_id=%s ORDER BY u.username""",
             (file_id,))
    return jsonify({"shares": clean_all(rows)})


@app.delete("/api/files/<int:file_id>/share/<int:user_id>")
@auth_required
def unshare(file_id, user_id):
    f = get_file(file_id)
    if f is None or f["owner_id"] != g.user["id"]:
        return err("File not found", 404)
    q("DELETE FROM permissions WHERE file_id=%s AND user_id=%s", (file_id, user_id), commit=True)
    return jsonify({"removed": user_id})


@app.get("/api/shared")
@auth_required
def shared_with_me():
    rows = q("""SELECT f.id, f.name, f.current_version, p.access, u.username AS owner,
                       v.size_bytes, v.uploaded_at
                FROM permissions p
                JOIN files f ON f.id = p.file_id
                JOIN users u ON u.id = f.owner_id
                JOIN file_versions v ON v.file_id = f.id AND v.version_no = f.current_version
                WHERE p.user_id=%s ORDER BY f.name""", (g.user["id"],))
    return jsonify({"files": clean_all(rows)})


# ---------------------------------------------------------------- storage
@app.get("/api/storage")
@auth_required
def storage():
    uid = g.user["id"]
    count = q("SELECT COUNT(*) AS n FROM files WHERE owner_id=%s", (uid,), one=True)
    return jsonify({"used_bytes": used_bytes(uid), "quota_bytes": QUOTA_MB * 1024 * 1024,
                    "files": int(count["n"])})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8001)
