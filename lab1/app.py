import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape

app = Flask(__name__)
app.config["DATABASE"] = os.environ.get("DATABASE", "app.db")
app.config["JWT_SECRET"] = os.environ.get("JWT_SECRET") or secrets.token_hex(32)

JWT_ALGORITHM = "HS256"
JWT_TTL = timedelta(minutes=30)
PASSWORD_MAX_BYTES = 72


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT UNIQUE NOT NULL, "
            "password_hash TEXT NOT NULL)"
        )
        db.commit()


def read_credentials():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    if not username or not password:
        return None
    return username, password


def token_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Missing token"), 401
        try:
            payload = jwt.decode(
                header.removeprefix("Bearer "),
                app.config["JWT_SECRET"],
                algorithms=[JWT_ALGORITHM],
                options={"require": ["exp", "sub"]},
            )
        except jwt.InvalidTokenError:
            return jsonify(error="Invalid or expired token"), 401
        g.user_id = int(payload["sub"])
        return view(*args, **kwargs)

    return wrapper


@app.post("/auth/register")
def register():
    credentials = read_credentials()
    if credentials is None:
        return jsonify(error="username and password are required"), 400
    username, password = credentials
    if len(username) > 32:
        return jsonify(error="username must be at most 32 characters"), 400
    if not 8 <= len(password.encode()) <= PASSWORD_MAX_BYTES:
        return jsonify(error="password must be 8-72 bytes long"), 400

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="username already taken"), 409

    return jsonify(id=cursor.lastrowid, username=escape(username)), 201


@app.post("/auth/login")
def login():
    credentials = read_credentials()
    if credentials is None:
        return jsonify(error="username and password are required"), 400
    username, password = credentials

    user = get_db().execute(
        "SELECT id, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    password_ok = (
        user is not None
        and len(password.encode()) <= PASSWORD_MAX_BYTES
        and bcrypt.checkpw(password.encode(), user["password_hash"].encode())
    )
    if not password_ok:
        return jsonify(error="invalid username or password"), 401

    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": str(user["id"]), "iat": now, "exp": now + JWT_TTL},
        app.config["JWT_SECRET"],
        algorithm=JWT_ALGORITHM,
    )
    return jsonify(access_token=token)


@app.get("/api/data")
@token_required
def get_data():
    rows = get_db().execute("SELECT id, username FROM users ORDER BY id").fetchall()
    users = [{"id": row["id"], "username": escape(row["username"])} for row in rows]
    return jsonify(users=users)


if __name__ == "__main__":
    init_db()
    app.run(port=int(os.environ.get("PORT", "5001")))
