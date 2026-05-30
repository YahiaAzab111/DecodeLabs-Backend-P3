"""
auth_routes.py
Handles user registration and login.

POST /auth/register  → hash password, store user
POST /auth/login     → verify password, return JWT
"""

import jwt
import sqlite3
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from datetime import datetime, timezone, timedelta
from flask import Blueprint, jsonify, request
from database import get_connection

# Argon2id with OWASP-recommended memory costs
# memory_cost=65536 = 64MB RAM, parallelism=2, time_cost=3 iterations
ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=2)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

SECRET_KEY = os.environ.get("JWT_SECRET", "decodelabs-yahia-secret-2026")


# ─── REGISTER ──────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    POST /auth/register
    Accepts: { username, email, password, role (optional) }

    Security steps:
    1. Validate all required fields
    2. Hash the password with bcrypt (adds a random salt automatically)
    3. Store ONLY the hash — the real password never touches the database

    Returns 409 if username or email already exists.
    Returns 201 on success.
    """
    body = request.get_json(silent=True)

    if not body:
        return jsonify({"status": "error", "message": "JSON body required."}), 400

    required = ["username", "email", "password"]
    missing = [f for f in required if not body.get(f)]
    if missing:
        return jsonify({
            "status": "error",
            "message": f"Missing field(s): {', '.join(missing)}."
        }), 400

    if len(body["password"]) < 6:
        return jsonify({
            "status": "error",
            "message": "Password must be at least 6 characters."
        }), 400

    # Argon2id is the OWASP-recommended algorithm (2024).
    # It combines resistance to GPU attacks (Argon2d) and side-channel attacks (Argon2i).
    # ph.hash() automatically generates a unique salt and embeds it in the output string.
    password_hash = ph.hash(body["password"])

    role = body.get("role", "user")
    if role not in ("user", "admin"):
        role = "user"

    try:
        conn = get_connection()
        cursor = conn.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (
                str(body["username"]).strip().lower(),
                str(body["email"]).strip().lower(),
                password_hash,
                role
            )
        )
        conn.commit()
        new_id = cursor.lastrowid
        conn.close()

        return jsonify({
            "status": "success",
            "message": "Account created successfully.",
            "data": {
                "id": new_id,
                "username": body["username"].strip().lower(),
                "email": body["email"].strip().lower(),
                "role": role
            }
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "status": "error",
            "message": "Username or email already exists."
        }), 409


# ─── LOGIN ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    POST /auth/login
    Accepts: { email, password }

    Security steps:
    1. Fetch user by email
    2. Use bcrypt.checkpw to compare the submitted password against the stored hash
    3. If match → generate a signed JWT with 24-hour expiry
    4. Return the token to the client

    Note: We return the same generic error for both "user not found" and
    "wrong password" — this prevents user enumeration attacks.
    """
    body = request.get_json(silent=True)

    if not body or not body.get("email") or not body.get("password"):
        return jsonify({
            "status": "error",
            "message": "Both 'email' and 'password' are required."
        }), 400

    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (body["email"].strip().lower(),)
    ).fetchone()
    conn.close()

    # Same error message whether user doesn't exist or password is wrong
    auth_error = jsonify({
        "status": "error",
        "message": "Invalid email or password."
    }), 401

    if user is None:
        return auth_error

    if not user["is_active"]:
        return jsonify({
            "status": "error",
            "message": "This account has been deactivated."
        }), 403

    # Argon2id verify — raises VerifyMismatchError if password doesn't match
    try:
        ph.verify(user["password_hash"], body["password"])
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return auth_error

    # Build the JWT payload
    payload = {
        "user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "exp": datetime.now(timezone.utc) + timedelta(hours=24)  # token expires in 24h
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "status": "success",
        "message": "Login successful.",
        "token": token,
        "expires_in": "24 hours"
    }), 200
