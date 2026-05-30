"""
middleware.py
JWT verification logic used to protect routes.

How it works:
  1. Client sends request with header: Authorization: Bearer <token>
  2. token_required decorator extracts and verifies the token
  3. If valid → the route function runs with the decoded user payload
  4. If invalid or missing → 401 Unauthorized is returned immediately

Why a decorator?
  It keeps auth logic in one place. Any route can be protected
  simply by adding @token_required above it.
"""

import jwt
import os
from functools import wraps
from flask import request, jsonify

# Secret key used to sign and verify tokens.
# In production this would come from an environment variable.
SECRET_KEY = os.environ.get("JWT_SECRET", "decodelabs-yahia-secret-2026")


def token_required(f):
    """
    Decorator that checks for a valid JWT in the Authorization header.
    Passes the decoded token payload to the wrapped function as `current_user`.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        # Header must follow format: "Bearer <token>"
        if not auth_header.startswith("Bearer "):
            return jsonify({
                "status": "error",
                "message": "Authorization header missing or malformed. Use: Bearer <token>"
            }), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({
                "status": "error",
                "message": "Token has expired. Please log in again."
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({
                "status": "error",
                "message": "Invalid token. Authentication failed."
            }), 401

        return f(payload, *args, **kwargs)

    return decorated


def admin_required(f):
    """
    Decorator for admin-only routes.
    Must be used after @token_required — it relies on the decoded payload.
    """
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if current_user.get("role") != "admin":
            return jsonify({
                "status": "error",
                "message": "Access denied. Admin privileges required."
            }), 403
        return f(current_user, *args, **kwargs)

    return decorated
