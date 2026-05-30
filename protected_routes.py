"""
protected_routes.py
Routes that require a valid JWT to access.

These demonstrate the token_required and admin_required decorators
from middleware.py in action.
"""

from flask import Blueprint, jsonify
from middleware import token_required, admin_required
from database import get_connection

protected_bp = Blueprint("protected", __name__)


@protected_bp.route("/profile", methods=["GET"])
@token_required
def get_profile(current_user):
    """
    GET /profile
    Returns the logged-in user's profile info.
    Requires: valid JWT in Authorization header.

    The current_user dict comes from the decoded token payload —
    no database query needed for basic info.
    """
    return jsonify({
        "status": "success",
        "message": "Profile data retrieved.",
        "data": {
            "user_id": current_user["user_id"],
            "username": current_user["username"],
            "email": current_user["email"],
            "role": current_user["role"]
        }
    }), 200


@protected_bp.route("/dashboard", methods=["GET"])
@token_required
def dashboard(current_user):
    """
    GET /dashboard
    A general protected page accessible to any authenticated user.
    """
    return jsonify({
        "status": "success",
        "message": f"Welcome to your dashboard, {current_user['username']}!",
        "data": {
            "user_id": current_user["user_id"],
            "role": current_user["role"]
        }
    }), 200


@protected_bp.route("/admin/users", methods=["GET"])
@token_required
@admin_required
def admin_get_all_users(current_user):
    """
    GET /admin/users
    Admin-only route — returns all registered users from the database.
    Returns 403 if the token belongs to a non-admin user.
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, username, email, role, is_active, created_at FROM users ORDER BY id"
    ).fetchall()
    conn.close()

    users = [dict(row) for row in rows]

    return jsonify({
        "status": "success",
        "count": len(users),
        "data": users
    }), 200
