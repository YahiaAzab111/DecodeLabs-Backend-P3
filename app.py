"""
DecodeLabs Internship - Backend Development
Project 3: Secure Authentication System
Author: Yahia
Stack: Python + Flask + SQLite + JWT + bcrypt
"""

from flask import Flask, jsonify
from database import init_db
from auth_routes import auth_bp
from protected_routes import protected_bp

app = Flask(__name__)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(protected_bp)

# Initialize DB on startup
with app.app_context():
    init_db()


@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "message": "Endpoint not found."}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"status": "error", "message": "Method not allowed."}), 405


if __name__ == "__main__":
    print("Auth server running at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
