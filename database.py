"""
database.py
SQLite setup for the authentication system.

The users table stores hashed passwords only — never plaintext.
role field enables role-based access control (Admin vs User).
"""

import sqlite3

DB_PATH = "auth.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Creates the users table.
    - password_hash: stores bcrypt hash, never the real password
    - role: 'user' or 'admin' — controls access to certain routes
    - is_active: soft disable accounts without deleting them
    """
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()
    print("Auth database ready.")
