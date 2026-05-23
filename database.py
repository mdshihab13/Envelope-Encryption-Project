import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

DATABASE = "foodie.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            failed_attempts INTEGER DEFAULT 0,
            is_locked BOOLEAN DEFAULT FALSE
        );

        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        );
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialized.")


def create_user(username, email, password_hash, role="user"):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, role),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_email(email):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(user_id):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def update_last_login(user_id):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET last_login = ?, failed_attempts = 0 WHERE id = ?",
            (datetime.utcnow(), user_id),
        )
        conn.commit()
    finally:
        conn.close()


def increment_failed_attempts(username):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?",
            (username,),
        )
        conn.commit()
        row = conn.execute(
            "SELECT failed_attempts FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row and row["failed_attempts"] >= 5:
            lock_account(username)
            return True  # locked
        return False
    finally:
        conn.close()


def lock_account(username):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET is_locked = TRUE WHERE username = ?", (username,)
        )
        conn.commit()
    finally:
        conn.close()


def log_auth_event(event, username=None, ip_address=None, details=None):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO auth_logs (event, username, ip_address, details) VALUES (?, ?, ?, ?)",
            (event, username, ip_address, details),
        )
        conn.commit()
    finally:
        conn.close()


def get_all_users():
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, username, email, role, created_at, last_login, failed_attempts, is_locked FROM users"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_auth_logs(limit=100):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()
