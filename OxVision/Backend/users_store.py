import time
import sqlite3
from contextlib import contextmanager
import bcrypt
from config import DATABASE_PATH, VALID_ROLES, SUPERADMIN_USERNAME, SUPERADMIN_PASSWORD, SUPERADMIN_EMAIL, logger

@contextmanager
def _connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT NOT NULL UNIQUE, "
            "email TEXT, "
            "team TEXT, "
            "password_hash TEXT NOT NULL, "
            "role TEXT NOT NULL DEFAULT 'user', "
            "is_active INTEGER NOT NULL DEFAULT 1, "
            "failed_attempts INTEGER NOT NULL DEFAULT 0, "
            "locked_until REAL NOT NULL DEFAULT 0, "
            "created_at REAL NOT NULL, "
            "last_login_at REAL)"
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)").fetchall()}
        if "team" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN team TEXT")
        connection.commit()
        yield connection
    finally:
        connection.close()

def _row_to_dict(row):
    if row is None:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "team": row["team"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "failed_attempts": row["failed_attempts"],
        "locked_until": row["locked_until"],
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
    }

def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password, password_hash):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False

def create_user(username, password, role="user", email=None, team=None, is_active=True):
    if role not in VALID_ROLES:
        raise ValueError("Invalid role")
    with _connection() as connection:
        connection.execute(
            "INSERT INTO users (username, email, team, password_hash, role, is_active, "
            "failed_attempts, locked_until, created_at, last_login_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (username, email, team, hash_password(password), role, int(is_active), 0, 0, time.time(), None),
        )
        connection.commit()

def get_user_by_username(username):
    with _connection() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return _row_to_dict(row)

def get_user_by_id(user_id):
    with _connection() as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
    return _row_to_dict(row)

def list_users():
    with _connection() as connection:
        rows = connection.execute(
            "SELECT * FROM users ORDER BY id"
        ).fetchall()
    return [_row_to_dict(row) for row in rows]

def username_exists(username):
    return get_user_by_username(username) is not None

def get_password_hash(username):
    with _connection() as connection:
        row = connection.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row["password_hash"] if row else None

def update_user_role(user_id, role):
    if role not in VALID_ROLES:
        raise ValueError("Invalid role")
    with _connection() as connection:
        cursor = connection.execute(
            "UPDATE users SET role = ? WHERE id = ?", (role, user_id)
        )
        connection.commit()
    return cursor.rowcount > 0

def set_user_active(user_id, is_active):
    with _connection() as connection:
        cursor = connection.execute(
            "UPDATE users SET is_active = ? WHERE id = ?", (int(is_active), user_id)
        )
        connection.commit()
    return cursor.rowcount > 0

def set_user_password(user_id, password):
    with _connection() as connection:
        cursor = connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(password), user_id),
        )
        connection.commit()
    return cursor.rowcount > 0

def delete_user(user_id):
    with _connection() as connection:
        cursor = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
        connection.commit()
    return cursor.rowcount > 0

def is_locked(user):
    return user["locked_until"] and user["locked_until"] > time.time()

def lock_seconds_remaining(user):
    remaining = user["locked_until"] - time.time()
    return max(0, int(remaining))

def register_failed_login(username, max_attempts, lockout_seconds):
    with _connection() as connection:
        row = connection.execute(
            "SELECT failed_attempts FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            return
        attempts = row["failed_attempts"] + 1
        locked_until = time.time() + lockout_seconds if attempts >= max_attempts else 0
        connection.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            (attempts if attempts < max_attempts else 0, locked_until, username),
        )
        connection.commit()

def register_successful_login(username):
    with _connection() as connection:
        connection.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0, last_login_at = ? "
            "WHERE username = ?",
            (time.time(), username),
        )
        connection.commit()

def seed_super_admin():
    existing = get_user_by_username(SUPERADMIN_USERNAME)
    if existing:
        if existing["role"] != "super_admin" or not existing["is_active"]:
            with _connection() as connection:
                connection.execute(
                    "UPDATE users SET role = 'super_admin', is_active = 1 WHERE username = ?",
                    (SUPERADMIN_USERNAME,),
                )
                connection.commit()
        return
    create_user(
        username=SUPERADMIN_USERNAME,
        password=SUPERADMIN_PASSWORD,
        role="super_admin",
        email=SUPERADMIN_EMAIL,
    )
    logger.info("Super admin account created: %s", SUPERADMIN_USERNAME)
