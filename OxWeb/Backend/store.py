import sqlite3
import time
from contextlib import contextmanager
from config import DATABASE_PATH

@contextmanager
def connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with connection() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS targets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "url TEXT NOT NULL UNIQUE, "
            "name TEXT, "
            "notes TEXT, "
            "created_by INTEGER, "
            "created_at REAL NOT NULL)"
        )
        conn.commit()

def _target_to_dict(row):
    return {
        "id": row["id"],
        "url": row["url"],
        "name": row["name"],
        "notes": row["notes"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }

def list_targets():
    with connection() as conn:
        rows = conn.execute("SELECT * FROM targets ORDER BY id DESC").fetchall()
    return [_target_to_dict(row) for row in rows]

def add_target(url, name, notes, user_id):
    with connection() as conn:
        cursor = conn.execute(
            "INSERT INTO targets (url, name, notes, created_by, created_at) VALUES (?, ?, ?, ?, ?)",
            (url, name, notes, user_id, time.time()),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM targets WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _target_to_dict(row)

def delete_target(target_id):
    with connection() as conn:
        cursor = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        conn.commit()
    return cursor.rowcount > 0
