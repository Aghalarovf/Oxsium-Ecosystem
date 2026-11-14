import os
import re
import sqlite3
import time
from pathlib import Path
import store
from config import DATABASE_PATH, UPLOAD_DIR, SNAPSHOT_DIR

SNAPSHOT_PATTERN = re.compile(r"^snapshot_\d{8}-\d{6}_(\d+)\.db$")
MAX_LABEL_LENGTH = 60

class RestoreError(Exception):
    pass

def _live_name():
    return os.path.basename(DATABASE_PATH).lower()

def _backup_names():
    names = []
    for name in os.listdir(UPLOAD_DIR):
        path = os.path.join(UPLOAD_DIR, name)
        lowered = name.lower()
        if not os.path.isfile(path):
            continue
        if lowered.endswith(".db.bak") or lowered.endswith(".db"):
            names.append(name)
    return names

def _snapshot_names():
    if not os.path.isdir(SNAPSHOT_DIR):
        return []
    return [
        name for name in os.listdir(SNAPSHOT_DIR)
        if name.lower().endswith(".db") and os.path.isfile(os.path.join(SNAPSHOT_DIR, name))
    ]

def _open_readonly(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)

def _inspect(path):
    try:
        connection = _open_readonly(path)
    except sqlite3.Error:
        return None
    try:
        tables = {
            row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        if "datasets" not in tables:
            return None
        datasets = connection.execute("SELECT COUNT(*) FROM datasets").fetchone()[0]
        label = ""
        created_at = None
        if "snapshot_info" in tables:
            row = connection.execute("SELECT label, created_at FROM snapshot_info LIMIT 1").fetchone()
            if row:
                label, created_at = row[0], row[1]
        return {"datasets": datasets, "label": label, "created_at": created_at}
    except sqlite3.Error:
        return None
    finally:
        connection.close()

def _entry(kind, directory, name):
    path = os.path.join(directory, name)
    info = _inspect(path)
    if info is None:
        return None
    stat = os.stat(path)
    return {
        "name": name,
        "kind": kind,
        "restoreable": name.lower() != _live_name(),
        "size": stat.st_size,
        "created_at": info["created_at"] or stat.st_mtime,
        "datasets": info["datasets"],
        "label": info["label"],
    }

def list_backups():
    entries = [_entry("backup", UPLOAD_DIR, name) for name in _backup_names()]
    return sorted((e for e in entries if e), key=lambda e: e["created_at"], reverse=True)

def list_snapshots():
    entries = [_entry("snapshot", SNAPSHOT_DIR, name) for name in _snapshot_names()]
    return sorted((e for e in entries if e), key=lambda e: e["created_at"], reverse=True)

def resolve(kind, name):
    if not isinstance(name, str) or not name:
        return None
    if kind == "backup" and name in _backup_names() and name.lower() != _live_name():
        return os.path.join(UPLOAD_DIR, name)
    if kind == "snapshot" and name in _snapshot_names():
        return os.path.join(SNAPSHOT_DIR, name)
    return None

def _next_snapshot_number():
    numbers = [
        int(match.group(1))
        for name in _snapshot_names()
        for match in [SNAPSHOT_PATTERN.match(name)]
        if match
    ]
    return max(numbers, default=0) + 1

def _copy_database(target):
    source = sqlite3.connect(DATABASE_PATH)
    destination = sqlite3.connect(target)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()

def create_snapshot(label=""):
    clean = " ".join(str(label or "").split())[:MAX_LABEL_LENGTH]
    with store._reset_lock:
        os.makedirs(SNAPSHOT_DIR, exist_ok=True)
        with store._connection():
            pass
        name = f"snapshot_{time.strftime('%Y%m%d-%H%M%S')}_{_next_snapshot_number()}.db"
        target = os.path.join(SNAPSHOT_DIR, name)
        try:
            _copy_database(target)
            connection = sqlite3.connect(target)
            try:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS snapshot_info ("
                    "label TEXT NOT NULL, created_at REAL NOT NULL)"
                )
                connection.execute("DELETE FROM snapshot_info")
                connection.execute(
                    "INSERT INTO snapshot_info (label, created_at) VALUES (?, ?)",
                    (clean, time.time()),
                )
                connection.commit()
            finally:
                connection.close()
        except Exception:
            if os.path.exists(target):
                os.remove(target)
            raise
        return _entry("snapshot", SNAPSHOT_DIR, name)

def delete_snapshot(name):
    path = resolve("snapshot", name)
    if path is None:
        return False
    os.remove(path)
    return True

def _archive_current():
    number = store._backup_number()
    stem = os.path.splitext(os.path.basename(DATABASE_PATH))[0]
    target = os.path.join(UPLOAD_DIR, f"{stem}_{number}.db.bak")
    with store._connection():
        pass
    _copy_database(target)
    return target

def _verify_source(path):
    if _inspect(path) is None:
        raise RestoreError("The selected file is not a valid scan database")
    try:
        connection = _open_readonly(path)
        try:
            result = connection.execute("PRAGMA quick_check").fetchone()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise RestoreError(f"The selected file could not be read: {error}")
    if not result or result[0] != "ok":
        raise RestoreError("The selected file failed the database integrity check")

def restore(kind, name):
    path = resolve(kind, name)
    if path is None:
        raise RestoreError("The selected file was not found")
    with store._reset_lock:
        _verify_source(path)
        safety = _archive_current()
        with store._connection() as connection:
            try:
                connection.execute("ATTACH DATABASE ? AS src", (path,))
                has_meta = connection.execute(
                    "SELECT 1 FROM src.sqlite_master WHERE type = 'table' AND name = 'subnet_meta'"
                ).fetchone() is not None
                has_groups = connection.execute(
                    "SELECT 1 FROM src.sqlite_master WHERE type = 'table' AND name = 'subnet_groups'"
                ).fetchone() is not None
                has_group_names = connection.execute(
                    "SELECT 1 FROM src.sqlite_master WHERE type = 'table' AND name = 'subnet_group_names'"
                ).fetchone() is not None
                connection.execute("DELETE FROM main.datasets")
                connection.execute("DELETE FROM main.subnet_meta")
                connection.execute("DELETE FROM main.subnet_groups")
                connection.execute("DELETE FROM main.subnet_group_names")
                connection.execute(
                    "INSERT INTO main.datasets (id, source_name, data, created_at) "
                    "SELECT id, source_name, data, created_at FROM src.datasets"
                )
                if has_meta:
                    connection.execute(
                        "INSERT INTO main.subnet_meta (subnet, special_name) "
                        "SELECT subnet, special_name FROM src.subnet_meta"
                    )
                if has_groups:
                    connection.execute(
                        "INSERT INTO main.subnet_groups (subnet, group_name) "
                        "SELECT subnet, group_name FROM src.subnet_groups"
                    )
                if has_group_names:
                    connection.execute(
                        "INSERT INTO main.subnet_group_names (group_name) "
                        "SELECT group_name FROM src.subnet_group_names"
                    )
                connection.commit()
            except sqlite3.Error as error:
                connection.rollback()
                raise RestoreError(f"The restore failed and nothing was changed: {error}")
        store._sync_cache()
        return os.path.basename(safety)
