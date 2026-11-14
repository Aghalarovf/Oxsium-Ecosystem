from flask import request, g
from app import app, limiter
from helpers import _ok, _err
from config import logger, MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS
import backups
import users_store
import auth
import store

def _confirm_password(user, payload):
    if users_store.is_locked(user):
        return _err("Account is temporarily locked. Try again later.", 429)
    password = payload.get("password") if isinstance(payload, dict) else None
    if not isinstance(password, str) or not password:
        return _err("Administrator password is required", 400)
    password_hash = users_store.get_password_hash(user["username"])
    if not password_hash or not users_store.verify_password(password, password_hash):
        users_store.register_failed_login(user["username"], MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS)
        logger.warning("Data restore refused for %s: wrong password", user["username"])
        return _err("Incorrect password", 403)
    return None

@app.route("/api/admin/data-files", methods=["GET"])
@auth.role_required("admin", "super_admin")
def admin_list_data_files():
    return _ok(backups=backups.list_backups(), snapshots=backups.list_snapshots())

@app.route("/api/admin/optimize", methods=["POST"])
@limiter.limit("5 per minute")
@auth.role_required("admin", "super_admin")
def admin_optimize_database():
    try:
        removed = store.optimize_database()
    except (OSError, ValueError, TypeError) as error:
        logger.exception("Could not optimize database")
        return _err(f"Could not optimize database: {error}", 500)
    logger.info("Database optimized by %s; removed %d duplicate hosts",
                g.current_user["username"], removed)
    return _ok(removed=removed)

@app.route("/api/admin/snapshots", methods=["POST"])
@limiter.limit("20 per minute")
@auth.role_required("admin", "super_admin")
def admin_create_snapshot():
    payload = request.get_json(silent=True)
    label = payload.get("label", "") if isinstance(payload, dict) else ""
    if not isinstance(label, str):
        return _err("Label must be a string", 400)
    try:
        snapshot = backups.create_snapshot(label)
    except OSError as error:
        logger.exception("Could not create snapshot")
        return _err(f"Could not create snapshot: {error}", 500)
    logger.info("Snapshot %s created by %s", snapshot["name"], g.current_user["username"])
    return _ok(snapshot=snapshot)

@app.route("/api/admin/snapshots/<name>", methods=["DELETE"])
@limiter.limit("30 per minute")
@auth.role_required("admin", "super_admin")
def admin_delete_snapshot(name):
    try:
        removed = backups.delete_snapshot(name)
    except OSError as error:
        logger.exception("Could not delete snapshot %s", name)
        return _err(f"Could not delete snapshot: {error}", 500)
    if not removed:
        return _err("Snapshot not found", 404)
    logger.info("Snapshot %s deleted by %s", name, g.current_user["username"])
    return _ok(name=name)

@app.route("/api/admin/restore", methods=["POST"])
@limiter.limit("5 per minute")
@auth.role_required("admin", "super_admin")
def admin_restore():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _err("A JSON object is required", 400)
    kind = payload.get("kind")
    name = payload.get("name")
    if kind not in {"backup", "snapshot"} or not isinstance(name, str) or not name:
        return _err("A valid file kind and name are required", 400)

    refusal = _confirm_password(g.current_user, payload)
    if refusal is not None:
        return refusal

    try:
        safety = backups.restore(kind, name)
    except backups.RestoreError as error:
        return _err(str(error), 400)
    except OSError as error:
        logger.exception("Could not restore %s", name)
        return _err(f"Could not restore: {error}", 500)

    logger.info("Database restored from %s %s by %s; previous data archived as %s",
                kind, name, g.current_user["username"], safety)
    return _ok(restored=name, archived_as=safety)
