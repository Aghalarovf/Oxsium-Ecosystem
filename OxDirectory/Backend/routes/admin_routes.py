import sqlite3
from flask import request, g
from app import app, limiter
from helpers import _ok, _err
from config import VALID_ROLES, logger, MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS
import domain_store
import users_store
import auth

@app.route("/api/admin/users", methods=["GET"])
@auth.role_required("manager", "admin", "super_admin")
def admin_list_users():
    users = users_store.list_users()
    if g.current_user["role"] == "manager":
        users = [
            user for user in users
            if user["id"] != g.current_user["id"]
            and user["role"] not in {"admin", "super_admin"}
            and user["team"] == g.current_user["team"]
        ]
    return _ok(users=[{
        "id": u["id"],
        "username": u["username"],
        "email": u["email"],
        "team": u["team"],
        "role": u["role"],
        "is_active": u["is_active"],
        "locked": users_store.is_locked(u),
        "created_at": u["created_at"],
        "last_login_at": u["last_login_at"],
    } for u in users])

@app.route("/api/admin/users", methods=["POST"])
@auth.role_required("super_admin")
def admin_create_user():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _err("A JSON object is required", 400)

    username = payload.get("username")
    password = payload.get("password")
    role = payload.get("role", "user")
    email = payload.get("email")
    team = payload.get("team")

    if not isinstance(username, str) or len(username.strip()) < 3:
        return _err("Username must be at least 3 characters", 400)
    if not isinstance(password, str) or len(password) < 8:
        return _err("Password must be at least 8 characters", 400)
    if role not in VALID_ROLES:
        return _err("Invalid role", 400)
    if users_store.username_exists(username):
        return _err("Username already exists", 409)

    if team is not None and not isinstance(team, str):
        return _err("Team must be a string", 400)
    if role == "manager" and (not isinstance(team, str) or not team.strip()):
        return _err("A team is required for manager accounts", 400)
    users_store.create_user(username.strip(), password, role, email, team.strip() if team else None)
    return _ok(username=username)

@app.route("/api/admin/users/<int:user_id>/role", methods=["POST"])
@auth.role_required("manager", "super_admin")
def admin_update_role(user_id):
    payload = request.get_json(silent=True)
    role = payload.get("role") if isinstance(payload, dict) else None
    if role not in VALID_ROLES:
        return _err("Invalid role", 400)

    target = users_store.get_user_by_id(user_id)
    if target is None:
        return _err("User not found", 404)
    if g.current_user["role"] == "manager":
        if target["id"] == g.current_user["id"]:
            return _err("Managers cannot change their own role", 400)
        if target["role"] in {"admin", "super_admin"} or target["team"] != g.current_user["team"]:
            return _err("Managers can only update users in their own team", 403)
        if role not in {"viewer", "analyst", "operator", "manager", "user"}:
            return _err("Managers cannot assign administrative roles", 403)
    if target["role"] == "super_admin" and role != "super_admin" and g.current_user["id"] == user_id:
        return _err("You cannot demote yourself", 400)

    users_store.update_user_role(user_id, role)
    return _ok(id=user_id, role=role)

@app.route("/api/admin/users/<int:user_id>/active", methods=["POST"])
@auth.role_required("super_admin")
def admin_set_active(user_id):
    payload = request.get_json(silent=True)
    is_active = payload.get("is_active") if isinstance(payload, dict) else None
    if not isinstance(is_active, bool):
        return _err("'is_active' must be a boolean", 400)

    if g.current_user["id"] == user_id and not is_active:
        return _err("You cannot disable your own account", 400)

    found = users_store.set_user_active(user_id, is_active)
    if not found:
        return _err("User not found", 404)
    return _ok(id=user_id, is_active=is_active)

@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@auth.role_required("super_admin")
def admin_delete_user(user_id):
    if g.current_user["id"] == user_id:
        return _err("You cannot delete your own account", 400)

    found = users_store.delete_user(user_id)
    if not found:
        return _err("User not found", 404)
    return _ok(id=user_id)


@app.route("/api/admin/reset-database", methods=["POST"])
@limiter.limit("5 per minute")
@auth.role_required("super_admin")
def admin_reset_database():
    payload = request.get_json(silent=True)
    password = payload.get("password") if isinstance(payload, dict) else None
    sections = payload.get("sections") if isinstance(payload, dict) else None
    if not isinstance(password, str) or not password:
        return _err("Administrator password is required", 400)
    if sections is not None and (
        not isinstance(sections, list)
        or not sections
        or not all(isinstance(section, str) for section in sections)
    ):
        return _err("At least one reset section must be selected", 400)
    user = g.current_user
    if users_store.is_locked(user):
        return _err("Account is temporarily locked. Try again later.", 429)
    password_hash = users_store.get_password_hash(user["username"])
    if not password_hash or not users_store.verify_password(password, password_hash):
        users_store.register_failed_login(user["username"], MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS)
        logger.warning("Database reset refused for %s: wrong password", user["username"])
        return _err("Incorrect password", 403)
    try:
        reset_sections = domain_store.reset_database(sections=sections, remove_files=True)
    except (OSError, ValueError, sqlite3.Error) as error:
        logger.exception("Directory database reset failed for %s", user["username"])
        return _err(f"Database reset failed: {error}", 500)
    logger.info("Directory database reset by %s; user database preserved", user["username"])
    return _ok(message="Selected directory sections and uploaded files were reset",
               sections=reset_sections)


@app.route("/api/admin/optimize", methods=["POST"])
@auth.role_required("admin", "super_admin")
def admin_optimize_database():
    try:
        removed = domain_store.optimize_database()
    except (OSError, ValueError, TypeError, sqlite3.Error) as error:
        return _err(f"Could not optimize database: {error}", 500)
    return _ok(removed=removed)
