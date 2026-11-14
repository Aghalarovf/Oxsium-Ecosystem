from flask import request, make_response, jsonify
from app import app, limiter
from helpers import _ok, _err
from config import (
    MAX_LOGIN_ATTEMPTS,
    LOGIN_LOCKOUT_SECONDS,
    REFRESH_TOKEN_COOKIE,
    ACCESS_TOKEN_COOKIE,
    ACCESS_TOKEN_TTL_SECONDS,
    COOKIE_SECURE,
    COOKIE_SAMESITE,
    logger,
)
import users_store
import auth

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _err("A JSON object is required", 400)

    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        return _err("Username and password are required", 400)

    user = users_store.get_user_by_username(username)
    if user is None:
        return _err("Invalid username or password", 401)

    if users_store.is_locked(user):
        remaining = users_store.lock_seconds_remaining(user)
        return _err(f"Account locked. Try again in {remaining} seconds", 423)

    if not user["is_active"]:
        return _err("Account is disabled", 403)

    password_hash = users_store.get_password_hash(username)

    if not password_hash or not users_store.verify_password(password, password_hash):
        users_store.register_failed_login(username, MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS)
        logger.warning("Failed login attempt for %s", username)
        return _err("Invalid username or password", 401)

    users_store.register_successful_login(username)

    response = make_response(jsonify({
        "ok": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "team": user["team"],
        },
    }))
    return auth.set_auth_cookies(response, user)

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    response = make_response(jsonify({"ok": True}))
    return auth.clear_auth_cookies(response)

@app.route("/api/auth/refresh", methods=["POST"])
def refresh():
    token = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if not token:
        return _err("Refresh token missing", 401)

    payload = auth.decode_token(token, expected_type="refresh")
    if payload is None:
        return _err("Invalid or expired refresh token", 401)

    user = users_store.get_user_by_id(payload["user_id"])
    if user is None or not user["is_active"]:
        return _err("Account unavailable", 401)

    access_token = auth.create_access_token(user)
    response = make_response(jsonify({"ok": True}))
    response.set_cookie(
        ACCESS_TOKEN_COOKIE,
        access_token,
        max_age=ACCESS_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )
    return response

@app.route("/api/auth/me", methods=["GET"])
@auth.login_required
def me():
    from flask import g
    user = g.current_user
    return _ok(user={
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "email": user["email"],
        "team": user["team"],
    })
