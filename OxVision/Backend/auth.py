import time
from functools import wraps
import jwt
from flask import request, g
from config import (
    JWT_SECRET,
    JWT_ALGORITHM,
    ACCESS_TOKEN_COOKIE,
    REFRESH_TOKEN_COOKIE,
    ACCESS_TOKEN_TTL_SECONDS,
    REFRESH_TOKEN_TTL_SECONDS,
    COOKIE_SECURE,
    COOKIE_SAMESITE,
)
import users_store

def create_access_token(user):
    now = int(time.time())
    payload = {
        "type": "access",
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def create_refresh_token(user):
    now = int(time.time())
    payload = {
        "type": "refresh",
        "user_id": user["id"],
        "iat": now,
        "exp": now + REFRESH_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token, expected_type=None):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    if expected_type and payload.get("type") != expected_type:
        return None
    return payload

def set_auth_cookies(response, user):
    access_token = create_access_token(user)
    refresh_token = create_refresh_token(user)
    response.set_cookie(
        ACCESS_TOKEN_COOKIE,
        access_token,
        max_age=ACCESS_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )
    response.set_cookie(
        REFRESH_TOKEN_COOKIE,
        refresh_token,
        max_age=REFRESH_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )
    return response

def clear_auth_cookies(response):
    response.set_cookie(ACCESS_TOKEN_COOKIE, "", max_age=0, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, path="/")
    response.set_cookie(REFRESH_TOKEN_COOKIE, "", max_age=0, httponly=True, secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE, path="/")
    return response

def get_current_user():
    token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    if not token:
        return None
    payload = decode_token(token, expected_type="access")
    if payload is None:
        return None
    user = users_store.get_user_by_id(payload["user_id"])
    if user is None or not user["is_active"]:
        return None
    return user

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        user = get_current_user()
        if user is None:
            from helpers import _err
            return _err("Authentication required", 401)
        g.current_user = user
        return view_func(*args, **kwargs)
    return wrapped

def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if user is None:
                from helpers import _err
                return _err("Authentication required", 401)
            if user["role"] not in allowed_roles:
                from helpers import _err
                return _err("Insufficient permissions", 403)
            g.current_user = user
            return view_func(*args, **kwargs)
        return wrapped
    return decorator

def capability_required(*allowed_roles):
    return role_required(*allowed_roles)
