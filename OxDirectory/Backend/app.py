import os
import shutil
import sys

PYCACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "PyCache"
)
sys.pycache_prefix = PYCACHE_DIR

def _discard_local_bytecode():
    local = os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__")
    if not os.path.isdir(local):
        return
    for name in os.listdir(local):
        if name.startswith("app.") and name.endswith(".pyc"):
            try:
                os.remove(os.path.join(local, name))
            except OSError:
                pass
    try:
        os.rmdir(local)
    except OSError:
        pass


def _cleanup_runtime_files():
    try:
        _discard_local_bytecode()
        if os.path.isdir(PYCACHE_DIR):
            shutil.rmtree(PYCACHE_DIR)
    except OSError as error:
        print(f"Could not remove runtime cache: {error}", file=sys.stderr)

if __name__ != "__main__":
    _discard_local_bytecode()

from flask import Flask, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import CORS_ORIGINS, HOST, MAX_UPLOAD_BYTES, PORT, REDIS_URL

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

sys.modules.setdefault("app", sys.modules[__name__])

CORS(
    app,
    resources={r"/api/*": {"origins": CORS_ORIGINS}},
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "DELETE", "OPTIONS"],
)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri=REDIS_URL,
)

PUBLIC_API_PATHS = {"/api/auth/login", "/api/auth/refresh"}


@app.before_request
def enforce_api_auth():
    if request.method == "OPTIONS" or not request.path.startswith("/api/"):
        return None
    if request.path in PUBLIC_API_PATHS:
        return None
    import auth
    from helpers import _err
    user = auth.get_current_user()
    if user is None:
        return _err("Authentication required", 401)
    from flask import g
    g.current_user = user
    return None

import users_store
users_store.seed_super_admin()

from routes import static_files
from routes import auth_routes
from routes import admin_routes
from routes import files
from routes import meta
import domain_store
domain_store.sync_files()

if __name__ == "__main__":
    from waitress import serve

    try:
        serve(
            app,
            host=HOST,
            port=PORT,
        )
    except KeyboardInterrupt:
        print("\nOxDirectory server stopped.", file=sys.stderr)
    finally:
        _cleanup_runtime_files()