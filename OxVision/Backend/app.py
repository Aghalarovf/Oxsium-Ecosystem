import os
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

if __name__ != "__main__":
    _discard_local_bytecode()

from flask import Flask, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import CORS_ORIGINS, MAX_UPLOAD_BYTES, UPLOAD_DIR
import store

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
    default_limits=["10000 per day", "1000 per hour"],
    storage_uri=os.getenv("REDIS_URL", "memory://"),
)

store.load_persisted_datasets(UPLOAD_DIR)

import users_store
users_store.seed_super_admin()

PUBLIC_API_PATHS = {"/api/auth/login", "/api/auth/refresh"}

@app.before_request
def enforce_api_auth():
    if request.method == "OPTIONS":
        return None
    if not request.path.startswith("/api/"):
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

from routes import static_files
from routes import auth_routes
from routes import admin_routes
from routes import upload
from routes import scan_data
from routes import graph
from routes import roles
from routes import vulnerabilities
from routes import data_admin

if __name__ == "__main__":
    from waitress import serve

    serve(
        app,
        host=os.getenv("OXVISUAL_HOST", "0.0.0.0"),
        port=int(os.getenv("OXVISUAL_PORT", "5000")),
    )