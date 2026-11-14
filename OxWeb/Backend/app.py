import os
import sys

PYCACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "PyCache"
)
sys.pycache_prefix = PYCACHE_DIR

from flask import Flask, request, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import CORS_ORIGINS, MAX_BODY_BYTES

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_BYTES

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

import store
import users_store
import web_results_store

store.init_db()
web_results_store.init_db()
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
    g.current_user = user
    return None

from routes import static_files
from routes import auth_routes
from routes import admin_routes
from routes import meta
from routes import targets
from routes import web_results

if __name__ == "__main__":
    from waitress import serve

    serve(
        app,
        host=os.getenv("OXWEB_HOST", "127.0.0.1"),
        port=int(os.getenv("OXWEB_PORT", "5100")),
    )
