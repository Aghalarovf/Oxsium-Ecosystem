import os
import logging
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
load_dotenv(os.path.join(ROOT_DIR, ".env"))

APP_NAME = "OxWeb"
APP_VERSION = "0.1.0"

DATA_DIR = os.getenv("OXWEB_DATA_DIR", os.path.join(ROOT_DIR, "data"))
DATABASE_PATH = os.path.join(DATA_DIR, "oxweb.db")
WEB_RESULTS_DIR = os.getenv("OXWEB_RESULTS_DIR", os.path.join(ROOT_DIR, "upload"))
WEB_RESULTS_DATABASE_PATH = os.path.join(WEB_RESULTS_DIR, "web_results.db")
HTML_DIR = os.path.join(ROOT_DIR, "HTML")
CSS_DIR = os.path.join(ROOT_DIR, "CSS")
JS_DIR = os.path.join(ROOT_DIR, "JS")
ASSETS_DIR = os.path.join(ROOT_DIR, "Configurations", "Assets")
MAX_BODY_BYTES = int(os.getenv("OXWEB_MAX_BODY_BYTES", str(10 * 1024 * 1024)))

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(WEB_RESULTS_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("oxweb")

def _required_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be set")
    return value

JWT_SECRET = _required_env("OXWEB_SECRET_KEY")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_COOKIE = "oxwtoken"
REFRESH_TOKEN_COOKIE = "oxwrefresh"
ACCESS_TOKEN_TTL_SECONDS = 60 * 60
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7
COOKIE_SECURE = os.getenv("OXWEB_ENV", "development") == "production"
COOKIE_SAMESITE = "Lax"

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60

VALID_ROLES = ("viewer", "analyst", "operator", "manager", "user", "admin", "super_admin")

SUPERADMIN_USERNAME = os.getenv("OXWEB_SUPERADMIN_USER", "admin")
SUPERADMIN_PASSWORD = _required_env("OXWEB_SUPERADMIN_PASSWORD")
SUPERADMIN_EMAIL = os.getenv("OXWEB_SUPERADMIN_EMAIL", "superadmin@oxweb.local")
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("OXWEB_CORS_ORIGINS", "http://127.0.0.1:5100").split(",")
    if origin.strip()
]
