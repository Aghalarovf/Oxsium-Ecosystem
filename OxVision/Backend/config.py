import os
import logging
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
load_dotenv(os.path.join(ROOT_DIR, ".env"))
DEFAULT_UPLOAD_DIR = (
    os.path.join(ROOT_DIR, "uploads")
)
UPLOAD_DIR = os.getenv("OXVISUAL_UPLOAD_DIR", DEFAULT_UPLOAD_DIR)
DATABASE_PATH = os.path.join(UPLOAD_DIR, "portscan.db")
SNAPSHOT_DIR = os.path.join(UPLOAD_DIR, "snapshots")
HTML_DIR = os.path.join(ROOT_DIR, "HTML")
CSS_DIR = os.path.join(ROOT_DIR, "CSS")
JS_DIR = os.path.join(ROOT_DIR, "JS")
ASSETS_DIR = os.path.join(ROOT_DIR, "Configurations", "Assets")
CWES_PATH = os.path.join(ROOT_DIR, "Configurations", "cwes.json")
MAX_UPLOAD_BYTES = int(os.getenv("OXVISUAL_MAX_UPLOAD_BYTES", str(1024 * 1024 * 1024)))

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("oxvision")

def _required_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be set")
    return value


JWT_SECRET = _required_env("OXVISUAL_SECRET_KEY")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_COOKIE = "oxtoken"
REFRESH_TOKEN_COOKIE = "oxrefresh"
ACCESS_TOKEN_TTL_SECONDS = 60 * 60
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7
COOKIE_SECURE = os.getenv("OXVISUAL_ENV", "development") == "production"
COOKIE_SAMESITE = "Lax"

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60

VALID_ROLES = ("viewer", "analyst", "operator", "manager", "user", "admin", "super_admin")

SUPERADMIN_USERNAME = os.getenv("OXVISUAL_SUPERADMIN_USER", "admin")
SUPERADMIN_PASSWORD = _required_env("OXVISUAL_SUPERADMIN_PASSWORD")
SUPERADMIN_EMAIL = os.getenv("OXVISUAL_SUPERADMIN_EMAIL", "superadmin@oxvisual.local")
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "OXVISUAL_CORS_ORIGINS",
        "http://127.0.0.1:5000",
    ).split(",")
    if origin.strip()
]
