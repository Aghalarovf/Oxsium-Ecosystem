import logging
import os

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
load_dotenv(os.path.join(ROOT_DIR, ".env"))

UPLOAD_DIR = os.path.join(ROOT_DIR, "uploads")
DATABASE_PATH = os.path.join(UPLOAD_DIR, "users.db")
FILES_DIR = UPLOAD_DIR
DOMAIN_DATABASE_PATH = os.path.join(UPLOAD_DIR, "domain.db")
EXCEPTION_FILE_PATH = os.path.join(ROOT_DIR, "Configurations", "exception.json")
MAX_UPLOAD_BYTES = int(os.getenv("OXDIRECTORY_MAX_UPLOAD_BYTES", str(1024 * 1024 * 1024)))

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(EXCEPTION_FILE_PATH), exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("oxdirectory")


def _required_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} must be set")
    return value


JWT_SECRET = _required_env("OXDIRECTORY_SECRET_KEY")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_COOKIE = "oxtoken"
REFRESH_TOKEN_COOKIE = "oxrefresh"
ACCESS_TOKEN_TTL_SECONDS = 60 * 60
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7
COOKIE_SECURE = os.getenv("OXDIRECTORY_ENV", "development") == "production"
COOKIE_SAMESITE = "Lax"

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60

VALID_ROLES = ("viewer", "analyst", "operator", "manager", "user", "admin", "super_admin")

SUPERADMIN_USERNAME = os.getenv("OXDIRECTORY_SUPERADMIN_USER", "admin")
SUPERADMIN_PASSWORD = _required_env("OXDIRECTORY_SUPERADMIN_PASSWORD")
SUPERADMIN_EMAIL = os.getenv("OXDIRECTORY_SUPERADMIN_EMAIL", "admin@oxdirectory.local")
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("OXDIRECTORY_CORS_ORIGINS", "http://192.168.0.8:6080").split(",")
    if origin.strip()
]