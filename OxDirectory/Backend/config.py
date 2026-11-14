import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)

UPLOAD_DIR = os.path.join(ROOT_DIR, "uploads")
DATABASE_PATH = os.path.join(UPLOAD_DIR, "users.db")
FILES_DIR = UPLOAD_DIR
DOMAIN_DATABASE_PATH = os.path.join(UPLOAD_DIR, "domain.db")
EXCEPTION_FILE_PATH = os.path.join(ROOT_DIR, "Configurations", "exception.json")
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(EXCEPTION_FILE_PATH), exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("oxdirectory")


JWT_SECRET = "uYnugCbULY1xtOjktoNgnqPvVTKrUubu-YwsHYvx7UFj1h837gBlnXaIzxKYLtAW"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_COOKIE = "oxtoken"
REFRESH_TOKEN_COOKIE = "oxrefresh"
ACCESS_TOKEN_TTL_SECONDS = 60 * 60
REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 7
COOKIE_SECURE = False
COOKIE_SAMESITE = "Lax"

MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 15 * 60

VALID_ROLES = ("viewer", "analyst", "operator", "manager", "user", "admin", "super_admin")

SUPERADMIN_USERNAME = "admin"
SUPERADMIN_PASSWORD = "IZhsjA6eNbHKKvCJIzIa1DWr"
SUPERADMIN_EMAIL = "admin@oxdirectory.local"
CORS_ORIGINS = ["http://0.0.0.0:6080"]
HOST = "0.0.0.0"
PORT = 6080
REDIS_URL = "memory://"