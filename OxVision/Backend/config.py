import os
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
DEFAULT_UPLOAD_DIR = (
    os.path.join(ROOT_DIR, "uploads")
)
UPLOAD_DIR = DEFAULT_UPLOAD_DIR
DATABASE_PATH = os.path.join(UPLOAD_DIR, "portscan.db")
SNAPSHOT_DIR = os.path.join(UPLOAD_DIR, "snapshots")
HTML_DIR = os.path.join(ROOT_DIR, "HTML")
CSS_DIR = os.path.join(ROOT_DIR, "CSS")
JS_DIR = os.path.join(ROOT_DIR, "JS")
ASSETS_DIR = os.path.join(ROOT_DIR, "Configurations", "Assets")
CWES_PATH = os.path.join(ROOT_DIR, "Configurations", "cwes.json")
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SNAPSHOT_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("oxvision")

JWT_SECRET = "sslvA9dJ7YL6TKrGC3Mdg66fopWrKcf1qTmbgPklTMkhDTwT2aAVz9Zy6pYxcCwb"
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
SUPERADMIN_PASSWORD = "MN3-0-_uSvjOR0mjxkuarYKI"
SUPERADMIN_EMAIL = "superadmin@oxvisual.local"
CORS_ORIGINS = ["http://localhost:5000", "http://127.0.0.1:5000"]
HOST = "0.0.0.0"
PORT = 5000
REDIS_URL = "memory://"
