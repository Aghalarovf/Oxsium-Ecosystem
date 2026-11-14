from app import app
from helpers import _ok
from config import APP_NAME, APP_VERSION

@app.route("/api/meta", methods=["GET"])
def get_meta():
    return _ok(name=APP_NAME, version=APP_VERSION)
