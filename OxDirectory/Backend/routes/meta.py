from app import app
from helpers import _ok
import store


@app.route("/api/meta", methods=["GET"])
def get_meta():
    dataset = store.get_dataset()
    return _ok(loaded=dataset is not None)
