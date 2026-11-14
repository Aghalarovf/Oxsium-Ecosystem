import sqlite3
from flask import request, g
from app import app
from helpers import _ok, _err
import store
import auth

@app.route("/api/targets", methods=["GET"])
def list_targets():
    return _ok(targets=store.list_targets())

@app.route("/api/targets", methods=["POST"])
@auth.role_required("analyst", "operator", "admin", "super_admin")
def create_target():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _err("A JSON object is required", 400)
    url = payload.get("url")
    if not isinstance(url, str) or not url.strip().lower().startswith(("http://", "https://")):
        return _err("A valid http(s) URL is required", 400)
    name = payload.get("name")
    notes = payload.get("notes")
    if name is not None and not isinstance(name, str):
        return _err("Name must be a string", 400)
    if notes is not None and not isinstance(notes, str):
        return _err("Notes must be a string", 400)
    try:
        target = store.add_target(url.strip(), (name or "").strip() or None, (notes or "").strip() or None, g.current_user["id"])
    except sqlite3.IntegrityError:
        return _err("Target already exists", 409)
    return _ok(target=target)

@app.route("/api/targets/<int:target_id>", methods=["DELETE"])
@auth.role_required("operator", "admin", "super_admin")
def remove_target(target_id):
    if not store.delete_target(target_id):
        return _err("Target not found", 404)
    return _ok(id=target_id)
