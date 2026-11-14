import json
import os
from flask import request, g
from werkzeug.utils import secure_filename
from app import app, limiter
from helpers import _ok, _err
from config import logger, MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS
import store
import auth
import users_store

MAX_UPLOAD_FILES = 200


def _import_file(f):
    original = f.filename or ""
    lower_name = original.lower()
    if not lower_name.endswith(".json"):
        return {"name": original, "ok": False, "error": "Only JSON files are accepted"}, None

    try:
        data = json.load(f.stream)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return {"name": original, "ok": False, "error": f"Invalid JSON: {e}"}, None

    if not isinstance(data, dict) or not isinstance(data.get("hosts"), list):
        return {"name": original, "ok": False, "error": "Missing or invalid 'hosts' field in JSON"}, None

    store.load_dataset(data, secure_filename(original) or "dataset.json")
    logger.info("Dataset loaded: %s (%d hosts)", original, len(data["hosts"]))
    return {"name": original, "ok": True, "host_count": len(data["hosts"])}, data

@app.route("/api/upload", methods=["POST"])
@limiter.limit("30 per minute")
@auth.role_required("operator", "admin", "super_admin")
def upload_scan():
    files = [f for f in request.files.getlist("file") if f and f.filename]
    if not files:
        return _err("No file provided", 400)
    if len(files) > MAX_UPLOAD_FILES:
        return _err(f"Too many files; the limit is {MAX_UPLOAD_FILES} per upload", 400)

    results = []
    mode = None
    for f in files:
        result, data = _import_file(f)
        results.append(result)
        if isinstance(data, dict) and data.get("mode"):
            mode = data.get("mode")

    loaded = [r for r in results if r["ok"]]
    if not loaded:
        message = results[0]["error"] if len(results) == 1 else f"None of the {len(results)} files could be imported"
        return _err(message, 400, results=results)

    return _ok(
        host_count=sum(r.get("host_count", 0) for r in loaded),
        subnet_count=len(store.get_subnets()),
        mode=mode,
        file_count=len(results),
        loaded_count=len(loaded),
        failed_count=len(results) - len(loaded),
        results=results,
    )

@app.route("/api/subnets", methods=["DELETE"])
@limiter.limit("60 per minute")
@auth.role_required("operator", "admin", "super_admin")
def delete_subnet():
    subnets = []
    for value in request.args.getlist("subnet"):
        value = value.strip()
        if value and value not in subnets:
            subnets.append(value)
    if not subnets:
        return _err("A subnet is required", 400)

    removed_hosts = 0
    removed_subnets = 0
    try:
        for subnet in subnets:
            hosts, entries = store.delete_subnet(subnet)
            removed_hosts += hosts
            removed_subnets += entries
    except OSError as e:
        logger.exception("Could not delete subnets %s", subnets)
        return _err(f"Could not delete subnet: {e}", 500)

    if not removed_hosts and not removed_subnets:
        return _err("Subnet not found", 404)

    logger.info("Subnets deleted: %s (%d hosts)", ", ".join(subnets), removed_hosts)
    return _ok(subnets=subnets, removed_hosts=removed_hosts, removed_subnets=removed_subnets)

@app.route("/api/subnets/special-name", methods=["POST"])
@limiter.limit("60 per minute")
@auth.role_required("operator", "admin", "super_admin")
def update_subnet_special_name():
    payload = request.get_json(silent=True)
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("subnet"), str)
        or not isinstance(payload.get("special_name"), str)
    ):
        return _err("A subnet and a string 'special_name' are required", 400)

    label = payload["subnet"].strip()
    if label not in {store.subnet_label(item) for item in store.get_subnets()}:
        return _err("Subnet not found", 404)

    name = store.clean_special_name(payload["special_name"])
    try:
        store.set_subnet_name(label, name)
    except OSError as e:
        logger.exception("Could not save special name for %s", label)
        return _err(f"Could not save special name: {e}", 500)
    return _ok(subnet=label, special_name=name)

@app.route("/api/subnets/group", methods=["POST"])
@limiter.limit("60 per minute")
@auth.role_required("operator", "admin", "super_admin")
def update_subnet_group():
    payload = request.get_json(silent=True)
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("subnet"), str)
        or not isinstance(payload.get("group_name"), str)
    ):
        return _err("A subnet and a string 'group_name' are required", 400)

    label = payload["subnet"].strip()
    if label not in {store.subnet_label(item) for item in store.get_subnets()}:
        return _err("Subnet not found", 404)

    group_name = store.clean_group_name(payload["group_name"])
    try:
        store.set_subnet_group(label, group_name)
    except OSError as error:
        logger.exception("Could not save group for %s", label)
        return _err(f"Could not save subnet group: {error}", 500)
    return _ok(subnet=label, group_name=group_name)

@app.route("/api/subnets/group-name", methods=["POST"])
@limiter.limit("60 per minute")
@auth.role_required("operator", "admin", "super_admin")
def create_subnet_group():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("group_name"), str):
        return _err("A string 'group_name' is required", 400)
    group_name = store.clean_group_name(payload["group_name"])
    if not group_name:
        return _err("A group name is required", 400)
    try:
        store.add_subnet_group_name(group_name)
    except OSError as error:
        logger.exception("Could not create subnet group")
        return _err(f"Could not create subnet group: {error}", 500)
    return _ok(group_name=group_name)

@app.route("/api/reset", methods=["POST"])
@limiter.limit("5 per minute")
@auth.role_required("admin", "super_admin")
def reset_scan():
    user = g.current_user
    if users_store.is_locked(user):
        return _err("Account is temporarily locked. Try again later.", 429)

    payload = request.get_json(silent=True)
    password = payload.get("password") if isinstance(payload, dict) else None
    if not isinstance(password, str) or not password:
        return _err("Administrator password is required", 400)

    password_hash = users_store.get_password_hash(user["username"])
    if not password_hash or not users_store.verify_password(password, password_hash):
        users_store.register_failed_login(user["username"], MAX_LOGIN_ATTEMPTS, LOGIN_LOCKOUT_SECONDS)
        logger.warning("Reset refused for %s: wrong password", user["username"])
        return _err("Incorrect password", 403)

    try:
        backup = store.reset_database()
    except OSError as error:
        logger.exception("Could not archive the database")
        return _err(f"Could not archive the database: {error}", 500)

    logger.info("Database reset by %s; previous data archived as %s", user["username"], backup)
    return _ok(backup=os.path.basename(backup) if backup else None)

@app.route("/api/hosts/<path:host>/note", methods=["POST"])
@auth.role_required("analyst", "operator", "admin", "super_admin")
def update_host_note(host):
    if store.get_dataset() is None:
        return _err("No dataset loaded", 404)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("note"), str):
        return _err("A string 'note' is required", 400)

    note = payload["note"].strip()
    try:
        found = store.update_host_field(host, "note", note)
    except OSError as e:
        logger.exception("Could not save note for host %s", host)
        return _err(f"Could not save note: {e}", 500)
    if not found:
        return _err("Host not found", 404)

    return _ok(host=host, note=note)