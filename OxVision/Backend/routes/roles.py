from flask import request
from app import app
from helpers import _ok, _err
from config import logger
import store
import auth

@app.route("/api/hosts/<path:host>/roles", methods=["POST"])
@auth.role_required("analyst", "operator", "admin", "super_admin")
def update_host_roles(host):
    if store.get_dataset() is None:
        return _err("No dataset loaded", 404)

    payload = request.get_json(silent=True)
    roles = store.clean_roles(payload.get("roles")) if isinstance(payload, dict) else None
    if roles is None:
        return _err("A list of 'roles' is required", 400)

    try:
        found = store.update_host_field(host, "roles", roles)
    except OSError as e:
        logger.exception("Could not save roles for host %s", host)
        return _err(f"Could not save roles: {e}", 500)
    if not found:
        return _err("Host not found", 404)

    return _ok(host=host, roles=roles)

@app.route("/api/hosts/<path:host>/details", methods=["POST"])
@auth.role_required("operator", "admin", "super_admin")
def update_host_details(host):
    if store.get_dataset() is None:
        return _err("No dataset loaded", 404)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _err("A JSON object is required", 400)

    hostname = payload.get("hostname", "").strip() if isinstance(payload.get("hostname", ""), str) else None
    os_name = payload.get("os") if isinstance(payload.get("os"), str) else None
    roles = store.clean_roles(payload.get("roles"))
    if hostname is None or len(hostname) > 253:
        return _err("A valid 'hostname' is required", 400)
    if os_name not in store.VALID_OPERATING_SYSTEMS:
        return _err("Invalid operating system", 400)
    if roles is None:
        return _err("A list of 'roles' is required", 400)

    try:
        found = store.update_host_fields(host, {"hostname": hostname, "os": os_name, "roles": roles})
    except OSError as e:
        logger.exception("Could not save details for host %s", host)
        return _err(f"Could not save host details: {e}", 500)
    if not found:
        return _err("Host not found", 404)

    return _ok(host=host, hostname=hostname, os=os_name, roles=roles)