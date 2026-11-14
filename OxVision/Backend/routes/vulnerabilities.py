from flask import request
from app import app
from helpers import _ok, _err
from config import logger
import store
import auth

@app.route("/api/hosts/<path:host>/vulnerabilities", methods=["GET"])
def get_host_vulnerabilities(host):
    if store.get_dataset() is None:
        return _err("No dataset loaded", 404)

    vulns = store.get_vulnerabilities(host)
    if vulns is None:
        return _err("Host not found", 404)

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    ordered = sorted(
        vulns,
        key=lambda v: (severity_order.get(v.get("severity"), 5), -(v.get("created_at") or 0)),
    )
    return _ok(host=host, vulnerabilities=ordered, total=len(ordered))

@app.route("/api/hosts/<path:host>/vulnerabilities", methods=["POST"])
@auth.role_required("analyst", "operator", "admin", "super_admin")
def create_host_vulnerability(host):
    if store.get_dataset() is None:
        return _err("No dataset loaded", 404)

    payload = request.get_json(silent=True)
    fields, error = store.clean_vulnerability_input(payload)
    if error:
        return _err(error, 400)

    try:
        record, error = store.add_vulnerability(host, fields)
    except OSError as e:
        logger.exception("Could not save vulnerability for host %s", host)
        return _err(f"Could not save vulnerability: {e}", 500)

    if error:
        return _err(error, 404 if error == "Host not found" else 400)

    logger.info("Vulnerability added for host %s: %s", host, fields["title"])
    return _ok(host=host, vulnerability=record)

@app.route("/api/hosts/<path:host>/vulnerabilities/<vuln_id>", methods=["POST"])
@auth.role_required("analyst", "operator", "admin", "super_admin")
def update_host_vulnerability(host, vuln_id):
    if store.get_dataset() is None:
        return _err("No dataset loaded", 404)

    payload = request.get_json(silent=True)
    fields, error = store.clean_vulnerability_input(payload)
    if error:
        return _err(error, 400)

    try:
        record, error = store.update_vulnerability(host, vuln_id, fields, payload.get("hosts"))
    except OSError as e:
        logger.exception("Could not update vulnerability %s for host %s", vuln_id, host)
        return _err(f"Could not update vulnerability: {e}", 500)

    if error:
        return _err(error, 404)

    return _ok(host=host, hosts=payload.get("hosts") or [host], vulnerability=record)

@app.route("/api/hosts/<path:host>/vulnerabilities/<vuln_id>", methods=["DELETE"])
@auth.role_required("analyst", "operator", "admin", "super_admin")
def delete_host_vulnerability(host, vuln_id):
    if store.get_dataset() is None:
        return _err("No dataset loaded", 404)

    try:
        found = store.delete_vulnerability(host, vuln_id)
    except OSError as e:
        logger.exception("Could not delete vulnerability %s for host %s", vuln_id, host)
        return _err(f"Could not delete vulnerability: {e}", 500)

    if not found:
        return _err("Vulnerability not found", 404)

    return _ok(host=host, vuln_id=vuln_id)

@app.route("/api/cwe/search", methods=["GET"])
def search_cwe():
    query = request.args.get("q", "")
    try:
        limit = min(int(request.args.get("limit", 25)), 50)
    except ValueError:
        limit = 25
    results = store.search_cwes(query, limit=limit)
    return _ok(results=results, total=len(results))

@app.route("/api/cwe/<cwe_id>", methods=["GET"])
def get_cwe_detail(cwe_id):
    entry = store.get_cwe(cwe_id)
    if entry is None:
        return _err("CWE not found", 404)
    return _ok(cwe=entry)

@app.route("/api/vulnerabilities/all", methods=["GET"])
def get_all_vulnerabilities():
    if store.get_dataset() is None:
        return _err("No dataset loaded", 404)

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    results = []
    for host in store.get_hosts():
        host_id = host.get("host") or host.get("ip") or ""
        for vuln in host.get("vulnerabilities", []) or []:
            results.append({
                **vuln,
                "category": vuln.get("category", store.VULNERABILITY_CATEGORIES[0]),
                "host": host_id,
            })

    results.sort(key=lambda v: (severity_order.get(v.get("severity"), 5), -(v.get("created_at") or 0)))
    return _ok(vulnerabilities=results, total=len(results))