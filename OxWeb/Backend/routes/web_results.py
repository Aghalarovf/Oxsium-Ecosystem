import json

from flask import request, g

from app import app
from helpers import _err, _ok
import auth
import web_results_store


@app.route("/api/whois-dns/results", methods=["GET"])
def list_whois_dns_results():
    return _ok(results=web_results_store.list_reports())


@app.route("/api/whois-dns/upload", methods=["POST"])
@auth.role_required("analyst", "operator", "admin", "super_admin")
def upload_whois_dns_result():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return _err("A JSON report file is required", 400)
    if not uploaded.filename.lower().endswith(".json"):
        return _err("Only JSON report files are supported", 400)
    try:
        report = json.loads(uploaded.read().decode("utf-8"))
        result = web_results_store.import_report(report, uploaded.filename)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return _err(str(exc), 400)
    return _ok(result=result)


@app.route("/api/whois-dns/reset", methods=["POST"])
@auth.role_required("operator", "admin", "super_admin")
def reset_whois_dns_results():
    deleted = web_results_store.reset_reports()
    return _ok(deleted=deleted)
