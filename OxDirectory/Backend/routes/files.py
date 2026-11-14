import os
import sqlite3
from flask import request
from werkzeug.utils import secure_filename

from app import app, limiter
from config import FILES_DIR, MAX_UPLOAD_BYTES
from helpers import _ok, _err
import auth
import domain_store
from domain_store import _is_importable


MAX_FILES = 200


@app.route("/api/files", methods=["GET"])
@auth.login_required
def files():
    return _ok(files=domain_store.list_files(), summary=domain_store.ace_summary())


@app.route("/api/dashboard-summary", methods=["GET"])
@auth.login_required
def dashboard_summary():
    return _ok(summary=domain_store.dashboard_summary())


@app.route("/api/vulnerabilities", methods=["GET"])
@auth.login_required
def vulnerabilities():
    return _ok(
        vulnerabilities=domain_store.list_vulnerabilities(),
        categories=domain_store.VULNERABILITY_CATEGORIES,
    )


@app.route("/api/ace-exceptions", methods=["GET"])
@auth.login_required
def ace_exceptions():
    try:
        return _ok(exceptions=domain_store.get_exceptions())
    except ValueError as error:
        return _err(str(error), 500)


@app.route("/api/ace-exceptions", methods=["POST"])
@auth.role_required("operator", "admin", "super_admin")
def add_ace_exception():
    payload = request.get_json(silent=True)
    value = payload.get("principal_name") if isinstance(payload, dict) else None
    if not isinstance(value, str) or not value.strip():
        return _err("Principal name is required", 400)
    try:
        principal = domain_store.find_ace_principal(value)
        if principal is None:
            return _err("Principal was not found in ACE records", 404)
        values = domain_store.get_exceptions()
        values.append(principal)
        return _ok(exceptions=domain_store.set_exceptions(values))
    except (OSError, ValueError) as error:
        return _err(str(error), 500)


@app.route("/api/ace-exceptions/<path:principal_name>", methods=["DELETE"])
@auth.role_required("operator", "admin", "super_admin")
def delete_ace_exception(principal_name):
    try:
        values = [
            value for value in domain_store.get_exceptions()
            if value["principal_name"].casefold() != principal_name.strip().casefold()
        ]
        return _ok(exceptions=domain_store.set_exceptions(values))
    except (OSError, ValueError) as error:
        return _err(str(error), 500)


@app.route("/api/ace-exceptions/optimize", methods=["POST"])
@auth.role_required("operator", "admin", "super_admin")
def optimize_ace_exceptions():
    try:
        exceptions, unresolved = domain_store.optimize_exceptions()
        return _ok(exceptions=exceptions, unresolved=unresolved)
    except (OSError, ValueError) as error:
        return _err(str(error), 500)


@app.route("/api/vulnerabilities/<path:vulnerability_id>/category", methods=["POST"])
@auth.role_required("analyst", "operator", "admin", "super_admin")
def vulnerability_category(vulnerability_id):
    payload = request.get_json(silent=True)
    category = payload.get("category") if isinstance(payload, dict) else None
    if category not in domain_store.VULNERABILITY_CATEGORIES:
        return _err("Invalid vulnerability category", 400)
    known = {item["id"] for item in domain_store.list_vulnerabilities()}
    if vulnerability_id not in known:
        return _err("Vulnerability not found", 404)
    try:
        domain_store.set_vulnerability_category(vulnerability_id, category)
    except sqlite3.Error as error:
        return _err(f"Could not save vulnerability category: {error}", 500)
    return _ok(vulnerability_id=vulnerability_id, category=category)


@app.route("/api/files/domain-aces", methods=["GET"])
@auth.login_required
def domain_aces():
    try:
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 50))
    except ValueError:
        return _err("Page values must be integers", 400)
    items, total, has_more = domain_store.list_aces(
        page,
        page_size,
        request.args.get("q", "").strip(),
        request.args.get("dangerous") == "1",
        request.args.get("filters", ""),
    )
    return _ok(
        items=items,
        page=max(page, 1),
        page_size=min(max(page_size, 1), 400),
        total=total,
        pages=max(page, page + (1 if has_more else 0)),
        has_more=has_more,
    )


@app.route("/api/domain-results/<kind>", methods=["GET"])
@auth.login_required
def domain_results(kind):
    allowed = {
        "domain": "domain_info",
        "users": "domain_users",
        "groups": "domain_groups",
        "computers": "domain_computers",
        "ous": "domain_ous",
        "gpos": "domain_gpos",
        "trusts": "domain_trusts",
        "certificates": "domain_certificates",
    }
    source_kind = allowed.get(kind)
    if source_kind is None:
        return _err("Unknown domain result", 404)
    try:
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", 50))
    except ValueError:
        return _err("Page values must be integers", 400)
    items, total = domain_store.list_records(
        source_kind, page, page_size, request.args.get("q", "").strip(),
        request.args.get("sort") or None, request.args.get("dir", "desc"),
        request.args.get("filters", ""),
    )
    return _ok(
        items=items,
        page=max(page, 1),
        page_size=min(max(page_size, 1), 200),
        total=total,
        pages=(total + min(max(page_size, 1), 200) - 1) // min(max(page_size, 1), 200),
    )


@app.route("/api/domain-ou-objects", methods=["GET"])
@auth.login_required
def domain_ou_objects():
    dn = request.args.get("dn", "").strip()
    if not dn:
        return _err("OU distinguished name is required", 400)
    items = domain_store.list_ou_objects(dn)
    return _ok(items=items, total=len(items))


@app.route("/api/files/upload", methods=["POST"])
@limiter.limit("30 per minute")
@auth.role_required("operator", "admin", "super_admin")
def upload_files():
    uploads = [item for item in request.files.getlist("file") if item and item.filename]
    if not uploads:
        return _err("No file provided", 400)
    if len(uploads) > MAX_FILES:
        return _err(f"Too many files; the limit is {MAX_FILES} per upload", 400)

    results = []
    for item in uploads:
        name = secure_filename(item.filename or "")
        if not name:
            results.append({"name": item.filename or "", "ok": False, "error": "Invalid filename"})
            continue
        if not _is_importable(name):
            results.append({
                "name": name, "ok": False,
                "error": "Only .json/.jsonl files are accepted (domain.db/users.db names are not allowed)",
            })
            continue
        path = os.path.join(FILES_DIR, name)
        try:
            item.save(path)
            count = domain_store.import_file(name)
            results.append({
                "name": name,
                "ok": True,
                "kind": domain_store.get_file(name)["kind"],
                "record_count": count,
            })
        except (OSError, UnicodeDecodeError, ValueError, sqlite3.Error) as error:
            if os.path.exists(path):
                os.remove(path)
            results.append({"name": name, "ok": False, "error": str(error)})
    loaded = [item for item in results if item["ok"]]
    if not loaded:
        return _err("No files could be imported", 400, results=results)
    return _ok(results=results, loaded_count=len(loaded), failed_count=len(results) - len(loaded))


@app.route("/api/files/<path:name>", methods=["GET"])
@auth.login_required
def file_preview(name):
    safe_name = secure_filename(name)
    if safe_name != name:
        return _err("File not found", 404)
    content = domain_store.get_file_content(safe_name)
    if content is None:
        return _err("File not found", 404)
    if len(content.encode("utf-8")) > MAX_UPLOAD_BYTES:
        return _err("File is too large to preview", 413)
    return _ok(
        name=safe_name,
        content=content[:200000],
        truncated=len(content) > 200000,
    )