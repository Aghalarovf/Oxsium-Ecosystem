from flask import jsonify


def _ok(**payload):
    return jsonify({"ok": True, **payload})


def _err(message, status=400, **payload):
    return jsonify({"ok": False, "error": message, **payload}), status
