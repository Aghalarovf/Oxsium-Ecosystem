from flask import jsonify

def _ok(**kwargs):
    return jsonify({"ok": True, **kwargs})

def _err(message, status=400, **extra):
    return jsonify({"ok": False, "error": message, **extra}), status