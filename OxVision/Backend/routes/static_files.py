from flask import send_from_directory, redirect
from app import app
from config import ROOT_DIR, HTML_DIR, CSS_DIR, JS_DIR, ASSETS_DIR
import auth

@app.route("/")
def index():
    if auth.get_current_user() is None:
        return redirect("/login")
    return send_from_directory(HTML_DIR, "index.html")

@app.route("/login")
def login_page():
    if auth.get_current_user() is not None:
        return redirect("/")
    return send_from_directory(HTML_DIR, "login.html")

@app.route("/admincpanel")
def admincpanel_page():
    user = auth.get_current_user()
    if user is None:
        return redirect("/login")
    if user["role"] not in {"manager", "admin", "super_admin"}:
        return redirect("/")
    return send_from_directory(HTML_DIR, "admincpanel.html")

@app.route("/html/<path:filename>")
def serve_html(filename):
    return send_from_directory(HTML_DIR, filename)

@app.route("/css/<path:filename>")
def serve_css(filename):
    return send_from_directory(CSS_DIR, filename)

@app.route("/js/<path:filename>")
def serve_js(filename):
    return send_from_directory(JS_DIR, filename)

@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(ASSETS_DIR, filename)
