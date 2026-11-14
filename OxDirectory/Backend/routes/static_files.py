import os

from flask import redirect, send_from_directory

from app import app
from config import ROOT_DIR
import auth


@app.route("/")
def index():
    if auth.get_current_user() is None:
        return redirect("/login")
    return send_from_directory(os.path.join(ROOT_DIR, "HTML"), "index.html")

@app.route("/login")
def login_page():
    if auth.get_current_user() is not None:
        return redirect("/")
    return send_from_directory(os.path.join(ROOT_DIR, "HTML"), "login.html")

@app.route("/admincpanel")
def admincpanel_page():
    user = auth.get_current_user()
    if user is None:
        return redirect("/login")
    if user["role"] not in {"manager", "admin", "super_admin"}:
        return redirect("/")
    return send_from_directory(os.path.join(ROOT_DIR, "HTML"), "admincpanel.html")


@app.route("/html/<path:filename>")
def html_files(filename):
    return send_from_directory(os.path.join(ROOT_DIR, "HTML"), filename)


@app.route("/css/<path:filename>")
def css_files(filename):
    return send_from_directory(os.path.join(ROOT_DIR, "CSS"), filename)


@app.route("/js/<path:filename>")
def js_files(filename):
    return send_from_directory(os.path.join(ROOT_DIR, "JS"), filename)
