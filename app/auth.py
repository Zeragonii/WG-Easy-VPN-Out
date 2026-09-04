from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user

from . import db
from .models import User

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard") if current_user.is_admin else url_for("clients.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one_or_none()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("main.dashboard") if user.is_admin else url_for("clients.index"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@bp.post("/logout")
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
