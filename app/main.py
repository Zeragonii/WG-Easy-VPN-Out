import os
import shutil
import subprocess

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

bp = Blueprint("main", __name__)


def command_exists(name):
    return shutil.which(name) is not None


def wg0_present():
    try:
        result = subprocess.run(
            ["ip", "link", "show", "wg0"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def system_status():
    return {
        "version": os.getenv("APP_VERSION", "0.3.2"),
        "wg_easy_url": os.getenv("WG_EASY_URL", "http://127.0.0.1:51821"),
        "wg0_present": wg0_present(),
        "tools": {
            "openvpn": command_exists("openvpn"),
            "wg": command_exists("wg"),
            "nft": command_exists("nft"),
            "ip": command_exists("ip"),
        },
    }


@bp.get("/")
@login_required
def dashboard():
    return render_template("dashboard.html", status=system_status())


@bp.get("/health")
def health():
    status = system_status()
    healthy = all(status["tools"].values())
    return jsonify({"status": "ok" if healthy else "degraded", **status}), 200 if healthy else 503
