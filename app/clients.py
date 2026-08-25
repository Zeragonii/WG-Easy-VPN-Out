import os

from flask import Blueprint, render_template
from flask_login import login_required

from .services.wg_easy import WGEasyError, WGEasyService

bp = Blueprint("clients", __name__, url_prefix="/clients")


def _wg_easy_service() -> WGEasyService:
    verify_tls = os.getenv("WG_EASY_VERIFY_TLS", "true").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }

    return WGEasyService(
        base_url=os.getenv("WG_EASY_URL", "http://127.0.0.1:51821"),
        username=os.getenv("WG_EASY_USERNAME", ""),
        password=os.getenv("WG_EASY_PASSWORD", ""),
        verify_tls=verify_tls,
    )


@bp.get("/")
@login_required
def index():
    try:
        clients = _wg_easy_service().get_clients()
        error = None
    except WGEasyError as exc:
        clients = []
        error = str(exc)

    return render_template(
        "clients.html",
        clients=clients,
        error=error,
    )
