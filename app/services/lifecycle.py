from __future__ import annotations

import atexit
import threading


_LOCK = threading.Lock()
_REGISTERED_APP_IDS = set()


def background_service_status(app):
    rows = []
    for service in app.extensions.get("background_services", []):
        try:
            rows.append(service.status())
        except Exception as exc:
            rows.append({
                "name": service.__class__.__name__,
                "running": None,
                "error": str(exc)[-300:],
            })
    return rows


def stop_background_services(app, timeout=3.0):
    """
    Stop background managers in reverse startup order.

    Each manager gets a bounded join so container shutdown cannot hang forever.
    """
    services = list(app.extensions.get("background_services", []))
    results = []

    for service in reversed(services):
        name = service.__class__.__name__
        try:
            stopped = service.stop(timeout=timeout)
        except Exception as exc:
            app.logger.exception("Error stopping background service %s.", name)
            results.append({
                "name": name,
                "stopped": False,
                "error": str(exc)[-300:],
            })
        else:
            results.append({
                "name": name,
                "stopped": bool(stopped),
                "error": None,
            })

    return results


def register_shutdown(app):
    """
    Register one process-exit cleanup callback per Flask application object.
    """
    app_id = id(app)
    with _LOCK:
        if app_id in _REGISTERED_APP_IDS:
            return
        _REGISTERED_APP_IDS.add(app_id)

    def _shutdown():
        try:
            results = stop_background_services(app)
            app.logger.info("Background service shutdown: %s", results)
        except Exception:
            # Never block interpreter shutdown because logging/app teardown
            # itself is already partially unavailable.
            pass

    atexit.register(_shutdown)
