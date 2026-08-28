from __future__ import annotations

from datetime import datetime, timezone
import threading

from .preflight import run_preflight


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


class PreflightJobManager:
    """
    Own one process-local preflight run at a time.

    The preflight thread is independent of the HTTP request that started it, so
    users may leave/revisit Diagnostics while verification continues. Results
    remain available until the next run or application restart.
    """

    def __init__(self, app, db):
        self.app = app
        self.db = db
        self._lock = threading.RLock()
        self._thread = None
        self._state = {
            "state": "idle",
            "started_at": None,
            "completed_at": None,
            "result": None,
            "error": None,
            "progress": None,
        }

    def _set_progress(self, progress):
        with self._lock:
            self._state["progress"] = dict(progress or {})

    def _run(self):
        try:
            with self.app.app_context():
                from ..models import ClientAssignment, RoutingGroup, VPNProfile

                result = run_preflight(
                    self.app,
                    self.db,
                    VPNProfile,
                    RoutingGroup,
                    ClientAssignment,
                    progress_callback=self._set_progress,
                )
                self.db.session.remove()

            with self._lock:
                self._state.update({
                    "state": "complete",
                    "completed_at": _iso_now(),
                    "result": result,
                    "error": None,
                    "progress": {"phase": "complete", "current": 0, "total": 0},
                })

        except Exception as exc:
            self.app.logger.exception("Asynchronous preflight job failed.")
            try:
                with self.app.app_context():
                    self.db.session.remove()
            except Exception:
                pass

            with self._lock:
                self._state.update({
                    "state": "failed",
                    "completed_at": _iso_now(),
                    "result": None,
                    "error": str(exc)[-600:],
                })

    def start(self):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False, self.status()

            self._state = {
                "state": "running",
                "started_at": _iso_now(),
                "completed_at": None,
                "result": None,
                "error": None,
                "progress": {"phase": "starting", "current": 0, "total": 0},
            }

            self._thread = threading.Thread(
                target=self._run,
                name="vpn-router-preflight",
                daemon=True,
            )
            self._thread.start()

            return True, self.status()

    def status(self):
        with self._lock:
            state = dict(self._state)
            state["running"] = bool(
                self._thread and self._thread.is_alive()
            )
            return state
