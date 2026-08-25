import os
from pathlib import Path

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"


def create_app():
    app = Flask(__name__)

    data_dir = Path(os.getenv("VPN_ROUTER_DATA_DIR", "/data"))
    data_dir.mkdir(parents=True, exist_ok=True)

    app.config.update(
        SECRET_KEY=os.environ["SECRET_KEY"],
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{data_dir / 'vpn-router.db'}",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from .auth import bp as auth_bp
    from .clients import bp as clients_bp
    from .main import bp as main_bp
    from .vpn_profiles import bp as vpn_profiles_bp
    from .routing_groups import bp as routing_groups_bp
    from .backups import bp as backups_bp
    from .diagnostics import bp as diagnostics_bp
    from .setup import bp as setup_bp
    from .settings import bp as settings_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(vpn_profiles_bp)
    app.register_blueprint(routing_groups_bp)
    app.register_blueprint(backups_bp)
    app.register_blueprint(diagnostics_bp)
    app.register_blueprint(setup_bp)
    app.register_blueprint(settings_bp)

    @app.before_request
    def require_initial_setup():
        from flask import request, redirect, url_for
        from .models import AppSetting
        from .services.settings import SettingsService
        if request.endpoint in {"setup.index", "static"}:
            return None
        if request.path.startswith("/health"):
            return None
        if not SettingsService(db, AppSetting).setup_complete():
            return redirect(url_for("setup.index"))
        return None

    with app.app_context():
        # Fresh-install bootstrap only. Existing/future schema evolution is
        # handled by the ordered migration framework below.
        db.create_all()

        from .services.migrations import run_migrations
        migration_result = run_migrations(db, app.logger)
        app.extensions["schema_migrations"] = migration_result

        from .models import AppSetting, VPNProfile
        from .services.settings import SettingsService

        settings = SettingsService(db, AppSetting)
        migrated_settings = settings.migrate_legacy_environment()
        if migrated_settings:
            app.logger.info(
                "Imported legacy environment settings: %s",
                ", ".join(migrated_settings),
            )

        _bootstrap_or_prepare_setup(app, settings)

        from .services.secrets import migrate_legacy_profile_passwords

        migrated = migrate_legacy_profile_passwords(db, VPNProfile)
        if migrated:
            app.logger.info("Encrypted %s legacy VPN password(s).", migrated)

    from .models import VPNProfile
    from .services.vpn_startup import restore_enabled_profiles

    restore_enabled_profiles(app, db, VPNProfile)

    with app.app_context():
        from .models import RoutingGroup
        from .services.routing import RoutingEngine, RoutingEngineError

        try:
            RoutingEngine().rebuild(db, RoutingGroup)
        except RoutingEngineError as exc:
            app.logger.error("Initial routing rebuild failed: %s", exc)

    from .services.routing_reconciler import RoutingReconciler

    routing_reconciler = RoutingReconciler(app, db, RoutingGroup)
    routing_reconciler.start()
    app.extensions["routing_reconciler"] = routing_reconciler

    from .services.vpn_resilience import VPNResilienceManager

    vpn_resilience = VPNResilienceManager(app, db, VPNProfile)
    vpn_resilience.start()
    app.extensions["vpn_resilience"] = vpn_resilience

    from .services.observability import ObservabilityService

    observability = ObservabilityService(app, db, VPNProfile)
    observability.start()
    app.extensions["observability"] = observability

    app.extensions["background_services"] = [
        routing_reconciler,
        vpn_resilience,
        observability,
    ]

    from .services.lifecycle import register_shutdown
    register_shutdown(app)

    return app



def _bootstrap_or_prepare_setup(app, settings):
    """
    Backward-compatible bootstrap:
    - Existing user => mark setup complete.
    - Legacy ADMIN_PASSWORD on a fresh DB => create admin and mark complete.
    - Otherwise generate a one-time setup token and require the web wizard.
    """
    from .models import User
    from .services.setup import ensure_setup_token, remove_setup_token

    user = db.session.execute(
        db.select(User).order_by(User.id.asc())
    ).scalars().first()

    if user is not None:
        if not settings.setup_complete():
            settings.mark_setup_complete()
        remove_setup_token()
        return

    username = os.getenv("ADMIN_USERNAME", "admin").strip() or "admin"
    password = os.getenv("ADMIN_PASSWORD", "")
    if password:
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        settings.mark_setup_complete()
        remove_setup_token()
        app.logger.info(
            "Created administrator from legacy ADMIN_* environment values."
        )
        return

    ensure_setup_token(app.logger)
