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
    from .traffic import bp as traffic_bp
    from .users import bp as users_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(vpn_profiles_bp)
    app.register_blueprint(routing_groups_bp)
    app.register_blueprint(backups_bp)
    app.register_blueprint(diagnostics_bp)
    app.register_blueprint(setup_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(users_bp)

    @app.before_request
    def enforce_user_scope():
        from flask import request, redirect, url_for
        from flask_login import current_user

        if not current_user.is_authenticated:
            return None
        if bool(getattr(current_user, "is_admin", False)):
            return None
        if request.blueprint in {"auth", "clients"} or request.endpoint == "static":
            return None
        return redirect(url_for("clients.index"))

    @app.context_processor
    def inject_ui_preferences():
        from .models import AppSetting
        from .services.settings import SettingsService
        try:
            particles_enabled = bool(
                SettingsService(db, AppSetting).get(
                    "background_particles_enabled"
                )
            )
        except Exception:
            # A rendering preference should never be able to take the app down.
            particles_enabled = False
        return {
            "background_particles_enabled": particles_enabled,
        }

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

        from .services.geoip import GeoIPService
        geoip = GeoIPService()
        app.extensions["geoip"] = geoip
        if geoip.available():
            app.logger.info("Local GeoIP database ready: %s", geoip.status().get("path"))
        else:
            app.logger.info(
                "Local GeoIP database not configured; location enrichment remains optional."
            )

        from .services.secrets import migrate_legacy_profile_passwords

        migrated = migrate_legacy_profile_passwords(db, VPNProfile)
        if migrated:
            app.logger.info("Encrypted %s legacy VPN password(s).", migrated)

        if geoip.available():
            from .services.profile_intelligence import inspect_profile
            from .services.geoip import apply_detected_location
            for profile in db.session.execute(
                db.select(VPNProfile).order_by(VPNProfile.id.asc())
            ).scalars().all():
                try:
                    folder = "openvpn" if profile.vpn_type == "openvpn" else "wireguard"
                    content = (
                        data_dir / folder / profile.config_filename
                    ).read_text(encoding="utf-8", errors="replace")
                    intelligence = inspect_profile(profile, content)
                    if intelligence.endpoint_is_ip and intelligence.endpoint_host:
                        apply_detected_location(
                            db,
                            profile,
                            geoip,
                            intelligence.endpoint_host,
                            "endpoint_geoip",
                        )
                except OSError:
                    continue
            db.session.commit()

    from .models import ClientAssignment, RoutingGroup, VPNProfile
    from .services.vpn_startup import restore_enabled_profiles
    from .services.on_demand import OnDemandVPNManager
    from .services.routing_overrides import TemporaryOverrideManager

    # Existing Always profiles restore exactly as before.
    restore_enabled_profiles(app, db, VPNProfile)

    # Remove expired persisted overrides before calculating which On-demand
    # tunnels are required and before the initial routing rebuild.
    temporary_overrides = TemporaryOverrideManager(app, db)
    with app.app_context():
        temporary_overrides.expire_once()
        db.session.remove()

    on_demand = OnDemandVPNManager(
        app,
        db,
        VPNProfile,
        RoutingGroup,
        ClientAssignment,
    )
    with app.app_context():
        on_demand.reconcile_once()
        db.session.remove()

    with app.app_context():
        from .services.routing import RoutingEngine, RoutingEngineError

        try:
            RoutingEngine().rebuild(db, RoutingGroup)
        except RoutingEngineError as exc:
            app.logger.error("Initial routing rebuild failed: %s", exc)

    from .services.routing_reconciler import RoutingReconciler

    routing_reconciler = RoutingReconciler(app, db, RoutingGroup)
    routing_reconciler.start()
    app.extensions["routing_reconciler"] = routing_reconciler

    on_demand.start()
    app.extensions["on_demand_vpn"] = on_demand

    temporary_overrides.start()
    app.extensions["temporary_routing_overrides"] = temporary_overrides

    from .services.vpn_resilience import VPNResilienceManager

    vpn_resilience = VPNResilienceManager(app, db, VPNProfile)
    vpn_resilience.start()
    app.extensions["vpn_resilience"] = vpn_resilience

    from .services.observability import ObservabilityService
    from .services.traffic_visibility import TrafficVisibilityService

    observability = ObservabilityService(app, db, VPNProfile)
    observability.start()
    app.extensions["observability"] = observability

    traffic_visibility = TrafficVisibilityService(app, db)
    traffic_visibility.start()
    app.extensions["traffic_visibility"] = traffic_visibility

    from .services.preflight_jobs import PreflightJobManager

    app.extensions["preflight_jobs"] = PreflightJobManager(app, db)

    app.extensions["background_services"] = [
        routing_reconciler,
        on_demand,
        temporary_overrides,
        vpn_resilience,
        observability,
        traffic_visibility,
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
        user = User(username=username, is_admin=True)
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
