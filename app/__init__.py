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

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(vpn_profiles_bp)
    app.register_blueprint(routing_groups_bp)

    with app.app_context():
        db.create_all()
        _bootstrap_admin()

        from .models import VPNProfile
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

    return app


def _bootstrap_admin():
    from .models import User

    username = os.getenv("ADMIN_USERNAME", "admin").strip()
    password = os.getenv("ADMIN_PASSWORD", "")

    if not password:
        raise RuntimeError("ADMIN_PASSWORD must be set")

    user = db.session.execute(
        db.select(User).filter_by(username=username)
    ).scalar_one_or_none()

    if user is None:
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
