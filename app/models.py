from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from . import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class VPNProfile(db.Model):
    __tablename__ = "vpn_profiles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    provider = db.Column(db.String(120), nullable=True)
    vpn_type = db.Column(db.String(16), nullable=False)
    config_filename = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=True)
    password = db.Column(db.String(255), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=False)
    connection_policy = db.Column(db.String(16), nullable=False, default="always")
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now(), nullable=False)
    @property
    def type_label(self):
        return "OpenVPN" if self.vpn_type == "openvpn" else "WireGuard"


class RoutingGroup(db.Model):
    __tablename__ = "routing_groups"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    vpn_profile_id = db.Column(
        db.Integer,
        db.ForeignKey("vpn_profiles.id"),
        nullable=True,
    )
    fallback_mode = db.Column(db.String(16), nullable=False, default="block")
    dns_mode = db.Column(db.String(16), nullable=False, default="inherit")
    dns_target = db.Column(db.String(64), nullable=True)
    fwmark = db.Column(db.Integer, unique=True, nullable=True)
    table_id = db.Column(db.Integer, unique=True, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)
    updated_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        onupdate=db.func.now(),
        nullable=False,
    )

    vpn_profile = db.relationship("VPNProfile")

    @property
    def target_label(self):
        return self.vpn_profile.name if self.vpn_profile else "Default WAN"

    @property
    def mark_hex(self):
        return f"0x{self.fwmark:x}" if self.fwmark is not None else "—"


    @property
    def effective_dns_target(self):
        if self.dns_mode == "pia":
            return "10.0.0.242"
        if self.dns_mode == "custom":
            return self.dns_target
        return None

    @property
    def dns_policy_label(self):
        if self.dns_mode == "pia":
            return "PIA DNS"
        if self.dns_mode == "custom":
            return f"Custom DNS ({self.dns_target or 'not set'})"
        return "Existing / client DNS"


class ClientRouteOverride(db.Model):
    __tablename__ = "client_route_overrides"

    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    client_name = db.Column(db.String(255), nullable=False)
    ipv4_address = db.Column(db.String(64), nullable=False)
    routing_group_id = db.Column(
        db.Integer,
        db.ForeignKey("routing_groups.id"),
        nullable=False,
        index=True,
    )
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        nullable=False,
    )

    routing_group = db.relationship("RoutingGroup")


class RouteOverrideEvent(db.Model):
    __tablename__ = "route_override_events"

    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.String(255), nullable=False, index=True)
    client_name = db.Column(db.String(255), nullable=False)
    event_type = db.Column(db.String(24), nullable=False, index=True)
    routing_group_id = db.Column(
        db.Integer,
        db.ForeignKey("routing_groups.id"),
        nullable=True,
        index=True,
    )
    routing_group_name = db.Column(db.String(120), nullable=True)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        nullable=False,
        index=True,
    )

    routing_group = db.relationship("RoutingGroup")


class ClientAssignment(db.Model):
    __tablename__ = "client_assignments"

    id = db.Column(db.Integer, primary_key=True)
    external_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    client_name = db.Column(db.String(255), nullable=False)
    ipv4_address = db.Column(db.String(64), nullable=False)
    routing_group_id = db.Column(
        db.Integer,
        db.ForeignKey("routing_groups.id"),
        nullable=False,
        index=True,
    )
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)
    updated_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        onupdate=db.func.now(),
        nullable=False,
    )

    routing_group = db.relationship("RoutingGroup")


class AppSetting(db.Model):
    __tablename__ = "app_settings"

    key = db.Column(db.String(120), primary_key=True)
    value = db.Column(db.Text, nullable=True)
    is_secret = db.Column(db.Boolean, nullable=False, default=False)
    updated_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        onupdate=db.func.now(),
        nullable=False,
    )


class RoutingEvent(db.Model):
    __tablename__ = "routing_events"

    id = db.Column(db.Integer, primary_key=True)
    routing_group_id = db.Column(
        db.Integer,
        db.ForeignKey("routing_groups.id"),
        nullable=False,
        index=True,
    )
    state = db.Column(db.String(32), nullable=False)
    effective_exit = db.Column(db.String(255), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        nullable=False,
        index=True,
    )

    routing_group = db.relationship("RoutingGroup")
