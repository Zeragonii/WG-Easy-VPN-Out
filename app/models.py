from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from . import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class UserClientAccess(db.Model):
    __tablename__ = "user_client_access"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id"),
        nullable=False,
        index=True,
    )
    external_id = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    client_name = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime,
        server_default=db.func.now(),
        nullable=False,
    )

    user = db.relationship("User", backref="client_access")


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
    detected_country_code = db.Column(db.String(8), nullable=True)
    detected_country_name = db.Column(db.String(120), nullable=True)
    detected_region = db.Column(db.String(120), nullable=True)
    detected_city = db.Column(db.String(120), nullable=True)
    detected_location_source = db.Column(db.String(32), nullable=True)
    detected_location_ip = db.Column(db.String(64), nullable=True)
    manual_country = db.Column(db.String(120), nullable=True)
    manual_region = db.Column(db.String(120), nullable=True)
    manual_city = db.Column(db.String(120), nullable=True)
    favorite = db.Column(db.Boolean, nullable=False, default=False)
    tags = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now(), nullable=False)
    @property
    def type_label(self):
        return "OpenVPN" if self.vpn_type == "openvpn" else "WireGuard"


    @property
    def tag_list(self):
        return [
            value.strip()
            for value in (self.tags or "").split(",")
            if value.strip()
        ]

    @property
    def has_manual_location(self):
        return bool(self.manual_country or self.manual_region or self.manual_city)

    @property
    def effective_country(self):
        return self.manual_country or self.detected_country_name

    @property
    def effective_region(self):
        return self.manual_region or self.detected_region

    @property
    def effective_city(self):
        return self.manual_city or self.detected_city

    @property
    def effective_location_source(self):
        if self.has_manual_location:
            return "manual"
        return self.detected_location_source

    @property
    def location_label(self):
        parts = [
            value
            for value in (
                self.effective_country,
                self.effective_region,
                self.effective_city,
            )
            if value
        ]
        return " · ".join(parts) if parts else "Unknown"


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
