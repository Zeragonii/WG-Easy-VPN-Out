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
