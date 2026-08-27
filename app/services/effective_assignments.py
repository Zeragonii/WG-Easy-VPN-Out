from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress

from ..models import ClientAssignment, ClientRouteOverride


@dataclass(frozen=True, slots=True)
class EffectiveAssignment:
    external_id: str
    client_name: str
    ipv4_address: str
    routing_group_id: int
    overridden: bool


def _utcnow_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def active_overrides(db):
    now = _utcnow_naive()
    return db.session.execute(
        db.select(ClientRouteOverride).where(
            db.or_(
                ClientRouteOverride.expires_at.is_(None),
                ClientRouteOverride.expires_at > now,
            )
        )
    ).scalars().all()


def effective_assignments(db):
    """
    Return the policy assignment that should actually be applied to each client.

    Temporary overrides take precedence over persistent ClientAssignment rows.
    """
    overrides = {
        str(row.external_id): row
        for row in active_overrides(db)
    }

    rows = []
    seen = set()

    assignments = db.session.execute(
        db.select(ClientAssignment)
        .order_by(ClientAssignment.id.asc())
    ).scalars().all()

    for assignment in assignments:
        external_id = str(assignment.external_id)
        override = overrides.get(external_id)

        source = override if override is not None else assignment
        try:
            ipv4 = str(ipaddress.IPv4Address(source.ipv4_address))
        except ipaddress.AddressValueError:
            continue

        rows.append(EffectiveAssignment(
            external_id=external_id,
            client_name=source.client_name,
            ipv4_address=ipv4,
            routing_group_id=int(source.routing_group_id),
            overridden=override is not None,
        ))
        seen.add(external_id)

    # Overrides are also valid for clients with no persistent assignment.
    for external_id, override in overrides.items():
        if external_id in seen:
            continue
        try:
            ipv4 = str(ipaddress.IPv4Address(override.ipv4_address))
        except ipaddress.AddressValueError:
            continue

        rows.append(EffectiveAssignment(
            external_id=external_id,
            client_name=override.client_name,
            ipv4_address=ipv4,
            routing_group_id=int(override.routing_group_id),
            overridden=True,
        ))

    return rows
