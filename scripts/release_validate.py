from __future__ import annotations

import py_compile
from pathlib import Path
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]


def fail(message):
    print(f"FAIL: {message}")
    raise SystemExit(1)


def main():
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+(?:\.\d+)+(?:[A-Za-z][A-Za-z0-9]*)?", version):
        fail(f"VERSION has an unsupported shape: {version!r}")

    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    if "APP_VERSION:" in compose:
        fail("docker-compose.yml must not override APP_VERSION")

    for py in ROOT.rglob("*.py"):
        if ".git" in py.parts:
            continue
        py_compile.compile(str(py), doraise=True)

    for yaml_path in (
        ROOT / "docker-compose.yml",
        ROOT / ".github/workflows/publish.yml",
    ):
        with yaml_path.open(encoding="utf-8") as handle:
            yaml.safe_load(handle)

    diagnostics = (ROOT / "app/services/diagnostics.py").read_text(encoding="utf-8")
    for required_fragment in (
        "effective = effective_assignments(db)",
        "overrides = active_overrides(db)",
        'if display_state == "standby"',
        '"permanent_clients"',
        '"effective_clients"',
        '"override_clients"',
        "Active temporary overrides:",
        "Effective client routes:",
    ):
        if required_fragment not in diagnostics:
            fail(f"v1.8.2 diagnostics cleanup is missing: {required_fragment}")

    if '"assigned_clients"' in diagnostics:
        fail("v1.8.2 diagnostics still uses legacy raw assigned_clients counts")

    for forbidden in (
        "WG_EASY_PASSWORD",
        "ADMIN_PASSWORD",
    ):
        if forbidden in diagnostics:
            fail(f"diagnostics source references forbidden secret: {forbidden}")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "AI-assisted development" not in readme:
        fail("README.md is missing the AI-assisted development disclosure")

    vpn_profiles_source = (ROOT / "app/vpn_profiles.py").read_text(encoding="utf-8")
    index_block = re.search(
        r'def index\(\):(?P<body>.*?)(?=\n@bp\.|\Z)',
        vpn_profiles_source,
        flags=re.S,
    )
    detail_block = re.search(
        r'def detail\(profile_id\):(?P<body>.*?)(?=\n@bp\.|\Z)',
        vpn_profiles_source,
        flags=re.S,
    )
    if not index_block or not detail_block:
        fail("Could not inspect VPN profile routes")

    index_body = index_block.group("body")
    detail_body = detail_block.group("body")

    # Catch the actual v1.5.1 regression: detail-only template context
    # must never be passed from the list route. The literal string
    # "on_demand" is valid in index() because connection-policy logic lives
    # there.
    for forbidden_fragment in (
        "runtime_display_state=runtime_display_state",
        "on_demand=on_demand",
    ):
        if forbidden_fragment in index_body:
            fail(
                "vpn_profiles.index leaks detail-only template context: "
                f"{forbidden_fragment}"
            )

    for required_fragment in (
        "runtime_display_state=runtime_display_state",
        "on_demand=on_demand",
    ):
        if required_fragment not in detail_body:
            fail(
                "vpn_profiles.detail is missing required template context: "
                f"{required_fragment}"
            )

    if "runtime_display=runtime_display" not in index_body:
        fail("vpn_profiles.index is missing runtime_display template context")

    index_template = (
        ROOT / "app/templates/vpn_profiles/index.html"
    ).read_text(encoding="utf-8")
    if "○ Offline" not in index_template:
        fail("VPN profile list must label idle profiles as Offline")

    dns_probe_source = (
        ROOT / "app/services/dns_observability.py"
    ).read_text(encoding="utf-8")
    dns_probe = re.search(
        r"def run_explicit_resolver_probe\((?P<sig>.*?)\):(?P<body>.*?)(?=\ndef |\Z)",
        dns_probe_source,
        flags=re.S,
    )
    if not dns_probe:
        fail("Could not inspect explicit DNS resolver probe")
    if "resolver_ip" not in dns_probe.group("sig"):
        fail("Explicit DNS resolver probe signature is missing resolver_ip")
    if "routing_table_id" not in dns_probe.group("sig"):
        fail("Explicit DNS resolver probe signature is missing routing_table_id")
    if "fwmark" not in dns_probe.group("sig"):
        fail("Explicit DNS resolver probe signature is missing fwmark")
    if 'f"@{resolver_ip}"' not in dns_probe.group("body"):
        fail("Explicit DNS resolver probe does not use resolver_ip in dig")
    if "type route hook output priority mangle" not in dns_probe.group("body"):
        fail("Explicit DNS resolver probe does not mark local DNS in output")
    if "meta mark set" not in dns_probe.group("body"):
        fail("Explicit DNS resolver probe does not apply fwmark")

    generic_dns_probe = re.search(
        r"def run_dns_leak_probe\((?P<sig>.*?)\):(?P<body>.*?)(?=\ndef run_explicit_resolver_probe)",
        dns_probe_source,
        flags=re.S,
    )
    if not generic_dns_probe:
        fail("Could not inspect generic DNS leak probe")
    for forbidden_name in ("resolver_ip", "routing_table_id"):
        if (
            forbidden_name in generic_dns_probe.group("sig")
            or forbidden_name in generic_dns_probe.group("body")
        ):
            fail(
                "Generic DNS leak probe contains forced-resolver-only name: "
                f"{forbidden_name}"
            )

    vpn_runtime_source = (
        ROOT / "app/services/vpn_runtime.py"
    ).read_text(encoding="utf-8")
    if 'getattr(profile, "enabled", False)' not in vpn_runtime_source:
        fail(
            "VPN runtime status must distinguish disabled disconnects "
            "from active failures"
        )

    observability_source = (
        ROOT / "app/services/observability.py"
    ).read_text(encoding="utf-8")
    for required_fragment in (
        "_dns_group_states",
        "def dns_group_state",
        "def _set_dns_group_state",
        "self.refresh_dns_group(group)",
    ):
        if required_fragment not in observability_source:
            fail(
                "Routing-group DNS observability is missing: "
                f"{required_fragment}"
            )

    routing_groups_source = (
        ROOT / "app/routing_groups.py"
    ).read_text(encoding="utf-8")
    if "observability.dns_group_state(group.id)" not in routing_groups_source:
        fail("Routing Group Health must read DNS state by routing-group ID")

    main_source = (ROOT / "app/main.py").read_text(encoding="utf-8")
    if "observability.dns_group_state(group.id)" not in main_source:
        fail("Dashboard routing snapshot must read DNS state by routing-group ID")

    for required_fragment in (
        '"expected_connected": expected_connected',
        '"runtime_state": status.state',
        'row["state"] in ("failed", "stale")',
        'row.get("expected_connected")',
        'display_state = "offline"',
    ):
        if required_fragment not in main_source:
            fail(
                "Dashboard VPN-status semantics are missing: "
                f"{required_fragment}"
            )

    if "resilience.state(" in main_source:
        fail(
            "Dashboard must not call nonexistent VPNResilienceManager.state()"
        )

    readme_lines = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    first_h2 = next((line for line in readme_lines if line.startswith("## ")), None)
    if first_h2 != "## AI-assisted development":
        fail("AI-assisted development disclosure must be the first README section")

    readme_text = "\n".join(readme_lines)
    for section in (
        "## What VPN Router does",
        "## Basic startup guide",
        "## Routing and DNS behavior",
        "## Data and backups",
        "## Multi-user self-service",
        "## VPN Profile Library",
        "## Interface appearance",
        "## Security notes",
        "## Releases and changelog",
    ):
        if section not in readme_text:
            fail(f"README.md is missing current documentation section: {section}")

    changelog_history_text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    for historical_version in (
        "1.5.2", "1.5.3", "1.5.4", "1.5.5",
        "1.5.6", "1.5.7", "1.5.8",
    ):
        if f"## {historical_version}" not in changelog_history_text:
            fail(f"CHANGELOG.md history is missing {historical_version}")

    clients_source = (ROOT / "app/clients.py").read_text(encoding="utf-8")
    for required_fragment in (
        "does not allow automatic connection",
        "Enable Allow automatic connection first.",
    ):
        if required_fragment not in clients_source:
            fail(f"Client assignment guard is missing: {required_fragment}")

    vpn_profiles_source = (ROOT / "app/vpn_profiles.py").read_text(encoding="utf-8")
    for required_fragment in (
        "consumer_counts",
        "consumer_count",
        "will remain blocked until automatic connection is allowed again",
    ):
        if required_fragment not in vpn_profiles_source:
            fail(f"Final v1.5 hardening is missing: {required_fragment}")

    migrations_source = (ROOT / "app/services/migrations.py").read_text(encoding="utf-8")
    if "CURRENT_SCHEMA_VERSION = 9" not in migrations_source:
        fail("v1.11.0 requires schema v9")
    if "temporary-routing-overrides" not in migrations_source:
        fail("v1.6.0 temporary override migration is missing")

    effective_source = (ROOT / "app/services/effective_assignments.py").read_text(encoding="utf-8")
    if "Temporary overrides take precedence" not in effective_source:
        fail("Effective-assignment override precedence is missing")

    routing_source = (ROOT / "app/services/routing.py").read_text(encoding="utf-8")
    if routing_source.count("effective_assignments(db)") < 2:
        fail("Routing rebuild/set refresh must both use effective assignments")

    on_demand_source = (ROOT / "app/services/on_demand.py").read_text(encoding="utf-8")
    if on_demand_source.count("effective_assignments(self.db)") < 2:
        fail("On-demand requirements/counts must use effective assignments")

    client_source = (ROOT / "app/clients.py").read_text(encoding="utf-8")
    for required_fragment in (
        "replacing_existing = override is not None",
        '"replaced" if replacing_existing else "started"',
        "Temporary routing override replaced",
    ):
        if required_fragment not in client_source:
            fail(f"v1.6.4 override replacement history is missing: {required_fragment}")

    for required_fragment in (
        'def set_temporary_override',
        'def cancel_temporary_override',
        'ensure_profile_ready(profile)',
        'RouteOverrideEvent',
    ):
        if required_fragment not in client_source:
            fail(f"Temporary override controller is missing: {required_fragment}")

    override_service = (ROOT / "app/services/routing_overrides.py").read_text(encoding="utf-8")
    for required_fragment in ("def expire_once", '"expired"', "RoutingEngine().apply_assignment_sets"):
        if required_fragment not in override_service:
            fail(f"Temporary override expiry handling is missing: {required_fragment}")

    clients_template = (ROOT / "app/templates/clients.html").read_text(encoding="utf-8")
    for required_fragment in (
        "selectable:",
        "unavailable_reason:",
        'group.selectable ? "" : " disabled"',
        "function formatEventAge",
        'event.event_type == "replaced"',
    ):
        if required_fragment not in clients_template:
            fail(f"v1.6.4 override UI hardening is missing: {required_fragment}")

    for required_fragment in (
        "function updateModalFromClient(client, preserveForm = false)",
        "const selectedGroup = overrideGroup.value;",
        "const selectedDuration = overrideDuration.value;",
        "updateModalFromClient(client, true);",
    ):
        if required_fragment not in clients_template:
            fail(f"v1.6.3 modal polling preservation is missing: {required_fragment}")

    if "renderEffectiveRoute(row, client)" in clients_template:
        if "function renderEffectiveRoute(row, client)" not in clients_template:
            fail(
                "Clients UI calls renderEffectiveRoute() without defining it"
            )
    for required_fragment in (
        'id="override-modal-backdrop"',
        'class="inline-button override-open"',
        'id="override-active-countdown"',
        'function formatOverrideRemaining',
        'Connecting target VPN and applying override…',
        'Cancel current override',
    ):
        if required_fragment not in clients_template:
            fail(f"v1.6.1 override modal UI is missing: {required_fragment}")

    if "override-controls" in clients_template:
        fail("Legacy always-visible override controls remain in Clients UI")

    traffic_source = (ROOT / "app/services/traffic_visibility.py").read_text(encoding="utf-8")
    if "return max(0.5, value)" not in traffic_source:
        fail("v1.7.1 traffic sampler must support the faster independent cadence")

    for required_fragment in (
        "class TrafficVisibilityService",
        "effective_assignments(self.db)",
        "def sample_once",
        "active_traffic",
        "route_source",
        "WAN fallback",
    ):
        if required_fragment not in traffic_source:
            fail(f"v1.7.0 traffic visibility is missing: {required_fragment}")

    traffic_routes = (ROOT / "app/traffic.py").read_text(encoding="utf-8")
    if 'url_prefix="/traffic"' not in traffic_routes or "def api()" not in traffic_routes:
        fail("v1.7.0 Traffic blueprint/API is missing")

    traffic_template = (ROOT / "app/templates/traffic.html").read_text(encoding="utf-8")
    if "const POLL_MS = 1000;" not in traffic_template:
        fail("v1.7.1 Traffic page must refresh its snapshot every second")

    for required_fragment in (
        "Effective route traffic",
        "Outbound VPN consumers",
        "Client traffic",
        "traffic-rx-rate",
        "traffic-vpns-body",
    ):
        if required_fragment not in traffic_template:
            fail(f"v1.7.0 Traffic UI is missing: {required_fragment}")

    init_source = (ROOT / "app/__init__.py").read_text(encoding="utf-8")
    for required_fragment in (
        "TrafficVisibilityService",
        'app.extensions["traffic_visibility"]',
        "app.register_blueprint(traffic_bp)",
    ):
        if required_fragment not in init_source:
            fail(f"v1.7.0 traffic startup integration is missing: {required_fragment}")

    runtime_source = (ROOT / "app/services/vpn_runtime.py").read_text(encoding="utf-8")
    for required_fragment in (
        'sanitized_config_path = self.runtime_dir / f"{iface}.conf"',
        '["wg-quick", "strip", str(sanitized_config_path)]',
        "sanitized_config_path.unlink(missing_ok=True)",
    ):
        if required_fragment not in runtime_source:
            fail(f"v1.8.1 WireGuard filename sanitization is missing: {required_fragment}")

    for required_fragment in (
        "def _wg_start(self, profile)",
        "wg-quick\", \"strip",
        "wg\", \"setconf",
        "def _wg_latest_handshake",
        "if profile.vpn_type == \"wireguard\":",
        "return self._wg_start(profile)",
        "return self._wg_stop(profile)",
        "waiting for WireGuard handshake",
    ):
        if required_fragment not in runtime_source:
            fail(f"v1.8.0 WireGuard runtime is missing: {required_fragment}")

    if '"wg-quick", "up"' in runtime_source:
        fail("v1.8.0 must not let wg-quick install provider default routes")

    startup_source = (ROOT / "app/services/vpn_startup.py").read_text(encoding="utf-8")
    if '("openvpn", "wireguard")' not in startup_source:
        fail("v1.8.0 startup restore does not include WireGuard")

    on_demand_source = (ROOT / "app/services/on_demand.py").read_text(encoding="utf-8")
    if 'profile.vpn_type not in ("openvpn", "wireguard")' not in on_demand_source:
        fail("v1.8.0 On-demand lifecycle does not include WireGuard")

    resilience_source = (ROOT / "app/services/vpn_resilience.py").read_text(encoding="utf-8")
    if 'profile.vpn_type not in ("openvpn", "wireguard")' not in resilience_source:
        fail("v1.8.0 resilience does not include WireGuard")

    detail_template = (ROOT / "app/templates/vpn_profiles/detail.html").read_text(encoding="utf-8")
    if "WireGuard runtime activation follows after OpenVPN" in detail_template:
        fail("v1.8.0 detail page still claims WireGuard runtime is unsupported")
    if "<h2>Runtime log</h2>" not in detail_template:
        fail("v1.8.0 VPN profile runtime log is not transport-neutral")

    preflight_source = (ROOT / "app/services/preflight.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def _verify_enabled_vpn_profiles",
        "def _wait_for_connected",
        "runtime.start(profile)",
        "runtime.exit_ip(",
        "runtime.stop(profile)",
        "started_temporarily",
        "Explicitly disabled profiles skipped:",
        "Enabled VPN profile verification",
    ):
        if required_fragment not in preflight_source:
            fail(f"v1.8.3 functional VPN preflight is missing: {required_fragment}")

    if '"warn" if not unhealthy else' in preflight_source or "Not currently connected:" in preflight_source:
        fail("v1.8.3 still contains legacy current-state-only VPN preflight logic")

    preflight_jobs_source = (ROOT / "app/services/preflight_jobs.py").read_text(encoding="utf-8")
    for required_fragment in (
        "class PreflightJobManager",
        "target=self._run",
        'name="vpn-router-preflight"',
        '"state": "running"',
        '"state": "complete"',
    ):
        if required_fragment not in preflight_jobs_source:
            fail(f"v1.8.4 asynchronous preflight manager is missing: {required_fragment}")

    diagnostics_routes = (ROOT / "app/diagnostics.py").read_text(encoding="utf-8")
    for required_fragment in (
        '@bp.post("/preflight/start")',
        '@bp.get("/preflight/status")',
        'current_app.extensions["preflight_jobs"]',
    ):
        if required_fragment not in diagnostics_routes:
            fail(f"v1.8.4 asynchronous preflight routes are missing: {required_fragment}")

    if 'run_preflight(' in diagnostics_routes:
        fail("v1.8.4 diagnostics HTTP routes must not run preflight synchronously")

    diagnostics_template = (ROOT / "app/templates/diagnostics/index.html").read_text(encoding="utf-8")
    for required_fragment in (
        "preflight_start",
        "preflight_status",
        'method: "POST"',
        '"X-CSRFToken": csrfToken',
        "window.setInterval(fetchStatus, 1000)",
        "You may leave this page and return",
        "group.effective_clients",
    ):
        if required_fragment not in diagnostics_template:
            fail(f"v1.8.4 asynchronous preflight UI is missing: {required_fragment}")

    init_source = (ROOT / "app/__init__.py").read_text(encoding="utf-8")
    if 'app.extensions["preflight_jobs"] = PreflightJobManager(app, db)' not in init_source:
        fail("v1.8.4 PreflightJobManager is not registered")

    vpn_profiles_source = (ROOT / "app/vpn_profiles.py").read_text(encoding="utf-8")
    for required_fragment in (
        "on_demand_states =",
        "manager.public_state(profile.id)",
        "on_demand_states=on_demand_states",
    ):
        if required_fragment not in vpn_profiles_source:
            fail(f"v1.8.5 On-demand list state is missing: {required_fragment}")

    vpn_index_template = (ROOT / "app/templates/vpn_profiles/index.html").read_text(encoding="utf-8")
    for required_fragment in (
        "vpn-idle-countdown",
        "Auto-stop in",
        "idle_remaining_seconds",
    ):
        if required_fragment not in vpn_index_template:
            fail(f"v1.8.5 VPN list countdown is missing: {required_fragment}")

    vpn_detail_template = (ROOT / "app/templates/vpn_profiles/detail.html").read_text(encoding="utf-8")
    for required_fragment in (
        'id="idle-countdown"',
        "data.on_demand",
        "idle_remaining_seconds",
        "Auto-stop in",
    ):
        if required_fragment not in vpn_detail_template:
            fail(f"v1.8.5 VPN detail countdown is missing: {required_fragment}")

    vpn_runtime_source = (ROOT / "app/services/vpn_runtime.py").read_text(encoding="utf-8")
    for required_fragment in (
        "Could not delete WireGuard interface",
        "still exists after stop request",
        '["ip", "link", "delete", iface]',
    ):
        if required_fragment not in vpn_runtime_source:
            fail(f"v1.8.5a WireGuard stop verification is missing: {required_fragment}")

    on_demand_source = (ROOT / "app/services/on_demand.py").read_text(encoding="utf-8")
    for required_fragment in (
        "stopped = self.runtime.status(",
        "Automatic stop failed for profile",
        "Keep the original idle timestamp",
    ):
        if required_fragment not in on_demand_source:
            fail(f"v1.8.5a On-demand stop hardening is missing: {required_fragment}")

    vpn_profiles_source = (ROOT / "app/vpn_profiles.py").read_text(encoding="utf-8")
    for required_fragment in (
        '@bp.get("/runtime-summary")',
        '"idle_remaining_seconds"',
        '"consumer_count"',
    ):
        if required_fragment not in vpn_profiles_source:
            fail(f"v1.8.5b bulk VPN runtime summary is missing: {required_fragment}")

    vpn_index_template = (ROOT / "app/templates/vpn_profiles/index.html").read_text(encoding="utf-8")
    for required_fragment in (
        "vpn_profiles.runtime_summary",
        "idle-countdown-{{ profile.id }}",
        "Auto-stop disabled",
        "setInterval(refresh, 2000)",
        "setInterval(renderAllCountdowns, 250)",
    ):
        if required_fragment not in vpn_index_template:
            fail(f"v1.8.5b live list countdown is missing: {required_fragment}")

    vpn_detail_template = (ROOT / "app/templates/vpn_profiles/detail.html").read_text(encoding="utf-8")
    for required_fragment in (
        "renderIdleCountdown",
        "idleSyncedAt",
        "setInterval(renderIdleCountdown, 250)",
    ):
        if required_fragment not in vpn_detail_template:
            fail(f"v1.8.5b live detail countdown is missing: {required_fragment}")

    vpn_index_template = (ROOT / "app/templates/vpn_profiles/index.html").read_text(encoding="utf-8")
    title_start = vpn_index_template.find("{% block title %}")
    title_end = vpn_index_template.find("{% endblock %}", title_start)
    countdown_script = vpn_index_template.find("setInterval(renderAllCountdowns, 250)")
    content_start = vpn_index_template.find("{% block content %}")
    content_end = vpn_index_template.rfind("{% endblock %}")

    if countdown_script >= 0 and title_start <= countdown_script <= title_end:
        fail("v1.8.5c countdown script is still embedded in the Jinja title block")

    if not (
        content_start >= 0
        and countdown_script > content_start
        and countdown_script < content_end
    ):
        fail("v1.8.5c countdown script is not inside the Jinja content block")

    runtime_source = (ROOT / "app/services/vpn_runtime.py").read_text(encoding="utf-8")
    if 'runtime_active = alive or (profile.vpn_type == "wireguard" and exists)' not in runtime_source:
        fail("v1.8.6 WireGuard uptime hardening is missing")

    preflight_source = (ROOT / "app/services/preflight.py").read_text(encoding="utf-8")
    preflight_jobs_source = (ROOT / "app/services/preflight_jobs.py").read_text(encoding="utf-8")
    diagnostics_template = (ROOT / "app/templates/diagnostics/index.html").read_text(encoding="utf-8")
    for fragment in ("progress_callback", '"phase": "vpn_verification"', '"current": index', '"total": total_enabled'):
        if fragment not in preflight_source:
            fail(f"v1.8.6 preflight progress is missing: {fragment}")
    if 'self._state["progress"]' not in preflight_jobs_source:
        fail("v1.8.6 preflight job progress state is missing")
    if "Verifying VPN ${progress.current} / ${progress.total}" not in diagnostics_template:
        fail("v1.8.6 preflight progress UI is missing")

    backups_source = (ROOT / "app/services/backups.py").read_text(encoding="utf-8")
    backups_routes = (ROOT / "app/backups.py").read_text(encoding="utf-8")
    for fragment in ("client_route_overrides", "ClientRouteOverride=None", 'data.setdefault("client_route_overrides", [])'):
        if fragment not in backups_source:
            fail(f"v1.8.6 route-override backup support is missing: {fragment}")
    if "ClientRouteOverride=ClientRouteOverride" not in backups_routes:
        fail("v1.8.6 backup routes do not pass ClientRouteOverride model")

    vpn_profiles_source = (ROOT / "app/vpn_profiles.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def _provider_options()",
        "def _provider_from_form()",
        '"connection_policy": request.form.get("connection_policy", "on_demand")',
        "connection_policy=policy",
        "providers=providers",
    ):
        if required_fragment not in vpn_profiles_source:
            fail(f"v1.8.7 VPN creation/provider handling is missing: {required_fragment}")

    vpn_form = (ROOT / "app/templates/vpn_profiles/form.html").read_text(encoding="utf-8")
    for required_fragment in (
        'name="provider_choice"',
        'value="__new__"',
        "+ Add New",
        'id="provider-new-wrap"',
        'name="connection_policy"',
        'value="on_demand"',
        'value="always"',
        "syncProviderInput",
    ):
        if required_fragment not in vpn_form:
            fail(f"v1.8.7 VPN form usability is missing: {required_fragment}")

    vpn_profiles_source = (ROOT / "app/vpn_profiles.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def _display_health_state(",
        '"verifying"',
        '"degraded"',
        'observability.exit_ip_state(profile.id)',
        "status(profile, include_probe=False)",
    ):
        if required_fragment not in vpn_profiles_source:
            fail(f"v1.8.7a egress health presentation is missing: {required_fragment}")

    vpn_index = (ROOT / "app/templates/vpn_profiles/index.html").read_text(encoding="utf-8")
    vpn_detail = (ROOT / "app/templates/vpn_profiles/detail.html").read_text(encoding="utf-8")
    for required_fragment in (
        "Verifying egress",
        "Degraded · no verified egress",
    ):
        if required_fragment not in vpn_index:
            fail(f"v1.8.7a VPN list health state is missing: {required_fragment}")
        if required_fragment not in vpn_detail:
            fail(f"v1.8.7a VPN detail health state is missing: {required_fragment}")

    vpn_profiles_source = (ROOT / "app/vpn_profiles.py").read_text(encoding="utf-8")
    for required_fragment in (
        "RoutingGroup",
        '"create_routing_group"',
        'fallback_mode="block"',
        'dns_mode="inherit"',
        "RoutingEngine().rebuild",
    ):
        if required_fragment not in vpn_profiles_source:
            fail(f"v1.8.8 automatic routing-group creation is missing: {required_fragment}")

    vpn_form = (ROOT / "app/templates/vpn_profiles/form.html").read_text(encoding="utf-8")
    for required_fragment in (
        'name="create_routing_group"',
        "Create matching routing group",
        "checked",
    ):
        if required_fragment not in vpn_form:
            fail(f"v1.8.8 routing-group form option is missing: {required_fragment}")

    migrations_source = (ROOT / "app/services/migrations.py").read_text(encoding="utf-8")
    if "CURRENT_SCHEMA_VERSION = 9" not in migrations_source:
        fail("v1.11.0 schema version is not v9")
    if "vpn-profile-location-intelligence" not in migrations_source:
        fail("v1.9.0 location migration is missing")

    geoip_source = (ROOT / "app/services/geoip.py").read_text(encoding="utf-8")
    for required_fragment in (
        "class GeoIPService",
        "endpoint_geoip",
        "exit_geoip",
        "def effective_location",
        "VPN_ROUTER_GEOIP_DB",
    ):
        if required_fragment not in geoip_source:
            fail(f"v1.9.0 local GeoIP service is missing: {required_fragment}")

    vpn_form = (ROOT / "app/templates/vpn_profiles/form.html").read_text(encoding="utf-8")
    for required_fragment in (
        'name="manual_country"',
        'name="manual_region"',
        'name="manual_city"',
        "Location override",
    ):
        if required_fragment not in vpn_form:
            fail(f"v1.9.0 manual location UI is missing: {required_fragment}")

    vpn_detail = (ROOT / "app/templates/vpn_profiles/detail.html").read_text(encoding="utf-8")
    for required_fragment in (
        "Effective location",
        "Automatic detection",
        "Verified exit IP · local GeoIP",
    ):
        if required_fragment not in vpn_detail:
            fail(f"v1.9.0 location detail UI is missing: {required_fragment}")

    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    if "maxminddb==3.1.1" not in requirements:
        fail("v1.9.0 maxminddb dependency is missing")

    wg_easy_source = (ROOT / "app/services/wg_easy.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def get_advertised_dns(",
        "def _extract_dns_values(",
        "/configuration",
        "/config",
    ):
        if required_fragment not in wg_easy_source:
            fail(f"v1.9.0a WG-Easy DNS inspection is missing: {required_fragment}")

    preflight_source = (ROOT / "app/services/preflight.py").read_text(encoding="utf-8")
    for required_fragment in (
        "WG-Easy client DNS compatibility",
        "IPv6 DNS resolver",
        "get_advertised_dns",
    ):
        if required_fragment not in preflight_source:
            fail(f"v1.9.0a DNS compatibility preflight is missing: {required_fragment}")

    diagnostics_source = (ROOT / "app/services/diagnostics.py").read_text(encoding="utf-8")
    for required_fragment in (
        "WG-Easy client DNS",
        "_wg_easy_dns_diagnostic",
        "ipv6_dns",
    ):
        if required_fragment not in diagnostics_source:
            fail(f"v1.9.0a DNS diagnostics are missing: {required_fragment}")

    routing_source = (ROOT / "app/services/routing.py").read_text(encoding="utf-8")
    for required_fragment in (
        "wan_hairpin_enabled",
        "wan_hairpin_public_ip",
        "def hairpin_state(",
        "_WAN_IP_CACHE_TTL = 600.0",
        "ip daddr {public_ip}",
        'mode in ("wan", "wan-fallback")',
    ):
        if required_fragment not in routing_source:
            fail(f"v1.9.0b hairpin routing is missing: {required_fragment}")

    settings_source = (ROOT / "app/services/settings.py").read_text(encoding="utf-8")
    for required_fragment in (
        "WAN_HAIRPIN_ENABLED",
        "WAN_HAIRPIN_PUBLIC_IP",
        "ipv4_optional",
    ):
        if required_fragment not in settings_source:
            fail(f"v1.9.0b hairpin setting is missing: {required_fragment}")

    diagnostics_source = (ROOT / "app/services/diagnostics.py").read_text(encoding="utf-8")
    if "Default WAN hairpin compatibility" not in diagnostics_source:
        fail("v1.9.0b hairpin diagnostics are missing")

    preflight_source = (ROOT / "app/services/preflight.py").read_text(encoding="utf-8")
    if "Default WAN hairpin compatibility" not in preflight_source:
        fail("v1.9.0b hairpin preflight is missing")

    vpn_profiles_source = (ROOT / "app/vpn_profiles.py").read_text(encoding="utf-8")
    if '"location": effective_location(' not in vpn_profiles_source:
        fail("v1.9.0c VPN profile index does not always provide location metadata")

    vpn_index = (ROOT / "app/templates/vpn_profiles/index.html").read_text(encoding="utf-8")
    for required_fragment in (
        '.get("location", {})',
        'location.get("country")',
        'location.get("source")',
    ):
        if required_fragment not in vpn_index:
            fail(f"v1.9.0c defensive location rendering is missing: {required_fragment}")

    traffic_routes = (ROOT / "app/traffic.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def _gauge_config()",
        "traffic_gauge_tx_max_mbps",
        "traffic_gauge_total_max_mbps",
        "traffic_gauge_rx_max_mbps",
        "traffic_gauges=_gauge_config()",
    ):
        if required_fragment not in traffic_routes:
            fail(f"v1.9.1 traffic gauge route/config is missing: {required_fragment}")

    traffic_template = (ROOT / "app/templates/traffic.html").read_text(encoding="utf-8")
    for required_fragment in (
        "traffic-gauge-tx",
        "traffic-gauge-total",
        "traffic-gauge-rx",
        "function gaugeRatio",
        "Math.log10(1 + mbps)",
        "traffic-redline-wobble",
        "ABSOLUTELY SENDING IT",
        "prefers-reduced-motion",
        "Number(totals.rx_rate || 0) + Number(totals.tx_rate || 0)",
    ):
        if required_fragment not in traffic_template:
            fail(f"v1.9.1 traffic gauge UI is missing: {required_fragment}")

    settings_source = (ROOT / "app/services/settings.py").read_text(encoding="utf-8")
    for required_fragment in (
        "TRAFFIC_GAUGE_TX_MAX_MBPS",
        "TRAFFIC_GAUGE_TOTAL_MAX_MBPS",
        "TRAFFIC_GAUGE_RX_MAX_MBPS",
        'section="Traffic visibility"',
    ):
        if required_fragment not in settings_source:
            fail(f"v1.9.1 traffic gauge setting is missing: {required_fragment}")

    traffic_template = (ROOT / "app/templates/traffic.html").read_text(encoding="utf-8")
    if "margin-bottom: 1rem;" not in traffic_template:
        fail("v1.9.1a traffic gauge spacing hotfix is missing")

    readme_text_current = (ROOT / "README.md").read_text(encoding="utf-8")
    if "## Release and patch history" in readme_text_current:
        fail("README still contains the legacy duplicated release history")
    for required_fragment in ("## Releases and changelog", "GitHub Releases", "CHANGELOG.md"):
        if required_fragment not in readme_text_current:
            fail(f"v1.9.2 README release navigation is missing: {required_fragment}")
    release_script = ROOT / "scripts/extract_release_notes.py"
    if not release_script.exists(): fail("v1.9.2 release-note extraction script is missing")
    publish_workflow = ROOT / ".github/workflows/publish.yml"
    publish_workflow_text = publish_workflow.read_text(encoding="utf-8")
    for required_fragment in (
        "name: Build, publish and release",
        "contents: write",
        "Read release version",
        "scripts/extract_release_notes.py",
        "Check release state",
        "Create version tag",
        "Verify existing tag points at this commit",
        "gh release create",
        "release_exists",
        "${{ steps.image.outputs.name }}:${{ steps.version.outputs.version }}",
    ):
        if required_fragment not in publish_workflow_text:
            fail(f"v1.9.2a consolidated release workflow is missing: {required_fragment}")

    if (ROOT / ".github/workflows/release.yml").exists():
        fail("v1.9.2a must not retain the dead tag-triggered release.yml workflow")

    backfill_workflow = ROOT / ".github/workflows/backfill-releases.yml"
    if not backfill_workflow.exists():
        fail("v1.9.2b historical release backfill workflow is missing")
    else:
        backfill_text = backfill_workflow.read_text(encoding="utf-8")
        for required_fragment in (
            "workflow_dispatch:",
            "dry_run:",
            "git tag --list 'v*' --sort=version:refname",
            "gh release view",
            "scripts/extract_release_notes.py",
            "historical fallback note",
            "gh release create",
            "--verify-tag",
        ):
            if required_fragment not in backfill_text:
                fail(f"v1.9.2b release backfill workflow is missing: {required_fragment}")

    publish_workflow = ROOT / ".github/workflows/publish.yml"
    publish_text = publish_workflow.read_text(encoding="utf-8")
    for required_fragment in (
        "Normalize container image name",
        "tr '[:upper:]' '[:lower:]'",
        'echo "name=ghcr.io/${repository}" >> "${GITHUB_OUTPUT}"',
        "${{ steps.image.outputs.name }}:latest",
        "${{ steps.image.outputs.name }}:${{ steps.version.outputs.version }}",
        "${{ steps.image.outputs.name }}:sha-${{ github.sha }}",
    ):
        if required_fragment not in publish_text:
            fail(f"v1.9.2c GHCR lowercase image-name fix is missing: {required_fragment}")

    if "ghcr.io/${{ github.repository }}" in publish_text:
        fail("v1.9.2c publish workflow still uses github.repository directly for GHCR tags")

    settings_source = (ROOT / "app/services/settings.py").read_text(encoding="utf-8")
    if "background_particles_enabled" not in settings_source:
        fail("v1.9.3 particle-background setting is missing")

    init_source = (ROOT / "app/__init__.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def inject_ui_preferences",
        "background_particles_enabled",
    ):
        if required_fragment not in init_source:
            fail(f"v1.9.3 global appearance preference injection is missing: {required_fragment}")

    base_template = (ROOT / "app/templates/base.html").read_text(encoding="utf-8")
    for required_fragment in (
        'id="particle-background"',
        "background_particles_enabled",
        "requestAnimationFrame(draw)",
        "LINK_DISTANCE",
        "MOUSE_RADIUS",
        'pointer-events: none',
        "prefers-reduced-motion: reduce",
        'document.addEventListener("visibilitychange"',
    ):
        if required_fragment not in base_template:
            fail(f"v1.9.3 particle background is missing: {required_fragment}")

    settings_template = (ROOT / "app/templates/settings/index.html").read_text(encoding="utf-8")
    if 'section == "Appearance"' not in settings_template:
        fail("v1.9.3 Appearance settings help text is missing")

    base_template = (ROOT / "app/templates/base.html").read_text(encoding="utf-8")
    for required_fragment in (
        'STORAGE_KEY = "vpn-router-particle-state-v1"',
        "function saveParticleState",
        "function restoreParticleState",
        "sessionStorage.setItem",
        "sessionStorage.getItem",
        'window.addEventListener("pagehide", saveParticleState',
        "window.setInterval(saveParticleState, 1000)",
        "STORAGE_MAX_AGE_MS = 15000",
        "saved.x * scaleX",
        "saved.y * scaleY",
    ):
        if required_fragment not in base_template:
            fail(f"v1.9.3a persistent particle state is missing: {required_fragment}")

    migrations_source = (ROOT / "app/services/migrations.py").read_text(encoding="utf-8")
    for required_fragment in (
        "CURRENT_SCHEMA_VERSION = 9",
        "vpn-profile-library-metadata",
        'ADD COLUMN favorite BOOLEAN NOT NULL DEFAULT 0',
        "ADD COLUMN tags TEXT",
    ):
        if required_fragment not in migrations_source:
            fail(f"v1.10.0 profile-library migration is missing: {required_fragment}")

    models_source = (ROOT / "app/models.py").read_text(encoding="utf-8")
    for required_fragment in (
        "favorite = db.Column",
        "tags = db.Column",
        "def tag_list",
    ):
        if required_fragment not in models_source:
            fail(f"v1.10.0 profile-library model support is missing: {required_fragment}")

    vpn_profiles_source = (ROOT / "app/vpn_profiles.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def _normalize_tags",
        "def _unique_profile_name",
        '@bp.post("/bulk")',
        'def bulk_import()',
        "request.files.getlist(\"configs\")",
        "Imported VPN",
        "profile.favorite",
    ):
        if required_fragment not in vpn_profiles_source:
            fail(f"v1.10.0 profile-library controller is missing: {required_fragment}")

    vpn_index = (ROOT / "app/templates/vpn_profiles/index.html").read_text(encoding="utf-8")
    for required_fragment in (
        "VPN Profile Library",
        'id="library-search"',
        'id="filter-provider"',
        'id="filter-country"',
        'id="filter-region"',
        'id="filter-protocol"',
        'id="filter-tag"',
        'id="filter-favourite"',
        'id="library-sort"',
        'id="select-visible"',
        'name="profile_ids"',
        "function applyLibrary",
    ):
        if required_fragment not in vpn_index:
            fail(f"v1.10.0 profile-library UI is missing: {required_fragment}")

    import_template = (ROOT / "app/templates/vpn_profiles/import.html").read_text(encoding="utf-8")
    for required_fragment in (
        "Bulk import VPN profiles",
        'name="configs"',
        "multiple",
        'name="create_routing_groups"',
        "Shared OpenVPN credentials",
    ):
        if required_fragment not in import_template:
            fail(f"v1.10.0 bulk-import UI is missing: {required_fragment}")

    backups_source = (ROOT / "app/services/backups.py").read_text(encoding="utf-8")
    for required_fragment in (
        '"favorite": bool(p.favorite)',
        '"tags": p.tags',
        "favorite=bool(row.get(\"favorite\", False))",
        'tags=row.get("tags")',
    ):
        if required_fragment not in backups_source:
            fail(f"v1.10.0 profile-library backup support is missing: {required_fragment}")

    vpn_index = (ROOT / "app/templates/vpn_profiles/index.html").read_text(encoding="utf-8")
    for required_fragment in (
        "bulk-action-grid",
        "bulk-select-cell",
        'id="select-visible"',
        "bulk-selected-count",
    ):
        if required_fragment not in vpn_index:
            fail(f"v1.10.1 bulk-actions alignment is missing: {required_fragment}")

    routing_index = (ROOT / "app/templates/routing_groups/index.html").read_text(encoding="utf-8")
    for required_fragment in (
        '<details class="card routing-group-card">',
        '<summary class="routing-group-summary">',
        "routing-group-chevron",
        "Configured exit",
        "Effective exit",
        "routing-group-details",
    ):
        if required_fragment not in routing_index:
            fail(f"v1.10.1 collapsed routing-group UI is missing: {required_fragment}")

    if '<details class="card routing-group-card" open>' in routing_index:
        fail("v1.10.1 routing groups must default collapsed")

    routing_index = (ROOT / "app/templates/routing_groups/index.html").read_text(encoding="utf-8")
    for required_fragment in (
        ".routing-group-status",
        "width:7.4rem",
        "text-align:left",
        'status-good routing-group-status',
        'status-warn routing-group-status',
        'status-bad routing-group-status',
    ):
        if required_fragment not in routing_index:
            fail(f"v1.10.1a routing-group status alignment fix is missing: {required_fragment}")

    migrations_source = (ROOT / "app/services/migrations.py").read_text(encoding="utf-8")
    for required_fragment in (
        "CURRENT_SCHEMA_VERSION = 9",
        "user-client-self-service",
        "UPDATE users SET is_admin = 1",
        "CREATE TABLE IF NOT EXISTS user_client_access",
    ):
        if required_fragment not in migrations_source:
            fail(f"v1.11.0 multi-user migration is missing: {required_fragment}")

    models_source = (ROOT / "app/models.py").read_text(encoding="utf-8")
    for required_fragment in (
        "is_admin = db.Column",
        "class UserClientAccess",
        'db.ForeignKey("users.id")',
    ):
        if required_fragment not in models_source:
            fail(f"v1.11.0 user model support is missing: {required_fragment}")

    users_source = (ROOT / "app/users.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def admin_required",
        "def create",
        "def update",
        "def ownership",
        "Client ownership is only needed for self-service users.",
    ):
        if required_fragment not in users_source:
            fail(f"v1.11.0 user administration is missing: {required_fragment}")

    clients_source = (ROOT / "app/clients.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def _owned_external_ids",
        "def _can_access_client",
        "You do not have access to this WG-Easy client.",
        "UserClientAccess.user_id == current_user.id",
    ):
        if required_fragment not in clients_source:
            fail(f"v1.11.0 client ownership enforcement is missing: {required_fragment}")

    init_source = (ROOT / "app/__init__.py").read_text(encoding="utf-8")
    for required_fragment in (
        "def enforce_user_scope",
        'request.blueprint in {"auth", "clients"}',
        "app.register_blueprint(users_bp)",
    ):
        if required_fragment not in init_source:
            fail(f"v1.11.0 global self-service scope is missing: {required_fragment}")

    users_template = (ROOT / "app/templates/users/index.html").read_text(encoding="utf-8")
    for required_fragment in (
        "Users & client access",
        "WG-Easy client ownership",
        'name="user_id"',
    ):
        if required_fragment not in users_template:
            fail(f"v1.11.0 Users UI is missing: {required_fragment}")

    base_template = (ROOT / "app/templates/base.html").read_text(encoding="utf-8")
    for required_fragment in (
        "viewport-fit=cover",
        "env(safe-area-inset-top)",
        "min-height: 44px",
        "-webkit-overflow-scrolling: touch",
    ):
        if required_fragment not in base_template:
            fail(f"v1.11.1 global mobile support is missing: {required_fragment}")

    clients_template = (ROOT / "app/templates/clients.html").read_text(encoding="utf-8")
    for required_fragment in (
        "clients-table",
        "client-primary",
        'data-label="Permanent route"',
        'data-label="Effective route"',
        'data-label="Temporary override"',
        "#override-modal-backdrop",
        "align-items: flex-end",
        "92dvh",
    ):
        if required_fragment not in clients_template:
            fail(f"v1.11.1 mobile My VPN UI is missing: {required_fragment}")

    users_template = (ROOT / "app/templates/users/index.html").read_text(encoding="utf-8")
    if "user-inline-form" not in users_template or "ownership-inline-form" not in users_template:
        fail("v1.11.1 mobile Users forms are missing")

    clients_template = (ROOT / "app/templates/clients.html").read_text(encoding="utf-8")
    for required_fragment in (
        "mobile-collapsed",
        "client-primary-summary",
        "client-card-chevron",
        "function bindClientCardToggle",
        "function refreshClientCardSummary",
        'aria-expanded="false"',
        'event.key !== "Enter"',
    ):
        if required_fragment not in clients_template:
            fail(f"v1.11.1a collapsible mobile client cards are missing: {required_fragment}")

    changelog_text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {version}" not in changelog_text:
        fail(f"CHANGELOG.md has no section for {version}")

    if not (ROOT / "CHANGELOG.md").is_file():
        fail("CHANGELOG.md is missing")
    if not (ROOT / "RELEASE_CHECKLIST.md").is_file():
        fail("RELEASE_CHECKLIST.md is missing")

    print(f"Release validation passed for v{version}.")


if __name__ == "__main__":
    main()
