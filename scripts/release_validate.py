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
        "## Security notes",
        "## Release and patch history",
    ):
        if section not in readme_text:
            fail(f"README.md is missing current documentation section: {section}")

    for historical_version in (
        "v1.5.2", "v1.5.3", "v1.5.4", "v1.5.5",
        "v1.5.6", "v1.5.7", "v1.5.8",
    ):
        if f"## {historical_version}" not in readme_text:
            fail(f"README.md patch history is missing {historical_version}")

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
