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
    if 'f"@{resolver_ip}"' not in dns_probe.group("body"):
        fail("Explicit DNS resolver probe does not use resolver_ip in dig")

    readme_lines = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
    first_h2 = next((line for line in readme_lines if line.startswith("## ")), None)
    if first_h2 != "## AI-assisted development":
        fail("AI-assisted development disclosure must be the first README section")

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
