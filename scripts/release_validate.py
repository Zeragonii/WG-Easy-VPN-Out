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
