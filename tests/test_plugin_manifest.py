"""Static consistency tests for the plugin manifest (catalog admission mirror).

These run in the credential-free CI job with only the standard library:
the authoritative YAML parse and capability probe belong to
`hermes plugins validate`, which the upstream-hermes-compat and
catalog-floor-gate CI jobs run against official Hermes checkouts.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parents[1] / "hermes-plugin" / "antigravity-acp"
MANIFEST = PLUGIN_DIR / "plugin.yaml"

# The declared compatibility floor. It is proven by the catalog-floor-gate CI
# job (official `plugins validate` + strict seam tests at the pinned Hermes
# tag). Moving this constant without moving the CI pin and plugin.yaml in the
# same change is a contract break and must fail here.
DECLARED_FLOOR = (0, 21, 6)
FLOOR_SPEC = ">=0.21.6"


def _flat_manifest() -> dict[str, str]:
    """Parse the manifest's flat ``key: value`` pairs without a YAML library.

    The manifest is intentionally flat scalars/lists; nested structures would
    be a manifest-contract change and the format guard below rejects them.
    """
    entries: dict[str, str] = {}
    for raw in MANIFEST.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith((" ", "\t", "-")):
            raise AssertionError(f"nested manifest line is out of contract: {raw!r}")
        key, sep, value = raw.partition(":")
        assert sep, f"manifest line is not a key/value pair: {raw!r}"
        entries[key.strip()] = value.strip()
    return entries


def test_manifest_required_identity_fields() -> None:
    entries = _flat_manifest()
    for key in ("name", "kind", "version", "description", "author"):
        assert entries.get(key), f"manifest must declare {key}"
    assert entries["kind"] == "model-provider"
    assert re.fullmatch(r"\d+\.\d+\.\d+", entries["version"].strip("\"'")), (
        "plugin version must be a plain SemVer release"
    )


def test_requires_hermes_floor_is_the_proven_spec() -> None:
    entries = _flat_manifest()
    spec = entries.get("requires_hermes", "").strip().strip("\"'")
    match = re.fullmatch(r">=(\d+)\.(\d+)\.(\d+)", spec)
    assert match, f"requires_hermes must be a SemVer floor, got {spec!r}"
    assert tuple(int(part) for part in match.groups()) == DECLARED_FLOOR, (
        "requires_hermes floor moved without updating the CI-proven constant"
    )
    assert spec == FLOOR_SPEC


def test_declared_surface_is_explicitly_empty_lists() -> None:
    entries = _flat_manifest()
    for key in (
        "provides_tools",
        "provides_hooks",
        "provides_middleware",
        "requires_env",
        "python_dependencies",
    ):
        assert key in entries, f"manifest must explicitly declare {key} (truthy-empty)"
        assert entries[key] == "[]", f"{key} must stay [] while the plugin is provider-only"


def test_plugin_registers_only_a_provider() -> None:
    """The empty provides_* lists are only truthful if no other register_* runs."""
    registered: set[str] = set()
    for source in sorted(PLUGIN_DIR.glob("*.py")):
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if isinstance(name, str) and name.startswith("register_"):
                registered.add(name)
    assert registered == {"register_provider"}, (
        "plugin registration surface changed; update plugin.yaml declares and "
        f"this test together, found: {sorted(registered)}"
    )


def test_no_secret_environment_reads_outside_declared_surface() -> None:
    """requires_env is []: the plugin must not read API-key style environment
    variables. Only the documented HERMES_ANTIGRAVITY_ACP_* operational
    overrides and Hermes' own session/home markers are allowed.

    Known guard limit (by design): environment names computed at runtime
    (variables, f-strings, loops) are invisible to this literal scan. The
    authoritative capability check is the official validate capability probe
    in the upstream-hermes-compat and catalog-floor-gate CI jobs.
    """
    allowed_prefixes = ("HERMES_ANTIGRAVITY_ACP_",)
    allowed_exact = {
        "HERMES_SESSION_ID",
        "HERMES_SESSION_KEY",
        "HERMES_CRON_SESSION",
        "HERMES_HOME",
        "HOME",
    }
    offenders: set[str] = set()
    for source in sorted(PLUGIN_DIR.glob("*.py")):
        text = source.read_text(encoding="utf-8")
        for literal in re.findall(r"""environ\.get\(\s*["']([A-Z0-9_]+)["']""", text):
            if not (
                literal.startswith(allowed_prefixes) or literal in allowed_exact
            ):
                offenders.add(f"{source.name}:{literal}")
    assert not offenders, f"undeclared environment reads (declare or remove): {sorted(offenders)}"
