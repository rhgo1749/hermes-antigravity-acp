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


# --- hermes_compat.py core-import inventory (issue #12) ----------------------
# docs/hermes-compatibility.md (module dependency register + Public API
# promotion record, 2026-11-12) is the register; this test is its enforcer in
# the credential-free lane. The PRIVATE set is the documented fail-closed
# allowlist of imports with NO published plugin-API route as of the 2026-11-12
# audit (upstream main 67664e236d); adding an entry means a new private
# dependency, a register row, and a fail-closed contract — all in one change.
# Removing an entry (upstream promotion, or a migration) must land with the
# register update too: this inventory is exact, not a ceiling.

_HERMES_TOP_LEVEL = frozenset({
    "agent", "gateway", "hermes_cli", "hermes_constants", "plugins",
    "providers", "tools", "utils",
})

# module.name pairs hermes_compat.py imports from Hermes core that the
# official plugin-API catalog (hermes_cli/data/plugin_api.json) lists, with
# the release the listing first shipped in.
PUBLIC_CORE_IMPORTS = frozenset({
    "hermes_constants.get_hermes_home",            # module-level entry, all refs
    "hermes_constants.apply_subprocess_home_env",  # module-level entry, all refs
    "gateway.session_context.get_session_env",     # per-symbol entry, all refs
    "agent.runtime_cwd.resolve_agent_cwd",         # per-symbol entry, all refs
    "agent.redact.redact_sensitive_text",          # catalog since v0.23.1 (upstream 79109635df)
    "agent.file_safety.get_read_block_error",      # catalog on main (upstream 9788899694)
})

# Deliberate private dependencies kept for their fail-closed security
# contracts; see the register rows for the consequence when one is missing.
PRIVATE_CORE_IMPORTS = frozenset({
    "tools.environments.local.hermes_subprocess_env",
    "agent.delegation_context.is_delegated_child_context",
    "tools.skill_provenance.get_current_write_origin",
    "agent.file_safety.get_nt_namespace_error",
})


def _core_import_targets(path: Path) -> set[str]:
    """Every ``module.name`` (or bare ``module``) Hermes import the AST sees."""
    targets: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            targets |= {
                alias.name for alias in node.names
                if alias.name.split(".")[0] in _HERMES_TOP_LEVEL
            }
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in _HERMES_TOP_LEVEL:
                targets |= {f"{node.module}.{alias.name}" for alias in node.names}
    return targets


def test_hermes_compat_core_import_surface_is_the_documented_inventory() -> None:
    found = _core_import_targets(PLUGIN_DIR / "hermes_compat.py")
    documented = PUBLIC_CORE_IMPORTS | PRIVATE_CORE_IMPORTS
    assert found == documented, (
        "hermes_compat.py core imports drifted from the "
        "docs/hermes-compatibility.md register; "
        f"unregistered: {sorted(found - documented)}, "
        f"no longer imported: {sorted(documented - found)}"
    )
