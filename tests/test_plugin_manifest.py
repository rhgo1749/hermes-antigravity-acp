"""Static consistency tests for the plugin manifest (catalog admission mirror).

These run in the credential-free CI job with only the standard library:
the authoritative YAML parse and capability probe belong to
`hermes plugins validate`, which the upstream-hermes-compat and
catalog-floor-gate CI jobs run against official Hermes checkouts.
"""

from __future__ import annotations

import ast
import re
import unittest
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


# --- hermes_compat.py core-import inventory (issue #12) ---------------------- (reworked after review)
# docs/hermes-compatibility.md (module dependency register + Public API
# promotion record, 2026-11-12) is the register; this test is its BLOCKING
# enforcer in the credential-free lane. The upstream `hermes plugins validate`
# Rule 9 warning is advisory (the validator exits 0 with warnings), so the
# warning existing is NOT a gate — this inventory is what fails CI.
#
# Hermes-owned namespaces: snapshot of the two official Core definitions
# (`plugin_validate_private_imports._hermes_packages` and
# `plugin_validate_core_override._hermes_top_level`), taken as the union over
# the audited refs v0.21.6, v0.23.0, v0.23.1, main@67664e23 on 2026-11-12,
# plus the two newly reported root modules at main@422ad186 on 2026-11-14.
# The credential-free lane has no Core checkout, so the sync check lives in
# tests/test_upstream_hermes_runtime_contracts.py: in both upstream CI lanes
# the installed Core's own namespaces must stay inside this snapshot. A new
# upstream namespace turns that lane RED until snapshot + register move
# together. Names upstream later drops stay in the snapshot (superset filter;
# this scan targets one plugin file with no third-party name collisions).

HERMES_TOP_LEVEL_SNAPSHOT = frozenset({
    "acp_adapter", "agent", "batch_runner", "cli",
    "cron", "evals", "gateway", "hermes_agent",
    "hermes_bootstrap", "hermes_cli", "hermes_constants", "hermes_constants_scratch",
    "hermes_constants_scratch_detach", "hermes_constants_scratch_stuck", "hermes_dir_acl", "hermes_logging",
    "hermes_platform", "hermes_plugins", "hermes_scope", "hermes_startup_watchdog",
    "hermes_state", "hermes_state_api_content", "hermes_state_common", "hermes_state_compaction_display",
    "hermes_state_compression", "hermes_state_coverage", "hermes_state_dbfile", "hermes_state_delegate_children",
    "hermes_state_detached_results", "hermes_state_errors", "hermes_state_fts", "hermes_state_gateway",
    "hermes_state_guard", "hermes_state_health", "hermes_state_holders", "hermes_state_identity",
    "hermes_state_ids", "hermes_state_keys", "hermes_state_legacy_refusal", "hermes_state_local",
    "hermes_state_local_lineage", "hermes_state_local_migration", "hermes_state_lockguard", "hermes_state_lockowners",
    "hermes_state_loop_guard",
    "hermes_state_maintenance", "hermes_state_media", "hermes_state_messages", "hermes_state_mutation_binding",
    "hermes_state_mutation_branch", "hermes_state_mutation_chat_pick", "hermes_state_mutation_compress", "hermes_state_mutation_guards",
    "hermes_state_mutation_prepared", "hermes_state_mutation_reset", "hermes_state_mutation_retirement", "hermes_state_mutation_transcript",
    "hermes_state_mutations", "hermes_state_pidns", "hermes_state_portability", "hermes_state_profile_repair",
    "hermes_state_prompt_refresh", "hermes_state_prune_rewrite", "hermes_state_readpool", "hermes_state_reconcile",
    "hermes_state_registry", "hermes_state_repair", "hermes_state_rewind", "hermes_state_runtime",
    "hermes_state_runtime_workers", "hermes_state_schema", "hermes_state_search", "hermes_state_session_list",
    "hermes_state_sessions", "hermes_state_sessions_model_config", "hermes_state_stored_reads", "hermes_state_telegram",
    "hermes_state_terminal", "hermes_state_timeline", "hermes_state_titles", "hermes_state_todo",
    "hermes_state_tool_retries", "hermes_state_usage", "hermes_state_user_copy", "hermes_state_wal",
    "hermes_state_worker_compression", "hermes_state_worker_context", "hermes_state_worker_lifecycle", "hermes_state_write",
    "hermes_time",
    "hermes_yaml", "mcp_serve", "mini_swe_runner", "model_tools",
    "plugins", "pm", "providers", "registration_lifecycle",
    "run_agent", "tests", "tools", "toolset_distributions",
    "toolsets", "trajectory_compressor", "tui_gateway", "utils",
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

DOCUMENTED_CORE_IMPORTS = PUBLIC_CORE_IMPORTS | PRIVATE_CORE_IMPORTS


def _assert_namespace_snapshot_covers(name, namespaces, snapshot) -> None:
    """Same fail-closed predicate for real Core and credential-free regressions."""
    unknown = namespaces - snapshot
    assert not unknown, (
        f"official Core {name} reports top-level namespaces outside the "
        f"credential-free snapshot: {sorted(unknown)}"
    )


def _core_import_targets(source: str) -> set[str]:
    """Hermes-core import targets in ``source``, mirroring the official
    validator's ``_imported()`` semantics: ``import a.b`` (target ``a.b``),
    non-relative ``from a import b`` (target ``a.b``), and string-literal
    ``importlib.import_module("a")`` / ``import_module("a")`` calls (target
    ``a``).

    Deliberate deviations from the official pass, both tightening-only and
    intentional (review requirement 6):
    - imports under ``if TYPE_CHECKING:`` are counted here; the official pass
      exempts them. A type-only core import still couples this plugin to the
      core module path and belongs in the register.
    - the official pass drops imports whose path resolves to one of the
      plugin's own modules (``_is_own_module_path``). This scan targets one
      plugin file and skips relative imports (``level > 0``), so a plugin-own
      module cannot appear under a Hermes top-level name; if that ever
      changes the exact inventory fails loudly instead of silently filing it
      as core.
    - the official pass treats a module-level catalog entry as allowing any
      non-underscore name in it; this inventory is exact per symbol, which is
      stricter by design.

    Documented static-analysis boundary (shared with the official pass):
    computed module names (f-strings, variables, loops) are invisible to AST
    scanning. This gate covers literal import spellings only; the
    upstream-hermes-compat ``hermes plugins validate`` run remains the
    advisory full-surface oracle, never the blocker.
    """
    targets: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            targets |= {
                alias.name for alias in node.names
                if alias.name.split(".")[0] in HERMES_TOP_LEVEL_SNAPSHOT
            }
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            if node.module.split(".")[0] in HERMES_TOP_LEVEL_SNAPSHOT:
                targets |= {f"{node.module}.{alias.name}" for alias in node.names}
        elif (
            isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and ast.unparse(node.func) in ("importlib.import_module", "import_module")
        ):
            module = node.args[0].value
            if module.split(".")[0] in HERMES_TOP_LEVEL_SNAPSHOT:
                targets.add(module)
    return targets


def _snippet(tmp_path, text: str) -> str:
    """Isolated temp-file source for the negative regressions (the production
    plugin file is never modified by these tests)."""
    path = tmp_path / "injected_surface.py"
    path.write_text(text, encoding="utf-8")
    return path.read_text(encoding="utf-8")


def test_hermes_compat_core_import_surface_is_the_documented_inventory() -> None:
    found = _core_import_targets((PLUGIN_DIR / "hermes_compat.py").read_text(encoding="utf-8"))
    assert found == DOCUMENTED_CORE_IMPORTS, (
        "hermes_compat.py core imports drifted from the "
        "docs/hermes-compatibility.md register; "
        f"unregistered: {sorted(found - DOCUMENTED_CORE_IMPORTS)}, "
        f"no longer imported: {sorted(DOCUMENTED_CORE_IMPORTS - found)}"
    )


def test_inventory_flags_unregistered_core_namespace_import(tmp_path) -> None:
    found = _core_import_targets(_snippet(tmp_path, "import hermes_state\n"))
    extra, _missing = found - DOCUMENTED_CORE_IMPORTS, DOCUMENTED_CORE_IMPORTS - found
    assert extra == {"hermes_state"}, (
        f"an unregistered `import hermes_state` must be an inventory violation, got extra={sorted(extra)}"
    )


def test_namespace_snapshot_covers_new_official_core_modules() -> None:
    _assert_namespace_snapshot_covers(
        "verified main@422ad186 root modules",
        {"hermes_state_loop_guard", "hermes_state_write"},
        HERMES_TOP_LEVEL_SNAPSHOT,
    )


def test_namespace_snapshot_rejects_omitted_or_future_core_modules() -> None:
    for name in ("hermes_state_loop_guard", "hermes_state_write"):
        with unittest.TestCase().assertRaisesRegex(AssertionError, name):
            _assert_namespace_snapshot_covers(
                "omitted module control", {name}, HERMES_TOP_LEVEL_SNAPSHOT - {name}
            )
    with unittest.TestCase().assertRaisesRegex(AssertionError, "hermes_future_unregistered"):
        _assert_namespace_snapshot_covers(
            "future namespace control", {"hermes_future_unregistered"}, HERMES_TOP_LEVEL_SNAPSHOT
        )


def test_new_namespace_imports_are_not_new_registered_dependencies() -> None:
    names = {"hermes_state_loop_guard", "hermes_state_write"}
    found = _core_import_targets("\n".join(f"import {name}" for name in sorted(names)))
    assert found == names
    assert found - DOCUMENTED_CORE_IMPORTS == names


def test_inventory_flags_dynamic_core_import(tmp_path) -> None:
    source = _snippet(
        tmp_path,
        "import importlib\n"
        "from importlib import import_module\n"
        'importlib.import_module("agent.file_safety")\n'
        'import_module("cron.execution_identity")\n',
    )
    found = _core_import_targets(source)
    assert found == {"agent.file_safety", "cron.execution_identity"}, (
        f"string-literal dynamic core imports must be inventoried as bare modules, got {sorted(found)}"
    )
    assert found - DOCUMENTED_CORE_IMPORTS == found, (
        "dynamic core imports outside the documented register must never pass as registered"
    )


def test_inventory_flags_unregistered_from_import(tmp_path) -> None:
    found = _core_import_targets(_snippet(tmp_path, "from cron import execution_identity\n"))
    assert found == {"cron.execution_identity"}
    assert found - DOCUMENTED_CORE_IMPORTS == found


def test_inventory_accepts_registered_import_spellings(tmp_path) -> None:
    source = _snippet(
        tmp_path,
        "from agent.file_safety import get_read_block_error\n"
        "from agent.redact import redact_sensitive_text\n"
        "from gateway.session_context import get_session_env\n",
    )
    found = _core_import_targets(source)
    assert found <= DOCUMENTED_CORE_IMPORTS, (
        f"registered import spellings must never be flagged, got {sorted(found - DOCUMENTED_CORE_IMPORTS)}"
    )


def test_inventory_flags_removed_registered_import(tmp_path) -> None:
    production = (PLUGIN_DIR / "hermes_compat.py").read_text(encoding="utf-8")
    removed = production.replace(
        "        from agent.delegation_context import is_delegated_child_context as resolve_child\n",
        "        pass  # registered import removed by this fixture\n",
    )
    assert removed != production, "the fixture anchor moved; update this test with the source"
    found = _core_import_targets(_snippet(tmp_path, removed))
    missing = DOCUMENTED_CORE_IMPORTS - found
    assert missing == {"agent.delegation_context.is_delegated_child_context"}, (
        f"dropping a registered core import must fail the exact inventory, missing={sorted(missing)}"
    )


def test_inventory_ignores_relative_plugin_imports(tmp_path) -> None:
    source = _snippet(tmp_path, "from . import client\nfrom .bridge import x\n")
    assert _core_import_targets(source) == set(), (
        "relative plugin-own imports must never be classified as core imports"
    )
