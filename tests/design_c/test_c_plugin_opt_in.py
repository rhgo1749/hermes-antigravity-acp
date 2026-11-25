"""Single-plugin dual-engine registration contract.

The Parked-MCP engine (``parked/``) and the Replay engine (flat modules) ship
in ONE plugin tree.  A default install CREATES exactly one provider profile,
``antigravity-acp`` (default, Parked-MCP); the historical
``antigravity-acp-mcp``/``agy-mcp`` ids are aliases on it (resolution without
creation).  ``antigravity-acp-replay`` (Replay) registers only when the
installer-written ``launch_config.json`` declares it in ``extra_providers``.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import re
import shutil
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from ._support import PLUGIN_DIR, ROOT

MANIFEST = ROOT / "hermes-plugin" / "antigravity-acp" / "plugin.yaml"
DEFAULT_PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"
AUDIT_SCRIPT = ROOT / "scripts" / "audit_public_tree.py"


def _flat_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith((" ", "\t", "-")):
            raise AssertionError(f"nested manifest line is out of contract: {raw!r}")
        key, sep, value = raw.partition(":")
        assert sep, f"manifest line is not a key/value pair: {raw!r}"
        entries[key.strip()] = value.strip()
    return entries


def _load_audit_module() -> types.ModuleType:
    name = "_design_c_audit_public_tree"
    spec = importlib.util.spec_from_file_location(name, AUDIT_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


def _load_isolated_plugin(package_name: str, plugin_dir: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(
        package_name,
        plugin_dir / "__init__.py",
        submodule_search_locations=[str(plugin_dir)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[package_name] = module
    spec.loader.exec_module(module)
    return module


def test_manifest_is_flat_valid_and_provider_only() -> None:
    entries = _flat_manifest(MANIFEST)
    assert entries["name"] == "antigravity-acp-provider"
    assert entries["kind"] == "model-provider"
    assert re.fullmatch(r"\d+\.\d+\.\d+", entries["version"].strip("\"'"))
    assert entries["description"]
    assert entries["author"]
    assert entries["requires_hermes"].strip("\"'") == ">=0.21.6"
    for key in (
        "provides_tools",
        "provides_hooks",
        "provides_middleware",
        "requires_env",
        "python_dependencies",
    ):
        assert entries.get(key) == "[]", f"{key} must stay [] for a provider-only plugin"


def test_parked_engine_registers_only_providers() -> None:
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
    assert registered == {"register_provider"}


def test_parked_engine_env_reads_stay_within_declared_surface() -> None:
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
            if not (literal.startswith(allowed_prefixes) or literal in allowed_exact):
                offenders.add(f"{source.name}:{literal}")
    assert not offenders, f"undeclared environment reads: {sorted(offenders)}"


def test_parked_tree_passes_public_hygiene_scan() -> None:
    audit = _load_audit_module()
    forbidden_mux = "antigravity-acp-" + "file-mux"
    files = [
        path
        for path in sorted(PLUGIN_DIR.rglob("*"))
        if path.is_file() and "__pycache__" not in path.relative_to(PLUGIN_DIR).parts
    ]
    assert len(files) == 12  # 10 engine modules + shared usage contract + package marker
    for path in files:
        text = path.read_text(encoding="utf-8")
        assert audit.scan_text(text) == [], f"secret rule triggered in {path.name}"
        for token in audit.PERSONAL_OPS_TOKENS:
            assert token not in text, f"personal-ops token in {path.name}"
        assert forbidden_mux not in text, f"personal mux reference in {path.name}"


def test_default_install_creates_one_profile_with_compat_aliases(monkeypatch) -> None:
    original_pkg = sys.modules.get("antigravity_acp_mcp")
    registered: list[Any] = []

    class StubProviderProfile:
        def __init__(self, **kwargs: Any) -> None:
            for key, value in kwargs.items():
                setattr(self, key, value)

    providers_mod = types.ModuleType("providers")
    providers_mod.register_provider = registered.append  # type: ignore[attr-defined]
    providers_base_mod = types.ModuleType("providers.base")
    providers_base_mod.ProviderProfile = StubProviderProfile  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "providers", providers_mod)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base_mod)

    acp_pkg = "_isolated_default_acp"
    try:
        _load_isolated_plugin(acp_pkg, DEFAULT_PLUGIN_DIR)

        assert sys.modules.get("antigravity_acp_mcp") is original_pkg
        assert [profile.name for profile in registered] == ["antigravity-acp"]
        default = registered[0]

        # The public default identity is the Parked-MCP engine; the historical
        # aliases followed it, and the compatibility ids are aliases too
        # (resolution without separately-created providers).
        assert set(default.aliases) == {
            "antigravity-cli",
            "agy",
            "antigravity",
            "agy-acp",
            "antigravity-official-acp",
            "antigravity-acp-mcp",
            "agy-mcp",
        }
        assert default.base_url == "acp://antigravity"
        assert default.fallback_models == ()
        assert default.supports_vision is True
        assert default.auth_type == "external_process"

        # Replay stays explicitly selectable (never a silent fallback), but
        # without an install-time declaration it is built, not registered.
        replay = getattr(sys.modules[acp_pkg], "antigravity_acp_replay")
        assert replay.name == "antigravity-acp-replay"
        assert set(replay.aliases) == {"agy-replay", "antigravity-replay"}

        # Engine identity surfaces are pairwise disjoint: no name or alias
        # may resolve to two engines.
        surfaces = [{profile.name, *profile.aliases} for profile in (*registered, replay)]
        for i in range(len(surfaces)):
            for j in range(i + 1, len(surfaces)):
                assert surfaces[i].isdisjoint(surfaces[j]), (i, j)

        # Runtime command precedence on the DEFAULT profile:
        # MCP_COMMAND > ACP_COMMAND > profile.process_command; explicit wins.
        monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", raising=False)
        monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_COMMAND", raising=False)
        default.process_command = "/profile/official-launcher"
        assert default.create_client()._command == "/profile/official-launcher"

        monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_COMMAND", "/env/shared-launcher")
        assert default.create_client()._command == "/env/shared-launcher"

        monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", "/env/mcp-launcher")
        assert default.create_client()._command == "/env/mcp-launcher"

        assert default.create_client(command="/explicit/launcher")._command == "/explicit/launcher"

        # Effort mapping through build_api_kwargs_extras.
        assert default.build_api_kwargs_extras(reasoning_config=None) == ({}, {})
        assert default.build_api_kwargs_extras(
            reasoning_config={"enabled": False, "effort": "high"}
        ) == ({}, {"reasoning_effort": "none"})
        assert default.build_api_kwargs_extras(
            reasoning_config={"enabled": True, "effort": "xhigh"}
        ) == ({}, {"reasoning_effort": "xhigh"})
        assert default.build_api_kwargs_extras(reasoning_config={}) == ({}, {})
    finally:
        for mod_name in list(sys.modules):
            if mod_name == acp_pkg or mod_name.startswith(acp_pkg + "."):
                sys.modules.pop(mod_name, None)


def _load_plugin_from_copy(
    monkeypatch, tmp_path: Path, config: dict[str, Any] | None, package_name: str
) -> list[Any]:
    """Import a copy of the plugin tree with an installer-written launch config."""
    plugin_dir = tmp_path / "plugin"
    shutil.copytree(DEFAULT_PLUGIN_DIR, plugin_dir, ignore=shutil.ignore_patterns("__pycache__"))
    if config is not None:
        (plugin_dir / "launch_config.json").write_text(
            json.dumps(config, sort_keys=True), encoding="utf-8"
        )
    registered: list[Any] = []

    class StubProviderProfile:
        def __init__(self, **kwargs: Any) -> None:
            for key, value in kwargs.items():
                setattr(self, key, value)

    providers_mod = types.ModuleType("providers")
    providers_mod.register_provider = registered.append  # type: ignore[attr-defined]
    providers_base_mod = types.ModuleType("providers.base")
    providers_base_mod.ProviderProfile = StubProviderProfile  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "providers", providers_mod)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base_mod)

    try:
        _load_isolated_plugin(package_name, plugin_dir)
    except BaseException:
        sys.modules.pop(package_name, None)
        raise
    return registered


def test_replay_registers_only_under_explicit_declaration(monkeypatch, tmp_path) -> None:
    registered = _load_plugin_from_copy(
        monkeypatch,
        tmp_path,
        {"extra_providers": ["antigravity-acp-replay"]},
        "_isolated_declared_acp",
    )
    try:
        assert [profile.name for profile in registered] == [
            "antigravity-acp-replay",
            "antigravity-acp",
        ]
    finally:
        sys.modules.pop("_isolated_declared_acp", None)


def test_legacy_launch_config_still_launches_default_only(monkeypatch, tmp_path) -> None:
    registered = _load_plugin_from_copy(
        monkeypatch,
        tmp_path,
        {"process_command": "/legacy/launcher", "process_args": ["--pin"]},
        "_isolated_legacy_acp",
    )
    try:
        assert [profile.name for profile in registered] == ["antigravity-acp"]
        assert registered[0].process_command == "/legacy/launcher"
        assert registered[0].process_args == ("--pin",)
    finally:
        sys.modules.pop("_isolated_legacy_acp", None)


@pytest.mark.parametrize(
    "config",
    [
        # An alias id is not a creatable provider.
        {"extra_providers": ["antigravity-acp-mcp"]},
        {"extra_providers": ["not-a-provider"]},
        {"unknown_key": []},
    ],
)
def test_launch_config_fails_closed(monkeypatch, tmp_path, config) -> None:
    with pytest.raises(RuntimeError):
        _load_plugin_from_copy(monkeypatch, tmp_path, config, "_isolated_bad_acp")


def test_default_official_command_prefers_user_bin_then_path_then_name(monkeypatch, tmp_path) -> None:
    from antigravity_acp_mcp import client as c

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setattr(c.shutil, "which", lambda _name: None)
    launcher_name = "antigravity-acp-official.cmd" if c.os.name == "nt" else "antigravity-acp-official"
    assert c._default_official_command() == launcher_name

    monkeypatch.setattr(c.shutil, "which", lambda name: f"/usr/local/bin/{name}")
    assert c._default_official_command() == f"/usr/local/bin/{launcher_name}"

    local_bin = tmp_path / ".local" / "bin"
    local_bin.mkdir(parents=True)
    launcher = local_bin / launcher_name
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    assert c._default_official_command() == str(launcher)
