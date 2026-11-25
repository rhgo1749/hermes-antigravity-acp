"""Dynamic model discovery for the MCP profile (backlog item 3, fail-closed picker).

The picker must show ONLY the signed-in account's live ``session/new`` rows; the static fallback list is
intentionally empty (a wrong id costs a -32602 and a silent fallback turn — the gemini-4-* incident).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp-mcp"
FAKE_AGY = str(ROOT / "tests" / "design_c" / "fake_agy.py")


def _load_entry(monkeypatch):
    registered = []

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = registered.append
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)

    pkg_name = "antigravity_acp_mcp"
    if pkg_name not in sys.modules:
        pkg = types.ModuleType(pkg_name)
        pkg.__file__ = str(PLUGIN_DIR / "__init__.py")
        pkg.__path__ = [str(PLUGIN_DIR)]
        pkg.__package__ = pkg_name
        monkeypatch.setitem(sys.modules, pkg_name, pkg)

    name = f"{pkg_name}._plugin_entry"
    monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location(name, PLUGIN_DIR / "_plugin_entry.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    assert registered == [module.antigravity_acp_mcp]
    return module


def _profile(monkeypatch, behaviour: dict):
    module = _load_entry(monkeypatch)
    for var in ("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", "HERMES_ANTIGRAVITY_ACP_COMMAND"):
        monkeypatch.delenv(var, raising=False)
    profile = module.antigravity_acp_mcp
    monkeypatch.setattr(profile, "process_command", sys.executable)
    monkeypatch.setattr(profile, "process_args", [FAKE_AGY, json.dumps(behaviour)])
    return profile


def test_static_fallback_is_empty():
    # The picker floor incident: an unverified static list must never return.
    source = (PLUGIN_DIR / "_plugin_entry.py").read_text(encoding="utf-8")
    assert "fallback_models=()," in source


def test_discovery_returns_live_server_rows(monkeypatch):
    profile = _profile(monkeypatch, {"available_models": [
        {"modelId": "gemini-3.8-flash", "name": "Gemini 3.8 Flash"},
        {"modelId": "duplicated", "name": "duplicated"},
        {"modelId": ""},
        {"modelId": "duplicated"},
    ]})
    rows = profile.discover_models()
    assert [r["id"] for r in rows] == ["gemini-3.8-flash", "duplicated"]
    assert rows[0]["label"] == "Gemini 3.8 Flash" and "label" not in rows[1]
    assert profile.fetch_models() == ["gemini-3.8-flash", "duplicated"]


def test_discovery_fails_closed_without_models(monkeypatch):
    profile = _profile(monkeypatch, {})  # fake answers session/new with no models surface
    assert profile.discover_models() is None
    assert profile.fetch_models() is None


def test_discovery_fails_closed_on_dead_command(monkeypatch):
    profile = _profile(monkeypatch, {})
    monkeypatch.setattr(profile, "process_args", ["/nonexistent/fake-agy.py", "{}"])
    assert profile.discover_models() is None
    assert profile.fetch_models() is None


def test_fresh_cache_answers_without_a_second_spawn(monkeypatch):
    profile = _profile(monkeypatch, {"available_models": [{"modelId": "m-one"}]})
    first = profile.discover_models()
    monkeypatch.setattr(profile, "process_command", "/nonexistent/would-fail")
    assert profile.discover_models() == first  # served from cache, no respawn
