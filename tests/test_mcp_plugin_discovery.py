"""Dynamic model discovery for the MCP profile (backlog item 3, fail-closed picker).

The picker must show ONLY the signed-in account's live ``session/new`` rows; the static fallback list is
intentionally empty (a wrong id costs a -32602 and a silent fallback turn — the gemini-4-* incident).
Fixtures use synthetic model ids per AGENTS.md; real catalog names never appear as fixture values.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp" / "parked"
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
    # Registration is explicit since 0.9.0: importing has no side effects.
    assert registered == []
    default, compat = module.register_parked_profiles()
    assert [p.name for p in registered] == ["antigravity-acp", "antigravity-acp-mcp"]
    return module, default, compat


def _profile(monkeypatch, behaviour: dict):
    module, default, _compat = _load_entry(monkeypatch)
    for var in ("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", "HERMES_ANTIGRAVITY_ACP_COMMAND"):
        monkeypatch.delenv(var, raising=False)
    profile = default
    monkeypatch.setattr(profile, "process_command", sys.executable)
    monkeypatch.setattr(profile, "process_args", [FAKE_AGY, json.dumps(behaviour)])
    return profile


def _events(log_path: Path):
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_static_fallback_is_empty():
    # The picker floor incident: an unverified static list must never return.
    source = (PLUGIN_DIR / "_plugin_entry.py").read_text(encoding="utf-8")
    assert "fallback_models=()," in source


def test_discovery_returns_live_server_rows(monkeypatch):
    profile = _profile(monkeypatch, {"available_models": [
        {"modelId": "fake-model-a", "name": "Fake Model A"},
        {"modelId": "fake-model-b-high", "name": "fake-model-b-high"},
        {"modelId": ""},
        {"modelId": "fake-model-b-high"},
    ]})
    rows = profile.discover_models()
    assert [r["id"] for r in rows] == ["fake-model-a", "fake-model-b-high"]
    assert rows[0]["label"] == "Fake Model A" and "label" not in rows[1]
    assert profile.fetch_models() == ["fake-model-a", "fake-model-b-high"]


def test_discovery_skips_malformed_rows(monkeypatch):
    """A server row that is not an object (or carries a non-string id) is skipped, never crashes the picker."""
    profile = _profile(monkeypatch, {"available_models": [
        "just-a-string", None, 42,
        {"modelId": {"nested": "object"}},          # non-scalar id: never str()-ified into the picker
        {"modelId": "fake-model-ok"},
    ]})
    rows = profile.discover_models()
    ids = [r["id"] for r in rows]
    assert ids == ["fake-model-ok"]  # only a real string id survives; str()-ified junk is never offered


def test_discovery_fails_closed_without_models(monkeypatch):
    profile = _profile(monkeypatch, {})  # fake answers session/new with no models surface
    assert profile.discover_models() is None
    assert profile.fetch_models() is None


def test_discovery_fails_closed_on_dead_command(monkeypatch):
    profile = _profile(monkeypatch, {})
    monkeypatch.setattr(profile, "process_args", ["/nonexistent/fake-agy.py", "{}"])
    assert profile.discover_models() is None
    assert profile.fetch_models() is None


def test_fresh_cache_answers_without_a_second_spawn(monkeypatch, tmp_path):
    log_path = tmp_path / "fake.log"
    profile = _profile(monkeypatch, {"available_models": [{"modelId": "fake-model-one"}], "log": str(log_path)})
    first = profile.discover_models()
    second = profile.discover_models()
    assert second == first
    assert sum(1 for e in _events(log_path) if e.get("ev") == "new") == 1  # served from cache


def test_launcher_change_invalidates_the_cache(monkeypatch):
    profile = _profile(monkeypatch, {"available_models": [{"modelId": "fake-model-one"}]})
    first = profile.discover_models()
    assert first is not None
    # Repointing the launcher must re-probe, not serve the old launcher's surface.
    monkeypatch.setattr(profile, "process_command", "/nonexistent/would-fail")
    assert profile.discover_models() is None


def test_discovery_closes_the_probe_session(monkeypatch, tmp_path):
    """The session/new used for discovery is closed per ACP v1 before the child is reaped."""
    log_path = tmp_path / "fake.log"
    profile = _profile(monkeypatch, {"available_models": [{"modelId": "fake-model-one"}],
                                     "session_close": True, "log": str(log_path)})
    assert profile.discover_models() is not None
    events = _events(log_path)
    assert any(e.get("ev") == "new" for e in events)
    assert any(e.get("ev") == "close_session" for e in events)


def test_ttl_override_is_sane(monkeypatch):
    module, _default, _compat = _load_entry(monkeypatch)
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS", raising=False)
    assert module._discovery_ttl() == module._DISCOVERY_TTL_DEFAULT_SECONDS
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS", "not-a-number")
    assert module._discovery_ttl() == module._DISCOVERY_TTL_DEFAULT_SECONDS
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS", "-5")
    assert module._discovery_ttl() == module._DISCOVERY_TTL_DEFAULT_SECONDS
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS", "nan")
    assert module._discovery_ttl() == module._DISCOVERY_TTL_DEFAULT_SECONDS
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS", "999999999")
    assert module._discovery_ttl() == module._DISCOVERY_TTL_MAX_SECONDS
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS", "30")
    assert module._discovery_ttl() == 30.0
