"""Provider-profile and standalone-client regression tests."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = (
    Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"
)
PLUGIN_SOURCE = (PLUGIN_DIR / "__init__.py").read_text(encoding="utf-8")
CLIENT_SOURCE = (PLUGIN_DIR / "client.py").read_text(encoding="utf-8")


def test_process_args_pin_official_wrapper_contract() -> None:
    assert "process_args=_STORED_PROCESS_ARGS," in PLUGIN_SOURCE
    assert "_STORED_PROCESS_COMMAND or _default_official_command()" in PLUGIN_SOURCE
    assert 'process_args=("--uid=",)' not in PLUGIN_SOURCE
    assert '"antigravity-acp-mux"' not in PLUGIN_SOURCE


def test_provider_label_does_not_imply_official_hermes_tier(monkeypatch) -> None:
    profile = _load_plugin(monkeypatch).antigravity_acp
    assert profile.display_name == "Antigravity ACP"
    assert "Google's official ACP" in profile.description
    assert "antigravity-official-acp" in profile.aliases


def test_picker_has_no_hardcoded_model_floor() -> None:
    # Dynamic-listing contract (operator directive 2026-11-09): every offered
    # model id must come from the signed-in account's live server surfaces.
    assert 'fallback_models=("antigravity-acp",)' not in PLUGIN_SOURCE
    assert "fallback_models=_PICKER_FALLBACK_MODELS," not in PLUGIN_SOURCE
    assert "fallback_models=()," in PLUGIN_SOURCE
    assert "_PICKER_FALLBACK_MODELS" not in PLUGIN_SOURCE


def test_profile_offers_no_models_without_a_live_surface(monkeypatch) -> None:
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp
    assert profile.fallback_models == ()

    class DeadClient:
        def session_model_surface(self, **_):
            raise RuntimeError("session/new failed: code=-32000; Authentication required")

        def close(self):
            pass

    monkeypatch.setattr(profile, "create_client", lambda **kw: DeadClient())
    assert profile.discover_models() is None
    assert profile.fetch_models() is None


def _surface_client(config_entries, legacy_entries):
    class SurfaceClient:
        def session_model_surface(self, **_):
            return config_entries, legacy_entries

        def close(self):
            pass

    return SurfaceClient()


def test_discover_models_uses_only_server_authored_rows(monkeypatch) -> None:
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp
    client = _surface_client(
        [
            {"value": "server-model-a", "name": "Server Model A"},
            {"value": "server-model-b", "_meta": {"copilotEnablement": "disabled"}},
        ],
        [
            {"modelId": "server-model-c", "name": "server-model-c"},
            {"modelId": "server-model-a"},
        ],
    )
    monkeypatch.setattr(profile, "create_client", lambda **kw: client)
    rows = profile.discover_models()
    ids = [row["id"] for row in rows]
    # deduped, disabled filtered, labels only when the server authored a
    # distinct name, and never a curated constant.
    assert ids == ["server-model-a", "server-model-c"]
    assert rows[0]["label"] == "Server Model A"
    assert "label" not in rows[1]
    assert "gemini-3.8-flash-high" not in ids or all(
        row["id"] in {"server-model-a", "server-model-c"} for row in rows
    )


def test_setup_status_reports_live_login_boundary(monkeypatch, tmp_path) -> None:
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp

    launcher = tmp_path / "antigravity-acp-official"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(profile, "process_command", str(launcher))

    class BoundaryClient:
        def list_models(self, **_):
            raise RuntimeError("Antigravity ACP session/new failed: code=-32000; Authentication required")

        def close(self):
            pass

    monkeypatch.setattr(profile, "create_client", lambda **kw: BoundaryClient())
    status = profile.setup_status()
    assert status["available"] is True
    assert status["logged_in"] is False
    assert "Not signed in" in status["detail"]
    assert status["login_command"][0]
    assert status["login_command"][1].endswith("login.py")

    class LoggedInClient:
        def list_models(self, **_):
            return ["server-model-a"]

        def close(self):
            pass

    monkeypatch.setattr(profile, "create_client", lambda **kw: LoggedInClient())
    status = profile.setup_status()
    assert status["available"] is True
    assert status["logged_in"] is True


def test_setup_status_fails_closed_on_unknown_probe_error(monkeypatch, tmp_path) -> None:
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp
    launcher = tmp_path / "antigravity-acp-official"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(profile, "process_command", str(launcher))

    class BrokenClient:
        def list_models(self, **_):
            raise RuntimeError("Antigravity ACP session/new failed: code=-32603; boom")

        def close(self):
            pass

    monkeypatch.setattr(profile, "create_client", lambda **kw: BrokenClient())
    status = profile.setup_status()
    assert status["logged_in"] is False
    assert "did not answer a status probe" in status["detail"]


def test_setup_status_marks_missing_install_unavailable(monkeypatch) -> None:
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp
    monkeypatch.setattr(profile, "process_command", "/nonexistent/antigravity-acp-official")
    status = profile.setup_status()
    assert status["available"] is False
    assert status["logged_in"] is False
    assert "not been installed" in status["detail"]


def test_setup_status_accepts_path_named_launcher(monkeypatch, tmp_path) -> None:
    """Production launches a mux CLI by bare name (``antigravity-acp-mux``).

    A PATH/user-local-bin name is exactly as installed as an absolute path —
    Hermes' own external-process evidence rule resolves it the same way. The
    regression this guards: ``available`` used to require ``isfile(command)``
    and reported a live production install as "not installed", which made
    Core's external-process setup flow refuse the provider entirely.
    """
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp
    launcher = tmp_path / ".local" / "bin" / "antigravity-acp-mux"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(module.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(profile, "process_command", "antigravity-acp-mux")

    class LoggedInClient:
        def list_models(self, **_):
            return ["server-model-a"]

        def close(self):
            pass

    monkeypatch.setattr(profile, "create_client", lambda **kw: LoggedInClient())
    status = profile.setup_status()
    assert status["available"] is True
    assert status["logged_in"] is True


def test_profile_declares_exact_gemini_vision_capability(monkeypatch) -> None:
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp
    assert profile.supports_vision is True
    assert profile.supports_vision_tool_messages is True
    # Capability gating is profile-level only: with a live-only model list, a
    # per-id capabilities map would be a curated model id in disguise. The
    # shipped source must never pass model_capabilities, whatever the host
    # ProviderProfile default happens to be.
    source = (PLUGIN_DIR / "__init__.py").read_text(encoding="utf-8")
    assert "model_capabilities" not in source


def test_plugin_no_longer_depends_on_hermes_copilot_client() -> None:
    assert "from agent.copilot_acp_client" not in PLUGIN_SOURCE
    assert "from agent.copilot_acp_client" not in CLIENT_SOURCE
    assert "import agent.copilot_acp_client" not in CLIENT_SOURCE
    assert "class AntigravityACPClient" in CLIENT_SOURCE


def _load_plugin(monkeypatch):
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

    module_name = "antigravity_acp_plugin_test"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            monkeypatch.delitem(sys.modules, name, raising=False)

    path = PLUGIN_DIR / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        module_name,
        path,
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    assert registered == [module.antigravity_acp]
    return module


def test_profile_builds_standalone_client_without_core_acp_module(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delitem(sys.modules, "agent.copilot_acp_client", raising=False)
    module = _load_plugin(monkeypatch)

    client = module.antigravity_acp.create_client()

    assert client.__class__.__name__ == "AntigravityACPClient"
    assert client.HERMES_SKIP_TRANSPORT_WRAP is True
    assert client.HERMES_SKIP_ASYNC_WRAP is True
    assert client._acp_command == "antigravity-acp-official"
    assert client._acp_args == []


def test_profile_preserves_legacy_provider_aliases(monkeypatch) -> None:
    module = _load_plugin(monkeypatch)
    assert "antigravity-cli" in module.antigravity_acp.aliases
    assert "agy" in module.antigravity_acp.aliases
    assert "antigravity" in module.antigravity_acp.aliases


def test_create_client_repairs_falsy_runtime_launch_metadata(monkeypatch) -> None:
    module = _load_plugin(monkeypatch)
    client = module.antigravity_acp.create_client(command=None, args=[], base_url=None)

    assert client._acp_command == module.antigravity_acp.process_command
    assert client._acp_args == list(module.antigravity_acp.process_args)
    assert client.base_url == module.antigravity_acp.base_url


def test_create_client_preserves_nonempty_launch_overrides(monkeypatch) -> None:
    module = _load_plugin(monkeypatch)
    client = module.antigravity_acp.create_client(
        command="custom-acp", args=["--custom"], base_url="acp://custom"
    )

    assert client._acp_command == "custom-acp"
    assert client._acp_args == ["--custom"]
    assert client.base_url == "acp://custom"


def test_rate_limit_retry_reopens_session_until_success(monkeypatch) -> None:
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_RATE_LIMIT_RETRIES", raising=False)
    module = _load_plugin(monkeypatch)
    client = module.antigravity_acp.create_client()
    calls = []

    def fake_once(prompt_text, **kwargs):
        calls.append((prompt_text, kwargs.get("resume_session_id")))
        if len(calls) < 3:
            raise RuntimeError("ACP session/prompt failed: 429 RESOURCE_EXHAUSTED")
        if kwargs["session_result"] is not None:
            kwargs["session_result"].update(session_id="s-ok", resumed=False)
        return "ok", ""

    monkeypatch.setattr(client, "_run_prompt_once", fake_once)

    assert client._run_prompt("hello", timeout_seconds=10) == ("ok", "")
    assert len(calls) == 3


def test_auth_error_reopens_session_until_success(monkeypatch) -> None:
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_RATE_LIMIT_RETRIES", raising=False)
    module = _load_plugin(monkeypatch)
    client = module.antigravity_acp.create_client()
    calls = 0

    def fake_once(prompt_text, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("ACP session/new failed: Authentication required")
        return "ok", ""

    monkeypatch.setattr(client, "_run_prompt_once", fake_once)

    assert client._run_prompt("hello", timeout_seconds=10) == ("ok", "")
    assert calls == 2


def test_non_failover_error_is_not_retried(monkeypatch) -> None:
    module = _load_plugin(monkeypatch)
    client = module.antigravity_acp.create_client()
    calls = 0

    def fake_once(prompt_text, **kwargs):
        nonlocal calls
        calls += 1
        raise RuntimeError("ACP session/prompt failed: invalid model")

    monkeypatch.setattr(client, "_run_prompt_once", fake_once)

    with pytest.raises(RuntimeError, match="invalid model"):
        client._run_prompt("hello", timeout_seconds=10)
    assert calls == 1


def test_rate_limit_retry_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_RATE_LIMIT_RETRIES", "0")
    module = _load_plugin(monkeypatch)
    client = module.antigravity_acp.create_client()
    calls = 0

    def fake_once(prompt_text, **kwargs):
        nonlocal calls
        calls += 1
        raise RuntimeError("too many requests (429)")

    monkeypatch.setattr(client, "_run_prompt_once", fake_once)

    with pytest.raises(RuntimeError, match="429"):
        client._run_prompt("hello", timeout_seconds=10)
    assert calls == 1


def test_status_and_models_cache_server_probes(monkeypatch, tmp_path) -> None:
    """Cold-start regression: a signed-in probe and a live model surface are
    reused within their TTL instead of respawning the official server on
    every status render and every ``/model`` open. On Windows each spawn
    pays a full cold start of the official binary through a cmd.exe wrapper,
    which stalled the CLI between commands and froze ``/model``."""
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp
    launcher = tmp_path / "antigravity-acp-official"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(profile, "process_command", str(launcher))

    spawns = {"count": 0}

    class LiveClient:
        def __init__(self) -> None:
            spawns["count"] += 1

        def list_models(self, **_):
            return ["server-model-a"]

        def session_model_surface(self, **_):
            return ([{"value": "server-model-a", "name": "Server Model A"}], [])

        def close(self):
            pass

    monkeypatch.setattr(profile, "create_client", lambda **kw: LiveClient())

    assert profile.setup_status()["logged_in"] is True
    assert profile.setup_status()["logged_in"] is True
    assert spawns["count"] == 1

    rows = profile.discover_models()
    assert [row["id"] for row in rows] == ["server-model-a"]
    assert profile.fetch_models() == ["server-model-a"]
    # One surface spawn answers discover_models and fetch_models.
    assert spawns["count"] == 2


def test_negative_login_probe_is_never_cached(monkeypatch, tmp_path) -> None:
    """A not-signed-in answer must re-probe: the setup wizard re-checks
    seconds after an interactive login and must not read a stale False."""
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp
    launcher = tmp_path / "antigravity-acp-official"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(profile, "process_command", str(launcher))

    spawns = {"count": 0}

    class BoundaryClient:
        def __init__(self) -> None:
            spawns["count"] += 1

        def list_models(self, **_):
            raise RuntimeError(
                "Antigravity ACP session/new failed: code=-32000; Authentication required"
            )

        def close(self):
            pass

    monkeypatch.setattr(profile, "create_client", lambda **kw: BoundaryClient())
    assert profile.setup_status()["logged_in"] is False
    assert profile.setup_status()["logged_in"] is False
    assert spawns["count"] == 2


def test_probe_and_discovery_budgets_survive_slow_spawns(monkeypatch, tmp_path) -> None:
    """Windows ARM64 cold-spawn regression: Defender scans each fresh server
    process, so the first probe can exceed the old 20s/25s hard budgets. That
    produced a false "did not answer a status probe" and "Login failed" even
    immediately after a successful interactive login. The budgets must be
    generous by default and env-overridable."""
    module = _load_plugin(monkeypatch)
    profile = module.antigravity_acp
    launcher = tmp_path / "antigravity-acp-official"
    launcher.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setattr(profile, "process_command", str(launcher))

    budgets = {}

    class BudgetClient:
        def list_models(self, *, timeout_seconds):
            budgets["probe"] = timeout_seconds
            return ["server-model-a"]

        def session_model_surface(self, *, timeout_seconds):
            budgets["discovery"] = timeout_seconds
            return ([{"value": "server-model-a", "name": "Server Model A"}], [])

        def close(self):
            pass

    monkeypatch.setattr(profile, "create_client", lambda **kw: BudgetClient())

    assert profile.setup_status()["logged_in"] is True
    assert profile.discover_models() is not None
    assert budgets["probe"] >= 60.0
    assert budgets["discovery"] >= 60.0

    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_PROBE_TIMEOUT_SECONDS", "120")
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_DISCOVERY_TIMEOUT_SECONDS", "90")
    profile._login_probe_cache = None
    profile._models_cache = None
    assert profile.setup_status()["logged_in"] is True
    assert profile.discover_models() is not None
    assert budgets["probe"] == 120.0
    assert budgets["discovery"] == 90.0

    # Junk or non-positive overrides must not shrink the budget below default.
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_PROBE_TIMEOUT_SECONDS", "nonsense")
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_DISCOVERY_TIMEOUT_SECONDS", "-5")
    profile._login_probe_cache = None
    profile._models_cache = None
    assert profile.setup_status()["logged_in"] is True
    assert profile.discover_models() is not None
    assert budgets["probe"] == 60.0
    assert budgets["discovery"] == 60.0
