"""Failure and fallback contracts for the Hermes compatibility boundary."""

from __future__ import annotations

import importlib
import subprocess
import sys
import types
from pathlib import Path

import pytest

from test_standalone_client import _load


def _compat(monkeypatch):
    _, _, client_module = _load(monkeypatch)
    return client_module, importlib.import_module(f"{client_module.__package__}.hermes_compat")


def _host_tools_package(monkeypatch, subprocess_env):
    tools_package = types.ModuleType("tools")
    tools_package.__path__ = []
    environments_package = types.ModuleType("tools.environments")
    environments_package.__path__ = []
    local_module = types.ModuleType("tools.environments.local")
    setattr(local_module, "hermes_subprocess_env", subprocess_env)
    monkeypatch.setitem(sys.modules, "tools", tools_package)
    monkeypatch.setitem(sys.modules, "tools.environments", environments_package)
    monkeypatch.setitem(sys.modules, "tools.environments.local", local_module)


def test_home_adapter_prefers_hermes_resolver_and_uses_explicit_home_fallback(
    monkeypatch, tmp_path
):
    _, compat = _compat(monkeypatch)
    hermes_home = tmp_path / "profiles" / "coder"
    fallback_home = tmp_path / "fallback"
    constants = types.ModuleType("hermes_constants")
    setattr(constants, "get_hermes_home", lambda: hermes_home)
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)
    assert compat.get_hermes_home() == hermes_home

    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    monkeypatch.setenv("HERMES_HOME", str(fallback_home))
    assert compat.get_hermes_home() == fallback_home


def test_active_home_resolver_failure_is_not_hidden_by_default_home(monkeypatch, tmp_path):
    _, compat = _compat(monkeypatch)
    constants = types.ModuleType("hermes_constants")

    def fail_resolving_home():
        raise RuntimeError("context-local home resolver failed")

    setattr(constants, "get_hermes_home", fail_resolving_home)
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)
    monkeypatch.delenv("HERMES_HOME", raising=False)

    with pytest.raises(RuntimeError, match="context-local home resolver failed"):
        compat.get_hermes_home()


def test_missing_home_resolver_in_hermes_runtime_fails_closed(monkeypatch):
    _, compat = _compat(monkeypatch)
    fake_agent = types.ModuleType("agent")
    fake_agent.__path__ = []
    monkeypatch.setitem(sys.modules, "agent", fake_agent)
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    monkeypatch.delenv("HERMES_HOME", raising=False)

    with pytest.raises(RuntimeError, match="active home cannot be resolved"):
        compat.get_hermes_home()


def _fake_session_context(monkeypatch, *, engaged=None, env_values=None):
    gateway_package = types.ModuleType("gateway")
    gateway_package.__path__ = []
    session_context = types.ModuleType("gateway.session_context")
    values = env_values or {}
    setattr(session_context, "get_session_env", lambda name, default="": values.get(name, default))
    if engaged is not None:
        setattr(session_context, "session_context_engaged", lambda: engaged)
    setattr(gateway_package, "session_context", session_context)
    monkeypatch.setitem(sys.modules, "gateway", gateway_package)
    monkeypatch.setitem(sys.modules, "gateway.session_context", session_context)


def test_cron_style_scope_without_session_ids_fails_closed_on_cwd_api_loss(monkeypatch):
    _, compat = _compat(monkeypatch)
    # Cron binds a job workdir with empty session key/id but engages the
    # upstream session-context latch (set_session_vars).
    _fake_session_context(monkeypatch, engaged=True, env_values={
        "HERMES_SESSION_KEY": "", "HERMES_SESSION_ID": "", "HERMES_CRON_SESSION": "1",
    })
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    monkeypatch.delenv("HERMES_SESSION_KEY", raising=False)
    monkeypatch.setitem(sys.modules, "agent.runtime_cwd", None)

    with pytest.raises(RuntimeError, match="session-scoped workspace is unavailable"):
        compat.resolve_agent_cwd()


def test_runtime_cwd_call_failure_never_falls_back_to_process_cwd(monkeypatch):
    _, compat = _compat(monkeypatch)
    runtime_cwd_module = types.ModuleType("agent.runtime_cwd")

    def fail_resolve():
        raise RuntimeError("simulated resolver crash")

    setattr(runtime_cwd_module, "resolve_agent_cwd", fail_resolve)
    agent_package = types.ModuleType("agent")
    agent_package.__path__ = []
    setattr(agent_package, "runtime_cwd", runtime_cwd_module)
    monkeypatch.setitem(sys.modules, "agent", agent_package)
    monkeypatch.setitem(sys.modules, "agent.runtime_cwd", runtime_cwd_module)

    with pytest.raises(RuntimeError, match="workspace lookup failed"):
        compat.resolve_agent_cwd()


def test_unbound_hermes_process_keeps_launch_cwd_fallback_on_cwd_api_loss(monkeypatch):
    _, compat = _compat(monkeypatch)
    # A Hermes process that never bound a task scope (latch False, no ids): the
    # launch-directory fallback matches upstream CLI semantics and stays intact.
    _fake_session_context(monkeypatch, engaged=False, env_values={
        "HERMES_SESSION_KEY": "", "HERMES_SESSION_ID": "",
    })
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    monkeypatch.delenv("HERMES_SESSION_KEY", raising=False)
    monkeypatch.setitem(sys.modules, "agent.runtime_cwd", None)
    assert compat.resolve_agent_cwd() is None


def test_video_cache_fallback_requires_an_explicit_home(monkeypatch):
    _, compat = _compat(monkeypatch)
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.delenv("HOME", raising=False)
    assert compat.get_hermes_home_for_video() is None

    monkeypatch.setenv("HOME", "/profile/home")
    assert compat.get_hermes_home_for_video() == Path("/profile/home/.hermes")

    monkeypatch.setenv("HERMES_HOME", "$HOME/selected-profile")
    assert compat.get_hermes_home_for_video() == Path("/profile/home/selected-profile")


def test_missing_session_and_optional_context_apis_fall_back_without_cross_imports(
    monkeypatch, tmp_path
):
    client_module, compat = _compat(monkeypatch)
    monkeypatch.setitem(sys.modules, "gateway.session_context", None)
    monkeypatch.setitem(sys.modules, "tools.skill_provenance", None)
    monkeypatch.setitem(sys.modules, "agent.runtime_cwd", None)
    monkeypatch.setenv("HERMES_SESSION_ID", "explicit-session-id")
    monkeypatch.setenv("HERMES_SESSION_KEY", "explicit-session-key")
    tools_package = types.ModuleType("tools")
    tools_package.__path__ = []
    monkeypatch.setitem(sys.modules, "tools", tools_package)

    assert compat.get_runtime_session_env() == (
        "explicit-session-id",
        "explicit-session-key",
    )
    with pytest.raises(RuntimeError, match="write-origin context is unavailable"):
        compat.get_current_write_origin()
    monkeypatch.delitem(sys.modules, "tools")
    assert compat.resolve_agent_cwd() is None

    monkeypatch.chdir(tmp_path)
    assert client_module._resolve_acp_working_directory(None) == str(tmp_path.resolve())


def test_write_origin_without_a_hermes_tools_package_uses_standalone_lane(monkeypatch):
    _, compat = _compat(monkeypatch)
    monkeypatch.delitem(sys.modules, "tools", raising=False)
    monkeypatch.setitem(sys.modules, "tools.skill_provenance", None)

    assert compat.get_current_write_origin() == "foreground"


def test_subprocess_environment_uses_host_policy_when_available(monkeypatch):
    client_module, _ = _compat(monkeypatch)
    tools_local = types.ModuleType("tools.environments.local")
    calls = []
    profile_home = "/profile/alpha"

    def hermes_subprocess_env(*, inherit_credentials):
        calls.append(inherit_credentials)
        return {
            "PATH": "/bin",
            "HOME": "/old-home",
            "SAFE_PROFILE_VALUE": "kept",
            "OPENAI_API_KEY": "synthetic-openai-value-not-a-key",
        }

    setattr(tools_local, "hermes_subprocess_env", hermes_subprocess_env)
    constants = types.ModuleType("hermes_constants")
    applied = []
    setattr(constants, "get_hermes_home", lambda: profile_home)

    def apply_home_policy(env):
        applied.append(env["HOME"])
        env["TMPDIR"] = "/profile/scratch"

    setattr(constants, "apply_subprocess_home_env", apply_home_policy)
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)
    monkeypatch.setitem(sys.modules, "tools.environments.local", tools_local)

    env = client_module._build_subprocess_env()

    assert calls == [True]
    assert applied == [env["HOME"]]
    assert env["TMPDIR"] == "/profile/scratch"
    assert env["PATH"] == "/bin"
    # historical reference: a successful host policy is the base, not the contract. The
    # ACP minimum environment filter narrows even a returned provider
    # credential and any unlisted profile value out before spawn.
    assert "SAFE_PROFILE_VALUE" not in env
    assert "OPENAI_API_KEY" not in env
    assert env["HOME"] != "/old-home"


def test_subprocess_environment_fallback_is_allowlisted(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    monkeypatch.setitem(sys.modules, "tools.environments.local", None)
    monkeypatch.setenv("PATH", "/bin")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("GEMINI_HOME", str(tmp_path / "gemini"))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "credential-value-must-not-leak")
    monkeypatch.setenv("UNLISTED_ACP_SECRET", "credential-value-must-not-leak")

    env = client_module._build_subprocess_env()

    assert env["PATH"] == "/bin"
    assert env["GEMINI_HOME"] == str(tmp_path / "gemini")
    assert "ANTHROPIC_API_KEY" not in env
    assert "UNLISTED_ACP_SECRET" not in env
    assert "credential-value-must-not-leak" not in env.values()


def test_host_profile_home_fallback_keeps_home_policy_and_allowlist(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    profile_home = tmp_path / "profiles" / "worker"
    monkeypatch.setenv("HOME", str(tmp_path / "host-home"))
    monkeypatch.setenv("HERMES_HOME", str(profile_home))
    monkeypatch.setenv("UNLISTED_SECRET", "must-not-leak")
    monkeypatch.setitem(sys.modules, "tools.environments.local", None)

    applied = []
    constants = types.ModuleType("hermes_constants")
    setattr(constants, "get_hermes_home", lambda: profile_home)

    def apply_home_policy(env):
        applied.append(env["HERMES_HOME"])
        env["HOME"] = str(profile_home / "home")
        env["TMPDIR"] = str(profile_home / "cache" / "scratch")

    setattr(constants, "apply_subprocess_home_env", apply_home_policy)
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)

    env = client_module._build_subprocess_env()

    assert applied == [str(profile_home)]
    assert env["HOME"] == str(profile_home / "home")
    assert env["TMPDIR"] == str(profile_home / "cache" / "scratch")
    assert "UNLISTED_SECRET" not in env
    assert "must-not-leak" not in env.values()


def test_home_policy_failure_in_hermes_runtime_denies_child_start(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    fake_agent = types.ModuleType("agent")
    fake_agent.__path__ = []
    _host_tools_package(
        monkeypatch,
        lambda *, inherit_credentials: {"HOME": str(tmp_path), "PATH": "/bin"},
    )
    monkeypatch.setitem(sys.modules, "agent", fake_agent)
    constants = types.ModuleType("hermes_constants")
    setattr(constants, "get_hermes_home", lambda: tmp_path / "profiles" / "worker")

    def fail_home_policy(env):
        raise RuntimeError("injected HOME/scratch policy error")

    setattr(constants, "apply_subprocess_home_env", fail_home_policy)
    monkeypatch.setitem(sys.modules, "hermes_constants", constants)

    with pytest.raises(RuntimeError, match="HOME/scratch policy failed"):
        client_module._build_subprocess_env()


def test_missing_home_policy_api_in_hermes_runtime_denies_child_start(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    fake_agent = types.ModuleType("agent")
    fake_agent.__path__ = []
    _host_tools_package(
        monkeypatch,
        lambda *, inherit_credentials: {"HOME": str(tmp_path), "PATH": "/bin"},
    )
    monkeypatch.setitem(sys.modules, "agent", fake_agent)
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profiles" / "coder"))

    with pytest.raises(RuntimeError, match="HOME/scratch policy is unavailable"):
        client_module._build_subprocess_env()


def test_public_provider_host_with_missing_internal_home_policy_fails_closed(
    monkeypatch, tmp_path
):
    client_module, _ = _compat(monkeypatch)
    providers = sys.modules["providers"]
    providers.__file__ = str(tmp_path / "hermes-install" / "providers" / "__init__.py")
    monkeypatch.setitem(sys.modules, "hermes_constants", None)
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profiles" / "coder"))
    monkeypatch.setattr(client_module, "build_hermes_subprocess_env", lambda: None)

    with pytest.raises(RuntimeError, match="HOME/scratch policy is unavailable"):
        client_module._build_subprocess_env()


def test_environment_policy_call_failure_in_hermes_runtime_denies_child_start(
    monkeypatch, tmp_path
):
    client_module, _ = _compat(monkeypatch)
    fake_agent = types.ModuleType("agent")
    fake_agent.__path__ = []

    def fail_subprocess_env(*, inherit_credentials):
        raise RuntimeError("injected Hermes environment policy error")

    _host_tools_package(monkeypatch, fail_subprocess_env)
    monkeypatch.setitem(sys.modules, "agent", fake_agent)
    monkeypatch.setenv("HOME", str(tmp_path))

    with pytest.raises(RuntimeError, match="environment policy failed"):
        client_module._build_subprocess_env()


def test_missing_file_safety_and_redaction_apis_fail_closed(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setitem(sys.modules, "agent.file_safety", None)

    with pytest.raises(PermissionError, match="file-safety policy is unavailable"):
        client_module._safe_path(str(workspace / "secret.txt"), str(workspace), verb="Read")

    file_safety = types.ModuleType("agent.file_safety")
    setattr(file_safety, "get_nt_namespace_error", lambda path, verb=None: None)
    setattr(file_safety, "get_read_block_error", lambda path: None)
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    monkeypatch.setitem(sys.modules, "agent.redact", None)
    secret = workspace / "secret.txt"
    secret.write_text("do not reveal", encoding="utf-8")

    with pytest.raises(PermissionError, match="file-read safety policy is unavailable"):
        client_module._fs_read_text_file({"path": str(secret)}, str(workspace))


def test_missing_write_approval_api_denies_without_creating_file(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    file_safety = types.ModuleType("agent.file_safety")
    setattr(file_safety, "get_nt_namespace_error", lambda path, verb=None: None)
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)

    target = workspace / "not-created.txt"
    with pytest.raises(PermissionError, match="file-write safety policy is unavailable"):
        client_module._fs_write_text_file(
            {"path": str(target), "content": "blocked"}, str(workspace)
        )
    assert not target.exists()


def _stub_read_safety(monkeypatch, *, read_block=None, redact=None):
    file_safety = types.ModuleType("agent.file_safety")
    setattr(file_safety, "get_nt_namespace_error", lambda path, verb=None: None)
    setattr(file_safety, "get_read_block_error", read_block or (lambda path: None))
    redact_module = types.ModuleType("agent.redact")
    setattr(redact_module, "redact_sensitive_text", redact or (lambda text, **kwargs: text))
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    monkeypatch.setitem(sys.modules, "agent.redact", redact_module)


def test_file_safety_call_failure_denies_path_access(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    def fail_namespace_check(path, verb=None):
        raise RuntimeError("simulated file-safety policy crash")

    file_safety = types.ModuleType("agent.file_safety")
    setattr(file_safety, "get_nt_namespace_error", fail_namespace_check)
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)

    with pytest.raises(PermissionError, match="file-safety policy is unavailable"):
        client_module._safe_path(str(workspace / "secret.txt"), str(workspace), verb="Read")


def test_read_block_call_failure_denies_read(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    secret = workspace / "secret.txt"
    secret.write_text("do not reveal", encoding="utf-8")

    def fail_read_block(path):
        raise RuntimeError("simulated read-block policy crash")

    _stub_read_safety(monkeypatch, read_block=fail_read_block)
    with pytest.raises(PermissionError, match="read-block policy failed"):
        client_module._fs_read_text_file({"path": str(secret)}, str(workspace))


def test_redaction_call_failure_never_returns_content(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    secret = workspace / "secret.txt"
    secret.write_text("do not reveal", encoding="utf-8")

    def fail_redact(text, **kwargs):
        raise RuntimeError("simulated redaction policy crash")

    _stub_read_safety(monkeypatch, redact=fail_redact)
    with pytest.raises(PermissionError, match="redaction policy failed") as caught:
        client_module._fs_read_text_file({"path": str(secret)}, str(workspace))
    assert "do not reveal" not in str(caught.value)


def test_write_policy_call_failure_denies_without_creating_file(monkeypatch, tmp_path):
    client_module, _ = _compat(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    def fail_write_denied(path, **kwargs):
        raise RuntimeError("simulated write-denial policy crash")

    file_safety = types.ModuleType("agent.file_safety")
    setattr(file_safety, "get_nt_namespace_error", lambda path, verb=None: None)
    setattr(file_safety, "get_write_denied_error", fail_write_denied)
    setattr(file_safety, "is_write_approval_required", lambda path: False)
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)

    target = workspace / "not-created.txt"
    with pytest.raises(PermissionError, match="file-write safety policy failed"):
        client_module._fs_write_text_file(
            {"path": str(target), "content": "blocked"}, str(workspace)
        )
    assert not target.exists()


def test_write_origin_lookup_failure_refuses_cross_lane_session_reuse(monkeypatch):
    client_module, compat = _compat(monkeypatch)
    tools_package = types.ModuleType("tools")
    tools_package.__path__ = []
    provenance = types.ModuleType("tools.skill_provenance")

    def fail_origin():
        raise RuntimeError("simulated write-origin lookup crash")

    setattr(provenance, "get_current_write_origin", fail_origin)
    monkeypatch.setitem(sys.modules, "tools", tools_package)
    monkeypatch.setitem(sys.modules, "tools.skill_provenance", provenance)
    monkeypatch.setitem(sys.modules, "gateway.session_context", None)
    monkeypatch.setenv("HERMES_SESSION_ID", "active-session-id")
    monkeypatch.setenv("HERMES_SESSION_KEY", "active-session-key")

    with pytest.raises(RuntimeError, match="write-origin lookup failed"):
        compat.get_current_write_origin()
    # An unknown lane under an active session identity never yields an affinity
    # key, so no foreground ACP session can be reused from another lane.
    with pytest.raises(RuntimeError, match="write-origin lookup failed"):
        client_module._conversation_affinity(
            [{"role": "user", "content": "hello"}], "/tmp"
        )


def test_windows_hide_flag_uses_stdlib_not_hermes_private_module(monkeypatch):
    client_module, _ = _compat(monkeypatch)
    monkeypatch.setitem(sys.modules, "hermes_cli._subprocess_compat", None)

    assert client_module._windows_hide_flags() == getattr(subprocess, "CREATE_NO_WINDOW", 0)
