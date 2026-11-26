"""Strict integration regressions against the unmodified Hermes runtime contracts.

This module intentionally imports Hermes directly and has no skip path. Run it
only in the upstream compatibility job after the official checkout is installed.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import hermes_constants
import providers
import pytest
from agent.context_compressor import ContextCompressor
from agent.model_metadata import estimate_request_tokens_rough
from agent.turn_context import _preflight_request_tokens
from agent.usage_anchor import anchored_context_tokens, capture_usage_anchor
from gateway.session_context import clear_session_vars, set_session_vars
from hermes_constants import reset_hermes_home_override, set_hermes_home_override

from test_vanilla_hermes_seam import _load_real_plugin


def _load_client(monkeypatch, tmp_path):
    # These runtime contracts (env allowlist, session context, conversation
    # registry) are the Replay engine's client contracts; the engine stays
    # seam-proven under its explicit id after the 0.9.0 default switch.
    plugin, profile = _load_real_plugin(monkeypatch, tmp_path, "antigravity-acp-replay")
    assert providers.get_provider_profile("antigravity-acp-replay") is profile
    return importlib.import_module(f"{plugin.__name__}.client")


# Synthetic markers: secret-shaped for policy purposes, meaningless values.
# Tier-2 provider/tool credentials pass upstream's policy only with
# inherit_credentials=True; the Tier-1 GitHub token never passes at all.
_SYNTHETIC_TIER2_SECRET_ENV = {
    "OPENAI_API_KEY": "synthetic-openai-value-not-a-key",
    "ANTHROPIC_API_KEY": "synthetic-anthropic-value-not-a-key",
    "GEMINI_API_KEY": "synthetic-gemini-value-not-a-key",
}
_SYNTHETIC_TIER1_SECRET_ENV = {
    "GH_TOKEN": "synthetic-forge-token-value",
}
_SYNTHETIC_MUX_CONFIG_ENV = {
    "ACP_MUX_ACCOUNTS": "/synthetic/acp-accounts.json",
    "ACP_MUX_TOKEN": "synthetic-mux-value",
}


def _poison_host_environment(monkeypatch, tmp_path):
    host_home = tmp_path / "host-home"
    host_home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(host_home))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    for key, value in _SYNTHETIC_TIER2_SECRET_ENV.items():
        monkeypatch.setenv(key, value)
    for key, value in _SYNTHETIC_TIER1_SECRET_ENV.items():
        monkeypatch.setenv(key, value)
    for key, value in _SYNTHETIC_MUX_CONFIG_ENV.items():
        monkeypatch.setenv(key, value)
    return host_home


def test_real_upstream_credential_policy_success_is_narrowed_for_acp_child(
    monkeypatch, tmp_path
):
    """Real unmodified ``hermes_subprocess_env(inherit_credentials=True)`` retains
    Tier-2 provider credentials — that is its documented contract — so the ACP
    child environment must be narrowed by an ACP-specific minimum contract
    before any of it reaches the official Google ACP child.

    This is the non-mockable proof of the maintainer-requested rework: it runs
    against the official Hermes venv at both ``main`` and the declared
    compatibility floor ``v0.21.6``, with the upstream source untouched
    (verified afterwards by the job's unmodified-core git checks).
    """
    client = _load_client(monkeypatch, tmp_path)
    from tools.environments.local import hermes_subprocess_env

    _poison_host_environment(monkeypatch, tmp_path)

    policy_result = hermes_subprocess_env(inherit_credentials=True)
    retained = sorted(key for key in _SYNTHETIC_TIER2_SECRET_ENV if key in policy_result)
    assert retained == sorted(_SYNTHETIC_TIER2_SECRET_ENV), (
        "premise broken: the real unmodified upstream policy no longer retains the "
        "Tier-2 markers under inherit_credentials=True; the maintainer-reported leak "
        "path changed upstream and this gate plus the compat docs need re-investigation"
    )
    assert "GH_TOKEN" not in policy_result, (
        "upstream Tier-1 contract regressed: GitHub-class secrets must never pass"
    )

    env = client._build_subprocess_env()

    leaked_keys = sorted(key for key in {**_SYNTHETIC_TIER2_SECRET_ENV, **_SYNTHETIC_TIER1_SECRET_ENV} if key in env)
    assert leaked_keys == []
    leaked_values = sorted(
        value
        for value in {
            **_SYNTHETIC_TIER2_SECRET_ENV,
            **_SYNTHETIC_TIER1_SECRET_ENV,
            **_SYNTHETIC_MUX_CONFIG_ENV,
        }.values()
        if value in env.values()
    )
    assert leaked_values == []
    assert not [key for key in env if key.startswith("ACP_MUX_")]
    # Legitimate runtime state survives: the policy PATH, the resolved HOME, and
    # the profile-scoped HERMES_HOME the compat layer adds.
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"]
    assert env["HERMES_HOME"]


_FAKE_ACP_CHILD_ENV_TEMPLATE = r'''
import json
import os
import sys

with open(__DUMP_PATH__, "w", encoding="utf-8") as dump:
    json.dump(sorted(os.environ), dump)

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    request_id = message.get("id")
    if method == "initialize":
        emit = {"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": 1}}
    elif method == "session/new":
        emit = {"jsonrpc": "2.0", "id": request_id,
                "result": {"sessionId": "child-env-session"}}
    elif method == "session/prompt":
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "method": "session/update",
            "params": {"update": {"sessionUpdate": "agent_message_chunk",
                "content": {"type": "text", "text": "acp-child-alive"}}}}) + "\n")
        sys.stdout.flush()
        emit = {"jsonrpc": "2.0", "id": request_id, "result": {"stopReason": "end_turn"}}
    else:
        continue
    sys.stdout.write(json.dumps(emit) + "\n")
    sys.stdout.flush()
'''


def test_credential_free_fake_acp_initialize_session_under_real_policy_filtering(
    monkeypatch, tmp_path
):
    """After the ACP minimum-contract filtering of the REAL host policy result, a
    credential-free fake ACP child still completes initialize/session/prompt and
    reports its own actual environment back over a side channel.
    """
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    monkeypatch.delenv("HERMES_SESSION_KEY", raising=False)
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(tmp_path / "acp-state.json"))
    client_module = _load_client(monkeypatch, tmp_path)
    _poison_host_environment(monkeypatch, tmp_path)
    hermes_home = tmp_path / ".hermes"
    (hermes_home / "home").mkdir(parents=True, exist_ok=True)
    (hermes_home / "cache" / "scratch").mkdir(parents=True, exist_ok=True)

    dump_path = tmp_path / "child-env.json"
    script = tmp_path / "fake_acp_child_env.py"
    script.write_text(
        _FAKE_ACP_CHILD_ENV_TEMPLATE.replace("__DUMP_PATH__", repr(str(dump_path))),
        encoding="utf-8",
    )
    client = client_module.AntigravityACPClient(
        command=sys.executable,
        args=[str(script)],
        acp_cwd=str(tmp_path),
        rate_limit_retries=0,
    )

    reply = client.chat.completions.create(
        model="antigravity-acp",
        messages=[{"role": "user", "content": "ping"}],
        timeout=30,
    )
    assert reply.choices[0].message.content == "acp-child-alive"

    child_keys = set(json.loads(dump_path.read_text(encoding="utf-8")))
    assert not sorted(key for key in {**_SYNTHETIC_TIER2_SECRET_ENV, **_SYNTHETIC_TIER1_SECRET_ENV} if key in child_keys)
    leaked_values = sorted(
        value
        for value in {**_SYNTHETIC_TIER2_SECRET_ENV, **_SYNTHETIC_MUX_CONFIG_ENV}.values()
        if value in json.dumps(sorted(child_keys))
    )
    assert leaked_values == []
    # Only the coordination keys that ``_spawn`` supplies itself may exist in the
    # child; no operator-inherited ``ACP_MUX_*`` configuration crosses over.
    spawn_owned = {
        "ACP_MUX_AFFINITY",
        "ACP_MUX_AFFINITY_PIN",
        "ACP_MUX_AFFINITY_TTL_SECONDS",
        "ACP_MUX_AFFINITY_MAX_ENTRIES",
        "ACP_MUX_SESSION_GC",
    }
    inherited_mux = sorted(
        key for key in child_keys if key.startswith("ACP_MUX_") and key not in spawn_owned
    )
    assert inherited_mux == []
    assert "PATH" in child_keys
    assert "HOME" in child_keys


def _write_usage_update_server(tmp_path: Path) -> Path:
    script = tmp_path / "fake_usage_update_acp.py"
    script.write_text(
        r'''import json
import sys

model_options = [{"value": "model-a"}, {"value": "model-b"}]

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def update(payload):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": payload}})

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    params = message.get("params") or {}
    request_id = message.get("id")
    if method == "initialize":
        # Self-report the production server identity so this lane exercises
        # the real initialize shape (issue #102: identity no longer gates
        # anything; consumption telemetry is scope-labeled for every server).
        emit({"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": 1,
            "agentInfo": {
                "name": "antigravity-acp",
                "title": "Google Antigravity",
                "version": "1.4.0",
            },
        }})
    elif method in ("session/new", "session/resume"):
        session_id = params.get("sessionId") or "native-session-secret"
        emit({"jsonrpc": "2.0", "id": request_id, "result": {
            "sessionId": session_id,
            "configOptions": [{
                "id": "model", "category": "model", "currentValue": "model-a",
                "options": model_options,
            }],
        }})
    elif method in ("session/set_config_option", "session/set_model"):
        emit({"jsonrpc": "2.0", "id": request_id, "result": {}})
    elif method == "session/prompt":
        prompt = " ".join(
            str(part.get("text") or "")
            for part in params.get("prompt", [])
            if isinstance(part, dict)
        )
        cases = (
            ("case-model-a-first", 100),
            ("case-model-b", 200),
            ("case-model-a-return", 50),
            ("case-no-session-id", 77),
        )
        used = next((value for marker, value in cases if marker in prompt), 1)
        update({"sessionUpdate": "usage_update", "used": used, "size": 1000})
        for invalid_used in ("malformed", -1, float("nan"), float("inf"), True):
            update({"sessionUpdate": "usage_update", "used": invalid_used, "size": 1000})
        update({"sessionUpdate": "agent_message_chunk", "content": {
            "type": "text", "text": f"reply-{used}"}})
        emit({"jsonrpc": "2.0", "id": request_id, "result": {"stopReason": "end_turn"}})
''',
        encoding="utf-8",
    )
    return script


def test_agent_cwd_uses_session_scope_and_refuses_process_cwd_on_api_loss(
    monkeypatch, tmp_path
):
    client = _load_client(monkeypatch, tmp_path)
    process_root = tmp_path / "gateway-launch"
    workspace_a = process_root / "profile-a-workspace"
    workspace_b = process_root / "profile-b-workspace"
    sibling = process_root / "other-profile"
    workspace_a.mkdir(parents=True)
    workspace_b.mkdir()
    sibling.mkdir()
    sibling_file = sibling / "private.txt"
    sibling_file.write_text("sibling-profile data", encoding="utf-8")
    isolated_host_home = tmp_path / "process-home"
    isolated_host_home.mkdir()
    monkeypatch.setenv("HOME", str(isolated_host_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(isolated_host_home))
    monkeypatch.chdir(process_root)

    tokens_a = set_session_vars(
        session_id="cwd-session-a", session_key="cwd-key-a", cwd=str(workspace_a)
    )
    try:
        assert client._resolve_acp_working_directory(None) == str(workspace_a.resolve())
        assert client._resolve_acp_working_directory(str(workspace_b)) == str(workspace_b.resolve())
        with pytest.raises(PermissionError):
            client._fs_read_text_file({"path": str(sibling_file)}, str(workspace_a))
    finally:
        clear_session_vars(tokens_a)

    tokens_b = set_session_vars(
        session_id="cwd-session-b", session_key="cwd-key-b", cwd=str(workspace_b)
    )
    try:
        assert client._resolve_acp_working_directory(None) == str(workspace_b.resolve())
    finally:
        clear_session_vars(tokens_b)

    tokens_missing = set_session_vars(
        session_id="cwd-session-missing-api",
        session_key="cwd-key-missing-api",
        cwd=str(workspace_a),
    )
    try:
        with monkeypatch.context() as unavailable:
            unavailable.setitem(sys.modules, "agent.runtime_cwd", None)
            try:
                resolved = client._resolve_acp_working_directory(None)
            except RuntimeError as exc:
                assert "session-scoped workspace" in str(exc)
            else:
                try:
                    leaked = client._fs_read_text_file({"path": str(sibling_file)}, resolved)
                except PermissionError as exc:
                    pytest.fail(
                        "resolver used the broader process cwd even though a session cwd was active; "
                        f"a second guard happened to deny this file: {exc}"
                    )
                pytest.fail(
                    "resolver used process cwd for an active session and file access crossed the "
                    f"session workspace: cwd={resolved}, content={leaked['content']!r}"
                )
    finally:
        clear_session_vars(tokens_missing)


def test_cron_scope_without_session_ids_refuses_process_cwd_on_api_loss(
    monkeypatch, tmp_path
):
    """Cron binds a scoped cwd with EMPTY session key/id (upstream _CronRunScope).

    Losing agent.runtime_cwd during a Hermes update must not widen ACP file
    access to the scheduler process cwd, even though no session id exists.
    """
    client = _load_client(monkeypatch, tmp_path)
    process_root = tmp_path / "scheduler-launch"
    workspace_a = process_root / "cron-job-a"
    sibling = process_root / "other-profile"
    workspace_a.mkdir(parents=True)
    sibling.mkdir()
    sibling_file = sibling / "private.txt"
    sibling_file.write_text("sibling-profile data", encoding="utf-8")
    isolated_host_home = tmp_path / "process-home"
    isolated_host_home.mkdir()
    monkeypatch.setenv("HOME", str(isolated_host_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(isolated_host_home))
    monkeypatch.delenv("HERMES_SESSION_KEY", raising=False)
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    monkeypatch.chdir(process_root)

    # Mirror _CronRunScope: set_session_vars(platform="", chat_id="", chat_name="",
    # session key/id left empty, cwd=job workdir, async_delivery=False).
    tokens = set_session_vars(
        platform="", chat_id="", chat_name="", cwd=str(workspace_a), async_delivery=False
    )
    try:
        assert client._resolve_acp_working_directory(None) == str(workspace_a.resolve())
        workspace_b = process_root / "explicit-target"
        workspace_b.mkdir()
        assert client._resolve_acp_working_directory(str(workspace_b)) == str(
            workspace_b.resolve()
        )

        with monkeypatch.context() as unavailable:
            unavailable.setitem(sys.modules, "agent.runtime_cwd", None)
            try:
                resolved = client._resolve_acp_working_directory(None)
            except RuntimeError as exc:
                assert "session-scoped workspace" in str(exc)
            else:
                leaked: dict = {}
                try:
                    leaked = client._fs_read_text_file({"path": str(sibling_file)}, resolved)
                except PermissionError as exc:
                    pytest.fail(
                        "resolver used the broader scheduler process cwd although the cron "
                        f"scope declared a workdir; a second guard denied it: {exc}"
                    )
                pytest.fail(
                    "cron scope without session ids widened ACP file root to process cwd: "
                    f"cwd={resolved}, content={leaked['content']!r}"
                )

        with monkeypatch.context() as failing_api:
            import agent.runtime_cwd as runtime_cwd_module

            def fail_resolve():
                raise RuntimeError("simulated runtime cwd resolver crash")

            failing_api.setattr(runtime_cwd_module, "resolve_agent_cwd", fail_resolve)
            with pytest.raises(RuntimeError, match="workspace lookup failed"):
                client._resolve_acp_working_directory(None)
    finally:
        clear_session_vars(tokens)


def test_subprocess_home_and_scratch_are_profile_scoped_and_fail_closed(
    monkeypatch, tmp_path
):
    client = _load_client(monkeypatch, tmp_path)
    host_home = tmp_path / "host-home"
    host_home.mkdir()
    monkeypatch.setenv("HOME", str(host_home))
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("TERMINAL_HOME_MODE", "profile")
    for name in ("TMPDIR", "TMP", "TEMP"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "synthetic-secret-must-not-leak")

    observed = []
    profile_homes = [tmp_path / "profiles" / name for name in ("alpha", "beta")]
    for profile_home in profile_homes:
        (profile_home / "home").mkdir(parents=True)
        gemini_home = profile_home / "home" / ".gemini"
        gemini_home.mkdir()
        monkeypatch.setenv("GEMINI_HOME", str(gemini_home))
        token = set_hermes_home_override(profile_home)
        try:
            env = client._build_subprocess_env()
            with monkeypatch.context() as without_environment_helper:
                without_environment_helper.setitem(sys.modules, "tools.environments.local", None)
                fallback_env = client._build_subprocess_env()
        finally:
            reset_hermes_home_override(token)

        expected_home = str(profile_home / "home")
        expected_scratch = str(profile_home / "cache" / "scratch")
        assert env["HERMES_HOME"] == str(profile_home)
        assert env["HOME"] == expected_home
        assert env["TMPDIR"] == expected_scratch
        assert env["TMP"] == expected_scratch
        assert env["TEMP"] == expected_scratch
        assert env["GEMINI_HOME"] == str(gemini_home)
        assert "TELEGRAM_BOT_TOKEN" not in env
        assert "synthetic-secret-must-not-leak" not in env.values()
        observed.append((env["HERMES_HOME"], env["HOME"], env["TMPDIR"]))
        assert fallback_env["HERMES_HOME"] == str(profile_home)
        assert fallback_env["HOME"] == expected_home
        assert fallback_env["TMPDIR"] == expected_scratch
        assert fallback_env["GEMINI_HOME"] == str(gemini_home)
        assert "TELEGRAM_BOT_TOKEN" not in fallback_env

    assert observed[0] != observed[1]

    profile_home = profile_homes[0]
    token = set_hermes_home_override(profile_home)
    try:
        with monkeypatch.context() as failing_policy:
            def fail_apply_home_policy(env):
                raise RuntimeError("simulated profile HOME/scratch policy failure")

            failing_policy.setattr(hermes_constants, "apply_subprocess_home_env", fail_apply_home_policy)
            with pytest.raises(RuntimeError, match="policy failed; refusing to start"):
                client._build_subprocess_env()
    finally:
        reset_hermes_home_override(token)


def test_real_upstream_file_policy_gates_acp_bridge_reads_and_writes(
    monkeypatch, tmp_path
):
    """Check real upstream read policy; ACP writes are denied independently.

    A read inside the plugin's containment root is redacted, while a project
    ``.env`` remains read-blocked. The ACP write callback refuses even a normal
    file; the real Hermes file tool can still create it in the workspace.
    """
    client = _load_client(monkeypatch, tmp_path)
    monkeypatch.delenv("HERMES_WRITE_SAFE_ROOT", raising=False)
    policy_home = tmp_path / "policy-home"
    (policy_home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(policy_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(policy_home))
    monkeypatch.chdir(policy_home)

    # Synthetic marker: secret-shaped for policy purposes, meaningless value.
    synthetic_key_value = "sk-syntheticvalue000000000000000000000000000"
    notes = policy_home / "notes.txt"
    notes.write_text(
        f"project note\nOPENAI_API_KEY={synthetic_key_value}\nplain line\n",
        encoding="utf-8",
    )

    # 1) Allowed read comes back ONLY after the real upstream redaction ran.
    redacted = client._fs_read_text_file({"path": str(notes)}, str(policy_home))
    assert synthetic_key_value not in redacted["content"]
    assert "plain line" in redacted["content"]
    assert "redacted" in redacted["content"].lower() or "***" in redacted["content"]

    # 2) Upstream read-blocked content inside the same plugin-allowed root.
    env_file = policy_home / ".env"
    env_file.write_text("SYNTHETIC_APP_SECRET=do-not-exfiltrate\n", encoding="utf-8")
    with pytest.raises(PermissionError):
        client._fs_read_text_file({"path": str(env_file)}, str(policy_home))

    # 3) ACP callback writes are denied even for a normal workspace file.
    ok = policy_home / "project" / "ok.txt"
    with pytest.raises(PermissionError, match="ACP fs/write_text_file is disabled"):
        client._fs_write_text_file({"path": str(ok), "content": "written"}, str(policy_home))
    assert not ok.exists()

    # The real Hermes file tool remains available for a normal new file.
    from tools.file_tools import write_file_tool

    result = json.loads(write_file_tool(str(ok), "written", task_id="acp-write-test"))
    assert "error" not in result, result
    assert ok.read_text(encoding="utf-8") == "written"

    # Exercise a real normal coding loop through the Core tools, without a model.
    workspace = policy_home / "project"
    source = workspace / "example.py"
    test_file = workspace / "test_example.py"
    for path, content in (
        (source, "def add(a, b):\n    return a - b\n"),
        (test_file, "import unittest\nfrom example import add\n"
         "class TestExample(unittest.TestCase):\n"
         "    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n"),
    ):
        result = json.loads(write_file_tool(str(path), content, task_id="acp-write-test"))
        assert "error" not in result, result
    from tools.file_tools import patch_tool
    from tools.terminal_tool import terminal_tool

    result = json.loads(patch_tool(
        mode="replace", path=str(source), old_string="return a - b",
        new_string="return a + b", task_id="acp-write-test",
    ))
    assert "error" not in result, result
    assert "return a + b" in source.read_text(encoding="utf-8")
    result = json.loads(terminal_tool(
        "python3 -m unittest test_example -q", task_id="acp-write-test", workdir=str(workspace)
    ))
    assert result.get("exit_code") == 0, result
    assert "OK" in result.get("output", ""), result


@pytest.mark.parametrize("surface", ["cli", "gateway", "cron", "subagent"])
def test_real_upstream_contexts_deny_acp_file_write(monkeypatch, tmp_path, surface):
    from contextlib import ExitStack
    from agent.delegation_context import delegated_child_context, is_delegated_child_context
    from gateway.session_context import get_session_env

    client = _load_client(monkeypatch, tmp_path)
    target = tmp_path / "AGENTS.md"
    target.write_text("original", encoding="utf-8")
    with ExitStack() as stack:
        if surface in {"gateway", "subagent"}:
            tokens = set_session_vars(
                platform="telegram", session_key="parent", session_id="parent-id", cwd=str(tmp_path)
            )
            stack.callback(clear_session_vars, tokens)
            assert get_session_env("HERMES_SESSION_KEY") == "parent"
        if surface == "subagent":
            stack.enter_context(delegated_child_context("child-id"))
            assert is_delegated_child_context()
            assert get_session_env("HERMES_SESSION_ID") == "child-id"
        if surface == "cron":
            from cron.scheduler import _CronRunScope

            scope = _CronRunScope({"workdir": str(tmp_path)}, "acp-test", "run-1")
            stack.callback(scope.exit)
            scope.enter()
            assert get_session_env("HERMES_CRON_SESSION") == "1"
        with pytest.raises(PermissionError, match="ACP fs/write_text_file is disabled"):
            client._fs_write_text_file({"path": str(target), "content": "changed"}, str(tmp_path))
        assert target.read_text(encoding="utf-8") == "original"


def test_real_upstream_lane_provenance_separates_affinity_and_fails_closed(
    monkeypatch, tmp_path
):
    """Gate B.5 (historical reference) scenario coverage: lane provenance.

    The plugin composes the runtime conversation identity from the REAL
    ``tools.skill_provenance`` lane ContextVar, so a background-review fork can
    never reuse the foreground conversation's native ACP continuation, and a
    failing origin lookup raises instead of silently defaulting the lane.
    """
    client = _load_client(monkeypatch, tmp_path)
    import tools.skill_provenance as skill_provenance

    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    monkeypatch.delenv("HERMES_SESSION_KEY", raising=False)
    messages = [{"role": "user", "content": "shared conversation"}]

    tokens = set_session_vars(
        session_id="lane-session",
        session_key="lane-conversation",
        cwd=str(tmp_path),
        async_delivery=False,
    )
    try:
        foreground_identity = client._runtime_conversation_identity()
        assert foreground_identity == (
            f"lane-conversation\0{skill_provenance.get_current_write_origin()}"
        )
        foreground_affinity = client._conversation_affinity(messages, str(tmp_path))
        assert foreground_affinity.startswith("sha256:")
        assert (
            foreground_affinity
            == client._conversation_affinity(messages, str(tmp_path))
        )

        origin_token = skill_provenance.set_current_write_origin(
            skill_provenance.BACKGROUND_REVIEW
        )
        try:
            background_identity = client._runtime_conversation_identity()
            background_affinity = client._conversation_affinity(messages, str(tmp_path))
        finally:
            skill_provenance.reset_current_write_origin(origin_token)

        assert background_identity.endswith(f"\0{skill_provenance.BACKGROUND_REVIEW}")
        assert background_identity != foreground_identity
        assert background_affinity != foreground_affinity

        def raise_origin() -> str:
            raise RuntimeError("simulated upstream write-origin lookup failure")

        with monkeypatch.context() as failing:
            failing.setattr(skill_provenance, "get_current_write_origin", raise_origin)
            with pytest.raises(RuntimeError, match="write-origin lookup failed"):
                client._runtime_conversation_identity()
    finally:
        clear_session_vars(tokens)


def test_public_session_context_persists_model_deltas_and_rejects_bad_frames(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    monkeypatch.delenv("HERMES_SESSION_KEY", raising=False)
    state_path = tmp_path / "acp-public-session-context.json"
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(state_path))
    client_module = _load_client(monkeypatch, tmp_path)
    client = client_module.AntigravityACPClient(
        command=sys.executable,
        args=[str(_write_usage_update_server(tmp_path))],
        acp_cwd=str(tmp_path),
        rate_limit_retries=0,
    )

    hermes_session_id = "explicit-hermes-session"
    turns = (
        ("model-a", "case-model-a-first", 100),
        ("model-b", "case-model-b", 200),
        ("model-a", "case-model-a-return", 50),
    )
    for turn, (model, marker, used) in enumerate(turns):
        tokens = set_session_vars(
            session_id=hermes_session_id,
            session_key=f"conversation-key-{turn}",
            cwd=str(tmp_path),
            async_delivery=False,
        )
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": marker}],
                timeout=10,
            )
        finally:
            clear_session_vars(tokens)

        telemetry = response.antigravity_usage_telemetry
        # Issue #102: completion.usage stays None (Core's designed usage-less
        # path); observed consumption lives only in scoped turn_consumption
        # telemetry with the honest unverified scope.
        assert response.usage is None
        assert "server_consumption_semantics" not in telemetry
        assert telemetry["turn_consumption"] == {
            "source": "acp.session/update:usage_update",
            "scope": "unverified_server_semantics",
            "is_billing_usage": False,
            "model_calls_observed": 1,
            "total_tokens": used,
        }
        assert "cost" not in telemetry and "currency" not in telemetry
        assert all(value is None for value in telemetry["request_usage"].values())
        assert telemetry["context_occupancy"] == {
            "source": "acp.session/update:usage_update",
            "scope": "unverified_server_semantics",
            "is_billing_usage": False,
            "used": used,
            "size": 1000,
        }

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    totals = payload["usage_totals"]
    assert set(totals) == {hermes_session_id}
    entry = totals[hermes_session_id]
    assert entry["summed_tokens"] == 350
    assert entry["by_model"] == {"model-a": 150, "model-b": 200}
    assert entry["model"] is None
    assert entry["frames_observed"] == 3
    assert entry["native_session_id_hash"].startswith("sha256:")
    serialized_totals = json.dumps(totals, sort_keys=True)
    assert "native-session-secret" not in serialized_totals
    assert "case-model-a-first" not in serialized_totals
    assert "conversation-key-" not in serialized_totals

    tokens = set_session_vars(
        session_id="",
        session_key="session-key-only-must-not-be-used",
        cwd=str(tmp_path),
        async_delivery=False,
    )
    try:
        response = client.chat.completions.create(
            model="model-a",
            messages=[{"role": "user", "content": "case-no-session-id"}],
            timeout=10,
        )
    finally:
        clear_session_vars(tokens)

    # Issue #6 AC4-1: even with no Hermes session id (no usage-store row),
    # the turn's observed consumption stays visible as scoped telemetry — but
    # never as a fabricated completion.usage split.
    assert response.usage is None
    assert response.antigravity_usage_telemetry["turn_consumption"]["total_tokens"] == 77
    assert response.antigravity_usage_telemetry["context_occupancy"]["used"] == 77
    updated = json.loads(state_path.read_text(encoding="utf-8"))
    assert set(updated["usage_totals"]) == {hermes_session_id}
    assert "session-key-only-must-not-be-used" not in json.dumps(updated["usage_totals"])


def test_credential_free_namespace_snapshot_covers_installed_core() -> None:
    """Sync check for the credential-free inventory enforcer (issue #12).

    `tests/test_plugin_manifest.py` classifies Hermes-owned namespaces with
    `HERMES_TOP_LEVEL_SNAPSHOT`, a snapshot of the official Core definitions
    taken without a Core checkout. This lane is the authoritative side: every
    Hermes-owned top-level namespace the installed Core reports through its
    own official functions must already be inside that snapshot. A failure
    means upstream added a namespace: move the snapshot and the
    docs/hermes-compatibility.md register in the same change — never widen
    the plugin's documented import surface here.
    """
    from hermes_cli.plugin_validate_core_override import _hermes_top_level

    from test_plugin_manifest import (
        HERMES_TOP_LEVEL_SNAPSHOT,
        _assert_namespace_snapshot_covers,
    )

    computed = {
        "plugin_validate_core_override._hermes_top_level": set(_hermes_top_level()),
    }
    try:
        from hermes_cli.plugin_validate_private_imports import _hermes_packages
    except ImportError:
        pass  # floor refs (v0.21.6) ship without the private-imports catalog
    else:
        computed["plugin_validate_private_imports._hermes_packages"] = set(_hermes_packages())

    for name, namespaces in computed.items():
        _assert_namespace_snapshot_covers(name, namespaces, HERMES_TOP_LEVEL_SNAPSHOT)


# ---------------------------------------------------------------------------
# Issue #102: Core occupancy-anchor boundary — FULL DATA PATH
# ---------------------------------------------------------------------------
#
# Full-path regressions for the production incident class.  Every test here
# drives the same chain production drove:
#
#     ACP server (fake) -> shipped plugin engine (Replay / Parked-MCP)
#       -> completion -> Core record_response_usage -> normalize_usage
#       -> capture/set_usage_anchor -> _preflight_request_tokens
#       -> ContextCompressor.should_compress
#
# Fixtures are the measured final-turn ``session/prompt`` usage reports of
# the four contaminated production sessions (issue #102 incident table),
# paired with synthetic transcripts of the published durable-transcript
# sizes.  The RED test replays the PRE-#102 engine completion shape through
# Core's real recording path; the GREEN tests drive the SHIPPED engines
# end to end.  No test injects numbers into Core internals directly.

# name: (inputTokens, outputTokens, thoughtTokens, cachedReadTokens,
#        transcript messages, transcript chars)
_INCIDENTS = {
    "S1": (5_373, 20_178, 0, 1_148_804, 143, 380_000),
    "S2": (5_656, 47_331, 0, 6_028_410, 324, 560_000),
    "S3": (2_087, 31_559, 0, 2_332_129, 385, 1_020_000),
    "S4": (0, 306, 17_000, 861_529, 89, 227_000),
}

_FAKE_AGY = Path(__file__).resolve().parent / "design_c" / "fake_agy.py"

_INCIDENT_ACP_SERVER = r"""import json
import sys


def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


USAGE = json.loads(sys.argv[1])


for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    params = message.get("params") or {}
    request_id = message.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": 1,
            "agentInfo": {"name": "antigravity-acp", "title": "Google Antigravity",
                          "version": "1.5.2"},
        }})
    elif method in ("session/new", "session/resume"):
        emit({"jsonrpc": "2.0", "id": request_id, "result": {
            "sessionId": params.get("sessionId") or "incident-native",
            "configOptions": [{"id": "model", "category": "model",
                               "currentValue": "model-a",
                               "options": [{"value": "model-a"}]}],
        }})
    elif method in ("session/set_config_option", "session/set_model"):
        emit({"jsonrpc": "2.0", "id": request_id, "result": {}})
    elif method == "session/prompt":
        emit({"jsonrpc": "2.0", "id": request_id, "result": {
            "stopReason": "end_turn", "usage": USAGE,
        }})
"""


def _incident_wire(name: str) -> dict:
    inp, out, thought, cached, _, _ = _INCIDENTS[name]
    wire = {"inputTokens": inp, "outputTokens": out,
            "totalTokens": inp + out + thought + cached,
            "cachedReadTokens": cached}
    if thought:
        wire["thoughtTokens"] = thought
    return wire


def _incident_transcript(name: str) -> list:
    _, _, _, _, n_msgs, n_chars = _INCIDENTS[name]
    per = max(1, n_chars // n_msgs)
    filler = "routine multi-turn engineering transcript body. "
    body = (filler * (per // len(filler) + 1))[:per]
    return [
        {"role": "user" if i % 2 == 0 else "assistant",
         "content": f"turn {i}: {body}"}
        for i in range(n_msgs)
    ]


def _core_agent():
    """Minimal agent surface accepted by ``record_response_usage`` across
    every supported Core era (v0.21.6 floor, stable baseline, main), with a
    fresh compression gate at the S4 production configuration (window
    1,048,576 @ 0.7 -> threshold 734,003; ``config_context_length`` keeps
    resolution credential-free)."""
    from types import SimpleNamespace
    return SimpleNamespace(
        _usage_anchor=None, _turn_base_usage_anchor=None, tools=None,
        api_mode="chat_completions", provider="antigravity-acp",
        model="fake-model-a", base_url="",
        context_compressor=ContextCompressor(
            model="fake-model-a", threshold_percent=0.7,
            config_context_length=1_048_576, quiet_mode=True),
        session_api_calls=0, quiet_mode=True, log_prefix="",
        verbose_logging=False, platform="cli",
        _vprint=lambda *a, **k: None, _safe_print=lambda *a, **k: None,
        _ensure_db_session=lambda: None,
        _session_db=None, session_id=None, _persist_disabled=True,
        _session_db_created=False, _turn_route_task="", client=None,
        session_prompt_tokens=0, session_completion_tokens=0,
        session_total_tokens=0, session_input_tokens=0,
        session_output_tokens=0, session_cache_read_tokens=0,
        session_cache_write_tokens=0, session_reasoning_tokens=0,
        session_estimated_cost_usd=0.0, session_cost_status=None,
        session_cost_source=None,
    )


def _record(agent, completion, messages):
    """Core's REAL response-usage recording path (the agent loop's own
    fold function): normalize_usage -> anchor capture -> session totals."""
    from agent.turn_usage import record_response_usage
    return record_response_usage(
        agent, completion, messages=messages, api_call_count=1,
        api_duration=0.1, compression_attempts=0, max_compression_attempts=3)


def _legacy_completion(wire: dict):
    """The PRE-#102 engine completion shape: the prompt-result consumption
    sum copied into ``usage`` verbatim (witnessed on the pre-fix tree with
    the S4 payload: prompt_tokens=0, cached=861,529, total=878,835)."""
    from types import SimpleNamespace
    return SimpleNamespace(
        id="chatcmpl-legacy", provider=None,
        usage=SimpleNamespace(
            prompt_tokens=wire["inputTokens"],
            completion_tokens=wire["outputTokens"] + wire.get("thoughtTokens", 0),
            total_tokens=wire["totalTokens"],
            prompt_tokens_details=SimpleNamespace(
                cached_tokens=wire["cachedReadTokens"])))


def _replay_completion(incident: str, monkeypatch, tmp_path):
    """Drive the SHIPPED Replay engine against a server reporting the
    incident's prompt-result usage; return its completion."""
    script = tmp_path / f"fake_{incident}_prompt_usage_acp.py"
    script.write_text(_INCIDENT_ACP_SERVER, encoding="utf-8")
    client_module = _load_client(monkeypatch, tmp_path)
    client = client_module.AntigravityACPClient(
        command=sys.executable,
        args=[str(script), json.dumps(_incident_wire(incident))],
        acp_cwd=str(tmp_path), rate_limit_retries=0,
    )
    return client.chat.completions.create(
        model="model-a",
        messages=[{"role": "user", "content": f"{incident} probe"}],
        timeout=10,
    )


def _parked_completion(incident: str, monkeypatch, tmp_path):
    """Drive the SHIPPED Parked-MCP engine (the deployed default) against
    the design_c fake ACP server reporting the incident's prompt-result
    usage; return its completion."""
    client_module = _load_client(monkeypatch, tmp_path)
    parked = importlib.import_module(client_module.__package__ + ".parked.client")
    behaviour = json.dumps({"script": [[
        {"text": "ok"},
        {"result_usage": _incident_wire(incident)},
    ]]})
    client = parked.AntigravityAcpMcpClient(
        acp_command=sys.executable, acp_args=[str(_FAKE_AGY), behaviour])
    return client.chat.completions.create(
        model="model-a",
        messages=[{"role": "user", "content": f"{incident} probe"}],
        timeout=30,
    )


@pytest.mark.parametrize("incident", sorted(_INCIDENTS))
def test_incident_usage_through_real_recording_path_poisons_gate(incident):
    """RED (full path): the pre-#102 completion shape, fed through Core's
    REAL record_response_usage, forms an occupancy anchor from the
    consumption sum and fires Core's own compression gate against the true
    transcript — the production premature-compaction mechanism, reproduced
    through the recording path rather than by injecting numbers."""
    wire = _incident_wire(incident)
    messages = _incident_transcript(incident)
    agent = _core_agent()
    rough = estimate_request_tokens_rough(messages, system_prompt="")
    _record(agent, _legacy_completion(wire), messages)
    assert agent._usage_anchor is not None
    assert agent._usage_anchor["prompt_tokens"] >= wire["cachedReadTokens"]
    preflight = _preflight_request_tokens(agent, messages, "")
    assert preflight > 5 * rough  # anchored figure is real usage + delta, never deferred
    assert agent.context_compressor.should_compress(preflight)  # premature fire
    assert not agent.context_compressor.should_compress(rough)  # truth: never fires


@pytest.mark.parametrize("incident", sorted(_INCIDENTS))
@pytest.mark.parametrize("engine", ["replay", "parked"])
def test_shipped_engines_never_poison_core_recording(incident, engine, monkeypatch, tmp_path):
    """GREEN (full path): both shipped engines, fed the exact incident
    reports, produce completions that Core's REAL record_response_usage
    treats as usage-less: no anchor is formed, preflight falls back to the
    transcript estimate, and the compression gate never fires early."""
    completion = (_replay_completion if engine == "replay" else _parked_completion)(
        incident, monkeypatch, tmp_path)
    messages = _incident_transcript(incident)
    agent = _core_agent()
    _record(agent, completion, messages)
    assert agent._usage_anchor is None
    rough = estimate_request_tokens_rough(messages, system_prompt="")
    preflight = _preflight_request_tokens(agent, messages, "")
    assert preflight <= rough * 1.05  # the local estimate governs
    assert not agent.context_compressor.should_compress(preflight)


def test_tainted_anchor_persists_through_real_usage_less_recording(monkeypatch, tmp_path):
    """Lifecycle (full path, documented operational consequence): an anchor
    formed from a pre-#102 completion is NOT cleared by later usage-less
    recordings — Core's real record_response_usage usage-less path never
    touches it, so the gate keeps firing early until the transcript
    fingerprint breaks or a verified-usage provider re-anchors the session.
    A restart is not a reset: Core persists the anchor on the session row
    (model_config._usage_anchor) and restores it while the fingerprint
    matches. No silent DB rewrite is performed anywhere."""
    wire = _incident_wire("S4")
    messages = _incident_transcript("S4")
    agent = _core_agent()
    _record(agent, _legacy_completion(wire), messages)
    tainted = agent._usage_anchor
    assert tainted is not None
    # Post-#102 steady state: the SHIPPED Replay engine's usage-less completion.
    _record(agent, _replay_completion("S4", monkeypatch, tmp_path), messages)
    assert agent._usage_anchor is tainted  # same object: never replaced
    preflight = _preflight_request_tokens(agent, messages, "")
    assert preflight >= wire["cachedReadTokens"]
    assert agent.context_compressor.should_compress(preflight)  # still fires early
    # Appending turns keeps the anchor matching (prefix fingerprint stable),
    # so the inflation is not self-healing within the session.
    grown = messages + [{"role": "user", "content": "one more routine question"}]
    assert anchored_context_tokens(grown, tainted) is not None


def _preflight_agent(anchor):
    from types import SimpleNamespace
    return SimpleNamespace(
        _usage_anchor=anchor, tools=None, api_mode="", provider="antigravity-acp",
        model="fake-model-a", base_url="",
    )


def _core_compressor() -> ContextCompressor:
    """Core's real compression gate at the S4 production configuration
    (window 1,048,576 @ 0.7).  ``config_context_length`` short-circuits
    endpoint probing, so this stays credential-free; ``should_compress`` is
    the exact predicate ``_preflight_compression`` consults."""
    return ContextCompressor(
        model="fake-model-a",
        threshold_percent=0.7,
        config_context_length=1_048_576,
        quiet_mode=True,
    )


def test_needed_compaction_still_fires_without_anchor_c1():
    """C1 control: a GENUINELY large transcript with no anchor (the post-#102
    steady state) still trips Core's compression gate — needed compaction is
    not suppressed by completion.usage=None."""
    big = [{"role": "user" if i % 2 == 0 else "assistant",
            "content": ("routine transcript body. " * 220) + str(i)}
           for i in range(700)]  # ~3.5MB chars -> ~800K tokens by rough estimate
    rough = estimate_request_tokens_rough(big, system_prompt="")
    assert rough > 600_000
    preflight = _preflight_request_tokens(_preflight_agent(None), big, "")
    assert preflight >= rough  # the gate sees the real size, undamped
    assert _core_compressor().should_compress(preflight)


def test_needed_compaction_still_fires_with_valid_anchor_c2():
    """C2 control: a VALID anchor (provider-priced occupancy matching the
    transcript) keeps driving compaction normally — #102 removes only the
    contamination channel, not the anchored fast path."""
    big = [{"role": "user" if i % 2 == 0 else "assistant",
            "content": ("routine transcript body. " * 220) + str(i)}
           for i in range(700)]
    rough = estimate_request_tokens_rough(big, system_prompt="")
    assert rough > 600_000
    anchor = capture_usage_anchor(rough, 100, big)
    assert anchor is not None
    anchored = anchored_context_tokens(big, anchor)
    assert anchored is not None and anchored >= rough
    preflight = _preflight_request_tokens(_preflight_agent(anchor), big, "")
    assert preflight >= rough
    assert _core_compressor().should_compress(preflight)
