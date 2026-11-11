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
from gateway.session_context import clear_session_vars, set_session_vars
from hermes_constants import reset_hermes_home_override, set_hermes_home_override

from test_vanilla_hermes_seam import _load_real_plugin


def _load_client(monkeypatch, tmp_path):
    plugin, profile = _load_real_plugin(monkeypatch, tmp_path)
    assert providers.get_provider_profile("antigravity-acp") is profile
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
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", str(tmp_path / "acp-limits.json")
    )
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
        # Issue #6 AC4-3: self-report the source-verified 1.4.x identity so
        # this lane exercises the verified consumption-accumulation path.
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
    """Gate B.5 (historical reference) scenario coverage: every read/redact/write decision the
    ACP file bridge makes is delegated to the REAL unmodified upstream policy —
    there is no local substitute anywhere in these paths.

    A read inside the plugin's own containment root returns only after upstream
    redaction; a project ``.env`` inside that same allowed root stays upstream
    read-blocked; the hard-denied ``~/.ssh`` key and the ``~/.ssh/config``
    approval gate fail closed without touching bytes; a policy call that raises
    denies the write outright; a benign workspace write passes both layers.
    Runs un-skipped at every upstream-venv lane (live ``main``, floor
    ``v0.21.6``) and was recorded against official ``v0.23.0``.
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

    # 3) Hard-denied credential write: upstream's verdict denies before any byte.
    private_key = policy_home / ".ssh" / "id_ed25519"
    private_key.write_text("synthetic-placeholder-bytes", encoding="utf-8")
    with pytest.raises(PermissionError):
        client._fs_write_text_file(
            {"path": str(private_key), "content": "overwritten"}, str(policy_home)
        )
    assert private_key.read_text(encoding="utf-8") == "synthetic-placeholder-bytes"

    # 4) Approval-gated write (``~/.ssh/config``): the non-interactive ACP
    #    bridge fails closed instead of silently skipping the human prompt.
    ssh_config = policy_home / ".ssh" / "config"
    ssh_config.write_text("Host synthetic-example\n", encoding="utf-8")
    with pytest.raises(PermissionError, match="requires interactive approval"):
        client._fs_write_text_file(
            {"path": str(ssh_config), "content": "overwritten"}, str(policy_home)
        )
    assert ssh_config.read_text(encoding="utf-8") == "Host synthetic-example\n"

    # 5) A raising upstream policy call is itself a denial, before the write.
    import agent.file_safety as file_safety

    def raise_denied_error(*args, **kwargs):
        raise RuntimeError("simulated upstream write policy failure")

    target = policy_home / "project" / "pending.txt"
    with monkeypatch.context() as failing:
        failing.setattr(file_safety, "get_write_denied_error", raise_denied_error)
        with pytest.raises(PermissionError, match="write safety policy failed"):
            client._fs_write_text_file(
                {"path": str(target), "content": "never-written"}, str(policy_home)
            )
    assert not target.exists()

    # 6) A benign workspace write passes both the plugin root containment and
    #    the real upstream denial/approval policy unchanged.
    ok = policy_home / "project" / "ok.txt"
    assert (
        client._fs_write_text_file({"path": str(ok), "content": "written"}, str(policy_home))
        is None
    )
    assert ok.read_text(encoding="utf-8") == "written"


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
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        str(tmp_path / "acp-public-session-limits.json"),
    )
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
        # Issue #6 AC4-1: without the server's own per-turn breakdown,
        # completion.usage stays None (Core's designed usage-less path);
        # observed consumption lives only in scoped turn_consumption telemetry.
        assert response.usage is None
        assert telemetry["server_consumption_semantics"] == "verified"
        assert telemetry["turn_consumption"] == {
            "source": "acp.session/update:usage_update",
            "scope": "per_model_call_consumption_delta",
            "is_billing_usage": False,
            "semantics": "verified",
            "model_calls_observed": 1,
            "total_tokens": used,
        }
        assert "cost" not in telemetry and "currency" not in telemetry
        assert all(value is None for value in telemetry["request_usage"].values())
        assert telemetry["context_occupancy"] == {
            "source": "acp.session/update:usage_update",
            "scope": "per_model_call_consumption_delta",
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
