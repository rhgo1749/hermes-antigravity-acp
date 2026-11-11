"""1.2.1 client-side stabilization: digest suppression, stopReason, replay safety.

Protocol-level regressions against a fake ACP subprocess plus permission-policy
units.  No credentials, no Google binary.  Contract: docs/official-server-
1.2.1-contract.md (S2, S4, stopReason, dedupe).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import time
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"

QUOTA_HEAD = (
    "Usage Limit Reached\n\n"
    "You have reached your current quota for this period."
)


def _load_client(monkeypatch, *, args: list[str], cwd: str, retries: int = 0):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(Path(cwd) / "acp-state.json")
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", str(Path(cwd) / "acp-limits.json")
    )
    registered: list = []

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = registered.append
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)
    file_safety = types.ModuleType("agent.file_safety")
    file_safety.get_nt_namespace_error = lambda path, verb=None: None
    file_safety.get_read_block_error = lambda path: None
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    redact = types.ModuleType("agent.redact")
    redact.redact_sensitive_text = lambda text, force=True: text
    monkeypatch.setitem(sys.modules, "agent.redact", redact)

    module_name = "antigravity_acp_121"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location(
        module_name, PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module.antigravity_acp.create_client(
        command=sys.executable, args=args, acp_cwd=cwd, rate_limit_retries=retries
    )


FAKE = r'''
import json
import os
import sys

# The plugin sanitizes the child environment (_build_subprocess_env), so
# mode/counter are baked into the script text, not passed via env vars.
mode = MODE
counter = COUNTER
spawn_index = 0
if counter:
    with open(counter, "a", encoding="utf-8") as fh:
        fh.write("spawn\n")
    spawn_index = sum(1 for _ in open(counter, encoding="utf-8"))

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def text_update(text):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
        "sessionUpdate": "agent_message_chunk",
        "content": {"type": "text", "text": text}}}})

def usage_update(used, size=1048576):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
        "sessionUpdate": "usage_update", "used": used, "size": size}}})

def tool_update(call_id, status):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
        "sessionUpdate": "tool_call" if status == "pending" else "tool_call_update",
        "toolCallId": call_id, "title": "Running run_command",
        "kind": "execute", "status": status}}})

for line in sys.stdin:
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": 1}})
    elif method == "session/new":
        if mode == "hang-new":
            continue
        session_id = f"s-{spawn_index or 1}" if mode == "quota-error" else "s-1"
        emit({"jsonrpc": "2.0", "id": rid, "result": {"sessionId": session_id}})
    elif method == "session/prompt":
        if mode == "digest-quota":
            text_update(QUOTA_TEXT)
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        elif mode == "refusal":
            text_update("I cannot help with that.")
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "refusal"}})
        elif mode == "cancelled":
            usage_update(42)
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "cancelled"}})
        elif mode == "quota-error-tools":
            tool_update("tc-1", "pending")
            emit({"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32000,
                "message": "Antigravity provider quota failure (resource_exhausted): "
                           "Usage Limit Reached"}})
        elif mode == "quota-error":
            if spawn_index == 1:
                usage_update(900000)
                emit({"jsonrpc": "2.0", "id": rid, "error": {
                    "code": -32000,
                    "message": "Antigravity provider quota failure (resource_exhausted): "
                               "Usage Limit Reached"}})
            else:
                usage_update(30)
                text_update("recovered")
                emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        elif mode == "quota-error-always":
            emit({"jsonrpc": "2.0", "id": rid, "error": {
                "code": -32000,
                "message": "Antigravity provider quota failure (resource_exhausted): "
                           "Usage Limit Reached"}})
        elif mode == "quota-then-429":
            if spawn_index == 1:
                emit({"jsonrpc": "2.0", "id": rid, "error": {
                    "code": -32000,
                    "message": "Antigravity provider quota failure (resource_exhausted): "
                               "Usage Limit Reached"}})
            elif spawn_index == 2:
                emit({"jsonrpc": "2.0", "id": rid, "error": {
                    "code": -32000,
                    "message": "Antigravity ACP session/prompt failed: 429 Too Many "
                               "Requests - rate limit exceeded"}})
            else:
                text_update("mixed-recovered")
                emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        elif mode == "429-then-recover":
            if spawn_index <= 2:
                emit({"jsonrpc": "2.0", "id": rid, "error": {
                    "code": -32000,
                    "message": "Antigravity ACP session/prompt failed: 429 Too Many "
                               "Requests - rate limit exceeded"}})
            else:
                text_update("transport-recovered")
                emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        elif mode == "dedup":
            tool_update("tc-1", "pending")
            tool_update("tc-1", "in_progress")
            tool_update("tc-1", "completed")
            text_update("fine")
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        else:
            text_update("plain answer")
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
'''

def _fake_server(tmp_path: Path, mode: str, spawn_count: Path | None = None) -> list[str]:
    script = tmp_path / "fake_acp.py"
    header = (
        f"QUOTA_TEXT = {QUOTA_HEAD!r}\n"
        f"MODE = {mode!r}\n"
        f"COUNTER = {str(spawn_count) if spawn_count is not None else ''!r}\n"
    )
    script.write_text(header + FAKE, encoding="utf-8")
    return [str(script)]


@pytest.fixture
def no_slash_env(monkeypatch):
    # Kept for call-site compatibility; mode is now baked into the fake
    # script, so nothing env-related needs cleanup.
    yield


# ------------------------------------------------- digest / stopReason


def test_quota_digest_returned_as_answer_is_suppressed(monkeypatch, tmp_path, no_slash_env) -> None:
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "digest-quota"), cwd=str(tmp_path)
    )
    with pytest.raises(Exception) as excinfo:
        client.chat.completions.create(
            model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
            timeout=10,
        )
    # Must be classified as a quota failure (retryable next turn), not an answer.
    assert "resource_exhausted" in str(excinfo.value)


def test_refusal_and_cancelled_stop_reasons_are_not_silent_success(monkeypatch, tmp_path, no_slash_env) -> None:
    for mode in ("refusal", "cancelled"):
        client = _load_client(
            monkeypatch, args=_fake_server(tmp_path, mode), cwd=str(tmp_path)
        )
        with pytest.raises(Exception) as excinfo:
            client.chat.completions.create(
                model="antigravity-acp",
                messages=[{"role": "user", "content": "hi"}], timeout=10,
            )
        assert mode in str(excinfo.value).lower()


def test_cancelled_partial_turn_does_not_expose_context_or_request_usage(
    monkeypatch, tmp_path, no_slash_env
) -> None:
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "cancelled"), cwd=str(tmp_path)
    )
    session_result = {}
    with pytest.raises(RuntimeError, match="stopReason=cancelled"):
        client._run_prompt_once(
            "partial turn", timeout_seconds=10, model="antigravity-acp",
            session_result=session_result,
        )
    assert "context_occupancy" not in session_result
    assert session_result["native_activity"]["session_updates"] >= 1


def test_end_turn_remains_normal(monkeypatch, tmp_path, no_slash_env) -> None:
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "plain"), cwd=str(tmp_path)
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10,
    )
    assert reply.choices[0].message.content == "plain answer"


# ------------------------------------------------- replay safety (S4)


def test_failover_replay_suppressed_after_native_tool_activity(monkeypatch, tmp_path, no_slash_env) -> None:
    counter = tmp_path / "spawns"
    client = _load_client(
        monkeypatch,
        args=_fake_server(tmp_path, "quota-error-tools", counter),
        cwd=str(tmp_path), retries=1,
    )
    with pytest.raises(Exception) as excinfo:
        client.chat.completions.create(
            model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
            timeout=10,
        )
    assert "resource_exhausted" in str(excinfo.value)
    assert counter.read_text(encoding="utf-8").count("spawn") == 1


def test_failover_replay_still_recovers_without_tool_activity(monkeypatch, tmp_path, no_slash_env) -> None:
    counter = tmp_path / "spawns"
    client = _load_client(
        monkeypatch,
        args=_fake_server(tmp_path, "quota-error", counter),
        cwd=str(tmp_path), retries=1,
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10,
    )
    assert reply.choices[0].message.content == "recovered"
    assert counter.read_text(encoding="utf-8").count("spawn") == 2
    telemetry = reply.antigravity_usage_telemetry
    # Issue #6 AC4-1/AC4-3: this fake self-reports no `agentInfo`, so its
    # frames are unverified — never accumulated, never synthesized into
    # completion.usage.  The failed first attempt's frame (900000) must not
    # leak into the surfaced turn's occupancy either (docs/acp-usage-telemetry.md).
    assert reply.usage is None
    assert telemetry["status"] == "unavailable"
    assert telemetry["server_consumption_semantics"] == "unverified"
    assert telemetry["turn_consumption"] is None
    assert telemetry["context_occupancy"] == {
        "source": "acp.session/update:usage_update",
        "scope": "per_model_call_consumption_delta",
        "is_billing_usage": False,
        "used": 30,
        "size": 1048576,
    }
    assert telemetry["native_session_id_hash"] == sys.modules[
        "antigravity_acp_121.client"
    ]._opaque_permission_id("s-2", "native-session")
    assert 900000 not in telemetry["context_occupancy"].values()
    assert all(value is None for value in telemetry["request_usage"].values())


def test_inband_quota_digest_replay_capped_at_one(monkeypatch, tmp_path, no_slash_env) -> None:
    # Reviewer P1: an in-band quota digest must not silently consume the
    # transport retry budget (default 2, max 8).  Even with retries=4 the
    # client gets exactly one failover replay, then the error surfaces.
    counter = tmp_path / "spawns"
    client = _load_client(
        monkeypatch,
        args=_fake_server(tmp_path, "quota-error-always", counter),
        cwd=str(tmp_path), retries=4,
    )
    with pytest.raises(Exception) as excinfo:
        client.chat.completions.create(
            model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
            timeout=10,
        )
    assert "resource_exhausted" in str(excinfo.value)
    assert counter.read_text(encoding="utf-8").count("spawn") == 2


def test_mixed_inband_then_429_sequence_stays_capped(monkeypatch, tmp_path, no_slash_env) -> None:
    # Re-review P1: an in-band quota failure spends the single replay
    # allowance; a later structured 429 must not re-arm the transport
    # budget.  Without the cap the client would reach spawn 3 and "recover".
    counter = tmp_path / "spawns"
    client = _load_client(
        monkeypatch,
        args=_fake_server(tmp_path, "quota-then-429", counter),
        cwd=str(tmp_path), retries=4,
    )
    with pytest.raises(Exception) as excinfo:
        client.chat.completions.create(
            model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
            timeout=10,
        )
    assert "429" in str(excinfo.value)
    assert counter.read_text(encoding="utf-8").count("spawn") == 2


def test_pure_transport_retry_budget_unchanged(monkeypatch, tmp_path, no_slash_env) -> None:
    # Control: a sequence with no in-band digest keeps the configured
    # transport budget (two replays here), so the mixed-sequence cap is
    # scoped to post-in-band failures only.
    counter = tmp_path / "spawns"
    client = _load_client(
        monkeypatch,
        args=_fake_server(tmp_path, "429-then-recover", counter),
        cwd=str(tmp_path), retries=2,
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10,
    )
    assert reply.choices[0].message.content == "transport-recovered"
    assert counter.read_text(encoding="utf-8").count("spawn") == 3


def test_native_tool_frames_dedupe_by_tool_call_id(monkeypatch, tmp_path, no_slash_env) -> None:
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "dedup"), cwd=str(tmp_path)
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10,
    )
    events = reply.antigravity_native_activity["native_tool_calls"]
    assert [e["tool_call_id"] for e in events] == ["tc-1"]


# ------------------------------------------------- session/new timeout


def test_session_new_timeout_is_bounded(monkeypatch, tmp_path, no_slash_env) -> None:
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "hang-new"), cwd=str(tmp_path)
    )
    started = time.monotonic()
    with pytest.raises(Exception):
        client.chat.completions.create(
            model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
            timeout=3,
        )
    assert time.monotonic() - started < 15


# --------------------------------------- permission policy (P0 / S2)


def _load_module(monkeypatch, tmp_path):
    client = _load_client(
        monkeypatch, args=[str(tmp_path / "unused.py")], cwd=str(tmp_path)
    )
    client_mod = importlib.import_module("antigravity_acp_121.client")
    return client, client_mod


def _permission(module, workspace: Path, tool_call: dict) -> str | None:
    return module._safe_read_permission_option(
        {
            "toolCall": {"kind": "other", **tool_call},
            "options": [
                {"kind": "allow_always", "optionId": "always"},
                {"kind": "allow_once", "optionId": "once"},
            ],
        },
        str(workspace),
    )


def test_mcp_origin_tools_are_never_auto_approved(monkeypatch, tmp_path) -> None:
    _, module = _load_module(monkeypatch, tmp_path)
    # Pin the scratch-evidence roots to a private fake home so assertions do
    # not depend on where pytest's tmp_path happens to live.
    fake_home = tmp_path / "fake-hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(fake_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    workspace = tmp_path / "ws"
    workspace.mkdir()
    document = workspace / "notes.md"
    document.write_text("x", encoding="utf-8")

    # MCP-flavored names with read hints must not be auto-approved.
    assert _permission(module, workspace, {
        "name": "google_workspace_read_email",
        "title": "Running google_workspace_read_email",
        "rawInput": {"absolute_path": str(document)},
    }) is None
    assert _permission(module, workspace, {
        "name": "mcp__slack__view_channel",
        "title": "view",
        "rawInput": {"absolute_path": str(document)},
    }) is None
    # Unknown tool with a generic read title is also rejected.
    assert _permission(module, workspace, {
        "name": "totally_new_vendor_tool",
        "title": "Reading remote vault",
        "rawInput": {"absolute_path": str(document)},
    }) is None
    # A nameless partial frame is never auto-approved: a title is not an
    # origin proof, so nameless frames stay cancelled (selection is up to
    # explicit user input).
    assert _permission(module, workspace, {
        "title": "View file",
        "rawInput": {"absolute_path": str(document)},
    }) is None
    # Spoofed title on an MCP-namespaced name: the exact name decides,
    # the title must never be able to fake native origin.
    assert _permission(module, workspace, {
        "name": "mcp__example__read_email",
        "title": "Running view_file",
        "rawInput": {"absolute_path": str(document)},
    }) is None


def test_known_native_read_tools_keep_allow_once(monkeypatch, tmp_path) -> None:
    _, module = _load_module(monkeypatch, tmp_path)
    workspace = tmp_path / "ws"
    workspace.mkdir()
    document = workspace / "notes.md"
    document.write_text("x", encoding="utf-8")

    assert _permission(module, workspace, {
        "name": "safe_view_file",
        "title": "Viewing notes",
        "rawInput": {"absolute_path": str(document)},
    }) == "once"
    assert _permission(module, workspace, {
        "name": "client_view_file",
        "title": "Running client_view_file",
        "rawInput": {"absolute_path": str(document)},
    }) == "once"
    # Exact-match boundary: near-miss names are not native tools.
    assert _permission(module, workspace, {
        "name": "client_view_file_v2",
        "title": "View file",
        "rawInput": {"absolute_path": str(document)},
    }) is None
    assert _permission(module, workspace, {
        "name": "search_directory",
        "title": "Searching",
        "rawInput": {"directory_path": str(workspace)},
    }) == "once"


def test_vendor_credential_paths_are_protected_everywhere(monkeypatch, tmp_path) -> None:
    _, module = _load_module(monkeypatch, tmp_path)
    home = tmp_path / "home"
    token = home / ".gemini" / "antigravity-acp" / "acp_token.json"
    token.parent.mkdir(parents=True)
    token.write_text('{"token": "secret"}', encoding="utf-8")
    mcp = home / ".gemini" / "config" / "mcp_config.json"
    mcp.parent.mkdir(parents=True)
    mcp.write_text("{}", encoding="utf-8")

    for protected in (token, mcp):
        with pytest.raises(PermissionError):
            module._safe_path(str(protected), str(home), verb="Read")
        with pytest.raises(PermissionError):
            module._fs_read_text_file({"path": str(protected)}, str(home))
        assert _permission(module, home, {
            "name": "safe_view_file",
            "title": "Viewing token",
            "rawInput": {"absolute_path": str(protected)},
        }) is None
