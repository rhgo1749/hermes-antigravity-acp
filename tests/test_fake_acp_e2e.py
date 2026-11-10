"""Protocol-level E2E against a fake ACP subprocess (no live credentials)."""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = (
    Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"
)


def _load_client(monkeypatch, *, command: str, args: list[str], cwd: str):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(Path(cwd) / "acp-conversation-state.json"),
    )
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

    module_name = "antigravity_acp_fake_e2e"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location(
        module_name,
        PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module.antigravity_acp.create_client(
        command=command,
        args=args,
        acp_cwd=cwd,
        rate_limit_retries=0,
    )


def _run_tool_bridge_activity(monkeypatch, tmp_path: Path, tools, messages, current_tool_calls=None):
    _load_client(monkeypatch, command=sys.executable, args=[], cwd=str(tmp_path))
    client_module = sys.modules["antigravity_acp_fake_e2e.client"]
    return client_module._tool_bridge_activity(
        tools, messages, current_tool_calls or []
    )


def _write_fake_server(
    tmp_path: Path,
    *,
    session_error: dict | None = None,
    session_result: dict | None = None,
    resume_result: dict[str, object] | None = None,
) -> tuple[Path, Path]:
    script = tmp_path / "fake_acp_server.py"
    log_path = tmp_path / "fake_acp_log.jsonl"
    script.write_text(
        f"SESSION_ERROR = {session_error!r}\n"
        f"SESSION_RESULT = {session_result!r}\n"
        + f"SESSION_RESUME_RESULT = {resume_result!r}\n"
        + r'''
import json
import os
import sys

log_path = sys.argv[1]

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def log(payload):
    row = {
        "affinity": os.environ.get("ACP_MUX_AFFINITY", ""),
        "affinity_pin": os.environ.get("ACP_MUX_AFFINITY_PIN", ""),
        "affinity_ttl": os.environ.get("ACP_MUX_AFFINITY_TTL_SECONDS", ""),
        "affinity_max_entries": os.environ.get("ACP_MUX_AFFINITY_MAX_ENTRIES", ""),
        "mux_session_id": os.environ.get("ACP_MUX_SESSION_ID", ""),
        "mux_session_gc": os.environ.get("ACP_MUX_SESSION_GC", ""),
        **payload,
    }
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")

def await_permission_response(expected_id):
    line = sys.stdin.readline()
    if not line:
        raise RuntimeError("client closed stdin before answering permission request")
    reply = json.loads(line)
    log({
        "id": reply.get("id"),
        "method": reply.get("method"),
        "params": reply.get("params"),
        "result": reply.get("result"),
    })
    if reply.get("id") != expected_id:
        raise RuntimeError(f"unexpected permission response id: {reply.get('id')}")

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    params = msg.get("params") or {}
    log({"id": msg.get("id"), "method": method, "params": params, "result": msg.get("result")})
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/new":
        if SESSION_ERROR is not None:
            emit({"jsonrpc": "2.0", "id": msg["id"], "error": SESSION_ERROR})
            continue
        session_result = SESSION_RESULT or {
            "sessionId": "session-1",
            "configOptions": [{
                "id": "model",
                "category": "model",
                "currentValue": "gemini-3.8-flash-high",
                "options": [
                    {"value": "gemini-3.1-pro"},
                    {"value": "gemini-3.8-flash-high"},
                ],
            }],
        }
        emit({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": session_result,
        })
    elif method == "session/resume":
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": SESSION_RESUME_RESULT or {}})
    elif method in ("session/set_config_option", "session/set_model"):
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/prompt":
        text = ((params.get("prompt") or [{}])[0].get("text") or "")
        if "pre-tool denial" in text and "Google-native web pre-tool denial" not in text:
            emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                "sessionUpdate": "tool_call",
                "toolCallId": "native-denied-1",
                "name": "run_command",
                "title": "Running run_command",
                "kind": "execute",
                "status": "in_progress",
                "rawInput": {"command": "SECRET_COMMAND_BODY"},
            }}})
            emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "native-denied-1",
                "name": "run_command",
                "title": "Running run_command",
                "kind": "execute",
                "status": "failed",
                "rawOutput": {"error": "denied by pre-tool hook: Denied by user (*)"},
            }}})
            response = "native tool denied"
        elif "Google-native web pre-tool denial" in text and "<tool_response>" not in text:
            emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                "sessionUpdate": "tool_call",
                "toolCallId": "native-web-denied-1",
                "name": "vendor_web_lookup",
                "origin": "native_acp",
                "title": "Searching the web",
                "kind": "search",
                "status": "in_progress",
                "rawInput": {"query": "PRIVATE_QUERY_MUST_NOT_BE_LOGGED"},
            }}})
            emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "native-web-denied-1",
                "name": "vendor_web_lookup",
                "origin": "native_acp",
                "title": "Searching the web",
                "kind": "search",
                "status": "failed",
                "rawOutput": {"error": "denied by pre-tool hook"},
            }}})
            response = '<tool_call>{"id":"web-fallback-1","type":"function","function":{"name":"web_search","arguments":"{\\"query\\":\\"public source lookup\\"}"}}</tool_call>'
        elif "web research unadvertised call" in text:
            response = '<tool_call>{"id":"web-unadvertised-1","type":"function","function":{"name":"web_search","arguments":"{\\"query\\":\\"public source lookup\\"}"}}</tool_call>'
        elif "web research unavailable" in text:
            response = "NOT AVAILABLE: no authorized Hermes web_search capability was advertised. The current-source research objective remains unresolved; no live sources were verified."
        elif "web research not attempted" in text:
            response = "NOT ATTEMPTED: the advertised web_search tool was not called. The current-source research objective remains unresolved."
        elif "web research authorized lookup" in text and "<tool_response>" not in text:
            response = '<tool_call>{"id":"web-search-call-1","type":"function","function":{"name":"web_search","arguments":"{\\"query\\":\\"public source lookup\\"}"}}</tool_call>'
        elif "native web permission rejection" in text and "<tool_response>" not in text:
            emit({"jsonrpc": "2.0", "id": 902, "method": "session/request_permission", "params": {
                "toolCall": {
                    "toolCallId": "native-web-permission-902",
                    "name": "vendor_web_lookup",
                    "origin": "native_acp",
                    "title": "Searching the public web",
                    "kind": "search",
                    "rawInput": {"query": "PRIVATE_QUERY_MUST_NOT_BE_LOGGED"},
                },
                "options": [
                    {"optionId": "allow-web-902", "kind": "allow_once"},
                    {"optionId": "reject-web-902", "kind": "reject_once"},
                ],
            }})
            await_permission_response(902)
            response = '<tool_call>{"id":"web-search-fallback-902","type":"function","function":{"name":"web_search","arguments":"{\\"query\\":\\"public source lookup\\"}"}}</tool_call>'
        elif "permission rejection" in text:
            emit({"jsonrpc": "2.0", "id": 900, "method": "session/request_permission", "params": {
                "toolCall": {
                    "toolCallId": "native-run-900",
                    "name": "run_command",
                    "title": "Running run_command",
                    "kind": "execute",
                    "rawInput": {"command": "pwd"},
                },
                "options": [
                    {"optionId": "allow-900", "kind": "allow_once"},
                    {"optionId": "reject-900", "kind": "reject_once"},
                ],
            }})
            await_permission_response(900)
            response = "permission response recorded"
        elif (
            "<ACTIVE_REQUEST>\n" in text
            and "Use the previously accessed Krafton API to write prose."
            in text.split("<ACTIVE_REQUEST>\n", 1)[1].split("</ACTIVE_REQUEST>", 1)[0]
        ):
            emit({"jsonrpc": "2.0", "id": 901, "method": "session/request_permission", "params": {
                "toolCall": {
                    "toolCallId": "native-prose-write-901",
                    "name": "run_command",
                    "title": "Running run_command",
                    "kind": "execute",
                    "rawInput": {"command": "synthetic Krafton prose write"},
                },
                "options": [
                    {"optionId": "allow-prose-901", "kind": "allow_once"},
                    {"optionId": "reject-prose-901", "kind": "reject_once"},
                ],
            }})
            await_permission_response(901)
            response = "Krafton prose write denied; no API request was executed."
        elif "actual cancellation" in text:
            response = "cancelled response should not surface"
        elif "native inspect" in text:
            emit({
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {"update": {
                    "sessionUpdate": "tool_call",
                    "toolCallId": "native-1",
                    "title": "Running client_view_file",
                    "kind": "read",
                    "status": "in_progress",
                    "rawInput": {"absolute_path": "/tmp/source.py", "start_line": 10, "end_line": 12},
                }},
            })
            emit({
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {"update": {
                    "sessionUpdate": "tool_call_update",
                    "toolCallId": "native-1",
                    "status": "completed",
                }},
            })
            response = "native result"
        elif "<tool_response>" in text:
            for used in (11840, 12000):
                emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                    "sessionUpdate": "usage_update", "used": used, "size": 1048576}}})
            if "https://example.test/source" in text:
                response = "The returned Hermes web_search result contains https://example.test/source; research is based only on that supplied result."
            elif any(
                f"preserve this objective: {status}." in text
                for status in ("DENIED", "CANCELLED", "FAILED")
            ):
                status = next(
                    status
                    for status in ("DENIED", "CANCELLED", "FAILED")
                    if f"preserve this objective: {status}." in text
                )
                response = (
                    f"{status}: the current-source research objective remains unresolved; "
                    "no current sources were verified."
                )
            else:
                response = "done after tool result"
        elif "inspect" in text:
            response = '<tool_call>{"id":"call-1","type":"function","function":{"name":"read_state","arguments":"{\\"path\\":\\"x\\"}"}}</tool_call>'
        else:
            response = "normal response"
        emit({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "update": {
                    "sessionUpdate": "agent_message_chunk",
                    "content": {"type": "text", "text": response},
                }
            },
        })
        result = {"stopReason": "cancelled"} if "actual cancellation" in text else {}
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": result})
'''.lstrip(),
        encoding="utf-8",
    )
    return script, log_path


def _tool_schema():
    return {
        "type": "function",
        "function": {
            "name": "read_state",
            "description": "Read state",
            "parameters": {"type": "object", "properties": {}},
        },
    }


def _resumed_tool_request(client):
    tools = [_tool_schema()]
    first_messages = [{"role": "user", "content": "inspect"}]
    first = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=first_messages,
        tools=tools,
    )
    assert first.model == "gemini-3.8-flash-high"
    call = first.choices[0].message.tool_calls[0]
    resumed_messages = [
        *first_messages,
        {
            "role": "assistant",
            "content": first.choices[0].message.content,
            "tool_calls": [{
                "id": call.id,
                "type": call.type,
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments,
                },
            }],
        },
        {
            "role": "tool",
            "tool_call_id": call.id,
            "name": call.function.name,
            "content": '{"value":1}',
        },
    ]
    return tools, resumed_messages


def test_acp_error_surfaces_code_and_sanitized_data_message(
    monkeypatch, tmp_path
) -> None:
    cases = [
        (None, "Authentication required; access_token=TOP_LEVEL_SECRET", None),
        (
            "Authentication failed: access_token=ACCESS_TOKEN_SECRET; "
            "Bearer BEARER_SECRET; authorization code: AUTH_CODE_SECRET; "
            "authorization code AUTH1234; callback "
            "https://accounts.google.com/o/oauth2/auth?client_id=safe&"
            "code=OAUTH_CODE_SECRET&state=safe",
            "Authentication required",
            "Authentication failed",
        ),
        (
            'Auth flow context: {"refresh_token" : "REFRESH_SECRET", '
            '"trace_id": "safe-trace"}',
            'Authentication required; response={"access_token": "TOP_SECRET"}',
            "Auth flow context",
        ),
        (
            r'Escaped auth context: {\"refresh_token\":\"REFRESH_SECRET\", '
            r'\"trace_id\":\"safe-trace\"}',
            r'Authentication required; response={\"access_token\":\"TOP_SECRET\"}',
            "Escaped auth context",
        ),
        ("Useful auth detail " + "x" * 600, "Authentication required", "Useful auth detail"),
    ]
    for data_message, error_message, expected_detail in cases:
        error = {"code": -32000, "message": error_message}
        if data_message is not None:
            error["data"] = {"message": data_message}
        script, _ = _write_fake_server(tmp_path, session_error=error)
        client = _load_client(
            monkeypatch,
            command=sys.executable,
            args=[str(script), str(tmp_path / "fake_acp_log.jsonl")],
            cwd=str(tmp_path),
        )

        try:
            client.chat.completions.create(
                model="antigravity-acp",
                messages=[{"role": "user", "content": "hello"}],
            )
        except RuntimeError as exc:
            diagnostic = str(exc)
        else:
            raise AssertionError("fake ACP JSON-RPC error was not surfaced")

        assert "code=-32000" in diagnostic
        assert "Authentication required" in diagnostic
        if expected_detail is None:
            assert "data.message" not in diagnostic
        else:
            assert expected_detail in diagnostic
            data_detail = diagnostic.split("data.message=", 1)[1]
            assert len(data_detail) <= 512
            if data_message is not None and len(data_message) > 512:
                assert data_detail.endswith("…")
        assert "TOP_LEVEL_SECRET" not in diagnostic
        if "TOP_SECRET" in error_message:
            assert "TOP_SECRET" not in diagnostic
            assert "REFRESH_SECRET" not in diagnostic
            assert "[REDACTED]" in diagnostic
            assert "safe-trace" in diagnostic
            if r'\"' in error_message:
                assert "access_token" in diagnostic
                assert "refresh_token" in diagnostic
                assert diagnostic.count("[REDACTED]") >= 2
            else:
                assert '"access_token": [REDACTED]' in diagnostic
                assert '"refresh_token" : [REDACTED]' in diagnostic
                assert '"trace_id": "safe-trace"' in diagnostic
        if data_message and "ACCESS_TOKEN_SECRET" in data_message:
            assert "access_token=[REDACTED]" in diagnostic
            assert "Bearer [REDACTED]" in diagnostic
            assert "authorization code: [REDACTED]" in diagnostic
            assert "[REDACTED_OAUTH_URL]" in diagnostic
            for secret in (
                "ACCESS_TOKEN_SECRET",
                "BEARER_SECRET",
                "AUTH_CODE_SECRET",
                "AUTH1234",
                "OAUTH_CODE_SECRET",
            ):
                assert secret not in diagnostic


def test_unoffered_model_records_effective_session_default_in_completion(
    monkeypatch, tmp_path, caplog
) -> None:
    script, _ = _write_fake_server(
        tmp_path,
        session_result={
            "sessionId": "session-default",
            "configOptions": [{
                "id": "model",
                "category": "model",
                "currentValue": "gemini-3.1-pro",
                "options": [{"value": "gemini-3.1-pro"}],
            }],
        },
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(tmp_path / "fake_acp_log.jsonl")],
        cwd=str(tmp_path),
    )

    completion = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        messages=[{"role": "user", "content": "hello"}],
    )

    assert completion.model == "gemini-3.1-pro"
    assert completion.antigravity_usage_telemetry["model"] == "gemini-3.1-pro"
    assert "using the session default" in caplog.text
    assert "'gemini-3.8-flash-high'" in caplog.text
    assert "'gemini-3.1-pro' (effective model)" in caplog.text


def test_unoffered_model_persists_effective_model_across_resume(
    monkeypatch, tmp_path
) -> None:
    script, log_path = _write_fake_server(
        tmp_path,
        session_result={
            "sessionId": "session-default",
            "configOptions": [{
                "id": "model",
                "category": "model",
                "currentValue": "gemini-3.8-flash-high",
                "options": [{"value": "gemini-3.8-flash-high"}],
            }],
        },
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    tools = [_tool_schema()]
    first_messages = [{"role": "user", "content": "inspect"}]

    first = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=first_messages,
        tools=tools,
    )
    assert first.model == "gemini-3.8-flash-high"
    call = first.choices[0].message.tool_calls[0]
    resumed_messages = [
        *first_messages,
        {
            "role": "assistant",
            "content": first.choices[0].message.content,
            "tool_calls": [{
                "id": call.id,
                "type": call.type,
                "function": {
                    "name": call.function.name,
                    "arguments": call.function.arguments,
                },
            }],
        },
        {
            "role": "tool",
            "tool_call_id": call.id,
            "name": call.function.name,
            "content": '{"value":1}',
        },
    ]

    # Rebuilding the provider reloads the persisted conversation state. The fake
    # session/resume response intentionally contains only an empty result.
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    resumed = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=resumed_messages,
        tools=tools,
    )

    assert resumed.model == "gemini-3.8-flash-high"
    assert resumed.antigravity_usage_telemetry["model"] == "gemini-3.8-flash-high"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert any(row["method"] == "session/resume" for row in rows)


def test_resumed_session_with_server_reported_model_is_accepted(
    monkeypatch, tmp_path
) -> None:
    active_model = "gemini-3.8-flash-high"
    model_option = {
        "id": "model",
        "category": "model",
        "currentValue": active_model,
        "options": [{"value": active_model}],
    }
    script, log_path = _write_fake_server(
        tmp_path,
        session_result={"sessionId": "session-reported", "configOptions": [model_option]},
        resume_result={
            "sessionId": "session-reported",
            "configOptions": [model_option],
        },
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    tools, resumed_messages = _resumed_tool_request(client)

    state_path = tmp_path / "acp-conversation-state.json"
    checkpoint = json.loads(state_path.read_text(encoding="utf-8"))
    matching_states = [
        state
        for state in checkpoint["states"].values()
        if state["session_id"] == "session-reported"
    ]
    assert len(matching_states) == 1
    matching_states[0]["effective_model"] = ""
    state_path.write_text(json.dumps(checkpoint), encoding="utf-8")

    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    resumed = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=resumed_messages,
        tools=tools,
    )

    assert resumed.model == active_model
    assert resumed.antigravity_usage_telemetry["model"] == active_model


def test_resumed_session_with_legacy_checkpoint_without_server_model_fails_explicitly(
    monkeypatch, tmp_path
) -> None:
    active_model = "gemini-3.8-flash-high"
    script, log_path = _write_fake_server(
        tmp_path,
        session_result={
            "sessionId": "session-legacy",
            "configOptions": [{
                "id": "model",
                "category": "model",
                "currentValue": active_model,
                "options": [{"value": active_model}],
            }],
        },
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    tools, resumed_messages = _resumed_tool_request(client)

    state_path = tmp_path / "acp-conversation-state.json"
    checkpoint = json.loads(state_path.read_text(encoding="utf-8"))
    matching_states = [
        state
        for state in checkpoint["states"].values()
        if state["session_id"] == "session-legacy"
    ]
    assert len(matching_states) == 1
    matching_states[0]["effective_model"] = ""
    state_path.write_text(json.dumps(checkpoint), encoding="utf-8")

    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    try:
        client.chat.completions.create(
            model="gemini-3.1-pro",
            messages=resumed_messages,
            tools=tools,
        )
    except RuntimeError as exc:
        assert "cannot determine the active model" in str(exc)
        assert "refusing to claim" in str(exc)
    else:
        raise AssertionError("resumed session with unknown model was not rejected")


def test_resumed_session_with_mismatched_session_id_without_server_model_fails_explicitly(
    monkeypatch, tmp_path
) -> None:
    active_model = "gemini-3.8-flash-high"
    script, log_path = _write_fake_server(
        tmp_path,
        session_result={
            "sessionId": "session-original",
            "configOptions": [{
                "id": "model",
                "category": "model",
                "currentValue": active_model,
                "options": [{"value": active_model}],
            }],
        },
        resume_result={"sessionId": "session-mismatch"},
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    tools, resumed_messages = _resumed_tool_request(client)

    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    try:
        client.chat.completions.create(
            model="gemini-3.1-pro",
            messages=resumed_messages,
            tools=tools,
        )
    except RuntimeError as exc:
        assert "cannot determine the active model" in str(exc)
        assert "refusing to claim" in str(exc)
    else:
        raise AssertionError("resumed session with mismatched state was not rejected")


def test_unoffered_model_without_reported_default_fails_explicitly(
    monkeypatch, tmp_path
) -> None:
    script, _ = _write_fake_server(
        tmp_path,
        session_result={
            "sessionId": "session-no-default",
            "configOptions": [{
                "id": "model",
                "category": "model",
                "options": [{"value": "gemini-3.1-pro"}],
            }],
        },
    )
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(tmp_path / "fake_acp_log.jsonl")],
        cwd=str(tmp_path),
    )

    try:
        client.chat.completions.create(
            model="not-offered",
            messages=[{"role": "user", "content": "hello"}],
        )
    except RuntimeError as exc:
        assert "does not report the active session model" in str(exc)
    else:
        raise AssertionError("unknown effective model was not rejected")


def test_fake_subprocess_normal_tool_turn_and_native_resume(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_TTL_SECONDS", "86400")
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_MAX_ENTRIES", "512")
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )

    normal = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=[{"role": "user", "content": "hello"}],
    )
    assert normal.choices[0].message.content == "normal response"
    assert normal.usage is None
    assert normal.antigravity_usage_telemetry["status"] == "unavailable"
    assert normal.antigravity_usage_telemetry["context_occupancy"] is None
    assert all(value is None for value in normal.antigravity_usage_telemetry["request_usage"].values())
    assert normal.antigravity_native_activity["session_updates"] >= 1
    assert normal.antigravity_native_activity["update_kinds"]["agent_message_chunk"] >= 1

    native = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=[{"role": "user", "content": "native inspect"}],
    )
    assert native.choices[0].message.content == "native result"
    assert not native.choices[0].message.tool_calls
    assert native.choices[0].finish_reason == "stop"
    native_details = native.choices[0].message.reasoning_details
    assert native_details == [{
        "type": "antigravity_native_tool",
        "tool_call_id": "native-1",
        "title": "Running client_view_file",
        "kind": "read",
        "status": "completed",
        "input": {"absolute_path": "/tmp/source.py", "start_line": 10, "end_line": 12},
    }]
    native_call = native.antigravity_native_activity["native_tool_calls"][0]
    assert {key: native_call[key] for key in native_details[0]} == native_details[0]
    assert native_call["origin"] == "unknown"
    assert native_call["tool_call_id_hash"].startswith("sha256:")
    assert native.antigravity_usage_telemetry["status"] == "unavailable"
    assert native.antigravity_usage_telemetry["context_occupancy"] is None

    tools = [_tool_schema()]
    first_messages = [{"role": "user", "content": "inspect"}]
    first = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=first_messages,
        tools=tools,
    )
    call = first.choices[0].message.tool_calls[0]
    assert call.id == "call-1"
    assert call.function.name == "read_state"
    assert first.usage is None
    assert first.antigravity_usage_telemetry["context_occupancy"] is None

    second_messages = [
        *first_messages,
        {
            "role": "assistant",
            "content": first.choices[0].message.content,
            "tool_calls": [
                {
                    "id": call.id,
                    "type": call.type,
                    "function": {
                        "name": call.function.name,
                        "arguments": call.function.arguments,
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": call.id,
            "name": call.function.name,
            "content": '{"value":1}',
        },
    ]
    second = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=second_messages,
        tools=tools,
    )
    assert second.choices[0].message.content == "done after tool result"
    assert second.usage is None
    assert second.antigravity_usage_telemetry["request_usage"] == first.antigravity_usage_telemetry["request_usage"]
    assert second.antigravity_usage_telemetry["context_occupancy"] == {
        "source": "acp.session/update:usage_update",
        "scope": "per_model_call_consumption_delta",
        "is_billing_usage": False,
        "used": 12000,
        "size": 1048576,
    }
    assert (
        second.antigravity_usage_telemetry["native_session_id_hash"]
        == first.antigravity_usage_telemetry["native_session_id_hash"]
    )
    assert second.antigravity_usage_telemetry["turn_id_hash"] != first.antigravity_usage_telemetry["turn_id_hash"]

    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    methods = [row["method"] for row in rows]
    assert "session/new" in methods
    assert "session/resume" in methods
    for row in rows:
        if row.get("method") in {"session/new", "session/resume"}:
            assert row["params"].get("_meta") == {"agy": {"disabledTools": ["run_command"]}}
            assert row["params"]["mcpServers"] == []
            assert row["affinity_ttl"] == "86400"
            assert row["affinity_max_entries"] == "512"
            assert row["affinity_pin"] == (
                "1" if row["method"] == "session/resume" else "0"
            )
            assert row["mux_session_id"] == (
                "session-1" if row["method"] == "session/resume" else ""
            )
            assert row["mux_session_gc"] == "1"
    resumed = next(row for row in rows if row["method"] == "session/resume")
    assert resumed["params"]["sessionId"] == "session-1"

    inspect_prompts = [
        row for row in rows
        if row["method"] == "session/prompt"
        and "inspect" in ((row["params"].get("prompt") or [{}])[0].get("text") or "")
    ]
    assert inspect_prompts
    continuation = next(
        row for row in rows
        if row["method"] == "session/prompt"
        and "Hermes continuation delta" in ((row["params"].get("prompt") or [{}])[0].get("text") or "")
    )
    assert "<tool_response>" in continuation["params"]["prompt"][0]["text"]
    assert inspect_prompts[-1]["affinity"] == continuation["affinity"]
    assert continuation["affinity"].startswith("sha256:")


def test_fake_pre_tool_denial_is_distinguished_without_permission_response(
    monkeypatch, tmp_path, caplog
) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    caplog.set_level(logging.INFO)

    completion = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=[{"role": "user", "content": "pre-tool denial"}],
    )

    assert completion.choices[0].message.content == "native tool denied"
    telemetry = [
        json.loads(record.getMessage().split("Antigravity ACP permission telemetry ", 1)[1])
        for record in caplog.records
        if "Antigravity ACP permission telemetry " in record.getMessage()
    ]
    assert len(telemetry) == 1
    event = telemetry[0]
    assert event["decision_stage"] == "server_pre_tool"
    assert event["server_outcome"] == "denied"
    assert event["tool_name"] == "run_command"
    assert event["tool_origin"] == "native_acp"
    assert event["session_id_hash"].startswith("sha256:")
    assert event["turn_id_hash"].startswith("sha256:")
    assert event["tool_call_id_hash"].startswith("sha256:")
    assert "SECRET_COMMAND_BODY" not in caplog.text

    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert not any(row.get("id") == 900 for row in rows)


def test_fake_permission_request_selects_offered_reject_option(
    monkeypatch, tmp_path
) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )

    completion = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=[{"role": "user", "content": "permission rejection"}],
    )

    assert completion.choices[0].message.content == "permission response recorded"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    response = next(row for row in rows if row.get("id") == 900)
    assert response["result"]["outcome"] == {
        "outcome": "selected", "optionId": "reject-900"
    }


def test_fake_native_web_permission_reject_keeps_hermes_fallback_separate(
    monkeypatch, tmp_path, caplog
) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    caplog.set_level(logging.INFO)

    completion = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        messages=[{
            "role": "user",
            "content": "native web permission rejection: research current public sources",
        }],
        tools=[_web_search_tool_schema()],
    )

    call = completion.choices[0].message.tool_calls[0]
    assert call.function.name == "web_search"
    assert completion.antigravity_native_activity["permission_denied"]
    assert completion.antigravity_tool_bridge["web_research_status"] == "PENDING"
    permission_response = next(
        json.loads(record.getMessage().split("Antigravity ACP permission telemetry ", 1)[1])
        for record in caplog.records
        if "Antigravity ACP permission telemetry " in record.getMessage()
    )
    assert permission_response["decision_stage"] == "harness_permission_response"
    assert permission_response["tool_name"] == "vendor_web_lookup"
    assert permission_response["tool_origin"] == "native_acp"
    assert permission_response["offered_option_kinds"] == ["allow_once", "reject_once"]
    assert permission_response["selected_option_kind"] == "reject_once"
    assert permission_response["tool_outcome"] == "permission_denied_not_executed"

    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    response = next(row for row in rows if row.get("id") == 902)
    assert response["result"]["outcome"] == {
        "outcome": "selected", "optionId": "reject-web-902"
    }
    assert not [
        row for row in rows
        if row.get("method") == "session/update"
        and (row.get("params") or {}).get("update", {}).get("sessionUpdate")
        in {"tool_call", "tool_call_update"}
    ]
    assert "PRIVATE_QUERY_MUST_NOT_BE_LOGGED" not in caplog.text


def test_fake_actual_turn_cancellation_remains_an_error(monkeypatch, tmp_path) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )

    try:
        client.chat.completions.create(
            model="gemini-3.1-pro",
            messages=[{"role": "user", "content": "actual cancellation"}],
        )
    except RuntimeError as exc:
        assert "stopReason=cancelled" in str(exc)
    else:
        raise AssertionError("a cancelled ACP turn must not surface as a successful answer")


def test_full_replay_prompt_orders_primer_before_history_e2e(monkeypatch, tmp_path) -> None:
    """historical reference: through the real bootstrap path against a fake ACP subprocess,
    the wire prompt must carry the primer band ahead of history."""
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch, command=sys.executable, args=[str(script), str(log_path)], cwd=str(tmp_path)
    )
    messages = [
        {"role": "user", "content": "업데이트 정상됐다는거네"},
        {"role": "assistant", "content": "게이트웨이(PID 1234) 정상입니다. the change 42/42 통과."},
        {"role": "user", "content": "커밋 2e3efa 반영됐나"},
        {"role": "assistant", "content": "네, production에 반영되었습니다."},
        {"role": "user", "content": "FDE가 무엇인지 ppt 하나 만들어줘"},
    ]
    completion = client.chat.completions.create(
        model="gemini-3.8-flash-high", messages=messages
    )
    assert completion.choices[0].message.content == "normal response"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    prompts = [
        ((row.get("params") or {}).get("prompt") or [{}])[0].get("text") or ""
        for row in rows
        if row.get("method") == "session/prompt"
    ]
    assert prompts
    wire_prompt = prompts[0]
    primer_at = wire_prompt.find("<ACTIVE_REQUEST_PRIMER>")
    hist_at = wire_prompt.find("<HISTORICAL_CONTEXT>")
    active_at = wire_prompt.find("<ACTIVE_REQUEST>\n")
    assert 0 <= primer_at < hist_at < active_at
    assert "FDE가 무엇인지 ppt 하나 만들어줘" in wire_prompt[primer_at:hist_at]


def test_fake_acp_intent_drift_after_model_switch_replay_and_reject_once(
    monkeypatch, tmp_path, caplog
) -> None:
    """Discriminate prompt continuity from denial recovery using fake ACP only.

    The Krafton history and model labels are synthetic inputs; no Krafton/API or
    real ACP request is made, and the fake server never executes the rejected call.
    """
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    caplog.set_level(logging.INFO)

    prose_objective = "Use the previously accessed Krafton API to write prose."
    elliptical_followup = "아까는 요청해봤잖아"
    krafton_history = [
        {"role": "system", "content": "You are Hermes in a synthetic conversation."},
        {"role": "user", "content": "List the Krafton API capabilities."},
        {
            "role": "assistant",
            "content": "I completed the prior Krafton API capability lookup.",
            "tool_calls": [
                {
                    "id": "krafton-capabilities-call-1",
                    "type": "function",
                    "function": {
                        "name": "krafton_api_read",
                        "arguments": '{"operation":"list_capabilities"}',
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": "krafton-capabilities-call-1",
            "name": "krafton_api_read",
            "content": "Completed synthetic lookup: reasoning and prose generation are available.",
        },
        {
            "role": "assistant",
            "content": "The prior API lookup found reasoning and prose-generation capabilities.",
        },
    ]

    # Prime the same synthetic conversation under the previous model label.
    prior = client.chat.completions.create(
        model="krafton-30b",
        messages=krafton_history,
    )
    assert prior.choices[0].message.content == "done after tool result"

    switched_messages = [
        *krafton_history,
        {"role": "assistant", "content": prior.choices[0].message.content},
        {"role": "user", "content": prose_objective},
    ]
    denied = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        messages=switched_messages,
    )
    assert denied.choices[0].message.content == (
        "Krafton prose write denied; no API request was executed."
    )
    assert denied.antigravity_native_activity.get("native_tool_calls", []) == []

    checkpoint = Path(tmp_path) / "acp-conversation-state.json"
    checkpoint_text = checkpoint.read_text(encoding="utf-8")
    checkpoint_state = next(iter(json.loads(checkpoint_text)["states"].values()))
    denied_fingerprint = checkpoint_state["denied_request_fingerprint"]
    assert len(denied_fingerprint) == 64
    assert all(char in "0123456789abcdef" for char in denied_fingerprint)
    assert prose_objective not in checkpoint_text
    assert "synthetic Krafton prose write" not in checkpoint_text

    followup_messages = [
        *switched_messages,
        {"role": "assistant", "content": denied.choices[0].message.content},
        {"role": "user", "content": elliptical_followup},
    ]
    followup = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        messages=followup_messages,
    )
    assert followup.choices[0].message.content == "normal response"

    replay_lines = [
        record.getMessage()
        for record in caplog.records
        if "ACP full replay: reason=" in record.getMessage()
    ]
    assert any(
        "reason=frontier_mismatch" in line
        and "model=gemini-3.8-flash-high" in line
        and "effective_model=unknown" in line
        and "section_order=SYSTEM_INSTRUCTIONS,ACTIVE_REQUEST_PRIMER,HISTORICAL_CONTEXT,ACTIVE_REQUEST"
        in line
        for line in replay_lines
    ), replay_lines
    continuation_lines = [
        record.getMessage()
        for record in caplog.records
        if "ACP continuation:" in record.getMessage()
    ]
    assert len(continuation_lines) == 1
    assert "reason=continuation_delta" in continuation_lines[0]
    assert "intent_owner=prior_denied_request_followup" in continuation_lines[0]
    assert "tool_outcome=permission_denied_not_executed" in continuation_lines[0]
    assert (
        "section_order=ACTIVE_REQUEST_ANCHOR,UNRESOLVED_USER_OBJECTIVE,LATEST_USER_FOLLOW_UP"
        in continuation_lines[0]
    )
    assert "requested_model=gemini-3.8-flash-high" in continuation_lines[0]
    assert "effective_model=unknown" in continuation_lines[0]
    assert prose_objective not in caplog.text

    rows = [
        json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    prompts = [
        ((row.get("params") or {}).get("prompt") or [{}])[0].get("text") or ""
        for row in rows
        if row.get("method") == "session/prompt"
    ]
    assert len(prompts) == 3
    _, denied_prompt, followup_prompt = prompts

    historical = denied_prompt.split("<HISTORICAL_CONTEXT>\n", 1)[1].split(
        "</HISTORICAL_CONTEXT>", 1
    )[0]
    active = denied_prompt.split("<ACTIVE_REQUEST>\n", 1)[1].split(
        "</ACTIVE_REQUEST>", 1
    )[0]
    assert "List the Krafton API capabilities." in historical
    assert "krafton-capabilities-call-1" in historical
    assert "<tool_response>" in historical
    assert "Completed synthetic lookup" in historical
    assert prose_objective not in historical
    assert prose_objective in active
    assert "List the Krafton API capabilities." not in active

    permission_responses = [
        row
        for row in rows
        if row.get("id") == 901 and (row.get("result") or {}).get("outcome")
    ]
    assert len(permission_responses) == 1
    permission_response = permission_responses[0]
    assert permission_response["result"]["outcome"] == {
        "outcome": "selected",
        "optionId": "reject-prose-901",
    }
    execution_updates = [
        row
        for row in rows
        if row.get("method") == "session/update"
        and (row.get("params") or {}).get("update", {}).get("sessionUpdate")
        in {"tool_call", "tool_call_update"}
    ]
    assert execution_updates == []
    permission_events = [
        json.loads(
            record.getMessage().split("Antigravity ACP permission telemetry ", 1)[1]
        )
        for record in caplog.records
        if "Antigravity ACP permission telemetry " in record.getMessage()
    ]
    assert len(permission_events) == 1
    assert permission_events[0]["selected_option_kind"] == "reject_once"
    assert permission_events[0]["server_outcome"] == "selected"
    assert permission_events[0]["tool_origin"] == "native_acp"
    assert permission_events[0]["tool_outcome"] == "permission_denied_not_executed"

    # This is the discrimination oracle: a later elliptical user turn must keep
    # the uncompleted prose objective active, not just quote its earlier denial.
    assert prose_objective in followup_prompt, (
        "post-rejection ACP continuation omitted the still-active Krafton prose "
        f"objective; continuation prompt was:\n{followup_prompt}"
    )
    assert "List the Krafton API capabilities." not in followup_prompt
    assert "<UNRESOLVED_USER_OBJECTIVE>" in followup_prompt
    assert "<LATEST_USER_FOLLOW_UP>" in followup_prompt


def test_denied_request_context_survives_model_switch_full_replay(
    monkeypatch, tmp_path, caplog
) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    caplog.set_level(logging.INFO)

    objective = "Use the previously accessed Krafton API to write prose."
    followup = "아까는 요청해봤잖아"
    denied = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        messages=[{"role": "user", "content": objective}],
    )
    assert denied.choices[0].message.content == (
        "Krafton prose write denied; no API request was executed."
    )
    assert denied.antigravity_native_activity.get("native_tool_calls", []) == []

    completion = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=[
            {"role": "user", "content": objective},
            {"role": "assistant", "content": denied.choices[0].message.content},
            {"role": "user", "content": followup},
        ],
    )
    assert completion.choices[0].message.content == "normal response"

    rows = [
        json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    prompts = [
        ((row.get("params") or {}).get("prompt") or [{}])[0].get("text") or ""
        for row in rows
        if row.get("method") == "session/prompt"
    ]
    assert len(prompts) == 2
    replay_prompt = prompts[-1]
    assert (
        objective
        in replay_prompt.split("<UNRESOLVED_DENIED_REQUEST_CONTEXT>\n", 1)[1].split(
            "</UNRESOLVED_DENIED_REQUEST_CONTEXT>", 1
        )[0]
    )
    assert "<ACTIVE_REQUEST>\n" in replay_prompt
    assert (
        followup
        in replay_prompt.split("<ACTIVE_REQUEST>\n", 1)[1].split(
            "</ACTIVE_REQUEST>", 1
        )[0]
    )
    assert "Do not claim the denied action ran" in replay_prompt

    replay_lines = [
        record.getMessage()
        for record in caplog.records
        if "ACP full replay:" in record.getMessage()
    ]
    assert any(
        "reason=frontier_mismatch" in line
        and "intent_owner=prior_denied_request_followup" in line
        and "tool_outcome=permission_denied_not_executed" in line
        and "UNRESOLVED_DENIED_REQUEST_CONTEXT" in line
        for line in replay_lines
    ), replay_lines
    assert objective not in caplog.text
    assert "SECRET_COMMAND_BODY" not in caplog.text

    permission_responses = [row for row in rows if row.get("id") == 901]
    assert len(permission_responses) == 1
    assert not [
        row
        for row in rows
        if row.get("method") == "session/update"
        and (row.get("params") or {}).get("update", {}).get("sessionUpdate")
        in {"tool_call", "tool_call_update"}
    ]


def _web_search_tool_schema():
    return {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search public web sources under Hermes policy.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    }


def test_tool_bridge_activity_rejects_orphan_tool_results(monkeypatch, tmp_path) -> None:
    activity = _run_tool_bridge_activity(
        monkeypatch,
        tmp_path,
        [_web_search_tool_schema()],
        [
            {"role": "user", "content": "private research query"},
            {
                "role": "tool",
                "tool_call_id": "orphan-call-id",
                "name": "web_search",
                "content": {"status": "success"},
            },
        ],
    )

    assert activity["web_research_status"] == "NOT_ATTEMPTED"
    assert activity["calls"] == []


def test_tool_bridge_activity_rejects_mismatched_call_ids(monkeypatch, tmp_path) -> None:
    original_id = "original-call-id"
    orphan_id = "orphan-result-id"
    activity = _run_tool_bridge_activity(
        monkeypatch,
        tmp_path,
        [_web_search_tool_schema()],
        [
            {"role": "user", "content": "private research query"},
            {
                "role": "assistant",
                "tool_calls": [{
                    "id": original_id,
                    "type": "function",
                    "function": {"name": "web_search", "arguments": "{}"},
                }],
            },
            {
                "role": "tool",
                "tool_call_id": orphan_id,
                "name": "web_search",
                "content": {"status": "success"},
            },
        ],
    )

    assert activity["web_research_status"] == "PENDING"
    assert len(activity["calls"]) == 1
    assert activity["calls"][0]["tool_name"] == "web_search"
    assert activity["calls"][0]["status"] == "PENDING"
    assert original_id not in json.dumps(activity)
    assert orphan_id not in json.dumps(activity)


@pytest.mark.parametrize(
    ("result_name", "advertise_result_tool"),
    [("other_tool", True), ("unadvertised_tool", False)],
)
def test_tool_bridge_activity_rejects_result_name_mismatches(
    monkeypatch, tmp_path, result_name, advertise_result_tool
) -> None:
    tools = [_web_search_tool_schema()]
    if advertise_result_tool:
        tools.append({
            "type": "function",
            "function": {"name": "other_tool", "parameters": {"type": "object"}},
        })
    activity = _run_tool_bridge_activity(
        monkeypatch,
        tmp_path,
        tools,
        [
            {"role": "user", "content": "private research query"},
            {
                "role": "assistant",
                "tool_calls": [{
                    "id": "matched-id",
                    "type": "function",
                    "function": {"name": "web_search", "arguments": "{}"},
                }],
            },
            {
                "role": "tool",
                "tool_call_id": "matched-id",
                "name": result_name,
                "content": {"status": "success"},
            },
        ],
    )

    assert activity["web_research_status"] == "PENDING"
    assert len(activity["calls"]) == 1
    assert activity["calls"][0]["tool_name"] == "web_search"
    assert activity["calls"][0]["status"] == "PENDING"


def test_tool_bridge_activity_rejects_duplicate_assistant_call_ids(
    monkeypatch, tmp_path
) -> None:
    duplicate_id = "duplicate-call-id"
    activity = _run_tool_bridge_activity(
        monkeypatch,
        tmp_path,
        [_web_search_tool_schema()],
        [
            {"role": "user", "content": "private research query"},
            {
                "role": "assistant",
                "tool_calls": [
                    {
                        "id": duplicate_id,
                        "type": "function",
                        "function": {"name": "web_search", "arguments": "{}"},
                    },
                    {
                        "id": duplicate_id,
                        "type": "function",
                        "function": {"name": "web_search", "arguments": "{}"},
                    },
                ],
            },
            {
                "role": "tool",
                "tool_call_id": duplicate_id,
                "name": "web_search",
                "content": {"status": "success"},
            },
        ],
    )

    assert activity["web_research_status"] == "PENDING"
    assert len(activity["calls"]) == 1
    assert activity["calls"][0]["status"] == "PENDING"


def test_tool_bridge_activity_does_not_overwrite_first_result_for_duplicate_id(
    monkeypatch, tmp_path
) -> None:
    call_id = "single-call-id"
    activity = _run_tool_bridge_activity(
        monkeypatch,
        tmp_path,
        [_web_search_tool_schema()],
        [
            {"role": "user", "content": "private research query"},
            {
                "role": "assistant",
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {"name": "web_search", "arguments": "{}"},
                }],
            },
            {
                "role": "tool",
                "tool_call_id": call_id,
                "name": "web_search",
                "content": {"status": "success"},
            },
            {
                "role": "tool",
                "tool_call_id": call_id,
                "name": "web_search",
                "content": {"status": "denied"},
            },
        ],
    )

    assert activity["web_research_status"] == "COMPLETED"
    assert len(activity["calls"]) == 1
    assert activity["calls"][0]["status"] == "COMPLETED"


def test_authorized_hermes_web_search_bridge_is_advertised_callable_and_traceable(
    monkeypatch, tmp_path, caplog
) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    caplog.set_level(logging.INFO)
    tools = [_web_search_tool_schema()]
    messages = [{"role": "user", "content": "web research authorized lookup for the current project status"}]

    first = client.chat.completions.create(
        model="gemini-3.8-flash-high", messages=messages, tools=tools
    )

    call = first.choices[0].message.tool_calls[0]
    assert call.function.name == "web_search"
    assert json.loads(call.function.arguments) == {"query": "public source lookup"}
    assert first.antigravity_tool_bridge["advertised_tools"] == ["web_search"]
    assert first.antigravity_tool_bridge["web_research_status"] == "PENDING"
    first_event = first.antigravity_tool_bridge["calls"][0]
    assert first_event["tool_name"] == "web_search"
    assert first_event["origin"] == "hermes_tool_bridge"
    assert first_event["status"] == "PENDING"
    assert first_event["tool_call_id_hash"].startswith("sha256:")
    assert call.id not in first_event["tool_call_id_hash"]

    source_result = {
        "status": "success",
        "sources": [{"title": "Fixture source", "url": "https://example.test/source"}],
    }
    completed = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        tools=tools,
        messages=[
            *messages,
            {
                "role": "assistant",
                "content": first.choices[0].message.content,
                "tool_calls": [{
                    "id": call.id,
                    "type": call.type,
                    "function": {
                        "name": call.function.name,
                        "arguments": call.function.arguments,
                    },
                }],
            },
            {
                "role": "tool",
                "tool_call_id": call.id,
                "name": call.function.name,
                "content": json.dumps(source_result),
            },
        ],
    )

    assert "https://example.test/source" in completed.choices[0].message.content
    assert completed.antigravity_tool_bridge["web_research_status"] == "COMPLETED"
    completed_event = completed.antigravity_tool_bridge["calls"][0]
    assert completed_event["tool_call_id_hash"] == first_event["tool_call_id_hash"]
    assert completed_event["status"] == "COMPLETED"
    assert "public source lookup" not in caplog.text
    assert "PRIVATE_QUERY_MUST_NOT_BE_LOGGED" not in caplog.text
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    prompt = next(
        ((row.get("params") or {}).get("prompt") or [{}])[0].get("text", "")
        for row in rows
        if row.get("method") == "session/prompt"
    )
    assert '"name": "web_search"' in prompt
    assert "Only tools advertised through this Hermes tool bridge" in prompt
    assert "Never fabricate citations" in prompt


@pytest.mark.parametrize(
    ("tool_result_content", "expected_status"),
    [
        ({"status": "denied", "error": "Hermes policy refused web_search"}, "DENIED"),
        ({"status": "cancelled", "error": "User cancelled search"}, "CANCELLED"),
        ({"status": "error", "error": "Search service network failure"}, "FAILED"),
        ({"outcome": "failed", "error": "Search service network failure"}, "FAILED"),
        (
            json.dumps({"outcome": "failed", "error": "Search service network failure"}),
            "FAILED",
        ),
        ({"status": "success", "outcome": "denied"}, "DENIED"),
        (json.dumps({"status": "success", "outcome": "denied"}), "DENIED"),
        ({"status": "success", "outcome": "cancelled"}, "CANCELLED"),
        (json.dumps({"status": "success", "outcome": "cancelled"}), "CANCELLED"),
        ({"status": "success", "outcome": "failed"}, "FAILED"),
        (json.dumps({"status": "success", "outcome": "failed"}), "FAILED"),
    ],
)
def test_hermes_web_tool_denied_cancelled_and_failed_results_are_distinguished(
    monkeypatch, tmp_path, tool_result_content, expected_status
) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    call_id = "web-search-result-" + expected_status.lower()
    completion = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        tools=[_web_search_tool_schema()],
        messages=[
            {
                "role": "user",
                "content": f"Research current official sources and preserve this objective: {expected_status}.",
            },
            {"role": "assistant", "content": "", "tool_calls": [{
                "id": call_id,
                "type": "function",
                "function": {"name": "web_search", "arguments": '{"query":"public query"}'},
            }]},
            {
                "role": "tool",
                "tool_call_id": call_id,
                "name": "web_search",
                "content": tool_result_content,
            },
        ],
    )

    assert completion.antigravity_tool_bridge["web_research_status"] == expected_status
    assert completion.antigravity_tool_bridge["calls"][0]["status"] == expected_status
    assert completion.choices[0].message.content.startswith(expected_status)
    assert "research objective remains unresolved" in completion.choices[0].message.content
    assert "no current sources were verified" in completion.choices[0].message.content
    assert "https://" not in completion.choices[0].message.content
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    prompt = next(
        ((row.get("params") or {}).get("prompt") or [{}])[0].get("text", "")
        for row in rows
        if row.get("method") == "session/prompt"
    )
    assert f"Research current official sources and preserve this objective: {expected_status}." in prompt
    assert "Never fabricate citations" in prompt


def test_web_research_unavailable_and_not_attempted_are_truthful(monkeypatch, tmp_path) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )

    unavailable = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        messages=[{"role": "user", "content": "web research unavailable: compare current upstream documentation"}],
    )
    not_attempted = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        tools=[_web_search_tool_schema()],
        messages=[{"role": "user", "content": "web research not attempted: compare current upstream documentation"}],
    )

    assert unavailable.antigravity_tool_bridge["web_research_status"] == "NOT_AVAILABLE"
    assert unavailable.antigravity_tool_bridge["advertised_tools"] == []
    assert "NOT AVAILABLE" in unavailable.choices[0].message.content
    assert "no live sources were verified" in unavailable.choices[0].message.content
    assert not_attempted.antigravity_tool_bridge["web_research_status"] == "NOT_ATTEMPTED"
    assert "NOT ATTEMPTED" in not_attempted.choices[0].message.content


def test_unadvertised_web_tool_call_is_not_returned_to_hermes(monkeypatch, tmp_path) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )

    with pytest.raises(RuntimeError, match="unadvertised Hermes tool call.*web_search"):
        client.chat.completions.create(
            model="gemini-3.8-flash-high",
            messages=[{"role": "user", "content": "web research unadvertised call"}],
            tools=[],
        )

    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert not [
        row for row in rows
        if row.get("method") == "session/request_permission"
    ]


def test_google_native_web_pre_tool_denial_is_separate_from_hermes_fallback(
    monkeypatch, tmp_path, caplog
) -> None:
    script, log_path = _write_fake_server(tmp_path)
    client = _load_client(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path)],
        cwd=str(tmp_path),
    )
    caplog.set_level(logging.INFO)
    completion = client.chat.completions.create(
        model="gemini-3.8-flash-high",
        messages=[{"role": "user", "content": "Google-native web pre-tool denial: research current project sources"}],
        tools=[_web_search_tool_schema()],
    )

    call = completion.choices[0].message.tool_calls[0]
    assert call.function.name == "web_search"
    assert completion.antigravity_native_activity["permission_denied"]
    assert completion.antigravity_native_activity["session_id_hash"].startswith("sha256:")
    assert completion.antigravity_native_activity["turn_id_hash"].startswith("sha256:")
    native_call = completion.antigravity_native_activity["native_tool_calls"][0]
    assert native_call["name"] == "vendor_web_lookup"
    assert native_call["origin"] == "native_acp"
    assert native_call["status"] == "failed"
    assert native_call["input"] == {"query_present": True}
    assert completion.antigravity_tool_bridge["web_research_status"] == "PENDING"
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert not [
        row for row in rows
        if row.get("method") == "session/request_permission"
    ]
    event = next(
        json.loads(record.getMessage().split("Antigravity ACP permission telemetry ", 1)[1])
        for record in caplog.records
        if "Antigravity ACP permission telemetry " in record.getMessage()
    )
    assert event["decision_stage"] == "server_pre_tool"
    assert event["tool_name"] == "vendor_web_lookup"
    assert event["tool_origin"] == "native_acp"
    assert event["server_outcome"] == "denied"
    assert "PRIVATE_QUERY_MUST_NOT_BE_LOGGED" not in caplog.text
