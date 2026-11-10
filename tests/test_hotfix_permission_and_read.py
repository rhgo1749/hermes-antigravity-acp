"""Regression tests for ACP permission aliases and missing-file read semantics.

A partial pathless native read permission remains allow-once; every provided
path alias must still be within the scoped file policy.
"""

from __future__ import annotations

import io
import json
import logging
import sys
import types

import pytest
from test_standalone_client import _load


@pytest.fixture
def acp(monkeypatch, tmp_path):
    _, client, module = _load(monkeypatch)
    file_safety = types.ModuleType("agent.file_safety")
    file_safety.get_nt_namespace_error = lambda path, verb=None: None
    file_safety.get_read_block_error = lambda path: None
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    redact = types.ModuleType("agent.redact")
    redact.redact_sensitive_text = lambda text, force=True: text
    monkeypatch.setitem(sys.modules, "agent.redact", redact)
    # Pin the scratch-allowance roots to a private fake home: pytest's
    # tmp dir can itself live inside Hermes' real scratch tree, which
    # would whitelist the very "outside" paths these tests must reject.
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(fake_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return client, module, workspace


def _permission(module, workspace, raw_input):
    return module._safe_read_permission_option({
        "toolCall": {
            "name": "client_view_file",
            "title": "Running client_view_file",
            "kind": "other",
            **({"rawInput": raw_input} if raw_input is not None else {}),
        },
        "options": [
            {"kind": "allow_always", "optionId": "always"},
            {"kind": "allow_once", "optionId": "once"},
        ],
    }, str(workspace))


def test_every_supplied_path_alias_is_scoped_without_denial_of_pathless_reads(acp, tmp_path):
    _, module, workspace = acp
    safe = workspace / "source.py"
    safe.write_text("print(1)", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("print(2)", encoding="utf-8")

    assert _permission(module, workspace, None) == "once"  # partial ToolCallUpdate
    assert _permission(module, workspace, {}) == "once"
    assert _permission(module, workspace, {"absolute_path": str(safe)}) == "once"
    assert _permission(module, workspace, {
        "absolute_path": str(safe), "directory_path": str(workspace),
    }) == "once"

    for bad_alias in ("path", "filePath", "file_path", "filename", "file", "directory_path"):
        assert _permission(module, workspace, {
            "absolute_path": str(safe), bad_alias: str(outside),
        }) is None, bad_alias

    assert _permission(module, workspace, {
        "absolute_path": str(outside), "path": str(safe),
    }) is None


def test_missing_file_returns_error_but_existing_empty_file_remains_valid(acp):
    client, module, workspace = acp
    missing = workspace / "missing.txt"
    empty = workspace / "empty.txt"
    empty.write_text("", encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="ACP file does not exist"):
        module._fs_read_text_file({"path": str(missing)}, str(workspace))
    assert module._fs_read_text_file({"path": str(empty)}, str(workspace)) == {"content": ""}

    class FakeProcess:
        def __init__(self):
            self.stdin = io.StringIO()

    process = FakeProcess()
    handled = client._handle_server_message({
        "jsonrpc": "2.0", "id": 3, "method": "fs/read_text_file",
        "params": {"path": str(missing)},
    }, process=process, cwd=str(workspace), text_parts=None, reasoning_parts=None)
    assert handled
    rpc_response = json.loads(process.stdin.getvalue())
    assert rpc_response["error"]["code"] == -32602
    assert "does not exist" in rpc_response["error"]["message"]


def test_conflicting_aliases_are_cancelled_over_jsonrpc(acp, tmp_path):
    client, _, workspace = acp
    safe = workspace / "safe.txt"
    safe.write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")

    class FakeProcess:
        def __init__(self):
            self.stdin = io.StringIO()

    for raw_input, outcome in [
        ({"absolute_path": str(safe), "directory_path": str(outside)}, "cancelled"),
        ({}, "selected"),
    ]:
        process = FakeProcess()
        assert client._handle_server_message({
            "jsonrpc": "2.0", "id": 4, "method": "session/request_permission",
            "params": {
                "toolCall": {"name": "client_view_file",
                             "title": "Running client_view_file", "kind": "other",
                             "rawInput": raw_input},
                "options": [{"optionId": "once", "kind": "allow_once"}],
            },
        }, process=process, cwd=str(workspace), text_parts=None, reasoning_parts=None)
        response = json.loads(process.stdin.getvalue())
        assert response["result"]["outcome"]["outcome"] == outcome
        if outcome == "selected":
            assert response["result"]["outcome"]["optionId"] == "once"


def _permission_response(client, workspace, tool_call, options):
    class FakeProcess:
        def __init__(self):
            self.stdin = io.StringIO()

    process = FakeProcess()
    client._handle_server_message({
        "jsonrpc": "2.0",
        "id": 99,
        "method": "session/request_permission",
        "params": {"toolCall": tool_call, "options": options},
    }, process=process, cwd=str(workspace), text_parts=None, reasoning_parts=None)
    return json.loads(process.stdin.getvalue())


def _permission_events(caplog):
    prefix = "Antigravity ACP permission telemetry "
    return [
        json.loads(record.getMessage().split(prefix, 1)[1])
        for record in caplog.records
        if prefix in record.getMessage()
    ]


def test_policy_denial_selects_server_reject_once_and_logs_safe_telemetry(
    acp, caplog
):
    client, _, workspace = acp
    secret_command = "printf 'COMMAND_BODY_MUST_NOT_BE_LOGGED'"
    credential_path = "/home/user/.gemini/antigravity/oauth_creds.json"
    caplog.set_level(logging.INFO)

    response = _permission_response(
        client,
        workspace,
        {
            "toolCallId": "native-run-1",
            "name": "run_command",
            "title": "Running run_command",
            "kind": "execute",
            "rawInput": {"command": secret_command, "path": credential_path},
        },
        [
            {"optionId": "allow", "kind": "allow_once"},
            {"optionId": "reject", "kind": "reject_once"},
        ],
    )

    assert response["result"]["outcome"] == {
        "outcome": "selected", "optionId": "reject"
    }
    assert len(_permission_events(caplog)) == 1
    event = _permission_events(caplog)[0]
    assert event["decision_stage"] == "harness_permission_response"
    assert event["tool_name"] == "run_command"
    assert event["tool_origin"] == "native_acp"
    assert event["offered_option_kinds"] == ["allow_once", "reject_once"]
    assert event["selected_option_kind"] == "reject_once"
    assert event["server_outcome"] == "selected"
    assert event["tool_call_id_hash"].startswith("sha256:")
    assert secret_command not in caplog.text
    assert credential_path not in caplog.text


@pytest.mark.parametrize(
    ("tool_call", "expected_name", "expected_origin"),
    [
        (
            {
                "toolCallId": "edit-1",
                "name": "write_file",
                "title": "Writing file",
                "kind": "edit",
                "rawInput": {"path": "/workspace/file.py", "content": "secret"},
            },
            "write_file",
            "unknown",
        ),
        (
            {
                "toolCallId": "mcp-1",
                "name": "mcp__slack__read_email",
                "title": "Reading email",
                "kind": "read",
                "rawInput": {"path": "/workspace/file.py"},
            },
            "mcp__slack__read_email",
            "mcp",
        ),
        (
            {
                "toolCallId": "unknown-native-1",
                "name": "unknown_vendor_tool",
                "title": "Reading private material",
                "kind": "read",
                "rawInput": {"path": "/workspace/file.py"},
            },
            "unknown_vendor_tool",
            "unknown",
        ),
        (
            {
                "toolCallId": "read-outside-1",
                "name": "view_file",
                "title": "Viewing file",
                "kind": "read",
                "rawInput": {"path": "/outside/private.txt"},
            },
            "view_file",
            "native_acp",
        ),
        (
            {
                "toolCallId": "partial-1",
                "title": "Running client_view_file",
                "kind": "read",
            },
            "unknown",
            "unknown",
        ),
    ],
)
def test_non_vetted_permission_requests_select_reject_not_allow(
    acp, caplog, tool_call, expected_name, expected_origin
):
    client, _, workspace = acp
    caplog.set_level(logging.INFO)
    response = _permission_response(
        client,
        workspace,
        tool_call,
        [{"optionId": "reject", "kind": "reject_once"}],
    )

    assert response["result"]["outcome"] == {
        "outcome": "selected", "optionId": "reject"
    }
    event = _permission_events(caplog)[0]
    assert event["selected_option_kind"] == "reject_once"
    assert event["tool_name"] == expected_name
    assert event["tool_origin"] == expected_origin


def test_missing_reject_option_fails_closed_and_reports_protocol_limitation(
    acp, caplog
):
    client, _, workspace = acp
    caplog.set_level(logging.INFO)
    response = _permission_response(
        client,
        workspace,
        {
            "toolCallId": "native-run-2",
            "name": "run_command",
            "title": "Running run_command",
            "kind": "execute",
            "rawInput": {"command": "SECRET_COMMAND"},
        },
        [{"optionId": "allow", "kind": "allow_once"}],
    )

    assert response["result"]["outcome"] == {"outcome": "cancelled"}
    assert "optionId" not in response["result"]["outcome"]
    assert "no documented reject option" in caplog.text
    event = _permission_events(caplog)[0]
    assert event["selected_option_kind"] is None
    assert event["server_outcome"] == "cancelled"
    assert event["protocol_limitation"] == "no_reject_option_offered"
    assert "SECRET_COMMAND" not in caplog.text


def test_reject_once_is_preferred_and_reject_always_is_used_only_as_fallback(
    acp
):
    client, _, workspace = acp
    tool_call = {
        "toolCallId": "native-run-3",
        "name": "run_command",
        "title": "Running run_command",
        "kind": "execute",
    }

    preferred = _permission_response(
        client,
        workspace,
        tool_call,
        [
            {"optionId": "reject-always", "kind": "reject_always"},
            {"optionId": "reject-once", "kind": "reject_once"},
        ],
    )
    fallback = _permission_response(
        client,
        workspace,
        tool_call,
        [{"optionId": "reject-always", "kind": "reject_always"}],
    )

    assert preferred["result"]["outcome"]["optionId"] == "reject-once"
    assert fallback["result"]["outcome"]["optionId"] == "reject-always"


def test_vetted_in_workspace_view_file_still_selects_allow_once(acp, caplog):
    client, _, workspace = acp
    safe = workspace / "source.py"
    safe.write_text("safe", encoding="utf-8")
    caplog.set_level(logging.INFO)

    response = _permission_response(
        client,
        workspace,
        {
            "toolCallId": "native-read-1",
            "name": "view_file",
            "title": "Running view_file",
            "kind": "read",
            "rawInput": {"path": str(safe)},
        },
        [
            {"optionId": "allow-read", "kind": "allow_once"},
            {"optionId": "reject-read", "kind": "reject_once"},
        ],
    )

    assert response["result"]["outcome"] == {
        "outcome": "selected", "optionId": "allow-read"
    }
    event = _permission_events(caplog)[0]
    assert event["selected_option_kind"] == "allow_once"
    assert event["server_outcome"] == "selected"


def test_unverified_native_web_search_permission_is_rejected_not_auto_approved(
    acp, caplog
):
    client, _, workspace = acp
    caplog.set_level(logging.INFO)

    response = _permission_response(
        client,
        workspace,
        {
            "toolCallId": "native-web-search-1",
            "name": "vendor_web_lookup",
            "origin": "native_acp",
            "title": "Searching the public web",
            "kind": "search",
            "rawInput": {"query": "PRIVATE_QUERY_MUST_NOT_BE_LOGGED"},
        },
        [
            {"optionId": "allow-web", "kind": "allow_once"},
            {"optionId": "reject-web", "kind": "reject_once"},
        ],
    )

    assert response["result"]["outcome"] == {
        "outcome": "selected", "optionId": "reject-web"
    }
    event = _permission_events(caplog)[0]
    assert event["decision_stage"] == "harness_permission_response"
    assert event["tool_name"] == "vendor_web_lookup"
    assert event["tool_origin"] == "native_acp"
    assert event["offered_option_kinds"] == ["allow_once", "reject_once"]
    assert event["selected_option_kind"] == "reject_once"
    assert event["server_outcome"] == "selected"
    assert event["tool_outcome"] == "permission_denied_not_executed"
    assert "PRIVATE_QUERY_MUST_NOT_BE_LOGGED" not in caplog.text
