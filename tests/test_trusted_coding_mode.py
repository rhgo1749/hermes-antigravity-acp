"""Trusted coding-agent mode (historical reference) regressions.

Covers: explicit opt-in only; default-mode byte-identity; session launch
_meta gating; the trusted permission chooser; workspace binding for isolated
worktrees; denial attribution (harness echo vs Google pre-tool hook); and a
full fake-ACP coding loop where the harness really writes files and the fake
server really runs pytest in the workspace.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"


def _load_plugin(monkeypatch, *, command: str = "", args: list[str] | None = None, cwd: str = ""):
    # isolate from any live Hermes runtime the tests happen to run inside:
    # resolve_agent_cwd() must not hijack the expected process-cwd default
    for var in ("HERMES_SESSION_ID", "HERMES_SESSION_KEY", "HERMES_SESSION_CWD"):
        monkeypatch.delenv(var, raising=False)
    # hermes_compat.resolve_agent_cwd() wraps agent.runtime_cwd in Path(), so
    # the stub must return a real directory: pin it to the process cwd so the
    # default-mode expectation is stable whether or not a live Hermes session
    # context exists around pytest.
    runtime_cwd_mod = types.ModuleType("agent.runtime_cwd")
    runtime_cwd_mod.resolve_agent_cwd = lambda: os.getcwd()
    monkeypatch.setitem(sys.modules, "agent.runtime_cwd", runtime_cwd_mod)
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        f"/tmp/antigravity-acp-trusted-{os.getpid()}-{id(monkeypatch)}.json",
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        f"/tmp/antigravity-acp-trusted-limits-{os.getpid()}-{id(monkeypatch)}.json",
    )
    registered: list[object] = []

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = registered.append
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)

    module_name = "antigravity_acp_trusted_test"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location(
        module_name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    client = module.antigravity_acp.create_client(
        command=command, args=args or [], acp_cwd=cwd or None
    )
    return module, client, sys.modules[module_name + ".client"]


def _stub_hermes_file_safety(monkeypatch):
    file_safety = types.ModuleType("agent.file_safety")
    file_safety.get_nt_namespace_error = lambda path, verb=None: None
    file_safety.get_read_block_error = lambda path: None
    file_safety.get_write_denied_error = lambda path, verb="Write", entry=False: None
    file_safety.is_write_approval_required = lambda path: path.endswith(".ssh/config")
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    redact = types.ModuleType("agent.redact")
    redact.redact_sensitive_text = lambda text, force=True: text
    monkeypatch.setitem(sys.modules, "agent.redact", redact)


# --- mode selection is explicit and default-neutral -----------------------

def test_mode_is_off_by_default_and_requires_exact_value(monkeypatch):
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", raising=False)
    _, client, module = _load_plugin(monkeypatch)
    assert client._trusted_coding is False

    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", "trusted-coding")
    _, trusted_client, _ = _load_plugin(monkeypatch)
    assert trusted_client._trusted_coding is True

    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", "trusted")
    _, partial_client, _ = _load_plugin(monkeypatch)
    assert partial_client._trusted_coding is False
    del module


def test_workspace_override_only_in_trusted_mode(monkeypatch, tmp_path):
    workspace = tmp_path / "wt-iso"
    workspace.mkdir()
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_WORKSPACE", str(workspace))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HERMES_REAL_HOME", str(tmp_path / "home"))

    _, _, module = _load_plugin(monkeypatch)
    # default mode ignores the workspace override entirely
    assert module._resolve_acp_working_directory(None, trusted_mode=False) == str(
        Path(os.getcwd()).resolve()
    )
    # trusted mode binds both session cwd and permission root to the worktree
    assert module._resolve_acp_working_directory(None, trusted_mode=True) == str(
        workspace.resolve()
    )
    # in trusted mode the operator pin is authoritative: an explicit kwarg may
    # agree with it but can never silently override or bypass its validation
    other = tmp_path / "explicit"
    other.mkdir()
    with pytest.raises(RuntimeError):
        module._resolve_acp_working_directory(str(other), trusted_mode=True)
    assert module._resolve_acp_working_directory(str(workspace), trusted_mode=True) == str(
        workspace.resolve()
    )
    # a malformed pin fails closed even when an explicit kwarg is supplied
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_WORKSPACE", "relative/path")
    with pytest.raises(RuntimeError):
        module._resolve_acp_working_directory(str(workspace), trusted_mode=True)
    # default mode ignores the pin entirely (unchanged behavior)
    assert module._resolve_acp_working_directory(str(other), trusted_mode=False) == str(
        other.resolve()
    )
    # fail-closed on missing or relative directories
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_WORKSPACE", str(tmp_path / "missing"))
    with pytest.raises(RuntimeError):
        module._resolve_acp_working_directory(None, trusted_mode=True)
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_WORKSPACE", "relative/path")
    with pytest.raises(RuntimeError):
        module._resolve_acp_working_directory(None, trusted_mode=True)


# --- trusted permission chooser -------------------------------------------

@pytest.fixture
def chooser_env(monkeypatch, tmp_path):
    _stub_hermes_file_safety(monkeypatch)
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(fake_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, _, module = _load_plugin(monkeypatch, cwd=str(workspace))
    return module, workspace


def _options(*kinds: tuple[str, str]):
    return [{"kind": kind, "optionId": option_id} for kind, option_id in kinds]


def _request(module, name: str, raw_input: dict | None):
    return {
        "toolCall": {
            "name": name,
            "title": f"Running {name}",
            **({"rawInput": raw_input} if raw_input is not None else {}),
        },
        "options": _options(
            ("allow_always", "always"), ("allow_once", "once"), ("reject_once", "reject")
        ),
    }


def test_chooser_allows_in_workspace_native_builtins(chooser_env):
    module, workspace = chooser_env
    target = workspace / "helpers.py"
    assert module._trusted_coding_permission_option(
        _request(module, "client_create_file", {"absolute_path": str(target)}),
        str(workspace),
    ) == ("always", "allow_always")
    assert module._trusted_coding_permission_option(
        _request(module, "client_edit_file", {"path": str(target)}), str(workspace)
    ) == ("always", "allow_always")
    assert module._trusted_coding_permission_option(
        _request(module, "run_command", {"command": "python3 -m pytest -q"}),
        str(workspace),
    ) == ("always", "allow_always")
    # only allow_once offered -> allow_once is still selectable
    request = _request(module, "run_command", {"command": "git diff --stat"})
    request["options"] = _options(("allow_once", "once"), ("reject_once", "reject"))
    assert module._trusted_coding_permission_option(request, str(workspace)) == (
        "once",
        "allow_once",
    )


def test_chooser_blocks_outside_workspace_credentials_and_forgery(chooser_env):
    module, workspace = chooser_env
    outside = Path("/some/other/tree/helpers.py")
    assert module._trusted_coding_permission_option(
        _request(module, "client_create_file", {"absolute_path": str(outside)}),
        str(workspace),
    ) is None
    # a later alias outside the workspace must not be masked by an in-scope alias
    assert module._trusted_coding_permission_option(
        _request(module, "client_edit_file", {
            "absolute_path": str(workspace / "ok.py"), "path": str(outside),
        }),
        str(workspace),
    ) is None
    # Antigravity credential roots stay blocked even inside an in-home workspace
    assert module._trusted_coding_permission_option(
        _request(module, "client_edit_file", {
            "absolute_path": str(Path.home() / ".gemini/config/edit.py"),
        }),
        str(workspace),
    ) is None
    # forged names and MCP-qualified tools never receive a trusted allow
    assert module._trusted_coding_permission_option(
        _request(module, "mcp__server__client_create_file", {"path": str(workspace / "x.py")}),
        str(workspace),
    ) is None
    assert module._trusted_coding_permission_option(
        _request(module, "shell", {"command": "rm -rf /"}), str(workspace)
    ) is None
    assert module._trusted_coding_permission_option(
        {"toolCall": {"title": "Running client_create_file"}, "options": []}, str(workspace)
    ) is None
    # no allow option offered at all -> fail closed
    request = _request(module, "run_command", {"command": "ls"})
    request["options"] = _options(("reject_once", "reject"))
    assert module._trusted_coding_permission_option(request, str(workspace)) is None


def test_chooser_denies_pathless_named_mutation_and_policy_denials(chooser_env, monkeypatch):
    module, workspace = chooser_env
    # named file-mutation frame with no checkable target anywhere: denied
    # (server-executed edits bypass the harness fs/write gate)
    assert module._trusted_coding_permission_option(
        {"toolCall": {"name": "client_edit_file", "title": "edit"},
         "options": _options(("allow_always", "always"), ("reject_once", "reject"))},
        str(workspace),
    ) is None
    assert module._trusted_coding_permission_option(
        _request(module, "client_create_file", None), str(workspace)
    ) is None
    # Hermes explicit write-denial applies to native mutations too
    file_safety = sys.modules["agent.file_safety"]
    monkeypatch.setattr(
        file_safety, "get_write_denied_error",
        lambda path, verb="Write", entry=False: (
            "blocked by Hermes write policy" if "denied_dir" in path else None
        ),
    )
    assert module._trusted_coding_permission_option(
        _nameless_diff_request(["denied_dir/inner.py"]), str(workspace)
    ) is None
    assert module._trusted_coding_permission_option(
        _nameless_diff_request(["allowed_dir/inner.py"]), str(workspace)
    ) == ("once", "allow_once")
    # policy errors fail closed
    def boom(path, verb="Write", entry=False):
        raise RuntimeError("policy unavailable")
    monkeypatch.setattr(file_safety, "get_write_denied_error", boom)
    assert module._trusted_coding_permission_option(
        _nameless_diff_request(["allowed_dir/inner.py"]), str(workspace)
    ) is None


def test_chooser_resolves_relative_paths_against_session_root(chooser_env):
    module, workspace = chooser_env
    # 1.4.0 discloses session-cwd-relative paths; they bind to the session root
    assert module._trusted_coding_permission_option(
        _request(module, "client_create_file", {"path": "relative.py"}), str(workspace)
    ) == ("always", "allow_always")
    assert module._trusted_coding_permission_option(
        _request(module, "client_edit_file", {"path": "../outside.py"}), str(workspace)
    ) is None
    assert module._trusted_coding_permission_option(
        _request(module, "client_edit_file", {"target_file": "sub/inner.py"}), str(workspace)
    ) == ("always", "allow_always")


def _nameless_diff_request(path_entries, kind="edit"):
    return {
        "toolCall": {
            "toolCallId": "live-1",
            "kind": kind,
            "status": "pending",
            "title": "Run client_create_file?",
            "content": [
                {"path": p, "newText": "x", "_meta": {"kind": "add"}, "type": "diff"}
                for p in path_entries
            ],
            "locations": [{"path": p} for p in path_entries],
            "rawInput": {"code_content_len": 1, "target_file_len": 10},
        },
        "options": _options(("allow_once", "once"), ("reject_once", "reject")),
    }


def test_chooser_accepts_real_140_nameless_diff_frames(chooser_env):
    module, workspace = chooser_env
    # 1.4.0 built-in frames: no name, relative session paths
    assert module._trusted_coding_permission_option(
        _nameless_diff_request(["helpers.py"]), str(workspace)
    ) == ("once", "allow_once")
    # absolute in-workspace path also fine
    assert module._trusted_coding_permission_option(
        _nameless_diff_request([str(workspace / "sub" / "deep.py")]), str(workspace)
    ) == ("once", "allow_once")
    # escaping relative path is blocked
    assert module._trusted_coding_permission_option(
        _nameless_diff_request(["../escape.py"]), str(workspace)
    ) is None
    # outside absolute path blocked
    assert module._trusted_coding_permission_option(
        _nameless_diff_request(["/tmp/other_tree.py"]), str(workspace)
    ) is None
    # one in-workspace location cannot mask an out-of-workspace alias
    assert module._trusted_coding_permission_option(
        _nameless_diff_request(["ok.py", "/tmp/other.py"]), str(workspace)
    ) is None
    # diff frames without any disclosed path cannot be verified
    request = _nameless_diff_request([])
    request["toolCall"]["content"] = [{"type": "diff", "_meta": {"kind": "add"}, "newText": "x"}]
    request["toolCall"]["locations"] = []
    assert module._trusted_coding_permission_option(request, str(workspace)) is None
    # nameless frames without the built-in diff shape stay on the deny path
    assert module._trusted_coding_permission_option(
        {"toolCall": {"kind": "edit", "title": "Run client_create_file?"},
         "options": _options(("allow_once", "once"))},
        str(workspace),
    ) is None
    # nameless run_command frame (live 1.4.0): kind=execute + CommandLine/Cwd
    def _nameless_execute(cwd_value, command="python3 -m pytest -q"):
        return {
            "toolCall": {
                "toolCallId": "live-run", "kind": "execute", "status": "pending",
                "title": command,
                "rawInput": {"CommandLine": command, "Cwd": cwd_value,
                             "WaitMsBeforeAsync": 5000},
            },
            "options": _options(("allow_always", "always"), ("allow_once", "once"),
                                ("reject_once", "reject")),
        }
    assert module._trusted_coding_permission_option(
        _nameless_execute(str(workspace)), str(workspace)
    ) == ("always", "allow_always")
    assert module._trusted_coding_permission_option(
        _nameless_execute("relative-sub"), str(workspace)
    ) == ("always", "allow_always")
    # Cwd outside the session workspace blocks the command frame
    assert module._trusted_coding_permission_option(
        _nameless_execute("/home/example"), str(workspace)
    ) is None
    # nameless execute without the built-in CommandLine shape stays denied
    assert module._trusted_coding_permission_option(
        {"toolCall": {"kind": "execute", "title": "Run client_create_file",
                      "rawInput": {"command": "rm -rf /"}},
         "options": _options(("allow_once", "once"))},
        str(workspace),
    ) is None
    # credential roots inside the workspace remain blocked even in diff frames
    assert module._trusted_coding_permission_option(
        _nameless_diff_request([".gemini/config/credentials.json"]), str(workspace)
    ) is None
    # Hermes interactive write-approval gate applies to server-executed edits
    # inside the workspace too (.ssh/config per the file-safety stub)
    assert module._trusted_coding_permission_option(
        _nameless_diff_request([".ssh/config"]), str(workspace)
    ) is None


# --- prompt preamble stays byte-identical by default ----------------------

def test_preamble_default_unchanged_and_trusted_replaces_one_line(chooser_env):
    module, _ = chooser_env
    assert module._prompt_preamble(False) == module._PROMPT_PREAMBLE
    default_prompt = module._format_messages_as_prompt(
        [{"role": "user", "content": "x"}]
    )
    assert "ACP-native run_command is disabled in Hermes model-provider mode." in default_prompt
    trusted_prompt = module._format_messages_as_prompt(
        [{"role": "user", "content": "x"}], trusted_coding=True
    )
    assert "ACP-native run_command is disabled" not in trusted_prompt
    assert "trusted coding-agent mode" in trusted_prompt
    # only the execution line differs
    assert len(trusted_prompt.splitlines()) == len(default_prompt.splitlines())


# --- fingerprint neutrality -----------------------------------------------

def test_default_fingerprint_bytes_unchanged(chooser_env):
    module, _ = chooser_env
    base = module._context_fingerprint("model-x", None, None)
    assert module._context_fingerprint("model-x", None, None, execution_mode="") == base
    assert module._context_fingerprint("model-x", None, None, execution_mode="trusted-coding") != base


# --- denial attribution: harness echo is never a user denial ---------------

def test_denied_by_user_after_harness_reject_is_attributed_to_harness(chooser_env, caplog):
    module, _ = chooser_env
    activity_stats: dict = {
        "_harness_denied_tool_call_hashes": {
            module._opaque_permission_id("run-1", "tool-call")
        }
    }
    with caplog.at_level(logging.INFO):
        module._log_server_pre_tool_denial(
            {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "run-1",
                "name": "run_command",
                "status": "failed",
                "rawOutput": {"error": "denied by pre-tool hook: Denied by user (*)"},
            },
            activity_stats,
        )
        module._log_server_pre_tool_denial(
            {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "web-2",
                "name": "vendor_web_lookup",
                "status": "failed",
                "rawOutput": {"error": "denied by pre-tool hook"},
            },
            activity_stats,
        )
    events = [
        json.loads(record.getMessage().split("permission telemetry ", 1)[1])
        for record in caplog.records
        if "permission telemetry " in record.getMessage()
    ]
    by_stage = {event["tool_call_id_hash"]: event["decision_stage"] for event in events}
    assert by_stage[module._opaque_permission_id("run-1", "tool-call")] == "harness_denial_echo"
    assert by_stage[module._opaque_permission_id("web-2", "tool-call")] == "server_pre_tool"


def test_140_rejected_by_user_echo_requires_correlation(chooser_env, caplog):
    # official 1.4.0 harness-rejection echo text seen live in the historical reference
    # canary: "Rejected by user" on a call the harness answered reject_once.
    module, _ = chooser_env
    activity_stats: dict = {
        "_harness_denied_tool_call_hashes": {
            module._opaque_permission_id("edit-echo", "tool-call")
        }
    }
    with caplog.at_level(logging.INFO):
        module._log_server_pre_tool_denial(
            {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "edit-plain",
                "status": "failed",
                "rawOutput": {"summary_lines": [], "chars": 16, "text": "Rejected by user"},
            },
            activity_stats,
        )
        module._log_server_pre_tool_denial(
            {
                "sessionUpdate": "tool_call_update",
                "toolCallId": "edit-echo",
                "status": "failed",
                "rawOutput": {"summary_lines": [], "chars": 16, "text": "Rejected by user"},
            },
            activity_stats,
        )
    events = [
        json.loads(record.getMessage().split("permission telemetry ", 1)[1])
        for record in caplog.records
        if "permission telemetry " in record.getMessage()
    ]
    by_id = {
        event["tool_call_id_hash"]: event["decision_stage"] for event in events
    }
    # uncorrelated "Rejected by user" must NOT be claimed as a harness echo
    assert by_id[module._opaque_permission_id("edit-plain", "tool-call")] == "server_pre_tool"
    assert by_id[module._opaque_permission_id("edit-echo", "tool-call")] == "harness_denial_echo"


# --- fs/write policy in trusted mode --------------------------------------

def test_fs_write_workspace_allowed_but_approval_gated_still_blocked(chooser_env):
    module, workspace = chooser_env
    target = workspace / "sub" / "new_file.py"
    module._fs_write_text_file(
        {"path": str(target), "content": "print(1)\n"}, str(workspace)
    )
    assert target.read_text(encoding="utf-8") == "print(1)\n"
    ssh_config = Path.home() / ".ssh" / "config"
    with pytest.raises(PermissionError):
        module._fs_write_text_file({"path": str(ssh_config), "content": "x"}, str(workspace))
    outside = Path("/etc/definitely_outside_workspace.py")
    with pytest.raises(PermissionError):
        module._fs_write_text_file({"path": str(outside), "content": "x"}, str(workspace))


# --- full fake-ACP loop ----------------------------------------------------

FAKE_SERVER = r'''
import json
import os
import subprocess
import sys

log_path = sys.argv[1]
workspace = sys.argv[2]


def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def log(payload):
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")


def permission(tool_call_id, name, raw_input, kinds, diff_paths=None, edit_kind=False):
    request_id = next(counter)
    if diff_paths is not None:
        tool_call = {
            "toolCallId": tool_call_id, "kind": "edit", "status": "pending",
            "title": "Run client_create_file?",
            "content": [{"path": p, "newText": "x", "_meta": {"kind": "add"}, "type": "diff"}
                        for p in diff_paths],
            "locations": [{"path": p} for p in diff_paths],
            "rawInput": {"code_content_len": 1, "target_file_len": len(diff_paths[0])},
        }
    else:
        tool_call = {"toolCallId": tool_call_id, "title": str(raw_input.get("CommandLine") or ""),
                     "kind": "execute",
                     "rawInput": {"CommandLine": raw_input.get("command", ""),
                                  "Cwd": workspace, "WaitMsBeforeAsync": 5000}}
        if name:
            tool_call["name"] = name
    emit({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "session/request_permission",
        "params": {
            "toolCall": tool_call,
            "options": [{"optionId": tool_call_id + "-" + kind, "kind": kind} for kind in kinds],
        },
    })
    reply = json.loads(sys.stdin.readline())
    log({"permission_answer": {"id": reply.get("id"), "tool_call_id": tool_call_id,
                               "name": name, "result": reply.get("result")}})
    outcome = ((reply.get("result") or {}).get("outcome") or {})
    option_id = str(outcome.get("optionId") or "")
    selected_kind = next((kind for kind in kinds if option_id.endswith("-" + kind)), "unknown")
    return str(outcome.get("outcome")), selected_kind


counter = iter(range(1000, 2000))

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    params = msg.get("params") or {}
    log({"method": method, "params": params})
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method in ("session/new", "session/resume"):
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {"sessionId": "coding-session-1"}})
    elif method in ("session/set_model", "session/set_config_option"):
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/prompt":
        text = ((params.get("prompt") or [{}])[0].get("text") or "")
        if "coding-loop" in text:
            # create helpers.py via fs/write_text_file after permission
            kinds = ["allow_once", "reject_once"]  # real 1.4.0 offers no allow_always
            outcome, kind = permission("create-1", None, None, kinds, diff_paths=["helpers.py"])
            if kind.startswith("allow"):
                req = {"jsonrpc": "2.0", "id": next(counter), "method": "fs/write_text_file",
                       "params": {"path": os.path.join(workspace, "helpers.py"),
                                  "content": "def add2(a, b):\n    return a + b\n"}}
                emit(req)
                reply = json.loads(sys.stdin.readline())
                log({"fs_write": {"id": reply.get("id"), "error": reply.get("error")}})
            # edit calc.py
            outcome, kind = permission("edit-1", None, None, kinds, diff_paths=["calc.py"])
            if kind.startswith("allow"):
                req = {"jsonrpc": "2.0", "id": next(counter), "method": "fs/write_text_file",
                       "params": {"path": os.path.join(workspace, "calc.py"),
                                  "content": "from helpers import add2\n\n\ndef add(a, b):\n    return add2(a, b)\n"}}
                emit(req)
                reply = json.loads(sys.stdin.readline())
                log({"fs_write": {"id": reply.get("id"), "error": reply.get("error")}})
            # outside-workspace write must fail closed regardless of permission
            outcome, kind = permission("edit-outside-1", None, None, kinds,
                                    diff_paths=["/tmp/outside_workspace_write.py"])
            if kind.startswith("allow"):
                req = {"jsonrpc": "2.0", "id": next(counter), "method": "fs/write_text_file",
                       "params": {"path": "/tmp/outside_workspace_write.py", "content": "x"}}
                emit(req)
                reply = json.loads(sys.stdin.readline())
                log({"fs_write": {"id": reply.get("id"), "error": reply.get("error")}})
            # run pytest for real inside the workspace
            outcome, kind = permission("run-1", None, {"command": "python3 -m unittest test_calc -q"},
                                    ["allow_always", "allow_once", "reject_once"])
            pytest_summary = "not-run"
            if kind.startswith("allow"):
                done = subprocess.run([sys.executable, "-m", "unittest", "test_calc", "-q"], cwd=workspace,
                                      capture_output=True, text=True)
                lines = [line for line in (done.stderr or done.stdout).splitlines() if line.strip()]
                pytest_summary = " | ".join(lines[-2:])
            def emit_update(update):
                log({"method": "session/update", "params": {"update": update}})
                emit({"jsonrpc": "2.0", "method": "session/update",
                      "params": {"update": update}})

            emit_update({
                "sessionUpdate": "tool_call_update", "toolCallId": "run-1", "name": "run_command",
                "kind": "execute", "status": "completed",
                "rawOutput": {"summary": pytest_summary}})
            # git diff for real
            outcome, kind = permission("run-2", None, {"command": "git diff --stat"},
                                    ["allow_always", "allow_once", "reject_once"])
            diff_summary = "not-run"
            if kind.startswith("allow"):
                done = subprocess.run(["git", "diff", "--stat"], cwd=workspace,
                                      capture_output=True, text=True)
                diff_summary = (done.stdout or "").strip()
            emit_update({
                "sessionUpdate": "tool_call_update", "toolCallId": "run-2", "name": "run_command",
                "kind": "execute", "status": "completed",
                "rawOutput": {"summary": diff_summary}})
            emit({"jsonrpc": "2.0", "id": msg["id"], "result": {"stopReason": "end_turn"}})
        else:
            emit({"jsonrpc": "2.0", "id": msg["id"], "result": {"stopReason": "end_turn"}})
'''


@pytest.fixture
def coding_workspace(tmp_path):
    _ = tmp_path
    return None


def _prepare_coding_fixture(workspace: Path) -> None:
    # stdlib unittest keeps the fake loop dependency-free under the sandboxed
    # child environment (HOME is a fake home there, so user-site pytest is not
    # guaranteed to resolve).
    (workspace / "calc.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    (workspace / "test_calc.py").write_text(
        "import unittest\nfrom calc import add\n\n\nclass CalcTests(unittest.TestCase):\n"
        "    def test_add(self):\n        self.assertEqual(add(2, 3), 5)\n\n"
        "    def test_add_neg(self):\n        self.assertEqual(add(-1, 1), 0)\n\n\n"
        "if __name__ == \"__main__\":\n    unittest.main()\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=workspace, check=True)
    subprocess.run(["git", "add", "-A"], cwd=workspace, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "fixture"],
        cwd=workspace, check=True,
    )


def _run_fake_coding_loop(monkeypatch, tmp_path, *, trusted: bool):
    _stub_hermes_file_safety(monkeypatch)
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(fake_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    workspace = tmp_path / "wt-iso"
    workspace.mkdir()
    _prepare_coding_fixture(workspace)

    script = tmp_path / "fake_coding_server.py"
    script.write_text(FAKE_SERVER, encoding="utf-8")
    log_path = tmp_path / "fake_log.jsonl"
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE",
                       "trusted-coding" if trusted else "off")
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_WORKSPACE", str(workspace))
    module, client, client_module = _load_plugin(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path), str(workspace)],
        cwd=str(workspace),
    )
    assert client._trusted_coding is trusted

    completion = client.chat.completions.create(
        messages=[{"role": "user", "content": "coding-loop"}], timeout=90, stream=False
    )
    client.close()
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    return module, client, client_module, workspace, rows, completion


def test_default_mode_rejects_coding_loop_end_to_end(monkeypatch, tmp_path):
    _, _, _, workspace, rows, _ = _run_fake_coding_loop(monkeypatch, tmp_path, trusted=False)
    answers = {row["permission_answer"]["tool_call_id"]: row["permission_answer"]
               for row in rows if "permission_answer" in row}
    assert answers["create-1"]["result"]["outcome"]["optionId"] == "create-1-reject_once"
    assert answers["run-1"]["result"]["outcome"]["optionId"] == "run-1-reject_once"
    # nothing was executed: no writes, no pytest
    assert not (workspace / "helpers.py").exists()
    assert "def add(a, b):\n    return a + b\n" in (workspace / "calc.py").read_text()
    session_new = next(row for row in rows if row.get("method") == "session/new")
    assert session_new["params"]["_meta"] == {"agy": {"disabledTools": ["run_command"]}}


def test_trusted_mode_coding_loop_end_to_end(monkeypatch, tmp_path):
    _, _, _, workspace, rows, completion = _run_fake_coding_loop(
        monkeypatch, tmp_path, trusted=True
    )
    session_new = next(row for row in rows if row.get("method") == "session/new")
    assert "_meta" not in session_new["params"]

    answers = {row["permission_answer"]["tool_call_id"]: row["permission_answer"]
               for row in rows if "permission_answer" in row}
    assert answers["create-1"]["result"]["outcome"]["optionId"] == "create-1-allow_once"
    assert answers["edit-1"]["result"]["outcome"]["optionId"] == "edit-1-allow_once"
    # the harness re-checked the outside-workspace path and denied it
    assert answers["edit-outside-1"]["result"]["outcome"]["optionId"] == "edit-outside-1-reject_once"
    assert answers["run-1"]["result"]["outcome"]["optionId"] == "run-1-allow_always"
    assert answers["run-2"]["result"]["outcome"]["optionId"] == "run-2-allow_always"

    # files really changed
    assert (workspace / "helpers.py").is_file()
    calc_text = (workspace / "calc.py").read_text(encoding="utf-8")
    assert "from helpers import add2" in calc_text
    assert not (tmp_path / "outside_workspace_write.py").exists()
    assert not Path("/tmp/outside_workspace_write.py").exists()

    # the fake server really ran pytest against the edited code
    updates = {
        row["params"]["update"]["toolCallId"]: row["params"]["update"]
        for row in rows
        if row.get("method") == "session/update"
    }
    assert "Ran 2 tests" in updates["run-1"]["rawOutput"]["summary"]
    assert "OK" in updates["run-1"]["rawOutput"]["summary"]
    assert "calc.py" in updates["run-2"]["rawOutput"]["summary"]
    assert completion.choices[0].finish_reason == "stop"
