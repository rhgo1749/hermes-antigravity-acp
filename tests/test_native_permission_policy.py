"""Native permission fail-closed policy regressions (catalog review fix).

Replaces the former trusted-coding-mode suite.  Covers the behaviour the
Hermes catalog review requires before listing:

- no native ``run_command`` or native file-mutation permission frame is ever
  auto-approved, in any environment, even inside the session workspace and
  even when the server offers ``allow_always`` first;
- the retired ``HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE`` /
  ``HERMES_ANTIGRAVITY_ACP_WORKSPACE`` switches are inert and the
  auto-approval machinery no longer exists;
- Hermes' original terminal-tool instruction is restored byte-identically in
  the prompt preamble (no "pre-approved" replacement text);
- the read-only Hermes scratch permission route is preserved; ACP fs/write
  callbacks are denied and file modifications use Hermes tools;
- ``session/new`` always pins ``agy.disabledTools=[run_command]``;
- a scripted fake-ACP loop checks native and callback denial and emits Hermes
  tool calls; it does not claim a real model autonomously falls back.
"""

from __future__ import annotations

import importlib.util
import io
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
    # the retired switches must never leak in from the developer host either
    for var in ("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", "HERMES_ANTIGRAVITY_ACP_WORKSPACE"):
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
        f"/tmp/antigravity-acp-failclosed-{os.getpid()}-{id(monkeypatch)}.json",
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        f"/tmp/antigravity-acp-failclosed-limits-{os.getpid()}-{id(monkeypatch)}.json",
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

    module_name = "antigravity_acp_failclosed_test"
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


@pytest.fixture
def policy_env(monkeypatch, tmp_path):
    _stub_hermes_file_safety(monkeypatch)
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(fake_home))
    monkeypatch.setenv("HERMES_REAL_HOME", str(fake_home))
    monkeypatch.setenv("HOME", str(fake_home))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, client, module = _load_plugin(monkeypatch, cwd=str(workspace))
    return client, module, workspace


class FakeProcess:
    def __init__(self):
        self.stdin = io.StringIO()

    def responses(self):
        text = self.stdin.getvalue().strip()
        return [json.loads(line) for line in text.splitlines() if line]


def _ask(client, params, cwd):
    process = FakeProcess()
    handled = client._handle_server_message(
        {"jsonrpc": "2.0", "id": 77, "method": "session/request_permission", "params": params},
        process=process,
        cwd=cwd,
        text_parts=None,
        reasoning_parts=None,
    )
    assert handled
    return process.responses()


def _options(*kinds: tuple[str, str]):
    return [{"kind": kind, "optionId": option_id} for kind, option_id in kinds]


def _request(name: str, raw_input: dict | None):
    return {
        "toolCall": {
            "toolCallId": f"call-{name}",
            "name": name,
            "title": f"Running {name}",
            **({"rawInput": raw_input} if raw_input is not None else {}),
        },
        "options": _options(
            ("allow_always", "always"), ("allow_once", "once"), ("reject_once", "reject")
        ),
    }


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


# --- the auto-approval machinery no longer exists --------------------------

@pytest.mark.parametrize(
    "mode_value", ["", "trusted", "trusted_coding", "trusted-coding", "codex", "TRUSTED-X"]
)
def test_auto_approval_machinery_is_gone_regardless_of_legacy_env(monkeypatch, tmp_path, mode_value):
    if mode_value:
        monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", mode_value)
    else:
        monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", raising=False)
    _, client, module = _load_plugin(monkeypatch)
    assert not hasattr(module, "_trusted_coding_mode_enabled")
    assert not hasattr(module, "_trusted_coding_permission_option")
    assert not hasattr(module, "_TRUSTED_NATIVE_MUTATION_TOOLS")
    assert not hasattr(module, "_TRUSTED_CODING_PREAMBLE_REPLACEMENTS")
    assert not hasattr(client, "_trusted_coding")


def test_legacy_workspace_env_is_inert(monkeypatch, tmp_path):
    workspace = tmp_path / "pinned"
    workspace.mkdir()
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_WORKSPACE", str(workspace))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("HERMES_REAL_HOME", str(tmp_path / "home"))
    _, _, module = _load_plugin(monkeypatch)
    # the retired operator pin can no longer relocate the session root and
    # can no longer abort startup with a RuntimeError
    assert module._resolve_acp_working_directory(None) == str(Path(os.getcwd()).resolve())
    other = tmp_path / "explicit"
    other.mkdir()
    assert module._resolve_acp_working_directory(str(other)) == str(other.resolve())


# --- every native mutation frame is denied, in-workspace included ----------

def test_named_native_mutation_frames_denied_in_workspace(policy_env):
    client, _, workspace = policy_env
    for name, raw_input in (
        ("client_create_file", {"absolute_path": str(workspace / "helpers.py")}),
        ("client_edit_file", {"path": str(workspace / "calc.py")}),
        ("run_command", {"command": "python3 -m pytest -q"}),
    ):
        responses = _ask(client, _request(name, raw_input), str(workspace))
        assert len(responses) == 1, "the harness must answer exactly once"
        outcome = responses[0]["result"]["outcome"]
        assert outcome == {"outcome": "selected", "optionId": "reject"}, (
            f"{name} must select the offered reject option, never allow_always"
        )


def test_nameless_builtin_diff_and_execute_frames_denied(policy_env):
    client, _, workspace = policy_env
    # live 1.4.0 built-in shapes: nameless diff and nameless execute frames
    for params in (
        _nameless_diff_request(["helpers.py"]),
        _nameless_diff_request([str(workspace / "sub" / "deep.py")]),
        _nameless_execute(str(workspace)),
        _nameless_execute("relative-sub"),
    ):
        responses = _ask(client, params, str(workspace))
        assert len(responses) == 1
        outcome = responses[0]["result"]["outcome"]
        assert outcome["outcome"] == "selected"
        assert outcome["optionId"] == "reject"


def test_denied_frames_never_select_any_allow_option(policy_env):
    client, _, workspace = policy_env
    # every combination the removed chooser used to accept must now deny
    frames = [
        _request("client_create_file", {"path": "relative.py"}),
        _request("client_edit_file", {"target_file": "sub/inner.py"}),
        _request("run_command", {"command": "git diff --stat"}),
        _nameless_diff_request(["ok.py", "also_ok.py"]),
    ]
    for params in frames:
        responses = _ask(client, params, str(workspace))
        selected = responses[0]["result"]["outcome"].get("optionId")
        assert selected in {"reject", "always", "once"} and selected == "reject", (
            "no allow option may ever be selected for a native mutation frame"
        )


def test_read_only_scratch_permission_route_is_preserved(policy_env):
    client, _, workspace = policy_env
    # the preserved read-only route: a known native read built-in under the
    # Hermes scratch evidence root still receives its allow_once option
    scratch = Path(os.environ["HERMES_HOME"]) / "cache" / "scratch" / "evidence.log"
    responses = _ask(
        client,
        _request("client_view_file", {"absolute_path": str(scratch)}),
        str(workspace),
    )
    outcome = responses[0]["result"]["outcome"]
    assert outcome["outcome"] == "selected"
    assert outcome["optionId"] == "once", (
        "the read-only scratch allow-once route must survive the fail-closed change"
    )


# --- prompt preamble restored to Hermes' original instruction --------------

def test_preamble_original_terminal_instruction_restored(policy_env):
    _, module, _ = policy_env
    prompt = module._format_messages_as_prompt([{"role": "user", "content": "x"}])
    assert (
        "For shell commands, builds, tests, and GitHub CLI work, use an available "
        "Hermes terminal tool via " in prompt
    )
    assert "ACP-native run_command is disabled in Hermes model-provider mode." in prompt
    assert "pre-approved" not in prompt
    assert "trusted coding-agent mode" not in prompt
    assert module._format_messages_as_prompt.__code__.co_varnames.count("trusted_coding") == 0


def test_fingerprint_has_no_execution_mode_axis(policy_env):
    _, module, _ = policy_env
    base = module._context_fingerprint("model-x", None, None)
    assert module._context_fingerprint("model-x", None, None) == base
    with pytest.raises(TypeError):
        module._context_fingerprint("model-x", None, None, execution_mode="trusted-coding")


# --- denial attribution: harness echo is never a user denial ---------------

def test_denied_by_user_after_harness_reject_is_attributed_to_harness(policy_env, caplog):
    _, module, _ = policy_env
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


def test_140_rejected_by_user_echo_requires_correlation(policy_env, caplog):
    # official 1.4.0 harness-rejection echo text seen live in the canary:
    # "Rejected by user" on a call the harness answered reject_once.
    _, module, _ = policy_env
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
    by_id = {event["tool_call_id_hash"]: event["decision_stage"] for event in events}
    # uncorrelated "Rejected by user" must NOT be claimed as a harness echo
    assert by_id[module._opaque_permission_id("edit-plain", "tool-call")] == "server_pre_tool"
    assert by_id[module._opaque_permission_id("edit-echo", "tool-call")] == "harness_denial_echo"


# --- ACP callback writes are always refused ---------------------------------

@pytest.mark.parametrize("surface", ["cli", "gateway", "cron", "subagent"])
@pytest.mark.parametrize("name", [
    "AGENTS.md", "CLAUDE.md", "SOUL.md", ".cursorrules", ".hermes/config.yaml",
    "config.yaml", "ordinary.py", "../outside.py",
])
def test_fs_write_callback_denied_for_all_paths_and_surfaces(policy_env, monkeypatch, surface, name):
    client, module, workspace = policy_env
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", surface)
    if surface == "cron":
        monkeypatch.setenv("HERMES_CRON_SESSION", "1")
    if surface == "subagent":
        monkeypatch.setenv("HERMES_DELEGATED_CHILD_CONTEXT", "1")
    target = workspace / name
    # Both raw relative and absolute paths are rejected, including existing files.
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("original", encoding="utf-8")
    for path in (name, str(target.resolve())):
        process = FakeProcess()
        client._handle_server_message(
            {"jsonrpc": "2.0", "id": 91, "method": "fs/write_text_file",
             "params": {"path": path, "content": "changed"}},
            process=process, cwd=str(workspace), text_parts=None, reasoning_parts=None,
        )
        assert "error" in process.responses()[0]
        assert target.read_text(encoding="utf-8") == "original"
    link = workspace / "link-to-target"
    try:
        link.symlink_to(target.resolve())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(PermissionError):
        module._fs_write_text_file({"path": str(link), "content": "changed"}, str(workspace))
    assert target.read_text(encoding="utf-8") == "original"


def test_active_config_write_and_symlink_are_denied(policy_env, monkeypatch, tmp_path):
    client, _, workspace = policy_env
    hermes_home = tmp_path / "active-hermes-home"
    hermes_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    active_config = hermes_home / "config.yaml"
    active_config.write_text("original: true\n", encoding="utf-8")
    link = workspace / "active-config-link.yaml"
    try:
        link.symlink_to(active_config)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    for path in (str(active_config), str(link)):
        process = FakeProcess()
        client._handle_server_message(
            {"jsonrpc": "2.0", "id": 92, "method": "fs/write_text_file",
             "params": {"path": path, "content": "changed"}},
            process=process, cwd=str(workspace), text_parts=None, reasoning_parts=None,
        )
        assert "error" in process.responses()[0]
        assert active_config.read_text(encoding="utf-8") == "original: true\n"


# --- Workspace writes are also denied ---------------------------------------

def test_fs_write_workspace_is_also_blocked(policy_env):
    _, module, workspace = policy_env
    target = workspace / "sub" / "new_file.py"
    with pytest.raises(PermissionError, match="ACP fs/write_text_file is disabled"):
        module._fs_write_text_file({"path": str(target), "content": "print(1)\n"}, str(workspace))
    assert not target.exists()


# --- full fake-ACP coding loop under the fail-closed policy ----------------

FAKE_SERVER = r'''
import json
import os
import sys

log_path = sys.argv[1]
workspace = sys.argv[2]


def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def log(payload):
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")


def permission(tool_call_id, raw_input, kinds, diff_paths=None):
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
                               "result": reply.get("result")}})
    outcome = ((reply.get("result") or {}).get("outcome") or {})
    option_id = str(outcome.get("optionId") or "")
    selected_kind = next((kind for kind in kinds if option_id.endswith("-" + kind)), "unknown")
    return str(outcome.get("outcome")), selected_kind


def harness_write(path, content):
    req = {"jsonrpc": "2.0", "id": next(counter), "method": "fs/write_text_file",
           "params": {"path": path, "content": content}}
    emit(req)
    reply = json.loads(sys.stdin.readline())
    log({"fs_write": {"id": reply.get("id"), "path": path, "error": reply.get("error")}})


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
            kinds = ["allow_always", "allow_once", "reject_once"]
            # native create/edit/execute frames: the fail-closed harness must
            # reject every one of them, each answered exactly once
            permission("create-1", None, kinds, diff_paths=["helpers.py"])
            permission("edit-1", None, kinds, diff_paths=["calc.py"])
            permission("edit-outside-1", None, kinds,
                       diff_paths=["/tmp/outside_workspace_write.py"])
            permission("run-1", {"command": "python3 -m unittest test_calc -q"}, kinds)
            # A scripted server attempts callback writes even though initialization
            # advertises no write capability. Each must be refused.
            harness_write(os.path.join(workspace, "helpers.py"),
                          "def add2(a, b):\n    return a + b\n")
            harness_write(os.path.join(workspace, "calc.py"),
                          "from helpers import add2\n\n\ndef add(a, b):\n    return add2(a, b)\n")
            harness_write("/tmp/outside_workspace_write.py", "x")
            # The server emits ordinary Hermes tool calls instead; the caller,
            # not this ACP fixture, owns tool execution and approvals.
            calls = [
                {"id": "call-write-1", "type": "function", "function": {
                    "name": "write_file", "arguments": json.dumps({
                        "path": os.path.join(workspace, "helpers.py"),
                        "content": "def add2(a, b):\n    return a + b\n"})}},
                {"id": "call-term-1", "type": "function", "function": {
                    "name": "terminal", "arguments": json.dumps({
                        "command": "python3 -m unittest test_calc -q"})}},
            ]
            answer = "".join("<tool_call>" + json.dumps(call) + "</tool_call>" for call in calls)
            emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                "sessionUpdate": "agent_message_chunk", "toolCallId": "answer-1",
                "content": {"type": "text", "text": answer}}}})
            emit({"jsonrpc": "2.0", "id": msg["id"], "result": {"stopReason": "end_turn"}})
        else:
            emit({"jsonrpc": "2.0", "id": msg["id"], "result": {"stopReason": "end_turn"}})
'''


def _prepare_coding_fixture(workspace: Path) -> None:
    # stdlib unittest keeps the fake loop dependency-free under the sandboxed
    # child environment (HOME is a fake home there, so user-site pytest is not
    # guaranteed to resolve).
    (workspace / "calc.py").write_text(
        "def add(a, b):\n    return a + b\n", encoding="utf-8"
    )
    (workspace / "test_calc.py").write_text(
        "import unittest\nfrom calc import add\n\n\n"
        "class CalcTests(unittest.TestCase):\n"
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


WRITE_TOOL = {
    "type": "function",
    "function": {
        "name": "write_file",
        "description": "Write a file through Hermes.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
}


TERMINAL_TOOL = {
    "type": "function",
    "function": {
        "name": "terminal",
        "description": "Run a shell command through Hermes (approval-gated).",
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
}


def test_fail_closed_coding_loop_end_to_end(monkeypatch, tmp_path):
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
    module, client, _ = _load_plugin(
        monkeypatch,
        command=sys.executable,
        args=[str(script), str(log_path), str(workspace)],
        cwd=str(workspace),
    )

    completion = client.chat.completions.create(
        messages=[{"role": "user", "content": "coding-loop"}],
        tools=[WRITE_TOOL, TERMINAL_TOOL],
        timeout=90,
        stream=False,
    )
    client.close()
    rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]

    # 1. session launch pins the native run_command disable
    initialize = next(row for row in rows if row.get("method") == "initialize")
    assert initialize["params"]["clientCapabilities"]["fs"] == {
        "readTextFile": True, "writeTextFile": False,
    }
    session_new = next(row for row in rows if row.get("method") == "session/new")
    assert session_new["params"]["_meta"] == {"agy": {"disabledTools": ["run_command"]}}

    # 2. every native permission frame was denied exactly once with reject_once
    answers = {row["permission_answer"]["tool_call_id"]: row["permission_answer"]
               for row in rows if "permission_answer" in row}
    assert set(answers) == {"create-1", "edit-1", "edit-outside-1", "run-1"}
    for tool_call_id, answer in answers.items():
        outcome = answer["result"]["outcome"]
        assert outcome["outcome"] == "selected", tool_call_id
        assert outcome["optionId"] == f"{tool_call_id}-reject_once", tool_call_id

    # 3. All three callback writes were refused, including ordinary workspace files.
    writes = [row["fs_write"] for row in rows if "fs_write" in row]
    assert len(writes) == 3
    assert all(write["error"] is not None for write in writes)
    assert not (workspace / "helpers.py").exists()
    assert (workspace / "calc.py").read_text(encoding="utf-8") == (
        "def add(a, b):\n    return a + b\n"
    )

    # 4. The scripted server emitted Hermes write_file and terminal calls.
    # This proves the bridge, not execution of the tools by Hermes.
    message = completion.choices[0].message
    assert completion.choices[0].finish_reason == "tool_calls"
    calls = {call.function.name: call for call in message.tool_calls}
    assert set(calls) == {"write_file", "terminal"}
    assert json.loads(calls["write_file"].function.arguments)["path"] == str(workspace / "helpers.py")
    assert "unittest" in json.loads(calls["terminal"].function.arguments)["command"]
    del module
