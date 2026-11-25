"""Issue #93: credential-free regression for the Parked-MCP canary lane.

``--engine parked`` drives the real deployed Parked-MCP provider/client
against a fake ACP subprocess.  These tests never start Google's server,
log in, read a credential, or call a model.  The live lane is exercised
only by an operator with separate approval and is never run here.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

CANARY_PATH = Path(__file__).resolve().parents[1] / "scripts" / "acp_live_canary.py"

PARKED_FAKE_SOURCE = r'''
import json
import os as _os
import sys
import time
import urllib.request

# The parked engine scrubs the child environment to its documented allowlist;
# a credential-shaped parent variable must therefore never appear here.
for _key in _os.environ:
    if "CANARY_TEST_SECRET" in _key:
        sys.stderr.write("ENV_GUARD_FAIL\n")
        sys.stderr.flush()

SCENARIO = "__SCENARIO__"
LOG_PATH = "__LOG_PATH__"


def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def receive():
    line = sys.stdin.readline()
    if not line:
        return None
    msg = json.loads(line)
    with open(LOG_PATH, "a", encoding="utf-8") as log:
        log.write(json.dumps(msg) + "\n")
    return msg


def chunk(text):
    return {"jsonrpc": "2.0", "method": "session/update", "params": {
        "sessionId": "parked-session-1",
        "update": {"sessionUpdate": "agent_message_chunk",
                   "content": {"type": "text", "text": text}}}}


mcp_url = None
mcp_headers = {"Content-Type": "application/json"}
rpc_seq = [0]


def mcp(method, params=None, notify=False):
    body = {"jsonrpc": "2.0", "method": method}
    if not notify:
        rpc_seq[0] += 1
        body["id"] = rpc_seq[0]
    if params is not None:
        body["params"] = params
    request = urllib.request.Request(
        mcp_url, data=json.dumps(body).encode(), headers=dict(mcp_headers))
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read()
    if notify or not raw:
        return {}
    return json.loads(raw)


def mcp_round():
    mcp("initialize", {"protocolVersion": "2025-03-26",
                       "clientInfo": {"name": "parked-fake-acp", "version": "0"},
                       "capabilities": {}})
    mcp("notifications/initialized", notify=True)
    listed = mcp("tools/list", {})
    names = sorted(tool["name"] for tool in listed.get("result", {}).get("tools", []))
    call = mcp("tools/call", {"name": "canary_echo",
                              "arguments": {"text": "ping-42"}})
    content = call.get("result", {}).get("content", [])
    return names, (content[0]["text"] if content else "")


prompt_count = 0
while True:
    request = receive()
    if request is None:
        break
    method = request.get("method")
    rpc_id = request.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": rpc_id, "result": {
            "protocolVersion": 1, "agentInfo": {"name": "parked-fake"}}})
    elif method == "session/new":
        servers = (request.get("params") or {}).get("mcpServers") or []
        if servers:
            mcp_url = servers[0]["url"]
            for header in servers[0].get("headers") or []:
                mcp_headers[header["name"]] = header["value"]
        emit({"jsonrpc": "2.0", "id": rpc_id, "result": {
            "sessionId": "parked-session-1",
            "models": {"availableModels": [{"modelId": "fake-test-model"}]}}})
    elif method in ("session/set_model", "session/set_config_option"):
        emit({"jsonrpc": "2.0", "id": rpc_id, "result": {}})
    elif method == "session/prompt":
        prompt_count += 1
        if SCENARIO == "parked_no_tool":
            emit(chunk("PLAIN_ANSWER_NO_TOOL"))
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "stopReason": "end_turn",
                "usage": {"inputTokens": 40, "outputTokens": 8,
                          "totalTokens": 48}}})
        elif prompt_count == 1:
            names, echoed = mcp_round()
            emit(chunk("TOOL_ROUND tools=" + ",".join(names)
                       + " echo=" + echoed))
            if SCENARIO == "parked_inflated_usage":
                usage = {"inputTokens": 10_000_000, "outputTokens": 8,
                         "totalTokens": 10_000_008}
            else:
                usage = {"inputTokens": 40, "outputTokens": 8,
                         "totalTokens": 48}
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "stopReason": "end_turn", "usage": usage}})
        else:
            emit(chunk("FOLLOW_UP_ANSWER ping-42"))
            if SCENARIO == "parked_inflated_usage":
                usage = {"inputTokens": 10_000_000, "outputTokens": 8,
                         "totalTokens": 10_000_008}
            else:
                usage = {"inputTokens": 60, "outputTokens": 10,
                         "totalTokens": 70}
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "stopReason": "end_turn", "usage": usage}})
            time.sleep(3)
            break
    # unknown methods: stay silent (the fake advertises no optional caps)
'''


@pytest.fixture
def canary():
    spec = importlib.util.spec_from_file_location("parked_lane_acp_canary", CANARY_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parked_fake(tmp_path: Path, scenario: str) -> tuple[Path, Path]:
    """A fake ACP server with the scenario baked into the script itself.

    The parked engine hands its child only the documented environment
    allowlist, so scenario configuration cannot travel by env var; embedding
    it is the supported way to configure a fake for this lane.
    """
    log_path = tmp_path / "parked_requests.jsonl"
    script = tmp_path / "parked_fake_acp.py"
    script.write_text(
        PARKED_FAKE_SOURCE.replace("__SCENARIO__", scenario)
        .replace("__LOG_PATH__", str(log_path)),
        encoding="utf-8",
    )
    binary = tmp_path / "parked-fake-acp"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import runpy\n"
        f"runpy.run_path({str(script)!r}, run_name='__main__')\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    return binary, log_path


def _parked_argv(tmp_path: Path, *extra):
    return [
        "acp_live_canary.py",
        "--repo", str(CANARY_PATH.parents[1]),
        "--cwd", str(tmp_path),
        "--mode", "default",
        "--engine", "parked",
        "--evidence", str(tmp_path / "evidence"),
        "--model", "fake-test-model",
        *extra,
    ]


def _run_parked(canary, monkeypatch, tmp_path: Path, scenario: str,
                extra_argv=()):
    binary, log_path = _parked_fake(tmp_path, scenario)
    monkeypatch.setenv("ACP_CANARY_TEST_SECRET", "NEVER_PASS_PARENT_ENV")
    evidence = tmp_path / "evidence"
    monkeypatch.setattr(sys, "argv", _parked_argv(
        tmp_path, "--fake-acp-only", "--command", str(binary), *extra_argv))
    code = canary.main()
    summary = json.loads((evidence / "summary.json").read_text(encoding="utf-8"))
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    requests = (
        [json.loads(line) for line in
         log_path.read_text(encoding="utf-8").splitlines() if line]
        if log_path.exists() else []
    )
    return code, summary, frames_text, requests


@pytest.mark.parametrize("lane_flags", ([], ["--fake-acp-only", "--operator-supervised-live"]))
def test_parked_requires_exactly_one_lane(canary, monkeypatch, tmp_path, lane_flags):
    """No lane, or both lanes: the parked engine refuses before any spawn."""
    monkeypatch.setattr(sys, "argv", _parked_argv(tmp_path, *lane_flags))
    assert canary.main() == 2


def test_parked_refuses_raw_probe_mode(canary, monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", [
        "acp_live_canary.py", "--repo", str(CANARY_PATH.parents[1]),
        "--cwd", str(tmp_path), "--mode", "raw-probe", "--engine", "parked",
        "--fake-acp-only", "--evidence", str(tmp_path / "evidence"),
        "--model", "fake-test-model", "--command", str(tmp_path / "nothing"),
    ])
    assert canary.main() == 2


def test_parked_fake_lane_refuses_official_binary(canary, monkeypatch, tmp_path):
    official = tmp_path / "antigravity-acp-official"
    official.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    official.chmod(0o700)
    monkeypatch.setattr(sys, "argv", _parked_argv(
        tmp_path, "--fake-acp-only", "--command", str(official)))
    assert canary.main() == 2


def test_parked_fake_lane_full_round(canary, monkeypatch, tmp_path):
    """Model selection, plain answer, parked MCP round, follow-up, usage,
    containment and teardown all pass against the fake, with no replay
    client construction anywhere on the path."""
    original_loader = canary.load_client_module

    def spy_loader(repo):
        module = original_loader(repo)

        def _no_replay_fallback(**kwargs):
            raise AssertionError(
                "parked lane must not construct the replay client")

        module.antigravity_acp_replay.create_client = _no_replay_fallback
        return module

    monkeypatch.setattr(canary, "load_client_module", spy_loader)
    code, summary, frames_text, requests = _run_parked(
        canary, monkeypatch, tmp_path, "parked_round")

    assert summary["error"] is None, summary
    assert summary["engine"] == "parked"
    assert summary["client_class"] == "AntigravityAcpMcpClient"
    assert code == 0, summary
    verdicts = summary["verdicts"]
    assert verdicts["parked_tool_round"] == "pass"
    assert verdicts["plain_response"] == "pass"
    assert verdicts["follow_up_same_session"] == "pass"
    assert verdicts["usage_contract"] == "pass"
    assert verdicts["containment"] == "pass"
    assert verdicts["normal_teardown"] == "pass"
    assert verdicts["model_selection"] == "pass"

    tool_round = summary["tool_round"]
    assert tool_round["calls_observed"] is True
    assert tool_round["call_id_shape_ok"] is True
    # Parked contract: the tool result is answered into the SAME held prompt.
    assert tool_round["prompt_requests_across_round"] == 1
    assert "canary_echo" in summary["answers"]["final"]
    assert "ping-42" in summary["answers"]["follow_up"]

    follow_up = summary["follow_up"]
    assert follow_up["session_new_requests_total"] == 1
    assert follow_up["prompt_requests_total"] == 2
    assert follow_up["model_selection_requests_total"] == 1

    assert summary["usage"]["final_turn_reported"] == {
        "prompt_tokens": 60, "completion_tokens": 10, "total_tokens": 70}
    assert summary["usage"]["billing_claim"].startswith("none")

    assert summary["containment"]["recorded_matches_engine_declaration_prefix"] is True
    assert summary["containment"]["run_command_in_engine_native_tools"] is True

    assert summary["teardown"]["acp_connections"] >= 1
    assert summary["teardown"]["direct_children_exited"] is True
    assert "not asserted" in summary["teardown"]["descendant_tree"]

    methods = [r.get("method") for r in requests]
    assert methods.count("session/new") == 1
    assert methods.count("session/prompt") == 2
    assert "session/set_model" in methods
    session_new = next(r for r in requests if r.get("method") == "session/new")
    server = (session_new.get("params") or {})["mcpServers"][0]
    assert server["url"].startswith("http://127.0.0.1:")
    disabled = session_new["params"]["_meta"]["antigravity"]["disabledTools"]
    # Authoritative list straight from the engine source (the evidence
    # recording is sanitizer-capped at 40 entries; the fake sees everything).
    import ast
    session_src = (CANARY_PATH.parents[1] / "hermes-plugin" / "antigravity-acp"
                   / "parked" / "session.py").read_text(encoding="utf-8")
    native: list[str] | None = None
    for node in ast.walk(ast.parse(session_src)):
        if (isinstance(node, ast.Assign)
                and getattr(node.targets[0], "id", "") == "NATIVE_TOOLS"
                and isinstance(node.value, ast.List)):
            native = [str(ast.literal_eval(el)) for el in node.value.elts]
    assert native is not None and len(native) > 40  # cap story holds
    assert list(disabled) == list(native)
    assert "run_command" in disabled

    # The per-run loopback bearer token is a secret: it must never reach
    # evidence, while the sanitizer records the redaction.
    assert "Bearer " not in frames_text
    assert "<redacted>" in frames_text


def test_parked_tool_round_inconclusive_is_not_a_failure(
    canary, monkeypatch, tmp_path
):
    """A model that never calls the advertised tool yields an inconclusive
    probe (exit 0), never a silent pass and never a fabricated failure."""
    code, summary, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_no_tool")
    assert summary["error"] is None
    assert code == 0
    assert summary["verdicts"]["parked_tool_round"] == "inconclusive"
    assert summary["verdicts"]["plain_response"] == "pass"
    assert summary["tool_round"]["calls_observed"] is False


def test_parked_inflated_usage_is_gated_and_visible(
    canary, monkeypatch, tmp_path
):
    """A wildly inflated server usage report is rejected by the shared
    usage contract: the summary reports no usage, surfaces the rejection in
    the engine log facts, and the run is inconclusive rather than silently
    passing."""
    code, summary, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_inflated_usage")
    assert summary["error"] is None
    assert code == 0
    assert summary["usage"]["final_turn_reported"] is None
    assert summary["verdicts"]["usage_contract"] == "inconclusive"
    assert any("rejected" in line for line in summary["engine_log_facts"])
    # The parked round itself still worked; usage gating is independent.
    assert summary["verdicts"]["parked_tool_round"] == "pass"
