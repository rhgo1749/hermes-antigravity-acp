"""Issue #93: credential-free regression for the Parked-MCP canary lane.

``--engine parked`` drives the real deployed Parked-MCP provider/client
against a fake ACP subprocess.  These tests never start Google's server,
log in, read a credential, or call a model.  The live lane is exercised
only by an operator with separate approval and is never run here.

Each review finding on PR #95 has a named regression test below:
evidence redaction, fake-lane isolation (explicit command, no env/launcher
resolution, resolved-path refusal), sentinel-proven tool rounds, selection
success vs request, declaration vs enforcement, gated usage, teardown
fail-vs-inconclusive, wall-clock timeout with child reaping, cancellation,
and the overall verdict / exit-code contract (0 pass, 1 fail, 2 preflight,
3 inconclusive).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

CANARY_PATH = Path(__file__).resolve().parents[1] / "scripts" / "acp_live_canary.py"

# Secret-shaped literals the fake smuggles into server-visible positions;
# every one of them must be absent from every evidence file.
SECRET_SESSION_ID = "sess-SECRET-SESSION-00042"
SECRET_BEARER = "leaked-bearer-token-999"
SECRET_ASSIGNMENT = "LEAKED-ACCESS-TOKEN-999"
SECRET_MCP_PATH = "SECRETPART-ALPHA"

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
PID_PATH = "__PID_PATH__"
SESSION_ID = "__SESSION_ID__"

with open(PID_PATH, "w", encoding="utf-8") as _pid_file:
    _pid_file.write(str(_os.getpid()))


def log_msg(payload):
    with open(LOG_PATH, "a", encoding="utf-8") as log:
        log.write(json.dumps(payload) + "\n")


def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def receive():
    line = sys.stdin.readline()
    if not line:
        return None
    msg = json.loads(line)
    log_msg(msg)
    return msg


def chunk(text):
    return {"jsonrpc": "2.0", "method": "session/update", "params": {
        "sessionId": SESSION_ID,
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


def native_permission_probe():
    """Ask the engine to permit a NATIVE tool (run_command); the engine's
    permission gate must refuse it.  The request/response ride the ACP
    stdio the canary tees, so the canary judges the engine's own answer."""
    emit({"jsonrpc": "2.0", "id": "perm-probe-1",
          "method": "session/request_permission",
          "params": {"sessionId": SESSION_ID,
                     "toolCall": {"toolCallId": "native-probe-1",
                                  "name": "run_command",
                                  "title": "canary-native-probe run_command",
                                  "kind": "native"},
                     "options": [{"optionId": "opt-allow", "kind": "allow_once"},
                                 {"optionId": "opt-reject", "kind": "reject_once"}]}})
    while True:
        line = sys.stdin.readline()
        if not line:
            sys.exit(0)
        msg = json.loads(line)
        log_msg({"__perm_response__": msg})
        if msg.get("id") == "perm-probe-1" and ("result" in msg or "error" in msg):
            return


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
            "sessionId": SESSION_ID,
            "models": {"availableModels": [{"modelId": "fake-test-model"}]}}})
    elif method in ("session/set_model", "session/set_config_option"):
        if SCENARIO == "parked_model_error" and method == "session/set_model":
            emit({"jsonrpc": "2.0", "id": rpc_id,
                  "error": {"code": -32603, "message": "model unavailable"}})
        else:
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {}})
    elif method == "session/prompt":
        params = request.get("params") or {}
        if "canary cancel probe" in json.dumps(params):
            # Cancellation probe: hold the prompt until the engine sends
            # session/cancel, then finish it as cancelled.
            while True:
                line = sys.stdin.readline()
                if not line:
                    sys.exit(0)
                msg = json.loads(line)
                log_msg(msg)
                if msg.get("method") == "session/cancel":
                    break
            emit({"jsonrpc": "2.0", "id": rpc_id,
                  "result": {"stopReason": "cancelled"}})
            continue
        prompt_count += 1
        if SCENARIO == "parked_hang":
            time.sleep(3600)
        if SCENARIO == "parked_no_tool":
            emit(chunk("PLAIN_ANSWER_NO_TOOL"))
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "stopReason": "end_turn",
                "usage": {"inputTokens": 40, "outputTokens": 8,
                          "totalTokens": 48}}})
        elif prompt_count == 1:
            if SCENARIO in ("parked_round", "parked_no_sentinel",
                            "parked_inflated_usage"):
                native_permission_probe()
            names, echoed = mcp_round()
            leak = ""
            if SCENARIO == "parked_round":
                leak = (" leak Bearer " + "__SECRET_BEARER__"
                        + " access_token=__SECRET_ASSIGNMENT__"
                        + " http://127.0.0.1:17777/mcp/__SECRET_MCP_PATH__")
            if SCENARIO == "parked_no_sentinel":
                emit(chunk("TOOL_ROUND tools=" + ",".join(names) + leak))
            else:
                emit(chunk("TOOL_ROUND tools=" + ",".join(names)
                           + " echo=" + echoed + leak))
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
    # unknown methods: stay silent (the fake advertises no optional caps)
'''


@pytest.fixture
def canary():
    spec = importlib.util.spec_from_file_location("parked_lane_acp_canary", CANARY_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parked_fake(tmp_path: Path, scenario: str) -> tuple[Path, Path, Path]:
    """A fake ACP server with the scenario baked into the script itself.

    The parked engine hands its child only the documented environment
    allowlist, so scenario configuration cannot travel by env var; embedding
    it is the supported way to configure a fake for this lane.
    """
    log_path = tmp_path / "parked_requests.jsonl"
    pid_path = tmp_path / "parked_fake.pid"
    script = tmp_path / "parked_fake_acp.py"
    script_text = (
        PARKED_FAKE_SOURCE.replace("__SCENARIO__", scenario)
        .replace("__LOG_PATH__", str(log_path))
        .replace("__PID_PATH__", str(pid_path))
        .replace("__SESSION_ID__", SECRET_SESSION_ID)
        .replace("__SECRET_BEARER__", SECRET_BEARER)
        .replace("__SECRET_ASSIGNMENT__", SECRET_ASSIGNMENT)
        .replace("__SECRET_MCP_PATH__", SECRET_MCP_PATH)
    )
    script.write_text(script_text, encoding="utf-8")
    binary = tmp_path / "parked-fake-acp"
    binary.write_text(
        f"#!{sys.executable}\n"
        "import runpy\n"
        f"runpy.run_path({str(script)!r}, run_name='__main__')\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    return binary, log_path, pid_path


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
    binary, log_path, pid_path = _parked_fake(tmp_path, scenario)
    monkeypatch.setenv("ACP_CANARY_TEST_SECRET", "NEVER_PASS_PARENT_ENV")
    evidence = tmp_path / "evidence"
    monkeypatch.setattr(sys, "argv", _parked_argv(
        tmp_path, "--fake-acp-only", "--command", str(binary), *extra_argv))
    code = canary.main()
    summary_text = (evidence / "summary.json").read_text(encoding="utf-8")
    summary = json.loads(summary_text)
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    requests = (
        [json.loads(line) for line in
         log_path.read_text(encoding="utf-8").splitlines() if line]
        if log_path.exists() else []
    )
    return code, summary, frames_text, summary_text, requests, pid_path


def _assert_pid_dead(pid_path: Path) -> None:
    import time as _time
    pid = int(pid_path.read_text(encoding="utf-8"))
    deadline = _time.monotonic() + 10.0
    while _time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        _time.sleep(0.1)
    raise AssertionError(f"fake ACP child pid {pid} still alive after canary exit")


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


def test_parked_fake_lane_requires_explicit_command(canary, monkeypatch, tmp_path):
    """P1 regression: the fake lane must never fall back to the engine's
    env/launcher resolution; an explicit --command is mandatory."""
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", str(tmp_path / "mux-launcher"))
    monkeypatch.setattr(sys, "argv", _parked_argv(tmp_path, "--fake-acp-only"))
    assert canary.main() == 2
    assert not (tmp_path / "evidence").exists()


def test_parked_fake_lane_never_executes_env_launcher(canary, monkeypatch, tmp_path):
    """P1 regression: even with the MUX/launcher env override pointing at an
    executable marker, the fake lane must run ONLY the explicit fake binary
    and never touch the env-resolved launcher."""
    marker = tmp_path / "env-launcher-ran"
    env_launcher = tmp_path / "mux-launcher"
    env_launcher.write_text(
        f"#!{sys.executable}\n"
        f"open({str(marker)!r}, 'w').write('ran')\n"
        "import time; time.sleep(30)\n",
        encoding="utf-8",
    )
    env_launcher.chmod(0o700)
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", str(env_launcher))
    code, summary, _, _, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_round")
    assert not marker.exists(), "fake lane executed the env-resolved launcher"
    assert summary["overall"] == "pass", summary
    # The scrubbed override is restored after the run.
    assert os.environ.get("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND") == str(env_launcher)


def test_parked_fake_lane_refuses_official_path_via_symlink(
    canary, monkeypatch, tmp_path
):
    """P1 regression: refusal is by RESOLVED path, not by file name — a
    differently-named symlink to the official launcher is still refused."""
    fake_home = tmp_path / "home"
    official = fake_home / ".local" / "bin" / "antigravity-acp-official"
    official.parent.mkdir(parents=True)
    official.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    official.chmod(0o700)
    monkeypatch.setenv("HOME", str(fake_home))
    disguised = tmp_path / "totally-not-official"
    disguised.symlink_to(official)
    monkeypatch.setattr(sys, "argv", _parked_argv(
        tmp_path, "--fake-acp-only", "--command", str(disguised)))
    assert canary.main() == 2


def test_parked_fake_lane_full_round(canary, monkeypatch, tmp_path):
    """Model discovery+selection success, plain answer, sentinel-proven
    parked MCP round, follow-up, gated usage, containment declaration,
    native permission enforcement, cancellation and teardown all pass
    against the fake — and every per-run secret stays out of the evidence."""
    original_loader = canary.load_client_module

    def spy_loader(repo):
        module = original_loader(repo)

        def _no_replay_fallback(**kwargs):
            raise AssertionError(
                "parked lane must not construct the replay client")

        module.antigravity_acp_replay.create_client = _no_replay_fallback
        return module

    monkeypatch.setattr(canary, "load_client_module", spy_loader)
    code, summary, frames_text, summary_text, requests, pid_path = _run_parked(
        canary, monkeypatch, tmp_path, "parked_round")

    assert summary["error"] is None, summary
    assert summary["engine"] == "parked"
    assert summary["client_class"] == "AntigravityAcpMcpClient"
    assert code == 0, summary
    assert summary["overall"] == "pass"
    verdicts = summary["verdicts"]
    assert verdicts["parked_tool_round"] == "pass"
    assert verdicts["plain_response"] == "pass"
    assert verdicts["follow_up_same_session"] == "pass"
    assert verdicts["usage_contract"] == "pass"
    assert verdicts["containment_declaration"] == "pass"
    assert verdicts["native_tool_execution_blocked"] == "pass"
    assert verdicts["normal_teardown"] == "pass"
    assert verdicts["model_selection"] == "pass"
    assert verdicts["cancel_path"] == "pass"

    tool_round = summary["tool_round"]
    assert tool_round["calls_observed"] is True
    assert tool_round["call_id_shape_ok"] is True
    # P2 regression: PASS requires the unique sentinel to have come back
    # through the model — a merely non-empty answer proves nothing.
    assert tool_round["sentinel_echoed_by_model"] is True
    assert tool_round["result_sentinel"] in summary["answers"]["final"]
    # Parked contract: the tool result is answered into the SAME held prompt.
    assert tool_round["prompt_requests_across_round"] == 1
    assert "canary_echo" in summary["answers"]["final"]
    assert "ping-42" in summary["answers"]["follow_up"]

    follow_up = summary["follow_up"]
    assert follow_up["session_new_requests_total"] == 1
    assert follow_up["prompt_requests_total"] == 2

    # P2 regression: selection SUCCESS (advertised + exact + ok response),
    # not the mere existence of a selection request.
    model = summary["model_selection"]
    assert model["selection_request"] == "exact"
    assert model["selection_response_ok"] is True
    assert model["selection_response_error"] is False
    assert "fake-test-model" in model["advertised_ids"]

    assert summary["usage"]["final_turn_reported"] == {
        "prompt_tokens": 60, "completion_tokens": 10, "total_tokens": 70}
    assert summary["usage"]["gate_rejection_logged"] is False
    assert summary["usage"]["billing_claim"].startswith("none")

    assert summary["containment"]["recorded_matches_engine_declaration_prefix"] is True
    assert summary["containment"]["run_command_in_engine_native_tools"] is True

    # P2 regression: declaration vs enforcement are separate verdicts; the
    # engine's permission gate must have refused the native probe.
    probe = summary["native_permission_probe"]
    assert probe["observed"] is True
    assert probe["outcome"]["optionId"] == "opt-reject"

    cancel = summary["cancel_probe"]
    assert cancel["attempted"] is True
    assert cancel["session_cancel_sent"] is True
    assert cancel["thread_outcome"] not in (None, "returned")
    assert cancel["thread_alive"] is False

    assert summary["teardown"]["acp_connections"] >= 1
    assert summary["teardown"]["direct_children_exited"] is True
    assert "not asserted" in summary["teardown"]["descendant_tree"]
    _assert_pid_dead(pid_path)

    methods = [r.get("method") for r in requests]
    # Two conversations hit the fake: the main one (1 session/new, 2 prompts)
    # and the cancel-probe one (its own session/new + held prompt).  The
    # follow_up facts above already pin the MAIN conversation to a single
    # session across the tool round and follow-up.
    assert methods.count("session/new") == 2
    assert methods.count("session/prompt") == 3
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

    # P1 regression: per-run secrets and smuggled credential shapes must be
    # absent from EVERY evidence file (session id, bearer token, secret
    # assignment, loopback MCP URL path), while the redaction is recorded.
    for evidence_text in (frames_text, summary_text):
        assert SECRET_SESSION_ID not in evidence_text
        assert SECRET_BEARER not in evidence_text
        assert SECRET_ASSIGNMENT not in evidence_text
        assert SECRET_MCP_PATH not in evidence_text
        assert "/mcp/" not in evidence_text
    # Every "Bearer" prefix must be followed by a placeholder, never a value.
    import re
    assert re.search(r"Bearer (?!\[REDACTED\]|<redacted>)", frames_text) is None
    assert "<redacted>" in frames_text
    assert "<path-redacted>" in frames_text
    assert "sess_" in frames_text


def test_parked_tool_round_inconclusive_is_not_a_failure(
    canary, monkeypatch, tmp_path
):
    """A model that never calls the advertised tool yields an inconclusive
    probe, never a silent pass and never a fabricated failure; the overall
    verdict and exit code say the contract was NOT fully verified (3)."""
    code, summary, _, _, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_no_tool")
    assert summary["error"] is None
    assert code == 3
    assert summary["overall"] == "inconclusive"
    assert summary["verdicts"]["parked_tool_round"] == "inconclusive"
    assert summary["verdicts"]["plain_response"] == "pass"
    assert summary["tool_round"]["calls_observed"] is False


def test_parked_tool_round_without_sentinel_echo_is_inconclusive(
    canary, monkeypatch, tmp_path
):
    """P2 regression: the tool call happened and the answer is non-empty,
    but the canned result never came back through the model — delivery is
    unconfirmed, so the parked round is inconclusive, never PASS."""
    code, summary, _, _, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_no_sentinel")
    assert summary["error"] is None
    verdicts = summary["verdicts"]
    assert verdicts["parked_tool_round"] == "inconclusive"
    assert summary["tool_round"]["calls_observed"] is True
    assert summary["tool_round"]["sentinel_echoed_by_model"] is False
    assert summary["tool_round"]["prompt_requests_across_round"] == 1
    assert code == 3
    assert summary["overall"] == "inconclusive"


def test_parked_model_selection_error_fails_run(canary, monkeypatch, tmp_path):
    """P2 regression: a server that ERRORS the model-selection request must
    not be scored as a successful selection; the run fails (exit 1)."""
    code, summary, _, _, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_model_error")
    assert code == 1
    assert summary["overall"] == "fail"
    assert summary["error"] is not None


def test_parked_inflated_usage_is_gated_and_fails(
    canary, monkeypatch, tmp_path
):
    """P2 regression: a wildly inflated server usage report is rejected by
    the shared usage contract.  The contract WAS exercised and breached —
    that is a FAIL (exit 1), not a hidden inconclusive."""
    code, summary, _, _, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_inflated_usage")
    assert summary["error"] is None
    assert code == 1
    assert summary["overall"] == "fail"
    assert summary["usage"]["final_turn_reported"] is None
    assert summary["usage"]["gate_rejection_logged"] is True
    assert summary["verdicts"]["usage_contract"] == "fail"
    # The parked round itself still worked; usage gating is independent.
    assert summary["verdicts"]["parked_tool_round"] == "pass"


def test_parked_timeout_bounds_run_and_reaps_child(canary, monkeypatch, tmp_path):
    """P2 regression: a server that never answers the prompt must be cut
    off by --timeout; the canary reports the timeout (exit 1), writes the
    summary, and reaps the ACP child it owns."""
    code, summary, _, _, _, pid_path = _run_parked(
        canary, monkeypatch, tmp_path, "parked_hang", extra_argv=["--timeout", "3"])
    assert code == 1
    assert summary["overall"] == "fail"
    assert "CanaryTimeout" in (summary["error"] or "")
    assert summary["elapsed_seconds"] < 60
    assert summary["verdicts"]["normal_teardown"] == "pass"
    _assert_pid_dead(pid_path)


def test_parked_teardown_verdict_distinguishes_fail_from_inconclusive(canary):
    """P2 regression: a direct child we spawned that did not exit is a
    FAILURE; only the absence of any observed child is inconclusive."""
    assert canary._teardown_verdict([True, True]) == "pass"
    assert canary._teardown_verdict([True, False]) == "fail"
    assert canary._teardown_verdict([False]) == "fail"
    assert canary._teardown_verdict([]) == "inconclusive"
