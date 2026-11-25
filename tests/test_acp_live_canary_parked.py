"""Issue #93: credential-free regression for the Parked-MCP canary lane.

``--engine parked`` drives the real deployed Parked-MCP provider/client against
a fake ACP subprocess.  These tests never start Google's server, log in, read
a credential, or call a model.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import pytest

CANARY_PATH = Path(__file__).resolve().parents[1] / "scripts" / "acp_live_canary.py"

SECRET_SESSION_ID = "sess-SECRET-SESSION-00042"
SECRET_BEARER = "leaked-bearer-token-999"
SECRET_ASSIGNMENT = "LEAKED-ACCESS-TOKEN-999"
SECRET_MCP_PATH = "SECRETPART-ALPHA"
SECRET_JSON_ACCESS = "json-access-secret-111"
SECRET_JSON_REFRESH = "json-refresh-secret-222"
SECRET_JSON_API_KEY = "json-apikey-secret-333"

PARKED_FAKE_SOURCE = r"""
MALFORMED_USAGE = {
    "parked_usage_malformed_missing_total": {"inputTokens": 40, "outputTokens": 8},
    "parked_usage_malformed_string_input": {"inputTokens": "40",
                                            "outputTokens": 8, "totalTokens": 48},
    "parked_usage_malformed_negative_input": {"inputTokens": -5,
                                              "outputTokens": 8, "totalTokens": 48},
    "parked_usage_malformed_bool_input": {"inputTokens": True,
                                          "outputTokens": 8, "totalTokens": 48},
    "parked_usage_malformed_negative_thought": {"inputTokens": 40, "outputTokens": 8,
                                                "totalTokens": 48, "thoughtTokens": -1},
}
import json
import os as _os
import sys
import time
import urllib.request

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
    return {} if (notify or not raw) else json.loads(raw)


def mcp_round():
    mcp("initialize", {"protocolVersion": "2025-03-26",
                       "clientInfo": {"name": "parked-fake-acp", "version": "0"},
                       "capabilities": {}})
    mcp("notifications/initialized", notify=True)
    listed = mcp("tools/list", {})
    names = sorted(t["name"] for t in listed.get("result", {}).get("tools", []))
    call = mcp("tools/call", {"name": "canary_echo", "arguments": {"text": "ping-42"}})
    content = call.get("result", {}).get("content", [])
    return names, (content[0]["text"] if content else "")


def native_permission_probe():
    emit({"jsonrpc": "2.0", "id": "perm-probe-1",
          "method": "session/request_permission",
          "params": {"sessionId": SESSION_ID,
                     "toolCall": {"toolCallId": "native-probe-1",
                                  "name": "run_command",
                                  "title": "probe run_command",
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
        result = {"sessionId": SESSION_ID}
        if SCENARIO == "parked_config_model":
            result["configOptions"] = [
                {"id": "thought_level", "category": "thought_level",
                 "options": [{"value": "low"}]},
                {"id": "model", "category": "model",
                 "options": [{"value": "fake-test-model"}]},
            ]
        else:
            result["models"] = {"availableModels": [{"modelId": "fake-test-model"}]}
        emit({"jsonrpc": "2.0", "id": rpc_id, "result": result})
    elif method in ("session/set_model", "session/set_config_option"):
        if SCENARIO == "parked_model_error" and method == "session/set_model":
            emit({"jsonrpc": "2.0", "id": rpc_id,
                  "error": {"code": -32603, "message": "model unavailable"}})
        else:
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {}})
    elif method == "session/prompt":
        params = request.get("params") or {}
        if "canary cancel probe" in json.dumps(params):
            while True:
                line = sys.stdin.readline()
                if not line:
                    sys.exit(0)
                msg = json.loads(line)
                log_msg(msg)
                if msg.get("method") == "session/cancel":
                    break
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {"stopReason": "cancelled"}})
            continue
        prompt_count += 1
        if SCENARIO == "parked_hang":
            time.sleep(3600)
        if SCENARIO == "parked_no_tool":
            emit(chunk("PLAIN_ANSWER_NO_TOOL"))
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "stopReason": "end_turn",
                "usage": {"inputTokens": 40, "outputTokens": 8, "totalTokens": 48}}})
        elif prompt_count == 1:
            if SCENARIO in ("parked_round", "parked_no_sentinel", "parked_inflated_usage"):
                native_permission_probe()
            names, echoed = mcp_round()
            leak = ""
            extra = {}
            if SCENARIO == "parked_round":
                leak = (" leak Bearer __SECRET_BEARER__"
                        " access_token=__SECRET_ASSIGNMENT__"
                        " http://127.0.0.1:17777/mcp/__SECRET_MCP_PATH__")
                extra = {
                    "access_token": "__SECRET_JSON_ACCESS__",
                    "nested": {
                        "refresh_token": "__SECRET_JSON_REFRESH__",
                        "items": [{"name": "api_key", "value": "__SECRET_JSON_API_KEY__"}],
                    },
                }
            text = ("TOOL_ROUND tools=" + ",".join(names) + leak
                    if SCENARIO == "parked_no_sentinel"
                    else "TOOL_ROUND tools=" + ",".join(names) + " echo=" + echoed + leak)
            emit(chunk(text))
            usage = ({"inputTokens": 10_000_000, "outputTokens": 8, "totalTokens": 10_000_008}
                     if SCENARIO in ("parked_inflated_usage",
                                     "parked_usage_turn1_bad_turn2_rejected")
                     else MALFORMED_USAGE.get(SCENARIO)
                     or {"inputTokens": 40, "outputTokens": 8, "totalTokens": 48})
            res = {"stopReason": "end_turn", "usage": usage}
            res.update(extra)
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": res})
        else:
            emit(chunk("FOLLOW_UP_ANSWER ping-42"))
            if SCENARIO in MALFORMED_USAGE:
                usage = MALFORMED_USAGE[SCENARIO]
            elif SCENARIO == "parked_usage_turn1_bad_turn2_rejected":
                usage = {"inputTokens": 20_000_000, "outputTokens": 8,
                         "totalTokens": 20_000_008}
            elif SCENARIO == "parked_inflated_usage":
                usage = {"inputTokens": 10_000_000, "outputTokens": 8,
                         "totalTokens": 10_000_008}
            else:
                usage = {"inputTokens": 60, "outputTokens": 10, "totalTokens": 70}
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {
                "stopReason": "end_turn", "usage": usage}})
"""


@pytest.fixture
def canary():
    spec = importlib.util.spec_from_file_location("parked_lane_acp_canary", CANARY_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parked_fake(tmp_path: Path, scenario: str) -> tuple[Path, Path, Path]:
    log_path = tmp_path / "parked_requests.jsonl"
    pid_path = tmp_path / "parked_fake.pid"
    script = tmp_path / "parked_fake_acp.py"
    text = (
        PARKED_FAKE_SOURCE.replace("__SCENARIO__", scenario)
        .replace("__LOG_PATH__", str(log_path))
        .replace("__PID_PATH__", str(pid_path))
        .replace("__SESSION_ID__", SECRET_SESSION_ID)
        .replace("__SECRET_BEARER__", SECRET_BEARER)
        .replace("__SECRET_ASSIGNMENT__", SECRET_ASSIGNMENT)
        .replace("__SECRET_MCP_PATH__", SECRET_MCP_PATH)
        .replace("__SECRET_JSON_ACCESS__", SECRET_JSON_ACCESS)
        .replace("__SECRET_JSON_REFRESH__", SECRET_JSON_REFRESH)
        .replace("__SECRET_JSON_API_KEY__", SECRET_JSON_API_KEY)
    )
    script.write_text(text, encoding="utf-8")
    binary = tmp_path / "parked-fake-acp"
    binary.write_text(
        f"#!{sys.executable}\nimport runpy\n"
        f"runpy.run_path({str(script)!r}, run_name='__main__')\n",
        encoding="utf-8",
    )
    binary.chmod(0o700)
    return binary, log_path, pid_path


def _parked_argv(tmp_path: Path, *extra: str) -> list[str]:
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


def _run_parked(canary, monkeypatch, tmp_path: Path, scenario: str, extra_argv=()):
    binary, log_path, pid_path = _parked_fake(tmp_path, scenario)
    monkeypatch.setenv("ACP_CANARY_TEST_SECRET", "NEVER_PASS_PARENT_ENV")
    evidence = tmp_path / "evidence"
    monkeypatch.setattr(sys, "argv", _parked_argv(
        tmp_path, "--fake-acp-only", "--command", str(binary), *extra_argv))
    code = canary.main()
    summary_text = (evidence / "summary.json").read_text(encoding="utf-8")
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    requests = (
        [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line]
        if log_path.exists() else []
    )
    return code, json.loads(summary_text), frames_text, summary_text, requests, pid_path


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


def test_parked_requires_posix_sigalrm(canary, monkeypatch, tmp_path):
    monkeypatch.delattr(canary.signal, "SIGALRM", raising=False)
    monkeypatch.setattr(sys, "argv", _parked_argv(
        tmp_path, "--fake-acp-only", "--command", str(tmp_path / "fake")))
    assert canary.main() == 2
    assert not (tmp_path / "evidence").exists()


def test_parked_fake_lane_isolation_preflight(canary, monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", str(tmp_path / "mux-launcher"))
    monkeypatch.setattr(sys, "argv", _parked_argv(tmp_path, "--fake-acp-only"))
    assert canary.main() == 2
    assert not (tmp_path / "evidence").exists()

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


def test_parked_fake_lane_never_executes_env_launcher(canary, monkeypatch, tmp_path):
    marker = tmp_path / "env-launcher-ran"
    env_launcher = tmp_path / "mux-launcher"
    env_launcher.write_text(
        f"#!{sys.executable}\nopen({str(marker)!r}, 'w').write('ran')\n",
        encoding="utf-8",
    )
    env_launcher.chmod(0o700)
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND", str(env_launcher))
    code, summary, _, _, _, _ = _run_parked(canary, monkeypatch, tmp_path, "parked_round")
    assert code == 0 and summary["overall"] == "pass"
    assert not marker.exists()
    assert os.environ.get("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND") == str(env_launcher)


def test_parked_fake_lane_full_round(canary, monkeypatch, tmp_path):
    original_loader = canary.load_client_module

    def spy_loader(repo):
        module = original_loader(repo)

        def _no_replay_fallback(**kwargs):
            raise AssertionError("parked lane must not construct the replay client")

        module.antigravity_acp_replay.create_client = _no_replay_fallback
        return module

    monkeypatch.setattr(canary, "load_client_module", spy_loader)
    code, summary, frames_text, summary_text, requests, pid_path = _run_parked(
        canary, monkeypatch, tmp_path, "parked_round")

    assert code == 0 and summary["overall"] == "pass"
    assert summary["error"] is None
    assert summary["client_class"] == "AntigravityAcpMcpClient"
    assert all(v == "pass" for v in summary["verdicts"].values()), summary["verdicts"]

    tr = summary["tool_round"]
    assert tr["sentinel_echoed_by_model"] is True
    assert tr["result_sentinel"] in summary["answers"]["final"]
    assert tr["prompt_requests_across_round"] == 1
    assert "ping-42" in summary["answers"]["follow_up"]

    assert summary["follow_up"]["session_new_requests_total"] == 1
    assert summary["follow_up"]["prompt_requests_total"] == 2
    assert summary["model_selection"]["selection_request"] == "exact"
    assert summary["model_selection"]["selection_response_ok"] is True

    assert summary["usage"]["server_report_status"] == "plausible"
    assert summary["usage"]["final_turn_reported"] == {
        "prompt_tokens": 60, "completion_tokens": 10, "total_tokens": 70}

    containment = summary["containment"]
    assert containment["recorded_matches_engine_declaration_prefix"] is True
    assert containment["native_permission_requests_observed"] == 1
    assert containment["native_permission_requests_refused"] == 1
    assert containment["native_permission_requests_allowed"] == 0
    perm_resp = next(r["__perm_response__"] for r in requests if "__perm_response__" in r)
    assert perm_resp["result"]["outcome"]["optionId"] == "opt-reject"

    cancel = summary["cancel_probe"]
    assert cancel["session_cancel_sent"] is True
    assert cancel["thread_outcome"] not in (None, "returned")
    assert cancel["thread_alive"] is False
    _assert_pid_dead(pid_path)

    for evidence_text in (frames_text, summary_text):
        for leaked in (
            SECRET_SESSION_ID, SECRET_BEARER, SECRET_ASSIGNMENT, SECRET_MCP_PATH,
            SECRET_JSON_ACCESS, SECRET_JSON_REFRESH, SECRET_JSON_API_KEY, "/mcp/",
        ):
            assert leaked not in evidence_text
    assert re.search(r"Bearer (?!\[REDACTED\]|<redacted>)", frames_text) is None
    assert "<redacted>" in frames_text and "<path-redacted>" in frames_text


def test_parked_live_style_no_permission_probe_passes_containment(canary, monkeypatch, tmp_path):
    """A run with no native permission requests observed still passes containment."""
    code, summary, _, _, _, _ = _run_parked(canary, monkeypatch, tmp_path, "parked_live_style")
    assert code == 0 and summary["overall"] == "pass"
    assert summary["verdicts"]["containment"] == "pass"
    assert summary["containment"]["native_permission_requests_observed"] == 0


def test_parked_model_selection_via_config_options(canary, monkeypatch, tmp_path):
    """Model discovery reuses client._session_model_ids, covering configOptions."""
    code, summary, _, _, requests, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_config_model")
    assert code == 0 and summary["overall"] == "pass"
    assert summary["verdicts"]["model_selection"] == "pass"
    assert summary["model_selection"]["selection_request"] == "exact"
    assert "session/set_config_option" in [r.get("method") for r in requests]


@pytest.mark.parametrize("scenario", ("parked_no_tool", "parked_no_sentinel"))
def test_parked_tool_round_inconclusive(canary, monkeypatch, tmp_path, scenario):
    code, summary, _, _, _, _ = _run_parked(canary, monkeypatch, tmp_path, scenario)
    assert code == 3 and summary["overall"] == "inconclusive"
    assert summary["verdicts"]["parked_tool_round"] == "inconclusive"


def test_parked_model_selection_error_fails_run(canary, monkeypatch, tmp_path):
    code, summary, _, _, _, _ = _run_parked(canary, monkeypatch, tmp_path, "parked_model_error")
    assert code == 1 and summary["overall"] == "fail"


def test_parked_inflated_usage_rejected_passes_contract(canary, monkeypatch, tmp_path):
    """#87: when the server sends inflated usage and the engine rejects it, that is PASS."""
    code, summary, _, _, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_inflated_usage")
    assert code == 0 and summary["overall"] == "pass"
    assert summary["usage"]["server_report_status"] == "anomalous_rejected"
    assert summary["usage"]["gate_rejection_logged"] is True
    assert summary["verdicts"]["usage_contract"] == "pass"


def test_parked_anomalous_usage_accepted_fails_contract(canary, monkeypatch, tmp_path):
    """#87: when anomalous server usage slips onto the completion, usage_contract FAILs."""
    original_loader = canary.load_client_module

    def spy_loader(repo):
        module = original_loader(repo)
        conv = importlib.import_module(module.__name__ + ".parked.conversation")
        monkeypatch.setattr(conv, "first_turn_report_plausible", lambda **kwargs: True)
        return module

    monkeypatch.setattr(canary, "load_client_module", spy_loader)
    code, summary, _, _, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_inflated_usage")
    assert code == 1 and summary["overall"] == "fail"
    assert summary["usage"]["server_report_status"] == "anomalous_accepted"
    assert summary["verdicts"]["usage_contract"] == "fail"


def test_parked_turn1_anomalous_accepted_turn2_rejected_fails_contract(
        canary, monkeypatch, tmp_path):
    """#87 boundary: an anomalous report accepted on turn 1 is a breach even
    when the engine correctly rejects turn 2's report (no false PASS)."""
    original_loader = canary.load_client_module

    def spy_loader(repo):
        module = original_loader(repo)
        conv = importlib.import_module(module.__name__ + ".parked.conversation")
        monkeypatch.setattr(conv, "first_turn_report_plausible", lambda **kwargs: True)
        return module

    monkeypatch.setattr(canary, "load_client_module", spy_loader)
    code, summary, _, _, _, _ = _run_parked(
        canary, monkeypatch, tmp_path, "parked_usage_turn1_bad_turn2_rejected")
    assert code == 1 and summary["overall"] == "fail"
    turns = summary["usage"]["turns"]
    assert turns[0]["engine_accepted"] is True
    assert turns[0]["plausible"] is False
    assert turns[1]["engine_accepted"] is False
    assert summary["usage"]["server_report_status"] == "anomalous_accepted"
    assert summary["verdicts"]["usage_contract"] == "fail"


@pytest.mark.parametrize("scenario", (
    "parked_usage_malformed_missing_total",
    "parked_usage_malformed_string_input",
    "parked_usage_malformed_negative_input",
    "parked_usage_malformed_bool_input",
    "parked_usage_malformed_negative_thought",
))
def test_parked_malformed_usage_rejected_passes_contract(
        canary, monkeypatch, tmp_path, scenario):
    """Engine-parser boundaries (missing required field, wrong type, negative,
    bool, invalid optional): the engine rejects the report whole and that is
    contract PASS, never a canary false FAIL."""
    code, summary, _, _, _, _ = _run_parked(canary, monkeypatch, tmp_path, scenario)
    assert code == 0 and summary["overall"] == "pass"
    turns = summary["usage"]["turns"]
    assert all(t["server_reported"] and not t["report_valid"]
               and not t["engine_accepted"] for t in turns)
    assert summary["usage"]["server_report_status"] == "invalid_rejected"
    assert summary["verdicts"]["usage_contract"] == "pass"


def test_parked_plausible_usage_rejected_fails_contract(canary, monkeypatch, tmp_path):
    """#87 boundary: the engine rejecting a PLAUSIBLE report is a contract
    breach (false rejection), not a pass."""
    original_loader = canary.load_client_module

    def spy_loader(repo):
        module = original_loader(repo)
        conv = importlib.import_module(module.__name__ + ".parked.conversation")
        monkeypatch.setattr(conv, "first_turn_report_plausible", lambda **kwargs: False)
        return module

    monkeypatch.setattr(canary, "load_client_module", spy_loader)
    code, summary, _, _, _, _ = _run_parked(canary, monkeypatch, tmp_path, "parked_round")
    assert code == 1 and summary["overall"] == "fail"
    turns = summary["usage"]["turns"]
    assert turns[0]["server_reported"] is True
    assert turns[0]["engine_accepted"] is False
    assert turns[0]["plausible"] is True
    assert summary["usage"]["server_report_status"] == "plausible_rejected"
    assert summary["verdicts"]["usage_contract"] == "fail"


def test_parked_usage_verdict_decision_table(canary):
    def turn(reported, accepted, plausible, valid=None):
        return {"server_reported": reported, "engine_accepted": accepted,
                "report_valid": reported if valid is None else valid,
                "plausible": plausible}
    # normal accepted -> PASS
    assert canary._usage_verdict([turn(True, True, True)]) == ("plausible", "pass")
    # anomalous rejected -> PASS
    assert canary._usage_verdict([turn(True, False, False)]) == ("anomalous_rejected", "pass")
    # anomalous accepted -> FAIL
    assert canary._usage_verdict([turn(True, True, False)]) == ("anomalous_accepted", "fail")
    # normal rejected -> FAIL
    assert canary._usage_verdict([turn(True, False, True)]) == ("plausible_rejected", "fail")
    # malformed rejected -> PASS
    assert canary._usage_verdict(
        [turn(True, False, False, valid=False)]) == ("invalid_rejected", "pass")
    # malformed accepted -> FAIL
    assert canary._usage_verdict(
        [turn(True, True, False, valid=False)]) == ("invalid_accepted", "fail")
    # usage invented with no server report -> FAIL
    assert canary._usage_verdict([turn(False, True, None)]) == ("invented_usage", "fail")
    # nothing reported -> INCONCLUSIVE
    assert canary._usage_verdict([turn(False, False, None)]) == ("unavailable", "inconclusive")
    assert canary._usage_verdict([]) == ("unavailable", "inconclusive")
    # any-turn breach poisons the whole run regardless of the other turn
    assert canary._usage_verdict(
        [turn(True, True, False), turn(True, False, False)]) == ("anomalous_accepted", "fail")
    assert canary._usage_verdict(
        [turn(True, False, False), turn(True, True, False)]) == ("anomalous_accepted", "fail")
    assert canary._usage_verdict(
        [turn(True, False, True), turn(True, True, True)]) == ("plausible_rejected", "fail")
    assert canary._usage_verdict(
        [turn(True, True, True, valid=False), turn(True, False, False)]) == ("invalid_accepted", "fail")
    assert canary._usage_verdict(
        [turn(True, True, True), turn(True, False, False)]) == ("mixed", "pass")


@pytest.mark.parametrize("flag", ("--prompt", "--follow-up"))
def test_parked_refuses_custom_prompts(canary, monkeypatch, tmp_path, flag):
    """Parked records only its fixed synthetic prompts; user text is refused
    at preflight so it never reaches the evidence files."""
    monkeypatch.setattr(sys, "argv", _parked_argv(
        tmp_path, "--fake-acp-only", "--command", str(tmp_path / "fake"),
        flag, "arbitrary user data"))
    assert canary.main() == 2
    assert not (tmp_path / "evidence").exists()


def test_parked_cancel_verdict_distinguishes_race_from_failure(canary):
    base = {"prompt_issued": True, "raced_completion": False,
            "thread_alive": False, "session_cancel_sent": True,
            "thread_outcome": "CancelledError"}
    assert canary._cancel_verdict(base) == "pass"
    raced = dict(base, raced_completion=True, session_cancel_sent=False,
                 thread_outcome="returned")
    assert canary._cancel_verdict(raced) == "inconclusive"
    assert canary._cancel_verdict(dict(base, thread_outcome="returned")) == "fail"
    assert canary._cancel_verdict(dict(base, thread_alive=True)) == "fail"
    assert canary._cancel_verdict(dict(base, prompt_issued=False)) == "inconclusive"


def test_parked_timeout_bounds_run_and_reaps_child(canary, monkeypatch, tmp_path):
    code, summary, _, _, _, pid_path = _run_parked(
        canary, monkeypatch, tmp_path, "parked_hang", extra_argv=["--timeout", "3"])
    assert code == 1 and summary["overall"] == "fail"
    assert "CanaryTimeout" in (summary["error"] or "")
    assert summary["verdicts"]["normal_teardown"] == "pass"
    _assert_pid_dead(pid_path)


def test_parked_teardown_verdict_distinguishes_fail_from_inconclusive(canary):
    assert canary._teardown_verdict([True, True]) == "pass"
    assert canary._teardown_verdict([True, False]) == "fail"
    assert canary._teardown_verdict([]) == "inconclusive"
