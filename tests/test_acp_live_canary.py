"""Credential-free subprocess regression for the incident canary driver.

These tests never start Google's server, log in, read a credential, or call a model.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

CANARY_PATH = Path(__file__).resolve().parents[1] / "scripts" / "acp_live_canary.py"
FAKE_SOURCE = r'''
import json
import os
import sys
import time

# The runner must not inherit the parent's credential-shaped environment.
if "ACP_CANARY_TEST_SECRET" in os.environ:
    raise RuntimeError("unsafe parent environment inherited")
scenario = os.environ["ACP_FAKE_SCENARIO"]
log_path = os.environ["ACP_FAKE_LOG"]

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def receive():
    line = sys.stdin.readline()
    if not line:
        return None
    msg = json.loads(line)
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(json.dumps(msg) + "\n")
    return msg

while True:
    request = receive()
    if request is None:
        break
    method = request.get("method")
    rpc_id = request.get("id")
    if method == "initialize":
        if scenario == "stderr_flood":
            sys.stderr.write("E" * 262144)
            sys.stderr.flush()
        init_result = {
            "protocolVersion": 1,
            "accountEmail": "sensitive@example.invalid",
            "auth": {"refreshToken": "VERY_SECRET_REFRESH"},
        }
        if scenario.startswith("init_version_"):
            # A server-controlled initialize result whose protocolVersion is
            # missing, malformed, type-confused, or an unsupported integer.
            variant = scenario[len("init_version_"):]
            if variant == "missing":
                init_result.pop("protocolVersion")
            elif variant == "object":
                init_result["protocolVersion"] = {"bad": "shape"}
            elif variant == "string":
                init_result["protocolVersion"] = "1"
            elif variant == "bool":
                init_result["protocolVersion"] = True
            elif variant == "float":
                init_result["protocolVersion"] = 1.0
            elif variant == "null":
                init_result["protocolVersion"] = None
            elif variant == "unsupported":
                init_result["protocolVersion"] = 2
        emit({"jsonrpc": "2.0", "id": rpc_id, "result": init_result})
    elif method == "session/new":
        if scenario == "wrong_id":
            emit({"jsonrpc": "2.0", "id": 901, "result": {"sessionId": "session-secret-opaque"}})
        else:
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {"sessionId": "session-secret-opaque"}})
    elif method == "session/set_model":
        if scenario == "set_model_error":
            emit({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32602, "message": "model rejected"}})
        else:
            # A separate incoming frame is required before session/prompt.
            time.sleep(0.04)
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {}})
    elif method == "session/prompt":
        if scenario == "hostile_values":
            # Every string below is a server-controlled value the strict
            # sanitizer must never persist verbatim, regardless of the
            # protocol field name it travels under.
            emit({"jsonrpc": "2.0", "method": "CANARY_SENTINEL_METHOD_4839207",
                  "params": {"detail": "CANARY_SENTINEL_DETAIL_4839207"}})
            emit({"jsonrpc": "2.0", "method": "session/update",
                  "params": {"sessionId": "session-secret-opaque",
                             "update": {"sessionUpdate": "CANARY_SENTINEL_SESSION_UPDATE_4839207",
                                        "content": {"type": "text", "text": "ignored"}}}})
            emit({"jsonrpc": "2.0", "method": "session/update",
                  "params": {"sessionId": "session-secret-opaque",
                             "update": {"sessionUpdate": "tool_call",
                                        "toolCallId": "tool-1",
                                        "kind": "CANARY_SENTINEL_TOOL_KIND_4839207",
                                        "status": "CANARY_SENTINEL_TOOL_STATUS_4839207"}}})
            emit({"jsonrpc": "2.0", "method": "session/update",
                  "params": {"sessionId": "session-secret-opaque",
                             "update": {"sessionUpdate": "agent_message_chunk",
                                        "content": {"type": "CANARY_SENTINEL_CONTENT_TYPE_4839207",
                                                    "text": "CANARY_SENTINEL_CHUNK_TEXT_4839207"}}}})
            emit({"jsonrpc": "2.0", "id": rpc_id,
                  "result": {"stopReason": "CANARY_SENTINEL_STOP_REASON_4839207"}})
            time.sleep(3)
            break
        if scenario == "hostile_keys":
            # JSON member NAMES are server-controlled too. Every sentinel
            # key below (arbitrary, nested, secret-fragment, primitive- or
            # list-valued) must never reach evidence; the valid protocol
            # members of the same notification must keep their verified
            # shape, and the probe may still PASS.
            emit({"jsonrpc": "2.0", "method": "session/update",
                  "params": {"sessionId": "session-secret-opaque",
                             "CANARY_SENTINEL_KEY_4839207": "sentinel-under-unknown-key",
                             "CANARY_SENTINEL_NESTED_KEY_4839207": {
                                 "CANARY_SENTINEL_INNER_KEY_4839207": "x"},
                             "CANARY_SENTINEL_TOKEN_KEY_4839207": "secretfragment-sentinel-value",
                             "CANARY_SENTINEL_INT_KEY_4839207": 7,
                             "CANARY_SENTINEL_LIST_KEY_4839207": [
                                 {"CANARY_SENTINEL_LISTITEM_KEY_4839207": 1}],
                             "update": {"sessionUpdate": "agent_message_chunk",
                                        "content": {"type": "text",
                                                    "text": "hostile-keys-control-chunk"}}}})
            emit({"jsonrpc": "2.0", "id": rpc_id,
                  "result": {"stopReason": "end_turn"}})
            time.sleep(3)
            break
        if scenario == "hostile_numbers":
            # Every non-string primitive below is a server-chosen value the
            # strict sanitizer must fail closed on regardless of JSON type:
            # arbitrary ints/floats under unknown keys, primitives nested in
            # lists, known-looking protocol member names smuggled under a
            # hostile wrapper, a secret-fragment key with a numeric value,
            # and type-confused numerics under allowlisted string-enum keys.
            # The valid session-bound members of the same run keep their
            # verified shape and the probe must still PASS.
            emit({"jsonrpc": "2.0", "method": "session/update",
                  "params": {"sessionId": "session-secret-opaque",
                             "CANARY_SENTINEL_INT_KEY_4839207": 7239184561029384756,
                             "CANARY_SENTINEL_NEGINT_KEY_4839207": -9876543210987654321,
                             "CANARY_SENTINEL_FLOAT_KEY_4839207": 4839207.25,
                             "CANARY_SENTINEL_BOOL_KEY_4839207": True,
                             "CANARY_SENTINEL_PRIMLIST_KEY_4839207":
                                 [7239184561029384756, 4839207.25, False, None],
                             "CANARY_SENTINEL_WRAPPER_KEY_4839207": {
                                 "id": 7239184561029384756,
                                 "code": 7239184561029384756,
                                 "protocolVersion": 7239184561029384756,
                                 "nested": [{"stopReason": 7239184561029384756}]},
                             "authToken": 7239184561029384756,
                             "update": {"sessionUpdate": "tool_call",
                                        "toolCallId": "tool-num-1",
                                        "kind": "execute",
                                        "status": 7239184561029384756}}})
            emit({"jsonrpc": "2.0", "method": "session/update",
                  "params": {"sessionId": "session-secret-opaque",
                             "update": {"sessionUpdate": "agent_message_chunk",
                                        "content": {"type": "text",
                                                    "text": "numeric-hostile-control-chunk"}}}})
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {"stopReason": "end_turn"}})
            time.sleep(3)
            break
        if scenario == "hostile_envelope_id":
            # The envelope id position keeps legitimate client ids verbatim;
            # a hostile numeric echo in that exact position must persist only
            # as a deterministic correlation token, never as the sentinel.
            emit({"jsonrpc": "2.0", "id": 7239184561029384756})
            time.sleep(3)
            break
        if scenario == "timeout":
            time.sleep(3)
            break
        if scenario == "permission":
            emit({"jsonrpc": "2.0", "id": 77, "method": "session/request_permission",
                  "params": {"options": [
                      {"kind": "allow_once", "optionId": "yes"},
                      {"kind": "allow_always", "optionId": "always"},
                      {"kind": "reject_once", "optionId": "no"}]}})
            permit = receive()
            if permit is None:
                break
        if scenario == "permission_sentinel":
            emit({"jsonrpc": "2.0", "id": 78, "method": "session/request_permission",
                  "params": {"sessionId": "session-secret-opaque",
                             "toolCall": {"toolCallId": "tool-1",
                                          "name": "CANARY_SENTINEL_NAME_9182736",
                                          "toolName": "CANARY_SENTINEL_TOOLNAME_9182736",
                                          "kind": "edit",
                                          "title": "edit CANARY_SENTINEL_TITLE_9182736"},
                             "options": [
                                 {"kind": "allow_once", "optionId": "yes"},
                                 {"kind": "reject_once", "optionId": "no"}]}})
            permit = receive()
            if permit is None:
                break
        if scenario == "permission_numeric_id":
            # A server-chosen permission request id is not one of this
            # driver's own ids: it must never persist verbatim, yet the
            # request and the harness answer must still share one
            # correlation token so evidence stays joinable.
            emit({"jsonrpc": "2.0", "id": 7239184561029384756,
                  "method": "session/request_permission",
                  "params": {"sessionId": "session-secret-opaque",
                             "toolCall": {"toolCallId": "tool-num-2",
                                          "kind": "edit"},
                             "options": [
                                 {"kind": "allow_once", "optionId": "yes"}]}})
            permit = receive()
            if permit is None:
                break
            emit({"jsonrpc": "2.0", "id": rpc_id,
                  "result": {"stopReason": "end_turn"}})
            time.sleep(3)
            break
        if scenario == "prompt_error":
            emit({"jsonrpc": "2.0", "id": rpc_id, "error": {"code": -32000, "message": "fake error"}})
        else:
            if scenario != "no_chunk":
                text = "" if scenario == "empty_chunk" else "DO_NOT_RECORD_PLAINTEXT_987"
                chunk_params = {"update": {"sessionUpdate": "agent_message_chunk",
                                           "content": {"type": "text", "text": text}}}
                if scenario == "foreign_session":
                    chunk_params["sessionId"] = "foreign-session-opaque"
                elif scenario != "missing_session":
                    chunk_params["sessionId"] = "session-secret-opaque"
                emit({"jsonrpc": "2.0", "method": "session/update",
                      "params": chunk_params})
            stop = "max_tokens" if scenario == "wrong_stop" else "end_turn"
            emit({"jsonrpc": "2.0", "id": rpc_id, "result": {"stopReason": stop}})
        time.sleep(3)
        break
'''

@pytest.fixture
def canary():
    spec = importlib.util.spec_from_file_location("incident_acp_canary", CANARY_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def _fake(tmp_path: Path) -> Path:
    executable = tmp_path / "fake_acp_server"
    executable.write_text(f"#!{sys.executable}\n" + FAKE_SOURCE, encoding="utf-8")
    executable.chmod(0o700)
    return executable

def _invoke(canary, monkeypatch, tmp_path: Path, scenario: str,
            model: str | None = "fake-test-model"):
    binary = _fake(tmp_path)
    log_path = tmp_path / "requests.jsonl"
    monkeypatch.setenv("ACP_FAKE_SCENARIO", scenario)
    monkeypatch.setenv("ACP_FAKE_LOG", str(log_path))
    monkeypatch.setenv("ACP_CANARY_TEST_SECRET", "NEVER_PASS_PARENT_ENV")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    recorder = canary.FrameRecorder(
        evidence / "frames.jsonl",
        lambda s: s,
        sanitizer=canary._sanitize_raw_protocol,
    )
    args = SimpleNamespace(
        command=str(binary), cwd=str(tmp_path), model=model,
        prompt="reply only pong", timeout=0.55, fake_acp_only=True,
    )
    try:
        code = canary.run_raw_allow(args, recorder, evidence)
    finally:
        recorder._fh.close()
    requests = []
    if log_path.exists():
        requests = [
            json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()
        ]
    return code, requests, recorder.frames, evidence

def _methods(requests):
    return [frame["method"] for frame in requests if frame.get("method")]

def test_one_prompt_after_confirmed_set_model_and_redacted_evidence(
    canary, monkeypatch, tmp_path
):
    code, requests, frames, evidence = _invoke(canary, monkeypatch, tmp_path, "ok")
    assert code == 0
    assert _methods(requests) == [
        "initialize", "session/new", "session/set_model", "session/prompt"
    ]
    positions = [
        (entry["dir"], entry["frame"].get("method"), entry["frame"].get("id"))
        for entry in frames
    ]
    model_response = next(i for i, e in enumerate(positions) if e == ("in", None, 3))
    prompt_request = next(i for i, e in enumerate(positions) if e == ("out", "session/prompt", 4))
    assert model_response < prompt_request
    raw = "\n".join(p.read_text(encoding="utf-8") for p in evidence.glob("*.json*"))
    assert "DO_NOT_RECORD_PLAINTEXT_987" not in raw
    assert "session-secret-opaque" not in raw
    assert "sensitive@example.invalid" not in raw
    assert "VERY_SECRET_REFRESH" not in raw
    assert "reply only pong" not in raw
    outcome = json.loads((evidence / "raw_run_status.json").read_text())
    assert outcome["outcome"] == "PASS"
    assert outcome["set_model_acknowledged"] is True
    assert outcome["effective_model_verified"] is False
    assert outcome["prompt_count"] == 1

def test_stderr_flood_cannot_deadlock_raw_probe(
    canary, monkeypatch, tmp_path
):
    code, requests, _, evidence = _invoke(
        canary, monkeypatch, tmp_path, "stderr_flood"
    )
    assert code == 0
    assert _methods(requests).count("session/prompt") == 1
    status = json.loads((evidence / "raw_run_status.json").read_text())
    assert status["outcome"] == "PASS"


def test_legacy_analysis_fields_remain_intact(
    canary, tmp_path
):
    recorder = canary.FrameRecorder(
        tmp_path / "legacy-frames.jsonl", lambda s: s
    )
    try:
        recorder.record("in", json.dumps({
            "jsonrpc": "2.0",
            "id": 77,
            "method": "session/request_permission",
            "params": {
                "toolCall": {
                    "toolCallId": "tool-1",
                    "name": "edit_file",
                    "kind": "edit",
                    "title": "Edit file",
                    "content": [{"path": "/tmp/project/a.py"}],
                },
                "options": [{"kind": "allow_once", "optionId": "yes"}],
            },
        }))
        recorder.record("out", json.dumps({
            "jsonrpc": "2.0",
            "id": 77,
            "result": {
                "outcome": {"outcome": "selected", "optionId": "yes"}
            },
        }))
        recorder.record("out", json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "session/new",
            "params": {
                "cwd": "/tmp/project",
                "_meta": {"agy": {"disabledTools": ["run_command"]}},
            },
        }))
        analysis = canary.analyze_frames(recorder)
    finally:
        recorder._fh.close()

    tool = analysis["tools"]["tool-1"]
    assert tool["names"] == ["edit_file"]
    assert tool["kinds"] == []
    assert [stage["stage"] for stage in tool["stages"]] == [
        "permission_request", "harness_answer"
    ]
    assert tool["stages"][0]["kind"] == "edit"
    session = analysis["tools"]["__session__"]["stages"][0]
    assert session["cwd"] == "/tmp/project"
    assert session["disabled_tools"] == ["run_command"]


@pytest.mark.parametrize("scenario", [
    "set_model_error", "wrong_id", "prompt_error", "wrong_stop",
    "no_chunk", "empty_chunk", "timeout", "permission",
])
def test_failure_fails_closed_never_retries(
    canary, monkeypatch, tmp_path, scenario
):
    code, requests, _, evidence = _invoke(canary, monkeypatch, tmp_path, scenario)
    assert code != 0, scenario
    assert _methods(requests).count("session/prompt") <= 1
    if scenario in ("set_model_error", "wrong_id"):
        assert "session/prompt" not in _methods(requests)
    if scenario == "permission":
        answers = [r for r in requests if r.get("id") == 77 and not r.get("method")]
        assert len(answers) == 1
        outcome = answers[0]["result"]["outcome"]
        assert outcome["outcome"] == "cancelled"
    status = json.loads((evidence / "raw_run_status.json").read_text())
    assert status["outcome"] != "PASS"
    assert status["prompt_count"] <= 1

def test_existing_evidence_directory_is_rejected_before_spawning(
    canary, monkeypatch, tmp_path
):
    binary = _fake(tmp_path)
    monkeypatch.setenv("ACP_FAKE_SCENARIO", "ok")
    monkeypatch.setenv("ACP_CANARY_TEST_SECRET", "NEVER_PASS_PARENT_ENV")
    log_path = tmp_path / "requests.jsonl"
    monkeypatch.setenv("ACP_FAKE_LOG", str(log_path))
    old = tmp_path / "old_evidence"
    old.mkdir()
    (old / "frames.jsonl").write_text("original-do-not-change\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "acp_live_canary.py", "--cwd", str(tmp_path), "--mode", "raw-probe",
        "--evidence", str(old), "--command", str(binary), "--timeout", "0.55",
        "--fake-acp-only",
    ])
    assert canary.main() == 2
    assert (old / "frames.jsonl").read_text() == "original-do-not-change\n"
    assert not log_path.exists()

def test_legacy_raw_allow_cannot_start_a_subprocess(
    canary, monkeypatch, tmp_path
):
    binary = _fake(tmp_path)
    monkeypatch.setenv("ACP_FAKE_SCENARIO", "ok")
    log_path = tmp_path / "requests.jsonl"
    monkeypatch.setenv("ACP_FAKE_LOG", str(log_path))
    monkeypatch.setattr(sys, "argv", [
        "acp_live_canary.py", "--cwd", str(tmp_path), "--mode", "raw-allow",
        "--evidence", str(tmp_path / "new_evidence"), "--command", str(binary),
    ])
    assert canary.main() == 2
    assert not log_path.exists()


@pytest.mark.parametrize("lane", [[], ["--operator-supervised-live"]])
def test_cli_refuses_unattended_or_unapproved_execution(
    canary, monkeypatch, tmp_path, lane
):
    binary = _fake(tmp_path)
    monkeypatch.setenv("ACP_FAKE_SCENARIO", "ok")
    log_path = tmp_path / "requests.jsonl"
    monkeypatch.setenv("ACP_FAKE_LOG", str(log_path))
    monkeypatch.setattr(sys, "argv", [
        "acp_live_canary.py", "--cwd", str(tmp_path), "--mode", "raw-probe",
        "--evidence", str(tmp_path / "evidence"), "--command", str(binary),
        *lane,
    ])
    assert canary.main() == 2
    assert not log_path.exists()


def test_explicit_fake_only_lane_runs_without_loading_provider(
    canary, monkeypatch, tmp_path
):
    binary = _fake(tmp_path)
    monkeypatch.setenv("ACP_FAKE_SCENARIO", "ok")
    log_path = tmp_path / "requests.jsonl"
    monkeypatch.setenv("ACP_FAKE_LOG", str(log_path))
    evidence = tmp_path / "fresh"
    monkeypatch.setattr(sys, "argv", [
        "acp_live_canary.py", "--cwd", str(tmp_path), "--mode", "raw-probe",
        "--evidence", str(evidence), "--command", str(binary),
        "--fake-acp-only", "--model", "fake-test-model", "--timeout", "0.55",
    ])
    # This path must not import the actual plugin runtime, Hermes or credentials.
    monkeypatch.setattr(
        canary, "load_client_module",
        lambda _: pytest.fail("raw probe unexpectedly loaded provider"),
    )
    assert canary.main() == 0
    assert (evidence / "raw_run_status.json").is_file()
    assert len([
        f for f in log_path.read_text().splitlines()
        if json.loads(f).get("method") == "session/prompt"
    ]) == 1


@pytest.mark.parametrize(("scenario", "expect_pass"), [
    ("ok", True),
    ("foreign_session", False),
    ("missing_session", False),
])
def test_nonempty_chunk_must_bind_active_session(
    canary, monkeypatch, tmp_path, scenario, expect_pass
):
    """Only a chunk whose sessionId equals the active session may count."""
    code, requests, _, evidence = _invoke(canary, monkeypatch, tmp_path, scenario)
    assert _methods(requests).count("session/prompt") == 1
    status = json.loads((evidence / "raw_run_status.json").read_text())
    if expect_pass:
        assert code == 0
        assert status["outcome"] == "PASS"
        assert status["message_chunk_count"] == 1
    else:
        assert code == 2
        assert status["outcome"] != "PASS"
        assert status["reason"] == "prompt_missing_nonempty_message_chunk"
        assert status["message_chunk_count"] == 0


def test_raw_probe_evidence_fingerprints_permission_name_sentinels(
    canary, monkeypatch, tmp_path
):
    """Strict raw-probe evidence never persists name/toolName verbatim."""
    binary = _fake(tmp_path)
    monkeypatch.setenv("ACP_FAKE_SCENARIO", "permission_sentinel")
    monkeypatch.setenv("ACP_FAKE_LOG", str(tmp_path / "requests.jsonl"))
    monkeypatch.setenv("ACP_CANARY_TEST_SECRET", "NEVER_PASS_PARENT_ENV")
    evidence = tmp_path / "evidence"
    monkeypatch.setattr(sys, "argv", [
        "acp_live_canary.py", "--cwd", str(tmp_path), "--mode", "raw-probe",
        "--evidence", str(evidence), "--command", str(binary),
        "--fake-acp-only", "--model", "fake-test-model", "--timeout", "0.55",
    ])
    assert canary.main() != 0
    artifacts = sorted(p for p in evidence.rglob("*") if p.is_file())
    assert artifacts
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in artifacts)
    assert "CANARY_SENTINEL" not in corpus
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    assert "name_meta" in frames_text
    assert "toolName_meta" in frames_text


def _run_cli_raw_probe(canary, monkeypatch, tmp_path, scenario):
    binary = _fake(tmp_path)
    monkeypatch.setenv("ACP_FAKE_SCENARIO", scenario)
    monkeypatch.setenv("ACP_FAKE_LOG", str(tmp_path / "requests.jsonl"))
    monkeypatch.setenv("ACP_CANARY_TEST_SECRET", "NEVER_PASS_PARENT_ENV")
    evidence = tmp_path / "evidence"
    monkeypatch.setattr(sys, "argv", [
        "acp_live_canary.py", "--cwd", str(tmp_path), "--mode", "raw-probe",
        "--evidence", str(evidence), "--command", str(binary),
        "--fake-acp-only", "--model", "fake-test-model", "--timeout", "0.55",
    ])
    code = canary.main()
    return code, evidence


def _key_alias(name: str) -> str:
    """Mirror of scripts/acp_live_canary._key_alias: deterministic safe
    alias for a member name outside the structural allowlist."""
    return "key_" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]


def _num_token(value: int) -> str:
    """Mirror of scripts/acp_live_canary._correlation_token: deterministic
    hashable stand-in for a server-chosen JSON-RPC id."""
    return "num_" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:12]


INT_SENTINEL = 7239184561029384756
NEG_INT_SENTINEL = -9876543210987654321
FLOAT_SENTINEL = 4839207.25


def test_raw_probe_never_persists_untrusted_protocol_string_values(
    canary, monkeypatch, tmp_path
):
    """Key membership is not trust: hostile method/sessionUpdate/type/kind/
    status/stopReason values are fingerprinted in every evidence artifact.
    "detail" is itself a server-chosen member name, so its raw name is
    aliased rather than carried into a ``detail_meta`` key."""
    code, evidence = _run_cli_raw_probe(canary, monkeypatch, tmp_path, "hostile_values")
    assert code != 0
    artifacts = sorted(p for p in evidence.rglob("*") if p.is_file())
    assert artifacts
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in artifacts)
    assert "CANARY_SENTINEL" not in corpus
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    for fingerprinted in ("method_meta", "sessionUpdate_meta", "type_meta",
                          "kind_meta", "status_meta"):
        assert fingerprinted in frames_text
    assert "detail" not in frames_text
    assert _key_alias("detail") + "_meta" in frames_text
    prompt_result = json.loads(
        (evidence / "raw_prompt_result.json").read_text(encoding="utf-8")
    )
    assert prompt_result["stop_reason"] is None
    status = json.loads((evidence / "raw_run_status.json").read_text(encoding="utf-8"))
    assert status["outcome"] != "PASS"
    assert status["reason"] == "prompt_stop_reason_not_end_turn"


def test_raw_probe_never_persists_untrusted_protocol_member_names(
    canary, monkeypatch, tmp_path
):
    """Server-controlled member NAMES are privacy-bound just like values:
    unknown keys — arbitrary, nested, secret-fragment, primitive- or
    list-valued — persist only as deterministic key_<sha256[:12]> aliases
    across ALL evidence artifacts, while the valid protocol members of the
    same hostile notification keep their allowlisted shape and the probe
    still PASSes."""
    code, evidence = _run_cli_raw_probe(canary, monkeypatch, tmp_path, "hostile_keys")
    assert code == 0
    artifacts = sorted(p for p in evidence.rglob("*") if p.is_file())
    assert artifacts
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in artifacts)
    assert "CANARY_SENTINEL" not in corpus
    assert "secretfragment-sentinel-value" not in corpus
    assert "hostile-keys-control-chunk" not in corpus
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    # arbitrary and nested keys: fingerprinted aliases, never raw names
    assert _key_alias("CANARY_SENTINEL_KEY_4839207") + "_meta" in frames_text
    assert _key_alias("CANARY_SENTINEL_NESTED_KEY_4839207") in frames_text
    assert _key_alias("CANARY_SENTINEL_INNER_KEY_4839207") + "_meta" in frames_text
    # secret-fragment key: alias name only, value redacted (not even hashed)
    assert _key_alias("CANARY_SENTINEL_TOKEN_KEY_4839207") in frames_text
    # primitive- and list-nested keys
    assert _key_alias("CANARY_SENTINEL_INT_KEY_4839207") in frames_text
    assert _key_alias("CANARY_SENTINEL_LIST_KEY_4839207") in frames_text
    assert _key_alias("CANARY_SENTINEL_LISTITEM_KEY_4839207") in frames_text
    # valid-shape control living inside the same hostile notification
    assert '"sessionUpdate": "agent_message_chunk"' in frames_text
    assert '"type": "text"' in frames_text
    assert '"sessionId": "<redacted>"' in frames_text
    prompt_result = json.loads(
        (evidence / "raw_prompt_result.json").read_text(encoding="utf-8")
    )
    assert prompt_result["stop_reason"] == "end_turn"
    status = json.loads((evidence / "raw_run_status.json").read_text(encoding="utf-8"))
    assert status["outcome"] == "PASS"


def test_raw_probe_preserves_verified_protocol_values(
    canary, monkeypatch, tmp_path
):
    """Positive control: exact members of the verified ACP v1 enums survive
    verbatim so analyzer behavior and protocol accounting stay intact."""
    code, evidence = _run_cli_raw_probe(canary, monkeypatch, tmp_path, "ok")
    assert code == 0
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    for known in ('"method": "initialize"', '"method": "session/new"',
                  '"method": "session/set_model"', '"method": "session/prompt"',
                  '"method": "session/update"', '"sessionUpdate": "agent_message_chunk"',
                  '"jsonrpc": "2.0"', '"stopReason": "end_turn"'):
        assert known in frames_text
    prompt_result = json.loads(
        (evidence / "raw_prompt_result.json").read_text(encoding="utf-8")
    )
    assert prompt_result["stop_reason"] == "end_turn"


def test_valid_non_pass_stop_reason_is_preserved_without_fingerprint(
    canary, monkeypatch, tmp_path
):
    """max_tokens is a verified StopReason: it fails the PASS gate but is
    still persisted verbatim (not redacted/fingerprinted)."""
    code, requests, _, evidence = _invoke(canary, monkeypatch, tmp_path, "wrong_stop")
    assert code != 0
    assert _methods(requests).count("session/prompt") == 1
    prompt_result = json.loads(
        (evidence / "raw_prompt_result.json").read_text(encoding="utf-8")
    )
    assert prompt_result["stop_reason"] == "max_tokens"


def test_legacy_mode_passes_lane_gate_without_new_flags(
    canary, monkeypatch, tmp_path
):
    """The legacy default CLI mode keeps its pre-historical reference unattended contract: no
    lane flag is required, and execution proceeds past argument/lane validation."""
    binary = _fake(tmp_path)
    monkeypatch.setenv("ACP_FAKE_SCENARIO", "ok")
    log_path = tmp_path / "requests.jsonl"
    monkeypatch.setenv("ACP_FAKE_LOG", str(log_path))
    monkeypatch.setenv("ACP_CANARY_TEST_SECRET", "NEVER_PASS_PARENT_ENV")
    # Pre-seed so monkeypatch restores (removes) whatever main() injects.
    monkeypatch.setitem(
        os.environ, "HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE", "preseed")
    monkeypatch.setitem(
        os.environ, "HERMES_ANTIGRAVITY_ACP_WORKSPACE", "preseed")

    class LegacyGatePassed(RuntimeError):
        """Signals execution reached the provider-loading stage."""

    def _stop_at_provider_load(_repo):
        raise LegacyGatePassed

    monkeypatch.setattr(canary, "load_client_module", _stop_at_provider_load)
    argv = [
        "acp_live_canary.py", "--cwd", str(tmp_path), "--mode", "default",
        "--evidence", str(tmp_path / "evidence"), "--command", str(binary),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(LegacyGatePassed):
        canary.main()
    # No subprocess may be spawned before the provider stage in legacy mode.
    assert not log_path.exists()
    # the retired switches are never (re)injected by the canary itself
    assert os.environ["HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE"] == "preseed"
    assert os.environ["HERMES_ANTIGRAVITY_ACP_WORKSPACE"] == "preseed"


def test_raw_probe_never_persists_server_controlled_primitives_of_any_json_type(
    canary, monkeypatch, tmp_path
):
    """Fail-closed privacy covers EVERY JSON primitive type, not just
    strings: hostile ints/floats under unknown keys, primitives nested in
    lists, known-looking id/code/protocolVersion smuggled under a hostile
    wrapper, secret-fragment keys carrying numbers, and type-confused
    numerics under allowlisted string-enum keys never reach ANY evidence
    artifact, while the probe still PASSes on valid session-bound members."""
    code, evidence = _run_cli_raw_probe(canary, monkeypatch, tmp_path, "hostile_numbers")
    assert code == 0
    artifacts = sorted(p for p in evidence.rglob("*") if p.is_file())
    assert artifacts
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in artifacts)
    for sentinel in (str(INT_SENTINEL), str(NEG_INT_SENTINEL), repr(FLOAT_SENTINEL)):
        assert sentinel not in corpus
    assert "CANARY_SENTINEL" not in corpus
    assert "numeric-hostile-control-chunk" not in corpus
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    # unknown-key numerics: aliased member name + fingerprint, never value
    assert _key_alias("CANARY_SENTINEL_INT_KEY_4839207") + "_meta" in frames_text
    assert _key_alias("CANARY_SENTINEL_FLOAT_KEY_4839207") + "_meta" in frames_text
    assert _key_alias("CANARY_SENTINEL_NEGINT_KEY_4839207") + "_meta" in frames_text
    # booleans fail closed with the single exfiltratable bit discarded
    assert '"value_type": "int"' in frames_text
    assert '"value_type": "float"' in frames_text
    assert '"value_type": "bool"' in frames_text
    # nested lists and the hostile id/code/protocolVersion wrapper
    assert _key_alias("CANARY_SENTINEL_PRIMLIST_KEY_4839207") in frames_text
    assert _key_alias("CANARY_SENTINEL_WRAPPER_KEY_4839207") in frames_text
    # secret-fragment key carrying a number: alias + redaction, no value
    assert _key_alias("authToken") in frames_text
    # type-confused numeric under an allowlisted string-enum key
    assert "status_meta" in frames_text
    # every recorded frame stays parseable JSON
    for line in frames_text.splitlines():
        json.loads(line)
    # legitimate protocol controls of the same run keep their verified shape
    assert '"jsonrpc": "2.0"' in frames_text
    assert '"sessionUpdate": "agent_message_chunk"' in frames_text
    assert '"stopReason": "end_turn"' in frames_text
    assert '"id": 4' in frames_text
    prompt_result = json.loads(
        (evidence / "raw_prompt_result.json").read_text(encoding="utf-8")
    )
    assert prompt_result["stop_reason"] == "end_turn"
    status = json.loads((evidence / "raw_run_status.json").read_text(encoding="utf-8"))
    assert status["outcome"] == "PASS"


def test_raw_probe_hostile_envelope_id_persists_only_as_correlation_token(
    canary, monkeypatch, tmp_path
):
    """The envelope id position is a legitimate numeric-protocol position;
    a hostile numeric echo there must still fail closed into the
    deterministic correlation token, never the sentinel integer."""
    code, evidence = _run_cli_raw_probe(
        canary, monkeypatch, tmp_path, "hostile_envelope_id"
    )
    assert code != 0
    artifacts = sorted(p for p in evidence.rglob("*") if p.is_file())
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in artifacts)
    assert str(INT_SENTINEL) not in corpus
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    assert _num_token(INT_SENTINEL) in frames_text
    status = json.loads((evidence / "raw_run_status.json").read_text(encoding="utf-8"))
    assert status["reason"] == "unexpected_response_id"


def test_raw_probe_server_permission_id_correlates_without_literal(
    canary, monkeypatch, tmp_path
):
    """A server-chosen permission id stays joinable across the request and
    the harness answer (same token in both frames) without its literal ever
    being persisted in any evidence artifact."""
    code, evidence = _run_cli_raw_probe(
        canary, monkeypatch, tmp_path, "permission_numeric_id"
    )
    assert code != 0
    artifacts = sorted(p for p in evidence.rglob("*") if p.is_file())
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in artifacts)
    assert str(INT_SENTINEL) not in corpus
    frames_text = (evidence / "frames.jsonl").read_text(encoding="utf-8")
    # request frame and the driver's cancelled-answer frame share one token
    assert frames_text.count(_num_token(INT_SENTINEL)) >= 2


def _strict(canary, frame):
    return canary._sanitize_raw_protocol(frame, lambda s: s)


def test_raw_protocol_sanitizer_fail_closed_primitive_matrix(canary):
    """Deterministic unit coverage for every generalized-invariant
    equivalence class: type-correct verified protocol numbers survive only
    at their exact protocol position; all other primitives fail closed."""
    dump = lambda obj: json.dumps(obj, ensure_ascii=False)  # noqa: E731

    # unknown key + integer: alias + {value_type, sha256}, never the value
    out = _strict(canary, {"weird": INT_SENTINEL})
    alias_meta = _key_alias("weird") + "_meta"
    assert out[alias_meta]["value_type"] == "int"
    assert out[alias_meta]["sha256"] == hashlib.sha256(
        str(INT_SENTINEL).encode("utf-8")).hexdigest()
    assert str(INT_SENTINEL) not in dump(out)

    # float under an unknown key
    out = _strict(canary, {"f": FLOAT_SENTINEL})
    assert out[_key_alias("f") + "_meta"]["value_type"] == "float"
    assert repr(FLOAT_SENTINEL) not in dump(out)

    # booleans fail closed with the value discarded entirely
    assert _strict(canary, {"b": True}) == _strict(canary, {"b": False})
    assert _strict(canary, {"b": True}) == {_key_alias("b") + "_meta": {"value_type": "bool"}}

    # null carries zero bits and stays null
    assert _strict(canary, {"n": None}) == {_key_alias("n"): None}

    # primitives nested inside a list all fail closed, except null
    items = _strict(canary, {"lst": [INT_SENTINEL, FLOAT_SENTINEL, True, None]})[
        _key_alias("lst")]
    assert [item["value_type"] for item in items[:3]] == ["int", "float", "bool"]
    assert items[3] is None
    assert str(INT_SENTINEL) not in dump(items)

    # known-looking protocol member names under a hostile wrapper context
    # are untrusted: values fail closed at every nesting level
    out = _strict(canary, {"wrapper": {"id": INT_SENTINEL, "code": INT_SENTINEL,
                                       "protocolVersion": INT_SENTINEL}})
    assert str(INT_SENTINEL) not in dump(out)

    # type confusion under an allowlisted string-enum key
    assert _strict(canary, {"stopReason": INT_SENTINEL}) == {
        "stopReason_meta": {"value_type": "int", "sha256": hashlib.sha256(
            str(INT_SENTINEL).encode("utf-8")).hexdigest()}}
    out = _strict(canary, {"params": {"update": {
        "sessionUpdate": "tool_call", "status": INT_SENTINEL}}})
    assert out["params"]["update"]["sessionUpdate"] == "tool_call"
    assert out["params"]["update"]["status_meta"]["value_type"] == "int"

    # envelope id: this driver's own finite id set stays verbatim integers
    for rpc_id in (1, 2, 3, 4):
        assert _strict(canary, {"jsonrpc": "2.0", "id": rpc_id})["id"] == rpc_id
    # server-chosen ids tokenize deterministically (cross-frame joinable)
    token_a = _strict(canary, {"jsonrpc": "2.0", "id": INT_SENTINEL})["id"]
    token_b = _strict(canary, {"jsonrpc": "2.0", "id": INT_SENTINEL,
                               "result": {}})["id"]
    assert token_a == token_b == _num_token(INT_SENTINEL)
    assert str(INT_SENTINEL) not in dump({"a": token_a})
    assert _strict(canary, {"jsonrpc": "2.0", "id": 5})["id"] == _num_token(5)
    # envelope id type confusion never survives as a value
    assert _strict(canary, {"id": True}) == {"id_meta": {"value_type": "bool"}}
    assert _strict(canary, {"id": 2.0})["id_meta"]["value_type"] == "float"
    assert "id_meta" in _strict(canary, {"id": "opaque-secret"})
    assert _strict(canary, {"id": None}) == {"id": None}

    # protocolVersion: verbatim only directly inside the envelope body,
    # only for the pinned ACP v1 value; closed elsewhere or otherwise
    init = _strict(canary, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                            "params": {"protocolVersion": 1, "clientCapabilities":
                                       {"fs": {"readTextFile": False}}}})
    assert init["params"]["protocolVersion"] == 1
    assert _strict(canary, {"result": {"protocolVersion": 1}}
                   )["result"]["protocolVersion"] == 1
    assert _strict(canary, {"result": {"protocolVersion": 2}}
                   )["result"]["protocolVersion_meta"]["value_type"] == "int"
    assert "protocolVersion_meta" in _strict(canary, {"jsonrpc": "2.0", "protocolVersion": 1})
    assert _strict(canary, {"result": {"protocolVersion": True}}
                   )["result"]["protocolVersion_meta"] == {"value_type": "bool"}

    # error.code: verbatim only inside the error object, only for the
    # JSON-RPC 2.0 predefined codes and the reserved server-error range
    for code_value in (-32700, -32600, -32601, -32602, -32603, -32000, -32099):
        assert _strict(canary, {"error": {"code": code_value}})["error"]["code"] == code_value
    err = _strict(canary, {"jsonrpc": "2.0", "id": 2,
                           "error": {"code": -32602, "message": "model rejected"}})
    assert err["error"]["code"] == -32602
    assert err["error"]["message_meta"]["chars"] == len("model rejected")
    assert _strict(canary, {"error": {"code": 42}})["error"]["code_meta"]["value_type"] == "int"
    closed = _strict(canary, {"error": {"code": INT_SENTINEL}})["error"]
    assert "code" not in closed
    assert closed["code_meta"]["value_type"] == "int"
    assert str(INT_SENTINEL) not in dump(closed)
    assert _strict(canary, {"error": {"code": True}})["error"]["code_meta"] == {"value_type": "bool"}
    # code outside its error-object context is type confusion, not trust
    assert "code_meta" in dump(_strict(canary, {"jsonrpc": "2.0", "id": 1, "code": -32602}))

    # secret-fragment member names with numeric values stay redacted
    assert _strict(canary, {"authToken": INT_SENTINEL}) == {_key_alias("authToken"): "<redacted>"}
    assert _strict(canary, {"params": {"sessionId": INT_SENTINEL}}
                   )["params"]["sessionId"] == "<redacted>"

    # legacy default sanitizer keeps its numeric pass-through contract
    assert canary._sanitize({"x": INT_SENTINEL, "y": True, "z": None},
                            lambda s: s) == {"x": INT_SENTINEL, "y": True, "z": None}


# ---------------------------------------------------------------------------
# Fail-closed initialize boundary (reviewer run 637, head b3156d96)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("variant", [
    "missing", "object", "string", "bool", "float", "null", "unsupported",
])
def test_malformed_initialize_protocol_version_fails_closed_before_session_new(
    canary, monkeypatch, tmp_path, variant
):
    """historical reference fail-closed contract: the driver advances past `initialize`
    only when the result carries the required, type-correct, supported ACP
    protocol version. Missing, object-shaped, string, bool-, float-, null- or
    unsupported-integer protocolVersion values are rejected conservatively:
    no `session/new`, no `session/set_model`, no `session/prompt`, no PASS."""
    code, requests, _, evidence = _invoke(
        canary, monkeypatch, tmp_path, f"init_version_{variant}"
    )
    assert code != 0, variant
    assert _methods(requests) == ["initialize"], variant
    status = json.loads(
        (evidence / "raw_run_status.json").read_text(encoding="utf-8")
    )
    assert status["outcome"] != "PASS", variant
    assert status["reason"] == "initialize_unsupported_protocol_version", variant
    assert status["prompt_count"] == 0, variant


def test_valid_initialize_protocol_version_positive_control(
    canary, monkeypatch, tmp_path
):
    """ACP v1 protocolVersion 1 — the value this driver and the pinned
    vendor client send in their own initialize params — still completes the
    full ordered handshake and PASSes."""
    code, requests, _, evidence = _invoke(canary, monkeypatch, tmp_path, "ok")
    assert code == 0
    assert _methods(requests) == [
        "initialize", "session/new", "session/set_model", "session/prompt"
    ]
    status = json.loads(
        (evidence / "raw_run_status.json").read_text(encoding="utf-8")
    )
    assert status["outcome"] == "PASS"


# ---------------------------------------------------------------------------
# Mandatory session/set_model confirmation before prompt/PASS
# (reviewer run 642, head 9c8ea39d)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("model_value", ["", "   ", None])
def test_empty_or_missing_model_fails_closed_before_any_prompt(
    canary, monkeypatch, tmp_path, model_value
):
    """historical reference ordering contract: the raw probe never sends
    `session/prompt` (and can never report PASS) unless a non-empty model
    was confirmed via `session/set_model`. The prior head skipped
    `session/set_model` for an empty/whitespace/missing model, prompted
    directly and recorded PASS; every such run must now fail closed after
    `initialize` and `session/new` only."""
    code, requests, _, evidence = _invoke(
        canary, monkeypatch, tmp_path, "ok", model=model_value
    )
    assert code != 0, repr(model_value)
    assert _methods(requests) == ["initialize", "session/new"], repr(model_value)
    assert "session/set_model" not in _methods(requests), repr(model_value)
    assert "session/prompt" not in _methods(requests), repr(model_value)
    status = json.loads(
        (evidence / "raw_run_status.json").read_text(encoding="utf-8")
    )
    assert status["outcome"] != "PASS", repr(model_value)
    assert status["reason"] == "model_missing_for_set_model", repr(model_value)
    assert status["prompt_count"] == 0, repr(model_value)
    assert status["set_model_acknowledged"] is False, repr(model_value)


def test_cli_empty_model_rejected_for_raw_probe_without_child_contact(
    canary, monkeypatch, tmp_path
):
    """CLI-level fail-closed gate: ``--model ""`` for ``--mode raw-probe``
    is rejected before the child is ever spawned — no handshake frames, no
    prompt, exit != 0, and no evidence dir is created."""
    binary = _fake(tmp_path)
    monkeypatch.setenv("ACP_FAKE_SCENARIO", "ok")
    monkeypatch.setenv("ACP_FAKE_LOG", str(tmp_path / "requests.jsonl"))
    monkeypatch.setenv("ACP_CANARY_TEST_SECRET", "NEVER_PASS_PARENT_ENV")
    evidence = tmp_path / "evidence"
    monkeypatch.setattr(sys, "argv", [
        "acp_live_canary.py", "--cwd", str(tmp_path), "--mode", "raw-probe",
        "--evidence", str(evidence), "--command", str(binary),
        "--fake-acp-only", "--model", "", "--timeout", "0.55",
    ])
    code = canary.main()
    assert code != 0
    assert not (tmp_path / "requests.jsonl").exists()
    assert not evidence.exists()


def test_set_model_error_never_reaches_prompt_or_pass(
    canary, monkeypatch, tmp_path
):
    """A server that rejects session/set_model stops the handshake: the
    driver received a set_model RPC error, so no session/prompt is sent and
    no PASS is recorded even though the fake would have answered one."""
    code, requests, _, evidence = _invoke(
        canary, monkeypatch, tmp_path, "set_model_error"
    )
    assert code != 0
    methods = _methods(requests)
    assert methods == ["initialize", "session/new", "session/set_model"]
    assert "session/prompt" not in methods
    status = json.loads(
        (evidence / "raw_run_status.json").read_text(encoding="utf-8")
    )
    assert status["outcome"] != "PASS"
    assert status["reason"] == "set_model_rpc_error"
    assert status["set_model_acknowledged"] is False
    assert status["prompt_count"] == 0


def test_nonempty_model_ordered_handshake_positive_control(
    canary, monkeypatch, tmp_path
):
    """Valid nonempty-model control for the mandatory-confirmation gate:
    the probe still runs exactly initialize -> session/new ->
    session/set_model -> session/prompt, observes the set_model success
    reply (response id 3) before emitting the prompt request (id 4), and
    PASSes with set_model_acknowledged true."""
    code, requests, frames, evidence = _invoke(canary, monkeypatch, tmp_path, "ok")
    assert code == 0
    assert _methods(requests) == [
        "initialize", "session/new", "session/set_model", "session/prompt"
    ]
    positions = [
        (entry["dir"], entry["frame"].get("method"), entry["frame"].get("id"))
        for entry in frames
    ]
    set_model_request = next(
        i for i, e in enumerate(positions)
        if e == ("out", "session/set_model", 3)
    )
    set_model_ack = next(i for i, e in enumerate(positions) if e == ("in", None, 3))
    prompt_request = next(
        i for i, e in enumerate(positions) if e == ("out", "session/prompt", 4)
    )
    assert set_model_request < set_model_ack < prompt_request
    status = json.loads(
        (evidence / "raw_run_status.json").read_text(encoding="utf-8")
    )
    assert status["outcome"] == "PASS"
    assert status["set_model_acknowledged"] is True
    assert status["effective_model_verified"] is False
    assert status["prompt_count"] == 1
