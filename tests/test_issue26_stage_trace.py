"""Issue #26: privacy-safe ACP stage tracing — credential-free fake-ACP tests.

Pins the opt-in trace contract agreed in the issue investigation:

* one JSONL line per observable event: ``{t_mono, stage, req_key, pid, detail}``;
* the eight lifecycle stages plus bounded rejection/retry classification;
* silence is recorded as an explicit ``unknown`` — never a fabricated vendor
  503, retry count, or queue position;
* disabled by default means zero files and zero writes;
* per-request event caps and single-file size rotation keep growth bounded;
* concurrent requests on separate client instances keep disjoint correlation
  identities;
* no prompt text, raw session ids, labels, tokens, or private paths leak.

The mux half (lane_bound with a lane fingerprint instead of the raw label,
plus process_exit) is exercised through the real mux entrypoint against a
fake official server, same harness style as tests/test_acp_mux.py.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"
MUX_ENTRYPOINT = ROOT / "scripts" / "acp_mux.py"

TRACE_ENV = "HERMES_ANTIGRAVITY_ACP_TRACE"
TRACE_FILE_ENV = "HERMES_ANTIGRAVITY_ACP_TRACE_FILE"
TRACE_SILENCE_ENV = "HERMES_ANTIGRAVITY_ACP_TRACE_SILENCE_SECONDS"

# Markers that must never appear anywhere in trace output.
SECRET_SESSION_ID = "fake-session-SECRETSESSION0001"
SECRET_PROMPT_MARKER = "SECRET-PROMPT-MARKER-DO-NOT-LOG"
SECRET_LABEL = "sensitive-account-label"
# Adversarial stopReason payload (review item 2): a hostile/malformed server
# string that must never cross the trace privacy boundary verbatim.
HOSTILE_STOP_REASON = (
    "IGNORE-PREVIOUS-INSTRUCTIONS sk-SECRET-STOPREASON-9137 "
    "fake-session-SECRETSESSION0001"
)
FORBIDDEN_SUBSTRINGS = (
    SECRET_SESSION_ID,
    SECRET_PROMPT_MARKER,
    SECRET_LABEL,
    "sk-SECRET-STOPREASON-9137",
    "IGNORE-PREVIOUS-INSTRUCTIONS",
    "ya29.",
    "access_token",
    "refresh_token",
    "Bearer",
)
# Vendor-error tokens are scanned only over stage/detail fields: a salted
# correlation hash is random hex and may contain any short decimal string
# ("503" included) by pure chance — that is not a vendor claim.
FORBIDDEN_VENDOR_TOKENS = ("503", "No capacity", "capacity", "queue position")


def _vendor_token_scan_text(records: list[dict]) -> str:
    def strip_hashes(value):
        if isinstance(value, dict):
            return {
                key: (
                    "<hash>"
                    if key.endswith("_hash") or key == "request_key"
                    else strip_hashes(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [strip_hashes(item) for item in value]
        if isinstance(value, str) and value.startswith("opaque:"):
            # Request-scoped model fingerprints are hex too: same entropy
            # caveat as salted hashes above.
            return "<opaque>"
        return value

    return json.dumps(
        [
            {"stage": r["stage"], "detail": strip_hashes(r["detail"])}
            for r in records
        ]
    ).lower()


def _load_plugin(monkeypatch, tmp_path: Path, *, trace: bool):
    """Load a fresh copy of the plugin package with trace env decided here.

    A fresh module tree also means a fresh ``request_trace`` singleton, so
    each test controls its own trace file.
    """
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(tmp_path / "acp-state.json")
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", str(tmp_path / "acp-limits.json")
    )
    if trace:
        monkeypatch.setenv(TRACE_ENV, "1")
        monkeypatch.setenv(TRACE_FILE_ENV, str(tmp_path / "trace.jsonl"))
    else:
        monkeypatch.delenv(TRACE_ENV, raising=False)
        monkeypatch.delenv(TRACE_FILE_ENV, raising=False)
    monkeypatch.delenv("ACP_MUX_TRACE", raising=False)

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
    file_safety = types.ModuleType("agent.file_safety")
    file_safety.get_nt_namespace_error = lambda path, verb=None: None
    file_safety.get_read_block_error = lambda path: None
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    redact = types.ModuleType("agent.redact")
    redact.redact_sensitive_text = lambda text, force=True: text
    monkeypatch.setitem(sys.modules, "agent.redact", redact)

    module_name = "antigravity_acp_issue26"
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
    # client/bridge/request_trace import lazily behind create_client in the
    # package __init__; import them explicitly so every test shares THIS copy.
    client_module = importlib.import_module(module_name + ".client")
    trace_module = importlib.import_module(module_name + ".request_trace")
    bridge_module = importlib.import_module(module_name + ".bridge")
    return module, client_module, trace_module, bridge_module


def _make_client(module, tmp_path: Path, mode: str):
    fake = tmp_path / "fake_acp_server.py"
    fake.write_text(FAKE_ACP, encoding="utf-8")
    fake_log = tmp_path / f"fake-events-{mode}-{time.time_ns()}.jsonl"
    client = module.antigravity_acp.create_client(
        command=sys.executable,
        args=[str(fake), mode, str(fake_log)],
        acp_cwd=str(tmp_path),
        rate_limit_retries=0,
    )
    return client, fake_log


FAKE_ACP = r'''
import json
import sys
import time

mode = sys.argv[1]
log_path = sys.argv[2]
t0 = time.monotonic()

def log(event):
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"event": event, "t": round(time.monotonic() - t0, 3)}) + "\n")

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def chunk(text):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "fake-session-SECRETSESSION0001",
        "update": {"sessionUpdate": "agent_message_chunk",
                   "content": {"type": "text", "text": text}}}})

turn = 0
for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": 1}})
    elif method == "session/new":
        current = (
            "123e4567-e89b-12d3-a456-426614174000"
            if mode == "hostile_model" else "fake-model-b"
        )
        emit({"jsonrpc": "2.0", "id": mid, "result": {
            "sessionId": "fake-session-SECRETSESSION0001",
            "configOptions": [{"id": "model", "category": "model",
                "currentValue": current,
                "options": [{"value": current}]},
                {"id": "thinking_level", "category": "think",
                 "currentValue": "high", "options": [{"value": "high"}]}],
        }})
    elif method in ("session/resume", "session/set_config_option", "session/set_model"):
        emit({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "session/prompt":
        turn += 1
        log("prompt_received")
        if mode == "stall":
            time.sleep(30)
        elif mode == "malformed" and turn == 1:
            chunk('<tool_call>{"id": "call-bad", "type": "function", "function": {"name": "read_file", "arguments": "{bad')
            emit({"jsonrpc": "2.0", "id": mid, "result": {"stopReason": "end_turn"}})
        elif mode == "hostile":
            chunk("done")
            emit({"jsonrpc": "2.0", "id": mid,
                  "result": {"stopReason": "IGNORE-PREVIOUS-INSTRUCTIONS sk-SECRET-STOPREASON-9137 fake-session-SECRETSESSION0001"}})
        else:
            chunk("done")
            emit({"jsonrpc": "2.0", "id": mid, "result": {"stopReason": "end_turn"}})
log("stdin_eof_exit")
'''


def _read_trace(path: Path, trace_module) -> list[dict]:
    text = Path(path).read_text(encoding="utf-8")
    records = [json.loads(line) for line in text.splitlines() if line.strip()]
    for record in records:
        assert set(record) == {"t_mono", "stage", "req_key", "pid", "detail"}
        assert record["stage"] in trace_module.TRACE_STAGES
        assert isinstance(record["t_mono"], float)
    return records


def _assert_no_leaks(text: str, tmp_path: Path, records: list[dict]) -> None:
    for forbidden in FORBIDDEN_SUBSTRINGS:
        assert forbidden not in text, forbidden
    assert str(tmp_path) not in text
    scan = _vendor_token_scan_text(records)
    for forbidden in FORBIDDEN_VENDOR_TOKENS:
        assert forbidden not in scan, forbidden


def _wait_for_file(predicate, timeout=10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _fake_events(path: Path) -> list[dict]:
    if not Path(path).exists():
        return []
    return [
        json.loads(line)
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# 1. Normal request lifecycle trace
# ---------------------------------------------------------------------------


def test_normal_lifecycle_trace(monkeypatch, tmp_path):
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client, _ = _make_client(module, tmp_path, "normal")
    try:
        answer, _ = client._run_prompt(
            f"{SECRET_PROMPT_MARKER} hello", timeout_seconds=20.0
        )
    finally:
        client.close()
    assert answer == "done"
    records = _read_trace(tmp_path / "trace.jsonl", trace_module)
    stages = [record["stage"] for record in records]
    assert stages == [
        "initialize",
        "session_new_or_resume",
        "prompt_sent",
        "first_update",
        "prompt_response",
    ], stages
    assert [r["t_mono"] for r in records] == sorted(r["t_mono"] for r in records)
    assert len({r["req_key"] for r in records}) == 1
    assert len({r["pid"] for r in records}) == 1
    assert all(r["pid"] for r in records)
    session_event = records[1]
    assert session_event["detail"]["branch"] == "new"
    assert session_event["detail"]["session_id_hash"].startswith("sha256:")
    prompt_event = records[2]
    assert prompt_event["detail"]["prompt_text_bytes"] > 0
    assert prompt_event["detail"]["turn_id_hash"].startswith("sha256:")
    # Requested-vs-effective model pair distinguishes a silent model
    # substitution from a plain slow turn (issue scope item 3).
    assert prompt_event["detail"]["requested_model"] == "unspecified"
    assert prompt_event["detail"]["effective_model"] == "fake-model-b"
    response_event = records[4]
    assert response_event["detail"]["outcome"] == "completed"
    assert response_event["detail"]["stop_reason"] == "end_turn"
    assert response_event["detail"]["session_updates"] >= 1
    _assert_no_leaks(
        (tmp_path / "trace.jsonl").read_text(encoding="utf-8"), tmp_path, records
    )


# ---------------------------------------------------------------------------
# 2. No-first-update stall: classified unknown, never a fabricated vendor 503
# ---------------------------------------------------------------------------


def test_silence_is_unknown_never_vendor_503(monkeypatch, tmp_path):
    monkeypatch.setenv(TRACE_SILENCE_ENV, "0.3")
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client, _ = _make_client(module, tmp_path, "stall")
    try:
        with pytest.raises(TimeoutError):
            client._run_prompt(
                f"{SECRET_PROMPT_MARKER} hello", timeout_seconds=2.0
            )
    finally:
        client.close()
    text = (tmp_path / "trace.jsonl").read_text(encoding="utf-8")
    records = _read_trace(tmp_path / "trace.jsonl", trace_module)
    stages = [record["stage"] for record in records]
    assert "prompt_sent" in stages
    assert "first_update" not in stages
    heartbeats = [
        record
        for record in records
        if record["detail"].get("classification")
        == "waiting_for_upstream_no_protocol_events"
    ]
    assert heartbeats, "silence must produce at least one unknown heartbeat"
    for heartbeat in heartbeats:
        assert heartbeat["stage"] == "unknown"
        assert heartbeat["detail"]["vendor_cause"] == "unknown"
        assert heartbeat["detail"]["waiting_on"] == "session/prompt"
    deadline_events = [
        record
        for record in records
        if record["detail"].get("classification") == "deadline_exceeded"
    ]
    assert deadline_events
    assert deadline_events[0]["detail"]["vendor_cause"] == "unknown"
    # The silence rule: nothing in the trace fields may imply a vendor
    # error class (hash fields excluded: random hex may contain digits).
    scan = _vendor_token_scan_text(records)
    assert "503" not in scan
    assert "capacity" not in scan
    assert "retry" not in scan
    _assert_no_leaks(text, tmp_path, records)


# ---------------------------------------------------------------------------
# 3. Successful completion (covered in test 1) and cancellation paths
# ---------------------------------------------------------------------------


def test_cancel_path_records_cancel_requested(monkeypatch, tmp_path):
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client, fake_log = _make_client(module, tmp_path, "stall")
    outcome: dict = {}

    def run() -> None:
        try:
            client._run_prompt(
                f"{SECRET_PROMPT_MARKER} hello", timeout_seconds=30.0
            )
        except BaseException as exc:  # noqa: BLE001 - classified below
            outcome["exc"] = exc

    thread = threading.Thread(target=run)
    thread.start()
    try:
        assert _wait_for_file(
            lambda: any(
                event["event"] == "prompt_received" for event in _fake_events(fake_log)
            )
        ), "fake server never received the prompt"
        client.cancel()
        thread.join(timeout=20)
        assert not thread.is_alive()
        assert isinstance(outcome.get("exc"), client_module._AcpCancelledError)
        records = _read_trace(tmp_path / "trace.jsonl", trace_module)
        prompt_events = [r for r in records if r["stage"] == "prompt_sent"]
        cancel_events = [r for r in records if r["stage"] == "cancel_requested"]
        assert len(prompt_events) == 1
        assert len(cancel_events) == 1
        # The cancel is attributed to the exact in-flight attempt it stopped.
        assert cancel_events[0]["req_key"] == prompt_events[0]["req_key"]
        assert cancel_events[0]["pid"] == prompt_events[0]["pid"]
        assert cancel_events[0]["detail"]["source"] == "hermes_interrupt"
        # The cancel (interrupt thread) still joins the request key of the
        # attempt it stopped, despite running outside the request context.
        assert (
            cancel_events[0]["detail"]["request_key"]
            == prompt_events[0]["detail"]["request_key"]
        )
        assert prompt_events[0]["detail"]["request_key"] != "unknown"
        _assert_no_leaks(
            (tmp_path / "trace.jsonl").read_text(encoding="utf-8"), tmp_path, records
        )
    finally:
        client.close()


# ---------------------------------------------------------------------------
# 4. Local response rejection and retry classification
# ---------------------------------------------------------------------------


def _malformed_call() -> str:
    return (
        "<tool_call>"
        + json.dumps(
            {
                "id": "call-bad",
                "type": "function",
                "function": {
                    "name": "read_file",
                    "arguments": '{"path": "router.py"',
                },
            }
        )
        + "</tool_call>"
    )


def _valid_call() -> str:
    return (
        "<tool_call>"
        + json.dumps(
            {
                "id": "call-good",
                "type": "function",
                "function": {
                    "name": "read_file",
                    "arguments": json.dumps({"path": "router.py"}),
                },
            }
        )
        + "</tool_call>"
    )


def _tool_schema(name: str):
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": "Read a file",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        },
    }


def test_local_rejection_and_retry_classification(monkeypatch, tmp_path):
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client = module.antigravity_acp.create_client()
    responses = [_malformed_call(), _valid_call()]
    turns: list[dict] = []

    def fake_run_prompt(prompt_text, **kwargs):
        turns.append({"prompt": prompt_text, "resume": kwargs["resume_session_id"]})
        kwargs["session_result"].update(
            session_id="session-re",
            resumed=bool(kwargs["resume_session_id"]),
            native_activity={"native_tool_calls": []},
        )
        return responses[len(turns) - 1], ""

    monkeypatch.setattr(client, "_run_prompt", fake_run_prompt)
    result = client.chat.completions.create(
        model="fake-model-b-high",
        messages=[{"role": "user", "content": f"{SECRET_PROMPT_MARKER} read router.py"}],
        tools=[_tool_schema("read_file")],
    )
    assert len(turns) == 2, "expected one malformed turn plus one correction turn"
    assert result.choices[0].message.tool_calls
    records = _read_trace(tmp_path / "trace.jsonl", trace_module)
    rejected = [r for r in records if r["stage"] == "response_rejected"]
    retried = [r for r in records if r["stage"] == "retry_attempt"]
    assert len(rejected) == 1
    assert rejected[0]["detail"]["classification"] == "malformed_tool_call"
    assert rejected[0]["detail"]["unrecoverable"] is False
    assert rejected[0]["detail"]["attempt"] == 1
    assert len(retried) == 1
    assert retried[0]["detail"]["reason"] == "malformed_correction"
    assert retried[0]["detail"]["attempt"] == 1
    # Rejection/retry events join the request key of the completion call
    # that produced them (per-call scope, not per-instance).
    assert rejected[0]["req_key"] == retried[0]["req_key"]
    assert rejected[0]["req_key"] not in ("", "unknown")
    _assert_no_leaks(
        (tmp_path / "trace.jsonl").read_text(encoding="utf-8"), tmp_path, records
    )


def test_orphan_guard_classes_are_distinguishable(monkeypatch, tmp_path):
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    Malformed = client_module.MalformedToolCallError
    with pytest.raises(Malformed) as orphan_result:
        bridge_module._reject_orphan_protocol_fragments(
            'prefix\nTool:\n'
            '<tool_response>{"tool_call_id": "x", "content": "y"}</tool_response>'
        )
    assert orphan_result.value.reason == "orphan_result"
    assert orphan_result.value.unrecoverable is True
    with pytest.raises(Malformed) as orphan_call:
        bridge_module._reject_orphan_protocol_fragments("dangling <tool_call text")
    assert orphan_call.value.reason == "orphan_call"
    assert orphan_call.value.unrecoverable is False


# ---------------------------------------------------------------------------
# 5. Concurrent requests keep distinct correlation identities
# ---------------------------------------------------------------------------


def test_frontier_mismatch_replay_is_classified(monkeypatch, tmp_path):
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client, _ = _make_client(module, tmp_path, "normal")
    try:
        client.chat.completions.create(
            model="fake-model-b-high",
            messages=[{"role": "user", "content": "hello"}],
            tools=[_tool_schema("read_file")],
        )
        client.chat.completions.create(
            model="fake-model-b-high",
            messages=[
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "done"},
                {"role": "user", "content": f"{SECRET_PROMPT_MARKER} again"},
            ],
            # A changed tool bridge changes the context fingerprint: the
            # continuation delta is impossible and the client full-replays.
            tools=[_tool_schema("terminal")],
        )
    finally:
        client.close()
    records = _read_trace(tmp_path / "trace.jsonl", trace_module)
    replays = [
        r
        for r in records
        if r["stage"] == "retry_attempt"
        and r["detail"].get("reason") == "frontier_mismatch"
    ]
    assert len(replays) == 1
    assert replays[0]["detail"]["prompt_bytes"] > 0
    # Per-call attribution: the frontier replay belongs to the SECOND
    # completion call on this instance, not the first and not the instance.
    sent = [r for r in records if r["stage"] == "prompt_sent"]
    assert len(sent) == 2
    call_keys = [r["detail"]["request_key"] for r in sent]
    assert len(set(call_keys)) == 2
    assert replays[0]["req_key"] == call_keys[1]
    assert replays[0]["req_key"] != call_keys[0]
    # Only the byte cost is recorded, never the fingerprint inputs.
    assert "fingerprint" not in json.dumps(replays[0])
    _assert_no_leaks(
        (tmp_path / "trace.jsonl").read_text(encoding="utf-8"), tmp_path, records
    )


def test_concurrent_requests_disjoint_req_keys(monkeypatch, tmp_path):
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client_a, _ = _make_client(module, tmp_path, "normal")
    client_b, _ = _make_client(module, tmp_path, "normal")
    errors: list[BaseException] = []

    def run(client, marker: str) -> None:
        try:
            client._run_prompt(f"{SECRET_PROMPT_MARKER} {marker}", timeout_seconds=20.0)
        except BaseException as exc:  # noqa: BLE001 - asserted below
            errors.append(exc)

    threads = [
        threading.Thread(target=run, args=(client, marker))
        for client, marker in ((client_a, "A"), (client_b, "B"))
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    try:
        assert not errors, errors
        records = _read_trace(tmp_path / "trace.jsonl", trace_module)
        # Derive each request's correlation identity from the trace itself:
        # one prompt_sent per client, each pinned to its own child pid.
        sent = [r for r in records if r["stage"] == "prompt_sent"]
        assert len(sent) == 2
        request_keys = {r["detail"]["request_key"] for r in sent}
        assert len(request_keys) == 2, (
            "concurrent requests must not share request keys"
        )
        assert all(k and k != "unknown" for k in request_keys)
        attempt_keys = {r["req_key"] for r in sent}
        assert len(attempt_keys) == 2
        pids = {r["pid"] for r in sent}
        assert len(pids) == 2
        # Every lifecycle stage of each request stayed on its own attempt
        # key and its own child process: no cross-request interleaving.
        for sent_rec in sent:
            mine = [r for r in records if r["req_key"] == sent_rec["req_key"]]
            assert {r["pid"] for r in mine} == {sent_rec["pid"]}
            assert {r["stage"] for r in mine} == {
                "initialize",
                "session_new_or_resume",
                "prompt_sent",
                "first_update",
                "prompt_response",
            }
        _assert_no_leaks(
            (tmp_path / "trace.jsonl").read_text(encoding="utf-8"), tmp_path, records
        )
    finally:
        client_a.close()
        client_b.close()


# ---------------------------------------------------------------------------
# 6. Disabled tracing produces no trace output
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 5b. Same-instance request correlation (independent review, item 1)
# ---------------------------------------------------------------------------


def test_same_client_sequential_calls_get_distinct_request_keys(
    monkeypatch, tmp_path,
):
    """Two completion calls on ONE client instance must not share a request key.

    The client is explicitly reusable (warm session reuse, cancel-epoch
    semantics), so grouping two calls under one correlation key would mix
    their events and let one request's event budget consume another's.
    """
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client, _ = _make_client(module, tmp_path, "normal")
    try:
        first, _ = client._run_prompt("first call", timeout_seconds=20.0)
        second, _ = client._run_prompt("second call", timeout_seconds=20.0)
    finally:
        client.close()
    assert first == "done" and second == "done"
    records = _read_trace(tmp_path / "trace.jsonl", trace_module)
    sent = [r for r in records if r["stage"] == "prompt_sent"]
    responses = [r for r in records if r["stage"] == "prompt_response"]
    assert len(sent) == 2 and len(responses) == 2
    request_keys = [r["detail"]["request_key"] for r in sent]
    assert all(k and k != "unknown" for k in request_keys), request_keys
    assert len(set(request_keys)) == 2, (
        "sequential calls on one client instance must carry distinct "
        f"request keys: {request_keys}"
    )
    # Attempt grouping stays exact: each call's attempt key appears once in
    # prompt_sent and once in prompt_response, in call order.
    attempt_keys = [r["req_key"] for r in sent]
    assert len(set(attempt_keys)) == 2
    assert [r["req_key"] for r in responses] == attempt_keys
    # The handshake events join the request that caused them (first call
    # only, if the second call reused the warm session).
    inits = [r for r in records if r["stage"] == "initialize"]
    assert inits, "first call must record initialize"
    assert inits[0]["detail"]["request_key"] == request_keys[0]
    for init in inits[1:]:
        assert init["detail"]["request_key"] in request_keys
    _assert_no_leaks(
        (tmp_path / "trace.jsonl").read_text(encoding="utf-8"), tmp_path, records
    )


def test_adversarial_stop_reason_recorded_as_unrecognized(monkeypatch, tmp_path):
    """A hostile stopReason string must never enter the trace verbatim."""
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client, _ = _make_client(module, tmp_path, "hostile")
    try:
        answer, _ = client._run_prompt("hello", timeout_seconds=20.0)
    finally:
        client.close()
    assert answer == "done"
    records = _read_trace(tmp_path / "trace.jsonl", trace_module)
    responses = [r for r in records if r["stage"] == "prompt_response"]
    assert len(responses) == 1
    assert responses[0]["detail"]["stop_reason"] == "unrecognized"
    text = (tmp_path / "trace.jsonl").read_text(encoding="utf-8")
    assert HOSTILE_STOP_REASON not in text
    assert "IGNORE-PREVIOUS-INSTRUCTIONS" not in text
    assert "sk-SECRET-STOPREASON-9137" not in text
    _assert_no_leaks(text, tmp_path, records)


def test_prompt_text_bytes_counts_utf8_bytes(monkeypatch, tmp_path):
    """prompt_text_bytes is the UTF-8 encoded length, not code points."""
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client, _ = _make_client(module, tmp_path, "normal")
    try:
        client._run_prompt("abcd", timeout_seconds=20.0)
        client._run_prompt("한글입니다", timeout_seconds=20.0)
    finally:
        client.close()
    records = _read_trace(tmp_path / "trace.jsonl", trace_module)
    sent = [r for r in records if r["stage"] == "prompt_sent"]
    assert len(sent) == 2
    assert sent[0]["detail"]["prompt_text_bytes"] == len(
        "abcd".encode("utf-8")
    )
    assert sent[1]["detail"]["prompt_text_bytes"] == len(
        "한글입니다".encode("utf-8")
    )
    assert sent[1]["detail"]["prompt_text_bytes"] == 15  # 5 × 3-byte Hangul
    _assert_no_leaks(
        (tmp_path / "trace.jsonl").read_text(encoding="utf-8"), tmp_path, records
    )


# ---------------------------------------------------------------------------
# 5c. Model-id surface gate (independent re-review: credential-shaped ids)
# ---------------------------------------------------------------------------


HOSTILE_MODEL_UUID = "123e4567-e89b-12d3-a456-426614174000"
HOSTILE_MODEL_KEY = "sk-1234567890abcdef"


def test_model_surface_gate_never_echoes_credential_shapes(monkeypatch, tmp_path):
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    hostile = [
        HOSTILE_MODEL_UUID,
        "ya29.a0AbCDefGhiJkLm",
        HOSTILE_MODEL_KEY,
        "AIzaSyDxTestKeyThatIsLongEnoughXx",
        "a" * 40,
    ]
    token = client_module._TRACE_REQUEST_KEY.set("request-scope-one")
    try:
        classified = [client_module._classify_model_surface(v) for v in hostile]
        same_again = client_module._classify_model_surface(HOSTILE_MODEL_UUID)
    finally:
        client_module._TRACE_REQUEST_KEY.reset(token)
    for value, out in zip(hostile, classified):
        assert value not in out, out
        assert out not in ("", "unreported")
    # Requested-vs-effective comparison survives inside one request scope:
    # equal inputs hash equal, different inputs hash different.
    assert same_again == classified[0]
    assert classified[0] != classified[2]
    # The fingerprint is request-scoped: the same hostile value in another
    # request scope must not be linkable across requests.
    token2 = client_module._TRACE_REQUEST_KEY.set("request-scope-two")
    try:
        other_scope = client_module._classify_model_surface(HOSTILE_MODEL_UUID)
    finally:
        client_module._TRACE_REQUEST_KEY.reset(token2)
    assert other_scope != classified[0]
    # Ordinary model names stay verbatim: the substitution-comparison feature
    # is preserved for the normal path.
    assert (
        client_module._classify_model_surface("fake-model-b-high")
        == "fake-model-b-high"
    )
    assert (
        client_module._classify_model_surface("claude-sonnet-4-20250514")
        == "claude-sonnet-4-20250514"
    )
    # Outside any request scope there is no comparable identity to offer.
    assert (
        client_module._classify_model_surface(HOSTILE_MODEL_KEY) == "unrecognized"
    )


def test_hostile_model_ids_never_recorded_verbatim(monkeypatch, tmp_path):
    """UUID-shaped server currentValue + caller-supplied API-key-shaped model."""
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    client, _ = _make_client(module, tmp_path, "hostile_model")
    try:
        answer, _ = client._run_prompt(
            "hello", timeout_seconds=20.0, model=HOSTILE_MODEL_KEY
        )
    finally:
        client.close()
    assert answer == "done"
    records = _read_trace(tmp_path / "trace.jsonl", trace_module)
    sent = [r for r in records if r["stage"] == "prompt_sent"]
    assert len(sent) == 1
    detail = sent[0]["detail"]
    assert detail["requested_model"] != HOSTILE_MODEL_KEY
    assert detail["effective_model"] != HOSTILE_MODEL_UUID
    assert detail["requested_model"] != detail["effective_model"]
    text = (tmp_path / "trace.jsonl").read_text(encoding="utf-8")
    assert HOSTILE_MODEL_KEY not in text
    assert HOSTILE_MODEL_UUID not in text
    assert "426614174000" not in text
    assert "ya29." not in text
    _assert_no_leaks(text, tmp_path, records)


def test_disabled_by_default_produces_no_file(monkeypatch, tmp_path):
    module, client_module, trace_module, bridge_module = _load_plugin(
        monkeypatch, tmp_path, trace=False
    )
    assert trace_module.get_tracer() is None
    client, _ = _make_client(module, tmp_path, "normal")
    assert client._trace is None
    try:
        answer, _ = client._run_prompt("hello", timeout_seconds=20.0)
    finally:
        client.close()
    assert answer == "done"
    assert not (tmp_path / "trace.jsonl").exists()
    assert not any(tmp_path.glob("*.jsonl")) or all(
        "fake-events" in path.name for path in tmp_path.glob("*.jsonl")
    )


# ---------------------------------------------------------------------------
# 7. Event count, file size, and retention remain bounded
# ---------------------------------------------------------------------------


def test_bounded_events_rotation_and_retention(monkeypatch, tmp_path):
    module, client_module, trace_module, bridge_module = _load_plugin(monkeypatch, tmp_path, trace=True)
    path = tmp_path / "bounded.jsonl"
    tracer = trace_module.StageTracer(
        path, max_file_bytes=1_500, max_events_per_request=5
    )
    for _ in range(100):
        tracer.emit(stage="prompt_sent", req_key="one-key")
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 6, "5 events + exactly one truncation marker"
    records = [json.loads(line) for line in lines]
    assert records[-1]["detail"]["classification"] == "trace_truncated"
    assert all(r["req_key"] == "one-key" for r in records)
    for index in range(400):
        tracer.emit(stage="prompt_sent", req_key=f"key-{index}", detail={"i": index})
    rotated = tmp_path / "bounded.jsonl.1"
    assert rotated.exists(), "size rotation must have happened"
    assert path.stat().st_size <= 1_500 + 400
    assert rotated.stat().st_size <= 1_500 + 400, "retention is ONE rotated file"
    for line in path.read_text(encoding="utf-8").splitlines():
        json.loads(line)
    # A detail carrying a structured value is redacted, never serialized.
    tracer2 = trace_module.StageTracer(tmp_path / "sanitize.jsonl")
    tracer2.emit(
        stage="prompt_sent",
        req_key="k",
        detail={"nested": {"secret": "x"}, "long": "y" * 500},
    )
    record = json.loads((tmp_path / "sanitize.jsonl").read_text(encoding="utf-8"))
    assert record["detail"]["nested"] == "redacted"
    assert len(record["detail"]["long"]) <= 160


# ---------------------------------------------------------------------------
# 8. No sensitive text or raw identifiers leak into logs
#    (leak assertions run inside tests 1-5; this pins the mux half)
# ---------------------------------------------------------------------------


def test_mux_trace_lane_fingerprint_and_exit(monkeypatch, tmp_path):
    fake = tmp_path / "fake_acp.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':request.get('id'),'result':{'ok':True}}), flush=True)\n"
    )
    fake.chmod(0o755)
    home = tmp_path / "account-home"
    home.mkdir()
    registry = tmp_path / "accounts.json"
    registry.write_text(
        json.dumps(
            {"accounts": [{"home": str(home), "label": SECRET_LABEL, "priority": 0}]}
        )
    )
    trace_path = tmp_path / "mux-trace.jsonl"
    proc_env = os.environ.copy()
    proc_env.update(
        {
            "ACP_MUX_ACCOUNTS": str(registry),
            "ACP_MUX_STATE": str(tmp_path / "state.json"),
            "ACP_MUX_LOG": str(tmp_path / "mux.log"),
            "ACP_MUX_PAR": str(fake),
            "ACP_MUX_TRACE": "1",
            "ACP_MUX_TRACE_FILE": str(trace_path),
            "HOME": str(tmp_path),
            "HERMES_REAL_HOME": str(tmp_path),
            "HERMES_HOME": str(tmp_path / ".hermes"),
        }
    )
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
    mux_proc = subprocess.Popen(
        [sys.executable, str(MUX_ENTRYPOINT)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=proc_env,
    )
    try:
        stdout, stderr = mux_proc.communicate(request, timeout=20)
    finally:
        if mux_proc.poll() is None:
            mux_proc.kill()
    completed = subprocess.CompletedProcess(
        args=[sys.executable, str(MUX_ENTRYPOINT)],
        returncode=mux_proc.returncode,
        stdout=stdout,
        stderr=stderr,
    )
    completed.pid = mux_proc.pid
    assert completed.returncode == 0, completed.stderr
    records = [
        json.loads(line)
        for line in trace_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    stages = [record["stage"] for record in records]
    assert stages == ["lane_bound", "process_exit"], stages
    lane_bound, process_exit = records
    assert lane_bound["mux_pid"] == completed.pid
    assert lane_bound["child_pid"] > 0
    assert process_exit["mux_pid"] == completed.pid
    assert process_exit["child_pid"] == lane_bound["child_pid"]
    assert isinstance(process_exit["exit_code"], int)
    # The join primitive is the fingerprint; the raw label never appears.
    spec = importlib.util.spec_from_file_location("acp_mux_trace_probe", MUX_ENTRYPOINT)
    assert spec is not None and spec.loader is not None
    acp_mux = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acp_mux)
    assert lane_bound["lane"] == acp_mux._lane_fingerprint(str(home), SECRET_LABEL)
    assert len(lane_bound["lane"]) == 12
    text = trace_path.read_text(encoding="utf-8")
    assert SECRET_LABEL not in text
    assert str(home) not in text
    assert str(tmp_path) not in text


def test_mux_trace_disabled_by_default(monkeypatch, tmp_path):
    fake = tmp_path / "fake_acp.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    request = json.loads(line)\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':request.get('id'),'result':{'ok':True}}), flush=True)\n"
    )
    fake.chmod(0o755)
    home = tmp_path / "account-home"
    home.mkdir()
    registry = tmp_path / "accounts.json"
    registry.write_text(
        json.dumps({"accounts": [{"home": str(home), "label": "l", "priority": 0}]})
    )
    proc_env = os.environ.copy()
    proc_env.update(
        {
            "ACP_MUX_ACCOUNTS": str(registry),
            "ACP_MUX_STATE": str(tmp_path / "state.json"),
            "ACP_MUX_LOG": str(tmp_path / "mux.log"),
            "ACP_MUX_PAR": str(fake),
            "HOME": str(tmp_path),
            "HERMES_REAL_HOME": str(tmp_path),
            "HERMES_HOME": str(tmp_path / ".hermes"),
        }
    )
    proc_env.pop("ACP_MUX_TRACE", None)
    proc_env.pop("ACP_MUX_TRACE_FILE", None)
    completed = subprocess.run(
        [sys.executable, str(MUX_ENTRYPOINT)],
        input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n",
        text=True,
        capture_output=True,
        env=proc_env,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert not (tmp_path / "mux-trace.jsonl").exists()
    assert not (tmp_path / ".hermes").exists() or not any(
        (tmp_path / ".hermes").rglob("acp-mux-trace.jsonl")
    )
