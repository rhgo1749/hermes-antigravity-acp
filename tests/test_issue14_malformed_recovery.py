"""Issue #14: bounded same-session recovery for malformed tool calls.

The read-evidence correction path previously let ``MalformedToolCallError``
escape ``chat.completions.create`` while the primary extraction path already
corrected the same error class in-session.  These tests pin the shared,
bounded recovery contract:

- only recoverable ``MalformedToolCallError`` enters the correction path;
- at most two additional generations per failed tool-call generation,
  composed across the primary and read-evidence paths (request-wide cap 2);
- regeneration resumes the same ACP session, never a silent new session;
- invalid calls are never dispatched and never re-appear alongside the
  regenerated call;
- permission denials, unadvertised tools, and arbitrary exceptions are not
  JSON-correction events.
"""

from __future__ import annotations

import json
import sys

import pytest

from test_standalone_client import _load, _tool_schema

_REVIEW_MESSAGE = {
    "role": "user",
    "content": (
        "Read-only independent review. MUST inspect actual git diff and actual "
        "source/test/doc files. Report blocking findings with exact file/line "
        "plus actual tool-read evidence."
    ),
}


def _malformed_call(name: str = "read_file", call_id: str = "call-bad") -> str:
    # function.arguments is missing its closing brace: json.loads fails inside
    # bridge._parse_tool_call, raising a recoverable MalformedToolCallError.
    return (
        "<tool_call>"
        + json.dumps(
            {
                "id": call_id,
                "type": "function",
                "function": {"name": name, "arguments": '{"path": "router.py"'},
            }
        )
        + "</tool_call>"
    )


def _valid_call(
    name: str = "read_file", call_id: str = "call-good", path: str = "router.py"
) -> str:
    return (
        "<tool_call>"
        + json.dumps(
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": json.dumps({"path": path}),
                },
            }
        )
        + "</tool_call>"
    )


def _fake_run_prompt(client, monkeypatch, responses):
    """Queue scripted responses; record every generation turn."""
    turns: list[dict] = []

    def fake_run_prompt(prompt_text, **kwargs):
        turns.append(
            {
                "prompt": prompt_text,
                "resume": kwargs["resume_session_id"],
                "full": kwargs["full_prompt_text"],
            }
        )
        kwargs["session_result"].update(
            session_id="session-re",
            resumed=bool(kwargs["resume_session_id"]),
            native_activity={"native_tool_calls": []},
        )
        return responses[len(turns) - 1], ""

    monkeypatch.setattr(client, "_run_prompt", fake_run_prompt)
    return turns


def _create(client, tools=None):
    return client.chat.completions.create(
        model="gemini-3.8-flash-high",
        messages=[_REVIEW_MESSAGE],
        tools=tools or [_tool_schema("read_file")],
    )


def test_malformed_in_read_evidence_correction_recovers_in_same_session(monkeypatch) -> None:
    """One malformed read-evidence turn recovers with one same-session regeneration."""
    _, client, _ = _load(monkeypatch)
    turns = _fake_run_prompt(
        client,
        monkeypatch,
        [
            "I inspected router.py:42 and found a race.",  # ungrounded -> gate
            _malformed_call(),  # malformed inside read-evidence correction
            _valid_call(),  # regenerated
        ],
    )

    completion = _create(client)

    assert len(turns) == 3
    assert turns[2]["resume"] == "session-re"
    assert "malformed JSON" in turns[2]["prompt"]
    assert "Previous malformed model output (not executed)" in turns[2]["full"]
    tool_call = completion.choices[0].message.tool_calls[0]
    assert tool_call.function.name == "read_file"
    assert tool_call.id == "call-good"


def test_two_malformed_read_evidence_turns_recover_on_third_generation(monkeypatch) -> None:
    """Two malformed generations recover on the third (initial + 2 corrections)."""
    _, client, _ = _load(monkeypatch)
    turns = _fake_run_prompt(
        client,
        monkeypatch,
        [
            "I inspected router.py:42 and found a race.",
            _malformed_call(call_id="call-bad-1"),
            _malformed_call(call_id="call-bad-2"),
            _valid_call(),
        ],
    )

    completion = _create(client)

    assert len(turns) == 4
    assert turns[2]["resume"] == "session-re"
    assert turns[3]["resume"] == "session-re"
    assert completion.choices[0].message.tool_calls[0].id == "call-good"


def test_third_consecutive_malformed_read_evidence_turn_terminates_bounded(monkeypatch) -> None:
    """Initial + 2 corrections all malformed -> bounded, identifiable failure."""
    _, client, _ = _load(monkeypatch)
    turns = _fake_run_prompt(
        client,
        monkeypatch,
        [
            "I inspected router.py:42 and found a race.",
            _malformed_call(call_id="call-bad-1"),
            _malformed_call(call_id="call-bad-2"),
            _malformed_call(call_id="call-bad-3"),
        ],
    )

    with pytest.raises(RuntimeError, match="malformed Hermes tool-call JSON again"):
        _create(client)

    # 1 ungrounded + 1 malformed + 2 corrections; no fourth generation.
    assert len(turns) == 4


def test_primary_and_read_evidence_share_one_malformed_budget(monkeypatch) -> None:
    """A correction spent in the primary path shrinks the read-evidence budget."""
    _, client, _ = _load(monkeypatch)
    turns = _fake_run_prompt(
        client,
        monkeypatch,
        [
            _malformed_call(name="terminal", call_id="call-bad-1"),  # primary fails
            _valid_call(name="terminal", call_id="call-term"),  # primary recovers (1 spent)
            _malformed_call(call_id="call-bad-2"),  # read-evidence turn malformed
            _malformed_call(call_id="call-bad-3"),  # only 1 budget left -> terminate
        ],
    )

    with pytest.raises(RuntimeError, match="malformed Hermes tool-call JSON again"):
        _create(client, tools=[_tool_schema("read_file"), _tool_schema("terminal")])

    # No fifth generation: read-evidence did not get a fresh 2-correction budget.
    assert len(turns) == 4


def test_mixed_valid_and_invalid_calls_never_double_dispatch(monkeypatch) -> None:
    """A mixed valid+invalid response is never dispatched; only the regenerated call is returned."""
    _, client, _ = _load(monkeypatch)
    mixed = _valid_call(call_id="call-first") + "\n" + _malformed_call(call_id="call-bad")
    turns = _fake_run_prompt(
        client,
        monkeypatch,
        [
            "I inspected router.py:42 and found a race.",
            mixed,  # valid call never dispatched alongside the invalid one
            _valid_call(call_id="call-regen"),
        ],
    )

    completion = _create(client)

    assert len(turns) == 3
    tool_calls = completion.choices[0].message.tool_calls
    assert [call.id for call in tool_calls] == ["call-regen"]


def test_malformed_recovery_without_session_id_fails_closed(monkeypatch) -> None:
    """No confirmed session continuity -> explicit error, no new session opened."""
    _, client, _ = _load(monkeypatch)
    turns: list[dict] = []

    def fake_run_prompt(prompt_text, **kwargs):
        turns.append(prompt_text)
        kwargs["session_result"].update(
            session_id="",  # session identity lost
            native_activity={"native_tool_calls": []},
        )
        if len(turns) == 1:
            return "I inspected router.py:42 and found a race.", ""
        return _malformed_call(), ""

    monkeypatch.setattr(client, "_run_prompt", fake_run_prompt)

    with pytest.raises(RuntimeError, match="session"):
        _create(client)

    # The malformed generation is the last one; no regeneration was attempted.
    assert len(turns) == 2


def test_arbitrary_exception_in_read_evidence_is_not_retried(monkeypatch) -> None:
    """Non-malformed exceptions (e.g. permission policy) bypass the correction path."""
    module, client, client_module = _load(monkeypatch)
    real_extract = client_module._extract_advertised_tool_calls

    def flaky_extract(text, tools):
        if "DENIED" in text:
            raise ValueError("permission denied by native tool policy")
        return real_extract(text, tools)

    monkeypatch.setattr(client_module, "_extract_advertised_tool_calls", flaky_extract)
    turns = _fake_run_prompt(
        client,
        monkeypatch,
        [
            "I inspected router.py:42 and found a race.",
            "DENIED",
            _valid_call(),  # must never be reached
        ],
    )

    with pytest.raises(ValueError, match="permission denied"):
        _create(client)

    assert len(turns) == 2


def test_unadvertised_tool_in_read_evidence_fails_closed_without_correction(monkeypatch) -> None:
    """Unrecoverable MalformedToolCallError stays a hard failure, not a correction event."""
    _, client, _ = _load(monkeypatch)
    turns = _fake_run_prompt(
        client,
        monkeypatch,
        [
            "I inspected router.py:42 and found a race.",
            _valid_call(name="rm_rf", call_id="call-evil"),
            _valid_call(),  # must never be reached
        ],
    )

    with pytest.raises(RuntimeError, match="unadvertised"):
        _create(client)

    assert len(turns) == 2


# --- P1 rework (independent review of PR #29): strict same-session transport ---
#
# The malformed regeneration inside _extract_with_malformed_recovery must never
# let _run_prompt's transport fall back to a resume-miss full replay or a
# fresh-session failover, and must reject a response that reports a different
# session id than the pinned one.  The ordinary conversation transport policy
# must stay byte-identical.


def _strict_transport(monkeypatch, client, fake_once):
    attempts: list[dict] = []

    def recording_once(prompt_text, **kwargs):
        attempts.append(
            {"resume": kwargs["resume_session_id"], "prompt": prompt_text}
        )
        return fake_once(prompt_text, attempts=len(attempts), **kwargs)

    monkeypatch.setattr(client, "_run_prompt_once", recording_once)
    return attempts


def test_strict_same_session_blocks_resume_miss_replay(monkeypatch) -> None:
    """A resume miss during malformed regeneration refuses, never replays."""
    _, client, _ = _load(monkeypatch)

    def resume_miss(prompt_text, *, attempts, **kwargs):
        raise RuntimeError("session not found: durable-session")

    calls = _strict_transport(monkeypatch, client, resume_miss)

    with pytest.raises(RuntimeError, match="strict same-session"):
        client._run_prompt(
            "malformed correction delta",
            timeout_seconds=30,
            resume_session_id="durable-session",
            full_prompt_text="full original prompt",
            session_result={},
            strict_same_session=True,
        )

    # Exactly one wire attempt: no fresh-session full replay was issued.
    assert len(calls) == 1


def test_strict_same_session_blocks_rate_limit_failover(monkeypatch) -> None:
    """A failover-eligible error during malformed regeneration never rotates."""
    _, client, _ = _load(monkeypatch)

    def rate_limited(prompt_text, *, attempts, **kwargs):
        raise RuntimeError("429 too many requests")

    calls = _strict_transport(monkeypatch, client, rate_limited)

    with pytest.raises(RuntimeError, match="strict same-session"):
        client._run_prompt(
            "malformed correction delta",
            timeout_seconds=30,
            resume_session_id="durable-session",
            full_prompt_text="full original prompt",
            session_result={},
            strict_same_session=True,
        )

    # Exactly one wire attempt: no fresh-session failover was issued.
    assert len(calls) == 1


def test_strict_same_session_rejects_unconfirmed_session_id(monkeypatch) -> None:
    """A response reported by a different session id than pinned is refused."""
    _, client, _ = _load(monkeypatch)

    def wrong_session(prompt_text, *, attempts, **kwargs):
        kwargs["session_result"].update(session_id="other-session", resumed=False)
        return _valid_call(), ""

    calls = _strict_transport(monkeypatch, client, wrong_session)

    with pytest.raises(RuntimeError, match="strict same-session"):
        client._run_prompt(
            "malformed correction delta",
            timeout_seconds=30,
            resume_session_id="durable-session",
            full_prompt_text="full original prompt",
            session_result={},
            strict_same_session=True,
        )

    assert len(calls) == 1


def test_strict_same_session_happy_path_returns_pinned_session(monkeypatch) -> None:
    """Same-session regeneration succeeds when the server confirms the pinned id."""
    _, client, _ = _load(monkeypatch)

    def same_session(prompt_text, *, attempts, **kwargs):
        kwargs["session_result"].update(session_id="durable-session", resumed=True)
        return _valid_call(), ""

    calls = _strict_transport(monkeypatch, client, same_session)

    answer, _reasoning = client._run_prompt(
        "malformed correction delta",
        timeout_seconds=30,
        resume_session_id="durable-session",
        full_prompt_text="full original prompt",
        session_result={},
        strict_same_session=True,
    )

    assert answer == _valid_call()
    assert len(calls) == 1


def test_normal_conversation_resume_miss_replay_policy_unchanged(monkeypatch) -> None:
    """Sibling non-strict traffic keeps the existing resume-miss full replay."""
    _, client, _ = _load(monkeypatch)

    def miss_then_rebuild(prompt_text, *, attempts, **kwargs):
        if attempts == 1:
            raise RuntimeError("session not found: durable-session")
        kwargs["session_result"].update(session_id="fresh-session", resumed=False)
        return "rebuilt answer", ""

    calls = _strict_transport(monkeypatch, client, miss_then_rebuild)

    answer, _reasoning = client._run_prompt(
        "delta text",
        timeout_seconds=30,
        resume_session_id="durable-session",
        full_prompt_text="full replay text",
        session_result={},
    )

    assert answer == "rebuilt answer"
    assert len(calls) == 2
    assert calls[1]["resume"] == ""
    assert calls[1]["prompt"] == "full replay text"


def test_normal_conversation_rate_limit_failover_policy_unchanged(monkeypatch) -> None:
    """Sibling non-strict traffic keeps the bounded fresh-session failover."""
    _, client, _ = _load(monkeypatch)

    def limited_then_ok(prompt_text, *, attempts, **kwargs):
        if attempts == 1:
            raise RuntimeError("429 too many requests")
        kwargs["session_result"].update(session_id="failover-session", resumed=False)
        return "failover answer", ""

    calls = _strict_transport(monkeypatch, client, limited_then_ok)

    answer, _reasoning = client._run_prompt(
        "delta text",
        timeout_seconds=30,
        resume_session_id="durable-session",
        full_prompt_text="full replay text",
        session_result={},
    )

    assert answer == "failover answer"
    assert len(calls) == 2
    assert calls[1]["resume"] == ""


def test_malformed_regeneration_requests_strict_same_session(monkeypatch) -> None:
    """Only the malformed regeneration turns pin strict mode; siblings do not."""
    _, client, _ = _load(monkeypatch)
    turns: list[dict] = []

    def fake_run_prompt(prompt_text, **kwargs):
        turns.append(
            {
                "prompt": prompt_text,
                "strict": bool(kwargs.get("strict_same_session", False)),
            }
        )
        kwargs["session_result"].update(
            session_id="session-re",
            resumed=bool(kwargs.get("resume_session_id")),
            native_activity={"native_tool_calls": []},
        )
        if len(turns) == 1:
            return "I inspected router.py:42 and found a race.", ""
        if len(turns) == 2:
            return _malformed_call(), ""
        return _valid_call(), ""

    monkeypatch.setattr(client, "_run_prompt", fake_run_prompt)

    _create(client)

    assert len(turns) == 3
    assert turns[0]["strict"] is False  # primary generation: existing policy
    assert turns[1]["strict"] is False  # read-evidence turn: existing policy
    assert turns[2]["strict"] is True  # malformed regeneration: pinned session


# --- P1 round 3 (independent re-review of PR #29): pre-prompt wire blocking ---
#
# The strict session-id equality check ran after _run_prompt_once() completed,
# but a session/resume response carrying a foreign sessionId would already
# have been used as the target of session/prompt inside that call.  Strict
# mode must block the mismatch at the resume response, before any prompt
# crosses the wire.  A resume response that legally omits sessionId (the ACP
# shape the repo's own fake servers emit) stays accepted via the pinned id.

_WIRE_FAKE_SERVER = r'''
import json
import os
import sys

log_path = sys.argv[1]
counter_path = sys.argv[2]

MODEL_CONFIG = {
    "configOptions": [{
        "id": "model",
        "category": "model",
        "currentValue": "gemini-3.1-pro",
        "options": [{"value": "gemini-3.1-pro"}],
    }],
}

MALFORMED = (
    "<tool_call>"
    + json.dumps({
        "id": "call-bad",
        "type": "function",
        "function": {"name": "read_state", "arguments": '{"path":"unterminated"'},
    })
    + "</tool_call>"
)
VALID = (
    "<tool_call>"
    + json.dumps({
        "id": "call-good",
        "type": "function",
        "function": {
            "name": "read_state",
            "arguments": json.dumps({"path": "x"}),
        },
    })
    + "</tool_call>"
)


def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def log(payload):
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")


def issued():
    try:
        n = int(open(counter_path, encoding="utf-8").read().strip())
    except (OSError, ValueError):
        n = 0
    n += 1
    with open(counter_path, "w", encoding="utf-8") as fh:
        fh.write(str(n))
    return f"wire-session-{os.getpid()}-{n}"


for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    params = msg.get("params") or {}
    row = {"id": msg.get("id"), "method": method, "params": params}
    if method == "initialize":
        log(row)
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/new":
        sid = issued()
        row["issued_session_id"] = sid
        log(row)
        emit({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"sessionId": sid, **MODEL_CONFIG},
        })
    elif method == "session/resume":
        row["resumed_session_id"] = str(params.get("sessionId") or "")
        log(row)
        result = dict(MODEL_CONFIG)
        if MODE == "wrong_id":
            # An explicitly different id is a protocol anomaly strict mode must
            # refuse; a legal omission is the else branch (no sessionId key).
            result["sessionId"] = "usurper-session-999"
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": result})
    elif method == "session/prompt":
        text = ((params.get("prompt") or [{}])[0].get("text") or "")
        log(row)
        response = VALID if "malformed JSON" in text else MALFORMED
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
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif msg.get("id") is not None:
        log(row)
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    else:
        log(row)
'''


def _write_wire_server(tmp_path, mode: str):
    script = tmp_path / "wire_acp_server.py"
    script.write_text(f"MODE = {mode!r}\n" + _WIRE_FAKE_SERVER, encoding="utf-8")
    return script


def _wire_client(module, tmp_path, mode: str):
    return module.antigravity_acp.create_client(
        command=sys.executable,
        args=[
            str(_write_wire_server(tmp_path, mode)),
            str(tmp_path / "wire_acp_log.jsonl"),
            str(tmp_path / "wire_counter"),
        ],
        acp_cwd=str(tmp_path),
        rate_limit_retries=0,
    )


def _wire_rows(tmp_path):
    log_path = tmp_path / "wire_acp_log.jsonl"
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]


def _wire_create(client):
    return client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=[{"role": "user", "content": "inspect state"}],
        tools=[_tool_schema()],
    )


def test_strict_regeneration_wire_never_prompts_foreign_session(monkeypatch, tmp_path) -> None:
    """A resume response with a foreign sessionId is refused before any prompt."""
    module, _, _ = _load(monkeypatch)
    client = _wire_client(module, tmp_path, "wrong_id")

    with pytest.raises(RuntimeError, match="strict same-session"):
        _wire_create(client)

    rows = _wire_rows(tmp_path)
    assert len([row for row in rows if row["method"] == "session/resume"]) == 1
    # The only prompt ever sent is the original malformed generation; the
    # strict regeneration was blocked before session/prompt crossed the wire.
    assert len([row for row in rows if row["method"] == "session/prompt"]) == 1


def test_strict_regeneration_wire_accepts_resume_omitting_session_id(monkeypatch, tmp_path) -> None:
    """The legal ACP resume shape without sessionId stays accepted via the pin."""
    module, _, _ = _load(monkeypatch)
    client = _wire_client(module, tmp_path, "omit_id")

    completion = _wire_create(client)

    assert completion.choices[0].message.tool_calls[0].id == "call-good"
    rows = _wire_rows(tmp_path)
    assert len([row for row in rows if row["method"] == "session/prompt"]) == 2
    assert len([row for row in rows if row["method"] == "session/resume"]) == 1
