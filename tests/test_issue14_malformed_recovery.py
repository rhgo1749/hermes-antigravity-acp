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
