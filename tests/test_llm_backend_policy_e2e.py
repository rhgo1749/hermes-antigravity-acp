"""historical reference: opt-in ``postprocessing_policy="llm_backend"`` E2E regressions.

All tests drive the real client against a fake ACP subprocess (no network,
no credentials, no live Antigravity). They pin the six acceptance-critical
behaviors:

- AC2: identical backend-mode requests never resume a prior native session
  (distinct issued session ids, zero conversation_registry traffic, no
  persisted state entries).
- AC3: an evidence/exact-file/line-phrased prompt with tools defined returns
  cleanly in backend mode (no review-evidence correction turns, no refusal).
- AC4: the same prompt under a default-instantiated client still raises the
  review-evidence refusal RuntimeError.
- AC6/security: malformed tool-call JSON in backend mode still fails closed
  within the same one-correction budget, while same-request correction keeps
  working; concurrent backend requests each get a fresh native session.
- Isolation: a default client and an opted-in client coexist in one process
  with no shared policy/session contamination (the default client keeps its
  registry resume path byte-for-byte).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

PLUGIN_DIR = (
    Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"
)


def _load_module(monkeypatch, tmp_path: Path):
    """Fresh plugin package import with isolated durable-state paths."""
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(tmp_path / "acp-conversation-state.json"),
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        str(tmp_path / "acp-limits.json"),
    )

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = lambda *_: None
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)

    module_name = "antigravity_acp_backend_policy"
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
    # create_client imports .client lazily; import it up-front so tests can
    # instrument the conversation_registry singleton before first use.
    client_module = importlib.import_module(module_name + ".client")
    return module, client_module


def _instrument_registry(client_module, monkeypatch):
    """Count every conversation_registry.get/.put reached from any client."""
    counters = {"get": 0, "put": 0}
    registry = client_module.conversation_registry
    orig_get, orig_put = registry.get, registry.put

    def counting_get(key):
        counters["get"] += 1
        return orig_get(key)

    def counting_put(key, state):
        counters["put"] += 1
        return orig_put(key, state)

    monkeypatch.setattr(registry, "get", counting_get)
    monkeypatch.setattr(registry, "put", counting_put)
    return counters


def _make_client(module, tmp_path: Path, *, postprocessing_policy: str | None = None):
    kwargs = {
        "command": sys.executable,
        "args": [
            str(tmp_path / "fake_acp_server.py"),
            str(tmp_path / "fake_acp_log.jsonl"),
            str(tmp_path / "fake_acp_counter"),
        ],
        "acp_cwd": str(tmp_path),
        "rate_limit_retries": 0,
    }
    if postprocessing_policy is not None:
        kwargs["postprocessing_policy"] = postprocessing_policy
    return module.antigravity_acp.create_client(**kwargs)


def _write_fake_server(tmp_path: Path, mode: str) -> tuple[Path, Path]:
    """Fake ACP server: unique issued session ids + scripted prompt modes.

    Modes:
      answer             plain text answer to any prompt
      malformed_always   malformed Hermes tool-call JSON for every prompt
      malformed_then_valid  malformed first, valid tool call after correction
      inspect_resume     tool call for 'inspect', 'done after tool result'
                         after a tool result (mirrors the default resume E2E)
    """
    script = tmp_path / "fake_acp_server.py"
    log_path = tmp_path / "fake_acp_log.jsonl"
    script.write_text(
        f"MODE = {mode!r}\n"
        + r'''
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
    row = {
        "affinity": os.environ.get("ACP_MUX_AFFINITY", ""),
        "mux_session_id": os.environ.get("ACP_MUX_SESSION_ID", ""),
        **payload,
    }
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def issued_session_id():
    # PID suffix keeps ids distinct across the per-request child processes
    # even if concurrent counter updates race.
    try:
        n = int(open(counter_path, encoding="utf-8").read().strip())
    except (OSError, ValueError):
        n = 0
    n += 1
    with open(counter_path, "w", encoding="utf-8") as fh:
        fh.write(str(n))
    return f"backend-session-{os.getpid()}-{n}"


for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    params = msg.get("params") or {}
    row = {"id": msg.get("id"), "method": method, "params": params}
    if method == "initialize":
        log(row)
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/new":
        session_id = issued_session_id()
        row["issued_session_id"] = session_id
        log(row)
        emit({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"sessionId": session_id, **MODEL_CONFIG},
        })
    elif method == "session/resume":
        row["resumed_session_id"] = str(params.get("sessionId") or "")
        log(row)
        # Report the current model so same-request correction can resolve the
        # effective model exactly like the official server does.
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {**MODEL_CONFIG}})
    elif method in ("session/set_config_option", "session/set_model"):
        log(row)
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/prompt":
        text = ((params.get("prompt") or [{}])[0].get("text") or "")
        log(row)
        if MODE == "malformed_always":
            response = MALFORMED
        elif MODE == "malformed_then_valid":
            # The in-session correction turn sends the short correction
            # instruction as the prompt block; it mentions malformed JSON.
            response = (
                VALID if "malformed JSON" in text else MALFORMED
            )
        elif MODE == "inspect_resume":
            if "<tool_response>" in text:
                response = "done after tool result"
            elif (
                "inspect" in text
                and "exact file/line" not in text
                and "auditable inspection" not in text
            ):
                response = VALID
            else:
                response = "backend answer: all clear."
        else:
            response = "backend answer: all clear."
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
'''.lstrip(),
        encoding="utf-8",
    )
    return script, log_path


def _rows(log_path: Path) -> list[dict]:
    return [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]


def _tool_schema():
    return {
        "type": "function",
        "function": {
            "name": "read_state",
            "description": "Read state",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        },
    }


# Prompt shape from the live Honcho fallback traces: read-evidence review
# vocabulary plus advertised tools. "exact file/line" is in the explicit
# trip list of _requires_auditable_read_evidence.
EVIDENCE_PROMPT = (
    "Review this pull request. Report exact file/line evidence for every "
    "finding, with the actual source/test/doc you inspected."
)


def test_backend_policy_is_opt_in_and_fail_closed_on_typo(monkeypatch, tmp_path) -> None:
    module, client_module = _load_module(monkeypatch, tmp_path)
    assert client_module.POSTPROCESSING_POLICY_AGENT == "agent"
    assert client_module.POSTPROCESSING_POLICY_LLM_BACKEND == "llm_backend"
    default_client = module.antigravity_acp.create_client(
        command=sys.executable, args=[], acp_cwd=str(tmp_path)
    )
    assert default_client.postprocessing_policy == "agent"
    assert default_client._llm_backend_postprocessing is False
    with pytest.raises(ValueError, match="postprocessing_policy must be one of"):
        module.antigravity_acp.create_client(
            command=sys.executable,
            args=[],
            acp_cwd=str(tmp_path),
            postprocessing_policy="llm-backend",
        )


def test_backend_mode_identical_requests_use_distinct_fresh_sessions(
    monkeypatch, tmp_path
) -> None:
    """AC2: no cross-request affinity; fresh native session per backend call."""
    _write_fake_server(tmp_path, "answer")
    module, client_module = _load_module(monkeypatch, tmp_path)
    counters = _instrument_registry(client_module, monkeypatch)
    client = _make_client(module, tmp_path, postprocessing_policy="llm_backend")

    messages = [{"role": "user", "content": "summarize this note"}]
    first = client.chat.completions.create(model="gemini-3.1-pro", messages=messages)
    second = client.chat.completions.create(model="gemini-3.1-pro", messages=messages)

    assert first.choices[0].message.content == "backend answer: all clear."
    assert second.choices[0].message.content == "backend answer: all clear."
    assert first.model == "gemini-3.1-pro"
    assert second.usage is None

    issued = first.antigravity_usage_telemetry["native_session_id_hash"]
    assert issued
    assert (
        second.antigravity_usage_telemetry["native_session_id_hash"] != issued
    ), "identical backend requests must not resume the prior native session"

    rows = _rows(tmp_path / "fake_acp_log.jsonl")
    assert not [row for row in rows if row["method"] == "session/resume"]
    session_news = [row for row in rows if row["method"] == "session/new"]
    assert len(session_news) == 2
    assert session_news[0]["issued_session_id"] != session_news[1]["issued_session_id"]
    assert all(row["affinity"] == "" for row in rows), (
        "backend requests must never set ACP_MUX_AFFINITY"
    )
    assert counters == {"get": 0, "put": 0}, (
        "backend path must not touch conversation_registry at all"
    )
    assert not (tmp_path / "acp-conversation-state.json").exists(), (
        "backend traffic must not persist any conversation state entries"
    )


def test_backend_mode_evidence_phrased_prompt_with_tools_succeeds(
    monkeypatch, tmp_path
) -> None:
    """AC3: Honcho-style review phrasing + tools never trips the review guard."""
    _write_fake_server(tmp_path, "answer")
    module, _ = _load_module(monkeypatch, tmp_path)
    client = _make_client(module, tmp_path, postprocessing_policy="llm_backend")

    completion = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=[{"role": "user", "content": EVIDENCE_PROMPT}],
        tools=[_tool_schema()],
    )
    assert completion.choices[0].message.content == "backend answer: all clear."
    assert completion.choices[0].finish_reason == "stop"
    assert not completion.choices[0].message.tool_calls

    rows = _rows(tmp_path / "fake_acp_log.jsonl")
    prompts = [row for row in rows if row["method"] == "session/prompt"]
    assert len(prompts) == 1, "backend mode must not add review-evidence correction turns"
    assert EVIDENCE_PROMPT in prompts[0]["params"]["prompt"][0]["text"]


def test_default_mode_same_evidence_prompt_still_refuses_without_read_evidence(
    monkeypatch, tmp_path
) -> None:
    """AC4: the identical prompt under a default client keeps the refusal.

    Mirrors the guard contract pinned by tests/test_evidence_gate_summarizer_skip.py,
    end-to-end: one read-evidence correction turn, then the refusal RuntimeError
    from the review-evidence gate in _create_chat_completion.
    """
    _write_fake_server(tmp_path, "answer")
    module, client_module = _load_module(monkeypatch, tmp_path)
    counters = _instrument_registry(client_module, monkeypatch)
    default_client = _make_client(module, tmp_path)

    with pytest.raises(
        RuntimeError, match="refused to provide the auditable source-read evidence"
    ):
        default_client.chat.completions.create(
            model="gemini-3.1-pro",
            messages=[{"role": "user", "content": EVIDENCE_PROMPT}],
            tools=[_tool_schema()],
        )

    rows = _rows(tmp_path / "fake_acp_log.jsonl")
    prompts = [row for row in rows if row["method"] == "session/prompt"]
    assert len(prompts) == 2, (
        "default mode must keep the guard and request exactly one evidence correction"
    )
    # The refusal happens before any registry put; the evidence correction's
    # in-session resume may still read persisted state for model attribution.
    assert counters["get"] >= 1 and counters["put"] == 0


def test_backend_mode_malformed_tool_call_json_still_fails_closed(
    monkeypatch, tmp_path
) -> None:
    """AC6/security: malformed tool-call JSON stays fail-closed in backend mode."""
    _write_fake_server(tmp_path, "malformed_always")
    module, client_module = _load_module(monkeypatch, tmp_path)
    counters = _instrument_registry(client_module, monkeypatch)
    client = _make_client(module, tmp_path, postprocessing_policy="llm_backend")

    with pytest.raises(
        RuntimeError, match="malformed Hermes tool-call JSON again after one correction"
    ):
        client.chat.completions.create(
            model="gemini-3.1-pro",
            messages=[{"role": "user", "content": "inspect state"}],
            tools=[_tool_schema()],
        )

    rows = _rows(tmp_path / "fake_acp_log.jsonl")
    prompts = [row for row in rows if row["method"] == "session/prompt"]
    assert len(prompts) == 2, (
        "backend mode must use the exact same one-correction fail-closed budget"
    )
    assert counters == {"get": 0, "put": 0}


def test_backend_mode_same_request_correction_still_works(monkeypatch, tmp_path) -> None:
    """Malformed-then-valid stays functional within one backend request."""
    _write_fake_server(tmp_path, "malformed_then_valid")
    module, client_module = _load_module(monkeypatch, tmp_path)
    counters = _instrument_registry(client_module, monkeypatch)
    client = _make_client(module, tmp_path, postprocessing_policy="llm_backend")

    completion = client.chat.completions.create(
        model="gemini-3.1-pro",
        messages=[{"role": "user", "content": "inspect state"}],
        tools=[_tool_schema()],
    )
    tool_call = completion.choices[0].message.tool_calls[0]
    assert tool_call.id == "call-good"
    assert tool_call.function.name == "read_state"
    assert json.loads(tool_call.function.arguments) == {"path": "x"}
    assert completion.choices[0].finish_reason == "tool_calls"

    rows = _rows(tmp_path / "fake_acp_log.jsonl")
    assert len([row for row in rows if row["method"] == "session/prompt"]) == 2
    resumes = [row for row in rows if row["method"] == "session/resume"]
    assert len(resumes) == 1, "same-request correction must resume the native session"
    assert resumes[0]["resumed_session_id"] == next(
        row["issued_session_id"] for row in rows if row["method"] == "session/new"
    )
    assert counters == {"get": 0, "put": 0}


def test_mixed_default_and_backend_clients_do_not_contaminate_each_other(
    monkeypatch, tmp_path
) -> None:
    """One process, two clients: default keeps resume/registry; backend never does."""
    _write_fake_server(tmp_path, "inspect_resume")
    module, client_module = _load_module(monkeypatch, tmp_path)
    counters = _instrument_registry(client_module, monkeypatch)
    default_client = _make_client(module, tmp_path)
    backend_client = _make_client(module, tmp_path, postprocessing_policy="llm_backend")

    tools = [_tool_schema()]
    first_messages = [{"role": "user", "content": "inspect"}]
    default_first = default_client.chat.completions.create(
        model="gemini-3.1-pro", messages=first_messages, tools=tools
    )
    call = default_first.choices[0].message.tool_calls[0]
    default_session = next(
        row["issued_session_id"]
        for row in _rows(tmp_path / "fake_acp_log.jsonl")
        if row["method"] == "session/new"
    )

    backend_messages = [{"role": "user", "content": "plain inference turn"}]
    backend_first = backend_client.chat.completions.create(
        model="gemini-3.1-pro", messages=backend_messages
    )
    assert backend_first.choices[0].message.content == "backend answer: all clear."
    # The backend request touched nothing the default client relies on.
    assert counters == {"get": 1, "put": 1}

    second_messages = [
        *first_messages,
        {
            "role": "assistant",
            "content": default_first.choices[0].message.content,
            "tool_calls": [
                {
                    "id": call.id,
                    "type": call.type,
                    "function": {
                        "name": call.function.name,
                        "arguments": call.function.arguments,
                    },
                }
            ],
        },
        {
            "role": "tool",
            "tool_call_id": call.id,
            "name": call.function.name,
            "content": '{"value":1}',
        },
    ]
    default_second = default_client.chat.completions.create(
        model="gemini-3.1-pro", messages=second_messages, tools=tools
    )
    assert default_second.choices[0].message.content == "done after tool result"

    backend_second = backend_client.chat.completions.create(
        model="gemini-3.1-pro", messages=backend_messages
    )
    assert backend_second.choices[0].message.content == "backend answer: all clear."
    assert (
        backend_second.antigravity_usage_telemetry["native_session_id_hash"]
        != backend_first.antigravity_usage_telemetry["native_session_id_hash"]
    )

    rows = _rows(tmp_path / "fake_acp_log.jsonl")
    resumes = [row for row in rows if row["method"] == "session/resume"]
    assert len(resumes) == 1, (
        "only the default client may resume; backend requests must never resume"
    )
    assert resumes[0]["resumed_session_id"] == default_session
    assert resumes[0]["affinity"].startswith("sha256:")
    default_prompts = [
        row
        for row in rows
        if row["method"] == "session/prompt" and row["affinity"].startswith("sha256:")
    ]
    backend_prompts = [
        row for row in rows if row["method"] == "session/prompt" and row["affinity"] == ""
    ]
    assert len(default_prompts) == 2 and len(backend_prompts) == 2
    # The default client's guard still fires after the backend client ran.
    with pytest.raises(
        RuntimeError, match="refused to provide the auditable source-read evidence"
    ):
        default_client.chat.completions.create(
            model="gemini-3.1-pro",
            messages=[{"role": "user", "content": EVIDENCE_PROMPT}],
            tools=tools,
        )


def test_backend_mode_concurrent_identical_requests_get_fresh_sessions(
    monkeypatch, tmp_path
) -> None:
    """Concurrency regression: parallel backend requests never share a session."""
    _write_fake_server(tmp_path, "answer")
    module, client_module = _load_module(monkeypatch, tmp_path)
    counters = _instrument_registry(client_module, monkeypatch)
    client = _make_client(module, tmp_path, postprocessing_policy="llm_backend")

    messages = [{"role": "user", "content": "the same inference prompt"}]
    with ThreadPoolExecutor(max_workers=4) as pool:
        completions = list(
            pool.map(
                lambda _: client.chat.completions.create(
                    model="gemini-3.1-pro", messages=messages
                ),
                range(4),
            )
        )

    assert all(
        completion.choices[0].message.content == "backend answer: all clear."
        for completion in completions
    )
    session_hashes = {
        completion.antigravity_usage_telemetry["native_session_id_hash"]
        for completion in completions
    }
    assert len(session_hashes) == 4, "each concurrent backend request needs its own session"

    rows = _rows(tmp_path / "fake_acp_log.jsonl")
    session_news = [row for row in rows if row["method"] == "session/new"]
    assert len(session_news) == 4
    assert len({row["issued_session_id"] for row in session_news}) == 4
    assert not [row for row in rows if row["method"] == "session/resume"]
    assert all(row["affinity"] == "" for row in rows)
    assert counters == {"get": 0, "put": 0}
    assert not (tmp_path / "acp-conversation-state.json").exists()
