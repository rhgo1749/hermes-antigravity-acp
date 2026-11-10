"""Deterministic long-context wire tests (eval pilot C8/C9 follow-up).

Proves that incident-scale histories (~84K and ~107K tokens measured in the
2026-10-12 failure at byte-per-token ratio 3.01) reach the Antigravity ACP
prompt intact when delivered as multiple chat-completions messages, WITHOUT
any model call and WITHOUT loosening Core's 65,536-char normalization cap.

Coverage boundary, stated honestly:
- Covered here: Core's content normalizer (when importable) and the plugin's
  prompt formatter, chained on the same inputs, plus band/integrity checks.
- NOT covered here: the live HTTP route. routes:680
  ``history = conversation_messages[:-1]`` (gateway/platforms/
  api_server_openai_routes.py in hermes-agent) is the hop that forwards body
  messages into provider history; it is verified by code reading and by the
  eval state.db records, and its pinning test belongs to Hermes Core
  (session-key contract issue), not to this repository.
- Token figures below are ESTIMATES from a measured byte/token ratio. No real
  tokenizer or model call participates in these tests.
"""

from __future__ import annotations

import importlib.util
import os
import random
import sys
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"

try:  # Core normalizer availability varies by test environment; skip, don't fail.
    from gateway.platforms import api_server as core
except Exception:
    core = None

needs_core = pytest.mark.skipif(core is None, reason="hermes-agent core not importable")

MAX_CHARS = 65_536  # gateway MAX_NORMALIZED_TEXT_LENGTH (asserted against core when present)
B_PER_TOKEN_ESTIMATE = 3.01  # measured on the 2026-10-12 incident prompts; estimate only
REQUEST_MARKER = "FDE-PPT-SLIDE2-CONTINUATION-REQUEST"


def _load_client(monkeypatch):
    """Load the plugin package the same way tests/test_standalone_client.py does."""
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        f"/tmp/antigravity-acp-wire-state-{os.getpid()}-{id(monkeypatch)}.json",
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        f"/tmp/antigravity-acp-wire-limits-{os.getpid()}-{id(monkeypatch)}.json",
    )

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = lambda *a, **k: None
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)

    module_name = "antigravity_acp_wire_test"
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
    return importlib.import_module(module_name + ".client")


def _deterministic_text(target_bytes: int, seed: int) -> str:
    """CJK+ASCII mixture close to the incident prompts; exact UTF-8 byte size."""
    rng = random.Random(seed)
    parts: list[str] = []
    total = 0
    while total < target_bytes:
        if rng.random() < 0.5:
            frag = "".join(rng.choice("배포감사결과보고서요청수정사항확인") for _ in range(rng.randint(30, 90)))
        else:
            frag = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz ,.") for _ in range(rng.randint(60, 180)))
        parts.append(frag)
        total += len(frag.encode("utf-8")) + 1
    text = "\n".join(parts)
    while len(text.encode("utf-8")) > target_bytes:
        text = text[:-10]
    return text


def _split_into_messages(text: str, max_chars: int = 60_000) -> list[dict]:
    """One conversation body: alternating user/assistant turns, each under the cap.

    The 65,536-char cap applies per message content (and per joined part array);
    there is no cross-message total cap on /v1/chat/completions, so this is the
    supported way to carry incident-scale context.
    """
    messages = []
    for i in range(0, len(text), max_chars):
        messages.append({"role": "user" if not messages or messages[-1]["role"] != "user" else "assistant",
                         "content": text[i:i + max_chars]})
    return messages


# ---------------------------------------------------------------- core normalizer


@needs_core
def test_core_cap_constant():
    assert core.MAX_NORMALIZED_TEXT_LENGTH == MAX_CHARS


@needs_core
def test_single_oversized_message_is_capped_and_loses_tail():
    """Incident shape: one 107K-token-scale message is truncated at the cap."""
    body = _deterministic_text(322_070, seed=107) + "\n" + REQUEST_MARKER
    normalized = core._normalize_chat_content(body)
    assert len(normalized) == MAX_CHARS
    assert REQUEST_MARKER not in normalized  # documented loss mode from pilot C8/C9


@needs_core
def test_split_messages_survive_core_normalization_whole():
    body = _deterministic_text(252_840, seed=84)  # ~84K-token scale
    normalized = [core._normalize_chat_content(m["content"]) for m in _split_into_messages(body)]
    assert all(len(c) <= MAX_CHARS for c in normalized)
    assert "".join(normalized) == body  # byte-exact reconstruction, zero loss


@needs_core
def test_content_part_array_is_capped_when_joined():
    joined = core._normalize_chat_content(
        [{"type": "text", "text": "a" * 60_000}, {"type": "text", "text": "b" * 60_000}]
    )
    assert len(joined) == MAX_CHARS  # parts inside ONE message do NOT escape the cap


# ---------------------------------------------------------------- ACP wire shape


def test_incident_scale_wire_carries_history_and_request(monkeypatch):
    client = _load_client(monkeypatch)
    history_text = _deterministic_text(322_070, seed=107)  # ~107K-token scale
    msgs = [{"role": "system", "content": "SYS"}] + _split_into_messages(history_text)
    msgs.append({"role": "user", "content": f"{REQUEST_MARKER}: summarize slide 2 and continue."})

    if core is not None:
        msgs = [{"role": m["role"], "content": core._normalize_chat_content(m["content"])} for m in msgs]

    wire = client._format_messages_as_prompt(msgs, "model-x")
    wire_bytes = len(wire.encode("utf-8"))
    assert wire_bytes >= 322_070  # full fixture reached the wire, not the 64Ki slice

    # Every history chunk present verbatim inside the historical band.
    for m in msgs[1:-1]:
        assert m["content"].strip() in wire
    # The newest request survives verbatim in the canonical ACTIVE band,
    # untouched by primer preview/neutralization.
    assert REQUEST_MARKER in wire
    active_text = msgs[-1]["content"]
    canonical_band = wire.split("<ACTIVE_REQUEST>\n", 1)[1].split("</ACTIVE_REQUEST>", 1)[0]
    assert active_text in canonical_band
    assert "preview truncated" not in canonical_band  # only the primer preview may be trimmed

    # F1 primer at the head; full ACTIVE_REQUEST band verbatim AFTER history
    # (sandwich: primer warns before the historical band, the verbatim request
    # closes the prompt so it is never buried).
    primer_pos = wire.find("<ACTIVE_REQUEST_PRIMER>")
    hist_pos = wire.find("<HISTORICAL_CONTEXT>")
    active_pos = wire.find("<ACTIVE_REQUEST>\n")
    assert primer_pos != -1 and hist_pos != -1 and active_pos != -1
    assert primer_pos < hist_pos < active_pos


def test_tool_call_result_pair_survives_history(monkeypatch):
    client = _load_client(monkeypatch)
    msgs = [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "read the file"},
        {"role": "assistant", "tool_calls": [{"id": "t1", "type": "function",
                                              "function": {"name": "read_file", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "t1", "content": "TOOLPAIR-WIRE-RESULT payload"},
        {"role": "user", "content": "now summarize"},
    ]
    wire = client._format_messages_as_prompt(msgs, "model-x")
    assert "TOOLPAIR-WIRE-RESULT payload" in wire
    assert "read_file" in wire
    # The result must be LINKED to the call by the same tool_call_id.
    call_seg = wire.split("TOOLPAIR-WIRE-RESULT payload", 1)[0]
    call_id_pos = call_seg.rfind("t1")
    result_pos = wire.find("TOOLPAIR-WIRE-RESULT payload")
    assert call_id_pos != -1 and call_id_pos < result_pos
    assert '\"tool_call_id\": \"t1\"' in wire or "\"id\": \"t1\"" in wire
    assert wire.count('\"tool_call_id\": \"t1\"') + wire.count('\"id\": \"t1\"') >= 2


def test_full_replay_bands_vs_historyless_bootstrap(monkeypatch):
    """Structural distinction at the formatter: prompts WITH history carry
    HISTORICAL_CONTEXT + primer; a history-less render is a bootstrap shape
    (neither band). True native continuation is separate and covered by
    test_native_continuation_delta_carries_only_new_events."""
    client = _load_client(monkeypatch)
    with_history = client._format_messages_as_prompt(
        [{"role": "system", "content": "S"}, {"role": "user", "content": "old"}, {"role": "user", "content": "q"}],
        "model-x",
    )
    bootstrap = client._format_messages_as_prompt(
        [{"role": "system", "content": "S"}, {"role": "user", "content": "q"}], "model-x",
    )
    assert "<HISTORICAL_CONTEXT>" in with_history and "ACTIVE_REQUEST_PRIMER" in with_history
    assert "<HISTORICAL_CONTEXT>" not in bootstrap
    assert "ACTIVE_REQUEST_PRIMER" not in bootstrap


def test_native_continuation_delta_carries_only_new_events(monkeypatch):
    """Continuation contract: when the frontier matches, the client sends ONLY
    new events (replay_reason=continuation_delta) — no HISTORICAL_CONTEXT band,
    no full replay of prior turns."""
    client = _load_client(monkeypatch)
    turn1 = [{"role": "system", "content": "S"}, {"role": "user", "content": "first question"}]
    assistant1 = {"role": "assistant", "content": "FIRST ANSWER"}
    followup = [
        {"role": "assistant", "tool_calls": [{"id": "t9", "type": "function",
                                              "function": {"name": "search_files", "arguments": "{}"}}]},
        {"role": "tool", "tool_call_id": "t9", "content": "DELTA-ONLY-EVIDENCE"},
        {"role": "user", "content": "continue please"},
    ]
    fingerprint = client._context_fingerprint("model-x", None, None)
    state = client.ACPConversationState(
        session_id="s-delta-test",
        context_fingerprint=fingerprint,
        request_fingerprints=tuple(client._message_fingerprint(m) for m in turn1),
        response_fingerprint=client._message_fingerprint(assistant1),
        updated_at=0.0,
        native_tokens=100,
    )
    delta = client._continuation_delta(turn1 + [assistant1] + followup, state, fingerprint)
    assert delta is not None and delta == followup
    prompt = client._format_continuation_delta(delta, active_request="first question")
    assert "DELTA-ONLY-EVIDENCE" in prompt
    assert "continuation delta" in prompt  # explicit delta framing sentence
    assert "<ACTIVE_REQUEST_ANCHOR>" in prompt  # anchor keeps governing request alive
    assert "<HISTORICAL_CONTEXT>" not in prompt
    assert "FIRST ANSWER" not in prompt  # prior turns are NOT re-sent
    # Frontier mismatch (different prior answer) must fall back, not delta.
    mismatch = client._continuation_delta(
        turn1 + [{"role": "assistant", "content": "DIFFERENT"}] + followup, state, fingerprint)
    assert mismatch is None


def test_measured_bytes_are_exact_and_tokens_remain_estimates(monkeypatch):
    client = _load_client(monkeypatch)
    history_text = _deterministic_text(252_840, seed=84)
    msgs = [{"role": "system", "content": "SYS"}] + _split_into_messages(history_text)
    msgs.append({"role": "user", "content": REQUEST_MARKER})
    wire = client._format_messages_as_prompt(msgs, "model-x")
    measured = len(wire.encode("utf-8"))
    estimated_tokens = measured / B_PER_TOKEN_ESTIMATE
    # Byte size is exact and reproducible; token size is explicitly an estimate.
    assert measured >= 252_840 + len(REQUEST_MARKER.encode())
    assert 80_000 < estimated_tokens < 95_000  # ~84K scale class, estimate band
