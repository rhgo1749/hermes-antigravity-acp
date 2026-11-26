"""Usage semantics (issue #102 shape, Parked-MCP engine).

The contract (docs/acp-usage-telemetry.md): ``completion.usage`` is ALWAYS
``None`` — the ``session/prompt`` result breakdown is a per-turn CONSUMPTION
sum over the server's internal model calls, never a verified single-request
context occupancy, and Hermes Core anchors its compaction decisions on
``completion.usage.prompt_tokens``.  ``usage_update`` frames stay visible as
explicitly-scoped, non-billing observations.  The magnitude gates that used to
police the contaminated channel (first-turn plausibility, 8x growth, window
cap) are retired with the channel itself.

Replays: the #194 chain audit (25.39M "tokens" that were a frame integral),
the 2026-11-23 incident (~31K transcript reported as ~1.07M), and the 2026-11-26
S4 sample (861,529 cachedReadTokens against a ~57K transcript that slipped
through the window cap because it only checked ``inputTokens``).
"""

from __future__ import annotations

from ._support import SYS, TOOLS, make_conv


def _run_turn(conv, messages, reply):
    messages.append({"role": "assistant", "content": reply})
    return messages


def test_prompt_result_usage_never_surfaces_as_completion_usage(tmp_path):
    """Even a complete, plausible breakdown may not seed Core's anchor."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [[{"result_usage": {"inputTokens": 900, "outputTokens": 40,
                                                      "thoughtTokens": 10, "totalTokens": 950,
                                                      "cachedReadTokens": 100}},
                                   {"text": "hi"}]])
    try:
        r = conv.run([SYS, {"role": "user", "content": "q"}], TOOLS, "m")
        assert _completion(r, "m").usage is None
    finally:
        conv.close()


def test_s4_shaped_breakdown_never_surfaces(tmp_path):
    """2026-11-26 S4 replay: the hop-sum cache-read (861,529) that the #99
    window cap passed verbatim (it only checked inputTokens=0) must not reach
    Core at all — no anchor, no premature compaction."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [[
        {"usage": {"used": 45_000, "size": 1_048_576}},
        {"result_usage": {"inputTokens": 0, "outputTokens": 306, "thoughtTokens": 17_000,
                          "totalTokens": 878_835, "cachedReadTokens": 861_529}},
        {"text": "hi"}]])
    try:
        r = conv.run([SYS, {"role": "user", "content": "q"}], TOOLS, "m")
        c = _completion(r, "m")
        assert c.usage is None
        # The server's own observation survives only as scoped telemetry.
        assert c.antigravity_usage_observations["used"] == 45_000
        assert c.antigravity_usage_observations["is_billing_usage"] is False
    finally:
        conv.close()


def test_occupancy_only_prompt_has_no_billing_usage(tmp_path):
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [[{"usage": {"used": 1200, "size": 1000000}}, {"text": "hi"}]])
    try:
        r = conv.run([SYS, {"role": "user", "content": "q"}], TOOLS, "m")
        c = _completion(r, "m")
        assert c.usage is None  # the #194 class: frame `used` must never surface as prompt_tokens
        assert c.antigravity_usage_observations["used"] == 1200
        assert c.antigravity_usage_observations["is_billing_usage"] is False
    finally:
        conv.close()


def test_inflated_growth_shapes_never_surface_on_any_turn(tmp_path):
    """2026-11-23 incident replay (Parked-MCP): both the plausible first turn
    and the ~50x inflated second turn surface usage=None — the gate that used
    to accept turn one is gone; Core's estimate fallback rules on every turn."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"result_usage": {"inputTokens": 10_000, "outputTokens": 5, "totalTokens": 10_005}}, {"text": "one"}],
        [{"result_usage": {"inputTokens": 509_000, "outputTokens": 5, "totalTokens": 509_005}}, {"text": "two"}],
    ])
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        r1 = conv.run(msgs, TOOLS, "m")
        assert _completion(r1, "m").usage is None
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        r2 = conv.run(msgs, TOOLS, "m")
        assert _completion(r2, "m").usage is None
    finally:
        conv.close()


def test_transcript_estimate_counts_text_and_tool_calls():
    from antigravity_acp_mcp.usage_contract import transcript_tokens
    empty = transcript_tokens([])
    grown = transcript_tokens([
        {"role": "user", "content": "x" * 300},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "1", "type": "function", "function": {"name": "some_tool", "arguments": '{"a": 1}'}}]},
    ])
    assert grown - empty > 100
