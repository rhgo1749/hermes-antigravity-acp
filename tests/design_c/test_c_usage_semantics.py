"""Usage-semantics split: consumption vs context occupancy (backlog item 2, P0).

The old engine's verified contract (docs/acp-usage-telemetry.md): ``completion.usage`` is fed ONLY by the
server's own ``session/prompt`` result breakdown and only after a growth-consistency gate; ``usage_update``
frames are occupancy/telemetry channels and must never reach billing. The #194 chain audit (25.39M
"tokens" that were an occupancy integral) is the regression case these tests replay.
"""

from __future__ import annotations

from ._support import SYS, TOOLS, make_conv


def _run_turn(conv, messages, reply):
    messages.append({"role": "assistant", "content": reply})
    return messages


def test_prompt_result_usage_is_the_only_consumption(tmp_path):
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [[{"result_usage": {"inputTokens": 900, "outputTokens": 40,
                                                       "thoughtTokens": 10, "totalTokens": 950,
                                                       "cachedReadTokens": 100}},
                                    {"text": "hi"}]])
    try:
        r = conv.run([SYS, {"role": "user", "content": "q"}], TOOLS, "m")
        u = _completion(r, "m").usage
        assert (u.prompt_tokens, u.completion_tokens, u.total_tokens) == (900, 50, 950)
        assert u.prompt_tokens_details.cached_tokens == 100
    finally:
        conv.close()


def test_occupancy_only_prompt_has_no_billing_usage(tmp_path):
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [[{"usage": {"used": 1200, "size": 1000000}}, {"text": "hi"}]])
    try:
        r = conv.run([SYS, {"role": "user", "content": "q"}], TOOLS, "m")
        c = _completion(r, "m")
        assert c.usage is None  # the #194 class: `used` must never surface as prompt_tokens
        assert c.antigravity_context_occupancy["used"] == 1200
    finally:
        conv.close()


def test_inflated_reported_growth_is_rejected(tmp_path):
    """2026-11-23 incident replay: a small local turn reported as ~500K growth yields usage=None."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"result_usage": {"inputTokens": 10_000, "outputTokens": 5}}, {"text": "one"}],
        [{"result_usage": {"inputTokens": 509_000, "outputTokens": 5}}, {"text": "two"}],
    ])
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        r1 = conv.run(msgs, TOOLS, "m")
        assert _completion(r1, "m").usage is not None  # first turn: baseline, no growth to correlate
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        r2 = conv.run(msgs, TOOLS, "m")
        assert _completion(r2, "m").usage is None  # rejected: Core falls back to its own estimate
    finally:
        conv.close()


def test_consistent_reported_growth_is_accepted(tmp_path):
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"result_usage": {"inputTokens": 10_000, "outputTokens": 5}}, {"text": "one"}],
        [{"result_usage": {"inputTokens": 10_400, "outputTokens": 5}}, {"text": "two"}],
    ])
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        conv.run(msgs, TOOLS, "m")
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        r2 = conv.run(msgs, TOOLS, "m")
        u = _completion(r2, "m").usage
        assert u is not None and u.prompt_tokens == 10_400
    finally:
        conv.close()


def test_rejected_baseline_is_kept_and_permanently_inflated_server_keeps_failing(tmp_path):
    """A rejected turn must not move the baseline: an inflated server stays rejected."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"result_usage": {"inputTokens": 10_000, "outputTokens": 5}}, {"text": "one"}],
        [{"result_usage": {"inputTokens": 509_000, "outputTokens": 5}}, {"text": "two"}],
        [{"result_usage": {"inputTokens": 510_000, "outputTokens": 5}}, {"text": "three"}],
    ])
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        conv.run(msgs, TOOLS, "m")
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        assert _completion(conv.run(msgs, TOOLS, "m"), "m").usage is None
        msgs = _run_turn(conv, msgs, "two")
        msgs.append({"role": "user", "content": "q3"})
        # 510_000 - 10_000 (last TRUSTED baseline) is still order-of-magnitude divergence.
        assert _completion(conv.run(msgs, TOOLS, "m"), "m").usage is None
    finally:
        conv.close()


def test_usage_mapping_has_no_used_fallback():
    from antigravity_acp_mcp.client import _usage
    assert _usage({"used": 5000, "size": 9000}) is None
    assert _usage({"input_tokens": 10}) is not None
    assert _usage({"input_tokens": True}) is None
    assert _usage(None) is None


def test_transcript_estimate_counts_text_and_tool_calls():
    from antigravity_acp_mcp.conversation import _transcript_tokens
    empty = _transcript_tokens([])
    grown = _transcript_tokens([
        {"role": "user", "content": "x" * 300},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "1", "type": "function", "function": {"name": "some_tool", "arguments": '{"a": 1}'}}]},
    ])
    assert grown - empty > 100
