"""Usage-semantics split: consumption vs semantically-unverified frame observations (backlog item 2, P0).

The old engine's verified contract (docs/acp-usage-telemetry.md): ``completion.usage`` is fed ONLY by the
server's own ``session/prompt`` result breakdown (required fields ``inputTokens``/``outputTokens``/
``totalTokens``, never invented) and only after a gate — first turn against the local transcript estimate,
later turns against growth consistency. ``usage_update`` frames are an explicitly-unverified observation
channel and must never reach billing. The #194 chain audit (25.39M "tokens" that were a frame integral)
and the 2026-11-23 incident (~31K transcript reported as ~1.07M) are the regressions these tests replay.
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


def test_missing_required_fields_are_rejected_not_invented(tmp_path):
    """Old-engine contract: outputTokens/totalTokens are required; a partial report yields usage=None."""
    from antigravity_acp_mcp.client import _completion
    for partial in ({"inputTokens": 900, "outputTokens": 40},        # no totalTokens -> no summed stand-in
                    {"inputTokens": 900, "totalTokens": 940},        # no outputTokens -> no invented 0
                    {"inputTokens": 900}):                            # inputTokens alone is not a report
        conv, _ = make_conv(tmp_path, [[{"result_usage": partial}, {"text": "hi"}]])
        try:
            r = conv.run([SYS, {"role": "user", "content": "q"}], TOOLS, "m")
            assert _completion(r, "m").usage is None, partial
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


def test_inflated_first_turn_is_rejected_without_setting_a_baseline(tmp_path):
    """The old engine accepted turn-one reports unconditionally; a bogus baseline must never be seeded."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"result_usage": {"inputTokens": 1_070_000, "outputTokens": 5, "totalTokens": 1_070_005}},
         {"text": "one"}],
    ])
    try:
        r = conv.run([SYS, {"role": "user", "content": "q1"}], TOOLS, "m")
        assert _completion(r, "m").usage is None  # ~1.07M vs a tiny local transcript: rejected whole
        assert conv._usage_baseline is None       # and no baseline was seeded from the bogus report
    finally:
        conv.close()


def test_inflated_reported_growth_is_rejected(tmp_path):
    """2026-11-23 incident replay: a small local turn reported as ~500K growth yields usage=None."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"result_usage": {"inputTokens": 10_000, "outputTokens": 5, "totalTokens": 10_005}}, {"text": "one"}],
        [{"result_usage": {"inputTokens": 509_000, "outputTokens": 5, "totalTokens": 509_005}}, {"text": "two"}],
    ])
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        r1 = conv.run(msgs, TOOLS, "m")
        assert _completion(r1, "m").usage is not None  # first turn within estimate tolerance
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        r2 = conv.run(msgs, TOOLS, "m")
        assert _completion(r2, "m").usage is None  # rejected: Core falls back to its own estimate
    finally:
        conv.close()


def test_consistent_reported_growth_is_accepted(tmp_path):
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"result_usage": {"inputTokens": 10_000, "outputTokens": 5, "totalTokens": 10_005}}, {"text": "one"}],
        [{"result_usage": {"inputTokens": 10_400, "outputTokens": 5, "totalTokens": 10_405}}, {"text": "two"}],
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
        [{"result_usage": {"inputTokens": 10_000, "outputTokens": 5, "totalTokens": 10_005}}, {"text": "one"}],
        [{"result_usage": {"inputTokens": 509_000, "outputTokens": 5, "totalTokens": 509_005}}, {"text": "two"}],
        [{"result_usage": {"inputTokens": 510_000, "outputTokens": 5, "totalTokens": 510_005}}, {"text": "three"}],
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


def test_usage_mapping_requires_all_totals():
    from antigravity_acp_mcp.client import _usage
    assert _usage({"used": 5000, "size": 9000}) is None
    assert _usage({"input_tokens": 10}) is None                       # no invented output/total
    assert _usage({"input_tokens": 10, "output_tokens": 2}) is None   # total must be the server's own
    assert _usage({"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}) is not None
    assert _usage({"input_tokens": True, "output_tokens": 2, "total_tokens": 12}) is None
    assert _usage(None) is None


def test_transcript_estimate_counts_text_and_tool_calls():
    from antigravity_acp_mcp.usage_contract import transcript_tokens
    empty = transcript_tokens([])
    grown = transcript_tokens([
        {"role": "user", "content": "x" * 300},
        {"role": "assistant", "content": "", "tool_calls": [
            {"id": "1", "type": "function", "function": {"name": "some_tool", "arguments": '{"a": 1}'}}]},
    ])
    assert grown - empty > 100
