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


def test_window_cap_rejects_same_turn_proportional_inflation_and_preserves_baseline(tmp_path):
    """Issue #99 E2E (Parked-MCP): usage_update.size caps result_usage even under 8x tolerance."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"usage": {"used": 500, "size": 20_000}},
         {"result_usage": {"inputTokens": 10_000, "outputTokens": 5, "totalTokens": 10_005}},
         {"text": "one"}],
        [{"usage": {"used": 500, "size": 20_000}},
         {"result_usage": {"inputTokens": 25_000, "outputTokens": 5, "totalTokens": 25_005}},
         {"text": "two"}],
        [{"usage": {"used": 500, "size": 20_000}},
         {"result_usage": {"inputTokens": 10_400, "outputTokens": 5, "totalTokens": 10_405}},
         {"text": "three"}],
    ])
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        r1 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r1, "fake-model-a").usage.prompt_tokens == 10_000
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        # 25_000 - 10_000 = 15_000 << 64_000 slack, so 8x gate would accept; window cap (20_000) rejects.
        r2 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r2, "fake-model-a").usage is None
        assert conv._usage_baseline[0] == 10_000
        msgs = _run_turn(conv, msgs, "two")
        msgs.append({"role": "user", "content": "q3"})
        r3 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r3, "fake-model-a").usage.prompt_tokens == 10_400
    finally:
        conv.close()


def test_window_cap_persists_across_unavailable_turns_and_clears_on_model_switch(tmp_path):
    """Turn 1 sets size via usage_update even with no result_usage; Turn 2 (no frame) still enforces it;
    switching to another model clears the prior model's limit."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"usage": {"used": 500, "size": 20_000}}, {"text": "one"}],
        [{"result_usage": {"inputTokens": 25_000, "outputTokens": 5, "totalTokens": 25_005}},
         {"text": "two"}],
        [{"result_usage": {"inputTokens": 25_000, "outputTokens": 5, "totalTokens": 25_005}},
         {"text": "three"}],
    ])
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        r1 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r1, "fake-model-a").usage is None
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        # Same model, no usage_update on turn 2: remembers 20_000 window and rejects 25_000.
        r2 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r2, "fake-model-a").usage is None
        msgs = _run_turn(conv, msgs, "two")
        msgs.append({"role": "user", "content": "q3"})
        # Model switch without a new usage_update: must NOT apply fake-model-a's 20_000 limit.
        r3 = conv.run(msgs, TOOLS, "fake-model-b")
        u3 = _completion(r3, "fake-model-b").usage
        assert u3 is not None and u3.prompt_tokens == 25_000
    finally:
        conv.close()


def test_window_cap_rejects_first_turn_overflow_without_seeding_baseline(tmp_path):
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        [{"usage": {"used": 500, "size": 20_000}},
         {"result_usage": {"inputTokens": 25_000, "outputTokens": 5, "totalTokens": 25_005}},
         {"text": "one"}],
    ])
    try:
        r = conv.run([SYS, {"role": "user", "content": "q1"}], TOOLS, "fake-model-a")
        assert _completion(r, "fake-model-a").usage is None
        assert conv._usage_baseline is None
    finally:
        conv.close()



def test_corrupt_usage_update_frame_does_not_set_or_overwrite_context_limit(tmp_path):
    """Whole-frame validity: a usage_update with invalid used/size never sets or overwrites _context_limit,
    while a valid partial frame (size without used) is accepted."""
    from antigravity_acp_mcp.client import _completion
    conv, _ = make_conv(tmp_path, [
        # Turn 1: corrupt used with valid size=20_000 -> frame rejected whole, no cap set -> 25_000 accepted (under 8x)
        [{"usage": {"used": "bogus", "size": 20_000}},
         {"result_usage": {"inputTokens": 25_000, "outputTokens": 5, "totalTokens": 25_005}},
         {"text": "one"}],
        # Turn 2: valid frame establishes 20_000 cap
        [{"usage": {"used": 500, "size": 20_000}}, {"text": "two"}],
        # Turn 3: corrupt frame with size=100_000 + size=0 must NOT overwrite trusted 20_000 cap -> 25_000 rejected
        [{"usage": {"used": -1, "size": 100_000}},
         {"usage": {"used": True, "size": 200_000}},
         {"usage": {"used": 600, "size": 0}},
         {"result_usage": {"inputTokens": 25_000, "outputTokens": 5, "totalTokens": 25_005}},
         {"text": "three"}],
        # Turn 4: valid partial frame (size only, no used) updates cap to 30_000 -> 25_000 accepted
        [{"usage": {"size": 30_000}},
         {"result_usage": {"inputTokens": 25_000, "outputTokens": 5, "totalTokens": 25_005}},
         {"text": "four"}],
    ])
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        r1 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r1, "fake-model-a").usage.prompt_tokens == 25_000
        assert conv._context_limit is None
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        conv.run(msgs, TOOLS, "fake-model-a")
        assert conv._context_limit == 20_000
        msgs = _run_turn(conv, msgs, "two")
        msgs.append({"role": "user", "content": "q3"})
        r3 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r3, "fake-model-a").usage is None
        assert conv._context_limit == 20_000
        msgs = _run_turn(conv, msgs, "three")
        msgs.append({"role": "user", "content": "q4"})
        r4 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r4, "fake-model-a").usage.prompt_tokens == 25_000
        assert conv._context_limit == 30_000
    finally:
        conv.close()


def test_thinking_change_on_composite_model_invalidates_prior_context_limit(tmp_path):
    """Changing thinking on a composite model id picks a different sibling model in session.py;
    Conversation must invalidate the prior model's _context_limit even when the requested model string is unchanged."""
    import json as _json
    import sys as _sys
    from antigravity_acp_mcp.acp_connection import AcpConnection
    from antigravity_acp_mcp.client import _completion
    from antigravity_acp_mcp.conversation import Conversation
    from ._support import FAKE_AGY

    log = tmp_path / "agy.log"
    behaviour = _json.dumps({
        "available_models": [
            {"modelId": "fake-model-a-medium"},
            {"modelId": "fake-model-a-xhigh"},
        ],
        "script": [
            [{"usage": {"used": 500, "size": 20_000}},
             {"result_usage": {"inputTokens": 10_000, "outputTokens": 5, "totalTokens": 10_005}},
             {"text": "one"}],
            # Turn 2: same requested model "fake-model-a-medium" with thinking="xhigh" -> selects fake-model-a-xhigh.
            # No usage_update on this turn; must NOT reuse fake-model-a-medium's 20_000 limit.
            [{"result_usage": {"inputTokens": 25_000, "outputTokens": 5, "totalTokens": 25_005}},
             {"text": "two"}],
        ],
        "log": str(log),
    })

    def spawn(_key, cwd):
        conn = AcpConnection(_sys.executable, [FAKE_AGY, behaviour], cwd)
        conn.start()
        conn.initialize()
        return conn

    conv = Conversation("k-thinking", spawn)
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        r1 = conv.run(msgs, TOOLS, "fake-model-a-medium", thinking="medium")
        assert _completion(r1, "fake-model-a-medium").usage.prompt_tokens == 10_000
        assert conv._context_limit == 20_000
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        r2 = conv.run(msgs, TOOLS, "fake-model-a-medium", thinking="xhigh")
        u2 = _completion(r2, "fake-model-a-medium").usage
        assert u2 is not None and u2.prompt_tokens == 25_000
        assert conv._context_limit is None
    finally:
        conv.close()


def test_pre_and_post_prompt_usage_update_frames_are_ignored_for_context_limit(tmp_path):
    """usage_update frames arriving before session/prompt or after prompt completion must not set _context_limit."""
    import json as _json
    import sys as _sys
    from antigravity_acp_mcp.acp_connection import AcpConnection
    from antigravity_acp_mcp.client import _completion
    from antigravity_acp_mcp.conversation import Conversation
    from ._support import FAKE_AGY

    log = tmp_path / "agy.log"
    behaviour = _json.dumps({
        "pre_prompt_usage": {"used": 0, "size": 10_000},
        "script": [
            [{"result_usage": {"inputTokens": 15_000, "outputTokens": 5, "totalTokens": 15_005}},
             {"post_prompt_usage": {"used": 0, "size": 10_000}},
             {"text": "one"}],
            [{"result_usage": {"inputTokens": 15_500, "outputTokens": 5, "totalTokens": 15_505}},
             {"text": "two"}],
        ],
        "log": str(log),
    })

    def spawn(_key, cwd):
        conn = AcpConnection(_sys.executable, [FAKE_AGY, behaviour], cwd)
        conn.start()
        conn.initialize()
        return conn

    conv = Conversation("k-window-bounds", spawn)
    msgs = [SYS, {"role": "user", "content": "q1"}]
    try:
        r1 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r1, "fake-model-a").usage.prompt_tokens == 15_000
        assert conv._context_limit is None
        msgs = _run_turn(conv, msgs, "one")
        msgs.append({"role": "user", "content": "q2"})
        r2 = conv.run(msgs, TOOLS, "fake-model-a")
        assert _completion(r2, "fake-model-a").usage.prompt_tokens == 15_500
        assert conv._context_limit is None
    finally:
        conv.close()
