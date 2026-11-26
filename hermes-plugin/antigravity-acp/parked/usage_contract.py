"""Single owner of the ACP turn-usage validity contract for BOTH engines.

The Replay engine (the parent package's flat modules) and the Parked-MCP
engine (this subpackage) must gate the server-reported per-turn
``inputTokens`` against the adapter's own local transcript estimate with
IDENTICAL rules.  This module is that one owner: the tolerance constants,
the first-turn absolute gate, the growth-consistency gate, and the token
estimator the gates measure against.

Drift history — why hand-copying this contract is forbidden:
- 2026-11-23 incident: a ~3.2K local turn reported ~499K growth (156x) and
  fired the Core compression gate twice early (issue #6 lineage).
- Issue #87: the first-turn absolute gate existed only in the Parked-MCP
  engine; the Replay engine accepted a ~1.4M cumulative first-turn report
  verbatim and fired premature compactions.  The follow-up "fix" mirrored
  the gate by hand-copying it — the copy is the disease; this file is the
  cure.  Neither engine may redefine these constants or reimplement these
  decisions locally; ``tests/test_usage_contract_single_owner.py`` fails
  the build when one does.

Location note: this lives in ``parked/`` because the design_c test lane
bootstraps this subpackage standalone (as ``antigravity_acp_mcp``) and must
not import from the parent package; the Replay engine imports it as
``.parked.usage_contract``.  It is shared contract, not parked-private
policy.
"""

from __future__ import annotations

import math
from typing import Any

# Deliberately generous (8x plus a flat 64K slack): the server legitimately
# adds per-turn records the local estimate never sees, and these gates exist
# to reject order-of-magnitude divergence, not to police bookkeeping noise.
USAGE_GROWTH_FACTOR = 8
USAGE_GROWTH_SLACK_TOKENS = 64_000

_CJK_RANGES = (
    (0x1100, 0x11FF), (0x2E80, 0x2FFF), (0x3040, 0x30FF), (0x3130, 0x318F),
    (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xAC00, 0xD7AF), (0xF900, 0xFAFF),
    (0xFE30, 0xFE4F), (0xFF00, 0xFFDC), (0x20000, 0x3134F),
)


def valid_context_limit(limit: Any) -> int | None:
    """Validate a model context-window token limit; return None when unknown/invalid."""
    if isinstance(limit, bool):
        return None
    if isinstance(limit, int):
        return limit if limit > 0 else None
    if isinstance(limit, float):
        if not math.isfinite(limit) or limit <= 0:
            return None
        val = int(limit)
        return val if val > 0 else None
    return None


def nonnegative_usage_number(value: Any) -> bool:
    """Validate one numeric field inside an ACP ``usage_update`` frame."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    return isinstance(value, float) and math.isfinite(value) and value >= 0


def usage_update_valid(update: Any) -> bool:
    """Whole-frame validity for ``usage_update`` ``used``/``size`` fields.

    A frame carrying any present-but-invalid ``used`` or ``size`` value is
    rejected as a whole so corrupt frames never contribute a sibling field or
    poison the trusted context-window limit.  Partial frames carrying only one
    valid field remain valid.
    """
    if (
        not isinstance(update, dict)
        or str(update.get("sessionUpdate") or "").strip() != "usage_update"
    ):
        return False
    present = [field for field in ("used", "size") if field in update]
    return bool(present) and all(
        nonnegative_usage_number(update[field]) for field in present
    )


def context_limit_from_usage_update(update: Any) -> int | None:
    """Extract a validated positive context-window limit from one ``usage_update``.

    Enforces whole-frame validity of ``used`` and ``size`` before validating
    the context limit so a corrupt ``used`` field vetoes ``size`` in the same
    frame, while valid partial frames (``size`` alone) remain accepted.
    """
    if not usage_update_valid(update):
        return None
    return valid_context_limit(update.get("size"))


def report_within_context_limit(*, reported: int, context_limit: Any) -> bool:
    """Hard ceiling check: prompt input tokens cannot exceed the model's context window.

    Runs ahead of the 8x growth/first-turn gates (issue #99): when the server
    folds cumulative cache/hidden state into ``inputTokens`` in proportion to
    transcript growth, the delta still clears 8x tolerance, yet the reported
    occupancy exceeds the model's physical window limit.  When the window limit
    is unknown/invalid (``None``), this check passes through to the 8x gates.
    """
    limit = valid_context_limit(context_limit)
    if limit is None:
        return True
    return reported <= limit


def usage_divergence_tolerance(reference: int) -> int:
    """Accepted divergence around ``reference`` tokens (see constants above)."""
    return max(
        USAGE_GROWTH_FACTOR * (abs(reference) + 1),
        USAGE_GROWTH_SLACK_TOKENS,
    )


def first_turn_report_plausible(*, reported: int, local: int) -> bool:
    """Absolute-level gate for the first turn of a conversation (issue #87).

    There is no growth to correlate on turn one, so the report's absolute
    level is gated against the local transcript estimate with the same
    divergence tolerance.  A server that folds hidden state (subagent
    caches, internal accumulators, cumulative cache reads) into
    ``inputTokens`` from turn one must not seed a bogus baseline that every
    later turn then "agrees" with.
    """
    return abs(reported - local) <= usage_divergence_tolerance(local)


def reported_usage_growth_consistent(
    *,
    prev_reported: int,
    reported: int,
    prev_local: int,
    local: int,
) -> tuple[bool, int, int]:
    """Compare one turn's server-reported input-token growth with local growth.

    The server's per-turn ``inputTokens`` must track the transcript the
    adapter actually grew (the local estimate).  Returns
    ``(ok, reported_growth, expected_growth)``.
    """
    expected = local - prev_local
    actual = reported - prev_reported
    ok = abs(actual - expected) <= usage_divergence_tolerance(expected)
    return ok, actual, expected


def estimate_tokens(text: str) -> int:
    """Conservative token estimate (CJK ~1 token/char, other ~1 token/3 chars).

    Explicit loop with an early break: this runs on every prompt build in both
    engines' hot paths, and the generator/`any()` form measured ~2.6-2.9x
    slower on long transcripts (external review of PR #89, timeit on 330K
    chars).  Outputs are identical; do not "simplify" back to a comprehension.
    """
    if not text:
        return 0
    cjk = 0
    for ch in text:
        code = ord(ch)
        for lo, hi in _CJK_RANGES:
            if lo <= code <= hi:
                cjk += 1
                break
    return cjk + (len(text) - cjk) // 3 + 1


def transcript_tokens(messages: list[dict[str, Any]]) -> int:
    """Local estimate of the transcript this adapter grew; the gate's yardstick."""
    total = 0
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            total += estimate_tokens(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    total += estimate_tokens(part["text"])
        for call in msg.get("tool_calls") or []:
            fn = call.get("function") if isinstance(call, dict) else None
            if isinstance(fn, dict):
                total += estimate_tokens(str(fn.get("name") or "")) + estimate_tokens(
                    str(fn.get("arguments") or "")
                )
    return total
