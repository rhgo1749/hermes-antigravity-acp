"""Single owner of the ACP usage contract for BOTH engines.

The Replay engine (the parent package's flat modules) and the Parked-MCP
engine (this subpackage) must treat server-reported usage with IDENTICAL
rules.  Since issue #102 the contract is:

1. ``completion.usage`` is ALWAYS ``None``.  Hermes Core treats
   ``completion.usage.prompt_tokens`` as the authoritative single-request
   context occupancy (agent/usage_anchor.py, agent/turn_context_compaction.py).
   The ACP ``session/prompt`` result ``usage`` is a per-turn CONSUMPTION sum
   over the server's internal model calls — ``cachedReadTokens`` accumulates
   each internal hop's cached prefix and can exceed the durable transcript by
   an order of magnitude (2026-11-26 samples: 861,529 cache-read against a
   ~57K transcript; 6.03M against ~140K).  No field on the current ACP surface
   is a verified single-request occupancy reading, so nothing may seed
   ``completion.usage``; ``None`` routes Core to its designed local-estimate
   fallback and normal context compaction keeps working.
2. ``usage_update`` frames are protocol-validated here (whole-frame validity)
   and captured ONLY as explicitly-scoped, ``is_billing_usage: False``
   provider telemetry (observations, turn sums, durable deltas).

Issue #102 also retired the magnitude-gate machinery that the old contract
hung off ``completion.usage`` — the 8x growth gate (#87/#6), the first-turn
plausibility gate (#87), the context-window cap (#99), their per-conversation
baselines and per-model limit tracking, and the consumption-semantics verdict
store they were the sole writers of.  Those gates policed a value that must
now never reach Core at all; keeping them would defend a channel the contract
already pins shut.  Drift history lives in git and docs/acp-usage-telemetry.md;
neither engine may reimplement those decisions locally.

Location note: this lives in ``parked/`` because the design_c test lane
bootstraps this subpackage standalone (as ``antigravity_acp_mcp``) and must
not import from the parent package; the Replay engine imports it as
``.parked.usage_contract``.  It is shared contract, not parked-private
policy.
"""

from __future__ import annotations

import math
from typing import Any


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
    rejected as a whole so corrupt frames never contribute a sibling field to
    ANY telemetry consumer.  Partial frames carrying only one valid field
    remain valid.
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
    """Local estimate of the transcript this adapter grew.

    Used for prompt-sizing bookkeeping (``ACPConversationState.native_tokens``
    resume deltas) and as the informational ``local_estimate_tokens`` reading
    in the live canary report.  It is no longer a gate yardstick: the
    magnitude gates that consumed it were retired with issue #102.
    """
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


_CJK_RANGES = (
    (0x1100, 0x11FF), (0x2E80, 0x2FFF), (0x3040, 0x30FF), (0x3130, 0x318F),
    (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xAC00, 0xD7AF), (0xF900, 0xFAFF),
    (0xFE30, 0xFE4F), (0xFF00, 0xFFDC), (0x20000, 0x3134F),
)
