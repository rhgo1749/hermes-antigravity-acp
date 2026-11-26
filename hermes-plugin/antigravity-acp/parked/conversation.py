"""PlanC components 5-8: per-conversation turn state, interrupt/deadline/abandonment, liveness.

One ``Conversation`` per Hermes conversation key (process-global registry). It owns one warm agy child (through
the account mux) and, per ACP session, one parked MCP endpoint. ``run()`` serves one ``chat.completions.create``:
it classifies the request with ``matcher.classify`` and either answers parked MCP calls and keeps reading the same
prompt (``resume_held``), sends a delta on the same idle session (``continue``), or retires the session and starts
a fresh one with a full text replay (``replay``). The plugin never executes a tool: a parked ``tools/call`` is
returned to Hermes as ``tool_calls`` and answered with the tool row Hermes sends next.

Concurrency model:
- Every ACP session has a generation number. Events carry it; anything from an older generation is dropped (a
  stale ``tools/call`` is answered ``isError`` at once and never handed to Hermes).
- ``self.lock`` guards state only and is never held while waiting on agy (spawn, session/new and the prompt run
  without it), so ``cancel()`` always gets it quickly.
- Callbacks from the connection reader / MCP threads never take ``self.lock`` except the deadline path, which is
  safe because those threads hold no connection lock.
Rule (plan component 4): a cancelled session is never prompted again; the next request starts a fresh session.
"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import re
import secrets
import shutil
import tempfile
import threading
import time
import unicodedata
from collections.abc import Callable
from dataclasses import replace
from typing import Any, TypeGuard

from .acp_connection import AcpConnection, AcpError
from .usage_contract import (
    context_limit_from_usage_update,
    first_turn_report_plausible,
    report_within_context_limit,
    reported_usage_growth_consistent,
    transcript_tokens,
    usage_update_valid,
    valid_context_limit,
)
from .matcher import (
    TurnView,
    IMAGE_PART_TYPES,
    _text,
    canonical_args,
    classify,
    explain_mismatch,
    fingerprint,
    images,
    project,
    trailing_tool_round,
    view_after,
)
from .parked_mcp import DEFAULT_DEADLINE_SECONDS, ParkedCall, ParkedMcpServer
from .permission import PermissionGate
from .session import AcpSession, new_session

logger = logging.getLogger(__name__)

STEP_DEADLINE_SECONDS = 90.0  # per model step (no ACP activity); no _await runs while Hermes executes a tool
COLLECT_WINDOW_SECONDS = 0.3  # gather near-simultaneous tools/call into one tool_calls (agy is sequential: S1b)
IDLE_TTL_SECONDS = 1800.0  # an idle conversation's warm agy child is reaped after this
GUARD_TEXT = "already executed; its result is in the conversation above"
NUDGE_TEXT = ("Your last reply was only {reply!r}, which looks cut off. Reply again with your complete answer to the "
              "user's latest request.")
GUARD_LOOP_TEXT = "The result of the last step is already in the conversation above; send 'continue' to proceed."
_SYS_MSG_RE = re.compile(r"<system-message>\n(.*?)\n</system-message>", re.DOTALL)
_SYS_MSG_DEDUPE_MIN_CHARS = 200
_SYS_MSG_OMITTED = "<system-message>(unchanged from earlier in this session)</system-message>"
_SYS_MSG_LATER = "<system-message>(same text is repeated in full later in this prompt)</system-message>"


def _sys_digests(text: str) -> set[str]:
    return {hashlib.sha256(m.group(1).encode("utf-8")).hexdigest() for m in _SYS_MSG_RE.finditer(text)
            if len(m.group(1)) >= _SYS_MSG_DEDUPE_MIN_CHARS}


def dedupe_system_messages(text: str, seen: set[str] | None, later: set[str] | frozenset[str] = frozenset()) -> str:
    """Replace large ``<system-message>`` blocks already sent in this ACP session with a one-line placeholder.

    ``later``: digests whose full copy appears later in the same prompt (replay renders ACTIVE_REQUEST and its
    progress before history, so the copy the model must act on stays complete and history copies point forward).
    Only called on outgoing text rendered for agy (never on matcher inputs), so prefix fingerprints stay exact.
    """
    if seen is None or "<system-message>" not in text:
        return text

    def repl(m: re.Match[str]) -> str:
        body = m.group(1)
        if len(body) < _SYS_MSG_DEDUPE_MIN_CHARS:
            return m.group(0)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        if digest in later:
            return _SYS_MSG_LATER
        if digest in seen:
            return _SYS_MSG_OMITTED
        seen.add(digest)
        return m.group(0)

    return _SYS_MSG_RE.sub(repl, text)


def degenerate(text: str) -> bool:
    """A final reply made only of punctuation (e.g. a lone ``}``): Gemini sometimes ends a long tool turn this way
    (seen 2026-11-23: 47 output tokens, content ``}``). Empty text is left to Hermes' own empty-reply handling."""
    stripped = text.strip()
    return bool(stripped) and len(stripped) <= 8 and all(unicodedata.category(c).startswith("P") for c in stripped)


# ---- usage semantics (ported from the old engine's verified contract; docs/acp-usage-telemetry.md) ----------
# ACP ``usage_update`` frames carry per-model-call consumption DELTA observations (``used``/``size``) whose
# server semantics are NOT verified — the canonical doc is explicit that ``used`` is not cumulative context
# occupancy and never billing. Reporting them as ``prompt_tokens`` makes every Hermes reader integrate
# frame snapshots as consumption (issue #6 class; #194 chain audit: 25.39M "tokens" that were a frame
# integral), so they are exposed ONLY as an explicitly unverified observation channel.
# ``completion.usage`` is fed ONLY by the server's own ``session/prompt`` result breakdown, and only after a
# growth-consistency gate against this adapter's local transcript estimate (2026-11-23 incident: a ~31K
# transcript reported as ~1.07M fired the Core compression gate twice early).
_CONTEXT_OBSERVATION_SOURCE = "acp.session/update:usage_update"
_USAGE_OBSERVATION_SEMANTICS = ("usage_update.used is per-model-call consumption delta, not billing usage "
                                "and not verified cumulative context occupancy; size is the context window")
_USAGE_SCOPE_UNVERIFIED = "unverified_server_semantics"  # no runtime verdict store here: label honestly
# Gate constants, tolerance, first-turn/growth decisions and the token
# estimator live in ONE owner shared with the Replay engine:
# ``usage_contract.py`` (issue #87 drift).  Do not re-fork them here.


def _nonnegative_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _consumption_from_prompt_result(result: dict[str, Any]) -> dict[str, int] | None:
    """The server's own per-turn breakdown from the ``session/prompt`` result; None when absent/invalid.

    Old-engine field contract (``_turn_usage_from_prompt_result``): ``inputTokens``, ``outputTokens`` and
    ``totalTokens`` are REQUIRED nonnegative ints — a report missing any of them is rejected whole, never
    patched with invented zeros or a locally summed total. ``thoughtTokens`` adds into output;
    ``totalTokens`` is forwarded exactly as reported; ``cachedReadTokens`` stays separate.
    """
    usage = result.get("usage")
    if not isinstance(usage, dict):
        return None
    required = ("inputTokens", "outputTokens", "totalTokens")
    optional = ("thoughtTokens", "cachedReadTokens")
    for name in required:
        if not _nonnegative_int(usage.get(name)):
            return None
    for name in optional:
        if usage.get(name) is not None and not _nonnegative_int(usage[name]):
            return None
    out = {"input_tokens": usage["inputTokens"],
           "output_tokens": usage["outputTokens"] + (usage.get("thoughtTokens") or 0),
           "total_tokens": usage["totalTokens"]}
    if usage.get("cachedReadTokens") is not None:
        out["cached_read_tokens"] = usage["cachedReadTokens"]
    return out


class ProviderError(RuntimeError):
    """Typed failure surfaced to Hermes; text never carries child stderr bytes."""


class CancelledByUser(ProviderError):
    """Hermes interrupted the request (``client.cancel()``); not retryable."""


class RateLimited(ProviderError):
    """agy's harness reported a 429 / RESOURCE_EXHAUSTED; not retried on another account."""


class StepTimeout(ProviderError):
    """No ACP activity for a whole model step."""


def mcp_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    out, seen = [], set()
    for entry in tools or []:
        fn = entry.get("function") if isinstance(entry, dict) and entry.get("type") == "function" else entry
        if not isinstance(fn, dict) or not fn.get("name") or fn["name"] in seen:
            continue
        seen.add(fn["name"])
        params = fn.get("parameters") if isinstance(fn.get("parameters"), dict) else {"type": "object"}
        out.append({"name": fn["name"], "description": str(fn.get("description") or ""), "inputSchema": params})
    return out


MAX_PROMPT_IMAGES = 8  # bounded: newest N attached; Hermes already replays only its recent window (default 3)
# MEASURED on agy_acp_server 1.5.2 (2026-11-24): USER_INPUT text is hard-truncated at 192,000 UTF-8 bytes,
# silently dropping everything after it (including <ACTIVE_REQUEST> at the tail). Keep replays safely below it.
MAX_REPLAY_BYTES = 180_000
_HISTORY_TOOL_TRIM_BYTES = 4_000


def _utf8_bytes(text: str) -> int:
    return len(text.encode("utf-8"))


def _utf8_head(text: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    return raw[:max_bytes].decode("utf-8", "ignore")


def _utf8_tail(text: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    tail = raw[-max_bytes:]
    i = 0
    while i < len(tail) and (tail[i] & 0xC0) == 0x80:
        i += 1
    return tail[i:].decode("utf-8", "ignore")


def _trim_utf8_middle(text: str, limit: int, label: str) -> str:
    raw_len = _utf8_bytes(text)
    if raw_len <= limit:
        return text
    note = f"\n[... truncated {raw_len - limit} bytes in {label} ...]\n"
    note_len = _utf8_bytes(note)
    if limit <= note_len + 16:
        return _utf8_head(text, max(0, limit))
    avail = limit - note_len
    head_cap = (avail * 6) // 10
    tail_cap = avail - head_cap
    head = _utf8_head(text, head_cap)
    tail = _utf8_tail(text, tail_cap)
    omitted = max(0, raw_len - _utf8_bytes(head) - _utf8_bytes(tail))
    note = f"\n[... truncated {omitted} bytes in {label} ...]\n"
    out = head + note + tail
    if _utf8_bytes(out) > limit:
        head = _utf8_head(head, max(0, head_cap - (_utf8_bytes(out) - limit)))
        out = head + note + tail
    return out


class _Images:
    """Numbers inline images in render order for one ACP session (same bytes = same number, numbering continues
    across prompts on that session) and builds each prompt's blocks with the images it has not attached yet.

    ``text`` marks image positions with a per-instance random sentinel, never with the visible ``[image #n]``: a user,
    the model or a tool can type that string, and it must not decide where an image lands. ``blocks`` turns every
    sentinel into the visible marker and puts each newly attached image right after its own sentinel."""

    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []
        self._index: dict[str, int] = {}
        self._sent = 0
        self._tag = "\x1eIMG" + secrets.token_hex(6) + ":"
        self._sentinel = re.compile(re.escape(self._tag) + r"(\d+)\x1f")

    def text(self, content: Any) -> str:
        if not isinstance(content, list) or not images(content):
            return _text(content)
        parts = []
        for part in content:
            if not isinstance(part, dict):
                parts.append(str(part))
            elif part.get("type") in IMAGE_PART_TYPES:
                img = images([part])
                if not img:
                    url = part.get("image_url")
                    url = url.get("url") if isinstance(url, dict) else url
                    parts.append(f"[image at {str(url)[:500]} (not attached; use a vision tool to view it)]" if url
                                 else "[image]")
                    continue
                n = self._index.get(img[0][1])
                if n is None:
                    self.items.append(img[0])
                    n = self._index[img[0][1]] = len(self.items)
                parts.append(f"{self._tag}{n}\x1f")
            else:
                parts.append(str(part.get("text") or part.get("type") or ""))
        return "\n".join(parts)

    def blocks(self, text: str) -> list[dict[str, Any]]:
        """Prompt blocks: each newly attached image sits right after its own marker, so the prompt keeps its order
        and its closing instruction stays last (images appended at the end were read as the request)."""
        first = max(self._sent, len(self.items) - MAX_PROMPT_IMAGES)
        note = ""
        if first > self._sent:
            skipped = f"#{self._sent + 1}" + (f"-#{first}" if first > self._sent + 1 else "")
            note = f"(image {skipped} not attached: only the newest {MAX_PROMPT_IMAGES} are)\n\n"
        out: list[dict[str, Any]] = []
        buf, pos, attached = note, 0, set()
        for m in self._sentinel.finditer(text):
            n = int(m.group(1))
            buf += text[pos:m.start()] + f"[image #{n}]"
            pos = m.end()
            if first < n <= len(self.items) and n not in attached:
                out.append({"type": "text", "text": buf})
                mime, data = self.items[n - 1]
                out.append({"type": "image", "mimeType": mime, "data": data})
                attached.add(n)
                buf = ""
        buf += text[pos:]
        if buf or not out:
            out.append({"type": "text", "text": buf})
        self._sent = len(self.items)
        return out


def _trim_content_with_images(content: Any, img_sink: _Images, cap: int, label: str) -> str:
    """Trim message content to at most ``cap`` UTF-8 bytes without leaving orphan image registrations."""
    if not isinstance(content, list) or not images(content):
        return _trim_utf8_middle(_text(content), cap, label)
    img_parts = [p for p in content if isinstance(p, dict) and p.get("type") in IMAGE_PART_TYPES and images([p])]
    # Each sentinel is ~22 bytes (and renders to a shorter "[image #n]" in blocks()); reserve 24 bytes per image.
    reserve = len(img_parts) * 24
    if cap <= reserve:
        return _trim_utf8_middle(_text(content), cap, label)
    markers = [img_sink.text([p]) for p in img_parts]
    marker_block = "\n".join(markers)
    text_budget = cap - _utf8_bytes(marker_block) - 1
    non_img = [p for p in content if not (isinstance(p, dict) and p.get("type") in IMAGE_PART_TYPES and images([p]))]
    plain = img_sink.text(non_img) if non_img else ""
    if not plain:
        return marker_block
    trimmed = _trim_utf8_middle(plain, max(0, text_budget), label)
    return f"{trimmed}\n{marker_block}" if trimmed else marker_block


def render_replay(messages: list[dict[str, Any]], imgs: _Images | None = None,
                  fence: str | None = None, seen_sys: set[str] | None = None,
                  max_bytes: int = MAX_REPLAY_BYTES) -> list[dict[str, Any]]:
    """Full replay for a fresh session as ACP prompt blocks; the system band rides at the top (no append).

    ``fence`` wraps tool output; a conversation passes its own (random once, then stable) so successive replays share
    a byte-identical prefix, which is meant to let the model provider's prefix cache hit (not measured).
    ``max_bytes`` keeps the rendered UTF-8 text below agy 1.5.2's 192,000-byte prompt cutoff so ``<ACTIVE_REQUEST>``
    is never silently truncated away; replays already within budget are rendered byte-identically."""
    msgs = [m for m in messages if isinstance(m, dict)]
    fence = fence or "TOOL-OUTPUT-" + secrets.token_hex(4)
    imgs = imgs if imgs is not None else _Images()
    system = [_text(m.get("content")) for m in msgs if m.get("role") == "system"]
    last_user = max((i for i, m in enumerate(msgs) if m.get("role") == "user"), default=-1)
    names: dict[str, Any] = {}
    for m in msgs:
        if m.get("role") == "assistant":
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                names[str(tc.get("id"))] = fn.get("name")

    def line(m: dict[str, Any], img_sink: _Images, *, tool_cap: int | None = None,
             line_cap: int | None = None) -> str:
        role = m.get("role")
        if role == "assistant":
            calls = []
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                calls.append(f"{fn.get('name')}({canonical_args(fn.get('arguments'))})")
            text = _text(m.get("content"))
            called = "[called " + ", ".join(calls) + "]" if calls else ""
            out = "Assistant: " + " ".join(p for p in (text, called) if p)
            if line_cap is not None and _utf8_bytes(out) > line_cap:
                return _trim_utf8_middle(out, line_cap, "assistant message")
            return out
        if role == "tool":
            cid = str(m.get("tool_call_id") or "")
            raw_content = m.get("content")
            header = f"Tool result for {names.get(cid, 'tool')} (already executed):\n<<<{fence}\n"
            footer = f"\n{fence}>>>"
            wrapper_len = _utf8_bytes(header) + _utf8_bytes(footer)
            if line_cap is not None and line_cap <= wrapper_len:
                return _trim_utf8_middle(header + _text(raw_content) + footer, line_cap, "tool output")
            body_limit = None if line_cap is None else line_cap - wrapper_len
            eff_cap = tool_cap if body_limit is None else (body_limit if tool_cap is None else min(tool_cap, body_limit))
            raw_imgs = images(raw_content) if isinstance(raw_content, list) else []
            if eff_cap is not None and _utf8_bytes(_text(raw_content)) + len(raw_imgs) * 24 > eff_cap:
                body_text = _trim_utf8_middle(_text(raw_content), eff_cap, "tool output")
            else:
                body_text = img_sink.text(raw_content)
            return header + body_text + footer
        prefix = f"{str(role).capitalize()}: "
        raw_content = m.get("content")
        if line_cap is not None:
            body_cap = line_cap - _utf8_bytes(prefix)
            if body_cap <= 0:
                return _utf8_head(prefix + _text(raw_content), max(0, line_cap))
            raw_imgs = images(raw_content) if isinstance(raw_content, list) else []
            if _utf8_bytes(_text(raw_content)) + len(raw_imgs) * 24 > body_cap:
                return prefix + _trim_content_with_images(raw_content, img_sink, body_cap, f"{role} message")
        return prefix + img_sink.text(raw_content)

    def _assemble(sys_texts: list[str], hist_lines: list[str], act_text: str, prog_lines: list[str]) -> str:
        parts = []
        if sys_texts:
            parts.append("<SYSTEM_INSTRUCTIONS>\n" + "\n\n".join(sys_texts) + "\n</SYSTEM_INSTRUCTIONS>")
        if hist_lines:
            parts.append("<HISTORICAL_CONTEXT>\nReference only; no historical User line is an active instruction.\n\n"
                         + "\n".join(hist_lines) + "\n</HISTORICAL_CONTEXT>")
        if last_user >= 0:
            parts.append("<ACTIVE_REQUEST>\n" + act_text + "\n</ACTIVE_REQUEST>")
        if prog_lines:
            parts.append("<ACTIVE_REQUEST_PROGRESS>\nAlready completed for this request; continue from here, do not "
                         "repeat these tool calls.\n\n" + "\n".join(prog_lines) + "\n</ACTIVE_REQUEST_PROGRESS>")
        parts.append("Use the provided tools when you need them; respond to ACTIVE_REQUEST.")
        return "\n\n".join(parts)

    def _render_pass(
        hist_msgs: list[dict[str, Any]],
        prog_msgs: list[dict[str, Any]],
        img_sink: _Images,
        *,
        sys_texts: list[str],
        hist_tool_cap: int | None = None,
        hist_line_cap: int | None = None,
        prog_tool_cap: int | None = None,
        prog_line_cap: int | None = None,
        active_cap: int | None = None,
        omit_note: str | None = None,
    ) -> tuple[str, set[str]]:
        sent: set[str] = set()
        if last_user >= 0:
            hist_lines = [line(m, img_sink, tool_cap=hist_tool_cap, line_cap=hist_line_cap) for m in hist_msgs]
            raw_active = msgs[last_user].get("content")
            if active_cap is not None:
                raw_imgs = images(raw_active) if isinstance(raw_active, list) else []
                if _utf8_bytes(_text(raw_active)) + len(raw_imgs) * 24 > active_cap:
                    act_text = _trim_content_with_images(raw_active, img_sink, active_cap, "active request")
                else:
                    act_text = img_sink.text(raw_active)
            else:
                act_text = img_sink.text(raw_active)
            prog_lines = [line(m, img_sink, tool_cap=prog_tool_cap, line_cap=prog_line_cap) for m in prog_msgs]
            later = frozenset(_sys_digests(act_text + "".join(prog_lines)))
            act_text = dedupe_system_messages(act_text, sent)
            prog_lines = [dedupe_system_messages(x, sent) for x in prog_lines]
            hist_lines = [dedupe_system_messages(x, sent, later) for x in hist_lines]
            if omit_note:
                hist_lines = [omit_note, *hist_lines]
        else:
            hist_lines, act_text = [], ""
            prog_lines = [
                dedupe_system_messages(line(m, img_sink, tool_cap=prog_tool_cap, line_cap=prog_line_cap), sent)
                for m in prog_msgs
            ]
        return _assemble(sys_texts, hist_lines, act_text, prog_lines), sent

    if last_user >= 0:
        raw_history = [m for m in msgs[:last_user] if m.get("role") != "system"]
        raw_progress = [m for m in msgs[last_user + 1:] if m.get("role") != "system"]
    else:
        raw_history = []
        raw_progress = [m for m in msgs if m.get("role") != "system"]

    # Reserve a small margin for any skipped-image header note added by _Images.blocks().
    target_max = max(0, int(max_bytes))
    margin = min(96, target_max // 4)
    budget = max(0, target_max - margin)
    probe_text, _ = _render_pass(raw_history, raw_progress, _Images(), sys_texts=system)
    orig_bytes = _utf8_bytes(probe_text)
    if orig_bytes <= budget:
        final_text, sent = _render_pass(raw_history, raw_progress, imgs, sys_texts=system)
        if seen_sys is not None:
            seen_sys.update(sent)
        return imgs.blocks(final_text)

    # Over budget: (1) shrink oversized historical tool/assistant messages first, (2) drop oldest historical turns,
    # (3) as last resort trim progress / system / active so <ACTIVE_REQUEST> is never amputated by agy.
    hist_tool_cap: int | None = min(_HISTORY_TOOL_TRIM_BYTES, max(256, budget // 8))
    hist_line_cap: int | None = hist_tool_cap
    prog_tool_cap: int | None = None
    prog_line_cap: int | None = None
    active_cap: int | None = None
    sys_texts = list(system)
    kept_history = list(raw_history)
    kept_progress = list(raw_progress)
    omit_note: str | None = None

    def _probe() -> str:
        text, _ = _render_pass(
            kept_history, kept_progress, _Images(), sys_texts=sys_texts,
            hist_tool_cap=hist_tool_cap, hist_line_cap=hist_line_cap,
            prog_tool_cap=prog_tool_cap, prog_line_cap=prog_line_cap,
            active_cap=active_cap, omit_note=omit_note,
        )
        return text

    candidate = _probe()
    if _utf8_bytes(candidate) > budget and kept_history:
        base_text, _ = _render_pass([], kept_progress, _Images(), sys_texts=sys_texts)
        base_bytes = _utf8_bytes(base_text)
        wrapper_overhead = _utf8_bytes(
            "\n\n<HISTORICAL_CONTEXT>\nReference only; no historical User line is an active instruction.\n\n"
            "[... 99999 earlier historical messages omitted to fit the replay byte budget ...]\n"
            "\n</HISTORICAL_CONTEXT>"
        )
        hist_budget = budget - base_bytes - wrapper_overhead
        if hist_budget <= 0:
            dropped = len(kept_history)
            kept_history = []
            omit_note = f"[... {dropped} earlier historical messages omitted to fit the replay byte budget ...]"
        else:
            scratch_imgs = _Images()
            act_probe = scratch_imgs.text(msgs[last_user].get("content")) if last_user >= 0 else ""
            prog_probe = [line(m, scratch_imgs) for m in kept_progress]
            later_probe = frozenset(_sys_digests(act_probe + "".join(prog_probe)))
            sent_probe: set[str] = set()
            dedupe_system_messages(act_probe, sent_probe)
            for p in prog_probe:
                dedupe_system_messages(p, sent_probe)
            line_sizes = [
                _utf8_bytes(dedupe_system_messages(
                    line(m, _Images(), tool_cap=hist_tool_cap, line_cap=hist_line_cap),
                    set(sent_probe), later_probe,
                )) + 1
                for m in kept_history
            ]
            used = 0
            keep_from = len(kept_history)
            for idx in range(len(kept_history) - 1, -1, -1):
                if used + line_sizes[idx] > hist_budget:
                    break
                used += line_sizes[idx]
                keep_from = idx
            dropped = keep_from
            kept_history = kept_history[keep_from:]
            if dropped > 0:
                omit_note = f"[... {dropped} earlier historical messages omitted to fit the replay byte budget ...]"

    candidate = _probe()
    while _utf8_bytes(candidate) > budget and kept_history:
        kept_history = kept_history[1:]
        dropped = len(raw_history) - len(kept_history)
        omit_note = f"[... {dropped} earlier historical messages omitted to fit the replay byte budget ...]"
        candidate = _probe()
    if _utf8_bytes(candidate) > budget and not kept_history and omit_note:
        omit_note = None
        candidate = _probe()

    prog_wrapper_overhead = _utf8_bytes(
        "\n\n<ACTIVE_REQUEST_PROGRESS>\nAlready completed for this request; continue from here, do not "
        "repeat these tool calls.\n\n\n</ACTIVE_REQUEST_PROGRESS>"
    )
    sys_wrapper_overhead = _utf8_bytes("<SYSTEM_INSTRUCTIONS>\n\n</SYSTEM_INSTRUCTIONS>\n\n")

    # Last-resort trimming if fixed sections (system + active + progress) alone exceed budget.
    if _utf8_bytes(candidate) > budget and kept_progress:
        prog_line_cap = min(_HISTORY_TOOL_TRIM_BYTES, max(128, budget // 4))
        prog_tool_cap = prog_line_cap
        candidate = _probe()
        while _utf8_bytes(candidate) > budget and len(kept_progress) > 1:
            kept_progress = kept_progress[1:]
            candidate = _probe()
        if _utf8_bytes(candidate) > budget and kept_progress:
            no_prog, _ = _render_pass(
                kept_history, [], _Images(), sys_texts=sys_texts,
                hist_tool_cap=hist_tool_cap, hist_line_cap=hist_line_cap,
                active_cap=active_cap, omit_note=omit_note,
            )
            avail_prog = budget - _utf8_bytes(no_prog) - prog_wrapper_overhead
            if avail_prog >= 64:
                prog_line_cap = prog_tool_cap = avail_prog
            elif last_user >= 0:
                kept_progress = []
            candidate = _probe()

    if _utf8_bytes(candidate) > budget and sys_texts:
        no_sys, _ = _render_pass(
            kept_history, kept_progress, _Images(), sys_texts=[],
            hist_tool_cap=hist_tool_cap, hist_line_cap=hist_line_cap,
            prog_tool_cap=prog_tool_cap, prog_line_cap=prog_line_cap,
            active_cap=active_cap, omit_note=omit_note,
        )
        avail_sys = budget - _utf8_bytes(no_sys) - sys_wrapper_overhead
        if avail_sys >= 32:
            sys_texts = [_trim_utf8_middle("\n\n".join(sys_texts), avail_sys, "system instructions")]
        else:
            sys_texts = []
        candidate = _probe()

    if _utf8_bytes(candidate) > budget and last_user >= 0:
        empty_act, _ = _render_pass(
            kept_history, kept_progress, _Images(), sys_texts=sys_texts,
            hist_tool_cap=hist_tool_cap, hist_line_cap=hist_line_cap,
            prog_tool_cap=prog_tool_cap, prog_line_cap=prog_line_cap,
            active_cap=0, omit_note=omit_note,
        )
        active_cap = max(0, budget - _utf8_bytes(empty_act))
        candidate = _probe()

    if _utf8_bytes(candidate) > budget and kept_progress:
        no_prog, _ = _render_pass(
            kept_history, [], _Images(), sys_texts=sys_texts,
            hist_tool_cap=hist_tool_cap, hist_line_cap=hist_line_cap,
            active_cap=active_cap, omit_note=omit_note,
        )
        avail_prog = budget - _utf8_bytes(no_prog) - prog_wrapper_overhead
        if avail_prog >= 16:
            prog_line_cap = prog_tool_cap = avail_prog
        else:
            kept_progress = []
        candidate = _probe()

    # Extreme tiny max_bytes where static XML wrapper tags alone exceed target_max: clamp without mutating imgs.
    if _utf8_bytes(candidate) > target_max:
        scratch = _Images()
        raw_cand, _ = _render_pass(
            kept_history, kept_progress, scratch, sys_texts=sys_texts,
            hist_tool_cap=hist_tool_cap, hist_line_cap=hist_line_cap,
            prog_tool_cap=prog_tool_cap, prog_line_cap=prog_line_cap,
            active_cap=active_cap, omit_note=omit_note,
        )
        plain_cand = scratch._sentinel.sub("[image]", raw_cand)
        final_text = _utf8_head(plain_cand, target_max)
        logger.warning(
            "acp-mcp replay clamped: %d -> %d UTF-8 bytes (max_bytes=%d)",
            orig_bytes, _utf8_bytes(final_text), target_max,
        )
        return imgs.blocks(final_text)

    # Final render against the caller's real _Images and seen_sys so dropped old history images are never attached.
    final_text, sent = _render_pass(
        kept_history, kept_progress, imgs, sys_texts=sys_texts,
        hist_tool_cap=hist_tool_cap, hist_line_cap=hist_line_cap,
        prog_tool_cap=prog_tool_cap, prog_line_cap=prog_line_cap,
        active_cap=active_cap, omit_note=omit_note,
    )
    if seen_sys is not None:
        seen_sys.update(sent)
    logger.warning(
        "acp-mcp replay trimmed: %d -> %d UTF-8 bytes (kept %d/%d history msgs)",
        orig_bytes, _utf8_bytes(final_text), len(kept_history), len(raw_history),
    )
    return imgs.blocks(final_text)


def render_delta(delta: list[dict[str, Any]], imgs: _Images | None = None,
                 seen_sys: set[str] | None = None) -> list[dict[str, Any]]:
    imgs = imgs if imgs is not None else _Images()
    text = "\n\n".join(dedupe_system_messages(imgs.text(m.get("content")), seen_sys)
                       for m in delta if isinstance(m, dict) and m.get("role") == "user")
    return imgs.blocks(text)


def tool_answer(content: Any, seen_sys: set[str] | None = None) -> tuple[str, list[tuple[str, str]]]:
    """A Hermes tool row's content as (text, inline images) for the parked MCP result."""
    return dedupe_system_messages(_text(content), seen_sys), images(content)


def _inflight_view(messages: list[dict[str, Any]]) -> TurnView:
    msgs = [m for m in messages if isinstance(m, dict)]
    return TurnView(consumed=len(msgs), prefix_fp=fingerprint(msgs), live=True, seen=tuple(project(m) for m in msgs))


class Conversation:
    def __init__(self, key: str, spawn: Callable[[str, str], AcpConnection], *, stateless: bool = False,
                 step_deadline: float = STEP_DEADLINE_SECONDS, call_deadline: float = DEFAULT_DEADLINE_SECONDS,
                 terminal_tools: frozenset[str] = frozenset(),
                 collect_window: float = COLLECT_WINDOW_SECONDS,
                 initial_conn: AcpConnection | None = None, cwd: str | None = None, owns_cwd: bool = False,
                 fence: str | None = None):
        self.key = key
        self._spawn = spawn  # (key, cwd) -> started + initialized AcpConnection
        self.stateless = stateless
        self.step_deadline = step_deadline
        self.call_deadline = call_deadline
        self.terminal_tools = frozenset(terminal_tools)
        self.collect_window = max(0.0, float(collect_window))
        # Only a directory this conversation created is deleted on close; a caller's cwd (or initial_conn's) is not.
        # close() deletes the cwd only if this conversation created it, or the caller hands ownership over
        # (owns_cwd=True, e.g. a pool's pre-warmed temp dir); a caller's own workspace is never deleted.
        self.cwd = cwd or (initial_conn.cwd if initial_conn is not None else None)
        self._owns_cwd = self.cwd is None or owns_cwd
        if self.cwd is None:
            self.cwd = tempfile.mkdtemp(prefix="acp-mcp-cwd-")  # empty dedicated dir (H1)
        self.lock = threading.RLock()  # state only; never held while waiting on agy
        self._spawn_lock = threading.Lock()  # serialises child spawn (outside self.lock)
        self.events: queue.Queue[tuple[int, str, Any]] = queue.Queue()
        self.gen = 0
        self.retire_reason = ""
        self.conn: AcpConnection | None = initial_conn
        self.server: ParkedMcpServer | None = None
        self.session: AcpSession | None = None
        self.prompt_thread: threading.Thread | None = None
        self.tools_fp = ""
        self.model = ""
        self.view = TurnView()
        self.handed: list[ParkedCall] = []
        self.guard: set[tuple[str, str]] = set()
        self.guard_refusals = 0
        self.owner_token: threading.Event | None = None
        self.text: list[str] = []
        self.reasoning: list[str] = []
        self.usage: dict[str, int] | None = None  # consumption: session/prompt RESULT breakdown only (gated)
        self.occupancy: dict[str, int | float] | None = None  # usage_update used/size: occupancy reading, never billing
        self.frame_usage: dict[str, int] | None = None  # usage_update token fields: telemetry only
        self._usage_baseline: tuple[int, int] | None = None  # (accepted reported input, local estimate)
        self._context_limit: int | None = None  # confirmed context window for the active model
        self._context_limit_model: str = ""
        self._context_limit_effective_model: str = ""
        self.images = _Images()  # image numbering of the current ACP session
        self._seen_sys_msgs: set[str] = set()  # sha256 of large <system-message> blocks already sent in this session
        self.fence = fence or "TOOL-OUTPUT-" + secrets.token_hex(4)  # unguessable to tool output, stable across replays
        self.nudged = False  # one re-ask per user turn after a degenerate final reply
        self.last_activity = time.monotonic()
        self.last_used = time.monotonic()
        self.closed = False

    # ---- public ---------------------------------------------------------------------------------------------

    def run(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None, model: str | None,
            token: threading.Event | None = None, thinking: str | None = None) -> dict:
        """Serve one create. Returns {"text", "reasoning", "tool_calls": [ParkedCall], "finish_reason"}."""
        started = self.begin(messages, tools, model, token, thinking)
        return started if "guest" in started else self.finish(started)

    def begin(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None, model: str | None,
              token: threading.Event | None = None, thinking: str | None = None,
              only: tuple[str, ...] | None = None) -> dict:
        """Classify and claim this conversation for one create without waiting on agy.

        Returns a handle for ``finish()``, ``{"guest": True}``, or ``{"declined": kind}`` when ``only`` is given and
        the decision is not in it (no state is touched then). Once a handle is returned the view is live, so a
        concurrent caller classifying this conversation sees it busy (the gateway's branch pool relies on this).
        """
        token = token or threading.Event()
        if token.is_set():
            raise CancelledByUser("request cancelled")
        tools_fp = json.dumps(mcp_tools(tools), sort_keys=True)
        need_open = False
        with self.lock:
            decision = classify(messages, self.view, tools)
            why = ""
            if decision.kind == "continue" and tools_fp != self.tools_fp:
                decision.kind, why = "replay", "tool list changed"  # fixed per session
            elif decision.kind == "continue" and f"{model or ''}|{thinking or ''}" != self.model:
                decision.kind, why = "replay", "model or thinking level changed"
            if decision.kind == "resume_held" and self.session is not None and not self.handed and self.view.live:
                # The held calls were already answered and that step is still running: this is a duplicate of the
                # request being served. Never retire the live step for it (that would fail the original request):
                # a pool caller (``only=``) moves it to another branch, a direct caller gets an error.
                if only is not None:
                    return {"declined": "duplicate", "why": "held calls already answered; step still running"}
                raise ProviderError("duplicate tool-result request while the step it answers is still running")
            if decision.kind == "resume_held" and (self.session is None or not self.handed):
                decision.kind = "replay"  # no session, or the held calls were already answered
            if decision.kind == "replay" and self.view.consumed and not why:
                why = ("session retired (" + self.retire_reason + ")" if self.view.retired
                       else explain_mismatch(messages, list(self.view.seen)))
            if only is not None and decision.kind not in only:
                return {"declined": decision.kind, "why": why}
            self.last_used = time.monotonic()
            logger.info("acp-mcp turn: %s%s", decision.kind, f" ({why})" if why else "")
            if decision.kind == "guest":
                return {"guest": True}
            if decision.kind != "resume_held":
                active_model = f"{str(model or '').strip()}|{str(thinking or '').strip()}"
                if active_model != self._context_limit_model:
                    self._context_limit = None
                    self._context_limit_model = active_model
                    self._context_limit_effective_model = ""
            self.owner_token = token
            if decision.kind == "resume_held":
                gen = self.gen
                if self.server is not None:
                    self.server.clear_completed(preserve_parked=True)
                for call in self.handed:
                    call.answer(*tool_answer(decision.tool_results.get(call.id, ""), self._seen_sys_msgs))
                self.handed = []
                self.last_activity = time.monotonic()
                self.text, self.reasoning, self.usage = [], [], None
                self.occupancy, self.frame_usage = None, None
            elif decision.kind == "continue":
                gen = self.gen
                self.nudged = False
                self.guard, self.guard_refusals = set(), 0
                self.view = _inflight_view(messages)
                self._start_prompt(gen, render_delta(decision.delta, self.images, self._seen_sys_msgs))
            else:  # supersede / replay
                self._retire("superseded" if decision.kind == "supersede" else "replay")
                gen = self.gen
                self.nudged = False
                self.view = _inflight_view(messages)  # live while opening: a concurrent /btw is a guest (F2)
                need_open = True
        return {"gen": gen, "need_open": need_open, "messages": messages, "tools": tools, "model": model,
                "tools_fp": tools_fp, "token": token, "thinking": thinking}

    def finish(self, h: dict, on_open: Callable[[], None] | None = None) -> dict:
        """Open the session if ``begin`` asked for it, then wait for the step result. ``on_open`` runs once the open
        attempt is over (success or failure); the gateway uses it to release its child-cap slot."""
        try:
            if h["need_open"]:
                self._open_interruptibly(h["gen"], h["messages"], h["tools"], h["model"], h["tools_fp"], h["token"],
                                         h["thinking"])
        finally:
            if on_open is not None:
                on_open()
        return self._await(h["messages"], h["gen"], h["token"])

    def _open_interruptibly(self, gen: int, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None,
                            model: str | None, tools_fp: str, token: threading.Event,
                            thinking: str | None = None) -> None:
        """Spawn/initialize/session-new can take tens of seconds: run them off-thread so cancel() returns within
        a poll interval (F1). A late-finishing open sees the generation moved on and cleans itself up."""
        done: dict[str, BaseException | None] = {}

        def opener() -> None:
            try:
                self._open_and_prompt(gen, messages, tools, model, tools_fp, token, thinking)
                done["error"] = None
            except BaseException as exc:  # noqa: BLE001 - re-raised on the create thread
                done["error"] = exc

        th = threading.Thread(target=opener, name=f"acp-open-{gen}", daemon=True)
        th.start()
        while th.is_alive():
            th.join(0.2)
            if token.is_set():
                raise self._fail(gen, "cancelled", CancelledByUser("request cancelled"))
            if self.gen != gen and th.is_alive():
                raise ProviderError("superseded by a newer request")
        error = done.get("error")
        if error is not None:
            with self.lock:
                if self.gen == gen:
                    self._retire("open-failed")  # not live any more: reapable, no phantom guest window
            if isinstance(error, ProviderError):
                raise error
            raise ProviderError(f"could not open an Antigravity session: {type(error).__name__}: {error}") from None

    def cancel(self, token: threading.Event | None = None) -> None:
        """Hermes interrupt (request-scoped facade ``cancel()``).

        User stop is TERMINAL for the conversation: the warm agy child is reaped,
        never kept. The vendor's compute stop after ``session/cancel`` is not
        observable here, and Core's request-slot worker may exit before a daemon
        retiree could signal the tree — so the interrupt path itself closes the
        connection (stdin EOF, terminate, kill; the reader thread reaps the
        zombie). Warm reuse across turns stays for supersede/deadline/replay.
        Fast in practice: no protocol response is awaited, only local signals.
        """
        if token is not None:
            token.set()
        conn, cwd, owns_cwd = None, None, False
        with self.lock:
            if token is None or self.owner_token is token:
                self._retire("cancelled")
                self.closed = True
                conn, self.conn = self.conn, None
                cwd, owns_cwd = self.cwd, self._owns_cwd
        try:
            if conn is not None:
                conn.close()
        finally:
            if owns_cwd and cwd is not None:
                shutil.rmtree(cwd, ignore_errors=True)

    def close(self) -> None:
        with self.lock:
            self.closed = True
            self._retire("close")
            conn, self.conn = self.conn, None
        try:
            if conn is not None:
                conn.close()
        finally:
            if self._owns_cwd:
                shutil.rmtree(self.cwd, ignore_errors=True)

    @property
    def live(self) -> bool:
        return self.view.live

    # ---- session lifecycle -----------------------------------------------------------------------------------

    def _connection(self) -> AcpConnection:
        with self._spawn_lock:
            with self.lock:
                conn = self.conn
            if conn is not None and not conn.exited:
                return conn
            if conn is not None:
                conn.close()
            conn = self._spawn(self.key, self.cwd)
            with self.lock:
                if not self.closed:
                    self.conn = conn
                    return conn
            conn.close()  # the conversation was closed while this child was spawning (e.g. a cancelled guest)
            raise CancelledByUser("conversation closed while starting Antigravity")

    def _open_and_prompt(self, gen: int, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None,
                         model: str | None, tools_fp: str, token: threading.Event,
                         thinking: str | None = None) -> None:
        """Open a fresh session for generation ``gen`` without holding self.lock, then install it."""
        conn = self._connection()
        server = ParkedMcpServer(mcp_tools(tools), lambda call: self._on_call(gen, call), deadline=self.call_deadline,
                                 on_deadline=lambda call: self._on_deadline(gen, call)).start()
        gate = PermissionGate(server.server_name, server.tool_names,
                              on_foreign_tool_call=lambda _u: self.events.put((gen, "foreign", None)),
                              on_our_tool_completed=server.mark_completed)
        try:
            session = new_session(conn, mcp_server=server.acp_mcp_server_config(), gate=gate, model=model,
                                  thinking=thinking)
        except Exception:
            server.close()
            raise
        abort: BaseException | None = None
        with self.lock:
            if self.gen != gen or token.is_set():  # cancelled or superseded while opening
                abort = CancelledByUser("request cancelled") if token.is_set() else ProviderError(
                    "superseded by a newer request")
            else:
                self.server, self.session = server, session
                self.tools_fp, self.model = tools_fp, f"{model or ''}|{thinking or ''}"
                effective_model = str(getattr(session, "effective_model", "") or "").strip()
                if effective_model:
                    if (
                        self._context_limit_effective_model
                        and effective_model != self._context_limit_effective_model
                    ):
                        self._context_limit = None
                    self._context_limit_effective_model = effective_model
                self.guard, self.guard_refusals = trailing_tool_round(messages), 0
                self.view = _inflight_view(messages)
                self.images = _Images()
                self._seen_sys_msgs = set()
                blocks = render_replay(messages, self.images, self.fence, self._seen_sys_msgs)
                logger.info("acp-mcp open: model=%s thinking=%s images=%d", model or "-", thinking or "-",
                            sum(1 for b in blocks if b.get("type") == "image"))
                self._start_prompt(gen, blocks)
        if abort is not None:
            server.retire()
            server.close()
            session.close()  # outside self.lock: session/close may wait on agy
            raise abort

    def _start_prompt(self, gen: int, blocks: list[dict[str, Any]]) -> None:  # lock held
        session = self.session
        assert session is not None
        if self.server is not None:
            self.server.clear_completed()
        self.text, self.reasoning, self.usage = [], [], None
        self.occupancy, self.frame_usage = None, None
        self.last_activity = time.monotonic()
        leftover: list[dict[str, Any]] = []
        while True:
            try:
                stale = session.updates.get_nowait()
            except queue.Empty:
                break
            if stale.get("sessionUpdate") != "usage_update":
                leftover.append(stale)
        for item in leftover:
            session.updates.put(item)

        def worker() -> None:
            try:
                self.events.put((gen, "end", session.prompt(blocks, timeout=None)))
            except Exception as exc:  # noqa: BLE001 - surfaced to the waiting create as a typed error
                self.events.put((gen, "error", exc))

        self.prompt_thread = threading.Thread(target=worker, name=f"acp-prompt-{gen}", daemon=True)
        self.prompt_thread.start()

    def _retire(self, reason: str) -> None:
        """Retire the current session without blocking (lock held). Always starts a new generation."""
        session, server, thread = self.session, self.server, self.prompt_thread
        self.session, self.server, self.prompt_thread = None, None, None
        self.gen += 1
        self.retire_reason = reason
        self.handed = []
        self.guard, self.guard_refusals = set(), 0
        self.view = replace(self.view, live=False, handed_out=(), retired=True)
        if session is None:
            return
        logger.info("acp-mcp: retiring session (%s)", reason)
        if server is not None:
            server.retire()
        try:
            session.cancel()
        except (AcpError, OSError):
            pass

        def release() -> None:  # M4: parked calls are released only after the prompt ended
            if thread is not None:
                thread.join(10.0)
            if server is not None:
                server.release_parked(reason, drop_connection=True)
                server.close()
            session.close()

        threading.Thread(target=release, name="acp-retire", daemon=True).start()

    # ---- callbacks (connection reader / MCP HTTP threads) -----------------------------------------------------

    def _on_call(self, gen: int, call: ParkedCall) -> None:
        if gen != self.gen:
            call.answer("session retired", is_error=True)  # straggler from a retired session (M1)
            return
        if (call.name, canonical_args(call.arguments)) in self.guard:
            self.guard_refusals += 1
            call.answer(GUARD_TEXT, is_error=True)  # replay guard: never handed to Hermes twice
            if self.guard_refusals >= 2:
                self.events.put((gen, "guard-loop", None))
            return
        self.last_activity = time.monotonic()
        self.events.put((gen, "call", call))

    def _on_deadline(self, gen: int, call: ParkedCall) -> None:  # before agy sees the isError (M4 order)
        with self.lock:
            if gen == self.gen:
                self._retire("deadline")

    # ---- waiting ---------------------------------------------------------------------------------------------

    def _drain_updates(self, gen: int) -> None:
        with self.lock:
            session = self.session if self.gen == gen else None
        if session is None:
            return
        while True:
            try:
                u = session.updates.get_nowait()
            except queue.Empty:
                return
            self.last_activity = time.monotonic()
            kind = u.get("sessionUpdate")
            content = u.get("content") or {}
            if kind == "agent_message_chunk" and content.get("type", "text") == "text":
                self.text.append(str(content.get("text") or ""))
            elif kind == "agent_thought_chunk" and content.get("type", "text") == "text":
                self.reasoning.append(str(content.get("text") or ""))
            elif kind == "usage_update":
                # Frames feed the OCCUPANCY and telemetry channels only; they never reach ``self.usage``
                # (consumption), which is fed exclusively by the session/prompt result breakdown.
                if usage_update_valid(u):
                    occ: dict[str, int | float] = dict(self.occupancy or {})
                    for key in ("used", "size"):
                        if key in u:
                            val = u[key]
                            occ[key] = (
                                int(val)
                                if isinstance(val, int) or float(val).is_integer()
                                else val
                            )
                    if occ:
                        self.occupancy = occ
                    limit = context_limit_from_usage_update(u)
                    if limit is not None:
                        with self.lock:
                            if self.gen == gen:
                                self._context_limit = limit
                fu: dict[str, int] = dict(self.frame_usage or {})
                for src_k, dst_k in (("inputTokens", "input_tokens"), ("outputTokens", "output_tokens"),
                                     ("input_tokens", "input_tokens"), ("output_tokens", "output_tokens")):
                    val = u.get(src_k)
                    if _nonnegative_int(val):
                        fu[dst_k] = int(val)
                if fu:
                    self.frame_usage = fu

    def _usage_observation(self) -> dict[str, Any] | None:
        """Latest ``usage_update`` frame readings as ONE explicitly-unverified observation channel.

        Never billing: the canonical doc labels these per-call deltas semantically unverified, and this
        adapter holds no runtime verdict store to promote them.
        """
        if not self.occupancy and not self.frame_usage:
            return None
        obs: dict[str, Any] = {"source": _CONTEXT_OBSERVATION_SOURCE, "scope": _USAGE_SCOPE_UNVERIFIED,
                               "semantics": _USAGE_OBSERVATION_SEMANTICS, "is_billing_usage": False}
        obs.update(self.occupancy or {})
        if self.frame_usage:
            obs["frame_tokens"] = dict(self.frame_usage)
        return obs

    def _gate_turn_consumption(self, result: dict[str, Any],
                               messages: list[dict[str, Any]],
                               *,
                               context_limit: Any = None) -> dict[str, int] | None:
        """Consumption for this turn: the prompt-result breakdown, gated on window cap & growth consistency.

        A rejected report yields ``None`` so Hermes falls back to its own token estimate instead of
        compacting against a number this adapter cannot vouch for; the last trusted baseline is kept,
        so a permanently inflated server keeps getting rejected.
        """
        consumption = _consumption_from_prompt_result(result)
        if consumption is None:
            return None
        reported = consumption["input_tokens"]
        effective_limit = getattr(self, "_context_limit", None) if context_limit is None else context_limit
        if not report_within_context_limit(reported=reported, context_limit=effective_limit):
            limit = valid_context_limit(effective_limit)
            logger.warning(
                "acp-mcp: reported inputTokens %d rejected: exceeds active model context window %s; "
                "Hermes falls back to its own token estimate this turn",
                reported,
                limit if limit is not None else effective_limit,
            )
            return None
        local = transcript_tokens(messages)
        baseline = self._usage_baseline
        if baseline is None:
            # First turn (or first after a restart): gate the absolute report
            # against the local transcript estimate (shared contract; the
            # Replay engine skipped this and shipped issue #87).  A rejected
            # first report leaves no baseline, so turn two is gated on its own.
            if not first_turn_report_plausible(reported=reported, local=local):
                logger.warning("acp-mcp: first-turn inputTokens %d rejected: diverges from local transcript "
                               "estimate %d beyond tolerance; Hermes falls back to its own estimate", reported, local)
                return None
            self._usage_baseline = (reported, local)
            return consumption
        ok, actual, expected = reported_usage_growth_consistent(
            prev_reported=baseline[0], reported=reported, prev_local=baseline[1], local=local)
        if ok:
            self._usage_baseline = (reported, local)
            return consumption
        logger.warning("acp-mcp: reported inputTokens rejected: server growth %d vs local estimate growth %d; "
                       "Hermes falls back to its own token estimate this turn", actual, expected)
        return None

    def _fail(self, gen: int, reason: str, exc: ProviderError, *, drop_conn: bool = False) -> ProviderError:
        with self.lock:
            if self.gen == gen:
                self._retire(reason)
            conn = None
            if drop_conn or (self.conn is not None and self.conn.exited):
                conn, self.conn = self.conn, None
        if conn is not None:
            conn.close()  # a fresh child next time (clears a sticky rate-limit flag, a dead process)
        return exc

    def _await(self, messages: list[dict[str, Any]], gen: int, token: threading.Event) -> dict:
        while True:
            if token.is_set():
                raise self._fail(gen, "cancelled", CancelledByUser("request cancelled"))
            if self.gen != gen:
                raise ProviderError(f"Antigravity session ended ({self.retire_reason})")
            self._drain_updates(gen)
            conn = self.conn
            if conn is not None and conn.saw_rate_limit:
                raise self._fail(gen, "rate-limit", RateLimited("Antigravity reported 429 RESOURCE_EXHAUSTED; "
                                                               "not retried"), drop_conn=True)
            try:
                egen, kind, payload = self.events.get(timeout=0.2)
            except queue.Empty:
                if time.monotonic() - self.last_activity > self.step_deadline:
                    raise self._fail(gen, "step-timeout", StepTimeout(
                        f"no Antigravity activity for {self.step_deadline:.0f}s")) from None
                continue
            if egen != gen:
                if kind == "call":
                    payload.answer("session retired", is_error=True)
                continue
            if kind == "call":
                calls = [payload] if payload.state == "parked" else []
                until = time.monotonic() + self.collect_window
                while (left := until - time.monotonic()) > 0:
                    try:
                        g2, k2, p2 = self.events.get(timeout=left)
                    except queue.Empty:
                        break
                    if g2 == gen and k2 == "call":
                        if p2.state == "parked":
                            calls.append(p2)
                    elif g2 == gen:
                        self.events.put((g2, k2, p2))
                        break
                if not calls:
                    continue
                self._drain_updates(gen)
                with self.lock:
                    if self.gen != gen or token.is_set():
                        continue  # retired/cancelled meanwhile: the loop top raises
                    self.handed = calls
                    self.view = view_after(messages, handed_out=tuple(c.id for c in calls), live=True)
                    if self.stateless:
                        self._retire("stateless-handout")  # children continue through replay (component 9)
                    elif self.terminal_tools and all(c.name in self.terminal_tools for c in calls):
                        self._retire("terminal-handout")  # caller ends on this tool (e.g. SubagentHandback)
                return {"text": "".join(self.text), "reasoning": "".join(self.reasoning), "tool_calls": calls,
                        "finish_reason": "tool_calls", "usage": None,
                        "usage_observation": self._usage_observation()}
            if kind == "end":
                self._drain_updates(gen)
                if payload.stop_reason == "cancelled":
                    raise self._fail(gen, "prompt-cancelled", CancelledByUser("prompt cancelled"))
                with self.lock:
                    if self.gen != gen:
                        continue
                    reply = "".join(self.text)
                    if not self.nudged and payload.stop_reason == "end_turn" and degenerate(reply):
                        self.nudged = True
                        logger.info("acp-mcp: degenerate final reply (%d chars); asking once more", len(reply))
                        self._start_prompt(gen, [{"type": "text", "text": NUDGE_TEXT.format(reply=reply.strip())}])
                        continue
                    self.guard, self.guard_refusals = set(), 0
                    self.view = view_after(messages)
                    if self.server is not None:
                        self.server.clear_completed()
                    self.usage = self._gate_turn_consumption(payload.result, messages)
                return {"text": "".join(self.text), "reasoning": "".join(self.reasoning), "tool_calls": [],
                        "finish_reason": payload.finish_reason, "usage": dict(self.usage) if self.usage else None,
                        "usage_observation": self._usage_observation()}
            if kind == "guard-loop":
                self._drain_updates(gen)
                with self.lock:
                    if self.gen == gen:
                        self._retire("guard-loop")
                    self.view = replace(view_after(messages), retired=True)
                return {"text": GUARD_LOOP_TEXT, "reasoning": "", "tool_calls": [], "finish_reason": "stop",
                        "usage": None,
                        "usage_observation": self._usage_observation()}
            if kind == "foreign":
                raise self._fail(gen, "native-tool", ProviderError("agy attempted a native tool; session cancelled"),
                                 drop_conn=True)
            # error
            raise self._fail(gen, "error", ProviderError(
                f"Antigravity ACP request failed: {type(payload).__name__}: {payload}"))


class Registry:
    """Process-global conversations keyed by the Hermes conversation key; idle ones are reaped."""

    def __init__(self, spawn: Callable[[str, str], AcpConnection], idle_ttl: float = IDLE_TTL_SECONDS):
        self._spawn = spawn
        self._idle_ttl = idle_ttl
        self._lock = threading.Lock()
        self._conversations: dict[str, Conversation] = {}

    def get(self, key: str) -> Conversation:
        if not key:
            return Conversation("", self._spawn, stateless=True)
        now = time.monotonic()
        with self._lock:
            idle = [k for k, c in self._conversations.items()
                    if k != key and not c.live and not c.closed and now - c.last_used > self._idle_ttl]
            reaped = [self._conversations.pop(k) for k in idle]
            conv = self._conversations.get(key)
            if conv is not None and conv.closed:
                # A cancelled conversation is terminal: its warm child is already
                # reaped; the next turn gets a fresh one carrying the same fence so
                # the rendered replay prefix stays byte-identical across the stop.
                conv = Conversation(key, self._spawn, fence=conv.fence)
                self._conversations[key] = conv
            elif conv is None:
                conv = self._conversations[key] = Conversation(key, self._spawn)
        for c in reaped:
            c.close()
        return conv

    def guest(self) -> Conversation:
        return Conversation("", self._spawn, stateless=True)

    def close_all(self) -> None:
        with self._lock:
            convs, self._conversations = list(self._conversations.values()), {}
        for conv in convs:
            conv.close()
