#!/usr/bin/env python3
"""Resilient entrypoint for the Antigravity ACP account mux.

The base mux intentionally ignores arbitrary model text when classifying provider
failures.  Google's Antigravity runtime has one special failure surface, though:
a provider failure can arrive as an ``agent_message_chunk`` whose text starts
with the vendor-generated ``Agent execution error`` sentinel, followed by a
successful JSON-RPC completion for ``session/prompt``.

Hermes would otherwise treat that sentinel as an ordinary model answer, so its
bounded provider failover loop never runs.  This entrypoint delegates the
entire relay lifecycle to ``acp_mux.main`` while supplying Antigravity-specific
failure classification, in-band turn buffering, and TOCTOU MCP config checks.

No Google credential files are read here.  Authentication remains entirely in
the official ACP runtime.
"""

from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
import re
import sys
import threading

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import acp_mux as base  # noqa: E402

_VENDOR_EXECUTION_PREFIX = (
    "Agent execution error: Agent execution terminated due to error."
)
# Exact vendor digests (verified against 1.2.1 sources, contract doc D-scan):
# ccpa_connection/quota_errors.py renders "Usage Limit Reached\n\nYou have
# reached your current quota for this period." and server.py renders
# "Agent connection was lost and could not be re-established: <error>".
# Both arrive as an agent_message_chunk followed by a successful prompt
# response, so they must be anchored at the very start of the turn text.
_VENDOR_QUOTA_SIGNATURE = (
    "Usage Limit Reached\n\n"
    "You have reached your current quota for this period."
)
_VENDOR_CONNECTION_PREFIX = (
    "Agent connection was lost and could not be re-established:"
)
_TURN_HEAD_LIMIT = 160
_VALIDATION_RE = re.compile(
    r"(?:\bVALIDATION_REQUIRED\b|verify your account to continue)", re.IGNORECASE
)
VALIDATION_COOLDOWN = float(os.environ.get("ACP_MUX_VALIDATION_COOLDOWN", "86400"))

_original_cooldown_for = base._cooldown_for


def _cooldown_for(kind: str) -> float:
    if kind == "validation":
        return VALIDATION_COOLDOWN
    return _original_cooldown_for(kind)


# _mark_failure resolves _cooldown_for from the base module at call time.
base._cooldown_for = _cooldown_for


def _classify_failure_text(text: str) -> str | None:
    if _VALIDATION_RE.search(text):
        return "validation"
    return base._classify_failure(text)


def _classify_structured_error(line: str) -> tuple[str, str] | None:
    failure = base._classify_json_error(line)
    if failure is None:
        return None
    kind, detail = failure
    if _VALIDATION_RE.search(detail):
        kind = "validation"
    return kind, detail


def _classify_vendor_execution_error_payload(
    payload: object,
) -> tuple[str, str] | None:
    """Classify only the exact vendor-generated execution-error message chunk.

    Normal model output is deliberately not scanned.  This accepts only an ACP
    ``session/update`` agent-message chunk whose text starts with Antigravity's
    fixed execution-error sentinel and also contains a known failover signal.
    """
    if not isinstance(payload, dict) or payload.get("method") != "session/update":
        return None
    params = payload.get("params")
    if not isinstance(params, dict):
        return None
    update = params.get("update")
    if not isinstance(update, dict):
        return None
    if str(update.get("sessionUpdate") or "").strip() != "agent_message_chunk":
        return None
    content = update.get("content")
    if not isinstance(content, dict):
        return None
    text = str(content.get("text") or "").strip()
    if not text.startswith(_VENDOR_EXECUTION_PREFIX):
        return None
    kind = _classify_failure_text(text)
    if kind is None:
        return None
    return kind, text


def _classify_inband_turn_head(head: str) -> tuple[str, str] | None:
    """Classify only vendor digests anchored at the very start of a turn.

    Quoted text, code blocks, and mid-answer mentions are position-anchored
    away: the turn buffer starts at the first character of the first
    agent-message chunk, so an ordinary answer cannot trip this check.
    """
    if head.startswith(_VENDOR_QUOTA_SIGNATURE):
        return "quota", head[:_TURN_HEAD_LIMIT]
    if head.startswith(_VENDOR_CONNECTION_PREFIX):
        return "connection-lost", head[:_TURN_HEAD_LIMIT]
    return None


def _could_extend_into_digest(head: str) -> bool:
    for signature in (_VENDOR_QUOTA_SIGNATURE, _VENDOR_CONNECTION_PREFIX):
        if len(head) < len(signature) and signature.startswith(head):
            return True
    return False


def _inband_provider_error(
    request_id: object, kind: str, detail: str, replay_safe: bool
) -> str:
    if kind == "quota" and replay_safe:
        # ``resource_exhausted`` is the marker the Hermes client classifies as
        # a retryable provider-quota error for its bounded failover.
        message = (
            f"Antigravity provider {kind} failure (resource_exhausted): {detail}"
        )
    elif kind == "quota":
        # A quota digest arriving after native tool activity means effects
        # may already exist; do not offer the client a retryable marker.
        message = (
            f"Antigravity provider {kind} failure: the turn already executed "
            "native tool calls; automatic replay is suppressed."
        )
    elif kind == "connection-lost":
        # The official server already attempted an internal reconnect and may
        # have executed native tools before the loss, so this message is
        # deliberately phrased so the client does not auto-replay the prompt.
        message = (
            "Antigravity provider connection-lost failure: turn aborted after "
            "a failed reconnect; automatic replay is suppressed."
        )
    else:
        message = f"Antigravity provider {kind} failure: {detail}"
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32000, "message": message},
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ) + "\n"


def _mcp_guard_error(request_id: object, violation: str) -> str:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32000,
                "message": f"Antigravity global MCP config guard: {violation}",
            },
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ) + "\n"


def _jsonrpc_provider_error(request_id: object, failure: tuple[str, str]) -> str:
    kind, detail = failure
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32000,
                "message": f"Antigravity provider {kind} failure: {detail}",
            },
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ) + "\n"


class _AntigravityRelayGuard:
    """Antigravity-specific sentinel/digest detection and TOCTOU MCP guard."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending_prompt_id: object | None = None
        self._failed_prompt_ids: set[object] = set()
        self._turn_head = ""
        self._held_lines: list[str] = []
        self._turn_hold_open = False
        self._failed_turn_active = False
        self._turn_tool_activity = 0

    def classify_stderr(self, text: str) -> str | None:
        return _classify_failure_text(text)

    def before_upstream(
        self,
        payload: object,
        method: str,
        request_id: object,
        bound_home: str,
        bound_label: str,
    ) -> str | None:
        if method == "session/prompt" and request_id is not None:
            with self._lock:
                self._pending_prompt_id = request_id
                self._turn_head = ""
                self._held_lines.clear()
                self._turn_hold_open = True
                self._failed_turn_active = False
                self._turn_tool_activity = 0

        config_id = ""
        if isinstance(payload, dict) and method == "session/set_config_option":
            params = payload.get("params")
            if isinstance(params, dict):
                config_id = str(params.get("configId") or "").strip().lower()
        if request_id is not None and (
            method in ("session/new", "session/resume", "session/load")
            or method == "session/set_model"
            or (method == "session/set_config_option" and config_id == "model")
        ):
            # TOCTOU re-check: a global MCP config written after bind-time
            # validation must still never reach the official server's merge on
            # session creation or model rebuilds.
            violation = base.mcp_config_violation(
                base.pinned_gemini_home(bound_home)
            )
            if violation is not None:
                base._mark_failure(
                    bound_home, bound_label, "mcp-config", violation
                )
                return _mcp_guard_error(request_id, violation)
        return None

    def on_upstream_stdout(
        self,
        line: str,
        bound_home: str,
        bound_label: str,
        after_cb: Callable[[str], str],
    ) -> list[str]:
        try:
            payload: object = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            payload = None

        with self._lock:
            chunk_text: str | None = None
            if (
                isinstance(payload, dict)
                and payload.get("method") == "session/update"
            ):
                params = payload.get("params")
                update = params.get("update") if isinstance(params, dict) else None
                if isinstance(update, dict):
                    kind = str(update.get("sessionUpdate") or "").strip()
                    if kind in ("tool_call", "tool_call_update"):
                        self._turn_tool_activity += 1
                    if self._failed_turn_active and kind in (
                        "agent_message_chunk",
                        "agent_thought_chunk",
                    ):
                        # Suppress the remainder of an already-failed turn.
                        return []
                    if kind == "agent_message_chunk" and self._turn_hold_open:
                        content = update.get("content")
                        chunk_text = (
                            str(content.get("text") or "")
                            if isinstance(content, dict)
                            else ""
                        )

            embedded = _classify_vendor_execution_error_payload(payload)
            if embedded is not None:
                base._mark_failure(
                    bound_home, bound_label, embedded[0], embedded[1]
                )
                request_id = self._pending_prompt_id
                if request_id is not None:
                    self._pending_prompt_id = None
                    self._failed_prompt_ids.add(request_id)
                    self._failed_turn_active = True
                    self._held_lines.clear()
                    self._turn_hold_open = False
                    # Do not expose the vendor failure sentinel as model output.
                    return [_jsonrpc_provider_error(request_id, embedded)]

            structural = _classify_structured_error(line)
            if structural is not None:
                base._mark_failure(
                    bound_home, bound_label, structural[0], structural[1]
                )

            if chunk_text is not None and self._turn_hold_open:
                self._turn_head = (self._turn_head + chunk_text)[:_TURN_HEAD_LIMIT]
                self._held_lines.append(line)
                failure = _classify_inband_turn_head(self._turn_head)
                if failure is not None:
                    base._mark_failure(
                        bound_home, bound_label, failure[0], failure[1]
                    )
                    request_id = self._pending_prompt_id
                    if request_id is not None:
                        self._pending_prompt_id = None
                        self._failed_prompt_ids.add(request_id)
                    self._failed_turn_active = True
                    self._held_lines.clear()
                    self._turn_hold_open = False
                    if request_id is not None:
                        return [
                            _inband_provider_error(
                                request_id,
                                *failure,
                                replay_safe=self._turn_tool_activity == 0,
                            )
                        ]
                    return []
                if (
                    len(self._turn_head) >= _TURN_HEAD_LIMIT
                    or not _could_extend_into_digest(self._turn_head)
                ):
                    released = list(self._held_lines)
                    self._held_lines.clear()
                    self._turn_hold_open = False
                    return released
                return []

            if isinstance(payload, dict):
                response_id = payload.get("id")
                if response_id in self._failed_prompt_ids:
                    # The prompt was already failed synthetically above;
                    # suppress the official runtime's trailing success reply.
                    self._failed_prompt_ids.discard(response_id)
                    self._failed_turn_active = False
                    return []
                if (
                    self._pending_prompt_id is not None
                    and response_id == self._pending_prompt_id
                ):
                    self._pending_prompt_id = None
                    released = list(self._held_lines)
                    self._held_lines.clear()
                    self._turn_hold_open = False
                    released.append(after_cb(line))
                    return released

            return [after_cb(line)]


def main() -> int:
    return base.main(relay_guard=_AntigravityRelayGuard())


if __name__ == "__main__":
    raise SystemExit(main())
