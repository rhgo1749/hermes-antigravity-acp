"""Permission gate (PlanC component 3, M2) and the detection-only native-tool tripwire (H1).

The gate allows a ``session/request_permission`` only for an MCP tool call to THIS
session's server and a tool in the active set, and only through an ``allow_once``
option. It never matches on titles and never picks ``allow_always``.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Collection
from typing import Any

from .acp_connection import CANCELLED_OUTCOME
from .parked_mcp import signature_key

log = logging.getLogger(__name__)
_MAX_TRACKED_SIG_KEYS = 1024


def _our_meta(meta: Any, server_name: str, tool_names: Collection[str]) -> bool:
    if not isinstance(meta, dict) or meta.get("is_mcp_tool_call") is not True:
        return False
    mcp = meta.get("mcp")
    return (
        isinstance(mcp, dict)
        and mcp.get("server") == server_name
        and mcp.get("tool") in tool_names
    )


def _bounded_equal(
    a: Any,
    b: Any,
    *,
    max_nodes: int = 4096,
    max_depth: int = 64,
) -> bool:
    """Iterative, depth- and node-bounded structural equality (exact type for bool vs int)."""
    stack: list[tuple[Any, Any, int]] = [(a, b, 0)]
    nodes = 0
    while stack:
        x, y, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            return False
        if isinstance(x, bool) or isinstance(y, bool):
            if type(x) is not type(y) or x != y:
                return False
            continue
        if isinstance(x, dict) and isinstance(y, dict):
            if len(x) != len(y):
                return False
            next_depth = depth + 1
            if x and (next_depth > max_depth or nodes + len(stack) + len(x) > max_nodes):
                return False
            for k, vx in x.items():
                if k not in y:
                    return False
                stack.append((vx, y[k], next_depth))
            continue
        if (isinstance(x, list) and isinstance(y, list)) or (
            isinstance(x, tuple) and isinstance(y, tuple)
        ):
            if len(x) != len(y):
                return False
            next_depth = depth + 1
            if x and (next_depth > max_depth or nodes + len(stack) + len(x) > max_nodes):
                return False
            for vx, vy in zip(x, y, strict=True):
                stack.append((vx, vy, next_depth))
            continue
        if isinstance(x, (dict, list, tuple)) or isinstance(y, (dict, list, tuple)):
            return False
        try:
            if x != y:
                return False
        except (TypeError, ValueError, RecursionError):
            return False
    return True


def _dedupe_sigs(candidates: list[bytes | None]) -> tuple[bytes, ...]:
    out: list[bytes] = []
    seen: set[bytes] = set()
    for sig in candidates:
        if sig is not None and sig not in seen:
            seen.add(sig)
            out.append(sig)
    return tuple(out)


def _extract_sig_keys(tool_name: str, raw_input: Any) -> tuple[bytes, ...]:
    """Extract ordered candidate signature keys from ACP ``rawInput``.

    Handles wrapped ``{"arguments": <inner>, ...<flattened>}`` shapes safely without
    allowing an unwrapped tool argument named ``"arguments"`` to match an unrelated call.
    """
    try:
        if not isinstance(raw_input, dict) or not raw_input:
            return ()
        if (
            len(raw_input) == 1
            and "arguments" in raw_input
            and raw_input["arguments"] is None
        ):
            return _dedupe_sigs(
                [signature_key(tool_name, {}), signature_key(tool_name, raw_input)]
            )
        inner = raw_input.get("arguments")
        if isinstance(inner, dict):
            is_wrapper = len(raw_input) == 1
            if not is_wrapper:
                expected_len = len(inner) + (0 if "arguments" in inner else 1)
                if len(raw_input) == expected_len and raw_input.keys() == (
                    inner.keys() | {"arguments"}
                ):
                    is_wrapper = all(
                        _bounded_equal(raw_input[k], inner[k])
                        for k in inner
                        if k != "arguments"
                    )
            if is_wrapper:
                return _dedupe_sigs(
                    [signature_key(tool_name, inner), signature_key(tool_name, raw_input)]
                )
        return _dedupe_sigs([signature_key(tool_name, raw_input)])
    except Exception:  # noqa: BLE001 - defensive: rawInput is untrusted ACP wire data
        return ()


class PermissionGate:
    def __init__(
        self,
        server_name: str,
        tool_names: Collection[str],
        on_foreign_tool_call: Callable[[dict[str, Any]], None] | None = None,
        on_our_tool_completed: Callable[[str, tuple[bytes, ...]], None] | None = None,
    ) -> None:
        self.server_name = server_name
        self.tool_names = frozenset(tool_names)
        self._on_foreign = on_foreign_tool_call
        self._on_our_completed = on_our_tool_completed
        self._lock = threading.Lock()
        self._ours: set[str] = set()  # toolCallIds first seen carrying our _meta
        self._our_tools: dict[str, str] = {}  # toolCallId -> our tool name
        self._our_sig_keys: dict[str, tuple[bytes, ...]] = {}  # toolCallId -> candidate sig_keys
        self._completed_ours: set[str] = set()  # toolCallIds already reported completed
        self._titles: dict[str, str] = {}  # foreign toolCallId -> title (for the log line only)

    def _store_sig_keys_locked(self, call_id: str, sig_keys: tuple[bytes, ...]) -> None:
        if call_id in self._completed_ours or not sig_keys:
            return
        self._our_sig_keys[call_id] = sig_keys
        while len(self._our_sig_keys) > _MAX_TRACKED_SIG_KEYS:
            self._our_sig_keys.pop(next(iter(self._our_sig_keys)), None)

    def decide(self, params: dict[str, Any]) -> dict[str, Any]:
        """Response result for a ``session/request_permission`` request."""
        tool_call = params.get("toolCall") if isinstance(params.get("toolCall"), dict) else {}
        options = [o for o in params.get("options") or [] if isinstance(o, dict)]
        allowed = _our_meta(tool_call.get("_meta"), self.server_name, self.tool_names)
        for kind in ("allow_once", "reject_once") if allowed else ("reject_once",):
            for option in options:
                if option.get("kind") == kind and option.get("optionId"):
                    if kind == "allow_once":
                        call_id = str(tool_call.get("toolCallId") or "")
                        if call_id:
                            tool_name = str(tool_call["_meta"]["mcp"]["tool"])
                            raw_input = tool_call.get("rawInput")
                            with self._lock:
                                already_completed = call_id in self._completed_ours
                            extracted_sigs = (
                                _extract_sig_keys(tool_name, raw_input)
                                if not already_completed and isinstance(raw_input, dict) and raw_input
                                else ()
                            )
                            with self._lock:
                                prev_tool = self._our_tools.get(call_id)
                                self._ours.add(call_id)
                                self._our_tools[call_id] = tool_name
                                if (
                                    prev_tool is not None
                                    and prev_tool != tool_name
                                    and not extracted_sigs
                                ):
                                    self._our_sig_keys.pop(call_id, None)
                                if extracted_sigs:
                                    self._store_sig_keys_locked(call_id, extracted_sigs)
                    return {"outcome": {"outcome": "selected", "optionId": option["optionId"]}}
        return CANCELLED_OUTCOME

    def observe_update(self, update: dict[str, Any]) -> None:
        """Tripwire, best effort: native tools may emit no ``tool_call`` update at all.

        Fires only when a call that is not ours reaches ``in_progress`` or ``completed`` (it actually runs).
        A disabled native tool the model merely tries arrives as ``pending``/``failed`` (live 2026-11-23:
        ``write_to_file`` attempted and refused) and is only logged: cancelling there cost a full replay.
        """
        kind = update.get("sessionUpdate")
        if kind not in ("tool_call", "tool_call_update"):
            return
        call_id = str(update.get("toolCallId") or "")
        status = str(update.get("status") or "")
        title = str(update.get("title") or "")[:60]
        raw_input = update.get("rawInput")
        has_raw_input = isinstance(raw_input, dict) and bool(raw_input)
        is_ours_meta = _our_meta(update.get("_meta"), self.server_name, self.tool_names)
        meta_tool = str(update["_meta"]["mcp"]["tool"]) if is_ours_meta else ""

        hash_tool = ""
        if call_id and has_raw_input:
            with self._lock:
                if call_id not in self._completed_ours:
                    if is_ours_meta:
                        prev_tool = self._our_tools.get(call_id)
                        if (
                            status != "completed"
                            or call_id not in self._our_sig_keys
                            or prev_tool != meta_tool
                        ):
                            hash_tool = meta_tool
                    elif call_id in self._ours:
                        known_tool = self._our_tools.get(call_id) or ""
                        if known_tool and (
                            status != "completed" or call_id not in self._our_sig_keys
                        ):
                            hash_tool = known_tool

        extracted_sigs = _extract_sig_keys(hash_tool, raw_input) if hash_tool else ()

        completed_tool: str | None = None
        completed_sigs: tuple[bytes, ...] = ()
        foreign = False
        log_title = "-"
        with self._lock:
            if is_ours_meta:
                if call_id:
                    prev_tool = self._our_tools.get(call_id)
                    self._ours.add(call_id)
                    self._our_tools[call_id] = meta_tool
                    if prev_tool is not None and prev_tool != meta_tool and not extracted_sigs:
                        self._our_sig_keys.pop(call_id, None)
                    if extracted_sigs and (
                        status != "completed"
                        or call_id not in self._our_sig_keys
                        or (prev_tool is not None and prev_tool != meta_tool)
                    ):
                        self._store_sig_keys_locked(call_id, extracted_sigs)
                    if status == "completed" and call_id not in self._completed_ours:
                        self._completed_ours.add(call_id)
                        completed_tool = meta_tool
                        completed_sigs = self._our_sig_keys.pop(call_id, ())
            elif call_id and call_id in self._ours:
                if (
                    extracted_sigs
                    and self._our_tools.get(call_id) == hash_tool
                    and (status != "completed" or call_id not in self._our_sig_keys)
                ):
                    self._store_sig_keys_locked(call_id, extracted_sigs)
                if status == "completed" and call_id not in self._completed_ours:
                    self._completed_ours.add(call_id)
                    completed_tool = self._our_tools.get(call_id)
                    completed_sigs = self._our_sig_keys.pop(call_id, ())
            else:
                if call_id and title:
                    self._titles[call_id] = title
                log_title = (self._titles.get(call_id) if call_id else title) or "-"
                foreign = True

        if completed_tool and self._on_our_completed:
            self._on_our_completed(completed_tool, completed_sigs)
        if foreign:
            log.warning("acp-mcp: native tool_call %s status=%s title=%s", kind, status or "-", log_title)
            if status in ("in_progress", "completed") and self._on_foreign:
                self._on_foreign(update)
