#!/usr/bin/env python3
"""Live ACP canary: exercises the real harness client against the official Antigravity ACP server.

This is an opt-in, operator-run tool. It authenticates through the official
server's own account home; the harness never reads credentials. Frames written
to the evidence log are sanitized: secrets are redacted, command bodies and
file contents are replaced by length markers, and tool outputs keep only
bounded summary lines (never full file contents).

Modes:
  default      run the client exactly as the current default Hermes
               model-provider policy does (reproduction of the denial chain)
  raw-probe    isolated, permission-denying JSON-RPC probe (never a Hermes
               provider E2E). Requires explicit command and fresh evidence.
  raw-allow    disabled historical alias; cannot run any subprocess.

Engines (--mode default only):
  replay       legacy flat client; the historical default, behavior frozen.
  parked       issue #93: the deployed Parked-MCP provider/client driven
               through its Hermes-facing facade (model discovery and
               selection success, plain response, one harmless harness-owned
               MCP tool parked inside a single held prompt with a unique
               sentinel proving delivery, same-conversation follow-up, usage
               contract through the shared gate, containment declaration and
               native-permission enforcement, cancellation, teardown).  The
               whole parked run is bounded by --timeout and its children are
               cancelled and reaped on expiry.  Requires exactly one
               execution lane: --fake-acp-only (explicit fake ACP binary;
               engine env/launcher resolution disabled) or
               --operator-supervised-live (attended terminal + typed
               approval; never CI).  Parked exit codes: 0 all verdicts pass,
               1 error or fail, 2 refused preflight, 3 inconclusive (the run
               did NOT fully verify the contract).  See docs/live-canary.md.

Evidence correlation: every frame keeps the JSON-RPC id (in strict
raw-probe mode a server-chosen id persists only as a deterministic
``num_<sha256[:12]>`` correlation token, so equal ids still join across
frames without the literal), and tool activity is
keyed by toolCallId, so a permission request, the harness answer, the
resulting tool_call_update status, and any pre-tool-hook denial are all tied
to one id.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import logging
import os
import queue
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import types
from pathlib import Path
from typing import Any, Callable

PROMPT = (
    "Complete these steps in order, then answer DONE_STEPS.\n"
    "1. Read calc.py.\n"
    "2. Create helpers.py containing exactly: def add2(a, b): return a + b\n"
    "3. Edit calc.py so add() returns add2(a, b) and the file imports add2 from helpers.\n"
    "4. Run the test suite with run_command using: python3 -m pytest -q\n"
    "5. Run git diff --stat with run_command and copy its output into your answer.\n"
    "Use your native ACP tools for every step; do not ask for approval and do "
    "not output Hermes-style tool_call blocks.\n"
)

# Issue #13 item 1 profile: a neutral mutation-plus-command task that makes
# native tools the model's natural first choice WITHOUT instructing the model
# toward or away from any tool class (the issue's canary spec forbids forcing
# or forbidding tools in the prompt text).
NEUTRAL_PROMPT = (
    "Workspace task: calc.py defines add(a, b). Create helpers.py containing "
    "exactly: def add2(a, b): return a + b. Then edit calc.py so add() imports "
    "add2 from helpers and returns add2(a, b). Then run ./run_tests.sh in the "
    "workspace and copy its final summary line verbatim into your answer. "
    "Use whichever tools you judge best for each step.\n"
)

# Issue #13 items 2/3: a same-conversation follow-up. Sent as a second
# completion over [user, assistant, user] history, it exercises the plugin's
# affinity resume path against the live server and asks for the exact test
# summary line (item 2's completion evidence).
FOLLOW_UP_PROMPT = (
    "Report the exact final summary line produced by the test run in the "
    "previous step, verbatim. Do not redo completed work.\n"
)

CANARY_CALC = "def add(a, b):\n    return a + b\n"
CANARY_TEST = '''import unittest

from calc import add


class CalcTest(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)


if __name__ == "__main__":
    unittest.main()
'''
# The 2026-11-12 run's 12-round cap was a PATH artifact (no pytest on the
# workspace PATH). This runner keeps a runnable test command on PATH in every
# environment: pytest when importable, stdlib unittest otherwise.
CANARY_RUNNER = (
    "#!/bin/sh\n"
    "if python3 -c 'import pytest' >/dev/null 2>&1; then\n"
    "    python3 -m pytest -q\n"
    "else\n"
    "    python3 -m unittest -q\n"
    "fi\n"
)


# Issue #93: the Parked-MCP lane advertises exactly ONE harmless,
# harness-owned MCP tool.  The driver answers the parked call with a canned
# string; nothing is executed on the host in any lane.
PARKED_CANARY_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "canary_echo",
        "description": (
            "Harmless canary probe owned by the test harness: echoes the "
            "given text back verbatim. It never touches the host."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "token to echo back"},
            },
            "required": ["text"],
        },
    },
}

PARKED_PROMPT = (
    "Call the canary_echo tool exactly once with text=\"ping-42\", then tell "
    "me in one short sentence what it returned."
)

PARKED_FOLLOW_UP_PROMPT = (
    "What exact token did canary_echo return a moment ago? Reply with just "
    "that token."
)


_BRIDGE_TERMINAL_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "terminal",
        "description": (
            "Run a shell command in the workspace via the Hermes approval-gated "
            "terminal tool."
        ),
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
}


_BRIDGE_FACT_MAX_CHARS = 300


def _bridge_tool_call_facts(
    completion: Any, phase: str, clean_text: Callable[[str], str]
) -> list[dict[str, Any]]:
    """Record (never execute) Hermes-bridge tool calls the model emitted.

    The plugin converts ``<tool_call>`` blocks into OpenAI-shaped
    ``message.tool_calls``.  A non-empty list is the bridge-transition fact
    issue #13 goal 1 asks for; execution belongs to the Hermes core, never
    to this driver.  Model-authored arguments are secret-redacted through
    the run's established clean_text redactor and length-bounded before
    they reach summary.json, exactly like the error field.  The helper
    assumes the plugin's SimpleNamespace-shaped completion contract (the
    same contract ``message.content`` access already assumes).
    """
    facts: list[dict[str, Any]] = []
    try:
        message = completion.choices[0].message
    except (AttributeError, IndexError, TypeError):
        return facts
    for call in getattr(message, "tool_calls", None) or []:
        function = getattr(call, "function", None)
        if function is None:
            continue
        facts.append({
            "phase": phase,
            "name": str(getattr(function, "name", "") or ""),
            "arguments": clean_text(
                str(getattr(function, "arguments", "") or "")
            )[:_BRIDGE_FACT_MAX_CHARS],
        })
    return facts


def prepare_workspace(cwd: str) -> list[str]:
    """Create the canary task files; never overwrite existing files."""
    created: list[str] = []
    for name, body in (
        ("calc.py", CANARY_CALC),
        ("test_calc.py", CANARY_TEST),
        ("run_tests.sh", CANARY_RUNNER),
    ):
        path = Path(cwd) / name
        if path.exists():
            continue
        path.write_text(body, encoding="utf-8")
        if name == "run_tests.sh":
            # Only files this function created get their mode changed.
            path.chmod(0o755)
        created.append(name)
    return created

SUMMARY_RE = re.compile(
    r"\b\d+ (?:passed|failed|error[s]?|skipped|deselected)\b[^\n]{0,80}"
)
PATH_KEYS = (
    "absolute_path", "path", "filePath", "file_path", "filename", "file",
    "directory_path",
)
LONG_STRING_CAP = 180
# The evidence files may eventually be shared. No server-controlled string
# value may be persisted verbatim unless it is an exact member of a finite
# set of protocol constants. Key membership alone is never trusted: hostile
# servers may send arbitrary text under legitimate field names. The sets
# below were verified against the official ACP v1 specification
# (agentclientprotocol.com: protocol/v1/prompt-turn SessionUpdate +
# StopReason tables, protocol/v1/tool-calls ToolKind + ToolCallStatus +
# PermissionOptionKind, protocol/v1/content ContentBlock types, plus the
# ToolCallContent "content"/"diff"/"terminal" variants) and against the
# pinned-vendor contract in hermes-plugin/antigravity-acp/client.py
# (_DOCUMENTED_PERMISSION_OPTION_KINDS, the lower-cased stopReason
# handling, the agent_message_chunk/agent_thought_chunk sinks, and the
# session/new + session/resume + session/set_model + session/prompt
# request sequence this driver itself speaks). Unknown values fail closed
# into {chars, sha256} fingerprints. Identifier strings such as
# name/toolName carry server-chosen text and are always fingerprinted.
_VERIFIED_JSONRPC_VERSIONS = frozenset({"2.0"})
_VERIFIED_PROTOCOL_METHODS = frozenset({
    "initialize", "session/new", "session/load", "session/resume",
    "session/set_model", "session/prompt", "session/cancel",
    "session/update", "session/request_permission",
    "fs/read_text_file", "fs/write_text_file",
})
_VERIFIED_SESSION_UPDATES = frozenset({
    "user_message_chunk", "agent_message_chunk", "agent_thought_chunk",
    "tool_call", "tool_call_update", "plan", "available_commands_update",
    "current_mode_update", "config_option_update", "session_info_update",
    "usage_update", "notice", "compaction_update",
    "compaction_summary_chunk",
})
_VERIFIED_STOP_REASONS = frozenset({
    "end_turn", "max_tokens", "max_turn_requests", "refusal", "cancelled",
})
_VERIFIED_CONTENT_TYPES = frozenset({
    "text", "image", "audio", "resource", "resource_link",
    "content", "diff", "terminal",
})
_VERIFIED_TOOL_KINDS = frozenset({
    "read", "edit", "delete", "move", "search", "execute", "think",
    "fetch", "switch_mode", "other",
})
_VERIFIED_PERMISSION_OPTION_KINDS = frozenset({
    "allow_once", "allow_always", "reject_once", "reject_always",
})
_VERIFIED_TOOL_STATUSES = frozenset(
    {"pending", "in_progress", "completed", "failed"}
)
# Strict raw-probe recursion contexts. Numeric protocol controls are only
# legitimate at their exact JSON-RPC 2.0 / ACP v1 position: the request id
# at the envelope top level, protocolVersion directly inside the params or
# result body of an envelope, and error.code directly inside the error
# object. Anywhere else ("untrusted") a number, boolean or null arrives
# under a name that does not own that control and must fail closed.
_CTX_ENVELOPE = "rpc-envelope"
_CTX_BODY = "rpc-body"
_CTX_ERROR = "rpc-error"
_CTX_UNTRUSTED = "untrusted"
_ENVELOPE_BODY_KEYS = frozenset({"params", "result"})
# ACP v1 pins protocolVersion 1 (this driver itself sends protocolVersion
# 1 in initialize). Any other integer is a future or hostile value and
# fails closed until explicitly allowlisted.
_VERIFIED_PROTOCOL_VERSIONS = frozenset({1})
# JSON-RPC 2.0 error codes: the five predefined codes plus the
# -32000..-32099 range reserved for implementation-defined server errors.
# Only integers inside this finite, spec-verified set may persist verbatim.
_VERIFIED_JSONRPC_ERROR_CODES = frozenset(
    {-32700, -32600, -32601, -32602, -32603}
) | frozenset(range(-32099, -31999))
# The finite set of request ids this driver's send_request() call sites
# generate (initialize=1, session/new=2, session/set_model or
# session/prompt=3, session/prompt=4). Envelope ids outside this set are
# server-chosen and persist only as deterministic correlation tokens.
_VERIFIED_CLIENT_REQUEST_IDS = frozenset({1, 2, 3, 4})
# (context, member name) -> the finite set of integers that may persist
# verbatim in strict raw-probe evidence at that exact position. Position is
# part of trust: the same member name outside its protocol context carries
# server-chosen data and fails closed like any unknown field.
_VERIFIED_PROTOCOL_NUMBERS: dict[tuple[str, str], frozenset] = {
    (_CTX_BODY, "protocolVersion"): _VERIFIED_PROTOCOL_VERSIONS,
    (_CTX_ERROR, "code"): _VERIFIED_JSONRPC_ERROR_CODES,
}
# Field name -> the finite set of exact string values that may survive
# verbatim in strict raw-probe evidence. "kind" is the union of the two
# verified enums that legitimately appear under that key (ToolKind on
# tool_call updates, PermissionOptionKind on permission options).
_VERIFIED_PROTOCOL_VALUES: dict[str, frozenset[str]] = {
    "jsonrpc": _VERIFIED_JSONRPC_VERSIONS,
    "method": _VERIFIED_PROTOCOL_METHODS,
    "sessionUpdate": _VERIFIED_SESSION_UPDATES,
    "stopReason": _VERIFIED_STOP_REASONS,
    "type": _VERIFIED_CONTENT_TYPES,
    "kind": _VERIFIED_TOOL_KINDS | _VERIFIED_PERMISSION_OPTION_KINDS,
    "status": _VERIFIED_TOOL_STATUSES,
}
_SECRET_FIELD_FRAGMENTS = (
    "sessionid", "token", "cookie", "password", "secret", "credential",
    "authorization", "account", "email", "username", "homedir",
)
# Finite allowlist of JSON object member NAMES that may persist verbatim in
# strict raw-probe evidence. Member names are server-controlled data: an
# adversarial ACP server can smuggle identifiers or incident text into keys.
# Any name outside this set is replaced by a deterministic key_<sha256[:12]>
# alias (see _key_alias) before persistence, in every nesting level. The set
# was verified against the official ACP v1 specification (JSON-RPC 2.0
# envelope; protocol/v1/prompt-turn session/prompt members; protocol/v1/
# content ContentBlock members; protocol/v1/tool-calls ToolCall/
# PermissionRequest members incl. rawInput/rawOutput/locations) and against
# the pinned-vendor contract in hermes-plugin/antigravity-acp/client.py
# (toolCallId, sessionUpdate, toolCall, toolName, origin, rawInput, _meta,
# optionId, outcome member reads) plus the member names this driver's own
# analyze_frames() and run_raw_allow() send_request() call sites speak.
_VERIFIED_STRUCTURAL_KEYS = frozenset({
    # JSON-RPC 2.0 envelope
    "jsonrpc", "id", "method", "params", "result", "error", "code", "message",
    # ACP v1 initialization / session / prompt-turn
    "protocolVersion", "sessionId", "update", "sessionUpdate", "stopReason",
    "prompt", "modelId", "cwd", "mcpServers",
    # ACP v1 content blocks
    "content", "text", "type", "uri", "mimeType", "data",
    # ACP v1 tool-calls / permissions (plus vendor-contract member reads)
    "toolCall", "toolCallId", "toolName", "name", "title", "origin",
    "kind", "status", "rawInput", "rawOutput", "locations", "path",
    "options", "optionId", "outcome",
    # members this driver itself sends (finite, verified at its call sites)
    "clientCapabilities", "clientInfo", "fs", "readTextFile", "writeTextFile",
    "version",
    # documented ACP extensibility member
    "_meta",
})


def _redact_factory(client_module: Any):
    redact = getattr(client_module, "_redact_acp_error_detail", None)

    def clean_text(text: str) -> str:
        if redact is not None:
            text = redact(text) or ""
        return text

    return clean_text


# The parked lane's loopback MCP endpoint carries per-run secrets in the URL
# path (parked_mcp._path); the path must never persist even though the host
# and port are harmless.
_LOOPBACK_MCP_URL_RE = re.compile(
    r"(?P<origin>https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?)/(?P<path>[^\s\"']*)"
)


class _ParkedRedactor:
    """Parked-lane redactor: the plugin's own ACP error redactor plus
    per-run dynamic secrets learned from the frames themselves.

    Session ids and the loopback MCP bearer/path are minted per run and have
    no fixed shape, so pattern redaction alone cannot catch them when they
    resurface inside server responses.  The sanitizer registers each raw
    value the moment it first appears (and replaces it structurally there);
    every later occurrence in any frame, log line or summary field is
    replaced by the same redactor.  Reuses the replay engine's
    ``_redact_acp_error_detail`` for the fixed secret shapes (Bearer,
    secret assignments, bare tokens, OAuth URLs) rather than duplicating it.
    """

    def __init__(self, base: Any) -> None:
        self._base = base
        self._extra: set[str] = set()

    def add_secret(self, value: Any) -> None:
        if isinstance(value, str) and len(value) >= 8:
            self._extra.add(value)

    def __call__(self, text: Any) -> str:
        if not isinstance(text, str):
            return ""
        if self._base is not None:
            text = self._base(text) or ""
        for secret in sorted(self._extra, key=len, reverse=True):
            text = text.replace(secret, "<run-secret>")
        text = _LOOPBACK_MCP_URL_RE.sub(
            lambda m: m.group("origin") + "/<path-redacted>", text)
        return text


_SECRET_HEADER_NAMES = {"authorization", "proxy-authorization", "x-api-key", "api-key"}


def _redact_structural(node: Any, redactor: _ParkedRedactor) -> Any:
    """Replace per-run secret-bearing protocol members at every nesting level.

    Returns a structure safe to hand to the legacy sanitizer; the raw values
    are registered with the redactor first so free-text mentions in later
    frames are covered too.
    """
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key == "sessionId" and isinstance(value, str) and value:
                redactor.add_secret(value)
                out[key] = "sess_" + hashlib.sha256(
                    value.encode("utf-8", errors="replace")).hexdigest()[:12]
            elif key == "url" and isinstance(value, str):
                match = _LOOPBACK_MCP_URL_RE.fullmatch(value.strip())
                if match:
                    redactor.add_secret(match.group("path"))
                    out[key] = match.group("origin") + "/<path-redacted>"
                else:
                    out[key] = value
            elif key == "headers" and isinstance(value, list):
                safe: list[Any] = []
                for item in value:
                    if (isinstance(item, dict)
                            and str(item.get("name", "")).lower()
                            in _SECRET_HEADER_NAMES):
                        redactor.add_secret(str(item.get("value", "")))
                        item = {**item, "value": "<redacted>"}
                    safe.append(item)
                out[key] = safe
            else:
                out[key] = _redact_structural(value, redactor)
        return out
    if isinstance(node, list):
        return [_redact_structural(item, redactor) for item in node]
    return node


def _make_parked_sanitizer(redactor: _ParkedRedactor):
    """Parked-lane frame sanitizer: structural secret registration on top of
    the established default-mode sanitizer (which is kept byte-compatible
    for the replay lane)."""

    def sanitize_parked(frame: Any, clean_text: Any) -> Any:
        return _sanitize(_redact_structural(frame, redactor), clean_text)

    return sanitize_parked


def _teardown_verdict(exited: list[bool]) -> str:
    """Direct-children teardown verdict: a child we spawned that we could
    not confirm exited is a FAILURE, not an inconclusive observation."""
    if not exited:
        return "inconclusive"
    return "pass" if all(exited) else "fail"


class CanaryTimeout(Exception):
    """The parked run exceeded its wall-clock --timeout budget."""


def _sanitize(frame: Any, clean_text: Any) -> Any:
    """Legacy sanitizer for default-mode evidence.

    Keep this behavior stable: analyze_frames() depends on structural strings
    such as toolCallId, permission kinds, paths and cwd. The stricter raw probe
    uses _sanitize_raw_protocol() instead.
    """
    if isinstance(frame, dict):
        out: dict[str, Any] = {}
        for key, value in frame.items():
            if key in {"rawOutput", "output", "stdout", "stderr"}:
                out[key] = _sanitize_tool_output(value, clean_text)
            elif key in {"newText", "oldText"} and isinstance(value, str):
                # structured diff bodies are file contents: never log them
                out[key + "_len"] = len(value)
            elif key == "rawInput" and isinstance(value, dict):
                safe: dict[str, Any] = {}
                for rk, rv in value.items():
                    if rk in PATH_KEYS and isinstance(rv, str):
                        safe[rk] = clean_text(rv)[:200]
                    elif isinstance(rv, str):
                        safe[rk + "_len"] = len(rv)
                    elif isinstance(rv, (int, float, bool)) or rv is None:
                        safe[rk] = rv
                    else:
                        safe[rk + "_type"] = type(rv).__name__
                out[key] = safe
            elif key in {"content", "text"} and isinstance(value, str):
                out[key] = clean_text(value)[:LONG_STRING_CAP]
                if len(value) > LONG_STRING_CAP:
                    out[key + "_len"] = len(value)
            elif key == "headers" and isinstance(value, list):
                # MCP server headers ride as [{name, value}] pairs; an
                # Authorization value (e.g. the parked loopback bearer token)
                # is a secret in every lane.
                safe_headers = []
                for item in value:
                    if (isinstance(item, dict)
                            and str(item.get("name", "")).lower()
                            in {"authorization", "proxy-authorization",
                                "x-api-key", "api-key"}):
                        item = {**item, "value": "<redacted>"}
                    safe_headers.append(_sanitize(item, clean_text))
                out[key] = safe_headers
            else:
                out[key] = _sanitize(value, clean_text)
        return out
    if isinstance(frame, list):
        return [_sanitize(item, clean_text) for item in frame[:40]]
    if isinstance(frame, str):
        text = clean_text(frame)
        return text if len(text) <= LONG_STRING_CAP else text[:LONG_STRING_CAP] + "…"
    return frame


def _sanitize_tool_output(value: Any, clean_text: Any) -> Any:
    """Keep only bounded summary lines from tool results; never full outputs."""
    if isinstance(value, str):
        text = clean_text(value)
        summaries = SUMMARY_RE.findall(text)
        entry: dict[str, Any] = {"summary_lines": summaries[:6], "chars": len(text)}
        if len(text) <= 160:
            entry["text"] = "".join(ch for ch in text if 32 <= ord(ch) < 127)[:160]
        return entry
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if isinstance(item, str) and len(item) > 80:
                summaries = SUMMARY_RE.findall(clean_text(item))
                out[key] = {"summary_lines": summaries[:6], "chars": len(item)}
            elif isinstance(item, str):
                out[key] = clean_text(item)[:160]
            else:
                out[key] = _sanitize_tool_output(item, clean_text)
        return out
    return _sanitize(value, clean_text)


def _string_fingerprint(value: str) -> dict[str, Any]:
    return {
        "chars": len(value),
        "sha256": hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest(),
    }


def _primitive_fingerprint(value: Any) -> dict[str, Any]:
    """Fail-closed marker for an untrusted non-string JSON primitive.

    Booleans carry one exfiltratable bit each and a hash of a bool would
    only disguise it (there are two possible digests), so the bit itself is
    discarded. Numbers keep only a SHA-256 over their canonical JSON text,
    so equal values stay comparable across frames without persisting the
    value. ``null`` never reaches this helper: it carries zero bits and is
    preserved as ``None`` by the callers.
    """
    if isinstance(value, bool):
        return {"value_type": "bool"}
    return {
        "value_type": type(value).__name__,
        "sha256": hashlib.sha256(
            json.dumps(value).encode("utf-8", errors="replace")
        ).hexdigest(),
    }


def _correlation_token(value: Any) -> str:
    """Deterministic hashable stand-in for a server-chosen JSON-RPC id.

    The literal integer never persists, but equal ids keep one shared
    token across frames, which is all analyze_frames() needs to join a
    permission request with its harness answer.
    """
    return "num_" + hashlib.sha256(
        json.dumps(value).encode("utf-8", errors="replace")
    ).hexdigest()[:12]


def _child_context(key: Any, context: str) -> str:
    """Recursion context for a dict member value. Protocol numeric controls
    exist only one level inside their envelope position; anything deeper,
    or anything not reached through that exact position, is untrusted."""
    if context != _CTX_ENVELOPE:
        return _CTX_UNTRUSTED
    if key == "error":
        return _CTX_ERROR
    if key in _ENVELOPE_BODY_KEYS:
        return _CTX_BODY
    return _CTX_UNTRUSTED


def _key_alias(key: Any) -> str:
    """Deterministic safe member name for anything outside the allowlist.

    The server-chosen name is never persisted; the 12-hex SHA-256 prefix
    keeps the same hostile key comparable across runs for diagnostics.
    """
    raw = key if isinstance(key, str) else json.dumps(
        key, ensure_ascii=False, sort_keys=True
    )
    return "key_" + hashlib.sha256(
        raw.encode("utf-8", errors="replace")
    ).hexdigest()[:12]


def _sanitize_raw_protocol(frame: Any, clean_text: Any, *, context: str = _CTX_ENVELOPE) -> Any:
    """Strict raw-probe evidence: verified protocol constants and names only.

    Fail-closed covers every JSON type, not just strings. A string survives
    verbatim only when it is an exact member of the finite allowlist for
    its field name; an integer survives verbatim only when it is a type-
    correct member of the finite numeric control set for its field name at
    its exact protocol position (``_VERIFIED_PROTOCOL_NUMBERS`` /
    ``_VERIFIED_CLIENT_REQUEST_IDS``); a boolean never survives (its single
    bit is discarded); ``null`` survives because it carries zero
    information. Every other server-controlled primitive — including one
    sent under a known field name via type confusion, nested in a list, or
    smuggled under a known-looking member name in a hostile context — is
    reduced to a fingerprint under a ``<key>_meta`` name (or, for a
    server-chosen envelope id, a ``num_<sha256[:12]>`` correlation token so
    evidence stays joinable). Object member NAMES are server-controlled
    too: only ``_VERIFIED_STRUCTURAL_KEYS`` persist; every other key —
    arbitrary, nested, or secret-fragment — is replaced by a
    ``key_<sha256[:12]>`` alias at every nesting level, so hostile member
    names can never reach evidence either.
    """
    if isinstance(frame, dict):
        out: dict[str, Any] = {}
        for key, value in frame.items():
            known = isinstance(key, str) and key in _VERIFIED_STRUCTURAL_KEYS
            normalized = key.lower().replace("_", "") if isinstance(key, str) else ""
            secret_bearing = any(
                fragment in normalized for fragment in _SECRET_FIELD_FRAGMENTS
            )
            if not known:
                safe_key = _key_alias(key)
                if secret_bearing:
                    out[safe_key] = "<redacted>"
                elif isinstance(value, str):
                    out[safe_key + "_meta"] = _string_fingerprint(clean_text(value))
                elif value is None:
                    out[safe_key] = None
                elif isinstance(value, (bool, int, float)):
                    out[safe_key + "_meta"] = _primitive_fingerprint(value)
                else:
                    out[safe_key] = _sanitize_raw_protocol(
                        value, clean_text, context=_CTX_UNTRUSTED
                    )
            elif secret_bearing:
                out[key] = "<redacted>"
            elif isinstance(value, str):
                allowed = _VERIFIED_PROTOCOL_VALUES.get(key)
                if allowed is not None and value in allowed:
                    out[key] = value
                else:
                    out[key + "_meta"] = _string_fingerprint(clean_text(value))
            elif key == "id" and context == _CTX_ENVELOPE and value is not None:
                # JSON-RPC envelope request id. Ids from this driver's own
                # finite set are driver data and persist verbatim; every
                # other integer is server-chosen and persists only as a
                # deterministic correlation token. Type-confused id values
                # (bool/float) are not ids at all and fail closed.
                if type(value) is int:
                    out[key] = (
                        value if value in _VERIFIED_CLIENT_REQUEST_IDS
                        else _correlation_token(value)
                    )
                elif isinstance(value, (bool, float)):
                    out[key + "_meta"] = _primitive_fingerprint(value)
                else:
                    out[key] = _sanitize_raw_protocol(
                        value, clean_text, context=_CTX_UNTRUSTED
                    )
            else:
                allowed_numbers = _VERIFIED_PROTOCOL_NUMBERS.get((context, key))
                if allowed_numbers is not None and type(value) is int:
                    if value in allowed_numbers:
                        out[key] = value
                    else:
                        out[key + "_meta"] = _primitive_fingerprint(value)
                elif value is None:
                    out[key] = None
                elif isinstance(value, (bool, int, float)):
                    out[key + "_meta"] = _primitive_fingerprint(value)
                else:
                    out[key] = _sanitize_raw_protocol(
                        value, clean_text, context=_child_context(key, context)
                    )
        return out
    if isinstance(frame, list):
        return [
            _sanitize_raw_protocol(item, clean_text, context=_CTX_UNTRUSTED)
            for item in frame[:40]
        ]
    if isinstance(frame, str):
        return _string_fingerprint(clean_text(frame))
    if frame is None:
        return None
    return _primitive_fingerprint(frame)


class FrameRecorder:
    def __init__(
        self,
        path: Path,
        clean_text: Any,
        *,
        sanitizer: Any = _sanitize,
        denial_fact_bits: bool = False,
    ) -> None:
        self._fh = path.open("x", encoding="utf-8")
        self._clean = clean_text
        self._sanitize = sanitizer
        # Pre-sanitization denial presence bits are a default-mode evidence
        # extension only; the strict raw-probe evidence format stays bit-exact
        # to its pre-existing contract.
        self._denial_fact_bits = denial_fact_bits
        self.frames: list[dict[str, Any]] = []

    def record(self, direction: str, payload: str) -> None:
        try:
            frame = json.loads(payload)
        except json.JSONDecodeError:
            frame = {"unparsed_len": len(payload)}
        entry = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "dir": direction,
            "frame": self._sanitize(frame, self._clean),
        }
        if self._denial_fact_bits:
            # A denial marker can ride inside a long server error string that
            # the sanitizer collapses into summary lines; keep only the
            # boolean fact, never the text. Scoped to inbound
            # session/update tool-activity frames' rawOutput so unrelated
            # fields cannot trigger a false positive.
            if (
                direction == "in"
                and isinstance(frame, dict)
                and frame.get("method") == "session/update"
            ):
                params = frame.get("params")
                update = params.get("update") if isinstance(params, dict) else None
                if (
                    isinstance(update, dict)
                    and str(update.get("sessionUpdate") or "").startswith("tool_call")
                ):
                    try:
                        scoped_text = json.dumps(
                            update.get("rawOutput"), ensure_ascii=False
                        )
                    except (TypeError, ValueError):
                        scoped_text = ""
                    if "denied by pre-tool hook" in scoped_text:
                        entry["pre_tool_hook_denial_fact"] = True
                    if "denied by user" in scoped_text:
                        entry["server_denied_by_user_fact"] = True
        self.frames.append(entry)
        self._fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._fh.flush()


class _StdinTee:
    def __init__(self, stream: Any, recorder: FrameRecorder) -> None:
        self._stream = stream
        self._recorder = recorder

    def write(self, data: str) -> int:
        self._recorder.record("out", data)
        return self._stream.write(data)

    def flush(self) -> None:
        self._stream.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


class _StdoutTee:
    def __init__(self, stream: Any, recorder: FrameRecorder) -> None:
        self._stream = stream
        self._recorder = recorder

    def __iter__(self):
        for line in self._stream or ():
            self._recorder.record("in", line)
            yield line

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)


def load_client_module(repo_root: Path):
    plugin_dir = repo_root / "hermes-plugin" / "antigravity-acp"

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    registered: list[Any] = []
    providers.register_provider = registered.append
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    # The fake registry is only needed while the plugin package is exec'd.
    # A surrounding pytest process may already have imported the real
    # ``providers`` package; overwriting it without restoring leaks the fake
    # into ``sys.modules`` and breaks every later test that imports the real
    # registry (e.g. the vanilla seam tests).
    shadowed = {
        name: module
        for name, module in sys.modules.items()
        if name == "providers" or name.startswith("providers.")
    }
    sys.modules["providers"] = providers
    sys.modules["providers.base"] = providers_base

    module_name = "acp_canary_plugin"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            del sys.modules[name]
    try:
        spec = importlib.util.spec_from_file_location(
            module_name, plugin_dir / "__init__.py",
            submodule_search_locations=[str(plugin_dir)],
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    finally:
        for name in [
            name for name in sys.modules
            if name == "providers" or name.startswith("providers.")
        ]:
            del sys.modules[name]
        sys.modules.update(shadowed)
    return module


class TelemetryCollector(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.INFO)
        self.events: list[dict[str, Any]] = []
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        message = record.getMessage()
        if "permission telemetry" in message:
            try:
                self.events.append(json.loads(message.split("telemetry ", 1)[1]))
            except (json.JSONDecodeError, IndexError):
                self.messages.append(message[:300])
        elif "permission" in message.lower():
            self.messages.append(message[:300])


def _jsonrpc_id_is_scalar(value: Any) -> bool:
    # JSON-RPC ids correlate only as str/int; bool is excluded despite being
    # an int subclass (True == 1 would collide with numeric id 1), and
    # dict/list ids are never hashed.
    return isinstance(value, (str, int)) and not isinstance(value, bool)


def analyze_frames(recorder: FrameRecorder) -> dict[str, Any]:
    tools: dict[str, dict[str, Any]] = {}
    pending_permission_ids: dict[Any, str] = {}

    def tool(tool_call_id: str) -> dict[str, Any]:
        return tools.setdefault(
            tool_call_id,
            {"stages": [], "names": set(), "origins": set(), "kinds": set()},
        )

    for ordinal, entry in enumerate(recorder.frames):
        frame = entry["frame"]
        direction = entry["dir"]
        params = frame.get("params") or {}
        update = params.get("update") if isinstance(params, dict) else None
        if isinstance(update, dict) and str(update.get("sessionUpdate") or "").startswith("tool_call"):
            call_id = str(update.get("toolCallId") or "unknown")
            rec = tool(call_id)
            rec.setdefault("first_activity_ordinal", ordinal)
            for key in ("name", "toolName"):
                if isinstance(update.get(key), str):
                    rec["names"].add(update[key])
            if isinstance(update.get("origin"), str):
                rec["origins"].add(update["origin"])
            if isinstance(update.get("kind"), str):
                rec["kinds"].add(update["kind"])
            stage = {
                "dir": direction,
                "stage": "tool_activity",
                "status": update.get("status"),
            }
            raw_output = update.get("rawOutput")
            if isinstance(raw_output, dict):
                text = json.dumps(raw_output, ensure_ascii=False)
                if "denied by pre-tool hook" in text:
                    stage["pre_tool_hook_denial"] = True
                if "denied by user" in text:
                    stage["server_reported_denied_by_user"] = True
            if entry.get("pre_tool_hook_denial_fact"):
                stage["pre_tool_hook_denial"] = True
            if entry.get("server_denied_by_user_fact"):
                stage["server_reported_denied_by_user"] = True
            rec["stages"].append(stage)
        if frame.get("method") == "session/request_permission":
            call = (params.get("toolCall") or {})
            call_id = str(call.get("toolCallId") or "unknown")
            rec = tool(call_id)
            rec["names"].add(call["name"] if isinstance(call.get("name"), str) else "<no-name>")
            disclosed = []
            for section in ("content", "locations"):
                for item in call.get(section) or []:
                    if isinstance(item, dict) and isinstance(item.get("path"), str):
                        disclosed.append("".join(ch for ch in item["path"] if 32 <= ord(ch) < 127)[:120])
            options = [
                str(option.get("kind"))
                for option in params.get("options") or []
                if isinstance(option, dict)
            ]
            rec["stages"].append({
                "dir": direction,
                "stage": "permission_request",
                "kind": str(call.get("kind") or "")[:20],
                "title": "".join(ch for ch in str(call.get("title") or "") if 32 <= ord(ch) < 127)[:80],
                "disclosed_paths": disclosed[:6],
                "offered_option_kinds": options,
            })
            if frame.get("id") is not None:
                pending_permission_ids[frame["id"]] = call_id
        if direction == "out" and frame.get("id") in pending_permission_ids and "result" in frame:
            outcome = (frame.get("result") or {}).get("outcome") or {}
            kind = str(outcome.get("outcome") or "")
            rec = tool(pending_permission_ids[frame["id"]])
            rec["stages"].append({"dir": direction, "stage": "harness_answer", "outcome": kind})
        if direction == "out" and frame.get("method") in {"session/new", "session/resume"}:
            meta = (frame.get("params") or {}).get("_meta") or {}
            agy = meta.get("agy") if isinstance(meta, dict) else None
            disabled = agy.get("disabledTools") if isinstance(agy, dict) else None
            record_cwd = (frame.get("params") or {}).get("cwd")
            session_launch = {
                "method": frame["method"],
                "cwd": record_cwd,
                "disabled_tools": disabled,
            }
            tools.setdefault("__session__", {"stages": [], "names": set(), "origins": set(), "kinds": set()})["stages"].append(session_launch)
    for rec in tools.values():
        rec["names"] = sorted(rec["names"])
        rec["origins"] = sorted(rec["origins"])
        rec["kinds"] = sorted(rec["kinds"])
    return {"tools": tools}


def _sha256_file(path: Path) -> str | None:
    """Local bytes only. A digest does NOT establish Google's provenance."""
    try:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def run_raw_allow(args, recorder: FrameRecorder, evidence_dir: Path) -> int:
    """Backward-compatible Python entry name; now a fail-closed raw probe.

    This is NOT a Hermes model-provider E2E, and does not authorize vendor
    credentials, live inference, or tool permission grants. A process never
    receives more than one session/prompt from this driver.
    """
    status: dict[str, Any] = {
        "schema_version": 1,
        "mode": "raw-probe",
        "outcome": "FAIL",
        "reason": "not_started",
        "requested_model": args.model,
        "set_model_acknowledged": False,
        "effective_model_verified": False,
        "prompt_count": 0,
        "message_chunk_count": 0,
        "permission_requests_cancelled": 0,
        "server_binary_basename": Path(args.command).name,
        "server_binary_sha256": _sha256_file(Path(args.command)),
        "driver_sha256": _sha256_file(Path(__file__)),
        "official_vendor_binary_verified": False,
        "python_version": sys.version.split()[0],
        "python_platform": sys.platform,
        "exit_code_before_cleanup": None,
        "exit_code_after_cleanup": None,
        "terminated_by_driver": False,
    }
    # Do not forward ambient GH_TOKEN, Gemini keys, Python injection knobs, or
    # other credential-shaped variables into the child. Fake mode receives a
    # new empty HOME so it cannot inherit a vendor-native OAuth session either.
    child_env = {
        key: os.environ[key] for key in (
            "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "TMPDIR",
            "ACP_FAKE_SCENARIO", "ACP_FAKE_LOG",
        ) if key in os.environ
    }
    if getattr(args, "fake_acp_only", False):
        isolated_home = evidence_dir / "fake-home"
        isolated_home.mkdir(mode=0o700, exist_ok=False)
        child_env["HOME"] = str(isolated_home)
        child_env["XDG_CONFIG_HOME"] = str(isolated_home / "config")
        child_env["XDG_DATA_HOME"] = str(isolated_home / "data")
    else:
        # An attended, separately approved official server may need its own
        # vendor HOME. Never preserve arbitrary ambient credential variables.
        for key in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"):
            if key in os.environ:
                child_env[key] = os.environ[key]
    try:
        proc = subprocess.Popen(
            [args.command],
            env=child_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            cwd=args.cwd,
        )
    except OSError:
        status["reason"] = "spawn_failed"
        (evidence_dir / "raw_run_status.json").write_text(
            json.dumps(status, indent=2), encoding="utf-8"
        )
        return 2

    assert proc.stdin is not None and proc.stdout is not None
    inbox: queue.Queue[Any] = queue.Queue()

    def pump() -> None:
        for line in proc.stdout:
            recorder.record("in", line)
            try:
                inbox.put(json.loads(line))
            except json.JSONDecodeError:
                inbox.put({"_malformed_json": True})

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()

    def send(message: dict[str, Any]) -> None:
        if message.get("method") == "session/prompt":
            if status["prompt_count"] != 0:
                raise RuntimeError("duplicate prompt refused")
            status["prompt_count"] += 1
        payload = json.dumps(message, ensure_ascii=False)
        recorder.record("out", payload)
        proc.stdin.write(payload + "\n")
        proc.stdin.flush()

    def send_request(rpc_id: int, method: str, params: dict[str, Any]) -> None:
        send({"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params})

    deadline = time.monotonic() + args.timeout
    phase = "initialize"
    expected_id = 1
    session_id: str | None = None

    def fail(reason: str, code: int = 2) -> int:
        status["reason"] = reason
        return code

    try:
        send_request(1, "initialize", {
            "protocolVersion": 1,
            "clientCapabilities": {
                "fs": {"readTextFile": False, "writeTextFile": False}
            },
            "clientInfo": {
                "name": "acp-live-canary-raw", "title": "ACP canary probe",
                "version": "0.2.0",
            },
        })
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                message = inbox.get(timeout=min(0.1, max(0.01, remaining)))
            except queue.Empty:
                if proc.poll() is not None:
                    return fail("child_exited_before_complete", 4)
                continue
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                return fail("malformed_json_rpc")
            method = message.get("method")
            if method is not None:
                if method == "session/request_permission":
                    permission_id = message.get("id")
                    if type(permission_id) is not int:
                        return fail("permission_request_id_invalid")
                    # Fail closed: never choose allow_once or allow_always.
                    status["permission_requests_cancelled"] += 1
                    send({
                        "jsonrpc": "2.0", "id": permission_id,
                        "result": {"outcome": {"outcome": "cancelled"}},
                    })
                elif method == "session/update" and phase == "prompt":
                    params = message.get("params")
                    update = params.get("update") if isinstance(params, dict) else None
                    # A chunk only counts toward this prompt when its
                    # sessionId exactly matches the session created for this
                    # run; missing or foreign session ids never satisfy PASS.
                    if (isinstance(params, dict)
                            and isinstance(session_id, str)
                            and params.get("sessionId") == session_id
                            and isinstance(update, dict)
                            and update.get("sessionUpdate") == "agent_message_chunk"):
                        content = update.get("content")
                        chunk = content.get("text") if isinstance(content, dict) else None
                        if isinstance(chunk, str) and chunk.strip():
                            status["message_chunk_count"] += 1
                elif type(message.get("id")) is int:
                    return fail("unexpected_server_request")
                continue

            if type(message.get("id")) is not int or message["id"] != expected_id:
                return fail("unexpected_response_id")
            if "error" in message:
                return fail(f"{phase}_rpc_error")
            result = message.get("result")
            if not isinstance(result, dict):
                return fail(f"{phase}_invalid_result")

            if phase == "initialize":
                # Fail closed: a dict alone never advances this state
                # machine. The initialize result must carry the required,
                # type-correct, supported ACP protocol version — the pinned
                # v1 integer 1 this driver and the vendored client itself
                # send (hermes-plugin/antigravity-acp/client.py
                # _INITIALIZE_PARAMS). Missing keys, object/list shapes,
                # strings, bool/float type confusion, and unsupported
                # integers all reject here, before any session/new,
                # session/set_model or session/prompt is ever sent.
                protocol_version = result.get("protocolVersion")
                if (type(protocol_version) is not int
                        or protocol_version not in _VERIFIED_PROTOCOL_VERSIONS):
                    return fail("initialize_unsupported_protocol_version")
                expected_id = 2
                phase = "session_new"
                send_request(2, "session/new", {
                    "cwd": args.cwd, "mcpServers": [],
                })
            elif phase == "session_new":
                session_id = result.get("sessionId")
                if not isinstance(session_id, str) or not session_id:
                    return fail("session_id_missing")
                # Fail closed on an empty/missing model (reviewer run 642):
                # the prior ``if args.model`` branch let ``--model ""`` skip
                # session/set_model, send session/prompt directly and record
                # PASS without any model confirmation. historical reference requires
                # initialize -> session/new -> confirmed session/set_model ->
                # exactly one session/prompt, so no prompt frame is ever
                # emitted unless a non-empty requested model exists.
                model = args.model
                if not isinstance(model, str) or not model.strip():
                    return fail("model_missing_for_set_model")
                expected_id = 3
                phase = "set_model"
                send_request(3, "session/set_model", {
                    "sessionId": session_id, "modelId": model,
                })
            elif phase == "set_model":
                # Reaching this branch proves the reply to request id 3
                # carried a successful result: error replies, unexpected ids
                # and non-dict results fail above. session/prompt is only
                # ever sent from here, so a prompt implies a successful
                # session/set_model acknowledgment.
                status["set_model_acknowledged"] = True
                expected_id = 4
                phase = "prompt"
                send_request(4, "session/prompt", {
                    "sessionId": session_id,
                    "prompt": [{"type": "text", "text": args.prompt}],
                })
            elif phase == "prompt":
                stop_reason = result.get("stopReason")
                # Pre-persistence privacy gate: raw_prompt_result.json is
                # written before the end_turn decision, so only a verified
                # StopReason enum member may ever be persisted verbatim;
                # any other server-chosen value is fingerprinted, never
                # stored as text.
                verified_stop_reason = (
                    stop_reason
                    if isinstance(stop_reason, str)
                    and stop_reason in _VERIFIED_STOP_REASONS
                    else None
                )
                rejected_stop_reason = None
                if stop_reason is not None and verified_stop_reason is None:
                    rejected_stop_reason = _string_fingerprint(
                        stop_reason
                        if isinstance(stop_reason, str)
                        else json.dumps(stop_reason, ensure_ascii=False)
                    )
                (evidence_dir / "raw_prompt_result.json").write_text(
                    json.dumps({
                        "stop_reason": verified_stop_reason,
                        "unverified_stop_reason_fingerprint": rejected_stop_reason,
                        "nonempty_message_chunk_count": status["message_chunk_count"],
                    }, indent=2), encoding="utf-8"
                )
                if stop_reason != "end_turn":
                    return fail("prompt_stop_reason_not_end_turn")
                if status["message_chunk_count"] < 1:
                    return fail("prompt_missing_nonempty_message_chunk")
                if status["permission_requests_cancelled"]:
                    return fail("tool_permission_requested_during_probe")
                if not status["set_model_acknowledged"]:
                    # Belt-and-braces PASS gate: PASS is unreachable unless
                    # a successful session/set_model reply was observed,
                    # even if a future edit grows another prompt path.
                    return fail("set_model_not_acknowledged_before_prompt")
                status["outcome"] = "PASS"
                status["reason"] = "fake_or_unverified_raw_protocol_only"
                return 0
            else:
                return fail("unexpected_state")
        return fail("protocol_timeout", 3)
    except (BrokenPipeError, OSError, RuntimeError, ValueError):
        return fail("transport_or_duplicate_prompt_error")
    finally:
        status["exit_code_before_cleanup"] = proc.poll()
        if proc.poll() is None:
            status["terminated_by_driver"] = True
            proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2.0)
        status["exit_code_after_cleanup"] = proc.returncode
        reader.join(timeout=1.0)
        (evidence_dir / "raw_run_status.json").write_text(
            json.dumps(status, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def _git_revision(repo: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout.strip() or None


def _parked_connections_teardown(parked_client: Any,
                                 spawned: list[Any]) -> tuple[list[Any], list[bool]]:
    """Close every conversation the run registered and report whether each
    ACP direct child this run spawned is confirmed exited."""
    for registry in list(parked_client._registries.values()):
        registry.close_all()
    parked_client._registries.clear()
    deadline = time.monotonic() + 10.0
    exited: list[bool] = []
    for conn in spawned:
        while time.monotonic() < deadline:
            proc = getattr(conn, "_proc", None)
            if (getattr(conn, "exited", False)
                    or (proc is not None and proc.returncode is not None)):
                break
            time.sleep(0.05)
        proc = getattr(conn, "_proc", None)
        exited.append(bool(
            getattr(conn, "exited", False)
            or (proc is not None and proc.returncode is not None)))
    return spawned, exited


def run_parked(args, module, recorder: FrameRecorder, evidence_dir: Path,
               started: float) -> int:
    """Issue #93: drive the deployed Parked-MCP provider/client as Hermes does.

    No mock engine and no protocol re-implementation: the engine modules are
    imported from the loaded plugin package and driven through the same
    OpenAI-shaped facade Hermes calls.  ACP stdio is teed into the frame
    recorder by wrapping the engine's own ``AcpConnection`` at spawn time.
    The driver answers parked tool calls with a canned, uniquely-tagged
    sentinel string; it never executes anything on the host, and the parked
    round only PASSES when that sentinel is echoed back by the model (proof
    the result was delivered into the same held prompt), never on a merely
    non-empty answer.

    Fake-lane isolation (``--fake-acp-only``): an explicit ``--command`` fake
    binary is mandatory; the engine's own env/launcher resolution
    (``HERMES_ANTIGRAVITY_ACP_MCP_COMMAND`` / ``HERMES_ANTIGRAVITY_ACP_COMMAND``
    / official launcher) is scrubbed for the run and the command is rejected
    when it resolves (realpath) to the official launcher, so the lane can
    never implicitly reach a real launcher, MUX configuration, authentication
    or inference.

    Evidence hygiene: frames, engine log facts, answers and errors pass
    through ``_ParkedRedactor`` — the plugin's own ACP error redactor plus
    per-run dynamic secrets (session ids, loopback MCP bearer and URL path)
    registered the moment they first appear.

    ``--timeout`` bounds the WHOLE parked run (wall clock, SIGALRM); on
    expiry or any error the finally block cancels in-flight engine work and
    tears down every session and ACP child the canary owns before reporting.

    Verdicts are per-probe ``pass`` / ``fail`` (contract exercised and
    breached) / ``inconclusive`` (probe could not be exercised).  A direct
    child that fails to exit is ``fail``, never hidden as inconclusive.
    Exit codes: 0 = every verdict pass; 1 = error or any fail; 2 = refused
    preflight; 3 = no fail but at least one inconclusive (the run did NOT
    fully verify the contract).
    """
    import importlib

    pkg = module.__name__
    parked_client = importlib.import_module(pkg + ".parked.client")
    parked_acp = importlib.import_module(pkg + ".parked.acp_connection")
    parked_session = importlib.import_module(pkg + ".parked.session")
    parked_usage = importlib.import_module(pkg + ".parked.usage_contract")

    # Reuse the plugin's established redactor for the fixed secret shapes;
    # _ParkedRedactor adds the per-run dynamic secrets on top.
    redactor = _ParkedRedactor(getattr(
        importlib.import_module(pkg + ".client"),
        "_redact_acp_error_detail", None))
    clean_text = redactor
    recorder._clean = redactor
    recorder._sanitize = _make_parked_sanitizer(redactor)

    scrubbed: dict[str, str] = {}
    if args.fake_acp_only:
        # Fake-lane isolation is structural, not name-based: the command is
        # explicit, the engine's resolution env is removed for the run, and
        # the official launcher is refused by resolved path, not basename.
        if args.command is None:
            print(
                "parked fake lane requires an explicit --command fake ACP "
                "binary; the engine's env/launcher resolution is disabled in "
                "this lane", file=sys.stderr,
            )
            return 2
        command = args.command
        for var in ("HERMES_ANTIGRAVITY_ACP_MCP_COMMAND",
                    "HERMES_ANTIGRAVITY_ACP_COMMAND"):
            if var in os.environ:
                scrubbed[var] = os.environ.pop(var)
        official = parked_client._default_official_command()
        if official and os.path.realpath(command) == os.path.realpath(official):
            print(
                "parked fake lane command resolves to the official launcher; "
                "refusing", file=sys.stderr,
            )
            os.environ.update(scrubbed)
            return 2
    else:
        command = args.command or parked_client._default_command()[0]
    # The canary is a standalone client, not a Hermes conversation.  Inside a
    # Hermes-hosted process the engine keys EVERY request to one conversation
    # via HERMES_SESSION_KEY/HERMES_SESSION_ID, which would collapse the
    # canary's separate probe conversations onto the main session (and let a
    # probe retire it).  Scrub the identity for the run so the documented
    # standalone affinity (cwd + opening user prefix) applies.
    for var in ("HERMES_SESSION_KEY", "HERMES_SESSION_ID"):
        if var in os.environ:
            scrubbed[var] = os.environ.pop(var)

    # Tee every ACP child this run spawns.  client._spawn_factory resolves
    # AcpConnection from the client module's globals at spawn time, and
    # start() opens the pipes via subprocess.Popen from acp_connection's
    # globals — both are rebound for the duration of start() only.
    original_connection = parked_acp.AcpConnection
    spawned_connections: list[Any] = []

    class _TeeConnection(original_connection):
        def __init__(self, *conn_args, **conn_kwargs):
            super().__init__(*conn_args, **conn_kwargs)
            # Teardown must verify EVERY child this run spawned, not just the
            # conversations still registered at the end (retired ones are
            # removed from the registry while their child is still ours).
            spawned_connections.append(self)

        def start(self):
            real_popen = subprocess.Popen

            def _teeing_popen(*popen_args, **popen_kwargs):
                proc = real_popen(*popen_args, **popen_kwargs)
                proc.stdin = _StdinTee(proc.stdin, recorder)  # type: ignore[assignment]
                proc.stdout = _StdoutTee(proc.stdout, recorder)  # type: ignore[attr-defined]
                return proc

            parked_acp.subprocess = types.SimpleNamespace(  # type: ignore[attr-defined]
                Popen=_teeing_popen, PIPE=subprocess.PIPE)
            try:
                super().start()
            finally:
                parked_acp.subprocess = subprocess  # type: ignore[attr-defined]

    parked_client.AcpConnection = _TeeConnection  # type: ignore[attr-defined]

    # Engine-side decisions (usage-gate rejections etc.) surface as fixed
    # "acp-mcp" log lines; capture them sanitized so a gate rejection is
    # distinguishable from a silent server omission.
    class _EngineLogCollector(logging.Handler):
        def __init__(self) -> None:
            super().__init__()
            self.messages: list[str] = []

        def emit(self, record: logging.LogRecord) -> None:
            try:
                msg = record.getMessage()
            except Exception:  # noqa: BLE001
                return
            if "acp-mcp" not in msg:
                return
            if len(self.messages) < 20:
                self.messages.append(clean_text(msg)[:200])

    engine_logs = _EngineLogCollector()
    engine_logger = logging.getLogger(pkg + ".parked")
    engine_logger.addHandler(engine_logs)

    client = parked_client.AntigravityAcpMcpClient(command=command, args=[])
    summary: dict[str, Any] = {
        "engine": "parked",
        "client_class": type(client).__name__,
        "started_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "server_binary_basename": Path(command).name,
        "command_resolution": "explicit" if args.command else "engine-default",
        "model_requested": args.model,
        "runtime_python": sys.version.split()[0],
        "harness_revision": _git_revision(Path(args.repo)),
        "timeout_seconds": args.timeout,
    }
    verdicts: dict[str, str] = {}
    error: str | None = None
    first_text = final_text = follow_answer = ""
    tool_round: dict[str, Any] = {}
    follow_up: dict[str, Any] = {}
    cancel_probe: dict[str, Any] = {"attempted": False}
    sentinel = "canary-simulated-result-" + secrets.token_hex(6)

    def out_frames(method: str) -> list[dict[str, Any]]:
        return [
            entry for entry in recorder.frames
            if entry.get("dir") == "out"
            and isinstance(entry.get("frame"), dict)
            and entry["frame"].get("method") == method
        ]

    def response_for(request_id: Any) -> dict[str, Any] | None:
        if request_id is None:
            return None
        for entry in recorder.frames:
            frame = entry.get("frame")
            if (entry.get("dir") == "in" and isinstance(frame, dict)
                    and frame.get("id") == request_id
                    and ("result" in frame or "error" in frame)):
                return frame
        return None

    def _alarm(signum: int, frame: Any) -> None:  # noqa: ANN001
        raise CanaryTimeout(
            f"parked lane exceeded --timeout={args.timeout}s")

    have_alarm = hasattr(signal, "SIGALRM")
    previous_handler = None
    if have_alarm:
        previous_handler = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, max(1.0, float(args.timeout)))
    try:
        try:
            messages = [{"role": "user", "content": args.prompt}]
            first = client.chat.completions.create(
                model=args.model, messages=messages,
                tools=[dict(PARKED_CANARY_TOOL)], stream=False,
            )
            first_text = first.choices[0].message.content or ""
            calls = list(getattr(first.choices[0].message, "tool_calls", None) or [])

            tool_round = {
                "advertised": True,
                "calls_observed": bool(calls),
                "call_id_shape_ok": None,
                "result_sentinel": sentinel,
                "sentinel_echoed_by_model": None,
                "prompt_requests_across_round": None,
            }
            final_text = first_text
            assistant_row: dict[str, Any] | None = None
            tool_rows: list[dict[str, Any]] = []
            if calls:
                ids = [str(getattr(call, "id", "")) for call in calls]
                tool_round["call_ids"] = ids
                tool_round["call_id_shape_ok"] = bool(ids) and all(
                    re.fullmatch(r"call_[0-9a-f]{32}", one) for one in ids
                )
                assistant_row = {
                    "role": "assistant", "content": None,
                    "tool_calls": [
                        {
                            "id": str(getattr(call, "id", "")),
                            "type": "function",
                            "function": {
                                "name": str(getattr(
                                    getattr(call, "function", None), "name", "")),
                                "arguments": str(getattr(
                                    getattr(call, "function", None), "arguments", "{}")),
                            },
                        }
                        for call in calls
                    ],
                }
                tool_rows = [
                    {"role": "tool", "tool_call_id": one, "content": sentinel}
                    for one in ids
                ]
                # Parked contract: the tool result is answered into the SAME
                # held ACP prompt; the engine must not open a second
                # session/prompt.
                second = client.chat.completions.create(
                    model=args.model, messages=messages + [assistant_row, *tool_rows],
                    tools=[dict(PARKED_CANARY_TOOL)], stream=False,
                )
                final_text = second.choices[0].message.content or ""
                # A merely non-empty answer proves NOTHING about delivery:
                # PASS requires the unique sentinel to come back through the
                # model, proving the canned result reached it.
                tool_round["sentinel_echoed_by_model"] = sentinel in final_text
            prompts_during_round = len(out_frames("session/prompt"))
            if calls:
                tool_round["prompt_requests_across_round"] = prompts_during_round
                if prompts_during_round != 1:
                    # Held-prompt contract broken: a second prompt request
                    # was opened across the parked round.
                    verdicts["parked_tool_round"] = "fail"
                elif tool_round["call_id_shape_ok"] and tool_round["sentinel_echoed_by_model"]:
                    verdicts["parked_tool_round"] = "pass"
                else:
                    # Delivery into the model could not be confirmed (the
                    # answer never repeated the sentinel): inconclusive,
                    # never a silent pass.
                    verdicts["parked_tool_round"] = "inconclusive"
            else:
                # The model chose not to call the advertised tool: the parked
                # round was never exercised.  Inconclusive, not a failure.
                verdicts["parked_tool_round"] = "inconclusive"
            verdicts["plain_response"] = "pass" if final_text.strip() else "fail"

            follow_text = (args.follow_up if args.follow_up is not None
                           else PARKED_FOLLOW_UP_PROMPT)
            follow_messages = list(messages)
            if assistant_row is not None:
                follow_messages += [assistant_row, *tool_rows]
            follow_messages += [
                {"role": "assistant", "content": final_text},
                {"role": "user", "content": follow_text},
            ]
            third = client.chat.completions.create(
                model=args.model, messages=follow_messages,
                tools=[dict(PARKED_CANARY_TOOL)], stream=False,
            )
            follow_answer = third.choices[0].message.content or ""
            follow_up = {
                "answered": bool(follow_answer.strip()),
                "prompt_requests_total": len(out_frames("session/prompt")),
                "session_new_requests_total": len(out_frames("session/new")),
            }
            follow_up["same_session_no_new"] = bool(
                follow_up["answered"]
                and follow_up["session_new_requests_total"] == 1
                and follow_up["prompt_requests_total"] == 2
            )
            verdicts["follow_up_same_session"] = (
                "pass" if follow_up["same_session_no_new"] else "fail"
            )

            usage = getattr(third, "usage", None)
            observations = getattr(third, "antigravity_usage_observations", None)
            summary["usage"] = {
                # OpenAI-style names as the deployed facade exposes them.
                "final_turn_reported": None if usage is None else {
                    "prompt_tokens": getattr(usage, "prompt_tokens", None),
                    "completion_tokens": getattr(usage, "completion_tokens", None),
                    "total_tokens": getattr(usage, "total_tokens", None),
                },
                "observations_present": bool(observations),
                "observations": _sanitize(observations, clean_text) if observations else None,
                "local_estimate_tokens": parked_usage.transcript_tokens(follow_messages),
                "gate_rejection_logged": any(
                    "rejected" in line for line in engine_logs.messages),
                "billing_claim": "none; server-reported figures are unverified telemetry",
            }
            # Existence of a usage figure alone verifies nothing: PASS
            # requires the server-reported usage to have PASSED the shared
            # usage gate against the local estimate.  A logged gate
            # rejection means the server sent contract-violating usage:
            # exercised and breached -> fail.
            if summary["usage"]["gate_rejection_logged"]:
                verdicts["usage_contract"] = "fail"
            elif (summary["usage"]["final_turn_reported"] is not None
                    and summary["usage"]["local_estimate_tokens"]):
                verdicts["usage_contract"] = "pass"
            else:
                verdicts["usage_contract"] = "inconclusive"

            disabled: list[str] = []
            for entry in out_frames("session/new"):
                meta = ((entry["frame"].get("params") or {}).get("_meta") or {})
                antigravity = meta.get("antigravity") or {}
                listed = antigravity.get("disabledTools")
                if isinstance(listed, list):
                    disabled = [str(one) for one in listed]
            native_tools = [str(one) for one in getattr(parked_session, "NATIVE_TOOLS", [])]
            # Evidence lists are capped by the sanitizer; a truncated recording
            # must never masquerade as a mismatch.  The authoritative set
            # equality is asserted against the fake's own request log in tests.
            recorded_prefix_ok = bool(
                disabled
                and native_tools
                and disabled == native_tools[:len(disabled)]
            )
            summary["containment"] = {
                "disabled_native_tools_recorded": len(disabled) or None,
                "engine_declared_native_tools": len(native_tools) or None,
                "recorded_matches_engine_declaration_prefix": recorded_prefix_ok,
                "run_command_in_engine_native_tools": "run_command" in native_tools,
            }
            # This verdict covers the DECLARATION only (config delivery).
            # Whether a native tool would actually be BLOCKED at execution
            # time is a separate verdict exercised by the permission probe
            # below; conflating the two would let a config echo stand in
            # for enforcement.
            verdicts["containment_declaration"] = (
                "pass" if recorded_prefix_ok and "run_command" in native_tools
                else "inconclusive"
            )

            probe_id: Any = None
            probe_options: dict[str, str] = {}
            probe_outcome: dict[str, Any] = {}
            for entry in recorder.frames:
                frame = entry.get("frame")
                if not isinstance(frame, dict):
                    continue
                if (entry.get("dir") == "in"
                        and frame.get("method") == "session/request_permission"):
                    tool_call = (frame.get("params") or {}).get("toolCall") or {}
                    label = " ".join(str(tool_call.get(k) or "")
                                     for k in ("name", "title"))
                    if "canary-native-probe" in label:
                        probe_id = frame.get("id")
                        for option in (frame.get("params") or {}).get("options") or []:
                            if isinstance(option, dict):
                                probe_options[str(option.get("optionId"))] = str(
                                    option.get("kind"))
                elif (probe_id is not None and "raw" not in probe_outcome
                        and entry.get("dir") == "out" and frame.get("id") == probe_id
                        and ("result" in frame or "error" in frame)):
                    probe_outcome["raw"] = (frame.get("result") or {}).get("outcome")
            summary["native_permission_probe"] = {
                "observed": probe_id is not None,
                "outcome": _sanitize(probe_outcome.get("raw"), clean_text),
                "options": probe_options,
            }
            if probe_id is None:
                verdicts["native_tool_execution_blocked"] = "inconclusive"
            else:
                outcome = probe_outcome.get("raw")
                kind = ""
                if isinstance(outcome, dict):
                    if outcome.get("outcome") == "cancelled":
                        kind = "cancelled"
                    else:
                        kind = probe_options.get(str(outcome.get("optionId")), "")
                if kind.startswith("reject") or kind == "cancelled":
                    verdicts["native_tool_execution_blocked"] = "pass"
                elif kind.startswith("allow"):
                    verdicts["native_tool_execution_blocked"] = "fail"
                else:
                    verdicts["native_tool_execution_blocked"] = "inconclusive"

            # Model selection: the REQUEST existing is not success.  Verify
            # (a) the server actually advertised the requested model in the
            # session/new result (real model discovery), (b) the selection
            # request carried exactly the requested model (no silent
            # fallback), and (c) the server's response to that request
            # succeeded.
            advertised: list[str] = []
            new_reqs = out_frames("session/new")
            if new_reqs:
                new_resp = response_for(new_reqs[0]["frame"].get("id"))
                if new_resp is not None:
                    models = (new_resp.get("result") or {}).get("models") or {}
                    advertised = [
                        str(m.get("modelId"))
                        for m in models.get("availableModels") or []
                        if isinstance(m, dict)
                    ]
            exact_request: dict[str, Any] | None = None
            fallback_request: dict[str, Any] | None = None
            for entry in (out_frames("session/set_model")
                          + out_frames("session/set_config_option")):
                params = entry["frame"].get("params") or {}
                candidate = params.get("modelId", params.get("value"))
                if candidate is None:
                    continue
                if str(candidate) == args.model:
                    exact_request = entry["frame"]
                elif fallback_request is None:
                    fallback_request = entry["frame"]
            selection_request = exact_request or fallback_request
            selection_response = (
                response_for(selection_request.get("id"))
                if selection_request is not None else None)
            selection_ok = bool(
                isinstance(selection_response, dict)
                and "result" in selection_response
                and "error" not in selection_response)
            summary["model_selection"] = {
                "requested": args.model,
                "advertised_ids": advertised[:40],
                "selection_request": (
                    "exact" if exact_request is not None
                    else ("fallback" if fallback_request is not None else None)),
                "selection_response_ok": selection_ok,
                "selection_response_error": bool(
                    isinstance(selection_response, dict)
                    and "error" in selection_response),
            }
            if selection_request is None:
                verdicts["model_selection"] = "inconclusive"
            elif summary["model_selection"]["selection_response_error"]:
                verdicts["model_selection"] = "fail"
            elif not selection_ok:
                verdicts["model_selection"] = "inconclusive"
            elif exact_request is None:
                # The engine selected a DIFFERENT model than requested.
                verdicts["model_selection"] = "fail"
            elif not advertised or args.model not in advertised:
                # Selection succeeded but the server never advertised the
                # model: real discovery is unverified.
                verdicts["model_selection"] = "inconclusive"
            else:
                verdicts["model_selection"] = "pass"

            # Cancellation: start a throwaway completion on its own fresh
            # conversation, wait until the engine has actually issued the
            # session/prompt (visible in the tee), then interrupt through
            # the facade's cancel() and require BOTH the vendor-visible
            # session/cancel notification and an interrupted request.
            cancel_probe = {"attempted": True}
            prompts_before = len(out_frames("session/prompt"))
            thread_result: dict[str, Any] = {}

            def _cancel_run() -> None:
                try:
                    client.chat.completions.create(
                        model=args.model,
                        messages=[{"role": "user", "content":
                                   "canary cancel probe " + secrets.token_hex(4)}],
                        tools=[dict(PARKED_CANARY_TOOL)], stream=False)
                    thread_result["outcome"] = "returned"
                except BaseException as exc:  # noqa: BLE001
                    thread_result["outcome"] = type(exc).__name__

            probe_thread = threading.Thread(target=_cancel_run, daemon=True)
            probe_thread.start()
            issued_deadline = time.monotonic() + 10.0
            while (time.monotonic() < issued_deadline
                   and len(out_frames("session/prompt")) <= prompts_before):
                time.sleep(0.05)
            cancel_probe["prompt_issued"] = (
                len(out_frames("session/prompt")) > prompts_before)
            if cancel_probe["prompt_issued"]:
                client.cancel()
                probe_thread.join(timeout=15.0)
            cancel_probe["session_cancel_sent"] = bool(out_frames("session/cancel"))
            cancel_probe["thread_outcome"] = thread_result.get("outcome")
            cancel_probe["thread_alive"] = probe_thread.is_alive()
            if not cancel_probe["prompt_issued"]:
                verdicts["cancel_path"] = "inconclusive"
            elif (cancel_probe["thread_alive"]
                    or not cancel_probe["session_cancel_sent"]):
                verdicts["cancel_path"] = "fail"
            elif thread_result.get("outcome") in (None, "returned"):
                # cancel() was issued yet the request completed normally:
                # the interrupt path did not take effect.
                verdicts["cancel_path"] = "fail"
            else:
                verdicts["cancel_path"] = "pass"
        except CanaryTimeout as exc:
            error = clean_text(f"{type(exc).__name__}: {exc}")[:400]
        except Exception as exc:  # noqa: BLE001 - the canary reports, never re-raises
            error = clean_text(f"{type(exc).__name__}: {exc}")[:400]
    finally:
        if have_alarm:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if previous_handler is not None:
                signal.signal(signal.SIGALRM, previous_handler)
        os.environ.update(scrubbed)
        engine_logger.removeHandler(engine_logs)
        try:
            # Stop any in-flight engine work (a timed-out prompt, the cancel
            # probe thread) BEFORE reaping, so teardown never races a live
            # request.
            client.cancel()
        except Exception:  # noqa: BLE001
            pass
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            connections, exited = _parked_connections_teardown(
                parked_client, spawned_connections)
        except Exception as exc:  # noqa: BLE001
            connections, exited = [], [False]
            error = error or clean_text(
                f"teardown failure: {type(exc).__name__}: {exc}")[:400]
        summary["teardown"] = {
            "acp_connections": len(connections),
            "direct_children_exited": all(exited) if exited else None,
            "descendant_tree": "not asserted (issue #94 F-3 is out of scope)",
        }
        # A direct child we spawned that did not exit is OUR failure, never
        # hidden behind inconclusive.
        verdicts["normal_teardown"] = _teardown_verdict(exited)
        recorder._fh.close()

    summary["engine_log_facts"] = engine_logs.messages
    summary["answers"] = {
        "initial": clean_text(first_text)[:200],
        "final": clean_text(final_text)[:200],
        "follow_up": clean_text(follow_answer)[:200],
    }
    summary["tool_round"] = tool_round
    summary["follow_up"] = follow_up
    summary["cancel_probe"] = cancel_probe
    summary["verdicts"] = verdicts
    summary["error"] = error
    summary["elapsed_seconds"] = round(time.monotonic() - started, 2)
    if error is not None or "fail" in verdicts.values():
        summary["overall"] = "fail"
    elif "inconclusive" in verdicts.values():
        summary["overall"] = "inconclusive"
    else:
        summary["overall"] = "pass"
    (evidence_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if error is not None or "fail" in verdicts.values():
        return 1
    if "inconclusive" in verdicts.values():
        return 3
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--cwd", required=True, help="absolute isolated worktree path")
    parser.add_argument("--mode", choices=("default", "raw-probe", "raw-allow"), required=True)
    parser.add_argument("--model", default="gemini-3.8-flash-low")
    parser.add_argument(
        "--engine",
        choices=("replay", "parked"),
        default="replay",
        help="replay = legacy flat client (preserved default); parked = the "
             "deployed Parked-MCP provider/client (issue #93). The parked "
             "engine requires an explicit execution lane flag.",
    )
    parser.add_argument("--timeout", type=float, default=600.0,
                        help="replay: per-request timeout; parked: wall-clock "
                             "budget for the WHOLE run (child processes are "
                             "cancelled and reaped on expiry)")
    parser.add_argument("--evidence", required=True)
    parser.add_argument(
        "--fake-acp-only", action="store_true",
        help="Explicit fake-subprocess lane; requires an explicit --command fake "
             "binary (the parked engine additionally disables its env/launcher "
             "resolution for the run so no real launcher or MUX config is reachable)",
    )
    parser.add_argument(
        "--operator-supervised-live", action="store_true",
        help="Interactive live lane; separate human approval is still required",
    )
    parser.add_argument("--prompt", default=None)
    parser.add_argument(
        "--prompt-profile",
        choices=("legacy-native-forcing", "neutral"),
        default="legacy-native-forcing",
        help="neutral = issue #13 item 1 adversarial profile (no tool forcing/forbidding)",
    )
    parser.add_argument(
        "--follow-up",
        nargs="?",
        const=FOLLOW_UP_PROMPT,
        default=None,
        help="send one same-conversation follow-up completion (default text: exact "
        "test summary line request); exercises the live session/resume path",
    )
    parser.add_argument(
        "--advertise-bridge-tools",
        action="store_true",
        help="advertise one Hermes terminal function tool so the plugin "
             "renders the <tool_call> bridge; the driver records the "
             "model's bridge tool calls without executing them",
    )
    parser.add_argument(
        "--prepare-workspace",
        action="store_true",
        help="create calc.py/test_calc.py/run_tests.sh in --cwd if absent before running",
    )
    parser.add_argument(
        "--command",
        default=None,
        help="ACP launcher; when omitted the replay engine keeps its "
             "historical default and the parked engine uses its own "
             "supported resolution (env override -> official launcher)",
    )
    args = parser.parse_args()
    if args.command is None and args.engine == "replay":
        # Byte-compatible with every pre-#93 invocation.
        args.command = str(Path.home() / ".local" / "bin" / "antigravity-acp-official")
    if args.mode == "raw-allow":
        print(
            "raw-allow is disabled: automatic ACP tool approval is unsafe. "
            "Use raw-probe (permissions cancelled) with separate live approval.",
            file=sys.stderr,
        )
        return 2
    # Execution-lane selection gates the isolated raw-probe driver only.
    # Legacy default invocations keep their original unattended CLI contract
    # (they never accepted these lane flags before this PR); per-flag guards
    # below still apply whenever a lane flag is passed.
    if (args.mode == "raw-probe"
            and args.fake_acp_only == args.operator_supervised_live):
        print(
            "Select exactly one execution lane: --fake-acp-only or "
            "--operator-supervised-live. Neither flag grants vendor approval.",
            file=sys.stderr,
        )
        return 2
    if args.engine == "parked":
        # Issue #93: the parked engine drives the real deployed provider, so
        # it never runs unattended.  Live inference additionally needs the
        # attended terminal + typed confirmation below.
        if args.mode != "default":
            print("--engine parked supports --mode default only", file=sys.stderr)
            return 2
        if args.fake_acp_only == args.operator_supervised_live:
            print(
                "parked engine requires exactly one execution lane: "
                "--fake-acp-only or --operator-supervised-live. Neither flag "
                "grants vendor approval.",
                file=sys.stderr,
            )
            return 2
        if args.fake_acp_only and args.command is None:
            print(
                "parked fake lane requires an explicit --command fake ACP "
                "binary; the engine's env/launcher resolution is disabled in "
                "this lane, so an implicit real launcher is impossible",
                file=sys.stderr,
            )
            return 2
    if (args.fake_acp_only and args.command is not None
            and Path(args.command).name == "antigravity-acp-official"):
        print("fake ACP lane refuses the default official binary", file=sys.stderr)
        return 2
    if args.mode == "raw-probe" and not (
            isinstance(args.model, str) and args.model.strip()):
        print(
            "raw-probe requires a non-empty --model: session/set_model is "
            "mandatory before session/prompt, and an empty model would "
            "silently skip that confirmation.",
            file=sys.stderr,
        )
        return 2
    if args.operator_supervised_live:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            print("live canary requires an attended interactive terminal", file=sys.stderr)
            return 2
        confirmation = input(
            "Separate approval is required. For this one live attempt type "
            "RUN_ONE_SUPERVISED_CANARY: "
        )
        if confirmation.strip() != "RUN_ONE_SUPERVISED_CANARY":
            print("live canary not confirmed", file=sys.stderr)
            return 2
    if args.prompt is None:
        if args.engine == "parked":
            args.prompt = PARKED_PROMPT
        elif args.mode == "raw-probe":
            args.prompt = "Reply with exactly pong."
        else:
            args.prompt = (
                NEUTRAL_PROMPT if args.prompt_profile == "neutral" else PROMPT
            )
    if args.mode != "default" and (
        args.follow_up is not None
        or args.prepare_workspace
        or args.advertise_bridge_tools
    ):
        print(
            "--follow-up/--prepare-workspace/--advertise-bridge-tools "
            "apply to --mode default only",
            file=sys.stderr,
        )
        return 2

    cwd = str(Path(args.cwd).resolve())
    if not Path(cwd).is_dir():
        print(f"cwd is not a directory: {cwd}")
        return 2
    evidence_dir = Path(args.evidence).resolve()
    try:
        evidence_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        print("evidence path already exists; refusing to append/overwrite", file=sys.stderr)
        return 2
    # Workspace preparation runs only after every preflight (including the
    # exclusive evidence directory) has passed, so a refused run never
    # leaves files behind.
    if args.prepare_workspace:
        print(json.dumps({"workspace_files_created": prepare_workspace(cwd)}))

    # client submodules are imported lazily by create_client; the raw driver
    # has no plugin client, so it falls back to the identity redactor.
    clean_text = _redact_factory(None)
    sanitizer = _sanitize_raw_protocol if args.mode == "raw-probe" else _sanitize
    recorder = FrameRecorder(
        evidence_dir / "frames.jsonl",
        clean_text,
        sanitizer=sanitizer,
        denial_fact_bits=(args.mode != "raw-probe"),
    )

    if args.mode == "raw-probe":
        rc = run_raw_allow(args, recorder, evidence_dir)
        (evidence_dir / "analysis.json").write_text(
            json.dumps(analyze_frames(recorder), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        recorder._fh.close()
        return rc

    module = load_client_module(Path(args.repo))
    scratch = evidence_dir / "state"
    scratch.mkdir(parents=True, exist_ok=True)
    # Honest self-check: the harness file callbacks delegate to Hermes
    # file policy (agent.file_safety).  A bare python without that package
    # must fail closed by design; record it so an environment mistake can
    # never be mistaken for a policy result.
    import importlib.util
    try:
        hermes_policy_available = (
            importlib.util.find_spec("agent.file_safety") is not None
        )
    except (ImportError, ValueError):
        # find_spec on a dotted name imports the parent package and raises
        # when it is absent; the recorded fact below is the contract.
        hermes_policy_available = False
    summary_environment = {
        "hermes_policy_available": hermes_policy_available,
        "python": sys.version.split()[0],
    }
    (evidence_dir / "environment.json").write_text(
        json.dumps(summary_environment, indent=2), encoding="utf-8"
    )
    os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"] = str(scratch / "conversation-state.json")
    os.environ["HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE"] = str(scratch / "limit-state.json")

    collector = TelemetryCollector()
    logging.getLogger().addHandler(collector)
    logging.getLogger().setLevel(logging.INFO)

    if args.engine == "parked":
        # Issue #93: drive the deployed Parked-MCP provider/client; the
        # replay client object is deliberately never constructed on this
        # path (a silent fallback would defeat the whole point).
        try:
            return run_parked(args, module, recorder, evidence_dir,
                              started=time.monotonic())
        finally:
            logging.getLogger().removeHandler(collector)

    client = module.antigravity_acp_replay.create_client(
        command=args.command, args=[], acp_cwd=cwd, rate_limit_retries=0,
    )
    client_module = sys.modules[module.__name__ + ".client"]
    # The plugin-aware redactor must back BOTH the frame recorder and every
    # summary-level fact (bridge arguments, error strings).  The pre-load
    # _redact_factory(None) is an identity redactor; keeping the local
    # clean_text bound to it would persist unredacted model text.
    clean_text = _redact_factory(client_module)
    recorder._clean = clean_text
    original_spawn = client._spawn

    def spawn_and_wrap(**kwargs):
        proc = original_spawn(**kwargs)
        proc.stdin = _StdinTee(proc.stdin, recorder)
        proc.stdout = _StdoutTee(proc.stdout, recorder)
        return proc

    client._spawn = spawn_and_wrap

    bridge_tools = (
        [dict(_BRIDGE_TERMINAL_TOOL)] if args.advertise_bridge_tools else []
    )
    bridge_facts: list[dict[str, Any]] = []
    follow_up_skipped_reason: str | None = None
    started = time.monotonic()
    error = None
    answer = None
    follow_up_answer = None
    try:
        completion = client.chat.completions.create(
            messages=[{"role": "user", "content": args.prompt}],
            model=args.model,
            tools=bridge_tools,
            timeout=args.timeout,
            stream=False,
        )
        answer = completion.choices[0].message.content
        bridge_facts.extend(
            _bridge_tool_call_facts(completion, "initial", clean_text)
        )
        if (
            error is None
            and args.follow_up is not None
            and bridge_facts
        ):
            # The initial turn ended with bridge tool calls this driver will
            # never execute. Re-sending the transcript as content-only would
            # mismatch the plugin's response_fingerprint(content, tool_calls)
            # and silently degrade the run's resume/continuation facts into
            # replay artifacts of an incomplete history. A faithful
            # continuation would require synthesizing tool results, which is
            # forbidden; skip the follow-up and record why.
            follow_up_skipped_reason = "pending_bridge_tool_calls"
        elif error is None and args.follow_up is not None:
            # Same conversation, one turn later: identical opening user
            # message keeps the standalone affinity key stable, so the plugin
            # must resume the native session created above (issue #13 item 3
            # observes what survives that boundary).
            follow_completion = client.chat.completions.create(
                messages=[
                    {"role": "user", "content": args.prompt},
                    {"role": "assistant", "content": answer or ""},
                    {"role": "user", "content": args.follow_up},
                ],
                model=args.model,
                tools=bridge_tools,
                timeout=args.timeout,
                stream=False,
            )
            follow_up_answer = follow_completion.choices[0].message.content
            bridge_facts.extend(
                _bridge_tool_call_facts(
                    follow_completion, "follow_up", clean_text
                )
            )
    except BaseException as exc:  # noqa: BLE001 - report every failure class truthfully
        error = f"{type(exc).__name__}: {clean_text(str(exc))[:300]}"
    finally:
        client.close()

    effects = {
        "helpers_py_created": (Path(cwd) / "helpers.py").is_file(),
        "calc_py_modified": False,
        "safe_file_created": (Path(cwd) / "safe_file.py").is_file(),
        "git_worktree": subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True,
        ).returncode == 0,
    }
    calc = Path(cwd) / "calc.py"
    if calc.is_file():
        effects["calc_py_modified"] = "add2" in calc.read_text(encoding="utf-8")

    analysis = analyze_frames(recorder)
    launch_seq = [
        stage
        for stage in analysis["tools"].get("__session__", {}).get("stages", [])
        if isinstance(stage, dict)
        and stage.get("method") in {"session/new", "session/resume"}
    ]
    new_positions = [
        i for i, s in enumerate(launch_seq) if s["method"] == "session/new"
    ]
    resume_positions = [
        i for i, s in enumerate(launch_seq) if s["method"] == "session/resume"
    ]
    first_resume = resume_positions[0] if resume_positions else None
    # Response-level resume outcome: the resume request's own JSON-RPC
    # response (a later frame carrying result or error under the same id)
    # must exist and carry no error. A resume that the server rejected is a
    # failure even when no full-replay session/new follows. Ids are matched
    # only when hashable scalars; a non-response frame under the same id
    # never counts.
    resume_request_ordinals: dict[Any, int] = {}
    for ordinal, entry in enumerate(recorder.frames):
        frame = entry["frame"]
        if (
            entry["dir"] == "out"
            and isinstance(frame, dict)
            and frame.get("method") == "session/resume"
        ):
            request_id = frame.get("id")
            if _jsonrpc_id_is_scalar(request_id):
                resume_request_ordinals.setdefault(request_id, ordinal)
    resume_response_seen = False
    resume_response_error = False
    for ordinal, entry in enumerate(recorder.frames):
        frame = entry["frame"]
        if entry["dir"] != "in" or not isinstance(frame, dict):
            continue
        response_id = frame.get("id")
        if (
            not _jsonrpc_id_is_scalar(response_id)
            or response_id not in resume_request_ordinals
            or ordinal <= resume_request_ordinals[response_id]
        ):
            continue
        if "result" not in frame and "error" not in frame:
            continue
        resume_response_seen = True
        if isinstance(frame.get("error"), dict):
            resume_response_error = True
    resume_fell_back = (
        first_resume is not None
        and any(i > first_resume for i in new_positions)
    )
    resume_succeeded = (
        first_resume is not None
        and resume_response_seen
        and not resume_response_error
        and not resume_fell_back
    )
    new_dt = (
        launch_seq[new_positions[0]].get("disabled_tools")
        if new_positions
        else None
    )
    resume_dt = (
        launch_seq[first_resume].get("disabled_tools")
        if first_resume is not None
        else None
    )
    # Vacuity guard: two missing/empty restriction lists are NOT evidence of
    # preservation; only a non-empty pin observed on BOTH launches can be
    # compared. Otherwise the result stays undetermined (None).
    disabled_tools_preserved = None
    if (
        resume_succeeded
        and isinstance(new_dt, list)
        and isinstance(resume_dt, list)
        and new_dt
        and resume_dt
    ):
        disabled_tools_preserved = sorted(new_dt) == sorted(resume_dt)
    resume_observation: dict[str, Any] = {
        "follow_up_requested": args.follow_up is not None,
        "resume_seen": first_resume is not None,
        "resume_succeeded": resume_succeeded if first_resume is not None else None,
        "resume_fell_back_to_new": resume_fell_back if first_resume is not None else None,
        "new_launch_disabled_tools": new_dt,
        "resume_launch_disabled_tools": resume_dt,
        "resume_response_seen": resume_response_seen,
        "resume_response_error": resume_response_error,
        "run_command_pinned_on_both": (
            isinstance(new_dt, list)
            and isinstance(resume_dt, list)
            and "run_command" in new_dt
            and "run_command" in resume_dt
        ),
        "disabled_tools_preserved": disabled_tools_preserved,
    }
    denial_records = []
    activity_sequence = []
    for tool_id, rec in analysis["tools"].items():
        if tool_id == "__session__":
            continue
        positions = [
            i for i, stage in enumerate(rec["stages"])
            if stage.get("pre_tool_hook_denial")
        ]
        ordinal = rec.get("first_activity_ordinal")
        activity_sequence.append({
            "tool_call_id": tool_id,
            "names": rec["names"],
            "first_activity_ordinal": ordinal,
        })
        if positions:
            denial_records.append({
                "names": rec["names"],
                "origins": rec["origins"],
                "kinds": rec["kinds"],
                "denial_stage_positions": positions,
                "stage_count": len(rec["stages"]),
                "first_activity_ordinal": ordinal,
            })
    activity_sequence.sort(
        key=lambda record: (
            record["first_activity_ordinal"]
            if record["first_activity_ordinal"] is not None
            else -1
        )
    )
    fallback_observation = {
        "denied_tool_records": denial_records,
        "tool_activity_sequence": activity_sequence,
        "note": (
            "facts only; the native-denial -> fallback transition verdict is "
            "made by the evidence reviewer against issue #13 criteria"
        ),
    }
    summary = {
        "mode": args.mode,
        "cwd": cwd,
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "answer_char_count": len(answer or ""),
        "follow_up_answer_char_count": (
            None
            if args.follow_up is None or follow_up_skipped_reason is not None
            else len(follow_up_answer or "")
        ),
        "error": error,
        "effects": effects,
        "permission_telemetry": collector.events,
        "permission_log_messages": collector.messages[:20],
        "bridge_tool_call_facts": {
            "advertised": bool(bridge_tools),
            "calls": bridge_facts,
            "follow_up_skipped_reason": follow_up_skipped_reason,
        },
        "resume_observation": resume_observation,
        "fallback_observation": fallback_observation,
        "analysis": analysis,
    }
    (evidence_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    tools = analysis["tools"]
    print(json.dumps({
        "mode": args.mode,
        "error": error,
        "effects": effects,
        "tool_ids": sorted(tools),
        "telemetry_events": len(collector.events),
        "resume_observation": resume_observation,
        "evidence": str(evidence_dir),
    }, indent=2))
    recorder._fh.close()
    return 0 if error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
