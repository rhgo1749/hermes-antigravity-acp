"""Standalone OpenAI-compatible client for Google's official Antigravity ACP server.

This module deliberately owns the ACP transport instead of subclassing Hermes'
``agent.copilot_acp_client.CopilotACPClient``.  The only Hermes contract the
provider needs is ``ProviderProfile.create_client()`` returning an object with a
``chat.completions.create`` surface.

The client keeps Antigravity-specific behavior here:
- faithful replay of Hermes tool calls/results,
- completed-tool and no-progress duplicate guards,
- stable per-conversation mux affinity,
- durable ACP ``session/resume`` with append-only delta prompts,
- bounded account failover for quota/auth failures.
"""

from __future__ import annotations

import asyncio
import atexit
import base64
import contextlib
import hashlib
import itertools
from importlib import import_module
import json
import logging
import math
import os
import queue
import re
import secrets
import subprocess
import stat
import tempfile
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote
from typing import Any, NoReturn

from .conversation_state import ACPConversationState, conversation_registry
from .hermes_compat import (
    apply_subprocess_home_env,
    build_hermes_subprocess_env,
    get_current_write_origin,
    get_file_read_safety,
    get_file_write_safety,
    get_hermes_home,
    get_hermes_home_for_video,
    get_nt_namespace_error,
    get_runtime_session_env,
    hermes_runtime_present,
    is_delegated_child_context,
    resolve_agent_cwd,
    windows_hide_flags,
)
from .native_limit_state import native_limit_registry
from .bridge import (
    MalformedToolCallError,
    advertised_tool_names,
    completion_to_stream_chunks,
    extract_tool_calls_from_text,
    render_tool_bridge_sections,
)


# Generic optional policy-overlay hook (historical reference rework-r2, rework-r4).
#
# The public client never knows — and never matches — which personal profile
# it serves, never names any overlay module, and never interprets any user
# constitution. A deployment MAY stage optional policy overlay modules
# inside this provider package; each overlay owns its activation and
# identity semantics through its own ``is_active()``. The client only
# forwards to the loaded overlays (when any): their ``SYSTEM_PROMPT`` and
# their execution-claim enforcement.
#
# Fail-closed obligation-evidence precedence (rework-r4): extension modules
# are named by deployment EVIDENCE, never by a hardcoded name here.
#
#   1. This package's ``install-provenance.json`` — the installer-owned
#      record written beside every standalone-installed tree. A well-formed
#      record listing ``.py`` modules under ``managed_files`` that are
#      absent from the tree, or declaring ``required_extensions`` that
#      cannot be imported, aborts the provider import.
#   2. A provenance record that is unreadable, non-dict, or whose
#      ``managed_files`` is missing or non-dict is ambiguous and aborts the
#      import: an unknown record can never rule an obligation out.
#   3. The generic per-home obligation record ``policy-obligation.json``
#      (``{"required_extensions": [...]}``) under the ACTIVE Hermes home —
#      written at deploy time by policy-required deployments and by the
#      private-ops migration tooling — aborts the import when it declares
#      a module that cannot be imported. An unreadable record, or a home
#      that cannot be resolved at all, aborts too (fail closed).
#   4. With neither provenance nor obligation record, the tree is a
#      verified clean public install and loads with no policy — generic,
#      overlay-less installs stay completely unhindered.
#
# Extension modules PRESENT in the package tree are always loaded: an
# installed overlay is never silently ignored. Presence is optional;
# declared obligation is mandatory.
_PROVENANCE_FILE = "install-provenance.json"
_OBLIGATION_RECORD_FILE = "policy-obligation.json"
_REQUIRED_EXTENSIONS_KEY = "required_extensions"
_OWN_PACKAGE_FILES = frozenset({"__init__.py", Path(__file__).name})
_EXTENSION_MODULE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _refuse_obligation(reason: str) -> NoReturn:
    raise RuntimeError(
        f"Refusing to start this provider tree: {reason}; deployment "
        "obligation evidence that cannot be verified is never treated as absent"
    )


def _extension_names(value: object, source: str) -> list[str]:
    """Validate a ``required_extensions`` value; refuse on anything ambiguous."""
    if value is None:
        return []
    if not isinstance(value, list) or not all(
        isinstance(name, str) and _EXTENSION_MODULE_NAME_RE.fullmatch(name) for name in value
    ):
        _refuse_obligation(f"the {source} carries a malformed {_REQUIRED_EXTENSIONS_KEY} declaration")
    return list(value)


def _read_json_record(path: Path, source: str) -> dict[str, Any] | None:
    """Parse a record; absent is None, unreadable/ambiguous refuses the start."""
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        _refuse_obligation(f"{source} at {path.name} cannot be read as JSON")
    if not isinstance(payload, dict):
        _refuse_obligation(f"{source} at {path.name} is not a JSON object")
    return payload


def _declared_extension_modules(package_dir: Path) -> list[str]:
    """Module names the deployment evidence requires to be importable."""
    required: list[str] = []
    provenance = _read_json_record(package_dir / _PROVENANCE_FILE, "install provenance record")
    if provenance is not None:
        managed = provenance.get("managed_files")
        if not isinstance(managed, dict):
            _refuse_obligation(
                "the install provenance record has no well-formed managed_files mapping"
            )
        for filename in sorted(managed):
            if (
                isinstance(filename, str)
                and filename.endswith(".py")
                and filename not in _OWN_PACKAGE_FILES
                and not (package_dir / filename).is_file()
            ):
                _refuse_obligation(
                    f"install provenance declares managed extension module {filename} "
                    "which is absent from this tree"
                )
        required.extend(
            _extension_names(provenance.get(_REQUIRED_EXTENSIONS_KEY), "install provenance record")
        )
    try:
        home = get_hermes_home()
    except Exception:
        # The active Hermes home cannot be resolved at all, so the presence
        # of a per-home obligation record cannot be verified: fail closed.
        _refuse_obligation(
            "the active Hermes home cannot be resolved to verify the policy obligation record"
        )
    record = _read_json_record(home / _OBLIGATION_RECORD_FILE, "policy obligation record")
    if record is not None:
        required.extend(
            _extension_names(record.get(_REQUIRED_EXTENSIONS_KEY), "policy obligation record")
        )
    return list(dict.fromkeys(required))


def _load_policy_overlays() -> tuple[Any, ...]:
    """Import declared-required and present extension modules; refuse on broken obligations."""
    package_dir = Path(__file__).resolve().parent
    loaded: dict[str, Any] = {}
    for name in _declared_extension_modules(package_dir):
        qualified = f"{__package__}.{name}"
        try:
            loaded[name] = import_module(qualified)
        except ModuleNotFoundError as exc:
            if exc.name not in {qualified, name}:
                raise
            _refuse_obligation(
                f"extension module {name} is declared as required by the "
                "deployment but cannot be imported"
            )
    for path in sorted(package_dir.glob("*.py")):
        name = path.stem
        if path.name in _OWN_PACKAGE_FILES or name in loaded:
            continue
        # A module file that is present here is part of this tree; a real
        # import error in it must surface, never be swallowed.
        loaded[name] = import_module(f"{__package__}.{name}")
    # Only overlay-shaped modules are ever forwarded to; the package's own
    # sibling modules were already imported through normal imports above.
    return tuple(module for module in loaded.values() if hasattr(module, "is_active"))


policy_overlays = _load_policy_overlays()

logger = logging.getLogger(__name__)

ACP_MARKER_BASE_URL = "acp://antigravity"
_DEFAULT_TIMEOUT_SECONDS = 900.0
_ROLE_LABELS = {
    "system": "System",
    "user": "User",
    "assistant": "Assistant",
    "tool": "Tool",
    "context": "Context",
}
_PROMPT_PREAMBLE = (
    "You are being used as the active ACP agent backend for Hermes.",
    "Use ACP capabilities to complete tasks.",
    "For read-only evidence paths under the Hermes scratch/cache area that are outside the ACP session cwd, "
    "prefer an available Hermes file-read tool (for example read_file) so Hermes can enforce policy and record evidence. "
    "If no Hermes file-read tool is available, use the ACP client fs/read_text_file capability. "
    "Never use shell/cat/execute to bypass workspace boundaries, and do not use this exception for writes.",
    "For shell commands, builds, tests, and GitHub CLI work, use an available Hermes terminal tool via "
    "the Hermes <tool_call> bridge. ACP-native run_command is disabled in Hermes model-provider mode. "
    "If the Hermes tool is unavailable or denies the action, report that outcome without attempting a bypass.",
    "IMPORTANT: If you take an action with a Hermes tool, you MUST output tool calls using "
    "<tool_call>{...}</tool_call> blocks with JSON exactly in OpenAI function-call shape.",
    "If no Hermes tool is needed, answer normally.",
)
_TOOL_HISTORY_CONTINUATION_NOTE = (
    "Continuation rule: tool calls and tool responses in the conversation transcript are completed past actions. "
    "Use their returned content as current evidence. Do not repeat an identical tool call merely because a standing "
    "system instruction says to call that tool first, orient, initialize, or inspect state. Repeat a completed call "
    "only when new evidence makes a fresh read necessary. If a tool response says the state/result is unchanged or "
    "that repeating the call makes no progress, continue with the result already present instead of calling it again."
)
_DUPLICATE_NO_PROGRESS_CORRECTION = (
    "Your proposed tool call exactly repeats the most recent completed call, and that call's tool response explicitly "
    "reported that the result/state is unchanged. That exact tool is deliberately unavailable for this correction "
    "turn. Do not emit it again. Continue from the existing result: choose a different available tool only if it "
    "advances the task, otherwise answer or perform the next required action."
)
_MAX_DUPLICATE_NO_PROGRESS_CORRECTIONS = 2
_MALFORMED_TOOL_CALL_CORRECTION = (
    "Your immediately previous response attempted a Hermes tool call with malformed JSON or delimiters "
    "and was NOT accepted. "
    "Do not repeat any earlier completed tools. Re-emit ONLY the same intended "
    "<tool_call>{...}</tool_call>, with function.arguments as valid JSON. "
    "Do not invent a different action or claim that a setting was changed."
)
_MAX_MALFORMED_TOOL_CALL_CORRECTIONS = 1
_ARTIFACT_CLAIM_CORRECTION = (
    "Your previous final answer claimed one or more Hermes scratch artifacts that do not exist on disk. "
    "Do not repeat or invent those paths. If the task still requires those artifacts, emit the exact Hermes tool call "
    "needed to create or inspect them now; otherwise give a corrected final answer that accurately states what exists."
)
_MAX_ARTIFACT_CLAIM_CORRECTIONS = 1
_READ_EVIDENCE_CORRECTION = (
    "The active request explicitly requires auditable inspection of real source, diff, or files, but the previous "
    "answer has no adapter-observed completed read/search evidence. Do not claim that you inspected code yet. "
    "Before giving the review, either use an available Hermes read/search tool by emitting its exact "
    "<tool_call>{...}</tool_call>, or use an ACP-native read/view/search tool. Base file/line claims only on what "
    "you actually read. If inspection is unavailable, say so instead of fabricating source evidence."
)
_MAX_READ_EVIDENCE_CORRECTIONS = 1
_READ_TOOL_NAME_RE = re.compile(
    r"(?:^|[_./-])(?:read|view|search|grep|find)(?:[_./-]|$)|"
    r"(?:client_view_file|client_read_file|search_files|grep_search|find_in_files)",
    re.IGNORECASE,
)
_INITIALIZE_PARAMS = {
    "protocolVersion": 1,
    "clientCapabilities": {"fs": {"readTextFile": True, "writeTextFile": True}},
    "clientInfo": {
        "name": "hermes-antigravity-acp",
        "title": "Hermes Antigravity ACP",
        "version": "1.0.0",
    },
}
_RATE_LIMIT_RE = re.compile(
    r"(?:\b429\b|resource[_ -]?exhausted|too many requests|rate[_ -]?limit(?:ed)?|"
    r"quota(?:\s+(?:exceeded|exhausted|depleted|reached|unavailable)))",
    re.IGNORECASE,
)
_AUTH_RE = re.compile(
    r"(?:\b401\b|\b403\b|unauthenticated|invalid[_ -]?grant|"
    r"authentication\s+(?:failed|failure|required)|authorization\s+(?:failed|failure)|"
    r"(?:access|refresh|id)?\s*token\s+(?:expired|revoked|invalid))",
    re.IGNORECASE,
)
_ACP_DIAGNOSTIC_MAX_CHARS = 512
_ACP_DIAGNOSTIC_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_ACP_OAUTH_URL_RE = re.compile(
    r"(?:oauth|authorize|accounts\.google|googleapis\.com/(?:auth|token)|openid-connect)",
    re.IGNORECASE,
)
_ACP_OAUTH_QUERY_RE = re.compile(
    r"[?&](?:code|access_token|refresh_token|id_token|token|authorization_code)=",
    re.IGNORECASE,
)
_ACP_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:access[_ -]?token|refresh[_ -]?token|id[_ -]?token|token|"
    r"authorization[_ -]?code|auth[_ -]?code)\b\\?[\"']?\s*[:=]\s*)"
    r"(?:\\?\"[^\"]*\\?\"|\\?'[^']*\\?'|[^\s,;<>]+)"
)
_ACP_SECRET_QUERY_RE = re.compile(
    r"(?i)([?&](?:access_token|refresh_token|id_token|token|code|"
    r"authorization_code|auth_code)=)[^&#\s]+"
)
_ACP_BARE_AUTH_CODE_RE = re.compile(
    r"(?i)(\b(?:authorization|auth)\s+code\s+)"
    r"(?!(?:expired|invalid|required|missing|was|is|not)\b)([A-Za-z0-9._~-]{6,})"
)
_ACP_BARE_TOKEN_RE = re.compile(
    r"(?i)(\b(?:access|refresh|id)[ _-]?token\s+)([A-Za-z0-9._~+/-]{20,})"
)


def _redact_acp_error_detail(value: Any) -> str:
    """Redact credentials and bound a human-readable ACP error detail."""
    if not isinstance(value, str):
        return ""

    text = value.strip()
    text = re.sub(
        r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*",
        "Bearer [REDACTED]",
        text,
    )
    text = _ACP_SECRET_ASSIGNMENT_RE.sub(r"\1[REDACTED]", text)
    text = _ACP_BARE_AUTH_CODE_RE.sub(r"\1[REDACTED]", text)
    text = _ACP_BARE_TOKEN_RE.sub(r"\1[REDACTED]", text)

    def redact_url(match: re.Match[str]) -> str:
        url = match.group(0)
        if _ACP_OAUTH_URL_RE.search(url) or _ACP_OAUTH_QUERY_RE.search(url):
            return "[REDACTED_OAUTH_URL]"
        return _ACP_SECRET_QUERY_RE.sub(r"\1[REDACTED]", url)

    text = _ACP_DIAGNOSTIC_URL_RE.sub(redact_url, text)
    if len(text) > _ACP_DIAGNOSTIC_MAX_CHARS:
        text = text[: _ACP_DIAGNOSTIC_MAX_CHARS - 1].rstrip() + "…"
    return text


# ACP child-process stderr is UNTRUSTED output: a server stuck in a login or
# headless-auth wait can print live credentials in shapes no fixed scrubber
# can anticipate, so the runtime never echoes raw stderr into exceptions,
# default logs, chat responses, or telemetry (historical reference).  Diagnostics carry
# only a deterministic, non-reversible summary: captured-tail line/byte
# counts, a truncated sha256 fingerprint for correlation, and which
# credential-shape CLASS names were observed (names, never values).  This is
# a deliberate runtime-local copy of the standalone installer script's
# no-echo principle; the standalone runtime plugin must not import installer
# code.
_ACP_STDERR_CREDENTIAL_SHAPES = (
    (
        "token-assignment",
        re.compile(
            r"(?i)\b(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|api[_ -]?key|"
            r"client[_ -]?secret|oauth[_ -]?token)\b\s*[:=]"
        ),
    ),
    ("authorization-header", re.compile(r"(?i)\bauthorization\b\s*[:=]")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{6,}={0,2}")),
    ("oauth-url", re.compile(r"(?i)https?://[^\s]*(?:accounts\.google\.com|oauth)[^\s]*")),
    ("google-access-token-prefix", re.compile(r"\bya29\.[A-Za-z0-9._-]{4,}")),
    ("google-api-key-prefix", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}")),
    ("github-token-prefix", re.compile(r"\bgh[opurs]_[A-Za-z0-9]{20,}")),
    ("pem-private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("cookie-header", re.compile(r"(?i)\bcookie\b\s*[:=]")),
)


def _acp_stderr_diagnostic(lines: list[str]) -> str:
    """Non-echoing, non-reversible summary of untrusted ACP child stderr.

    Deterministic for identical input; bounded; contains no substring of the
    child's output beyond fixed class names and the fingerprint.
    """
    raw = "\n".join(lines).encode("utf-8", "replace")
    decoded = raw.decode("utf-8", "replace")
    nonempty = [line for line in decoded.splitlines() if line.strip()]
    observed = sorted(
        name
        for name, pattern in _ACP_STDERR_CREDENTIAL_SHAPES
        if any(pattern.search(line) for line in nonempty)
    )
    return (
        "server stderr suppressed (untrusted text is never echoed; "
        "credential-shaped material may be live): captured tail "
        f"{len(nonempty)} line(s), {len(raw)} byte(s), "
        f"sha256={hashlib.sha256(raw).hexdigest()[:16]}; "
        f"credential-shape classes observed: "
        f"{', '.join(observed) if observed else 'none'}"
    )


# Retry/failure classification for the early-exit path (historical reference rework,
# Reviewer review-record): suppressing the stderr echo must not suppress
# previously-eligible failover.  The client's pre-existing failover
# signature regexes run over the captured untrusted stderr AT CAPTURE
# TIME; only the resulting FIXED class name travels to the retry/failover
# decision on a structured exception attribute, so the exception TEXT
# stays the bounded no-echo summary and string classification never sees
# raw child output.
_ACP_STDERR_RETRY_CLASSES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("rate-limit", _RATE_LIMIT_RE),
    ("authentication", _AUTH_RE),
)
_FAILOVER_RETRY_CLASSES = frozenset(name for name, _ in _ACP_STDERR_RETRY_CLASSES)


def _acp_stderr_retry_class(lines: list[str]) -> str | None:
    """Structured retry/failure class derived from captured child stderr.

    Returns one of the fixed ``_FAILOVER_RETRY_CLASSES`` names, or ``None``.
    The return value is always one of the client's own constants — never a
    substring of the child's output.
    """
    text = "\n".join(lines)
    return next(
        (name for name, pattern in _ACP_STDERR_RETRY_CLASSES if pattern.search(text)),
        None,
    )


class _AcpEarlyExitError(RuntimeError):
    """Early-exit RuntimeError carrying a safe, structured retry signal.

    ``acp_retry_class`` holds only a fixed class name from
    ``_FAILOVER_RETRY_CLASSES`` (or ``None``); the public message remains
    the bounded no-echo diagnostic, and the attribute never appears in
    ``str()``/``repr()`` output.
    """

    def __init__(self, message: str, *, acp_retry_class: str | None = None) -> None:
        super().__init__(message)
        self.acp_retry_class = acp_retry_class


def _is_failover_error(exc: BaseException) -> bool:
    if isinstance(exc, _AcpEarlyExitError):
        # historical reference rework 2 (Reviewer review-record / run 458): early-exit
        # classification is EXCLUSIVELY structured.  The bounded no-echo
        # diagnostic embeds the captured stderr byte count, so a benign
        # tail of exactly 401/403/429 bytes matched the word-boundary
        # auth/rate-limit signatures when the string path below consumed
        # it.  Use only the capture-time class here; never parse the
        # generated diagnostic or any stderr-derived summary as a
        # fallback.  Legacy string classification is retained verbatim
        # for unrelated (non-early-exit) errors.
        return exc.acp_retry_class in _FAILOVER_RETRY_CLASSES
    text = str(exc)
    return bool(_RATE_LIMIT_RE.search(text) or _AUTH_RE.search(text))


# In-band digests (mux-synthesized or client-suppressed) exhaust the quota
# at the provider already, so their failover allowance is a single replay,
# independent of the transport retry budget (default 2, configurable to 8).
_INBAND_DIGEST_REPLAY_LIMIT = 1
_INBAND_DIGEST_RE = re.compile(
    r"provider (?:quota|connection) failure \(resource_exhausted"
)


def _is_inband_digest_error(exc: BaseException) -> bool:
    return bool(_INBAND_DIGEST_RE.search(str(exc)))


# 1.2.1 renders some provider failures as an assistant-message digest followed
# by a successful prompt response (contract doc D3).  Anchored at the very
# start of the turn text, these signatures are vendor digests, not answers.
_VENDOR_QUOTA_SIGNATURE = (
    "Usage Limit Reached\n\n"
    "You have reached your current quota for this period."
)
_VENDOR_CONNECTION_PREFIX = (
    "Agent connection was lost and could not be re-established:"
)


def _vendor_turn_digest(answer: str) -> str | None:
    """Classify a turn whose entire text is a vendor failure digest."""
    if answer.startswith(_VENDOR_QUOTA_SIGNATURE):
        return "quota"
    if answer.startswith(_VENDOR_CONNECTION_PREFIX):
        return "connection-lost"
    return None


def _resolve_home_dir() -> str:
    if home := os.environ.get("HOME", "").strip():
        return home
    if (expanded := os.path.expanduser("~")) and expanded != "~":
        return expanded
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir.strip() or tempfile.gettempdir()
    except Exception:
        return tempfile.gettempdir()


def _read_par_pin() -> str | None:
    """Per-deployment official-PAR pin for canary/pilot isolation.

    A ``par.txt`` sitting next to THIS plugin copy overrides which official
    server the mux spawns for processes started from this home only; other
    homes keep their own default.  Fail-closed: a non-empty pin that points at
    a missing file raises instead of silently running the default server,
    because a silently ignored pin would run 1.2.1 traffic labeled as canary.
    """
    path = Path(__file__).resolve().with_name("par.txt")
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    pin = raw.strip()
    if not pin:
        return None
    if not os.path.isfile(pin):
        raise RuntimeError(
            f"antigravity-acp: par.txt pins missing PAR {pin!r}; refusing to "
            "fall back to the default server silently"
        )
    return pin


# ACP child minimum-environment contract (historical reference rework rounds 2-3). The
# official Google ACP child needs local runtime state only; Google authentication
# is managed inside Google's own runtime and the catalog declares an empty
# ``requires_env`` surface. Hermes' policy is consulted first, but its result is
# never the contract: upstream ``hermes_subprocess_env(inherit_credentials=True)``
# intentionally retains Tier-2 provider credentials (verified against the real
# unmodified upstream at the v0.21.6 floor and main in
# tests/test_upstream_hermes_runtime_contracts.py), so everything not on this
# explicit allowlist — provider/cloud credentials, gateway tokens, operator
# ``ACP_MUX_*`` multiplexor configuration, session identity — is dropped before
# the child is spawned. ``_spawn`` supplies the multiplexor coordination keys
# it owns itself, after this filter.
_ACP_CHILD_ENV_ALLOW_EXACT = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "TERM",
    "TMPDIR",
    "TEMP",
    "TMP",
    "PYTHONUTF8",
    "HERMES_REAL_HOME",
    "HERMES_HOME",
    "GEMINI_HOME",
    # POSIX locale categories, enumerated.  Rework round 2 admitted these via
    # an ``LC_`` wildcard; the maintainer P2 (historical reference) showed a
    # prefix silently authorizes arbitrary future names (``LC_API_TOKEN``).
    # Values here are locale names such as ``en_US.UTF-8`` — never paths.
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_COLLATE",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    # Windows OS and profile roots.  HOME is usually unset in Windows shells,
    # and a child process without SYSTEMROOT cannot even start; without the
    # profile roots the official server has no home directory and dies at
    # startup before answering initialize (verified on hosted
    # windows-2022/windows-11-arm: full env OK, filtered env silent-timeout).
    # These are OS/path basics, never credential material.
    "SYSTEMROOT",
    "WINDIR",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
}
# The four XDG Base Directory variables the specification roots under $HOME
# ($HOME/.config, $HOME/.local/share, $HOME/.cache, $HOME/.local/state).  Like
# the locale categories these are enumerated, not prefix-matched; in addition,
# ``_acp_child_env_filter`` admits their values only when they resolve inside
# the child's own profile home, so a parent or sibling profile's path is never
# copied in merely because the key name is approved.  XDG_RUNTIME_DIR (rooted
# in /run/user/<uid>), the system-wide XDG_*_DIRS search lists, and desktop
# session identity variables are not needed by the headless ACP child and stay
# off the allowlist.  Dropped bases fall back to the spec defaults under the
# child's own HOME, which are profile-scoped by construction.
_ACP_CHILD_ENV_ALLOW_XDG_DIRS = {
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
}


def _is_acp_child_env_key(key: str) -> bool:
    # Names fold to uppercase for membership: on Windows the env block itself
    # is case-insensitive, so a lowercase-stored ``openai_api_key`` IS its
    # uppercase credential twin and must not slip through on casing alone.
    # Admission is an explicit enumeration only — no wildcard prefixes.
    folded = key.upper()
    return folded in _ACP_CHILD_ENV_ALLOW_EXACT or folded in _ACP_CHILD_ENV_ALLOW_XDG_DIRS


def _xdg_dir_is_profile_scoped(value: str, profile_home: Path) -> bool:
    """True only when an XDG base resolves inside the child's own profile home."""
    candidate = (value or "").strip()
    if not candidate:
        return False
    try:
        expanded = os.path.expandvars(candidate)
        if expanded.startswith("~") or "$HOME" in candidate or "${HOME}" in candidate:
            # ``~`` and ``$HOME`` spellings must expand against the child's own
            # resolved home, never the parent's ambient HOME value mid-build.
            expanded = expanded.replace("$HOME", str(profile_home))
            expanded = expanded.replace("${HOME}", str(profile_home))
        resolved = Path(expanded).expanduser().resolve()
        root = profile_home.resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    resolved_key = os.path.normcase(str(resolved))
    root_key = os.path.normcase(str(root))
    return resolved_key == root_key or resolved_key.startswith(root_key + os.sep)


def _acp_child_env_filter(
    env: dict[str, str], *, profile_home: str | Path | None = None
) -> dict[str, str]:
    """Narrow any candidate environment to the ACP child minimum contract.

    XDG base-directory values additionally face a profile-scoping check
    against the child's own home: an approved key name never licenses a
    parent/sibling profile's path.
    """
    home = Path(profile_home) if profile_home is not None else Path(_resolve_home_dir())
    narrowed: dict[str, str] = {}
    for key, value in env.items():
        folded = key.upper()
        if folded in _ACP_CHILD_ENV_ALLOW_EXACT:
            narrowed[key] = value
        elif folded in _ACP_CHILD_ENV_ALLOW_XDG_DIRS and _xdg_dir_is_profile_scoped(
            value, home
        ):
            narrowed[key] = value
    return narrowed


def _build_subprocess_env() -> dict[str, str]:
    """Build the ACP child environment under the ACP minimum contract.

    Hermes' credential-aware subprocess policy is the base when available; the
    documented local allowlist is the base in a lightweight test environment
    without Hermes internals. Either base is then narrowed by the same ACP
    child contract, so neither arbitrary secret-bearing environment keys nor
    inherited ``ACP_MUX_*`` configuration can cross the process boundary —
    regardless of what the host policy returns.
    """
    child_home = _resolve_home_dir()
    env = build_hermes_subprocess_env()
    if env is None:
        env = dict(os.environ)
    env = _acp_child_env_filter(env, profile_home=child_home)
    if hermes_runtime_present():
        env["HERMES_HOME"] = str(get_hermes_home())
    env["HOME"] = child_home
    apply_subprocess_home_env(env)
    return env


def _windows_hide_flags() -> int:
    return windows_hide_flags()


def _jsonrpc_result(message_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def _jsonrpc_error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {"code": code, "message": message},
    }


def _enabled_id_list(entries: Any, key: str) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        value = str(entry.get(key) or "").strip()
        if (
            not value
            or value in seen
            or str((entry.get("_meta") or {}).get("copilotEnablement") or "").strip().lower()
            == "disabled"
        ):
            continue
        seen.add(value)
        result.append(value)
    return result


def _model_config_options(session: dict[str, Any]) -> list[dict[str, Any]]:
    """Every model-category ``configOptions`` group the server authored.

    Matched on the declared ``category``/``id`` only; the values inside each
    group come from the session itself and no model name is asserted here.
    This is a list rather than a single ``next(...)`` because a server is free
    to split its models across groups (a second model family is exactly the
    case that would otherwise disappear from the picker silently).
    """
    return [
        option
        for option in (session.get("configOptions") or [])
        if isinstance(option, dict) and "model" in (option.get("category"), option.get("id"))
    ]


def _model_config_option(session: dict[str, Any]) -> dict[str, Any] | None:
    options = _model_config_options(session)
    return options[0] if options else None


_THINKING_LEVEL_ENV = "HERMES_ANTIGRAVITY_ACP_THINKING_LEVEL"
_REASONING_EFFORT_TO_THINKING_LEVEL = {
    "none": "low",
    "minimal": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",
    "max": "high",
    "ultra": "high",
}
# Values are mapped into the server's own option list; nothing here asserts
# which levels a given account exposes.  The eight Hermes reasoning-effort
# levels clamp monotonically onto the thinking levels the server exposes:
# efforts below the low floor (none/minimal) land on low, efforts above the
# high ceiling (xhigh/max/ultra) clamp onto high.
_VALID_THINKING_LEVELS = frozenset({"low", "medium", "high"})


def _thinking_level_config_option(session: dict[str, Any]) -> dict[str, Any] | None:
    """The server-authored thinking-level select, or None when it has none.

    Matched on the declared ``category``/``id`` only; option values come from
    the session itself and are never assumed here.
    """
    return next(
        (
            option
            for option in (session.get("configOptions") or [])
            if isinstance(option, dict)
            and str(option.get("category") or "").strip().lower() == "thought_level"
            and str(option.get("id") or "").strip().lower() in {"", "thinking_level", "thought_level"}
        ),
        None,
    )


def _desired_thinking_level(reasoning_effort: object) -> tuple[str | None, str]:
    """``(level, source)`` from the profile env override, else the request's
    ``reasoning_effort`` mapped into thinking levels. ``(None, "")`` when the
    caller expressed nothing — the server session default then stands."""
    override = os.environ.get(_THINKING_LEVEL_ENV, "").strip().lower()
    if override:
        return (override, "env") if override in _VALID_THINKING_LEVELS else (None, "env")
    effort = str(reasoning_effort or "").strip().lower()
    if not effort:
        return None, ""
    if effort in _VALID_THINKING_LEVELS:
        return effort, "reasoning_effort"
    mapped = _REASONING_EFFORT_TO_THINKING_LEVEL.get(effort)
    return (mapped, "reasoning_effort") if mapped else (None, "")


def _env_override_present() -> bool:
    return bool(os.environ.get(_THINKING_LEVEL_ENV, "").strip())


def _thinking_level_selection(
    session: dict[str, Any], desired: str
) -> tuple[str, dict[str, str]] | None:
    """``session/set_config_option`` args for a desired level, or None.

    The desired value must be one the server actually authored for this
    session; an unoffered level is refused here and reported by the caller,
    never force-sent and never silently substituted.
    """
    option = _thinking_level_config_option(session)
    if option is None:
        return None
    offered = [
        str(entry.get("value") or "").strip()
        for entry in (option.get("options") or [])
        if isinstance(entry, dict)
    ]
    if desired not in offered:
        return None
    return (
        "session/set_config_option",
        {
            "sessionId": str(session.get("sessionId") or "").strip(),
            "configId": str(option.get("id") or "thinking_level"),
            "value": desired,
        },
    )


def _legacy_session_model_ids(session: dict[str, Any]) -> list[str]:
    return _enabled_id_list((session.get("models") or {}).get("availableModels"), "modelId")


def _session_model_ids(session: dict[str, Any]) -> list[str]:
    """Every model id this session offers, across both server surfaces.

    The official 1.4.x server authors two axes with different contents: a
    base-model ``configOptions`` group and the composite legacy
    ``models.availableModels`` rows, each tracking its own current id.  The
    offered set is the union of both, never one preferred over the other --
    preferring one surface hid the other's ids from resume-time validation and
    from ``list_models``.
    """
    ids: list[str] = []
    for option in _model_config_options(session):
        ids.extend(_enabled_id_list(option.get("options"), "value"))
    ids.extend(_legacy_session_model_ids(session))
    return list(dict.fromkeys(ids))


def _model_selection_request(
    session: dict[str, Any], requested_model: str
) -> tuple[str, dict[str, str]] | None:
    """The request that actually selects ``requested_model``, or ``None``.

    Two server-authored axes, two methods.  A value a ``configOptions`` model
    group offered is set through that group; an id the legacy
    ``models.availableModels`` surface offered is set through
    ``session/set_model``, which the official 1.4.x server accepts for exactly
    those ids.  Routing the legacy ids through the config group instead made
    them unselectable no-ops, so a picker could display rows that changed
    nothing.  An id neither surface authored is refused here, never force-sent
    and never silently substituted.  When the server authored no model surface
    at all there is nothing to check against, so the legacy method is
    attempted and the caller judges the server's answer.
    """
    session_id = str(session.get("sessionId") or "").strip()
    requested_model = str(requested_model or "").strip()
    if not session_id or not requested_model or requested_model == "antigravity-acp":
        return None
    config_options = _model_config_options(session)
    for option in config_options:
        if requested_model in _enabled_id_list(option.get("options"), "value"):
            return (
                "session/set_config_option",
                {
                    "sessionId": session_id,
                    "configId": str(option.get("id") or "model"),
                    "value": requested_model,
                },
            )
    available = _legacy_session_model_ids(session)
    if requested_model in available:
        return "session/set_model", {"sessionId": session_id, "modelId": requested_model}
    if available or config_options:
        return None
    return "session/set_model", {"sessionId": session_id, "modelId": requested_model}


def _session_current_model(session: dict[str, Any]) -> str:
    models = session.get("models")
    if isinstance(models, dict):
        current_model = str(models.get("currentModelId") or "").strip()
        if current_model:
            return current_model

    option = _model_config_option(session)
    if option:
        return str(option.get("currentValue") or "").strip()
    return ""


def _redact_inline_image_payloads(value: Any) -> Any:
    """Keep image/video bytes out of prompt text; ACP media blocks carry payloads."""
    if isinstance(value, list):
        return [_redact_inline_image_payloads(item) for item in value]
    if not isinstance(value, dict):
        return value
    copied = dict(value)
    part_type = str(copied.get("type") or "").lower()
    if part_type == "image_url":
        image = copied.get("image_url")
        if isinstance(image, dict):
            image = dict(image)
            if str(image.get("url") or "").startswith("data:"):
                image["url"] = "[image pixels are attached as an ACP image block]"
            copied["image_url"] = image
        elif isinstance(image, str) and image.startswith("data:"):
            copied["image_url"] = "[image pixels are attached as an ACP image block]"
        return copied
    if part_type == "image" and isinstance(copied.get("data"), str):
        copied["data"] = "[image pixels are attached as an ACP image block]"
        return copied
    if part_type == "video_url":
        video = copied.get("video_url")
        if isinstance(video, dict):
            video = dict(video)
            if str(video.get("url") or "").startswith("data:"):
                video["url"] = "[video payload is attached as an ACP video block]"
            copied["video_url"] = video
        elif isinstance(video, str) and video.startswith("data:"):
            copied["video_url"] = "[video payload is attached as an ACP video block]"
        return copied
    if part_type == "video" and isinstance(copied.get("data"), str):
        copied["data"] = "[video payload is attached as an ACP video block]"
        return copied
    return {key: _redact_inline_image_payloads(item) for key, item in copied.items()}


def _fp_render_message_content(content: Any) -> str:
    """Fingerprint-path renderer. VERBATIM copy of the pre-redaction
    ``_render_message_content``; the persisted ``request_fingerprints`` in the
    conversation checkpoint were built from this exact text, so any drift
    silently forces a full replay and loses native resume for existing
    sessions. Never change this function to "match" the prompt renderers.
    """
    if content is None:
        return ""
    if isinstance(content, dict):
        if "text" in content:
            return str(content.get("text") or "").strip()
        if isinstance(content.get("content"), str):
            return content["content"].strip()
        return json.dumps(content, ensure_ascii=True)
    if isinstance(content, list):
        parts = [
            item if isinstance(item, str) else item["text"].strip()
            for item in content
            if isinstance(item, str)
            or (
                isinstance(item, dict)
                and isinstance(item.get("text"), str)
                and item["text"].strip()
            )
        ]
        return "\n".join(parts).strip()
    return str(content).strip()


def _fp_render_prompt_message(message: dict[str, Any], role: str) -> str:
    """Fingerprint-path row renderer; pinned to the pre-redaction version for
    the same checkpoint-compatibility reason as ``_fp_render_message_content``.
    The base64 it may include is only ever hashed in memory, never persisted
    or sent — only the SHA-256 fingerprint reaches the checkpoint, and prompt
    traffic goes through the redacting ``_render_prompt_message`` instead.
    """
    content = _fp_render_message_content(message.get("content"))
    if role == "assistant":
        parts = [content] if content else []
        for tool_call in message.get("tool_calls") or []:
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function")
            if not isinstance(function, dict) or not str(function.get("name") or "").strip():
                continue
            payload = {
                "id": str(tool_call.get("id") or ""),
                "type": str(tool_call.get("type") or "function"),
                "function": {
                    "name": str(function.get("name") or ""),
                    "arguments": function.get("arguments", "{}"),
                },
            }
            parts.append(
                f"<tool_call>\n{json.dumps(payload, ensure_ascii=False, default=str)}\n</tool_call>"
            )
        return "\n".join(parts).strip()
    if role == "tool" and message.get("tool_call_id"):
        result: Any = content
        if content.lstrip().startswith(("{", "[")):
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                pass
        payload: dict[str, Any] = {
            "tool_call_id": str(message["tool_call_id"]),
            "content": result,
        }
        if message.get("name"):
            payload["name"] = str(message["name"])
        return (
            f"<tool_response>\n{json.dumps(payload, ensure_ascii=False, default=str)}\n"
            "</tool_response>"
        )
    return content


def _render_message_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, dict):
        if content.get("_multimodal") is True:
            text = _render_message_content(content.get("content"))
            summary = str(content.get("text_summary") or "").strip()
            if summary and summary not in text:
                return "\n".join(part for part in (text, summary) if part)
            return text
        if "text" in content:
            return str(content.get("text") or "").strip()
        if isinstance(content.get("content"), str):
            return content["content"].strip()
        return json.dumps(_redact_inline_image_payloads(content), ensure_ascii=True)
    if isinstance(content, list):
        parts = [
            item if isinstance(item, str) else item["text"].strip()
            for item in content
            if isinstance(item, str)
            or (
                isinstance(item, dict)
                and isinstance(item.get("text"), str)
                and item["text"].strip()
            )
        ]
        return "\n".join(parts).strip()
    return str(content).strip()


def _render_prompt_message(message: dict[str, Any], role: str) -> str:
    """Render a history row while retaining call/result identity."""
    content = _render_message_content(message.get("content"))
    if role == "assistant":
        parts = [content] if content else []
        for tool_call in message.get("tool_calls") or []:
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function")
            if not isinstance(function, dict) or not str(function.get("name") or "").strip():
                continue
            payload = {
                "id": str(tool_call.get("id") or ""),
                "type": str(tool_call.get("type") or "function"),
                "function": {
                    "name": str(function.get("name") or ""),
                    "arguments": function.get("arguments", "{}"),
                },
            }
            parts.append(
                f"<tool_call>\n{json.dumps(payload, ensure_ascii=False, default=str)}\n</tool_call>"
            )
        return "\n".join(parts).strip()
    if role == "tool" and message.get("tool_call_id"):
        result: Any = content
        if content.lstrip().startswith(("{", "[")):
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                pass
        if isinstance(result, dict) and result.get("_multimodal") is True:
            result = _render_message_content(result)
        elif isinstance(result, (dict, list)):
            result = _redact_inline_image_payloads(result)
        payload: dict[str, Any] = {
            "tool_call_id": str(message["tool_call_id"]),
            "content": result,
        }
        if message.get("name"):
            payload["name"] = str(message["name"])
        return (
            f"<tool_response>\n{json.dumps(payload, ensure_ascii=False, default=str)}\n"
            "</tool_response>"
        )
    return content


def _tool_execution_failed(content: Any) -> bool:
    """Only explicit execution status/outcome is proof of failure, not arbitrary text."""
    if isinstance(content, dict):
        result = content
    else:
        raw = _render_message_content(content)
        try:
            result = json.loads(raw)
        except (ValueError, TypeError):
            return bool(re.search(
                r"(?i)(?:\[(?:failed|error)\]|\bexit_code\s*[:=]\s*[1-9]\d*|"
                r"\bstatus\s*[:=]\s*['\"]?(?:error|failed)\b)", raw
            ))
    if not isinstance(result, dict):
        return False
    statuses = {
        str(result.get(field) or "").strip().lower()
        for field in ("status", "outcome")
    }
    if statuses & {"error", "failed", "failure"}:
        return True
    exit_code = result.get("exit_code")
    return isinstance(exit_code, int) and not isinstance(exit_code, bool) and exit_code != 0


def _tool_result_status(content: Any) -> str:
    """Classify only explicit Hermes tool-result states; never infer from prose."""
    if isinstance(content, dict):
        result = content
    else:
        try:
            result = json.loads(_render_message_content(content))
        except (ValueError, TypeError):
            return "FAILED" if _tool_execution_failed(content) else "RESULT_RECEIVED"
    if not isinstance(result, dict):
        return "RESULT_RECEIVED"
    status = str(result.get("status") or "").strip().lower()
    outcome = str(result.get("outcome") or "").strip().lower()
    reported_status = status or outcome
    denied_statuses = {"denied", "refused", "blocked", "permission_denied"}
    cancelled_statuses = {"cancelled", "canceled", "cancel"}
    successful_statuses = {"success", "succeeded", "complete", "completed", "ok"}
    if reported_status in denied_statuses:
        return "DENIED"
    if reported_status in cancelled_statuses:
        return "CANCELLED"
    if status in successful_statuses and outcome in denied_statuses:
        return "DENIED"
    if status in successful_statuses and outcome in cancelled_statuses:
        return "CANCELLED"
    if _tool_execution_failed(result):
        return "FAILED"
    if reported_status in successful_statuses:
        return "COMPLETED"
    return "RESULT_RECEIVED"


def _latest_tool_result_failed(messages: list[dict[str, Any]]) -> bool:
    """Look only at the most recent Hermes tool result for the active request."""
    last_user = max(
        (i for i, m in enumerate(messages) if isinstance(m, dict) and m.get("role") == "user"),
        default=-1,
    )
    for message in reversed(messages[last_user + 1:]):
        if isinstance(message, dict) and message.get("role") == "tool":
            return _tool_execution_failed(message.get("content"))
    return False


def _claims_completed_live_verification(text: str) -> bool:
    return bool(re.search(
        r"(?i)(?:실사한 결과|실사 완료|조사 완료|검증 완료|실측 확인|"
        r"테스트 (?:통과|완료)|(?:tests?|pytest).{0,35}\bpassed\b|"
        r"verified (?:successfully|live)|live (?:check|verification) (?:passed|completed))",
        text,
    ))


def _has_completed_tool_history(messages: list[dict[str, Any]]) -> bool:
    return any(
        isinstance(message, dict)
        and str(message.get("role") or "").strip().lower() == "tool"
        and bool(str(message.get("tool_call_id") or "").strip())
        for message in messages
    )


def _format_labeled_messages(messages: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for message in (item for item in messages if isinstance(item, dict)):
        role = str(message.get("role") or "unknown").strip().lower()
        if rendered := _render_prompt_message(message, role):
            rows.append(f"{_ROLE_LABELS.get(role, 'Context')}:\n{rendered}")
    return "\n\n".join(rows)


_PRIMER_MAX_CHARS = 2000
_PRIMER_TRIM_MARKER = "\n…(preview truncated; the complete request is in the ACTIVE_REQUEST section below)"

# Section tags that delimit prompt bands (emitted today or scanned in
# diagnostics).  Shared so neutralization can never drift behind banding.
_BAND_TAGS = (
    "SYSTEM_INSTRUCTIONS",
    "ACTIVE_REQUEST_PRIMER",
    "HISTORICAL_CONTEXT",
    "MEMORY_CONTEXT",
    "ACTIVE_REQUEST",
    "ACTIVE_REQUEST_PROGRESS",
    "UNRESOLVED_DENIED_REQUEST_CONTEXT",
    "ACTIVE_REQUEST_ANCHOR",
    "UNRESOLVED_USER_OBJECTIVE",
    "LATEST_USER_FOLLOW_UP",
)


def _neutralize_section_tags(text: str) -> str:
    """Keep literal section names inside a copied primer from breaking section parsing.

    Only the primer copy is rewritten; the canonical ACTIVE_REQUEST keeps the
    user's text byte-for-byte.
    """
    for tag in _BAND_TAGS:
        text = text.replace(f"<{tag}>", f"⟨{tag}⟩").replace(f"</{tag}>", f"⟨/{tag}⟩")
    return text


def _active_request_primer(active_text: str) -> str:
    body = _neutralize_section_tags(active_text.strip())
    if not body:
        return ""
    if len(body) > _PRIMER_MAX_CHARS:
        body = body[: _PRIMER_MAX_CHARS - len(_PRIMER_TRIM_MARKER)] + _PRIMER_TRIM_MARKER
    return body


# Back-compat alias; the tuple now lives above with the primer helpers.
_REPLAY_BAND_TAGS = _BAND_TAGS


def _prompt_section_diagnostics(prompt_text: str) -> tuple[list[str], list[str]]:
    sections: list[tuple[int, str, str]] = []
    for tag in _REPLAY_BAND_TAGS:
        open_tag, close_tag = f"<{tag}>", f"</{tag}>"
        start = prompt_text.find(open_tag)
        if start == -1:
            continue
        end = prompt_text.find(close_tag, start)
        size = (
            len(prompt_text[start : end + len(close_tag)].encode("utf-8"))
            if end != -1
            else "?"
        )
        sections.append((start, tag, str(size)))
    sections.sort(key=lambda item: item[0])
    return (
        [f"{tag}={size}" for _, tag, size in sections],
        [tag for _, tag, _ in sections],
    )


def _log_full_replay_diagnostics(
    *,
    reason: str,
    prompt_text: str,
    model: str | None,
    affinity_key: str,
    intent_owner: str = "latest_user_request",
    tool_outcome: str = "unobserved",
) -> None:
    """One structured, privacy-safe line per full replay (historical reference).

    Only UTF-8 byte sizes, band ordering, turn counts, and the opaque
    conversation handle are logged; never prompt content, message text, or
    credentials.  Byte sizes (not character counts) are mandatory: Korean-heavy
    incident prompts triple under UTF-8, and char-based numbers would mislead
    capacity triage.  Band sizes remain best-effort heuristics (a user literal
    that duplicates a section tag can skew them), so this line is for
    diagnosis only and must never drive behavior.
    """
    bands, section_order = _prompt_section_diagnostics(prompt_text)
    history_start = prompt_text.find("<HISTORICAL_CONTEXT>")
    history_end = prompt_text.find("</HISTORICAL_CONTEXT>")
    history_turns = (
        prompt_text.count("User:\n", history_start, history_end)
        if history_start != -1 and history_end != -1
        else 0
    )
    logger.info(
        "ACP full replay: reason=%s model=%s requested_model=%s effective_model=unknown "
        "intent_owner=%s tool_outcome=%s conversation=%s prompt_bytes=%d "
        "history_user_turns=%d section_order=%s bands[%s]",
        reason,
        str(model or "?"),
        str(model or "?"),
        intent_owner,
        tool_outcome,
        (affinity_key or "")[:16] or "none",
        len(prompt_text.encode("utf-8")),
        history_turns,
        ",".join(section_order),
        ",".join(bands),
    )


def _log_continuation_diagnostics(
    *,
    reason: str,
    prompt_text: str,
    model: str | None,
    affinity_key: str,
    intent_owner: str,
    tool_outcome: str,
) -> None:
    bands, section_order = _prompt_section_diagnostics(prompt_text)
    logger.info(
        "ACP continuation: reason=%s model=%s requested_model=%s effective_model=unknown "
        "intent_owner=%s tool_outcome=%s conversation=%s prompt_bytes=%d "
        "section_order=%s bands[%s]",
        reason,
        str(model or "?"),
        str(model or "?"),
        intent_owner,
        tool_outcome,
        (affinity_key or "")[:16] or "none",
        len(prompt_text.encode("utf-8")),
        ",".join(section_order),
        ",".join(bands),
    )


def _format_messages_as_prompt(
    messages: list[dict[str, Any]],
    model: str | None = None,
    tools: list[dict[str, Any]] | None = None,
    tool_choice: Any = None,
    *,
    unresolved_denied_request: str = "",
) -> str:
    """Build a full ACP bootstrap without making old user turns look active.

    ACP v1 accepts one prompt string rather than Hermes' role-structured message
    array.  A naive ``User:/Assistant:/Tool:`` transcript therefore turns every
    old user request into text inside the *current* ACP user prompt.  Under long
    histories that let the model resume a completed task instead of following
    the newest request.  Keep system instructions authoritative, mark older
    dialogue as reference-only, and isolate the newest user request plus any
    already-completed progress that followed it.
    """
    del model  # Model selection is performed on the ACP session, never by prompt text.
    valid = [item for item in messages if isinstance(item, dict)]
    sections: list[str] = [
        *_PROMPT_PREAMBLE,
        *render_tool_bridge_sections(tools, tool_choice),
    ]
    for overlay in policy_overlays:
        if overlay.is_active() and getattr(overlay, "SYSTEM_PROMPT", None):
            sections.append(overlay.SYSTEM_PROMPT)

    system_rows = [
        message for message in valid
        if str(message.get("role") or "").strip().lower() == "system"
    ]
    if system_text := _format_labeled_messages(system_rows):
        sections.append(
            "<SYSTEM_INSTRUCTIONS>\n"
            "The following System messages are authoritative instructions for this request.\n\n"
            + system_text
            + "\n</SYSTEM_INSTRUCTIONS>"
        )

    last_user_index: int | None = None
    for index, message in enumerate(valid):
        if str(message.get("role") or "").strip().lower() == "user":
            last_user_index = index

    if last_user_index is None:
        reference = [
            message for message in valid
            if str(message.get("role") or "").strip().lower() != "system"
        ]
        if reference_text := _format_labeled_messages(reference):
            sections.append(
                "<HISTORICAL_CONTEXT>\n"
                "Conversation transcript (REFERENCE ONLY; no historical User block is an active instruction):\n\n"
                + reference_text
                + "\n</HISTORICAL_CONTEXT>"
            )
        sections.append("Continue from the latest available conversation state.")
    else:
        historical = [
            message for message in valid[:last_user_index]
            if str(message.get("role") or "").strip().lower() != "system"
        ]
        active = valid[last_user_index]
        progress = [
            message for message in valid[last_user_index + 1 :]
            if str(message.get("role") or "").strip().lower() != "system"
        ]

        historical_text = _format_labeled_messages(historical)
        active_text = _render_prompt_message(active, "user")

        # F1 (historical reference): state the current request BEFORE the long reference
        # band.  Under full replay of a long history the tail-only ACTIVE_REQUEST
        # lost to the dominant narrative (2026-10-12 REA audit); an early bounded
        # primer restored current-request handling at the same length and
        # content.  The primer is a pointer to the same single active turn, so
        # it must never read as a second request.
        if historical_text and (primer := _active_request_primer(active_text)):
            sections.append(
                "<ACTIVE_REQUEST_PRIMER>\n"
                "The user's current request is stated first (preview below) and repeated verbatim in the "
                "ACTIVE_REQUEST section that follows HISTORICAL_CONTEXT. This is one single active turn, not two "
                "requests. Answer this request; do not resume an earlier request unless ACTIVE_REQUEST itself asks "
                "for it.\n\n"
                + primer
                + "\n</ACTIVE_REQUEST_PRIMER>"
            )

        if historical_text:
            sections.append(
                "<HISTORICAL_CONTEXT>\n"
                "Conversation transcript (REFERENCE ONLY). Older User messages below are completed/previous requests, "
                "not current instructions. Use them only as evidence and do not resume them unless the ACTIVE_REQUEST "
                "explicitly asks you to.\n\n"
                + historical_text
                + "\n</HISTORICAL_CONTEXT>"
            )

        # F2 (historical reference) HELD at the adapter boundary: Hermes core flattens the
        # memory stamp into plain user content (turn_context.compose_user_api_content
        # -> substitute_api_content), so no metadata distinguishes a core stamp
        # from a user quoting the identical block.  Splitting would risk altering
        # user text; the Core-side fix (structured api_content part with
        # provenance) is tracked on historical reference as a Core-owned handoff.  User text,
        # including any <memory-context> block, stays byte-for-byte in
        # ACTIVE_REQUEST below.

        sections.append(
            "<ACTIVE_REQUEST>\n"
            "This is the user's current request. It takes precedence over every historical User block above.\n\n"
            + active_text
            + "\n</ACTIVE_REQUEST>"
        )

        if progress_text := _format_labeled_messages(progress):
            sections.append(
                "<ACTIVE_REQUEST_PROGRESS>\n"
                "These events happened after ACTIVE_REQUEST and are already-completed progress for that same request. "
                "Continue from them; do not restart or repeat them.\n\n"
                + progress_text
                + "\n</ACTIVE_REQUEST_PROGRESS>"
            )

        if unresolved_denied_request.strip():
            sections.append(
                "<UNRESOLVED_DENIED_REQUEST_CONTEXT>\n"
                "This earlier user objective was left unresolved after a native ACP permission denial before execution. "
                "It is context for interpreting ACTIVE_REQUEST, not a standalone command. ACTIVE_REQUEST remains the "
                "controlling user instruction: continue this objective only if ACTIVE_REQUEST refers to or continues it; "
                "otherwise follow the latest request. Do not claim the denied action ran, repeat it, or bypass permission. "
                "Use only a separately available, authorized Hermes-owned tool; otherwise explain the blocker and give a "
                "task-aware safe next step.\n\n"
                + _neutralize_section_tags(unresolved_denied_request.strip())
                + "\n</UNRESOLVED_DENIED_REQUEST_CONTEXT>"
            )

        sections.append(
            "Respond to ACTIVE_REQUEST using the latest state and ACTIVE_REQUEST_PROGRESS. "
            "Do not switch back to, continue, or re-execute an older request merely because it appears in HISTORICAL_CONTEXT."
        )

    if _has_completed_tool_history(valid):
        sections.append(_TOOL_HISTORY_CONTINUATION_NOTE)
    return "\n\n".join(section.strip() for section in sections if section and section.strip())


def _normalized_tool_arguments(arguments: Any) -> str:
    if isinstance(arguments, str):
        text = arguments.strip() or "{}"
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return text
        return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return json.dumps(
        arguments if arguments is not None else {},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _tool_result_reports_unchanged(content: Any) -> bool:
    text = _render_message_content(content)
    if not text:
        return False
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict) and parsed.get("unchanged") is True:
        return True
    return '"unchanged":true' in "".join(text.lower().split())


def _latest_unchanged_tool_signature(
    messages: list[dict[str, Any]],
) -> tuple[str, str] | None:
    for index in range(len(messages) - 1, -1, -1):
        message = messages[index]
        if (
            not isinstance(message, dict)
            or str(message.get("role") or "").strip().lower() != "tool"
        ):
            continue
        call_id = str(message.get("tool_call_id") or "").strip()
        if not call_id or not _tool_result_reports_unchanged(message.get("content")):
            return None
        for prior in range(index - 1, -1, -1):
            assistant = messages[prior]
            if (
                not isinstance(assistant, dict)
                or str(assistant.get("role") or "").strip().lower() != "assistant"
            ):
                continue
            for tool_call in assistant.get("tool_calls") or []:
                if (
                    not isinstance(tool_call, dict)
                    or str(tool_call.get("id") or "").strip() != call_id
                ):
                    continue
                function = tool_call.get("function")
                if not isinstance(function, dict):
                    return None
                name = str(function.get("name") or "").strip()
                if not name:
                    return None
                return name, _normalized_tool_arguments(function.get("arguments", "{}"))
        return None
    return None


def _repeats_latest_unchanged_call(
    messages: list[dict[str, Any]], tool_calls: list[Any]
) -> bool:
    if len(tool_calls) != 1:
        return False
    previous = _latest_unchanged_tool_signature(messages)
    if previous is None:
        return False
    call = tool_calls[0]
    function = getattr(call, "function", None)
    name = str(getattr(function, "name", "") or "").strip()
    arguments = getattr(function, "arguments", "{}")
    return (name, _normalized_tool_arguments(arguments)) == previous


def _without_openai_tool(
    tools: list[dict[str, Any]] | None, blocked_name: str
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for tool in tools or []:
        function = tool.get("function") if isinstance(tool, dict) else None
        name = str(function.get("name") or "").strip() if isinstance(function, dict) else ""
        if name != blocked_name:
            filtered.append(tool)
    return filtered


def _extract_advertised_tool_calls(
    text: str, tools: list[dict[str, Any]] | None
) -> tuple[list[Any], str]:
    """Reject model-emitted calls that Hermes did not advertise to this request."""
    tool_calls, cleaned_text = extract_tool_calls_from_text(text)
    allowed = set(advertised_tool_names(tools))
    for call in tool_calls:
        function = getattr(call, "function", None)
        name = str(getattr(function, "name", "") or "").strip()
        if name in allowed:
            continue
        safe_name = (
            name
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", name)
            else "unknown"
        )
        raise MalformedToolCallError(
            f"Antigravity ACP emitted unadvertised Hermes tool call {safe_name!r}; "
            "refusing to pass it to Hermes.",
            tool_name=safe_name,
            unrecoverable=True,
            reason="unadvertised_tool",
        )
    return tool_calls, cleaned_text


def _tool_bridge_activity(
    tools: list[dict[str, Any]] | None,
    messages: list[dict[str, Any]],
    current_tool_calls: list[Any],
) -> dict[str, Any]:
    """Build privacy-safe provenance from advertised tools, calls, and returned results."""
    advertised = advertised_tool_names(tools)
    allowed = set(advertised)
    events_by_id: dict[str, dict[str, str]] = {}
    call_names_by_id: dict[str, list[tuple[str, int]]] = {}
    tool_results: list[tuple[int, dict[str, object]]] = []
    last_user = max(
        (
            index
            for index, message in enumerate(messages)
            if isinstance(message, dict)
            and str(message.get("role") or "").strip().lower() == "user"
        ),
        default=-1,
    )
    active_messages = messages[last_user + 1 :]

    def add_event(call_id: str, name: str) -> None:
        call_id = str(call_id or "").strip()
        name = str(name or "").strip()
        if not call_id or name not in allowed or call_id in events_by_id:
            return
        safe_name = (
            name
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", name)
            else "unknown"
        )
        call_hash = "sha256:" + hashlib.sha256(
            f"antigravity-acp-tool-bridge\0{call_id}".encode(
                "utf-8", errors="surrogatepass"
            )
        ).hexdigest()
        events_by_id[call_id] = {
            "tool_call_id_hash": call_hash,
            "tool_name": safe_name,
            "origin": "hermes_tool_bridge",
            "status": "PENDING",
        }

    def record_call(call_id: str, name: str, message_index: int) -> None:
        normalized_id = str(call_id or "").strip()
        if normalized_id:
            call_names_by_id.setdefault(normalized_id, []).append((name, message_index))

    for message_index, message in enumerate(active_messages):
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role == "assistant":
            for call in message.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                function = call.get("function")
                name = (
                    str(function.get("name") or "").strip()
                    if isinstance(function, dict)
                    else ""
                )
                record_call(
                    str(call.get("id") or "").strip(), name, message_index
                )
        elif role == "tool":
            tool_results.append((message_index, message))

    for call in current_tool_calls:
        function = getattr(call, "function", None)
        record_call(
            str(getattr(call, "id", "") or "").strip(),
            str(getattr(function, "name", "") or "").strip(),
            len(active_messages),
        )

    for call_id, call_entries in call_names_by_id.items():
        name = next(
            (name for name, _ in call_entries if name in allowed), ""
        )
        if name:
            add_event(call_id, name)

    for message_index, message in tool_results:
        call_id = str(message.get("tool_call_id") or "").strip()
        call_entries = call_names_by_id.get(call_id, [])
        event = events_by_id.get(call_id)
        if (
            not call_id
            or len(call_entries) != 1
            or call_entries[0][1] >= message_index
            or call_entries[0][0] not in allowed
            or event is None
            or event["status"] != "PENDING"
        ):
            continue
        call_name = call_entries[0][0]
        result_name = str(message.get("name") or "").strip()
        if result_name and result_name != call_name:
            continue
        event["status"] = _tool_result_status(message.get("content"))

    events = list(events_by_id.values())[-128:]
    web_events = [event for event in events if event.get("tool_name") == "web_search"]
    if web_events:
        web_status = web_events[-1]["status"]
    elif "web_search" in allowed:
        web_status = "NOT_ATTEMPTED"
    else:
        web_status = "NOT_AVAILABLE"
    safe_advertised = [
        name
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", name)
        else "unknown"
        for name in advertised[:128]
    ]
    return {
        "schema_id": "antigravity-acp-tool-bridge-v1",
        "advertised_tools": safe_advertised,
        "calls": events,
        "web_research_status": web_status,
    }


def _runtime_conversation_identity() -> str | None:
    """Stable Hermes conversation identity when running inside Hermes.

    ``HERMES_SESSION_KEY`` is the stable gateway conversation identity across
    cached/fresh AIAgent turns. ``HERMES_SESSION_ID`` is a fallback for surfaces
    that do not provide a gateway key. The write-origin ContextVar separates
    detached forks (background review, /btw side questions) that intentionally
    share the parent's physical conversation but must never share its native ACP
    continuation state. Both imports are optional so the standalone plugin and
    tests remain usable outside Hermes.

    A delegate_task child is the one case where the session key is NOT the
    conversation identity: core deliberately propagates the parent's key into the
    child because it is the async-completion routing address
    (``tools/delegate_tool_dispatch.py::_resolve_async_session_key``), while the
    child's own durable session id is bound task-locally around its run
    (``agent/delegation_context.py::delegated_child_context``).  Keying a child
    with the parent's routing key makes every sibling and the parent fight over
    one native ACP continuation (issue #2), so a child keys with its own session
    id.  A child whose own id is absent is AMBIGUOUS: no key can distinguish it
    from its parent or siblings, so it returns ``None`` — the caller must run it
    stateless (empty affinity, fresh native session, resume nothing) rather than
    degrade to the prompt-prefix path, which two same-prompt siblings would
    share.

    Return contract: non-empty string = identity; ``""`` = no Hermes runtime
    identity (standalone fallback path applies); ``None`` = ambiguous delegated
    child (stateless, never resume).
    """
    session_id, session_key = get_runtime_session_env()
    if is_delegated_child_context():
        if not session_id:
            return None
        identity = session_id
    else:
        identity = session_key or session_id
    if not identity:
        return ""
    lane = get_current_write_origin()
    return f"{identity}\0{lane}"


def _conversation_affinity(messages: list[dict[str, Any]], cwd: str) -> str:
    """Stable opaque mux/continuation key for one logical Hermes conversation.

    Prefer Hermes' stable gateway session key over prompt bytes and the more
    transiently-bound durable session id: cached and freshly rebuilt AIAgents must
    resolve to the same native ACP continuation. Outside Hermes, fall back to cwd +
    the immutable opening user prefix so the standalone client still has deterministic
    affinity. An ambiguous delegated child (no own session id) gets the EMPTY
    affinity: the request runs stateless against a fresh native session and resumes
    nothing, because no derivable key can tell it apart from its parent or siblings.
    """
    runtime_identity = _runtime_conversation_identity()
    if runtime_identity is None:
        return ""
    if runtime_identity:
        material = f"hermes-session\0{runtime_identity}"
        return "sha256:" + hashlib.sha256(
            material.encode("utf-8", errors="surrogatepass")
        ).hexdigest()

    opening: list[str] = []
    saw_user = False
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role in {"assistant", "tool"}:
            break
        if role not in {"system", "context", "user"}:
            continue
        opening.append(f"{role}\0{_fp_render_message_content(message.get('content'))}")
        if role == "user":
            saw_user = True
            break
    if not saw_user:
        return ""
    material = f"{Path(cwd).resolve()}\0" + "\0".join(opening)
    return "sha256:" + hashlib.sha256(
        material.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def _effective_timeout(timeout: Any) -> float:
    if isinstance(timeout, (int, float)):
        return float(timeout)
    candidates = [
        getattr(timeout, attr, None)
        for attr in ("read", "write", "connect", "pool", "timeout")
    ]
    return max(
        (float(value) for value in candidates if isinstance(value, (int, float))),
        default=_DEFAULT_TIMEOUT_SECONDS,
    )


def _hermes_scratch_read_roots() -> tuple[Path, ...]:
    """Return narrow read-only roots used for Hermes-generated evidence."""
    candidates: list[Path] = []
    for env_name in ("HERMES_HOME", "HERMES_REAL_HOME"):
        raw = os.environ.get(env_name, "").strip()
        if raw:
            candidates.append(Path(raw).expanduser().resolve() / "cache" / "scratch")
    candidates.append(Path.home().resolve() / ".hermes" / "cache" / "scratch")

    roots: list[Path] = []
    for root in candidates:
        if root not in roots:
            roots.append(root)
    return tuple(roots)


_ABSOLUTE_PATH_RE = re.compile(r"(?<![\w])(/[^\s`'\"<>]+)")
_ARTIFACT_POSITIVE_RE = re.compile(
    r"(?:artifact|evidence|script|file|output|result|created|generated|saved|written|wrote|"
    r"산출물|증거|스크립트|파일|생성|저장|작성)",
    re.IGNORECASE,
)
_ARTIFACT_NEGATIVE_RE = re.compile(
    r"(?:not\s+found|missing|does\s+not\s+exist|nonexistent|없(?:음|다|습니다)?|"
    r"존재하지|미생성|생성하지\s+못)",
    re.IGNORECASE,
)


def _claimed_scratch_artifact_paths(text: str) -> tuple[Path, ...]:
    """Extract positively claimed Hermes scratch paths from a final answer.

    This intentionally ignores negative statements such as "file does not
    exist" so diagnostic answers are not forced into a correction loop.
    """
    if not text:
        return ()
    roots = _hermes_scratch_read_roots()
    found: list[Path] = []
    for match in _ABSOLUTE_PATH_RE.finditer(text):
        # Trailing shell-prompt sigils ("…/scratch/demorec$") and annotation
        # marks are not path characters; keeping them makes every quoted
        # prompt look like a missing artifact.
        raw = match.group(1).rstrip(".,;:!?)]}~$#%*&")
        if not raw:
            continue
        start = max(0, match.start() - 140)
        end = min(len(text), match.end() + 140)
        # Judge the prose around the path, not path components themselves
        # (a directory named e.g. "missing-fixture" is not a negative claim).
        context = text[start:match.start()] + text[match.end():end]
        if _ARTIFACT_NEGATIVE_RE.search(context):
            continue
        if not _ARTIFACT_POSITIVE_RE.search(context):
            continue
        try:
            resolved = Path(raw).resolve()
        except OSError:
            continue
        if any(
            _path_is_within(resolved, root)
            for root in roots
        ) and resolved not in found:
            found.append(resolved)
    return tuple(found)


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _missing_claimed_scratch_artifacts(text: str) -> tuple[Path, ...]:
    return tuple(path for path in _claimed_scratch_artifact_paths(text) if not path.exists())


# The official ACP server roots tokens and config under ``<GEMINI_HOME>``
# (= ~/.gemini by default).  These paths must never be auto-approved or read
# through the ACP file bridge, even when the session cwd covers the home.
_VENDOR_CREDENTIAL_ROOT_RE = re.compile(
    r"(?:^|/)\.gemini/(?:antigravity(?:-acp|-cli)?|config)(?:/|$)"
)


def _safe_path(path_text: str, cwd: str, *, verb: str) -> Path:
    """Delegate file policy to vanilla Hermes and keep ACP writes fail-closed.

    Reads may additionally target Hermes' generated scratch evidence. This is
    intentionally read-only and still passes through Hermes' read-block and
    redaction policy in _fs_read_text_file.
    """
    try:
        nt_error = get_nt_namespace_error(path_text, verb=verb)
    except Exception as exc:
        raise PermissionError("Hermes file-safety policy is unavailable; ACP file access denied.") from exc
    if nt_error:
        raise PermissionError(nt_error)
    if not Path(path_text).is_absolute():
        raise PermissionError("ACP file-system paths must be absolute.")

    resolved, root = Path(path_text).resolve(), Path(cwd).resolve()
    if _VENDOR_CREDENTIAL_ROOT_RE.search(resolved.as_posix()):
        raise PermissionError(
            f"ACP file-system {verb.lower()} denied: Antigravity credential/config path."
        )
    allowed_roots = (root,)
    if verb.strip().lower() == "read":
        allowed_roots += _hermes_scratch_read_roots()

    for allowed_root in allowed_roots:
        try:
            resolved.relative_to(allowed_root)
            return resolved
        except ValueError:
            continue

    raise PermissionError(
        f"Path '{resolved}' is outside the permitted ACP {verb.lower()} roots."
    )


def _fs_read_text_file(params: dict[str, Any], cwd: str) -> Any:
    try:
        get_read_block_error, redact_sensitive_text = get_file_read_safety()
    except Exception as exc:
        raise PermissionError("Hermes file-read safety policy is unavailable.") from exc
    path = _safe_path(str(params.get("path") or ""), cwd, verb="Read")
    try:
        block_error = get_read_block_error(str(path))
    except Exception as exc:
        raise PermissionError(
            "Hermes read-block policy failed; ACP file read denied."
        ) from exc
    if block_error:
        raise PermissionError(block_error)
    try:
        content = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"ACP file does not exist: {path}") from exc
    line, limit = params.get("line"), params.get("limit")
    if isinstance(line, int) and line > 1:
        end = line - 1 + limit if isinstance(limit, int) and limit > 0 else None
        content = "".join(content.splitlines(keepends=True)[line - 1 : end])
    if content:
        try:
            content = redact_sensitive_text(content, force=True)
        except Exception as exc:
            # A redaction failure must never return the unredacted contents.
            raise PermissionError(
                "Hermes redaction policy failed; ACP file read denied before content is returned."
            ) from exc
    return {"content": content}


def _fs_write_text_file(params: dict[str, Any], cwd: str) -> Any:
    try:
        get_write_denied_error, is_write_approval_required = get_file_write_safety()
    except Exception as exc:
        raise PermissionError("Hermes file-write safety policy is unavailable.") from exc
    path = _safe_path(str(params.get("path") or ""), cwd, verb="Write")
    try:
        denied = get_write_denied_error(str(path))
        needs_approval = is_write_approval_required(str(path))
    except Exception as exc:
        raise PermissionError(
            "Hermes file-write safety policy failed; ACP file write denied."
        ) from exc
    if denied:
        raise PermissionError(denied)
    if needs_approval:
        raise PermissionError(
            f"Write denied: '{path}' requires interactive approval and cannot be written through the ACP file bridge."
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(params.get("content") or ""), encoding="utf-8")
    return None


_FS_HANDLERS = {
    "fs/read_text_file": _fs_read_text_file,
    "fs/write_text_file": _fs_write_text_file,
}


_PERMISSION_READ_HINT_RE = re.compile(r"(?:^|[_\s-])(read|view)(?:[_\s-]|$)", re.IGNORECASE)
_PERMISSION_MUTATION_HINT_RE = re.compile(
    r"(?:^|[_\s-])(write|edit|delete|remove|execute|exec|run|shell|command)(?:[_\s-]|$)",
    re.IGNORECASE,
)

# Only 1.2.1-verified native read/callback tools can be auto-approved.  The
# ``disabledTools`` filter never reaches MCP-provided tools (verified defect
# D2), so any tool name outside this set - MCP or otherwise unknown - must go
# through normal approval instead of auto-allow.
_KNOWN_NATIVE_READ_TOOLS = frozenset(
    {
        "view_file",
        "safe_view_file",
        "client_view_file",
        "list_directory",
        "search_directory",
        "find_file",
    }
)


def _is_known_native_read_tool(name: str) -> bool:
    """True only for the exact 1.2.1 native read tool name.

    This is a policy-level origin gate, not a protocol proof: an external
    MCP server could register the same simple name.  It is safe under the
    lane's standing assumptions (mux S1 blocks global MCP configs, the
    client always sends ``mcpServers: []``); if either assumption weakens,
    this gate must be re-reviewed.
    """
    return name.strip().lower() in _KNOWN_NATIVE_READ_TOOLS


def _permission_tool_call(params: dict[str, Any]) -> dict[str, Any]:
    tool_call = params.get("toolCall")
    if isinstance(tool_call, dict):
        return tool_call
    subject = params.get("subject")
    if isinstance(subject, dict) and str(subject.get("type") or "").strip() == "tool_call":
        tool_call = subject.get("toolCall")
        if isinstance(tool_call, dict):
            return tool_call
    return {}


def _permission_paths(tool_call: dict[str, Any]) -> tuple[str, ...]:
    """Inspect every supplied path alias, not just the first matching field."""
    raw_input = tool_call.get("rawInput")
    if not isinstance(raw_input, dict):
        return ()
    paths: list[str] = []
    for key in ("absolute_path", "path", "filePath", "file_path", "filename", "file", "directory_path"):
        value = raw_input.get(key)
        if isinstance(value, str) and value.strip() and value.strip() not in paths:
            paths.append(value.strip())
    return tuple(paths)


def _is_under_hermes_scratch(path: Path) -> bool:
    resolved = path.resolve()
    for root in _hermes_scratch_read_roots():
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _safe_read_permission_option(params: dict[str, Any], cwd: str) -> str | None:
    """Select one offered allow-once option for a narrow scratch-file read."""
    tool_call = _permission_tool_call(params)
    if not tool_call:
        return None

    descriptor = " ".join(
        str(tool_call.get(key) or "") for key in ("name", "title", "kind")
    ).strip()
    if _PERMISSION_MUTATION_HINT_RE.search(descriptor):
        return None
    # Fail-closed origin policy (assumption-scoped, see
    # _is_known_native_read_tool): the exact protocol ``name`` must be a
    # 1.2.1 native read tool. Titles are model/MCP-controlled and a frame
    # like name='mcp__example__read_email', title='Running view_file' must
    # never approve. Nameless partial frames cannot prove native origin,
    # so they are cancelled too (selection stays on explicit user input).
    tool_name = str(tool_call.get("name") or "").strip()
    if not _is_known_native_read_tool(tool_name):
        return None

    # Some native tools provide several path aliases. Validate all of them:
    # an in-scope first alias must never mask a later out-of-scope path.
    # Pathless partial tool updates retain allow-once for availability.
    for path_text in _permission_paths(tool_call):
        try:
            _safe_path(path_text, cwd, verb="Read")
        except PermissionError:
            return None

    # Some ACP agents send only a partial ToolCallUpdate in the permission
    # request and disclose the concrete path in the subsequent fs/read_text_file
    # request. That read is independently constrained by _safe_path plus Hermes'
    # read-block/redaction policy, so a missing permission-time path is safe to
    # approve once for an explicitly read/view-only operation.
    for option in params.get("options") or []:
        if not isinstance(option, dict):
            continue
        if str(option.get("kind") or "").strip() != "allow_once":
            continue
        option_id = str(option.get("optionId") or "").strip()
        if option_id:
            return option_id
    return None


_DOCUMENTED_PERMISSION_OPTION_KINDS = frozenset(
    {"allow_once", "allow_always", "reject_once", "reject_always"}
)
_NATIVE_PERMISSION_TOOL_NAMES = _KNOWN_NATIVE_READ_TOOLS | {"run_command"}

# --- Native coding-agent permission policy (FAIL CLOSED) ------------------
# Every ``session/request_permission`` frame the official server emits for a
# NATIVE tool (run_command, file create/edit/delete executed server-side) is
# answered with the server's own reject option.  The plugin never auto-allows
# a native mutation or command, in any run mode, and no configuration or
# environment variable can enable one: shell and file-mutation work belongs to
# Hermes' own approval-gated terminal and file tools, which the model reaches
# through the Hermes <tool_call> bridge (see _PROMPT_PREAMBLE).  The only
# permission auto-allow that remains is the read-only Hermes scratch-area
# route in _safe_read_permission_option, and harness fs/read/fs/write
# callbacks keep enforcing the full Hermes write-safety chain.  The former
# "trusted coding" auto-approval (HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE /
# HERMES_ANTIGRAVITY_ACP_WORKSPACE) was removed after the Hermes catalog
# review; both environment variables are now inert.


def _opaque_permission_id(value: Any, domain: str) -> str | None:
    normalized = str(value or "").strip()
    if not normalized:
        return None
    material = f"antigravity-acp-permission\0{domain}\0{normalized}"
    return "sha256:" + hashlib.sha256(material.encode("utf-8", errors="surrogatepass")).hexdigest()


_USAGE_BUCKETS = (
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
)
_CONTEXT_OCCUPANCY_SOURCE = "acp.session/update:usage_update"
_USAGE_DELTA_SCOPE = "per_model_call_consumption_delta"
_USAGE_SCOPE_UNVERIFIED = "unverified_server_semantics"

# Server identities whose ``usage_update.used`` semantics are SOURCE-VERIFIED
# as per-model-call consumption deltas (NOT the ACP v1 occupancy snapshot):
#   * ``agy_acp_server.par`` 1.4.0 ``server.py`` (``_maybe_send_usage_update``,
#     ``_extract_tokens_used``) — verified 2026-11-02 (antigravity-acp-harness
#     issue #68 evidence); its ``initialize`` self-reports
#     ``agentInfo.version == "1.4.0"`` (stage-3 canary frames).
#   * ``agy_acp_server.par`` 1.4.4 ``server.py`` — re-verified 2026-11-11 from
#     the installed par; its credential-free ``initialize`` self-reports
#     ``agentInfo.version == "1.4.4"``, enforced by ``EXPECTED_AGENT_INFO`` in
#     ``scripts/hosted_clean_room_ci.py`` and recorded in
#     ``docs/official-server-1.4.4-clean-room-e2e-2026-11-07.md``.
# These pins are OBSERVED IDENTITY triples, not trustworthy version
# comparisons: any deviation (absent, unknown, changed, malformed
# ``agentInfo``) disables consumption accumulation instead of guessing
# (issue #6 AC4-3).  Residual risk: a future server that keeps one of these
# exact triples while changing the semantics would pass the gate.
_VERIFIED_CONSUMPTION_IDENTITIES = frozenset(
    {
        # 1.4.0: observed identity in the stage-3 canary frames.
        ("antigravity-acp", "Google Antigravity", "1.4.0"),
        # 1.4.4: identity verified credential-free against the official
        # binary by the hosted clean room (`EXPECTED_AGENT_INFO` in
        # scripts/hosted_clean_room_ci.py; per-call delta semantics source-
        # verified in the 1.4.4 PAR). The server reports its own binary
        # version here, so every verified release must be pinned explicitly.
        ("antigravity-acp", "Google Antigravity", "1.4.4"),
    }
)
_USAGE_SEMANTICS_VERIFIED = "verified"
_USAGE_SEMANTICS_UNVERIFIED = "unverified"
_USAGE_SEMANTICS_ATTR = "_antigravity_usage_semantics"
_SERVER_CONSUMPTION_SEMANTICS_KEY = "server_consumption_semantics"
_PROMPT_TURN_ACTIVE_KEY = "prompt_turn_active"


def _usage_semantics_from_initialize(result: Any) -> str:
    """Pin the observed server identity from the ``initialize`` result.

    Returns ``verified`` only when ``agentInfo`` is a well-formed object whose
    exact ``(name, title, version)`` triple matches a source-verified
    per-call-delta server.  Anything else — absent, non-string, unknown, or
    changed identity — is ``unverified``; the adapter never guesses semantics.
    """
    if not isinstance(result, dict):
        return _USAGE_SEMANTICS_UNVERIFIED
    agent_info = result.get("agentInfo")
    if not isinstance(agent_info, dict):
        return _USAGE_SEMANTICS_UNVERIFIED
    fields = tuple(agent_info.get(field) for field in ("name", "title", "version"))
    if not all(isinstance(field, str) and field for field in fields):
        return _USAGE_SEMANTICS_UNVERIFIED
    return (
        _USAGE_SEMANTICS_VERIFIED
        if fields in _VERIFIED_CONSUMPTION_IDENTITIES
        else _USAGE_SEMANTICS_UNVERIFIED
    )


def _nonnegative_json_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value >= 0
    return isinstance(value, float) and math.isfinite(value) and value >= 0


def _capture_usage_delta(
    update: Any, activity_stats: dict[str, Any] | None
) -> None:
    """Persist each valid per-model-call ``used`` delta for an explicit session.

    The official server omits zero-delta frames and can omit calls during
    re-anchoring or when its context window is unknown. Subagent usage is also
    excluded. We record only observations actually delivered by ACP.
    Every decision on a usage-delta candidate is counted in the store
    (``usage_drop_counters``) so a silent drop becomes observable (historical reference).
    """
    if (
        not isinstance(update, dict)
        or str(update.get("sessionUpdate") or "").strip() != "usage_update"
        or "used" not in update
    ):
        return  # not a usage-delta candidate; every frame passes through here
    # Invariant: frames_seen counts every candidate; exactly one reason counter
    # marks where a rejected candidate died, so seen minus reasons equals the
    # deltas that reached add_usage_delta.
    conversation_registry.note_usage_frame("frames_seen")
    # Whole-frame validity, identical to _capture_context_occupancy and
    # _capture_turn_usage: a frame carrying any present-but-invalid
    # used/size value contributes nothing to ANY consumer, so the durable
    # sum, the turn sum and the occupancy reading can never disagree about
    # which frames were real (issue #6 review).
    if not isinstance(activity_stats, dict):
        conversation_registry.note_usage_frame("dropped_invalid")
        return
    present = [field for field in ("used", "size") if field in update]
    if "used" not in present or not all(
        _nonnegative_json_number(update[field]) for field in present
    ):
        conversation_registry.note_usage_frame("dropped_invalid")
        return
    # The server never reports a zero delta from `_maybe_send_usage_update`
    # (`if not used: return`); a zero frame can only be the new-session
    # placeholder. It is not consumption under ANY identity or lifecycle
    # position, so it is classified by value first and must not create
    # totals entries.
    if update["used"] == 0:
        conversation_registry.note_usage_frame("dropped_zero")
        return
    # Issue #6 AC4-3: accumulate only for a server identity whose per-call
    # delta semantics are source-verified (see _VERIFIED_CONSUMPTION_IDENTITIES).
    if activity_stats.get(_SERVER_CONSUMPTION_SEMANTICS_KEY) != _USAGE_SEMANTICS_VERIFIED:
        conversation_registry.note_usage_frame("dropped_semantics_unverified")
        return
    # Issue #6 AC4-2: the official 1.4.x server emits consumption deltas ONLY
    # while a prompt turn is in flight (`_maybe_send_usage_update` is reached
    # exclusively from `prompt()`/`_stream_live_step`).  Frames outside the
    # window are re-reports of `last_reported_used` (model switch) — never new
    # consumption.  This is event-order correlation against the adapter's own
    # `session/prompt` request, NOT value equality: two real calls with
    # identical `used` both accumulate.
    if not activity_stats.get(_PROMPT_TURN_ACTIVE_KEY):
        conversation_registry.note_usage_frame("dropped_outside_prompt_turn")
        return
    try:
        hermes_session_id, _session_key = get_runtime_session_env()
    except Exception:
        conversation_registry.note_usage_frame("dropped_no_session_identity")
        return
    hermes_session_id = str(hermes_session_id or "").strip()
    if not hermes_session_id:
        conversation_registry.note_usage_frame("dropped_no_session_identity")
        return

    native_session_id_hash = _opaque_permission_id(
        activity_stats.get("native_session_id"), "native-session"
    )
    if not native_session_id_hash:
        conversation_registry.note_usage_frame("dropped_no_native_session")
        return
    conversation_registry.add_usage_delta(
        hermes_session_id,
        model=str(activity_stats.get("model") or "antigravity-acp"),
        used=update["used"],
        native_session_id_hash=native_session_id_hash,
    )


def _capture_context_occupancy(
    update: Any, activity_stats: dict[str, Any] | None
) -> None:
    """Keep the latest valid ACP usage update separate from request billing usage.

    A frame carrying any present-but-invalid used/size value is rejected as a
    whole (a corrupt frame never contributes its otherwise-valid sibling).
    Valid frames merge field-wise so a partial frame updates only the fields it
    carries without erasing the last valid observation of the others.
    """
    if (
        not isinstance(update, dict)
        or not isinstance(activity_stats, dict)
        or not activity_stats.get("turn_id_hash")
        or str(update.get("sessionUpdate") or "").strip() != "usage_update"
    ):
        return

    present = [field for field in ("used", "size") if field in update]
    if not present or not all(
        _nonnegative_json_number(update[field]) for field in present
    ):
        return

    previous = activity_stats.get("context_occupancy")
    merged: dict[str, Any] = {}
    if isinstance(previous, dict):
        merged = {
            field: previous[field]
            for field in ("used", "size")
            if field in previous and _nonnegative_json_number(previous[field])
        }
    merged.update({field: update[field] for field in present})
    # The reading's MEANING depends on the server's semantics.  Only a
    # source-verified identity gets the per-call-consumption-delta label;
    # for anything else the meaning is honestly unverified (issue #6 review).
    verified = (
        activity_stats.get(_SERVER_CONSUMPTION_SEMANTICS_KEY)
        == _USAGE_SEMANTICS_VERIFIED
    )
    activity_stats["context_occupancy"] = {
        "source": _CONTEXT_OCCUPANCY_SOURCE,
        "scope": _USAGE_DELTA_SCOPE if verified else _USAGE_SCOPE_UNVERIFIED,
        "is_billing_usage": False,
        **merged,
    }


_TURN_USAGE_CALLS_KEY = "turn_usage_calls_observed"
_TURN_USAGE_SUM_KEY = "turn_usage_tokens_sum"


def _capture_turn_usage(update: Any, activity_stats: dict[str, Any] | None) -> None:
    """Accumulate one prompt turn's server-reported per-call consumption.

    ``usage_update.used`` is the official server's consumption delta for the
    latest model call (docs/acp-usage-telemetry.md), not cumulative session
    occupancy.  Summing the gated frames observed inside one turn gives the
    provider's own view of the turn's token consumption.  It may under-report
    (the server omits zero-delta frames and excludes subagent calls) and
    carries no input/output split, so it is exposed ONLY as explicitly scoped
    provider telemetry (``turn_consumption``) and durable observed sums —
    never as the generic OpenAI-shaped usage (issue #6 AC4-1).
    """
    if (
        not isinstance(update, dict)
        or str(update.get("sessionUpdate") or "").strip() != "usage_update"
        or not isinstance(activity_stats, dict)
    ):
        return
    # Whole-frame validity mirrors _capture_context_occupancy: a frame with a
    # present-but-invalid used/size contributes nothing, even when its other
    # field is well-formed.
    present = [field for field in ("used", "size") if field in update]
    if "used" not in present or not all(
        _nonnegative_json_number(update[field]) for field in present
    ):
        return
    # Same consumption gates as _capture_usage_delta: the turn sum is a
    # per-call consumption proxy only for a verified identity's in-prompt-turn
    # frames; re-reports, out-of-window frames, and zero placeholders are not
    # consumption and must not inflate the sum or the call count.
    if (
        activity_stats.get(_SERVER_CONSUMPTION_SEMANTICS_KEY) != _USAGE_SEMANTICS_VERIFIED
        or not activity_stats.get(_PROMPT_TURN_ACTIVE_KEY)
        or update["used"] == 0
    ):
        return
    activity_stats[_TURN_USAGE_CALLS_KEY] = int(activity_stats.get(_TURN_USAGE_CALLS_KEY) or 0) + 1
    activity_stats[_TURN_USAGE_SUM_KEY] = float(
        activity_stats.get(_TURN_USAGE_SUM_KEY) or 0.0
    ) + float(update["used"])


def _turn_usage_from_prompt_result(result: Any) -> Any:
    """Translate ACP's optional per-turn Usage into OpenAI usage fields."""
    usage = result.get("usage") if isinstance(result, dict) else None
    if not isinstance(usage, dict):
        return None
    required = ("inputTokens", "outputTokens", "totalTokens")
    optional = ("thoughtTokens", "cachedReadTokens", "cachedWriteTokens")
    for name in required + optional:
        value = usage.get(name)
        if name in required or value is not None:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return None
    thoughts = usage.get("thoughtTokens") or 0
    result_usage = SimpleNamespace(
        prompt_tokens=usage["inputTokens"],
        completion_tokens=usage["outputTokens"] + thoughts,
        total_tokens=usage["totalTokens"],
        completion_tokens_details=SimpleNamespace(reasoning_tokens=thoughts),
    )
    if usage.get("cachedReadTokens") is not None:
        result_usage.prompt_tokens_details = SimpleNamespace(
            cached_tokens=usage["cachedReadTokens"]
        )
    return result_usage




def _build_usage_telemetry(
    *,
    model: str | None,
    session_id: Any,
    turn_id_hash: str | None,
    context_occupancy: Any,
    turn_consumption: Any = None,
    server_consumption_semantics: str = _USAGE_SEMANTICS_UNVERIFIED,
) -> dict[str, Any]:
    """Build JSON-compatible metadata without inferring billable token counts."""
    semantics_verified = server_consumption_semantics == _USAGE_SEMANTICS_VERIFIED
    occupancy: dict[str, Any] | None = None
    if isinstance(context_occupancy, dict):
        values = {
            field: context_occupancy[field]
            for field in ("used", "size")
            if field in context_occupancy
            and _nonnegative_json_number(context_occupancy[field])
        }
        if values:
            # The capture site already labeled the reading's meaning against
            # the pinned server semantics; carry that label, never relabel it
            # as a delta here (issue #6 review).
            captured_scope = context_occupancy.get("scope")
            occupancy = {
                "source": _CONTEXT_OCCUPANCY_SOURCE,
                "scope": (
                    captured_scope
                    if isinstance(captured_scope, str) and captured_scope
                    else (
                        _USAGE_DELTA_SCOPE
                        if semantics_verified
                        else _USAGE_SCOPE_UNVERIFIED
                    )
                ),
                "is_billing_usage": False,
                **values,
            }

    consumption: dict[str, Any] | None = (
        dict(turn_consumption) if isinstance(turn_consumption, dict) else None
    )
    occupancy_provenance = (
        "usage_update.used is per-model-call consumption, not billing usage; "
        "size is the context window"
        if semantics_verified
        else (
            "this server's usage_update.used semantics are not source-verified; "
            "the reading is retained as an opaque observation, not billing "
            "usage, consumption deltas, or context occupancy"
        )
    )

    return {
        "schema_id": "antigravity-acp-usage-v1",
        "status": "unavailable",
        "provider": "antigravity-acp",
        "model": str(model or "antigravity-acp"),
        "request_usage": {bucket: None for bucket in _USAGE_BUCKETS},
        "server_consumption_semantics": str(server_consumption_semantics),
        "provenance": {
            "source": "official_acp_v1.4.0",
            "request_usage": (
                "populated in completion.usage ONLY from the server's own "
                "session/prompt result usage breakdown; never synthesized from "
                "usage_update frames (issue #6 AC4-1)"
            ),
            "context_occupancy": occupancy_provenance,
            "turn_consumption": (
                "sum of gated per-model-call consumption deltas observed this turn "
                "(main-agent-only, may under-report); observed processing, not "
                "unique-context size, billed tokens, or account quota"
            ),
        },
        "native_session_id_hash": _opaque_permission_id(session_id, "native-session"),
        "turn_id_hash": turn_id_hash or _opaque_permission_id(uuid.uuid4().hex, "turn"),
        "context_occupancy": occupancy,
        "turn_consumption": consumption,
    }


def _safe_permission_tool_name(tool_call: dict[str, Any]) -> str:
    name = str(tool_call.get("name") or "").strip()
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,63}", name):
        return name
    return "unknown"


def _permission_tool_origin(tool_call: dict[str, Any]) -> str:
    name = _safe_permission_tool_name(tool_call)
    explicit_origin = str(tool_call.get("origin") or "").strip().lower()
    if explicit_origin in {"native", "native_acp", "builtin", "built_in"}:
        return "native_acp"
    if explicit_origin in {"mcp", "hermes"}:
        return explicit_origin
    if name.startswith(("mcp__", "mcp.")):
        return "mcp"
    if name in _NATIVE_PERMISSION_TOOL_NAMES:
        return "native_acp"
    return "unknown"


def _permission_option_kinds(params: dict[str, Any]) -> list[str]:
    options = params.get("options")
    if not isinstance(options, list):
        return []
    kinds: list[str] = []
    for option in options[:16]:
        if not isinstance(option, dict):
            continue
        kind = str(option.get("kind") or "").strip()
        kinds.append(kind if kind in _DOCUMENTED_PERMISSION_OPTION_KINDS else "other")
    return kinds


def _safe_reject_permission_option(params: dict[str, Any]) -> tuple[str, str] | None:
    options = params.get("options")
    if not isinstance(options, list):
        return None
    for preferred_kind in ("reject_once", "reject_always"):
        for option in options:
            if not isinstance(option, dict):
                continue
            if str(option.get("kind") or "").strip() != preferred_kind:
                continue
            option_id = str(option.get("optionId") or "").strip()
            if option_id:
                return option_id, preferred_kind
    return None


def _emit_permission_telemetry(
    *,
    tool_call: dict[str, Any],
    activity_stats: dict[str, Any] | None,
    decision_stage: str,
    offered_option_kinds: list[str],
    selected_option_kind: str | None,
    server_outcome: str,
    protocol_limitation: str | None = None,
    selection_source: str | None = None,
) -> None:
    tool_call_id = str(tool_call.get("toolCallId") or "").strip()
    permission_denied = (
        decision_stage == "server_pre_tool"
        or selected_option_kind in {"reject_once", "reject_always"}
        or server_outcome in {"denied", "cancelled"}
    )
    if permission_denied and activity_stats is not None:
        activity_stats["permission_denied"] = True
    event: dict[str, Any] = {
        "decision_stage": decision_stage,
        "session_id_hash": (activity_stats or {}).get("session_id_hash"),
        "turn_id_hash": (activity_stats or {}).get("turn_id_hash"),
        "tool_call_id_hash": _opaque_permission_id(tool_call_id, "tool-call"),
        "tool_name": _safe_permission_tool_name(tool_call),
        "tool_origin": _permission_tool_origin(tool_call),
        "offered_option_kinds": offered_option_kinds,
        "selected_option_kind": selected_option_kind,
        "server_outcome": server_outcome,
        "tool_outcome": (
            "permission_denied_not_executed"
            if permission_denied
            else "permission_granted_execution_not_observed"
        ),
    }
    if protocol_limitation:
        event["protocol_limitation"] = protocol_limitation
    if selection_source:
        event["selection_source"] = selection_source
    logger.info(
        "Antigravity ACP permission telemetry %s",
        json.dumps(event, sort_keys=True, separators=(",", ":")),
    )


def _contains_denial_marker(value: Any, depth: int = 0) -> bool:
    if depth > 3:
        return False
    if isinstance(value, str):
        text = value.lower()
        return any(
            marker in text
            for marker in (
                "denied by pre-tool hook",
                "denied by user",
                # official 1.4.0 echoes the harness's own rejection with this
                # exact text (verified live in the historical reference canary); the
                # correlation table decides whether it is a harness echo.
                "rejected by user",
            )
        )
    if isinstance(value, dict):
        return any(
            _contains_denial_marker(value.get(key), depth + 1)
            for key in ("error", "message", "text", "rawOutput", "content")
        )
    if isinstance(value, list):
        return any(_contains_denial_marker(item, depth + 1) for item in value[:16])
    return False


def _log_server_pre_tool_denial(
    update: dict[str, Any], activity_stats: dict[str, Any] | None
) -> None:
    if activity_stats is None or not isinstance(update, dict):
        return
    status = str(update.get("status") or "").strip().lower()
    if status not in {"failed", "error", "failure"} or not _contains_denial_marker(update):
        return

    tool_call = {
        "toolCallId": update.get("toolCallId"),
        "name": update.get("name") or update.get("toolName"),
        "origin": update.get("origin"),
    }
    call_hash = _opaque_permission_id(tool_call.get("toolCallId"), "tool-call")
    seen = activity_stats.setdefault("_permission_telemetry_seen", set())
    if call_hash and call_hash in seen:
        return
    if call_hash:
        seen.add(call_hash)
    # A failed update carrying "Denied by user" is not evidence a human denied
    # anything: when the harness itself selected the reject option, the official
    # server echoes that selection back with that wording. Attribute it to the
    # harness echo; only an uncorrelated denial is a server-side pre-tool hook.
    denied_by_harness = bool(call_hash) and call_hash in activity_stats.get(
        "_harness_denied_tool_call_hashes", ()
    )
    decision_stage = (
        "harness_denial_echo" if denied_by_harness else "server_pre_tool"
    )
    _emit_permission_telemetry(
        tool_call=tool_call,
        activity_stats=activity_stats,
        decision_stage=decision_stage,
        offered_option_kinds=[],
        selected_option_kind=None,
        server_outcome="denied",
    )


_NATIVE_TOOL_SAFE_INPUT_KEYS = frozenset({
    "absolute_path", "path", "file_path", "directory_path",
    "start_line", "end_line", "query", "pattern", "glob", "num_results",
})


def _native_tool_safe_input(kind: str, raw_input: Any, *, title: str = "") -> dict[str, Any] | None:
    """Preserve bounded read evidence even if ACP labels a read tool as kind='other'.

    Never persist command/code bodies for unknown, execute, or mutation tools.
    """
    if not isinstance(raw_input, dict):
        return None
    safe: dict[str, Any] = {}
    normalized_title = title.strip().lower().replace("-", "_")
    known_read_tool = any(name in normalized_title for name in (
        "client_view_file", "view_file", "read_file", "client_read_file",
        "client_search", "search_files", "grep_search", "find_in_files",
    ))
    if kind in {"read", "search"} or (
        kind in {"", "other"} and known_read_tool
        and not _PERMISSION_MUTATION_HINT_RE.search(title)
    ):
        for key in _NATIVE_TOOL_SAFE_INPUT_KEYS:
            value = raw_input.get(key)
            if key == "query":
                if isinstance(value, str) and value.strip():
                    safe["query_present"] = True
                continue
            if isinstance(value, str):
                safe[key] = value[:1000]
            elif isinstance(value, (int, float, bool)) or value is None:
                if key in raw_input:
                    safe[key] = value
    else:
        # Never persist command/code bodies for execute/write-style native tools.
        keys = sorted(str(key) for key in raw_input.keys())[:32]
        if keys:
            safe["input_keys"] = keys
    return safe or None


def _capture_native_tool_activity(
    update: dict[str, Any], activity_stats: dict[str, Any] | None
) -> None:
    """Merge ACP-native tool events into audit-only activity records.

    These calls have already executed inside Antigravity. They must never be surfaced as
    Hermes message.tool_calls because doing so would execute the same effect twice.
    """
    if activity_stats is None or not isinstance(update, dict):
        return
    update_kind = str(update.get("sessionUpdate") or "").strip()
    if update_kind not in {"tool_call", "tool_call_update"}:
        return

    call_id = str(update.get("toolCallId") or "").strip()
    if not call_id:
        return
    events = activity_stats.setdefault("native_tool_calls", [])
    index = activity_stats.setdefault("_native_tool_call_index", {})
    event = None
    pos = index.get(call_id)
    if isinstance(pos, int) and 0 <= pos < len(events):
        existing = events[pos]
        if isinstance(existing, dict):
            event = existing
    if event is None:
        event = {"type": "antigravity_native_tool", "tool_call_id": call_id}
        index[call_id] = len(events)
        events.append(event)

    for key, target in (
        ("name", "name"),
        ("toolName", "name"),
        ("title", "title"),
        ("kind", "kind"),
        ("status", "status"),
    ):
        value = update.get(key)
        if isinstance(value, str) and value.strip():
            if target == "name":
                safe_name = _safe_permission_tool_name({"name": value})
                if safe_name != "unknown":
                    event[target] = safe_name
            else:
                event[target] = value.strip()[:500]

    event["origin"] = _permission_tool_origin(update)
    event["tool_call_id_hash"] = _opaque_permission_id(call_id, "tool-call") or "unknown"

    kind = str(event.get("kind") or update.get("kind") or "").strip().lower()
    safe_input = _native_tool_safe_input(
        kind, update.get("rawInput"), title=str(event.get("title") or "")
    )
    if safe_input:
        event["input"] = safe_input


def _native_tool_reasoning_details(native_activity: dict[str, Any]) -> list[dict[str, Any]]:
    """Return durable transcript evidence for already-executed ACP-native tools."""
    details: list[dict[str, Any]] = []
    for item in native_activity.get("native_tool_calls") or []:
        if not isinstance(item, dict):
            continue
        detail = {
            "type": "antigravity_native_tool",
            "tool_call_id": str(item.get("tool_call_id") or ""),
            "title": str(item.get("title") or ""),
            "kind": str(item.get("kind") or ""),
            "status": str(item.get("status") or ""),
        }
        if isinstance(item.get("input"), dict):
            detail["input"] = dict(item["input"])
        details.append(detail)
    return details


def _is_read_tool_name(name: Any) -> bool:
    return bool(_READ_TOOL_NAME_RE.search(str(name or "").strip()))


def _native_completed_read_evidence(native_activity: dict[str, Any]) -> list[dict[str, Any]]:
    """Completed ACP-native reads/searches that can ground a source-review claim."""
    evidence: list[dict[str, Any]] = []
    successful = {"completed", "complete", "done", "success", "succeeded", "finished"}
    for item in native_activity.get("native_tool_calls") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").strip().lower()
        title = str(item.get("title") or "").strip()
        if kind not in {"read", "search"} and not _is_read_tool_name(title):
            continue
        status = str(item.get("status") or "").strip().lower()
        if status not in successful:
            continue
        raw_input = item.get("input")
        if not isinstance(raw_input, dict) or not any(
            key in raw_input
            for key in (
                "absolute_path", "path", "file_path", "directory_path",
                "query_present", "query", "pattern", "glob",
            )
        ):
            continue
        evidence.append(item)
    return evidence


def _pending_read_tool_call(tool_calls: list[Any]) -> bool:
    for call in tool_calls or []:
        function = getattr(call, "function", None)
        if _is_read_tool_name(getattr(function, "name", "")):
            return True
    return False


def _completed_hermes_read_evidence(messages: list[dict[str, Any]]) -> bool:
    """Whether the active request already has a completed Hermes read/search result."""
    last_user = -1
    for index, message in enumerate(messages):
        if isinstance(message, dict) and str(message.get("role") or "").strip().lower() == "user":
            last_user = index
    call_names: dict[str, str] = {}
    for message in messages[last_user + 1 :]:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role == "assistant":
            for call in message.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                function = call.get("function")
                if not isinstance(function, dict):
                    continue
                call_id = str(call.get("id") or "").strip()
                name = str(function.get("name") or "").strip()
                if call_id and name:
                    call_names[call_id] = name
            continue
        if role != "tool":
            continue
        name = str(message.get("name") or "").strip()
        if not name:
            name = call_names.get(str(message.get("tool_call_id") or "").strip(), "")
        if _is_read_tool_name(name) and not _tool_execution_failed(message.get("content")):
            return True
    return False


def _requires_auditable_read_evidence(messages: list[dict[str, Any]]) -> bool:
    """Conservative gate for review prompts that explicitly demand real source-read proof."""
    active = ""
    for message in reversed(messages):
        if isinstance(message, dict) and str(message.get("role") or "").strip().lower() == "user":
            active = _render_message_content(message.get("content"))
            break
    if not active:
        return False
    lowered = active.lower()
    # Hermes context compaction sends the transcript inside a summarizer
    # prompt; that transcript can carry review vocabulary ("evidence",
    # "독립 검토") and would falsely trip this gate. The summarizer cannot
    # do tool reads, so a gate failure there just breaks compaction. These
    # preamble phrases are byte-pinned in hermes' context_compressor.py
    # (_summarizer_preamble); matching them is conservative by construction.
    summarizer_preamble = "you are a summarization agent creating a context checkpoint"
    if lowered.lstrip().startswith(summarizer_preamble) or (
        "you are updating a context compaction summary" in lowered[:1500]
    ):
        return False
    explicit = (
        "actual tool-read evidence",
        "tool-read evidence",
        "must inspect actual",
        "inspect actual git diff",
        "exact file/line",
        "actual source/test/doc",
        "도구 열람 기록",
        "도구 읽기 증거",
        "실제 git diff",
        "정확한 파일/줄",
    )
    if any(phrase in lowered for phrase in explicit):
        return True
    inspect_signal = any(
        phrase in lowered
        for phrase in ("must inspect", "independent review", "직접 검증", "실제 소스", "실제 파일", "독립 검토")
    )
    audit_signal = any(
        phrase in lowered
        for phrase in ("evidence", "exact file", "line", "증거", "근거", "줄번호", "열람")
    )
    return inspect_signal and audit_signal


def _native_evidence_summary(details: list[dict[str, Any]]) -> str:
    """Short adapter-authored progress text so Hermes live transcripts retain native read proof."""
    rows: list[str] = []
    for item in details[:4]:
        title = str(item.get("title") or item.get("kind") or "native_tool").strip()
        status = str(item.get("status") or "").strip()
        raw_input = item.get("input") if isinstance(item.get("input"), dict) else {}
        target = next(
            (
                str(raw_input.get(key) or "").strip()
                for key in ("absolute_path", "path", "file_path", "directory_path", "query", "pattern", "glob")
                if str(raw_input.get(key) or "").strip()
            ),
            "",
        )
        line_bits = []
        for key in ("start_line", "end_line"):
            if raw_input.get(key) is not None:
                line_bits.append(str(raw_input[key]))
        line_range = (" lines=" + "-".join(line_bits)) if line_bits else ""
        rows.append(f"{title} {target}{line_range} [{status or 'observed'}]".strip())
    if not rows:
        return ""
    text = "; ".join(rows)
    if len(text) > 700:
        text = text[:697] + "..."
    return "[ACP native evidence | adapter-observed, not model-authored] " + text


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _fingerprint_prompt_message(message: dict[str, Any], role: str) -> str:
    if role != "assistant":
        return _fp_render_prompt_message(message, role)
    content = _fp_render_message_content(message.get("content"))
    parts = [content] if content else []
    for tool_call in message.get("tool_calls") or []:
        if not isinstance(tool_call, dict):
            continue
        function = tool_call.get("function")
        if not isinstance(function, dict) or not str(function.get("name") or "").strip():
            continue
        payload = {
            "id": str(tool_call.get("id") or ""),
            "type": str(tool_call.get("type") or "function"),
            "function": {
                "name": str(function.get("name") or ""),
                "arguments": _normalized_tool_arguments(function.get("arguments", "{}")),
            },
        }
        parts.append(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
        )
    return "\n".join(parts).strip()


def _message_fingerprint(message: dict[str, Any]) -> str:
    role = str(message.get("role") or "unknown").strip().lower()
    return _sha256_text(f"{role}\0{_fingerprint_prompt_message(message, role)}")


def _context_fingerprint(
    model: str | None,
    tools: list[dict[str, Any]] | None,
    tool_choice: Any,
) -> str:
    payload_obj: dict[str, Any] = {
        "model": str(model or ""),
        "tool_bridge": render_tool_bridge_sections(tools, tool_choice),
    }
    payload = json.dumps(
        payload_obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return _sha256_text(payload)


def _response_fingerprint(content: str, tool_calls: list[Any]) -> str:
    message: dict[str, Any] = {"role": "assistant", "content": content or ""}
    if tool_calls:
        message["tool_calls"] = [
            {
                "id": str(getattr(call, "id", "") or ""),
                "type": str(getattr(call, "type", "function") or "function"),
                "function": {
                    "name": str(getattr(getattr(call, "function", None), "name", "") or ""),
                    "arguments": getattr(getattr(call, "function", None), "arguments", "{}"),
                },
            }
            for call in tool_calls
        ]
    return _message_fingerprint(message)


def _continuation_delta(
    messages: list[dict[str, Any]],
    state: ACPConversationState,
    context_fingerprint: str,
) -> list[dict[str, Any]] | None:
    if state.context_fingerprint != context_fingerprint:
        return None
    prefix_len = len(state.request_fingerprints)
    if len(messages) <= prefix_len:
        return None
    if tuple(_message_fingerprint(message) for message in messages[:prefix_len]) != state.request_fingerprints:
        return None
    assistant = messages[prefix_len]
    if (
        not isinstance(assistant, dict)
        or str(assistant.get("role") or "").strip().lower() != "assistant"
        or _message_fingerprint(assistant) != state.response_fingerprint
    ):
        return None
    delta = messages[prefix_len + 1 :]
    if not delta:
        return None
    if any(
        str(message.get("role") or "").strip().lower() == "system"
        for message in delta
        if isinstance(message, dict)
    ):
        return None
    return delta


def _active_user_text(messages: list[dict[str, Any]]) -> str:
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            return _render_prompt_message(message, "user")
    return ""


def _denied_request_text(
    messages: list[dict[str, Any]], state: ACPConversationState | None
) -> str:
    """Resolve the last denied request by fingerprint without persisting its text."""
    fingerprint = str(getattr(state, "denied_request_fingerprint", "") or "")
    if not fingerprint:
        return ""
    for message in messages:
        if (
            isinstance(message, dict)
            and str(message.get("role") or "").strip().lower() == "user"
            and _message_fingerprint(message) == fingerprint
        ):
            return _render_prompt_message(message, "user")
    return ""


_DATA_IMAGE_RE = re.compile(r"^data:([a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+);base64,")


def _image_blocks_for_messages(
    messages: list[dict[str, Any]], *, active_turn_only: bool = False
) -> list[dict[str, str]]:
    """Extract inline images as ACP blocks, preserving order and deduping bytes.

    Full replays keep the legacy active-turn boundary: prior user turns have already
    been normalized to text, while tool-result images following the latest user are
    part of the active request and must accompany it.
    """
    blocks: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add_block(mime: str, data: str) -> None:
        if not mime or not data:
            return
        key = (mime, data)
        if key in seen:
            return
        seen.add(key)
        blocks.append({"type": "image", "data": data, "mimeType": mime})

    def extract_part(part: Any) -> None:
        if not isinstance(part, dict):
            return
        part_type = str(part.get("type") or "").lower()
        if part_type == "image_url":
            image = part.get("image_url")
            url = str(image.get("url") if isinstance(image, dict) else image or "")
            match = _DATA_IMAGE_RE.match(url)
            if match is not None:
                add_block(match.group(1), url.split(",", 1)[1])
        elif part_type == "image":
            add_block(str(part.get("mimeType") or ""), str(part.get("data") or ""))

    def extract_content(value: Any) -> None:
        if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return
        if isinstance(value, list):
            for part in value:
                extract_part(part)
            return
        if not isinstance(value, dict):
            return
        if str(value.get("type") or "").lower() in {"image_url", "image"}:
            extract_part(value)
            return
        nested = value.get("content")
        if value.get("_multimodal") is True or isinstance(nested, list):
            extract_content(nested)

    image_messages = messages
    if active_turn_only:
        latest_user_index = next(
            (
                index for index in range(len(messages) - 1, -1, -1)
                if isinstance(messages[index], dict)
                and str(messages[index].get("role") or "").strip().lower() == "user"
            ),
            None,
        )
        if latest_user_index is not None:
            image_messages = messages[latest_user_index:]

    for message in image_messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role not in {"user", "tool"}:
            continue
        extract_content(message.get("content"))
    return blocks


def _message_text_parts(message: dict[str, Any]) -> list[str]:
    content = message.get("content")
    if isinstance(content, str):
        return [content]
    if isinstance(content, list):
        return [
            str(part.get("text") or "")
            for part in content
            if isinstance(part, dict) and str(part.get("type") or "").lower() == "text"
        ]
    return []


def _latest_user_index(messages: list[dict[str, Any]]) -> int | None:
    return next(
        (
            index
            for index in range(len(messages) - 1, -1, -1)
            if isinstance(messages[index], dict)
            and str(messages[index].get("role") or "").strip().lower() == "user"
        ),
        None,
    )


# Native video is opt-in, never enabled by note shape alone. There is no
# authenticated Core-generated attachment marker in the plugin request_messages
# shape; a same-user sender can forge this text and point at any video in the
# allowed cache. Enabling this variable is therefore an explicit trust decision
# (unsafe for shared Hermes homes or untrusted users).
_VIDEO_ATTACHMENT_NOTE_RE = re.compile(
    r"\[The user sent a video attachment: '[^']*'\.\s*"
    r"It is saved at:\s*(?P<path>[^\s'\"\]]+)\."
    r"\s*Its content is not inlined here\."
)
# Guessed MIME types here must match the official server's SUPPORTED_VIDEO_MIMES
# after mimetypes.guess_type(); .avi/.mkv are deliberately absent because their
# guesses (video/x-msvideo, video/x-matroska) are rejected by the server and
# would silently degrade to a bare path string.
_NATIVE_VIDEO_MIMES = {
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".webm": "video/webm",
}
_NATIVE_VIDEO_EXT_BY_MIME = {
    "video/mp4": ".mp4",
    "video/quicktime": ".mov",
    "video/webm": ".webm",
}
_MAX_NATIVE_VIDEO_BLOCKS = 2
_MAX_NATIVE_VIDEO_BYTES = 50 * 1024 * 1024
_MAX_NATIVE_VIDEO_AGE_SECONDS = 24 * 3600
_ACTIVE_TEMP_VIDEO_FILES: set[Path] = set()


def _cleanup_temp_video_files(paths: Any) -> None:
    for item in list(paths or ()):
        if isinstance(item, (str, Path)):
            p = Path(item)
            _ACTIVE_TEMP_VIDEO_FILES.discard(p)
            with contextlib.suppress(OSError):
                if p.is_file() or p.is_symlink():
                    p.unlink(missing_ok=True)


atexit.register(lambda: _cleanup_temp_video_files(list(_ACTIVE_TEMP_VIDEO_FILES)))


def _native_video_cache_root() -> Path | None:
    """The video cache directory of the current Hermes home/profile."""
    home = get_hermes_home_for_video()
    if home is None:
        return None
    return home / "cache" / "videos"


def _validated_video_resource_link(path_str: str) -> dict[str, str] | None:
    """Turn a note's cache path into a safe ACP resource_link block, or None.

    The note text is attacker-influenceable (a chat participant can type the
    same sentence about any local path), so the path must pass a fail-closed
    allowlist: current home's video cache directory only, regular file
    (symlinks rejected via lstat AND realpath identity), known video suffix,
    bounded size and freshness.  The official server reads the URI with its
    own privileges and embeds supported documents verbatim, so any looser
    containment is an arbitrary local file read.
    """
    if os.environ.get("HERMES_ANTIGRAVITY_ACP_NATIVE_VIDEO", "").strip() != "1":
        return None
    path = Path(path_str)
    if not path.is_absolute() or ".." in path.parts:
        return None
    if path.suffix.lower() not in _NATIVE_VIDEO_MIMES:
        return None
    try:
        stat_result = path.lstat()
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(stat_result.st_mode):
        return None
    if not 0 < stat_result.st_size <= _MAX_NATIVE_VIDEO_BYTES:
        return None
    now = time.time()
    if stat_result.st_mtime > now + 300 or now - stat_result.st_mtime > _MAX_NATIVE_VIDEO_AGE_SECONDS:
        return None
    try:
        real = path.resolve(strict=True)
        root = _native_video_cache_root()
    except (OSError, ValueError):
        return None
    if root is None:
        return None
    try:
        root = root.resolve(strict=False)
    except (OSError, ValueError):
        return None
    # The cache layout is flat; requiring the resolved parent (and the raw
    # path itself, via lstat-regular + equality below) to be exactly the
    # current profile's cache directory blocks symlinked directories,
    # cross-profile caches, and traversal in one comparison.
    if real.parent != root or str(real) != str(path):
        return None
    try:
        final_stat = path.lstat()
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(final_stat.st_mode) or (
        stat_result.st_dev,
        stat_result.st_ino,
        stat_result.st_size,
        stat_result.st_mtime_ns,
        stat_result.st_ctime_ns,
    ) != (
        final_stat.st_dev,
        final_stat.st_ino,
        final_stat.st_size,
        final_stat.st_mtime_ns,
        final_stat.st_ctime_ns,
    ):
        return None
    return {
        "type": "resource_link",
        "uri": "file://" + quote(str(real), safe="/"),
        "name": real.name,
        "mimeType": _NATIVE_VIDEO_MIMES[real.suffix.lower()],
        # Private in-process metadata, stripped before ACP wire serialization.
        # It lets us reject a file replaced after extraction but before send.
        "_hermes_source_path": str(real),
        "_hermes_identity": ":".join(
            str(value)
            for value in (
                final_stat.st_dev,
                final_stat.st_ino,
                final_stat.st_size,
                final_stat.st_mtime_ns,
                final_stat.st_ctime_ns,
            )
        ),
    }


def _wire_media_blocks(blocks: tuple[dict[str, str], ...] | list[dict[str, str]]) -> list[dict[str, str]]:
    """Revalidate path identity immediately before session/prompt serialization.

    A resource_link is a path, not a file descriptor. This closes the larger
    extraction→session-start race and detects ordinary replacements before the
    request is sent, but cannot eliminate the final race between this check and
    the official server's later open(). The wire format has no fd/pin primitive.
    """
    result: list[dict[str, str]] = []
    for block in blocks:
        source_path = block.get("_hermes_source_path")
        expected_identity = block.get("_hermes_identity")
        if source_path and expected_identity:
            current = _validated_video_resource_link(source_path)
            if current is None or current.get("_hermes_identity") != expected_identity:
                logger.warning("Skipping native video changed before ACP prompt serialization.")
                continue
            result.append(
                {key: current[key] for key in ("type", "uri", "name", "mimeType")}
            )
        elif block.get("type") == "resource_link":
            # Never trust caller-supplied ACP resource_link blocks; only the
            # validator above may mint an in-process identity for this path.
            logger.warning("Skipping native video resource_link without local validation metadata.")
        else:
            result.append(block)
    return result


def _materialize_video_data_url(
    mime: str, data: bytes, *, temp_files: list[Path] | None = None
) -> dict[str, str] | None:
    """Safely write decoded video bytes to current profile's cache and return resource_link."""
    if os.environ.get("HERMES_ANTIGRAVITY_ACP_NATIVE_VIDEO", "").strip() != "1":
        return None
    if not (0 < len(data) <= _MAX_NATIVE_VIDEO_BYTES):
        return None
    ext = _NATIVE_VIDEO_EXT_BY_MIME.get(mime)
    if not ext:
        return None
    root = _native_video_cache_root()
    if root is None:
        return None
    try:
        root = root.resolve(strict=False)
        root.mkdir(parents=True, exist_ok=True)
        token = secrets.token_hex(16)
        temp_name = f"video_data_{os.getpid()}_{time.time_ns()}_{token}{ext}"
        temp_path = root / temp_name
        fd = os.open(str(temp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with open(fd, "wb", closefd=True) as fh:
                fh.write(data)
        except Exception:
            with contextlib.suppress(OSError):
                os.close(fd)
            with contextlib.suppress(OSError):
                temp_path.unlink(missing_ok=True)
            return None
    except (OSError, ValueError):
        return None

    block = _validated_video_resource_link(str(temp_path))
    if block is None:
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)
        return None

    _ACTIVE_TEMP_VIDEO_FILES.add(temp_path)
    if temp_files is not None:
        temp_files.append(temp_path)
    return block


def _extract_video_data_urls(content: Any) -> list[tuple[str, bytes]]:
    """Extract (mime_type, raw_bytes) from structured content parts."""
    results: list[tuple[str, bytes]] = []

    def extract_part(part: Any) -> None:
        if not isinstance(part, dict):
            return
        part_type = str(part.get("type") or "").strip().lower()
        url = ""
        if part_type == "video_url":
            video = part.get("video_url")
            if isinstance(video, dict):
                url = str(video.get("url") or "")
            elif isinstance(video, str):
                url = video
            if not url:
                url = str(part.get("url") or "")
        elif part_type == "video":
            if "data" in part and ("mimeType" in part or "mime_type" in part):
                mime = str(part.get("mimeType") or part.get("mime_type") or "").strip().lower()
                data_str = str(part.get("data") or "").strip()
                if mime in _NATIVE_VIDEO_EXT_BY_MIME and data_str:
                    try:
                        raw = base64.b64decode(data_str, validate=True)
                        if 0 < len(raw) <= _MAX_NATIVE_VIDEO_BYTES:
                            results.append((mime, raw))
                    except Exception:
                        pass
                return
            url = str(part.get("url") or "")
        else:
            return

        if not url.startswith("data:"):
            # Refuse non-data URLs: no network fetch, no arbitrary file read
            return

        match = _DATA_IMAGE_RE.match(url)
        if match is None:
            return
        mime = match.group(1).lower()
        if mime not in _NATIVE_VIDEO_EXT_BY_MIME:
            return
        try:
            b64_payload = url.split(",", 1)[1].strip()
            raw = base64.b64decode(b64_payload, validate=True)
            if 0 < len(raw) <= _MAX_NATIVE_VIDEO_BYTES:
                results.append((mime, raw))
        except Exception:
            pass

    def extract_content(value: Any) -> None:
        if isinstance(value, str) and value.lstrip().startswith(("{", "[")):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                return
        if isinstance(value, list):
            for part in value:
                extract_part(part)
            return
        if not isinstance(value, dict):
            return
        if str(value.get("type") or "").lower() in {"video_url", "video"}:
            extract_part(value)
            return
        nested = value.get("content")
        if value.get("_multimodal") is True or isinstance(nested, list):
            extract_content(nested)

    extract_content(content)
    return results


def _video_blocks_for_messages(
    messages: list[dict[str, Any]], *, temp_files: list[Path] | None = None
) -> list[dict[str, str]]:
    """resource_link blocks for videos attached to the active (latest) user turn.

    Only the latest user turn is scanned, so a video note from a previous turn
    is never re-attached in later requests; dedupe by URI and cap the count to
    keep per-call model token cost bounded.
    """
    latest_user = _latest_user_index(messages)
    if latest_user is None:
        return []
    blocks: list[dict[str, str]] = []
    seen: set[str] = set()
    seen_hashes: set[str] = set()
    for message in messages[latest_user:]:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "").strip().lower()
        if role not in {"user", "tool"}:
            continue
        for text in _message_text_parts(message):
            for match in _VIDEO_ATTACHMENT_NOTE_RE.finditer(text):
                block = _validated_video_resource_link(match.group("path"))
                if block is None or block["uri"] in seen:
                    continue
                seen.add(block["uri"])
                blocks.append(block)
                if len(blocks) >= _MAX_NATIVE_VIDEO_BLOCKS:
                    return blocks
        for mime, raw_bytes in _extract_video_data_urls(message.get("content")):
            content_hash = hashlib.sha256(raw_bytes).hexdigest()
            if content_hash in seen_hashes:
                continue
            seen_hashes.add(content_hash)
            block = _materialize_video_data_url(mime, raw_bytes, temp_files=temp_files)
            if block is None or block["uri"] in seen:
                continue
            seen.add(block["uri"])
            blocks.append(block)
            if len(blocks) >= _MAX_NATIVE_VIDEO_BLOCKS:
                return blocks
    return blocks


def _format_continuation_delta(
    messages: list[dict[str, Any]],
    *,
    active_request: str = "",
    unresolved_denied_request: str = "",
) -> str:
    transcript: list[str] = []
    for message in (item for item in messages if isinstance(item, dict)):
        role = str(message.get("role") or "unknown").strip().lower()
        if rendered := _render_prompt_message(message, role):
            transcript.append(f"{_ROLE_LABELS.get(role, 'Context')}:\n{rendered}")
    sections = [
        "Hermes continuation delta: the ACP session already contains all earlier conversation context and your previous response."
    ]
    if transcript:
        sections.append(
            "New conversation events since your previous ACP turn:\n\n"
            + "\n\n".join(transcript)
        )
    if _has_completed_tool_history(messages):
        sections.append(_TOOL_HISTORY_CONTINUATION_NOTE)
    if unresolved_denied_request.strip():
        sections.append(
            "<ACTIVE_REQUEST_ANCHOR>\n"
            "The latest user message is the active turn. The earlier objective below was left unresolved because its "
            "native ACP permission request was denied before execution. Interpret the latest message against that goal "
            "only when it refers to or continues it; if it changes or cancels the goal, follow the latest message. "
            "Do not claim the denied action ran, repeat it, or bypass permission. Use only a separately available, "
            "authorized Hermes-owned tool; otherwise explain the blocker and give a task-aware safe next step.\n\n"
            "<UNRESOLVED_USER_OBJECTIVE>\n"
            + _neutralize_section_tags(unresolved_denied_request.strip())
            + "\n</UNRESOLVED_USER_OBJECTIVE>\n"
            "<LATEST_USER_FOLLOW_UP>\n"
            + _neutralize_section_tags(active_request.strip())
            + "\n</LATEST_USER_FOLLOW_UP>\n"
            "</ACTIVE_REQUEST_ANCHOR>"
        )
    elif active_request:
        sections.append(
            "<ACTIVE_REQUEST_ANCHOR>\nThe user's original active request still governs this "
            "tool-result continuation. Treat prior tasks as history only.\n"
            + active_request
            + "\n</ACTIVE_REQUEST_ANCHOR>"
        )
    if _latest_tool_result_failed(messages):
        sections.append(
            "EXECUTION FAILED: the latest Hermes tool result reports failure. "
            "Do not claim live inspection/test success from this failed call; "
            "correct the call or explicitly report verification incomplete."
        )
    sections.append(
        "Continue from these new events only; do not restart or repeat completed earlier work."
    )
    return "\n\n".join(section.strip() for section in sections if section.strip())


def _resume_session_missing(exc: BaseException) -> bool:
    text = str(exc).lower()
    return (
        "session not found" in text
        or "no session with this id" in text
        or "current gemini_home" in text
        # The official ACP server crashes its executor when a resumed session's
        # trajectory exceeds the context window and checkpoint state is gone
        # ("could not find doneCh for checkpoint").  The session is unusable
        # from that point on, so it must count as a resume miss and rebuild.
        or "donech for checkpoint" in text
        or "agent executor error" in text
        or "agent execution terminated due to error" in text
    )


# Start from the model-supported context ceiling. The ACP protocol does not
# proactively report its checkpoint/trajectory budget, so stricter limits are
# learned from explicit server errors or inferred from a context/checkpoint
# failure and persisted across Hermes profiles. Rotation keeps a safety margin.
_DEFAULT_NATIVE_TOKEN_LIMIT = 1_000_000
_NATIVE_TOKEN_ROTATION_FRACTION = 0.9
_MIN_INFERRED_NATIVE_LIMIT = 100_000
_CJK_RANGES = (
    (0x1100, 0x11FF), (0x2E80, 0x2FFF), (0x3040, 0x30FF), (0x3130, 0x318F),
    (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xAC00, 0xD7AF), (0xF900, 0xFAFF),
    (0xFE30, 0xFE4F), (0xFF00, 0xFFDC), (0x20000, 0x3134F),
)
_LEARNED_NATIVE_LIMIT_RE = re.compile(
    r"token limit:\s*(\d+)|max_token_limit\s*\((\d+)\)", re.IGNORECASE
)


def _estimate_tokens(text: str) -> int:
    """Conservative token estimate (CJK ~1 token/char, other ~1 token/3 chars)."""
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


def _model_limit_key(model: str | None) -> str:
    return str(model or "").strip() or "default"


def _native_token_limit(model: str | None = None) -> int:
    """Effective cap for one model: learned ACP truth clamps the 1M ceiling."""
    candidates: list[int] = []
    learned = native_limit_registry.get(_model_limit_key(model))
    if learned is not None:
        candidates.append(learned.value)
    override = os.environ.get("HERMES_ANTIGRAVITY_ACP_NATIVE_TOKEN_LIMIT", "").strip()
    if override.isdigit() and int(override) > 0:
        candidates.append(int(override))
    return min(candidates) if candidates else _DEFAULT_NATIVE_TOKEN_LIMIT


def _is_native_limit_failure(text: str) -> bool:
    lowered = str(text or "").lower()
    return bool(
        "max_token_limit" in lowered
        or "token limit" in lowered
        or "context window" in lowered
        or ("trajectory" in lowered and "limit" in lowered)
    )


def _learn_native_limit(
    text: str,
    model: str | None = None,
    *,
    inferred_upper_bound: int = 0,
) -> None:
    """Learn a durable per-model ACP cap from server truth or a bounded failure."""
    key = _model_limit_key(model)
    match = _LEARNED_NATIVE_LIMIT_RE.search(text or "")
    if match:
        value = int(match.group(1) or match.group(2))
        if value > 0:
            state = native_limit_registry.put(key, value, source="server")
            if state is not None:
                logger.warning(
                    "Antigravity ACP learned server native-session limit %d for model %s",
                    state.value,
                    key,
                )
        return

    # A bare doneCh/checkpoint executor crash is not evidence of a token limit.
    if (
        inferred_upper_bound >= _MIN_INFERRED_NATIVE_LIMIT
        and _is_native_limit_failure(text)
    ):
        state = native_limit_registry.put(
            key,
            int(inferred_upper_bound),
            source="inferred_failure",
            only_lower=True,
        )
        if state is not None:
            logger.warning(
                "Antigravity ACP inferred native-session upper bound %d for model %s; "
                "future sessions will rotate before this point.",
                state.value,
                key,
            )


def _rotation_threshold(model: str | None = None) -> int:
    fraction = _NATIVE_TOKEN_ROTATION_FRACTION
    raw = os.environ.get("HERMES_ANTIGRAVITY_ACP_ROTATION_FRACTION", "").strip()
    try:
        candidate = float(raw) if raw else fraction
    except ValueError:
        candidate = fraction
    fraction = min(max(candidate, 0.5), 0.99)
    return int(_native_token_limit(model) * fraction)


def _resolve_acp_working_directory(explicit_cwd: str | None) -> str:
    """Use Hermes' scoped workdir before the process-wide launch directory.

    A gateway may be launched from /ws/hermes-agent while a delegated reviewer is
    scoped to /ws/projects/<repo>.  The native ACP session must use that same
    workdir for file permissions and relative operations.

    The former ``HERMES_ANTIGRAVITY_ACP_WORKSPACE`` operator pin belonged to the
    removed trusted-coding auto-approval and is no longer read; the session cwd
    is always the Hermes-scoped working directory.
    """
    if explicit_cwd:
        return str(Path(explicit_cwd).expanduser().resolve())
    runtime_cwd = resolve_agent_cwd()
    if runtime_cwd is None:
        return str(Path(os.getcwd()).resolve())
    return str(runtime_cwd.resolve())


class _AsyncCompatibleCompletion:
    """A completion that is awaitable in async code and attribute-compatible in sync code."""

    def __init__(self, call: Callable[[], Any], *, stream: bool) -> None:
        self._call = call
        self._stream = stream
        self._lock = threading.Lock()
        self._resolved = False
        self._result: Any = None
        self._error: BaseException | None = None

    def _resolve(self) -> Any:
        with self._lock:
            if not self._resolved:
                try:
                    self._result = self._call()
                except BaseException as exc:
                    self._error = exc
                self._resolved = True
            if self._error is not None:
                raise self._error
            return self._result

    async def _await_result(self) -> Any:
        result = await asyncio.to_thread(self._resolve)
        if self._stream and isinstance(result, list):
            async def iterate_chunks():
                for chunk in result:
                    yield chunk
            return iterate_chunks()
        return result

    def __await__(self):
        return self._await_result().__await__()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resolve(), name)

    def __iter__(self):
        return iter(self._resolve())

    def __getitem__(self, key):
        return self._resolve()[key]

    def __len__(self) -> int:
        return len(self._resolve())

    def __bool__(self) -> bool:
        return bool(self._resolve())

    def __repr__(self) -> str:
        if self._resolved and self._error is None:
            return repr(self._result)
        return "<Antigravity ACP completion pending>"


class _DualModeCompletionCreate:
    """Keep sync calls immediate off-loop; return an awaitable surface on the Gateway loop."""

    def __init__(self, client: "AntigravityACPClient") -> None:
        self._client = client

    def __call__(self, **kwargs: Any) -> Any:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return self._client._create_chat_completion(**kwargs)
        return _AsyncCompatibleCompletion(
            lambda: self._client._create_chat_completion(**kwargs),
            stream=bool(kwargs.get("stream", False)),
        )


# Explicit, opt-in postprocessing policy (historical reference).  The default "agent"
# preserves every Hermes-agent safeguard, affinity continuation and
# post-response guard byte-for-byte for all existing callers.  "llm_backend"
# opts one client instance into pure ACP transport for OpenAI-compatible
# inference (for example a local Honcho bridge): the agent-interactive-only
# post-response guards (auditable review-evidence gate, scratch-artifact-claim
# remediation, duplicate no-progress tool-action checking) are skipped and
# cross-request native session resume is disabled so every request runs a
# fresh native session.  Malformed tool-call fail-closed safety, same-request
# correction, permission handling, structured-output claims checks and every
# other protocol behavior stay identical in both modes.  The policy is
# per-client-instance state only; no global default changes and no shared
# mutable policy is ever monkeypatched.
POSTPROCESSING_POLICY_AGENT = "agent"
POSTPROCESSING_POLICY_LLM_BACKEND = "llm_backend"
POSTPROCESSING_POLICIES = (POSTPROCESSING_POLICY_AGENT, POSTPROCESSING_POLICY_LLM_BACKEND)


# --- Warm process pool ---------------------------------------------------
# The ACP protocol's intended topology is a persistent server: one
# ``initialize`` handshake followed by many ``session/new`` round-trips on
# the same stdio connection (verified against the official 1.4.4 server:
# three distinct sessionIds on one process, 0.55-1.48s each).  The
# historical default spawned one short-lived child per session, paying a
# full cold start of the official binary inside every TTFT — seconds on
# warm Linux, 10s+ on a cold Windows ARM64 laptop.  A finished session's
# process is parked here and reused by the next session with the same
# launch identity until an idle TTL expires.  Parked processes are outside
# ``_active_processes`` so ``close()`` never kills them; ``atexit``, the
# idle TTL and the per-key pool cap bound their lifetime instead.
_WARM_IDLE_TTL_SECONDS = float(
    os.environ.get("HERMES_ANTIGRAVITY_ACP_WARM_TTL_SECONDS", "120")
)
_WARM_POOL_MAX_PER_KEY = 4
_warm_pool_lock = threading.Lock()
# key: (command, args tuple, cwd, affinity key) -> list of parked entries.
# entry: {proc, inbox, stderr_tail, stderr_reader, next_id, idle_since, key}
_warm_pool: dict[tuple[str, tuple[str, ...], str, str], list[dict[str, Any]]] = {}
_warm_pool_atexit_armed = False


def _terminate_parked(proc: subprocess.Popen[str]) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        with contextlib.suppress(Exception):
            proc.kill()


def _shutdown_warm_pool() -> None:
    with _warm_pool_lock:
        pools = list(_warm_pool.values())
        _warm_pool.clear()
    for entries in pools:
        for entry in entries:
            _terminate_parked(entry["proc"])


def _drain_parked_inbox(inbox: queue.Queue) -> None:
    """Discard late lines from the previous session on this connection.

    A parked server may still emit trailing notifications/responses after a
    session ends; they must never reach the next session's request loop.
    Drain until the pipe is quiet for 200ms (bounded to 1s total).
    """
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            inbox.get(timeout=0.2)
        except queue.Empty:
            return


class AntigravityACPClient:
    """OpenAI-client-compatible facade backed by Google's official ACP process.

    Postprocessing policy (historical reference): ``postprocessing_policy="agent"`` is
    the default and keeps the existing Antigravity ACP behavior and responses
    exactly unchanged — same prompt formatting, model selection, low-thinking
    configuration, session fingerprinting, guard execution, response
    text/reasoning/tool_calls, streaming, error semantics and MUX handling.
    Callers that do not pass the parameter notice nothing.

    Pass ``postprocessing_policy="llm_backend"`` explicitly to opt a single
    client instance into pure-LLM transport: the ACP handshake, model
    selection, thinking-level configuration and the caller-visible response
    schema stay identical, while Hermes-agent-only post-response enforcement
    (``_requires_auditable_read_evidence`` review rejection, scratch-artifact
    claim remediation, duplicate no-progress tool-action checking) is skipped
    and no native session is resumed across requests, so repeated identical
    backend requests never reuse or contaminate a prior native session.
    Same-request malformed tool-call correction, fail-closed malformed-JSON
    safety, permission-denial handling and tool-execution security gates
    remain active in every mode.
    """

    HERMES_SKIP_TRANSPORT_WRAP = True
    # The create surface itself is dual-mode: sync outside a loop, awaitable inside.
    # Hermes must not rebuild it as an AsyncOpenAI HTTP client.
    HERMES_SKIP_ASYNC_WRAP = True

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        default_headers: dict[str, str] | None = None,
        acp_command: str | None = None,
        acp_args: list[str] | None = None,
        acp_cwd: str | None = None,
        command: str | None = None,
        args: list[str] | None = None,
        rate_limit_retries: int = 2,
        postprocessing_policy: str = POSTPROCESSING_POLICY_AGENT,
        **_: Any,
    ) -> None:
        self.api_key = api_key or "antigravity-acp"
        self.base_url = base_url or ACP_MARKER_BASE_URL
        self._default_headers = dict(default_headers or {})
        self._acp_command = acp_command or command or "antigravity-acp-official"
        selected_args = acp_args if acp_args is not None else args
        self._acp_args = list(selected_args) if selected_args is not None else []
        self._acp_cwd = _resolve_acp_working_directory(acp_cwd)
        self._rate_limit_retries = max(0, min(int(rate_limit_retries), 8))
        # Fail closed on a misspelled policy name: silently falling back to a
        # different postprocessing set would change security-relevant behavior.
        if (
            not isinstance(postprocessing_policy, str)
            or postprocessing_policy not in POSTPROCESSING_POLICIES
        ):
            raise ValueError(
                "postprocessing_policy must be one of "
                f"{list(POSTPROCESSING_POLICIES)!r}; got {postprocessing_policy!r}. "
                "'agent' is the unchanged default; 'llm_backend' is the explicit "
                "opt-in for pure-LLM transport."
            )
        self.postprocessing_policy = postprocessing_policy
        self._llm_backend_postprocessing = (
            postprocessing_policy == POSTPROCESSING_POLICY_LLM_BACKEND
        )
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=_DualModeCompletionCreate(self))
        )
        self.is_closed = False
        self._active_processes: set[subprocess.Popen[str]] = set()
        self._active_process_lock = threading.Lock()

    @staticmethod
    def _terminate_process(proc: subprocess.Popen[str]) -> None:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            with contextlib.suppress(Exception):
                proc.kill()

    def _release_process(self, proc: subprocess.Popen[str]) -> None:
        with self._active_process_lock:
            self._active_processes.discard(proc)
        # A poisoned or failed child is terminated here; a healthy session's
        # child is parked for reuse by ``_session``'s warm-pool release path
        # instead. The facade itself must remain open so Hermes can reuse its
        # durable ACP continuation state.
        self._terminate_process(proc)

    def _warm_acquire(
        self, affinity_key: str, resume_session_id: str
    ) -> dict[str, Any] | None:
        """Pop a live parked process with this launch identity, if any.

        A resume request is never served by a parked process: the resume
        session id is pinned through the spawn environment
        (``ACP_MUX_SESSION_ID``) and a parked child was spawned without it.
        """
        if resume_session_id:
            return None
        key = (self._acp_command, tuple(self._acp_args), self._acp_cwd, affinity_key)
        now = time.monotonic()
        chosen: dict[str, Any] | None = None
        victims: list[dict[str, Any]] = []
        current_pin: str | None = None
        with _warm_pool_lock:
            kept: list[dict[str, Any]] = []
            for entry in _warm_pool.get(key, []):
                dead = entry["proc"].poll() is not None
                expired = now - entry["idle_since"] > _WARM_IDLE_TTL_SECONDS
                if dead or expired:
                    victims.append(entry)
                    continue
                if chosen is None:
                    if current_pin is None:
                        current_pin = _read_par_pin() or ""
                    if str(entry.get("par_pin") or "") == current_pin:
                        chosen = entry
                        continue
                kept.append(entry)
            if kept:
                _warm_pool[key] = kept
            else:
                _warm_pool.pop(key, None)
        for victim in victims:
            _terminate_parked(victim["proc"])
        if chosen is None:
            return None
        with self._active_process_lock:
            self._active_processes.add(chosen["proc"])
            self.is_closed = False
        _drain_parked_inbox(chosen["inbox"])
        return chosen

    def _warm_park(self, entry: dict[str, Any]) -> None:
        global _warm_pool_atexit_armed
        if entry["proc"].poll() is not None:
            # The child died between the last request and release; never
            # park a corpse.
            self._release_process(entry["proc"])
            return
        entry["idle_since"] = time.monotonic()
        with self._active_process_lock:
            self._active_processes.discard(entry["proc"])
        victims: list[dict[str, Any]] = []
        with _warm_pool_lock:
            bucket: list[dict[str, Any]] = []
            for parked in _warm_pool.get(entry["key"], []):
                if parked["proc"].poll() is None:
                    bucket.append(parked)
                else:
                    victims.append(parked)
            bucket.append(entry)
            while len(bucket) > _WARM_POOL_MAX_PER_KEY:
                victims.append(bucket.pop(0))
            _warm_pool[entry["key"]] = bucket
            if not _warm_pool_atexit_armed:
                atexit.register(_shutdown_warm_pool)
                _warm_pool_atexit_armed = True
        for victim in victims:
            _terminate_parked(victim["proc"])

    def close(self) -> None:
        with self._active_process_lock:
            procs, self._active_processes = tuple(self._active_processes), set()
        self.is_closed = True
        for proc in procs:
            self._terminate_process(proc)

    def _create_chat_completion(
        self,
        *,
        model: str | None = None,
        messages: list[dict[str, Any]] | None = None,
        timeout: float | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: Any = None,
        stream: bool = False,
        reasoning_effort: Any = None,
        **_: Any,
    ) -> Any:
        request_messages = messages or []
        requested_thinking_level, _ = _desired_thinking_level(reasoning_effort)
        active_tools = tools
        # llm_backend mode derives no conversation affinity: the
        # conversation_registry get/put below short-circuits on the empty key,
        # the mux child gets no ACP_MUX_AFFINITY pin, and every backend
        # request therefore runs a fresh native session.  Same-request
        # correction still resumes through session_result directly.
        affinity_key = (
            ""
            if self._llm_backend_postprocessing
            else _conversation_affinity(request_messages, self._acp_cwd)
        )
        context_fingerprint = _context_fingerprint(model, tools, tool_choice)
        prior_state = conversation_registry.get(affinity_key) if affinity_key else None
        denied_request = _denied_request_text(request_messages, prior_state)
        full_prompt_text = _format_messages_as_prompt(
            request_messages,
            model=model,
            tools=tools,
            tool_choice=tool_choice,
            unresolved_denied_request=denied_request,
        )

        resume_session_id = ""
        prompt_text = full_prompt_text
        prior_native_tokens = 0
        resume_native_token_hint = 0
        replay_reason = "bootstrap"
        delta_messages: list[dict[str, Any]] | None = None
        if prior_state is not None:
            delta = _continuation_delta(
                request_messages, prior_state, context_fingerprint
            )
            if delta is not None:
                delta_prompt = _format_continuation_delta(
                    delta,
                    active_request=_active_user_text(request_messages),
                    unresolved_denied_request=denied_request,
                )
                delta_tokens = _estimate_tokens(delta_prompt)
                projected = (
                    prior_state.native_tokens
                    + delta_tokens
                    + _estimate_tokens(full_prompt_text)
                    // 20  # slack for response growth
                )
                if projected >= _rotation_threshold(model):
                    replay_reason = "rotation"
                    logger.info(
                        "Antigravity ACP session %s projected at ~%d tokens "
                        "(limit %d); rotating to a fresh session with one full replay.",
                        prior_state.session_id[:12],
                        projected,
                        _native_token_limit(model),
                    )
                else:
                    replay_reason = "continuation_delta"
                    resume_session_id = prior_state.session_id
                    delta_messages = delta
                    resume_native_token_hint = projected
                    prior_native_tokens = prior_state.native_tokens + delta_tokens
                    prompt_text = delta_prompt
            else:
                replay_reason = "frontier_mismatch"
                logger.info(
                    "Antigravity ACP continuation frontier changed; using full replay."
                )

        has_denied_request_context = bool(denied_request)
        intent_owner = (
            "prior_denied_request_followup"
            if has_denied_request_context
            else "latest_user_request"
        )
        tool_outcome = (
            "permission_denied_not_executed"
            if has_denied_request_context
            else "no_prior_denial_observed"
        )
        # Video rides as ACP resource_link blocks appended to the active turn's
        # media blocks. They are recomputed deterministically on every replay
        # (same note text and same cache file -> same blocks) and are never
        # part of request_messages, so message fingerprints, continuation
        # accounting, and checkpoint state stay untouched.
        video_source = (
            delta_messages
            if resume_session_id and delta_messages is not None
            else request_messages
        )
        temp_video_files: list[Path] = []
        try:
            video_blocks = tuple(
                _video_blocks_for_messages(video_source, temp_files=temp_video_files)
            )
            replay_image_blocks = tuple(
                _image_blocks_for_messages(request_messages, active_turn_only=True)
            ) + video_blocks
            image_blocks = (
                tuple(_image_blocks_for_messages(delta_messages)) + video_blocks
                if resume_session_id and delta_messages is not None
                else replay_image_blocks
            )
    
            if resume_session_id:
                _log_continuation_diagnostics(
                    reason=replay_reason,
                    prompt_text=prompt_text,
                    model=model,
                    affinity_key=affinity_key,
                    intent_owner=intent_owner,
                    tool_outcome=tool_outcome,
                )
            else:
                _log_full_replay_diagnostics(
                    reason=replay_reason,
                    prompt_text=full_prompt_text,
                    model=model,
                    affinity_key=affinity_key,
                    intent_owner=intent_owner,
                    tool_outcome=tool_outcome,
                )
    
            timeout_seconds = _effective_timeout(timeout)
            started = time.monotonic()
            session_result: dict[str, Any] = {}
            response_text, reasoning = self._run_prompt(
                prompt_text,
                timeout_seconds=timeout_seconds,
                model=model,
                affinity_key=affinity_key,
                resume_session_id=resume_session_id,
                full_prompt_text=full_prompt_text,
                session_result=session_result,
                native_token_hint=resume_native_token_hint,
                image_blocks=image_blocks,
                replay_image_blocks=replay_image_blocks,
                thinking_level=requested_thinking_level,
            )
            tool_calls: list[Any] = []
            cleaned_text = ""
            for malformed_attempt in range(_MAX_MALFORMED_TOOL_CALL_CORRECTIONS + 1):
                try:
                    tool_calls, cleaned_text = _extract_advertised_tool_calls(
                        response_text, active_tools
                    )
                    break
                except MalformedToolCallError as exc:
                    if exc.unrecoverable:
                        if exc.reason == "unadvertised_tool":
                            raise RuntimeError(str(exc)) from exc
                        raise RuntimeError(
                            "Antigravity ACP leaked malformed tool-result protocol data; "
                            "outcome is UNKNOWN, refusing to replay any action or expose the result."
                        ) from exc
                    if malformed_attempt >= _MAX_MALFORMED_TOOL_CALL_CORRECTIONS:
                        raise RuntimeError(
                            "Antigravity ACP emitted malformed Hermes tool-call JSON again after one correction; "
                            "refusing to expose or execute the invalid action."
                        ) from exc
                    remaining = timeout_seconds - (time.monotonic() - started)
                    if remaining <= 0:
                        raise TimeoutError(
                            "Timed out while correcting malformed Antigravity ACP tool-call JSON."
                        ) from exc
                    prior_session_id = str(session_result.get("session_id") or "").strip()
                    correction_full_prompt = (
                        f"{full_prompt_text}\n\nPrevious malformed model output (not executed):\n{response_text}"
                        f"\n\n{_MALFORMED_TOOL_CALL_CORRECTION}"
                    )
                    correction_result: dict[str, Any] = {}
                    logger.warning(
                        "Antigravity ACP emitted malformed tool-call JSON%s; requesting one in-session correction.",
                        f" for {exc.tool_name!r}" if exc.tool_name else "",
                    )
                    response_text, reasoning = self._run_prompt(
                        _MALFORMED_TOOL_CALL_CORRECTION,
                        timeout_seconds=remaining,
                        model=model,
                        affinity_key=affinity_key,
                        resume_session_id=prior_session_id,
                        full_prompt_text=correction_full_prompt,
                        session_result=correction_result,
                        image_blocks=(),
                        replay_image_blocks=replay_image_blocks,
                        thinking_level=requested_thinking_level,
                    )
                    session_result = correction_result
            if malformed_attempt and not tool_calls:
                raise RuntimeError(
                    "Antigravity ACP correction did not produce a valid Hermes tool call; "
                    "refusing to present an unverified task completion."
                )
    
            # Duplicate no-progress tool-action checking is an
            # agent-interactive guard; llm_backend mode skips it by keeping
            # the signature empty (the block below never engages).
            duplicate_signature = (
                None
                if self._llm_backend_postprocessing
                else _latest_unchanged_tool_signature(request_messages)
            )
            if duplicate_signature is not None and _repeats_latest_unchanged_call(
                request_messages, tool_calls
            ):
                blocked_name, _ = duplicate_signature
                correction_tools = _without_openai_tool(active_tools, blocked_name)
                correction_choice = tool_choice if correction_tools else None
                correction_base = _format_messages_as_prompt(
                    request_messages,
                    model=model,
                    tools=correction_tools,
                    tool_choice=correction_choice,
                )
                for correction_index in range(_MAX_DUPLICATE_NO_PROGRESS_CORRECTIONS):
                    remaining = timeout_seconds - (time.monotonic() - started)
                    if remaining <= 0:
                        break
                    corrected_prompt = (
                        f"{correction_base}\n\n{_DUPLICATE_NO_PROGRESS_CORRECTION} "
                        f"Blocked tool: {blocked_name}. Correction attempt {correction_index + 1}."
                    )
                    correction_result: dict[str, Any] = {}
                    response_text, reasoning = self._run_prompt(
                        corrected_prompt,
                        timeout_seconds=remaining,
                        model=model,
                        affinity_key=affinity_key,
                        resume_session_id="",
                        full_prompt_text=corrected_prompt,
                        session_result=correction_result,
                        image_blocks=replay_image_blocks,
                        replay_image_blocks=replay_image_blocks,
                        thinking_level=requested_thinking_level,
                    )
                    tool_calls, cleaned_text = _extract_advertised_tool_calls(
                        response_text, correction_tools
                    )
                    if not _repeats_latest_unchanged_call(request_messages, tool_calls):
                        active_tools = correction_tools
                        session_result = correction_result
                        context_fingerprint = _context_fingerprint(
                            model, correction_tools, correction_choice
                        )
                        break
                if _repeats_latest_unchanged_call(request_messages, tool_calls):
                    raise RuntimeError(
                        f"Antigravity ACP repeated unchanged no-progress tool call {blocked_name!r} "
                        f"after {_MAX_DUPLICATE_NO_PROGRESS_CORRECTIONS} correction attempts; refusing to execute it again."
                    )
    
            # The auditable review-evidence gate models an interactive Hermes
            # code-review workflow; opted-in llm_backend requests skip it
            # entirely (no correction turns, no refusal).  Default agent mode
            # keeps it fully active, including the refusal RuntimeError below.
            if (
                not self._llm_backend_postprocessing
                and _requires_auditable_read_evidence(request_messages)
                and not _completed_hermes_read_evidence(request_messages)
                and not _native_completed_read_evidence(
                    dict(session_result.get("native_activity") or {})
                )
                and not _pending_read_tool_call(tool_calls)
            ):
                for _read_evidence_attempt in range(_MAX_READ_EVIDENCE_CORRECTIONS):
                    remaining = timeout_seconds - (time.monotonic() - started)
                    if remaining <= 0:
                        break
                    prior_session_id = str(session_result.get("session_id") or "").strip()
                    correction_full_prompt = (
                        f"{full_prompt_text}\n\nPrevious ungrounded review output (not accepted):\n{cleaned_text}"
                        f"\n\n{_READ_EVIDENCE_CORRECTION}"
                    )
                    correction_result: dict[str, Any] = {}
                    logger.warning(
                        "Antigravity ACP review response lacked required source-read evidence; "
                        "requesting one grounded inspection turn."
                    )
                    response_text, reasoning = self._run_prompt(
                        _READ_EVIDENCE_CORRECTION,
                        timeout_seconds=remaining,
                        model=model,
                        affinity_key=affinity_key,
                        resume_session_id=prior_session_id,
                        full_prompt_text=correction_full_prompt,
                        session_result=correction_result,
                        image_blocks=(),
                        replay_image_blocks=replay_image_blocks,
                        thinking_level=requested_thinking_level,
                    )
                    tool_calls, cleaned_text = _extract_advertised_tool_calls(
                        response_text, active_tools
                    )
                    session_result = correction_result
                    if _pending_read_tool_call(tool_calls) or _native_completed_read_evidence(
                        dict(session_result.get("native_activity") or {})
                    ):
                        break
                if (
                    not _pending_read_tool_call(tool_calls)
                    and not _native_completed_read_evidence(
                        dict(session_result.get("native_activity") or {})
                    )
                ):
                    raise RuntimeError(
                        "Antigravity ACP refused to provide the auditable source-read evidence required by "
                        "the active review request; refusing to surface an ungrounded review as completed."
                    )
    
            # Scratch-artifact-claim remediation re-verifies agent file
            # claims against the filesystem; it is an agent-interactive guard
            # skipped for opted-in llm_backend requests and byte-identical
            # for default agent mode.
            #
            # A turn that carried user-supplied image/video media is
            # descriptive: the answer reports what the model was shown (often
            # quoting an on-screen path such as a shell prompt), it does not
            # claim to have produced files.  Applying the guard there destroys
            # correct vision-analysis answers.
            turn_carried_media = bool(replay_image_blocks)
            if (
                not tool_calls
                and not turn_carried_media
                and not self._llm_backend_postprocessing
            ):
                missing_artifacts = _missing_claimed_scratch_artifacts(cleaned_text)
                for _artifact_attempt in range(_MAX_ARTIFACT_CLAIM_CORRECTIONS):
                    if not missing_artifacts:
                        break
                    remaining = timeout_seconds - (time.monotonic() - started)
                    if remaining <= 0:
                        break
                    missing_lines = "\n".join(f"- {path}" for path in missing_artifacts)
                    correction_prompt = (
                        f"{_ARTIFACT_CLAIM_CORRECTION}\n\n"
                        f"Fresh filesystem verification says these claimed paths are missing:\n{missing_lines}"
                    )
                    correction_full_prompt = (
                        f"{full_prompt_text}\n\nPrevious final answer (not accepted):\n{cleaned_text}"
                        f"\n\n{correction_prompt}"
                    )
                    prior_session_id = str(session_result.get("session_id") or "").strip()
                    correction_result: dict[str, Any] = {}
                    logger.warning(
                        "Antigravity ACP final answer claimed %d missing scratch artifact(s); "
                        "requesting one grounded correction.",
                        len(missing_artifacts),
                    )
                    response_text, reasoning = self._run_prompt(
                        correction_prompt,
                        timeout_seconds=remaining,
                        model=model,
                        affinity_key=affinity_key,
                        resume_session_id=prior_session_id,
                        full_prompt_text=correction_full_prompt,
                        session_result=correction_result,
                        image_blocks=(),
                        replay_image_blocks=replay_image_blocks,
                        thinking_level=requested_thinking_level,
                    )
                    tool_calls, cleaned_text = _extract_advertised_tool_calls(
                        response_text, active_tools
                    )
                    session_result = correction_result
                    if tool_calls:
                        missing_artifacts = ()
                        break
                    missing_artifacts = _missing_claimed_scratch_artifacts(cleaned_text)
                if missing_artifacts:
                    missing_text = ", ".join(str(path) for path in missing_artifacts)
                    raise RuntimeError(
                        "Antigravity ACP final answer still claims scratch artifacts that do not exist "
                        f"after grounded correction: {missing_text}"
                    )
    
            native_activity = dict(session_result.get("native_activity") or {})
            native_failures = any(
                str(item.get("status") or "").strip().lower() in {"failed", "error", "failure"}
                for item in native_activity.get("native_tool_calls") or []
                if isinstance(item, dict)
            )
            if (
                not tool_calls
                and _claims_completed_live_verification(cleaned_text)
                and (_latest_tool_result_failed(request_messages) or native_failures)
            ):
                raise RuntimeError(
                    "Antigravity ACP final answer claimed completed live verification "
                    "despite failed tool execution; refusing an unsupported PASS. "
                    "Retry the failed tool or report verification incomplete."
                )
    
            tool_bridge_activity = _tool_bridge_activity(
                active_tools, request_messages, tool_calls
            )
            logger.info(
                "Antigravity ACP Hermes tool bridge telemetry %s",
                json.dumps(tool_bridge_activity, sort_keys=True, separators=(",", ":")),
            )
    
            for overlay in policy_overlays:
                enforce = getattr(overlay, "enforce_filled_order_claim", None)
                if enforce is not None:
                    enforce(
                        cleaned_text,
                        request_messages,
                        has_tool_calls=bool(tool_calls),
                        render_content=_render_message_content,
                    )
    
            session_id = str(session_result.get("session_id") or "").strip()
            if affinity_key and session_id:
                resumed = bool(session_result.get("resumed"))
                if resumed:
                    native_tokens = prior_native_tokens + _estimate_tokens(prompt_text)
                else:
                    native_tokens = _estimate_tokens(full_prompt_text)
                native_tokens = min(
                    native_tokens + _estimate_tokens(cleaned_text),
                    _native_token_limit(model),
                )
                denied_request_fingerprint = ""
                if session_result.get("permission_denied"):
                    denied_request = next(
                        (
                            message
                            for message in reversed(request_messages)
                            if isinstance(message, dict)
                            and str(message.get("role") or "").strip().lower() == "user"
                        ),
                        None,
                    )
                    if denied_request is not None:
                        denied_request_fingerprint = _message_fingerprint(denied_request)
                state = ACPConversationState(
                    session_id=session_id,
                    context_fingerprint=context_fingerprint,
                    request_fingerprints=tuple(
                        _message_fingerprint(message)
                        for message in request_messages
                        if isinstance(message, dict)
                    ),
                    response_fingerprint=_response_fingerprint(cleaned_text, tool_calls),
                    updated_at=time.time(),
                    native_tokens=native_tokens,
                    denied_request_fingerprint=denied_request_fingerprint,
                    effective_model=str(session_result.get("effective_model") or ""),
                )
                conversation_registry.put(affinity_key, state)
    
            native_reasoning_details = _native_tool_reasoning_details(native_activity)
            message = SimpleNamespace(
                content=cleaned_text,
                tool_calls=tool_calls,
                # ACP-native tool activity is structured audit evidence, not model-authored
                # reasoning. Never splice shell commands/statuses into the thought channel.
                reasoning=reasoning or None,
                reasoning_content=reasoning or None,
                reasoning_details=native_reasoning_details or None,
            )
            completion = SimpleNamespace(
                antigravity_native_activity=native_activity,
                antigravity_tool_bridge=tool_bridge_activity,
                antigravity_usage_telemetry=_build_usage_telemetry(
                    model=session_result.get("effective_model") or model,
                    session_id=session_id,
                    turn_id_hash=session_result.get("turn_id_hash"),
                    context_occupancy=session_result.get("context_occupancy"),
                    turn_consumption=session_result.get("turn_consumption"),
                    server_consumption_semantics=str(
                        session_result.get("server_consumption_semantics")
                        or _USAGE_SEMANTICS_UNVERIFIED
                    ),
                ),
                choices=[
                    SimpleNamespace(
                        message=message,
                        finish_reason="tool_calls" if tool_calls else "stop",
                    )
                ],
                # Prefer the official prompt result's per-turn breakdown. If it
                # is absent or invalid, retain the v0.7.4 usage_update proxy;
                # the proxy does not provide a real input/output split.
                usage=session_result.get("turn_usage"),
                model=session_result.get("effective_model") or model or "antigravity-acp",
            )
            result = completion_to_stream_chunks(completion) if stream else completion
            return result
        finally:
            _cleanup_temp_video_files(temp_video_files)

    def _spawn(
        self,
        *,
        affinity_key: str = "",
        pin_affinity: bool = False,
        session_id: str = "",
    ) -> subprocess.Popen[str]:
        child_env = _build_subprocess_env()
        child_env.pop("ACP_MUX_SESSION_ID", None)
        if affinity_key:
            child_env["ACP_MUX_AFFINITY"] = affinity_key
        if session_id:
            child_env["ACP_MUX_SESSION_ID"] = session_id
        # The native session-store GC deletes bundles that no continuation
        # checkpoint protects; until the full native session lifetime contract
        # lands (issue #3 follow-up) it is opt-in only.  Ownership-record
        # cleanup inside the mux stays always-on and is metadata-only.
        child_env["ACP_MUX_SESSION_GC"] = (
            "1"
            if os.environ.get("HERMES_ANTIGRAVITY_ACP_NATIVE_GC", "").strip() == "1"
            else "0"
        )
        child_env["ACP_MUX_AFFINITY_PIN"] = "1" if pin_affinity else "0"
        child_env["ACP_MUX_AFFINITY_TTL_SECONDS"] = os.environ.get(
            "HERMES_ANTIGRAVITY_ACP_STATE_TTL_SECONDS", "86400"
        )
        child_env["ACP_MUX_AFFINITY_MAX_ENTRIES"] = os.environ.get(
            "HERMES_ANTIGRAVITY_ACP_STATE_MAX_ENTRIES", "512"
        )
        par_pin = _read_par_pin()
        if par_pin is not None:
            child_env["ACP_MUX_PAR"] = par_pin
        try:
            proc = subprocess.Popen(
                [self._acp_command] + self._acp_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                cwd=self._acp_cwd,
                env=child_env,
                creationflags=_windows_hide_flags(),
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Could not start Antigravity ACP command '{self._acp_command}'. "
                "Install the official ACP wrapper or configure the provider command."
            ) from exc
        if proc.stdin is None or proc.stdout is None:
            proc.kill()
            raise RuntimeError("Antigravity ACP process did not expose stdin/stdout pipes.")
        with self._active_process_lock:
            self._active_processes.add(proc)
            self.is_closed = False
        return proc

    @contextlib.contextmanager
    def _session(
        self,
        timeout_seconds: float,
        *,
        allow_file_requests: bool = True,
        affinity_key: str = "",
        resume_session_id: str = "",
        activity_stats_out: dict[str, Any] | None = None,
    ) -> Iterator[tuple[dict[str, Any], Callable[..., Any], dict[str, Any]]]:
        resume_session_id = str(resume_session_id or "").strip()
        entry = self._warm_acquire(affinity_key, resume_session_id)
        fresh = entry is None
        if fresh:
            proc = self._spawn(
                affinity_key=affinity_key,
                pin_affinity=bool(resume_session_id),
                session_id=resume_session_id,
            )
            inbox = queue.Queue()
            stderr_tail = deque(maxlen=40)

            def decode(line: str) -> dict[str, Any]:
                try:
                    return json.loads(line)
                except Exception:
                    return {"raw": line.rstrip("\n")}

            def pump(stream: Any, sink: Callable[[str], Any]) -> None:
                for line in stream or ():
                    sink(line)

            threading.Thread(
                target=pump,
                args=(proc.stdout, lambda line: inbox.put(decode(line))),
                daemon=True,
            ).start()
            stderr_reader = threading.Thread(
                target=pump,
                args=(proc.stderr, lambda line: stderr_tail.append(line.rstrip("\n"))),
                daemon=True,
            )
            stderr_reader.start()
            entry = {
                "proc": proc,
                "inbox": inbox,
                "stderr_tail": stderr_tail,
                "stderr_reader": stderr_reader,
                "next_id": 1,
                "idle_since": 0.0,
                # The publisher pin is read at spawn time and baked into the
                # child's environment; reuse must not cross a pin change.
                "par_pin": _read_par_pin() or "",
                "key": (
                    self._acp_command,
                    tuple(self._acp_args),
                    self._acp_cwd,
                    affinity_key,
                ),
            }
        proc = entry["proc"]
        inbox = entry["inbox"]
        stderr_tail = entry["stderr_tail"]
        stderr_reader = entry["stderr_reader"]
        # JSON-RPC ids must stay unique for the lifetime of one stdio
        # connection, so the counter continues across parked sessions.
        id_state = {"last": entry["next_id"] - 1}
        request_ids = itertools.count(entry["next_id"])
        session_deadline = time.monotonic() + timeout_seconds
        activity_stats: dict[str, Any] = (
            activity_stats_out if activity_stats_out is not None else {}
        )
        activity_stats.clear()
        activity_stats.update(
            {
                "session_updates": 0,
                "step_updates": 0,
                "update_kinds": {},
                "native_tool_calls": [],
                "permission_denied": False,
                "_native_tool_call_index": {},
                _SERVER_CONSUMPTION_SEMANTICS_KEY: str(
                    getattr(proc, _USAGE_SEMANTICS_ATTR, _USAGE_SEMANTICS_UNVERIFIED)
                    or _USAGE_SEMANTICS_UNVERIFIED
                ),
            }
        )

        def request(
            method: str,
            params: dict[str, Any],
            *,
            text_parts: list[str] | None = None,
            reasoning_parts: list[str] | None = None,
        ) -> Any:
            assert proc.stdin is not None
            request_id = next(request_ids)
            id_state["last"] = request_id
            if method == "session/prompt":
                session_id = str(params.get("sessionId") or "").strip()
                activity_stats["session_id_hash"] = _opaque_permission_id(
                    session_id, "session"
                )
                activity_stats["turn_id_hash"] = _opaque_permission_id(
                    f"{session_id}\0{uuid.uuid4().hex}", "turn"
                )
                # Consumption-window correlation (issue #6 AC4-2): from this
                # send until the prompt response, usage_update frames are
                # per-model-call deltas; frames outside it are re-reports or
                # placeholders (see _capture_usage_delta).
                activity_stats[_PROMPT_TURN_ACTIVE_KEY] = True
            proc.stdin.write(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": method,
                        "params": params,
                    }
                )
                + "\n"
            )
            proc.stdin.flush()
            while time.monotonic() < session_deadline and proc.poll() is None:
                try:
                    message = inbox.get(timeout=0.1)
                except queue.Empty:
                    continue
                if self._handle_server_message(
                    message,
                    process=proc,
                    cwd=self._acp_cwd,
                    text_parts=text_parts,
                    reasoning_parts=reasoning_parts,
                    allow_file_requests=allow_file_requests,
                    activity_stats=activity_stats,
                ) or message.get("id") != request_id:
                    continue
                if "error" in message:
                    error = message.get("error")
                    error = error if isinstance(error, dict) else {}
                    details: list[str] = []
                    code = error.get("code")
                    if isinstance(code, int) and not isinstance(code, bool):
                        details.append(f"code={code}")
                    if detail := _redact_acp_error_detail(error.get("message")):
                        details.append(detail)
                    data = error.get("data")
                    if isinstance(data, dict):
                        if detail := _redact_acp_error_detail(data.get("message")):
                            details.append(f"data.message={detail}")
                    diagnostic = f"Antigravity ACP {method} failed"
                    if details:
                        diagnostic += ": " + "; ".join(details)
                    raise RuntimeError(diagnostic)
                return message.get("result")
            if proc.poll() is not None:
                # The child is gone; give the pump a bounded moment to drain
                # the pipe so the captured-tail summary is deterministic.
                stderr_reader.join(timeout=2.0)
                if "\n".join(stderr_tail).strip():
                    # historical reference: raw child stderr is untrusted and is never
                    # interpolated into the exception.  Only the bounded,
                    # non-reversible summary crosses public surfaces.  The
                    # retry/failover class is derived from the still-captured
                    # stderr HERE (historical reference rework) and travels separately on
                    # the exception's structured attribute, never in its text.
                    raise _AcpEarlyExitError(
                        "Antigravity ACP process exited early (exit code "
                        f"{proc.poll()}); {_acp_stderr_diagnostic(list(stderr_tail))}. "
                        "Inspect the configured ACP command's own output manually "
                        "if more detail is required.",
                        acp_retry_class=_acp_stderr_retry_class(list(stderr_tail)),
                    )
            raise TimeoutError(
                f"Timed out waiting for Antigravity ACP response to {method}."
            )

        poisoned = False
        try:
            if fresh:
                initialize_result = request("initialize", _INITIALIZE_PARAMS)
                # Pin the server's consumption semantics for the lifetime of
                # this stdio connection (issue #6 AC4-3); warm reuse of the
                # same process keeps the pinned identity.
                setattr(
                    proc,
                    _USAGE_SEMANTICS_ATTR,
                    _usage_semantics_from_initialize(initialize_result),
                )
                # The activity_stats seed above ran before this handshake on a
                # fresh connection; refresh it with the pinned identity.
                activity_stats[_SERVER_CONSUMPTION_SEMANTICS_KEY] = str(
                    getattr(proc, _USAGE_SEMANTICS_ATTR)
                    or _USAGE_SEMANTICS_UNVERIFIED
                )
            # Hermes model-provider mode always disables the native
            # run_command built-in at launch; shell work belongs to Hermes'
            # approval-gated terminal tool through the <tool_call> bridge.
            session_meta = {"agy": {"disabledTools": ["run_command"]}}
            if resume_session_id:
                resume_params: dict[str, Any] = {
                    "sessionId": resume_session_id,
                    "cwd": self._acp_cwd,
                    "mcpServers": [],
                }
                if session_meta is not None:
                    resume_params["_meta"] = session_meta
                session = request("session/resume", resume_params) or {}
                session = dict(session)
                session.setdefault("sessionId", resume_session_id)
                session["_hermes_resumed"] = True
            else:
                new_params: dict[str, Any] = {
                    "cwd": self._acp_cwd,
                    "mcpServers": [],
                }
                if session_meta is not None:
                    new_params["_meta"] = session_meta
                session = request("session/new", new_params) or {}
            if not str(session.get("sessionId") or "").strip():
                raise RuntimeError("Antigravity ACP did not return a sessionId.")
            yield session, request, activity_stats
        except (TimeoutError, _AcpEarlyExitError, BrokenPipeError, OSError):
            # Transport-level failure: the connection's state is unknown and
            # the child must never be parked for the next session.
            poisoned = True
            raise
        except Exception:
            # Protocol-level failure (e.g. a JSON-RPC quota/resource_exhausted
            # error from session/prompt): the native session may be poisoned.
            # Failover safety (S4) requires retrying on a fresh process with a
            # fresh native session, so a child whose session raised is never
            # parked for reuse.
            poisoned = True
            raise
        finally:
            entry["next_id"] = id_state["last"] + 1
            if poisoned or proc.poll() is not None:
                self._release_process(proc)
            else:
                self._warm_park(entry)

    def list_models(self, *, timeout_seconds: float = 15.0) -> list[str]:
        try:
            with self._session(
                timeout_seconds, allow_file_requests=False
            ) as (session, _, _activity_stats):
                return _session_model_ids(session)
        finally:
            self.close()

    def session_model_surface(
        self, *, timeout_seconds: float = 15.0
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """``(config_option_entries, legacy_available_model_entries)`` from one live session.

        The official 1.4.x server exposes two model surfaces with different
        contents (a single-category ``configOptions`` picker and the richer
        legacy ``models.availableModels`` rows). Both are server-authored and
        account-scoped; callers must never substitute a hardcoded list for
        either. ``_AcpEarlyExitError``/auth-boundary exceptions propagate.
        """
        try:
            with self._session(
                timeout_seconds, allow_file_requests=False
            ) as (session, _, _activity_stats):
                config_entries = [
                    entry
                    for option in _model_config_options(session)
                    for entry in (option.get("options") or [])
                    if isinstance(entry, dict)
                ]
                legacy_entries = [
                    entry
                    for entry in ((session.get("models") or {}).get("availableModels") or [])
                    if isinstance(entry, dict)
                ]
                return config_entries, legacy_entries
        finally:
            self.close()

    def _run_prompt(
        self,
        prompt_text: str,
        *,
        timeout_seconds: float,
        model: str | None = None,
        affinity_key: str = "",
        resume_session_id: str = "",
        full_prompt_text: str | None = None,
        session_result: dict[str, Any] | None = None,
        native_token_hint: int = 0,
        image_blocks: tuple[dict[str, str], ...] = (),
        replay_image_blocks: tuple[dict[str, str], ...] = (),
        thinking_level: str | None = None,
    ) -> tuple[str, str]:
        """Run a prompt with native resume, resume-miss replay, and bounded failover."""
        deadline = time.monotonic() + timeout_seconds
        replay_text = full_prompt_text or prompt_text
        next_text = prompt_text
        next_resume = str(resume_session_id or "").strip()
        next_image_blocks = image_blocks
        resume_miss_replayed = False
        failovers = 0
        inband_digest_replays = 0

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out before Antigravity ACP prompt could complete.")
            attempt_activity: dict[str, Any] = {}
            try:
                return self._run_prompt_once(
                    next_text,
                    timeout_seconds=remaining,
                    model=model,
                    thinking_level=thinking_level,
                    affinity_key=affinity_key,
                    resume_session_id=next_resume,
                    session_result=session_result,
                    activity_out=attempt_activity,
                    image_blocks=next_image_blocks,
                )
            except RuntimeError as exc:
                # A checkpoint error after the prompt has started may follow partial
                # native shell/git mutations. A blind full replay is unsafe even
                # if the official server no longer knows its checkpoint channel.
                checkpoint_error = "donech for checkpoint" in str(exc).lower()
                prompt_started = (session_result or {}).get("phase") == "session/prompt"
                if checkpoint_error and next_resume and affinity_key:
                    previous = conversation_registry.get(affinity_key)
                    if previous is not None and previous.session_id == next_resume:
                        conversation_registry.delete(affinity_key)
                if checkpoint_error and prompt_started:
                    native_events = (
                        (session_result or {}).get("native_activity") or {}
                    ).get("native_tool_calls") or []
                    raise RuntimeError(
                        "Antigravity ACP checkpoint failed after session/prompt began; "
                        "execution outcome is UNKNOWN and automatic replay was refused "
                        "to prevent duplicate side effects. Reconcile external state "
                        f"before explicitly retrying (observed native events: {len(native_events)})."
                    ) from exc
                _learn_native_limit(
                    str(exc),
                    model,
                    inferred_upper_bound=native_token_hint if next_resume else 0,
                )
                if next_resume and not resume_miss_replayed and _resume_session_missing(exc):
                    logger.info(
                        "Antigravity ACP session %s is unavailable; rebuilding with one full replay.",
                        next_resume[:12],
                    )
                    _log_full_replay_diagnostics(
                        reason="resume_miss", prompt_text=replay_text, model=model, affinity_key=affinity_key
                    )
                    next_text = replay_text
                    next_resume = ""
                    next_image_blocks = replay_image_blocks
                    resume_miss_replayed = True
                    continue
                if failovers >= self._rate_limit_retries or not _is_failover_error(exc):
                    raise
                if attempt_activity.get("native_tool_calls"):
                    # The failed attempt already executed ACP-native tools on
                    # the provider side. A full replay would duplicate those
                    # side effects, so the bounded failover is refused here
                    # even though the error itself is retryable.
                    logger.warning(
                        "Antigravity ACP failover refused: the failed attempt executed %d "
                        "native tool call(s); replaying could duplicate their effects.",
                        len(attempt_activity["native_tool_calls"]),
                    )
                    raise
                if inband_digest_replays >= _INBAND_DIGEST_REPLAY_LIMIT:
                    # Reviewer P1 (mixed-sequence bypass): once an in-band
                    # digest failure has spent the single allowed replay, a
                    # later failure of a different class (structured JSON-RPC
                    # 429, auth) must not re-arm the transport budget.
                    # Sequences like in-band quota -> 429 -> 429 would
                    # otherwise keep full-replaying past the S4 contract.
                    raise
                if _is_inband_digest_error(exc):
                    # Reviewer P1: in-band quota/connection digests must not
                    # silently consume the transport retry budget (default 2,
                    # max 8). The provider is already signalling exhaustion,
                    # so one failover replay is the whole allowance; the
                    # absence of tool_call events is never treated as proof
                    # of no side effects, which is why this path never
                    # retries beyond a single lane switch.
                    inband_digest_replays += 1
                failovers += 1
                logger.warning(
                    "Antigravity ACP failover attempt %d/%d; starting a fresh ACP session.",
                    failovers,
                    self._rate_limit_retries,
                )
                next_text = replay_text
                next_resume = ""
                next_image_blocks = replay_image_blocks

    def _run_prompt_once(
        self,
        prompt_text: str,
        *,
        timeout_seconds: float,
        model: str | None = None,
        affinity_key: str = "",
        resume_session_id: str = "",
        session_result: dict[str, Any] | None = None,
        activity_out: dict[str, Any] | None = None,
        image_blocks: tuple[dict[str, str], ...] = (),
        thinking_level: str | None = None,
    ) -> tuple[str, str]:
        requested_model = str(model or "").strip()
        with self._session(
            timeout_seconds,
            affinity_key=affinity_key,
            resume_session_id=resume_session_id,
            activity_stats_out=activity_out,
        ) as (session, request, activity_stats):
            session_id = str(session.get("sessionId") or "").strip()
            resumed = bool(session.get("_hermes_resumed"))
            persisted_model = ""
            if resumed and affinity_key:
                prior_state = conversation_registry.get(affinity_key)
                if prior_state is not None and prior_state.session_id == session_id:
                    persisted_model = prior_state.effective_model
            current_model = _session_current_model(session)
            if resumed and not (current_model or persisted_model):
                raise RuntimeError(
                    "Antigravity ACP cannot determine the active model for this resumed session; "
                    "the server did not report it and no effective model is persisted for this "
                    "exact sessionId, so refusing to claim a requested model."
                )
            effective_model = (
                current_model or persisted_model or requested_model or "antigravity-acp"
            )
            model_selection_outcome = (
                "resumed_session_model_reported"
                if resumed and current_model
                else "resumed_session_model_persisted"
                if resumed and persisted_model
                else "resumed_session_model_unreported"
                if resumed
                else "session_default_reported"
                if current_model
                else "session_default_unreported"
            )
            if requested_model and requested_model != "antigravity-acp":
                if resumed:
                    offered_models = _session_model_ids(session)
                    if offered_models and requested_model not in offered_models:
                        if not (current_model or persisted_model):
                            raise RuntimeError(
                                f"Antigravity ACP does not offer requested model {requested_model!r} "
                                "and does not report the active session model; refusing to claim "
                                "the requested model."
                            )
                        effective_model = current_model or persisted_model
                        model_selection_outcome = "requested_model_unoffered"
                        logger.warning(
                            "Antigravity ACP does not offer model %r; using the session default %r "
                            "(effective model).",
                            requested_model,
                            effective_model,
                        )
                    elif current_model:
                        effective_model = current_model
                else:
                    selection = _model_selection_request(session, requested_model)
                    if selection is None:
                        model_selection_outcome = "requested_model_unoffered"
                        if not current_model:
                            raise RuntimeError(
                                f"Antigravity ACP does not offer requested model {requested_model!r} "
                                "and does not report the active session model; refusing to claim "
                                "the requested model."
                            )
                        effective_model = current_model
                        logger.warning(
                            "Antigravity ACP does not offer model %r; using the session default %r "
                            "(effective model).",
                            requested_model,
                            effective_model,
                        )
                    else:
                        try:
                            request(*selection)
                        except RuntimeError as exc:
                            model_selection_outcome = "selection_failed_session_default"
                            if not current_model:
                                raise RuntimeError(
                                    f"Antigravity ACP model selection for {requested_model!r} failed "
                                    "without a reported active session model; refusing to claim the "
                                    f"requested model: {exc}"
                                ) from exc
                            effective_model = current_model
                            logger.warning(
                                "Antigravity ACP model selection for %r failed; continuing with "
                                "session default %r (effective model): %s",
                                requested_model,
                                effective_model,
                                exc,
                            )
                        else:
                            effective_model = requested_model
                            model_selection_outcome = "requested_option_accepted"
            logger.info(
                "ACP model selection: conversation=%s requested_model=%s "
                "effective_model=%s outcome=%s",
                (affinity_key or "")[:16] or "none",
                requested_model or "?",
                effective_model or "unknown",
                model_selection_outcome,
            )
            # Thinking level is set only on fresh sessions: a resumed native
            # session already carries the level chosen when it was created,
            # and mid-session changes are never attempted. The desired level
            # must be one the server authored for this session; an unoffered
            # level is reported and the server session default stands.
            if thinking_level and not resumed:
                thinking_option = _thinking_level_config_option(session)
                if thinking_option is not None:
                    selection = _thinking_level_selection(session, thinking_level)
                    if selection is None:
                        logger.warning(
                            "Antigravity ACP does not offer thinking level %r (source %s); "
                            "using the session default %r.",
                            thinking_level,
                            "env" if _env_override_present() else "request",
                            thinking_option.get("currentValue") or "unreported",
                        )
                    else:
                        try:
                            request(*selection)
                        except RuntimeError as exc:
                            logger.warning(
                                "Antigravity ACP thinking-level selection for %r failed; "
                                "continuing with the session default: %s",
                                thinking_level,
                                exc,
                            )
                        else:
                            logger.info(
                                "ACP thinking level: conversation=%s level=%s outcome=accepted",
                                (affinity_key or "")[:16] or "none",
                                thinking_level,
                            )
            text_parts: list[str] = []
            reasoning_parts: list[str] = []
            activity_stats["native_session_id"] = session_id
            activity_stats["model"] = str(
                effective_model or requested_model or model or "antigravity-acp"
            )
            if session_result is not None:
                session_result.update(
                    phase="session/prompt",
                    session_id=session_id,
                    resumed=resumed,
                    requested_model=requested_model or None,
                    effective_model=effective_model,
                )
            # Revalidate native video file identity as late as possible. A
            # resource_link is a pathname, so this only narrows (does not
            # eliminate) the server-open TOCTOU window.
            wire_media_blocks = _wire_media_blocks(image_blocks)
            try:
                prompt_result = request(
                    "session/prompt",
                    {
                        "sessionId": session_id,
                        # Media blocks precede text so the model reads them as
                        # context for the question that follows.
                        "prompt": [
                            *wire_media_blocks,
                            {"type": "text", "text": prompt_text},
                        ],
                    },
                    text_parts=text_parts,
                    reasoning_parts=reasoning_parts,
                )
            finally:
                # The consumption window closes with the prompt response: any
                # later usage_update frame (model-switch re-report, new-session
                # placeholder, or a frame the pump only now drains) is outside
                # the window and is never accumulated as consumption.
                activity_stats[_PROMPT_TURN_ACTIVE_KEY] = False
                # Preserve partial native-tool provenance even when ACP returns an
                # executor error instead of a completed prompt response.
                if session_result is not None:
                    session_result.update(
                        session_id=session_id,
                        resumed=resumed,
                        turn_id_hash=activity_stats.get("turn_id_hash"),
                        native_activity={
                            "session_id_hash": activity_stats.get("session_id_hash"),
                            "turn_id_hash": activity_stats.get("turn_id_hash"),
                            "session_updates": int(activity_stats.get("session_updates") or 0),
                            "step_updates": int(activity_stats.get("step_updates") or 0),
                            "update_kinds": dict(activity_stats.get("update_kinds") or {}),
                            "permission_denied": bool(activity_stats.get("permission_denied")),
                            "native_tool_calls": [
                                dict(item)
                                for item in activity_stats.get("native_tool_calls") or []
                                if isinstance(item, dict)
                            ],
                        },
                        permission_denied=bool(activity_stats.get("permission_denied")),
                    )
            if activity_stats.get("session_updates"):
                logger.info(
                    "Antigravity ACP native activity: updates=%s step_updates=%s kinds=%s",
                    activity_stats.get("session_updates"),
                    activity_stats.get("step_updates"),
                    activity_stats.get("update_kinds"),
                )
            answer = "".join(text_parts)
            stop_reason = str((prompt_result or {}).get("stopReason") or "").strip().lower()
            # Non-end_turn stop reasons must never surface as a normal answer;
            # max_tokens stays a success because the server rotates context
            # internally and continues the same turn.
            if stop_reason in ("refusal", "cancelled"):
                raise RuntimeError(
                    f"Antigravity ACP turn ended with stopReason={stop_reason}; "
                    "partial output suppressed."
                )
            # Defense in depth: if the mux digest filter is bypassed, an
            # answer that is entirely a vendor failure digest is still an
            # error, never a model answer (contract doc D3).
            digest = _vendor_turn_digest(answer)
            if digest == "quota":
                raise RuntimeError(
                    "Antigravity provider quota failure (resource_exhausted): "
                    "vendor turn digest suppressed."
                )
            if digest == "connection-lost":
                raise RuntimeError(
                    "Antigravity provider connection-lost failure: turn aborted "
                    "after a failed reconnect; automatic replay is suppressed."
                )
            if session_result is not None:
                occupancy = activity_stats.get("context_occupancy")
                session_result["context_occupancy"] = (
                    dict(occupancy) if isinstance(occupancy, dict) else None
                )
                # Issue #6 AC4-1: the ONLY source for the generic OpenAI-shaped
                # usage is the server's own per-turn `usage` breakdown on the
                # prompt result.  When it is absent or invalid, usage stays
                # None (Core's designed usage-less path); the observed
                # per-call consumption frames are reported ONLY as explicitly
                # scoped provider telemetry below, never as measured
                # input/output.
                session_result["turn_usage"] = _turn_usage_from_prompt_result(
                    prompt_result
                )
                session_result["server_consumption_semantics"] = str(
                    activity_stats.get(_SERVER_CONSUMPTION_SEMANTICS_KEY)
                    or _USAGE_SEMANTICS_UNVERIFIED
                )
                # Observed per-call consumption stays in explicitly scoped
                # provider telemetry (issue #6 AC4-1): never generic-priced,
                # never presented as an input/output split.
                _turn_calls = int(activity_stats.get(_TURN_USAGE_CALLS_KEY) or 0)
                _turn_sum = activity_stats.get(_TURN_USAGE_SUM_KEY)
                session_result["turn_consumption"] = (
                    {
                        "source": _CONTEXT_OCCUPANCY_SOURCE,
                        "scope": _USAGE_DELTA_SCOPE,
                        "is_billing_usage": False,
                        "semantics": str(
                            activity_stats.get(_SERVER_CONSUMPTION_SEMANTICS_KEY)
                            or _USAGE_SEMANTICS_UNVERIFIED
                        ),
                        "model_calls_observed": _turn_calls,
                        "total_tokens": (
                            int(_turn_sum)
                            if _turn_calls
                            and _turn_sum is not None
                            and _nonnegative_json_number(_turn_sum)
                            else None
                        ),
                    }
                    if _turn_calls
                    else None
                )
            return answer, "".join(reasoning_parts)

    def _handle_server_message(
        self,
        msg: dict[str, Any],
        *,
        process: subprocess.Popen[str],
        cwd: str,
        text_parts: list[str] | None,
        reasoning_parts: list[str] | None,
        allow_file_requests: bool = True,
        activity_stats: dict[str, Any] | None = None,
    ) -> bool:
        method = msg.get("method")
        if not isinstance(method, str):
            return False
        if method == "session/update":
            update = (msg.get("params") or {}).get("update") or {}
            if activity_stats is not None:
                activity_stats["session_updates"] = int(activity_stats.get("session_updates") or 0) + 1
                update_kind = str(update.get("sessionUpdate") or "").strip()
                if not update_kind and isinstance(update.get("stepUpdate"), dict):
                    update_kind = "step_update"
                    activity_stats["step_updates"] = int(activity_stats.get("step_updates") or 0) + 1
                if not update_kind:
                    update_kind = "unknown"
                kinds = activity_stats.setdefault("update_kinds", {})
                kinds[update_kind] = int(kinds.get(update_kind) or 0) + 1
            _capture_usage_delta(update, activity_stats)
            _capture_turn_usage(update, activity_stats)
            _capture_context_occupancy(update, activity_stats)
            _capture_native_tool_activity(update, activity_stats)
            _log_server_pre_tool_denial(update, activity_stats)
            content = update.get("content") or {}
            chunk_text = str(content.get("text") or "") if isinstance(content, dict) else ""
            sinks = {
                "agent_message_chunk": text_parts,
                "agent_thought_chunk": reasoning_parts,
            }
            sink = sinks.get(str(update.get("sessionUpdate") or "").strip())
            if chunk_text and sink is not None:
                sink.append(chunk_text)
            return True
        if process.stdin is None:
            return True
        message_id = msg.get("id")
        if method == "session/request_permission":
            params = msg.get("params") or {}
            if not isinstance(params, dict):
                params = {}
            allow_option_id = _safe_read_permission_option(params, cwd)
            selected_option_kind = "allow_once" if allow_option_id else None
            selection_source = "read_only_scratch" if allow_option_id else None
            reject_option = None if allow_option_id else _safe_reject_permission_option(params)
            offered_kinds = _permission_option_kinds(params)
            tool_call = _permission_tool_call(params)
            protocol_limitation = None
            if allow_option_id:
                selected_option_id = allow_option_id
                server_outcome = "selected"
                logger.info(
                    "Antigravity ACP approved one read-only Hermes scratch permission request."
                )
                outcome = {"outcome": "selected", "optionId": selected_option_id}
            elif reject_option:
                selected_option_id, selected_option_kind = reject_option
                server_outcome = "selected"
                outcome = {"outcome": "selected", "optionId": selected_option_id}
            else:
                selected_option_kind = None
                server_outcome = "cancelled"
                protocol_limitation = "no_reject_option_offered"
                logger.warning(
                    "ACP permission policy denial failed closed: no documented reject option "
                    "was offered, so the request was cancelled."
                )
                outcome = {"outcome": "cancelled"}
            if (
                selected_option_kind in {"reject_once", "reject_always"}
                or server_outcome == "cancelled"
            ) and activity_stats is not None:
                # Correlate the later failed tool_call_update: the official server
                # answers a harness reject with echo wording ("Rejected by user"
                # on 1.4.0).  This hash set lets telemetry attribute that text
                # to the harness, never to a human denial.  Bounded so a
                # long-lived session cannot grow it without limit; entries are
                # only needed until the matching failed update arrives.
                denied_hash = _opaque_permission_id(
                    tool_call.get("toolCallId"), "tool-call"
                )
                if denied_hash:
                    denied_hashes = activity_stats.setdefault(
                        "_harness_denied_tool_call_hashes", set()
                    )
                    if len(denied_hashes) < 256:
                        denied_hashes.add(denied_hash)
            _emit_permission_telemetry(
                tool_call=tool_call,
                activity_stats=activity_stats,
                decision_stage="harness_permission_response",
                offered_option_kinds=offered_kinds,
                selected_option_kind=selected_option_kind,
                server_outcome=server_outcome,
                protocol_limitation=protocol_limitation,
                selection_source=selection_source,
            )
            response = _jsonrpc_result(message_id, {"outcome": outcome})
        elif method in _FS_HANDLERS:
            if not allow_file_requests:
                response = _jsonrpc_error(
                    message_id,
                    -32601,
                    "File access is unavailable during model discovery.",
                )
            else:
                try:
                    response = _jsonrpc_result(
                        message_id, _FS_HANDLERS[method](msg.get("params") or {}, cwd)
                    )
                except Exception as exc:
                    response = _jsonrpc_error(message_id, -32602, str(exc))
        else:
            response = _jsonrpc_error(
                message_id,
                -32601,
                f"ACP client method '{method}' is not supported by the Antigravity provider.",
            )
        process.stdin.write(json.dumps(response) + "\n")
        process.stdin.flush()
        return True
