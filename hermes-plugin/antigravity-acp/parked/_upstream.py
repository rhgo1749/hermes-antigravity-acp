"""Vendored, behaviour-unchanged pieces of the MIT-licensed hermes-antigravity-acp plugin.

Source: rhgo1749/hermes-antigravity-acp, hermes-plugin/antigravity-acp/
        client.py (stderr policy, rate/auth regexes, child-env allowlist, _resolve_home_dir)
        hermes_compat.py (hermes_runtime_present, get_hermes_home,
        build_hermes_subprocess_env, apply_subprocess_home_env)
Commit: acb68264ea7380082e28ece0bec134028a770622
Upstream: https://github.com/rhgo1749/hermes-antigravity-acp

MIT License. Copyright (c) 2026 rhgo1749
Permission notice: see the upstream LICENSE; it applies to this file unchanged.

Only the imports were merged into one module (and ``typing.MutableMapping`` became
``collections.abc.MutableMapping``); function bodies are verbatim. Do not edit
behaviour here: re-vendor from upstream instead.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import tempfile
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any

# ---- hermes_compat.py (subset) ------------------------------------------------

def hermes_runtime_present() -> bool:
    """Whether this process has loaded Hermes' public provider or a runtime package."""
    providers = sys.modules.get("providers")
    if providers is not None and getattr(providers, "__file__", None):
        return True
    return any(
        sys.modules.get(name) is not None
        for name in ("agent", "gateway", "tools", "hermes_constants")
    )




def get_hermes_home() -> Path:
    """Resolve the active Hermes home, with the provider's standalone fallback."""
    try:
        from hermes_constants import get_hermes_home as resolve_home
    except (ImportError, AttributeError):
        configured = os.environ.get("HERMES_HOME", "").strip()
        if configured:
            return Path(os.path.expandvars(os.path.expanduser(configured)))
        if hermes_runtime_present():
            raise RuntimeError(  # noqa: B904 - vendored verbatim
                "Hermes active home cannot be resolved; refusing to use the default profile."
            )
        return Path.home() / ".hermes"
    return Path(resolve_home())




def build_hermes_subprocess_env() -> dict[str, str] | None:
    """Ask Hermes' credential-aware environment policy; None selects the safe local allowlist.

    The returned mapping is a base, never the child contract: upstream
    ``hermes_subprocess_env(inherit_credentials=True)`` intentionally retains
    Tier-2 provider credentials for children that need them. The caller in
    ``client.py`` narrows any result through the ACP child minimum-environment
    contract before spawning.
    """
    try:
        from tools.environments.local import hermes_subprocess_env
    except ImportError:
        return None
    try:
        return hermes_subprocess_env(inherit_credentials=True)
    except Exception as exc:
        if hermes_runtime_present():
            raise RuntimeError(
                "Hermes subprocess environment policy failed; refusing to start the ACP child."
            ) from exc
        return None


def apply_subprocess_home_env(env: MutableMapping[str, str]) -> bool:
    """Apply Hermes HOME/scratch policy; fail closed in an active Hermes runtime."""
    try:
        from hermes_constants import apply_subprocess_home_env as apply_home_policy
    except Exception as exc:
        if hermes_runtime_present():
            raise RuntimeError(
                "Hermes subprocess HOME/scratch policy is unavailable; refusing to start the ACP child."
            ) from exc
        return False
    try:
        apply_home_policy(env)
    except Exception as exc:
        if hermes_runtime_present():
            raise RuntimeError(
                "Hermes subprocess HOME/scratch policy failed; refusing to start the ACP child."
            ) from exc
        return False
    return True


# ---- client.py: failover signature regexes -----------------------------------

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

# ---- client.py: stderr policy ---------------------------------------------------

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
    text = re.sub(r"\bya29\.[A-Za-z0-9._-]{4,}", "[REDACTED_TOKEN]", text)
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


# ---- client.py: child environment contract -------------------------------------

def _resolve_home_dir() -> str:
    if home := os.environ.get("HOME", "").strip():
        return home
    if (expanded := os.path.expanduser("~")) and expanded != "~":
        return expanded
    try:
        import pwd

        return pwd.getpwuid(os.getuid()).pw_dir.strip() or tempfile.gettempdir()
    except Exception:  # noqa: BLE001 - vendored verbatim
        return tempfile.gettempdir()


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
    # Local addition (not upstream): keeps the official server's credentials in a file under GEMINI_HOME instead of
    # the user's login Keychain. A boolean switch, never credential material.
    "AGY_ACP_FORCE_FILE_STORAGE",
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


