#!/usr/bin/env python3
"""Antigravity ACP account multiplexer — one ACP endpoint, many Google accounts.

A client (for example Hermes' external_process provider) spawns this as one ACP
v1 stdio agent. Per client session the mux:

1. hot-loads an account registry,
2. chooses the healthiest account from the best priority tier, balancing new
   affinity assignments while keeping resumed ACP sessions account-sticky,
3. spawns Google's official ``agy_acp_server.par`` with that account's HOME,
4. relays ACP JSON-RPC unchanged while observing only explicit upstream
   failures for future routing decisions.

The mux deliberately does not open Antigravity credential files, exchange
refresh tokens, or call private/internal Google quota APIs. Authentication
remains inside Google's official ACP runtime.

Observed failures affect *future* sessions only. Quota/rate-limit, auth, and
unexpected process failures receive separate cooldowns. If every account is
cooling down, the account whose cooldown expires first is probed so the mux
never turns a stale health record into a hard outage.

Environment:
  ACP_MUX_HOME            shared mux control home; defaults to HERMES_REAL_HOME,
                          then HOME. Used only for default registry/state/log paths.
  ACP_MUX_ACCOUNTS        registry path (default ~/.hermes/acp-accounts.json)
  ACP_MUX_DEFAULT_HOME    explicit default account home; registry entries
                          without ``home`` resolve here.  Without it, a legacy
                          (no ``schema_version``) registry resolves such an
                          entry to the control home with a logged diagnostic,
                          while a ``schema_version: 1`` registry refuses the
                          entry instead of silently adopting process HOME.
  ACP_MUX_PAR             official agy_acp_server.par path (required)
  ACP_MUX_STATE           routing/health state (default ~/.hermes/cache/acp-mux-state.json)
  ACP_MUX_LOG             selection log (default ~/.hermes/logs/acp-mux.log)
  ACP_MUX_AFFINITY        opaque client-supplied conversation affinity key; when
                          set, new sessions use least-assigned selection
  ACP_MUX_AFFINITY_PIN    set to 1 when resuming an existing native ACP session;
                          legacy affinities retain their rendezvous assignment
  ACP_MUX_AFFINITY_TTL_SECONDS  affinity assignment retention; defaults to the
                          ACP continuation-state TTL (24 hours)
  ACP_MUX_AFFINITY_MAX_ENTRIES  affinity assignment cap; defaults to the ACP
                          continuation-state cap (512)
  ACP_MUX_SESSION_GC      set to 1 to run the destructive native session-store
                          GC once at bind time.  The Hermes provider only sets
                          this when HERMES_ANTIGRAVITY_ACP_NATIVE_GC=1; the GC
                          is opt-in until the native session lifetime contract
                          is finished (issue #3 follow-up).
  ACP_MUX_OWNER_GRACE_SECONDS  minimum age before an ownership record whose
                          native bundle and checkpoint are both gone may be
                          retired; defaults to the affinity retention TTL
  ACP_MUX_AUTH_COOLDOWN   auth failure cooldown seconds (default 300)
  ACP_MUX_QUOTA_COOLDOWN  quota/rate-limit cooldown seconds (default 900)
  ACP_MUX_CRASH_COOLDOWN  unexpected process failure cooldown seconds (default 60)

For deployment compatibility, HERMES_ACP_ACCOUNTS and
HERMES_ANTIGRAVITY_ACP_PAR are accepted as fallback names. ACP_MUX_CACHE is
accepted as a legacy alias for ACP_MUX_STATE.

Diagnostics: ``python3 acp_mux.py doctor`` prints the fully resolved path
contract (control home, registry, state, log, default home, per-account lane
existence, alias/symlink/collision findings).  It writes nothing and never
prints labels or credentials.  Exit 0 = clean, 1 = findings to review,
2 = registry present but unusable.  The portable contract (precedence,
registry schema, migration, Docker bind-mount topologies) is documented in
docs/acp-path-contract.md (historical reference).
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Iterator, Mapping

try:  # POSIX deployment gets cross-process state serialization; other OSes degrade safely.
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]


def _env(primary: str, fallback: str | None, default: str) -> str:
    value = os.environ.get(primary)
    if value is None and fallback:
        value = os.environ.get(fallback)
    return value if value is not None else default


def _control_home(env: dict[str, str] | None = None) -> str:
    """Shared mux control home, independent from an isolated subprocess HOME.

    Hermes intentionally rewrites ``HOME`` for profile-scoped subprocesses and
    publishes the OS-user home as ``HERMES_REAL_HOME``. The mux account
    registry and health state are host-level control-plane data, so their
    defaults should follow the real home while the selected ACP child still
    receives the account-specific HOME below.

    ``ACP_MUX_HOME`` is the explicit portable override for non-Hermes hosts.
    """
    values = os.environ if env is None else env
    raw = (
        values.get("ACP_MUX_HOME")
        or values.get("HERMES_REAL_HOME")
        or values.get("HOME")
        or os.path.expanduser("~")
    )
    return os.path.expanduser(raw)


def _default_control_path(relative: str, env: dict[str, str] | None = None) -> str:
    return os.path.join(_control_home(env), ".hermes", relative)


PATH_CONTRACT_VERSION = 1
SUPPORTED_REGISTRY_SCHEMA_VERSIONS = frozenset({1})

# Ordered candidate environment names; the first non-empty value wins.  An
# empty value means "unset" (a contract note operators can rely on; it used
# to be a silently broken path override).
_CONTROL_HOME_ENV_ORDER = ("ACP_MUX_HOME", "HERMES_REAL_HOME", "HOME")
_REGISTRY_ENV_ORDER = ("ACP_MUX_ACCOUNTS", "HERMES_ACP_ACCOUNTS")
_STATE_ENV_ORDER = ("ACP_MUX_STATE", "ACP_MUX_CACHE")
_PAR_ENV_ORDER = ("ACP_MUX_PAR", "HERMES_ANTIGRAVITY_ACP_PAR")
_DEFAULT_HOME_ENV_ORDER = ("ACP_MUX_DEFAULT_HOME",)


def _first_nonempty(values: Mapping[str, str], names: tuple) -> tuple:
    for name in names:
        raw = values.get(name)
        if raw:
            return raw, name
    return "", ""


def resolve_layout(env: Mapping[str, str] | None = None) -> dict:
    """Single source of truth for the portable control-plane path contract.

    historical reference: every resolved control path derives from one environment
    mapping with one precedence, so import-time constants, the ``doctor``
    diagnostics, and a fresh process always agree.  Resolution happens per
    call from the given mapping: a running process keeps the layout it
    imported with, and a fresh process re-resolves.  Nothing is created,
    read, or written here, and no personal path is ever assumed.
    """
    values = dict(os.environ) if env is None else dict(env)

    raw_home, home_source = _first_nonempty(values, _CONTROL_HOME_ENV_ORDER)
    if raw_home:
        control_home = os.path.expanduser(raw_home)
    else:
        control_home = os.path.expanduser("~")
        home_source = "expanduser(~)"

    registry, registry_source = _first_nonempty(values, _REGISTRY_ENV_ORDER)
    if not registry:
        registry = _default_control_path("acp-accounts.json", values)
        registry_source = "control-home-default"

    state, state_source = _first_nonempty(values, _STATE_ENV_ORDER)
    if not state:
        state = _default_control_path("cache/acp-mux-state.json", values)
        state_source = "control-home-default"

    log, log_source = _first_nonempty(values, ("ACP_MUX_LOG",))
    if not log:
        log = _default_control_path("logs/acp-mux.log", values)
        log_source = "control-home-default"

    par, par_source = _first_nonempty(values, _PAR_ENV_ORDER)

    default_home, default_source = _first_nonempty(values, _DEFAULT_HOME_ENV_ORDER)
    if default_home:
        default_source = "ACP_MUX_DEFAULT_HOME"
    else:
        default_home = control_home
        default_source = "control-home-fallback"

    def _resolved(path: str) -> str:
        expanded = os.path.expanduser(path) if path else ""
        return os.path.normpath(expanded) if expanded else ""

    return {
        "contract_version": PATH_CONTRACT_VERSION,
        "control_home": _resolved(control_home),
        "registry_path": _resolved(registry),
        "state_path": _resolved(state),
        "log_path": _resolved(log),
        "par": _resolved(par),
        "default_home": _resolved(default_home),
        "sources": {
            "control_home": home_source,
            "registry": registry_source,
            "state": state_source,
            "log": log_source,
            "par": par_source or "unset",
            "default_home": default_source,
        },
    }


_LAYOUT = resolve_layout()
REGISTRY_PATH = _LAYOUT["registry_path"]
STATE_PATH = _LAYOUT["state_path"]
LOG_PATH = _LAYOUT["log_path"]
PAR = _LAYOUT["par"]
DEFAULT_HOME = _LAYOUT["default_home"]

AUTH_COOLDOWN = float(os.environ.get("ACP_MUX_AUTH_COOLDOWN", "300"))
QUOTA_COOLDOWN = float(os.environ.get("ACP_MUX_QUOTA_COOLDOWN", "900"))
CRASH_COOLDOWN = float(os.environ.get("ACP_MUX_CRASH_COOLDOWN", "60"))

_DEFAULT_AFFINITY_TTL_SECONDS = 24 * 60 * 60
_DEFAULT_AFFINITY_MAX_ENTRIES = 512
_SESSION_STATE_FILENAME = "antigravity-acp-sessions.json"
_SESSION_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)


def _configured_positive_int(primary: str, fallback: str, default: int) -> int:
    raw = os.environ.get(primary)
    if raw is None:
        raw = os.environ.get(fallback)
    try:
        value = int(raw) if raw is not None else default
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


AFFINITY_TTL_SECONDS = _configured_positive_int(
    "ACP_MUX_AFFINITY_TTL_SECONDS",
    "HERMES_ANTIGRAVITY_ACP_STATE_TTL_SECONDS",
    _DEFAULT_AFFINITY_TTL_SECONDS,
)
AFFINITY_MAX_ENTRIES = _configured_positive_int(
    "ACP_MUX_AFFINITY_MAX_ENTRIES",
    "HERMES_ANTIGRAVITY_ACP_STATE_MAX_ENTRIES",
    _DEFAULT_AFFINITY_MAX_ENTRIES,
)
OWNER_GRACE_SECONDS = _configured_positive_int(
    "ACP_MUX_OWNER_GRACE_SECONDS",
    "HERMES_ANTIGRAVITY_ACP_OWNER_GRACE_SECONDS",
    _DEFAULT_AFFINITY_TTL_SECONDS,
)

_QUOTA_RE = re.compile(
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


def _log(msg: str) -> None:
    try:
        directory = os.path.dirname(LOG_PATH)
        if directory:
            os.makedirs(directory, exist_ok=True)
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 200_000:
            os.replace(LOG_PATH, LOG_PATH + ".1")
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


def _redact(line: str) -> str:
    line = re.sub(
        r"(access_token|refresh_token|id_token|code_verifier|client_secret)(=|:)\s*\S+",
        r"\1\2***",
        line,
        flags=re.I,
    )
    line = re.sub(r"ya29\.\S+", "ya29.***", line)
    # OAuth hand-off URLs authenticate the ACP server; their query strings
    # carry state/redirect parameters that must never reach logs (1.2.1 D4).
    line = re.sub(
        r"(?i)(authenticate the ACP server:)\s*\S+", r"\1 [redacted]", line
    )
    line = re.sub(
        r"https?://(?:accounts\.google\.com|[^\s]*)[^\s]*oauth[^\s]*",
        "[redacted-oauth-url]",
        line,
    )
    return line[:500]


def pinned_gemini_home(home: str) -> str:
    """Return the per-account Gemini home the official server must use.

    The 1.2.1 server roots all state at ``$GEMINI_HOME`` else ``~/.gemini``.
    Pinning it per account lane prevents a stray parent ``GEMINI_HOME`` from
    collapsing every lane onto one shared token store and one shared global
    ``config/mcp_config.json`` (contract doc, S1/S3).
    """
    return os.path.join(home, ".gemini")


def mcp_config_violation(gemini_home: str) -> str | None:
    """Fail-closed check of the global MCP config the server will merge.

    ``mcpServers: []`` from the client does not suppress the official server's
    merge of ``<GEMINI_HOME>/config/mcp_config.json`` (verified defect D1), so
    any unexpected entry — or malformed/unreadable file — is reported here.
    Entry names only are returned; config contents are never logged.
    """
    path = os.path.join(gemini_home, "config", "mcp_config.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read(65536)
    except FileNotFoundError:
        return None
    except OSError:
        return "unreadable"
    if not raw.strip():
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return "malformed-json"
    if not isinstance(data, dict):
        return "malformed-schema"
    servers = data.get("mcpServers")
    if servers is None or servers == {}:
        return None
    if isinstance(servers, dict):
        names = ",".join(sorted(str(name) for name in servers)[:8])
        return f"mcpServers={names}" if names else "malformed-schema"
    return "malformed-schema"


def _load_registry_data(
    registry_path: str | None = None,
) -> tuple[list | None, dict, str]:
    """Read the registry once.  Returns ``(entries, meta, problem)``.

    ``problem`` is "" when the registry parsed cleanly, "missing" when the
    path does not exist, and a diagnostic code otherwise; entries are None
    whenever ``problem`` is non-empty.  An unknown ``schema_version`` is a
    problem (fail closed) rather than a silent legacy read.
    """
    path = REGISTRY_PATH if registry_path is None else registry_path
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None, {}, "missing"
    except OSError:
        return None, {}, "unreadable"
    except ValueError:
        return None, {}, "malformed-json"
    if not isinstance(data, dict):
        return None, {}, "malformed-schema"
    schema = data.get("schema_version")
    if schema is not None:
        if isinstance(schema, bool) or not isinstance(schema, int):
            return None, data, "malformed-schema"
        if schema not in SUPPORTED_REGISTRY_SCHEMA_VERSIONS:
            return None, data, "unsupported-schema-version"
    accounts = data.get("accounts")
    if not isinstance(accounts, list):
        return None, data, "missing-accounts"
    return [entry for entry in accounts if isinstance(entry, dict)], data, ""


def _load_registry() -> list:
    entries, _meta, _problem = _load_registry_data()
    return entries or []


def _effective_default_home(
    meta: dict | None, env: Mapping[str, str] | None = None
) -> tuple:
    """Return ``(default_home, explicit)`` for missing per-entry homes.

    Precedence: ``ACP_MUX_DEFAULT_HOME`` then a registry-level
    ``default_home``.  ``explicit`` is False only when neither exists and the
    resolution falls back to the process control home — the legacy behavior
    the portable contract deprecates but preserves for unversioned registries.
    """
    values = os.environ if env is None else env
    raw = (values.get("ACP_MUX_DEFAULT_HOME") or "").strip()
    if raw:
        return os.path.expanduser(raw), True
    declared = (meta or {}).get("default_home")
    if isinstance(declared, str) and declared.strip():
        return os.path.expanduser(declared.strip()), True
    return DEFAULT_HOME, False


def _account(
    entry: dict, default_home: str | None = None
) -> tuple[str, str, int, str]:
    if default_home is None:
        default_home = DEFAULT_HOME
    home = entry.get("home") or default_home
    home = os.path.expanduser(str(home))
    label = str(entry.get("label") or os.path.basename(home.rstrip("/")) or "acp")
    priority = entry.get("priority")
    priority = priority if isinstance(priority, int) else 0
    key = f"{label}\t{home}"
    return home, label, priority, key


def _lane_fingerprint(home: str, label: str) -> str:
    """Stable non-identifying lane token for diagnostics and stderr."""
    return hashlib.sha256(
        f"{label}\t{home}".encode("utf-8", errors="surrogatepass")
    ).hexdigest()[:12]


def _empty_state() -> dict:
    return {"version": 1, "cursor": {}, "accounts": {}, "affinities": {}}


def _load_state_unlocked() -> dict:
    try:
        with open(STATE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return _empty_state()
    except (OSError, json.JSONDecodeError):
        return _empty_state()

    cursor = data.get("cursor")
    accounts = data.get("accounts")
    affinities = data.get("affinities")
    return {
        "version": 1,
        "cursor": cursor if isinstance(cursor, dict) else {},
        "accounts": accounts if isinstance(accounts, dict) else {},
        "affinities": affinities if isinstance(affinities, dict) else {},
    }


def _save_state_unlocked(state: dict) -> bool:
    tmp = STATE_PATH + f".tmp.{os.getpid()}"
    try:
        directory = os.path.dirname(STATE_PATH)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh, sort_keys=True)
        os.replace(tmp, STATE_PATH)
        return True
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return False


def _affinity_digest(affinity: str) -> str:
    return hashlib.sha256(
        affinity.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def _prune_affinity_assignments(
    affinities: dict,
    now: float,
    keep_digest: str = "",
) -> None:
    expires_before = now - AFFINITY_TTL_SECONDS
    expires_after = now + AFFINITY_TTL_SECONDS
    for digest, record in tuple(affinities.items()):
        last_seen = record.get("last_seen") if isinstance(record, dict) else None
        if (
            isinstance(last_seen, bool)
            or not isinstance(last_seen, (int, float))
            or not math.isfinite(last_seen)
            or last_seen < expires_before
            or last_seen > expires_after
        ):
            affinities.pop(digest, None)
    if len(affinities) > AFFINITY_MAX_ENTRIES:
        oldest = sorted(
            affinities.items(),
            key=lambda item: (
                item[1]["last_seen"],
                item[0] == keep_digest,
            ),
        )
        for digest, _ in oldest[: len(affinities) - AFFINITY_MAX_ENTRIES]:
            affinities.pop(digest, None)


def _store_affinity_assignment(
    affinities: dict,
    digest: str,
    account_key: str,
    selected_key: str,
    now: float,
) -> None:
    affinities[digest] = {
        "account_key": account_key,
        "selected_key": selected_key,
        "last_seen": now,
    }
    _prune_affinity_assignments(affinities, now, keep_digest=digest)


def _hermes_session_state_paths(env: Mapping[str, str]) -> list[Path] | None:
    """Find checkpoint files that can still resume native ACP sessions.

    A missing checkpoint is normal; an unreadable or malformed existing one is
    not safe to treat as an empty active-session set, so the caller must skip
    garbage collection in that case.
    """
    paths: list[Path] = []
    override = env.get("HERMES_ANTIGRAVITY_ACP_STATE_FILE", "").strip()
    if override:
        paths.append(Path(os.path.expanduser(override)))

    hermes_home = env.get("HERMES_HOME", "").strip()
    real_home = env.get("HERMES_REAL_HOME", "").strip()
    if not hermes_home and not real_home and not override:
        return None
    if hermes_home:
        profile_home = Path(os.path.expanduser(hermes_home))
        if not profile_home.is_absolute():
            return None
        paths.append(profile_home / "cache" / _SESSION_STATE_FILENAME)

    if real_home:
        root = Path(os.path.expanduser(real_home))
        if not root.is_absolute():
            return None
        hermes_root = root if root.name == ".hermes" else root / ".hermes"
        paths.append(hermes_root / "cache" / _SESSION_STATE_FILENAME)
        profiles = hermes_root / "profiles"
        try:
            profiles_info = profiles.lstat()
        except FileNotFoundError:
            profiles_info = None
        except OSError:
            return None
        if profiles_info is not None:
            if not stat.S_ISDIR(profiles_info.st_mode):
                return None
            try:
                with os.scandir(profiles) as entries:
                    for entry in entries:
                        if entry.is_symlink():
                            return None
                        if entry.is_dir(follow_symlinks=False):
                            paths.append(
                                Path(entry.path) / "cache" / _SESSION_STATE_FILENAME
                            )
            except OSError:
                return None

    unique: dict[str, Path] = {}
    for path in paths:
        unique[str(path)] = path
    return list(unique.values())


def _active_hermes_session_ids(
    *, now: float | None = None, env: Mapping[str, str] | None = None
) -> set[str] | None:
    """Return IDs protected by unexpired Hermes continuation checkpoints."""
    values: Mapping[str, str] = os.environ if env is None else env
    now = time.time() if now is None else now
    paths = _hermes_session_state_paths(values)
    if paths is None:
        return None

    active: set[str] = set()
    for path in paths:
        if path.is_symlink():
            return None
        if not path.exists():
            continue
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeError):
            return None
        if (
            not isinstance(payload, dict)
            or payload.get("version") != 1
            or not isinstance(payload.get("states"), dict)
        ):
            return None
        for record in payload["states"].values():
            if not isinstance(record, dict):
                continue
            session_id = record.get("session_id")
            updated_at = record.get("updated_at")
            if (
                not isinstance(session_id, str)
                or not session_id.strip()
                or isinstance(updated_at, bool)
                or not isinstance(updated_at, (int, float))
                or not math.isfinite(updated_at)
            ):
                continue
            if now - AFFINITY_TTL_SECONDS <= updated_at <= now + AFFINITY_TTL_SECONDS:
                active.add(session_id.strip())

    current_session = values.get("ACP_MUX_SESSION_ID", "").strip()
    if current_session:
        active.add(current_session)
    return active


@contextmanager
def _session_gc_lock() -> Iterator[bool]:
    """Serialize destructive session-store pruning across mux processes."""
    lock_path = STATE_PATH + ".session-gc.lock"
    directory = os.path.dirname(lock_path)
    if fcntl is None or not hasattr(os, "O_NOFOLLOW"):
        yield False
        return
    fd = -1
    try:
        if directory:
            os.makedirs(directory, exist_ok=True)
        fd = os.open(
            lock_path,
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
            0o600,
        )
        os.fchmod(fd, 0o600)
    except OSError:
        if fd >= 0:
            os.close(fd)
        yield False
        return

    lock = os.fdopen(fd, "a+", encoding="utf-8")
    acquired = False
    try:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            acquired = True
        except OSError:
            pass
        yield acquired
    finally:
        if acquired:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        lock.close()


def _ownership_accounts() -> list[tuple[str, str, str]] | None:
    """Return distinct registered lanes, refusing aliases or invalid registry entries."""
    entries, meta, problem = _load_registry_data()
    if problem == "missing":
        entries, meta = [{"home": DEFAULT_HOME, "label": "default"}], {}
    elif problem or entries is None or len(entries) != len(meta.get("accounts", [])):
        return None
    default, explicit = _effective_default_home(meta)
    seen: set[tuple[int, int]] = set()
    lanes = []
    for entry in entries:
        raw = entry.get("home")
        if not raw and isinstance(meta.get("schema_version"), int) and not explicit:
            return None
        home, label, _, key = _account(entry, default)
        if not os.path.isabs(home) or os.path.realpath(home) != os.path.abspath(home):
            return None
        try:
            info = os.stat(home, follow_symlinks=False)
        except OSError:
            return None
        identity = (info.st_dev, info.st_ino)
        if not stat.S_ISDIR(info.st_mode) or identity in seen:
            return None
        seen.add(identity)
        lanes.append((home, label, key))
    return lanes or None


def _read_session_owners() -> dict[str, dict] | None:
    """Return ownership entries keyed by hashed session id.

    Version 2 stores ``{"lane": hash, "at": epoch}`` per entry so record
    cleanup can apply a grace period.  Version 1 (hash -> hash) is accepted
    read-only and back-dated to the file mtime; the next write upgrades the
    file in place.
    """
    path = STATE_PATH + ".owners.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return {}
    except OSError:
        return None
    try:
        with os.fdopen(fd, encoding="utf-8") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode):
                return None
            mtime = info.st_mtime
            data = json.load(handle)
        if not isinstance(data, dict) or data.get("version") not in (1, 2):
            return None
        owners = data.get("owners")
        if not isinstance(owners, dict):
            return None
        entries: dict[str, dict] = {}
        for key, value in owners.items():
            if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
                return None
            if data["version"] == 1:
                if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                    return None
                entries[key] = {"lane": value, "at": mtime}
                continue
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("lane"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["lane"])
                or isinstance(value.get("at"), bool)
                or not isinstance(value.get("at"), (int, float))
                or not math.isfinite(value["at"])
            ):
                return None
            entries[key] = {"lane": value["lane"], "at": float(value["at"])}
        return entries
    except (OSError, ValueError, UnicodeError):
        return None


def _owner_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def _record_session_owner(session_id: str, home: str, label: str) -> bool:
    if not isinstance(session_id, str) or not session_id or len(session_id) > 512:
        return False
    with _session_gc_lock() as locked:
        if not locked:
            return False
        lanes = _ownership_accounts()
        owners = _read_session_owners()
        if lanes is None or owners is None:
            return False
        key = f"{label}\t{home}"
        if not any(row[2] == key for row in lanes):
            return False
        digest, lane = _owner_hash(session_id), _owner_hash(key)
        existing = owners.get(digest)
        if existing is not None:
            if existing["lane"] != lane:
                return False
        else:
            owners[digest] = {"lane": lane, "at": time.time()}
        path = STATE_PATH + ".owners.json"
        tmp = ""
        try:
            fd, tmp = tempfile.mkstemp(prefix=".acp-owners-", dir=os.path.dirname(path) or ".")
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"version": 2, "owners": owners}, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            return True
        except OSError:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            return False


def _resolve_session_owner(session_id: str) -> tuple[str, str] | None:
    if not isinstance(session_id, str) or not session_id or len(session_id) > 512:
        return None
    with _session_gc_lock() as locked:
        if not locked:
            return None
        lanes = _ownership_accounts()
        owners = _read_session_owners()
        if lanes is None or owners is None:
            return None
        digest = _owner_hash(session_id)
        if digest in owners:
            lane = owners[digest]["lane"]
            found = [(home, label) for home, label, key in lanes if _owner_hash(key) == lane]
            return found[0] if len(found) == 1 else None
        if not _is_store_session_id(session_id):
            return None
        matches = []
        store_ids: set[tuple[int, int]] = set()
        for home, label, _ in lanes:
            current = Path(home)
            try:
                missing = False
                for component in (".gemini", "antigravity-acp", "conversations"):
                    current = current / component
                    try:
                        info = current.lstat()
                    except FileNotFoundError:
                        missing = True
                        break
                    if not stat.S_ISDIR(info.st_mode):
                        return None
                if missing:
                    continue
                current_info = current.lstat()
                identity = (current_info.st_dev, current_info.st_ino)
                if identity in store_ids:
                    return None
                store_ids.add(identity)
                # Establish directory readability before interpreting absence.
                with os.scandir(current):
                    pass
                try:
                    target = (current / f"{session_id}.db").lstat()
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(target.st_mode):
                    return None
                matches.append((home, label))
            except OSError:
                return None
        return matches[0] if len(matches) == 1 else None


class _SessionOwnerRelay:
    """Correlate session/new replies and reject resume on the wrong lane."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._new_requests: set = set()

    @staticmethod
    def _error(request_id: object, message: str) -> str:
        return json.dumps({"jsonrpc": "2.0", "id": request_id,
                           "error": {"code": -32000, "message": message}}) + "\n"

    def before(self, payload: object, home: str, label: str) -> str | None:
        if not isinstance(payload, dict) or "id" not in payload:
            return None
        request_id = payload["id"]
        if not isinstance(request_id, (int, str)) or isinstance(request_id, bool):
            return self._error(request_id, "Invalid request id")
        method = payload.get("method")
        if method in ("session/resume", "session/load"):
            params = payload.get("params")
            session_id = params.get("sessionId") if isinstance(params, dict) else None
            if not isinstance(session_id, str) or _resolve_session_owner(session_id) != (home, label):
                return self._error(request_id, "Session not found: owner unavailable on this lane")
        if method == "session/new":
            with self._lock:
                if request_id in self._new_requests:
                    return self._error(request_id, "Duplicate session/new request id")
                self._new_requests.add(request_id)
        return None

    def after(self, line: str, home: str, label: str) -> str:
        try:
            payload = json.loads(line)
        except (ValueError, TypeError):
            return line
        if not isinstance(payload, dict) or "method" in payload:
            return line
        request_id = payload.get("id")
        if not isinstance(request_id, (int, str)) or isinstance(request_id, bool):
            return line
        with self._lock:
            if request_id not in self._new_requests:
                return line
            self._new_requests.remove(request_id)
        result = payload.get("result")
        session_id = result.get("sessionId") if isinstance(result, dict) else None
        if session_id is not None and not _record_session_owner(session_id, home, label):
            return self._error(request_id, "Session ownership could not be persisted")
        return line


def _session_store_root(home: str) -> Path | None:
    """Return only the official server's ACP conversation store for one HOME."""
    account_home = Path(os.path.expanduser(str(home)))
    if not account_home.is_absolute() or account_home.is_symlink():
        return None
    gemini_home = account_home / ".gemini"
    store = gemini_home / "antigravity-acp"
    if gemini_home.is_symlink() or store.is_symlink():
        return None
    if not store.exists():
        return None
    if not store.is_dir():
        return None
    for name in ("conversations", "brain"):
        child = store / name
        if child.is_symlink() or (child.exists() and not child.is_dir()):
            return None
    return store


def _is_store_session_id(value: str) -> bool:
    return bool(_SESSION_ID_RE.fullmatch(value))


def _session_store_records(store: Path) -> dict[str, dict] | None:
    """Inventory UUID-named ACP session bundles without opening their contents."""
    records: dict[str, dict] = {}
    conversations = store / "conversations"
    brain = store / "brain"
    try:
        try:
            conversations_info = conversations.lstat()
        except FileNotFoundError:
            conversations_exists = False
        else:
            if not stat.S_ISDIR(conversations_info.st_mode):
                return None
            conversations_exists = True
        if conversations_exists:
            with os.scandir(conversations) as entries:
                for entry in entries:
                    name = entry.name
                    suffix = next(
                        (candidate for candidate in (".db-wal", ".db-shm", ".meta", ".db") if name.endswith(candidate)),
                        None,
                    )
                    if suffix is None:
                        continue
                    session_id = name[:-len(suffix)]
                    if not _is_store_session_id(session_id):
                        continue
                    record = records.setdefault(
                        session_id,
                        {"session_id": session_id, "files": [], "brain": None, "unsafe": False},
                    )
                    if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                        record["unsafe"] = True
                    else:
                        record["files"].append(Path(entry.path))
        try:
            brain_info = brain.lstat()
        except FileNotFoundError:
            brain_exists = False
        else:
            if not stat.S_ISDIR(brain_info.st_mode):
                return None
            brain_exists = True
        if brain_exists:
            with os.scandir(brain) as entries:
                for entry in entries:
                    if not _is_store_session_id(entry.name):
                        continue
                    record = records.setdefault(
                        entry.name,
                        {"session_id": entry.name, "files": [], "brain": None, "unsafe": False},
                    )
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        record["unsafe"] = True
                    else:
                        record["brain"] = Path(entry.path)
    except OSError:
        return None
    return records


def _session_record_mtime(record: dict) -> float | None:
    if record["unsafe"]:
        return None
    latest = 0.0
    for path in record["files"]:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode):
            return None
        latest = max(latest, info.st_mtime)
    brain = record["brain"]
    if brain is not None:
        try:
            info = brain.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            return None
        else:
            if not stat.S_ISDIR(info.st_mode):
                return None
            latest = max(latest, info.st_mtime)
    return latest if latest > 0 else None


def _safe_tree_size(path: Path) -> int | None:
    total = 0
    errors: list[OSError] = []
    try:
        for current, directories, files in os.walk(
            path, topdown=True, followlinks=False, onerror=errors.append
        ):
            current_path = Path(current)
            for name in directories:
                child = current_path / name
                info = child.lstat()
                if not stat.S_ISDIR(info.st_mode):
                    return None
            for name in files:
                child = current_path / name
                info = child.lstat()
                if not stat.S_ISREG(info.st_mode):
                    return None
                total += info.st_size
    except OSError:
        return None
    return None if errors else total


def _delete_session_bundle(store: Path, record: dict) -> tuple[bool, int]:
    """Delete only one validated DB/meta/brain bundle under the ACP store."""
    if record["unsafe"]:
        return False, 0
    session_id = record["session_id"]
    conversations = store / "conversations"
    brain_path = store / "brain" / session_id
    size = 0
    paths = [
        conversations / f"{session_id}.db-wal",
        conversations / f"{session_id}.db-shm",
        conversations / f"{session_id}.meta",
        conversations / f"{session_id}.db",
    ]
    for path in paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return False, 0
        if not stat.S_ISREG(info.st_mode):
            return False, 0
        size += info.st_size

    brain_size = 0
    if brain_path.is_symlink():
        return False, 0
    if brain_path.exists():
        if not brain_path.is_dir():
            return False, 0
        measured = _safe_tree_size(brain_path)
        if measured is None:
            return False, 0
        brain_size = measured

    try:
        if brain_path.exists():
            shutil.rmtree(brain_path)
        for path in paths:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    except OSError:
        return False, 0
    return True, size + brain_size


def _prune_session_store(
    home: str,
    active_session_ids: set[str],
    *,
    now: float,
) -> dict[str, int]:
    result = {"expired": 0, "capacity": 0, "bytes": 0, "failed": 0}
    store = _session_store_root(home)
    if store is None:
        return result
    records = _session_store_records(store)
    if records is None:
        result["failed"] += 1
        return result

    cutoff = now - AFFINITY_TTL_SECONDS
    activities: dict[str, float] = {}
    for session_id, record in records.items():
        activity = _session_record_mtime(record)
        if activity is None:
            record["unsafe"] = True
            result["failed"] += 1
            activities[session_id] = now + AFFINITY_TTL_SECONDS
        else:
            activities[session_id] = activity

    removed: set[str] = set()
    for session_id, record in records.items():
        activity = activities[session_id]
        if (
            record["unsafe"]
            or session_id in active_session_ids
            or activity > now + AFFINITY_TTL_SECONDS
            or activity >= cutoff
        ):
            continue
        deleted, freed = _delete_session_bundle(store, record)
        if deleted:
            removed.add(session_id)
            result["expired"] += 1
            result["bytes"] += freed
        else:
            record["unsafe"] = True
            result["failed"] += 1

    remaining = [
        (session_id, record)
        for session_id, record in records.items()
        if session_id not in removed
    ]
    excess = max(0, len(remaining) - AFFINITY_MAX_ENTRIES)
    evictable = sorted(
        (
            (session_id, record)
            for session_id, record in remaining
            if not record["unsafe"] and session_id not in active_session_ids
        ),
        key=lambda item: activities[item[0]],
    )
    for session_id, record in evictable[:excess]:
        deleted, freed = _delete_session_bundle(store, record)
        if deleted:
            removed.add(session_id)
            result["capacity"] += 1
            result["bytes"] += freed
        else:
            record["unsafe"] = True
            result["failed"] += 1
    return result


def _session_store_bundle_bytes(records: dict[str, dict]) -> int | None:
    total = 0
    for record in records.values():
        for path in record["files"]:
            try:
                total += path.lstat().st_size
            except OSError:
                return None
    return total


def prune_session_owners(*, now: float | None = None) -> dict[str, int] | None:
    """Retire ownership records whose native bundle and checkpoint are gone.

    Metadata-only: this never deletes a session bundle file.  An entry is
    removed only when every guard passes — it is older than the grace period,
    no registered lane's conversation store still contains that session id,
    no unexpired Hermes continuation checkpoint references it, and its lane
    is still registered (an unresolvable lane keeps its entry).  Any
    unreadable registry, ownership file, checkpoint inventory, or session
    store aborts the pass and keeps every entry (fail closed).
    """
    now = time.time() if now is None else now
    with _session_gc_lock() as locked:
        if not locked:
            _log("owner-records skipped: cross-process lock unavailable")
            return None
        lanes = _ownership_accounts()
        owners = _read_session_owners()
        if lanes is None or owners is None:
            _log("owner-records skipped: registry or ownership records unreadable")
            return None
        if not owners:
            return {"removed": 0, "kept": 0, "bundles": 0, "bytes": 0}
        active = _active_hermes_session_ids(now=now)
        if active is None:
            _log("owner-records skipped: continuation checkpoint inventory unavailable")
            return None
        live = {_owner_hash(session_id) for session_id in active}
        bundles = 0
        total_bytes: int | None = 0
        for home, _label, _key in lanes:
            try:
                (Path(home) / ".gemini" / "antigravity-acp").lstat()
            except FileNotFoundError:
                continue
            except OSError:
                _log("owner-records skipped: session store probe failed")
                return None
            store = _session_store_root(home)
            if store is None:
                _log("owner-records skipped: session store layout refused")
                return None
            records = _session_store_records(store)
            if records is None:
                _log("owner-records skipped: session store inventory failed")
                return None
            bundles += len(records)
            for session_id in records:
                live.add(_owner_hash(session_id))
            if total_bytes is not None:
                measured = _session_store_bundle_bytes(records)
                total_bytes = None if measured is None else total_bytes + measured
        lane_keys = {_owner_hash(key) for _home, _label, key in lanes}
        kept: dict[str, dict] = {}
        removed = 0
        for digest, entry in owners.items():
            if (
                entry["at"] + OWNER_GRACE_SECONDS > now
                or digest in live
                or entry["lane"] not in lane_keys
            ):
                kept[digest] = entry
            else:
                removed += 1
        if removed:
            path = STATE_PATH + ".owners.json"
            tmp = ""
            try:
                fd, tmp = tempfile.mkstemp(prefix=".acp-owners-", dir=os.path.dirname(path) or ".")
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump({"version": 2, "owners": kept}, handle, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, path)
            except OSError:
                if tmp:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                _log("owner-records skipped: ownership write failed")
                return None
        reported_bytes = -1 if total_bytes is None else total_bytes
        _log(
            f"owner-records kept={len(kept)} removed={removed} "
            f"bundles={bundles} bytes={reported_bytes}"
        )
        return {
            "removed": removed,
            "kept": len(kept),
            "bundles": bundles,
            "bytes": reported_bytes,
        }


def prune_session_stores(*, now: float | None = None) -> dict[str, int] | None:
    """Prune expired, unreferenced official ACP session bundles across accounts.

    This uses the continuation checkpoint TTL/cap, preserves every unexpired
    Hermes session ID, and fails closed when the checkpoint inventory is not
    readable. It touches only ``.gemini/antigravity-acp`` conversation stores.
    """
    now = time.time() if now is None else now
    entries, meta, _problem = _load_registry_data()
    default_home, _explicit = _effective_default_home(meta)
    homes = {os.path.abspath(os.path.expanduser(default_home))}
    for entry in entries:
        home, _label, _priority, _key = _account(entry, default_home)
        if home:
            homes.add(os.path.abspath(os.path.expanduser(home)))

    totals = {"expired": 0, "capacity": 0, "bytes": 0, "failed": 0}
    with _session_gc_lock() as locked:
        if not locked:
            _log("session-gc skipped: cross-process lock unavailable")
            return None
        active = _active_hermes_session_ids(now=now)
        if active is None:
            _log("session-gc skipped: continuation checkpoint inventory unavailable")
            return None
        for home in sorted(homes):
            result = _prune_session_store(home, active, now=now)
            for key in totals:
                totals[key] += result[key]

    if any(totals.values()):
        _log(
            "session-gc expired={expired} capacity={capacity} failed={failed} bytes={bytes}".format(
                **totals
            )
        )
    return totals


@contextmanager
def _state_lock() -> Iterator[None]:
    """Serialize cursor/health updates across concurrent mux processes on POSIX."""
    lock_path = STATE_PATH + ".lock"
    directory = os.path.dirname(lock_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    try:
        lock = open(lock_path, "a+", encoding="utf-8")
    except OSError:
        yield
        return
    try:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()


def _cooldown_for(kind: str) -> float:
    if kind == "auth":
        return AUTH_COOLDOWN
    if kind == "quota":
        return QUOTA_COOLDOWN
    return CRASH_COOLDOWN


def _mark_failure(home: str, label: str, kind: str, detail: str = "") -> None:
    """Persist one observed failure without inspecting vendor credentials."""
    now = time.time()
    key = f"{label}\t{home}"
    with _state_lock():
        state = _load_state_unlocked()
        accounts = state["accounts"]
        current = accounts.get(key)
        current = current if isinstance(current, dict) else {}

        # One upstream failure may be repeated on stdout/stderr. Do not keep
        # extending the same cooldown for duplicate lines from the same event.
        last_at = current.get("last_failure_at", 0)
        if current.get("reason") == kind and isinstance(last_at, (int, float)) and now - last_at < 5:
            return

        cooldown_until = max(
            float(current.get("cooldown_until", 0) or 0),
            now + _cooldown_for(kind),
        )
        accounts[key] = {
            "label": label,
            "home": home,
            "reason": kind,
            "cooldown_until": cooldown_until,
            "last_failure_at": now,
            "failures": int(current.get("failures", 0) or 0) + 1,
            "detail": _redact(detail),
        }
        _save_state_unlocked(state)
    _log(f"quarantine {label}: {kind} until={int(cooldown_until)}")


def _affinity_pick(pool: list[tuple[int, int, str, str, str]], affinity: str) -> tuple[int, int, str, str, str]:
    """Rendezvous-hash one healthy tier so an affinity remaps only when health changes."""
    def score(row: tuple[int, int, str, str, str]) -> bytes:
        return hashlib.sha256(f"{affinity}\0{row[4]}".encode("utf-8", errors="surrogatepass")).digest()

    return max(pool, key=score)


def _pick_account(
    now: float | None = None,
    affinity: str | None = None,
    pin_affinity: bool = False,
) -> tuple[str, str, str]:
    """Balance new affinity assignments while preserving resumable session pins."""
    entries, meta, problem = _load_registry_data()
    if problem == "missing":
        return DEFAULT_HOME, "default", "no-registry"
    if problem:
        return "", "", "registry-invalid"

    default_home, default_explicit = _effective_default_home(meta)
    versioned = isinstance(meta.get("schema_version"), int)

    now = time.time() if now is None else now
    affinity_key = str(affinity or "").strip()
    affinity_digest = _affinity_digest(affinity_key) if affinity_key else ""
    rows = []
    for index, entry in enumerate(entries):
        raw_home = entry.get("home")
        missing_home = raw_home is None or (
            isinstance(raw_home, str) and not raw_home.strip()
        )
        if missing_home and versioned and not default_explicit:
            # Contract: a schema_version registry must never resolve an
            # absent home to process state (historical reference).
            _log(f"account-excluded idx={index} reason=missing-home")
            continue
        if missing_home and not default_explicit:
            _log(f"account-legacy-home idx={index} resolved=control-home-fallback")
        home, label, priority, key = _account(entry, default_home)
        if not missing_home and not os.path.isabs(home):
            _log(f"account-excluded idx={index} reason=home-not-absolute")
            continue
        rows.append((priority, index, home, label, key))
    if not rows:
        return "", "", "registry-invalid"

    with _state_lock():
        state = _load_state_unlocked()
        health = state["accounts"]
        cursor = state["cursor"]
        affinities = state["affinities"]
        _prune_affinity_assignments(affinities, now)

        def healthy_row(account_key: object) -> tuple[int, int, str, str, str] | None:
            if not isinstance(account_key, str):
                return None
            row = next((item for item in rows if item[4] == account_key), None)
            if row is None:
                return None
            record = health.get(account_key)
            record = record if isinstance(record, dict) else {}
            until = record.get("cooldown_until", 0)
            until = float(until) if isinstance(until, (int, float)) else 0.0
            return row if until <= now else None

        if affinity_key and pin_affinity:
            assignment = affinities.get(affinity_digest)
            assignment = assignment if isinstance(assignment, dict) else {}
            preferred_key = assignment.get("account_key")
            preferred = healthy_row(preferred_key)
            if preferred is not None:
                _store_affinity_assignment(
                    affinities,
                    affinity_digest,
                    preferred[4],
                    preferred[4],
                    now,
                )
                _save_state_unlocked(state)
                return preferred[2], preferred[3], "affinity"

            selected = healthy_row(assignment.get("selected_key"))
            if selected is not None:
                if isinstance(preferred_key, str) and any(
                    row[4] == preferred_key for row in rows
                ):
                    account_key = preferred_key
                    reason = "affinity-failover"
                else:
                    account_key = selected[4]
                    reason = "affinity"
                _store_affinity_assignment(
                    affinities,
                    affinity_digest,
                    account_key,
                    selected[4],
                    now,
                )
                _save_state_unlocked(state)
                return selected[2], selected[3], reason

        for priority in sorted({row[0] for row in rows}):
            pool = []
            for row in rows:
                if row[0] != priority:
                    continue
                record = health.get(row[4])
                record = record if isinstance(record, dict) else {}
                until = record.get("cooldown_until", 0)
                until = float(until) if isinstance(until, (int, float)) else 0.0
                if until <= now:
                    pool.append(row)
            if not pool:
                continue

            if affinity_key:
                assignment = affinities.get(affinity_digest)
                assignment = assignment if isinstance(assignment, dict) else {}
                preferred_key = assignment.get("account_key")
                selected_key = assignment.get("selected_key")
                preferred = next(
                    (row for row in rows if row[4] == preferred_key),
                    None,
                )

                if pin_affinity:
                    if preferred is not None and preferred in pool:
                        chosen = preferred
                        reason = "affinity"
                    else:
                        # On upgrade, an unrecorded live session follows the
                        # old deterministic route. During cooldown/priority
                        # failover the rendezvous fallback stays stable while
                        # the preferred account remains recorded for recovery.
                        chosen = _affinity_pick(pool, affinity_key)
                        reason = "affinity-failover" if preferred is not None else "affinity"
                    _store_affinity_assignment(
                        affinities,
                        affinity_digest,
                        preferred[4] if preferred is not None else chosen[4],
                        chosen[4],
                        now,
                    )
                    _save_state_unlocked(state)
                    return chosen[2], chosen[3], reason

                pool_keys = {row[4] for row in pool}
                counts = {key: 0 for key in pool_keys}
                for digest, record in affinities.items():
                    if digest == affinity_digest or not isinstance(record, dict):
                        continue
                    assigned_key = record.get("selected_key")
                    if assigned_key in counts:
                        counts[assigned_key] += 1

                least_assigned = min(counts.values())
                least_pool = [row for row in pool if counts[row[4]] == least_assigned]
                cursor_key = f"affinity:{priority}"
                raw_cursor = cursor.get(cursor_key, 0)
                position = (
                    raw_cursor
                    if isinstance(raw_cursor, int) and not isinstance(raw_cursor, bool)
                    else 0
                )
                position = max(position, 0)
                chosen = least_pool[position % len(least_pool)]
                cursor[cursor_key] = position + 1
                _store_affinity_assignment(
                    affinities,
                    affinity_digest,
                    chosen[4],
                    chosen[4],
                    now,
                )
                if _save_state_unlocked(state):
                    return chosen[2], chosen[3], "affinity-balanced"

                # Without a durable pin, the next resumed request could be
                # sent to a different account. Prefer the previous effective
                # account when it is healthy, otherwise use the old stable hash.
                previous_selected = next(
                    (row for row in pool if row[4] == selected_key),
                    None,
                )
                fallback = previous_selected or preferred
                if fallback is None or fallback not in pool:
                    fallback = _affinity_pick(pool, affinity_key)
                return fallback[2], fallback[3], "affinity-state-fallback"

            cursor_key = str(priority)
            raw_cursor = cursor.get(cursor_key, 0)
            position = int(raw_cursor) if isinstance(raw_cursor, int) else 0
            chosen = pool[position % len(pool)]
            cursor[cursor_key] = (position + 1) % len(pool)
            _save_state_unlocked(state)
            reason = "round-robin" if len(pool) > 1 else "priority"
            return chosen[2], chosen[3], reason

        # Every account is cooling down. Probe the one expected to recover
        # first instead of refusing service based on stale observations.
        candidates = []
        for row in rows:
            record = health.get(row[4])
            record = record if isinstance(record, dict) else {}
            until = record.get("cooldown_until", 0)
            until = float(until) if isinstance(until, (int, float)) else 0.0
            candidates.append((until, row[0], row[1], row))
        _, _, _, chosen = min(candidates)
        if affinity_key:
            assignment = affinities.get(affinity_digest)
            assignment = assignment if isinstance(assignment, dict) else {}
            preferred_key = assignment.get("account_key")
            if (
                pin_affinity
                and isinstance(preferred_key, str)
                and any(row[4] == preferred_key for row in rows)
            ):
                account_key = preferred_key
            else:
                account_key = chosen[4]
            _store_affinity_assignment(
                affinities,
                affinity_digest,
                account_key,
                chosen[4],
                now,
            )
            _save_state_unlocked(state)
        elif affinities:
            _save_state_unlocked(state)
        return chosen[2], chosen[3], "cooldown-probe"


def _classify_failure(text: str) -> str | None:
    if _QUOTA_RE.search(text):
        return "quota"
    if _AUTH_RE.search(text):
        return "auth"
    return None


def _iter_structured_error_details(value: object):
    """Yield explicit error metadata from an upstream ACP payload.

    Antigravity may report provider failures inside a successful JSON-RPC
    envelope (for example ``stepUpdate.state=STATE_ERROR`` with a nested
    ``error.httpCode=429``) instead of using the top-level JSON-RPC ``error``
    member.  Only inspect structural error fields; never scan arbitrary model
    text/content for quota-looking words.
    """
    if isinstance(value, dict):
        state = str(value.get("state") or "").strip().upper()
        explicit_state_error = state in {"STATE_ERROR", "ERROR", "FAILED", "FAILURE"}

        if "error" in value:
            yield value["error"]

        if explicit_state_error:
            detail = {
                key: value[key]
                for key in ("state", "errorMessage", "httpCode", "code", "reason")
                if key in value
            }
            if detail:
                yield detail

        # Some ACP bridges expose the HTTP status alongside an error message
        # without a state marker.  Treat that pair as explicit error metadata.
        if ("httpCode" in value or "code" in value) and "errorMessage" in value:
            yield {
                key: value[key]
                for key in ("errorMessage", "httpCode", "code", "reason")
                if key in value
            }

        for key, child in value.items():
            # ``content``/``text``/delta fields are model output and may discuss
            # quota errors as ordinary prose.  Do not recursively classify them.
            if key in {"content", "text", "textDelta", "thinking", "thinkingDelta"}:
                continue
            if isinstance(child, (dict, list)):
                yield from _iter_structured_error_details(child)
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, (dict, list)):
                yield from _iter_structured_error_details(child)


def _classify_json_error(line: str) -> tuple[str, str] | None:
    """Classify explicit structured ACP errors, never normal model content."""
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None

    for error_detail in _iter_structured_error_details(payload):
        detail = json.dumps(error_detail, ensure_ascii=False)
        kind = _classify_failure(detail)
        if kind:
            return kind, detail
    return None


def _path_kind(path: str) -> str:
    """Classify one path via lstat (final symlink component inspected)."""
    if not path:
        return "unset"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "unreadable"
    if stat.S_ISLNK(info.st_mode):
        return "symlink" if os.path.exists(path) else "broken-symlink"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISREG(info.st_mode):
        return "file"
    return "special"


def _identity(path: str):
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (info.st_dev, info.st_ino)


_REGISTRY_INVALID_MESSAGE = (
    "antigravity-acp-mux: the account registry is present but unusable "
    "(unreadable, malformed, unsupported schema_version, or no valid "
    "accounts); refusing a silent fallback — run the mux `doctor` command "
    "for the actionable report\n"
)


def run_doctor(env: Mapping[str, str] | None = None) -> int:
    """Print the resolved path contract; write nothing; print no secrets.

    Exit codes: 0 clean, 1 findings to review, 2 registry present but
    unusable.  Account labels are never printed; lanes appear only as a
    sha256 fingerprint prefix.  Credential locations are reported as
    existence flags; no credential file is ever opened.
    """
    values = dict(os.environ) if env is None else dict(env)
    layout = resolve_layout(values)
    lines = [f"contract-version={layout['contract_version']}"]
    warnings: list = []
    fatal = False

    lines.append(f"control-home={layout['control_home']}")
    lines.append(f"control-home-source={layout['sources']['control_home']}")

    registry = layout["registry_path"]
    registry_kind = _path_kind(registry)
    lines.append(f"registry-path={registry}")
    lines.append(f"registry-source={layout['sources']['registry']}")
    lines.append(f"registry-kind={registry_kind}")
    if registry_kind in ("symlink", "broken-symlink"):
        warnings.append(f"registry is {registry_kind} (durability during recreation)")

    entries, meta, problem = _load_registry_data(registry)
    if problem == "missing":
        lines.append("registry=absent (single-lane mode: only the default home is selectable)")
    elif problem:
        lines.append(f"registry-problem={problem}")
        warnings.append(f"registry {problem}")
        fatal = True

    declared = meta.get("default_home")
    if layout["sources"]["default_home"] == "ACP_MUX_DEFAULT_HOME":
        default_home, default_explicit = layout["default_home"], True
    elif isinstance(declared, str) and declared.strip():
        default_home = os.path.expanduser(declared.strip())
        default_explicit = True
    else:
        default_home, default_explicit = layout["default_home"], False
    versioned = isinstance(meta.get("schema_version"), int)
    lines.append(f"registry-schema={'1' if versioned else 'legacy'}")
    lines.append(f"default-home={default_home}")
    lines.append(
        "default-home-source="
        + (layout["sources"]["default_home"] if default_explicit else "control-home-fallback")
    )
    if not versioned and problem == "":
        warnings.append("registry is legacy/unversioned (add schema_version and default_home)")
    if not problem and entries and not default_explicit:
        warnings.append(
            "default home is not explicit (set ACP_MUX_DEFAULT_HOME or registry default_home)"
        )

    if not problem and entries is not None:
        lines.append(f"registry-accounts={len(entries)}")
        seen: dict = {}
        for index, entry in enumerate(entries):
            raw_home = entry.get("home")
            missing_home = raw_home is None or (
                isinstance(raw_home, str) and not raw_home.strip()
            )
            home, label, _priority, _key = _account(entry, default_home)
            status = "lane"
            if missing_home and versioned and not default_explicit:
                status = "excluded:missing-home-in-versioned-registry"
                warnings.append(f"account[{index}] omits home in a schema_version registry")
            elif missing_home and not default_explicit:
                status = "resolved-default:legacy-control-home"
                warnings.append(
                    f"account[{index}] home resolves to the process control home (legacy)"
                )
            elif missing_home:
                status = "resolved-default:explicit"
            elif not os.path.isabs(home):
                status = "excluded:home-not-absolute"
                warnings.append(f"account[{index}] home is not absolute")
            lane_kind = _path_kind(home)
            if lane_kind == "symlink":
                warnings.append(f"account[{index}] home is a symlink")
            elif lane_kind == "broken-symlink":
                warnings.append(f"account[{index}] home is a broken symlink")
            gemini = pinned_gemini_home(home)
            # Vendor auth store: existence only, contents never opened, and
            # the store directory (not any credential filename) is probed.
            store_dir = os.path.join(gemini, "antigravity-acp")
            lines.append(
                f"account[{index}] lane={_lane_fingerprint(home, label)} "
                f"home={home} home-kind={lane_kind} "
                f"gemini-home-exists={os.path.isdir(gemini)} "
                f"auth-store-dir-exists={os.path.isdir(store_dir)} "
                f"status={status}"
            )
            canonical = os.path.abspath(os.path.expanduser(home))
            if canonical in seen:
                warnings.append(f"accounts {seen[canonical]} and {index} share the same home")
            else:
                seen[canonical] = index

    state = layout["state_path"]
    state_kind = _path_kind(state)
    lines.append(f"state-path={state}")
    lines.append(f"state-source={layout['sources']['state']}")
    lines.append(f"state-kind={state_kind}")
    if state_kind in ("symlink", "broken-symlink"):
        warnings.append(f"state file is {state_kind}")
    if state_kind == "file":
        try:
            with open(state, encoding="utf-8") as fh:
                state_data = json.load(fh)
            if isinstance(state_data, dict):
                counts = " ".join(
                    f"{name}={len(state_data[name])}"
                    for name in ("cursor", "accounts", "affinities")
                    if isinstance(state_data.get(name), dict)
                )
                lines.append(f"state-records={counts or 'none'}")
            else:
                warnings.append("state file is not a JSON object")
        except (OSError, ValueError):
            warnings.append("state file is unreadable or malformed")

    log = layout["log_path"]
    log_kind = _path_kind(log)
    lines.append(f"log-path={log}")
    lines.append(f"log-source={layout['sources']['log']}")
    lines.append(f"log-kind={log_kind}")
    if log_kind in ("symlink", "broken-symlink"):
        warnings.append(f"log file is {log_kind}")
    if log_kind == "file":
        try:
            lines.append(f"log-size={os.path.getsize(log)}")
        except OSError:
            pass

    launcher = layout["par"]
    lines.append(f"server-launcher={launcher or 'unset'}")
    lines.append(f"server-launcher-source={layout['sources']['par']}")
    if launcher:
        exists = os.path.exists(launcher)
        lines.append(f"server-launcher-exists={exists}")
        if not exists:
            warnings.append("server launcher does not exist")
    else:
        warnings.append("server launcher is unset (ACP_MUX_PAR)")

    if values.get("GEMINI_HOME"):
        warnings.append(
            "parent GEMINI_HOME is set; mux lanes ignore it (pinned per account)"
        )

    # Alias / overlapping-mount detection: distinct configured strings that
    # resolve to the same underlying object are reported.  Two explicitly
    # configured paths are an informational alias (a reviewed migration may
    # rely on it); anything crossing config and derived defaults is a
    # warning because an overlapping bind mount usually explains it.
    candidates: dict = {}
    for name in _CONTROL_HOME_ENV_ORDER:
        if values.get(name):
            candidates[f"env:{name}"] = os.path.normpath(os.path.expanduser(values[name]))
    if (values.get("HERMES_HOME") or "").strip():
        candidates["env:HERMES_HOME"] = os.path.normpath(
            os.path.expanduser(values["HERMES_HOME"])
        )
    candidates["derived:control-home"] = layout["control_home"]
    for name in _REGISTRY_ENV_ORDER:
        if values.get(name):
            candidates[f"env:{name}"] = os.path.normpath(os.path.expanduser(values[name]))
    candidates["derived:registry-default"] = os.path.normpath(
        os.path.join(layout["control_home"], ".hermes", "acp-accounts.json")
    )
    names = sorted(candidates)
    for position, left in enumerate(names):
        for right in names[position + 1:]:
            if candidates[left] == candidates[right]:
                continue
            left_identity = _identity(candidates[left])
            if left_identity is None or left_identity != _identity(candidates[right]):
                continue
            if left.startswith("env:") and right.startswith("env:"):
                lines.append(f"alias={left}~{right} object={candidates[left]}")
            else:
                warnings.append(
                    f"{left} and {right} resolve to the same object "
                    f"({candidates[left]}); overlapping mount or symlink?"
                )

    for warning in warnings:
        lines.append(f"warning: {warning}")
    lines.append(f"doctor-findings={len(warnings)}")
    print("\n".join(lines))
    return 2 if fatal else (1 if warnings else 0)


def main() -> int:
    if sys.argv[1:2] in (["doctor"], ["--doctor"]):
        return run_doctor()
    if not PAR or not os.path.exists(PAR):
        sys.stderr.write("antigravity-acp-mux: set ACP_MUX_PAR to the official agy_acp_server.par\n")
        return 2

    # Buffer stdin until the first request (normally initialize), then bind one
    # official ACP child for the lifetime of this client session.
    upstream: subprocess.Popen[str] | None = None
    bound_home = ""
    bound_label = ""
    session_gc_run = False
    owner_prune_run = False
    pump_threads: list[threading.Thread] = []
    owner_relay = _SessionOwnerRelay()

    def pump_upstream_out() -> None:
        assert upstream is not None
        for line in upstream.stdout or ():
            failure = _classify_json_error(line)
            if failure:
                _mark_failure(bound_home, bound_label, failure[0], failure[1])
            sys.stdout.write(owner_relay.after(line, bound_home, bound_label))
            sys.stdout.flush()

    def pump_upstream_err() -> None:
        assert upstream is not None
        for line in upstream.stderr or ():
            redacted = _redact(line.rstrip("\n"))
            kind = _classify_failure(redacted)
            if kind:
                _mark_failure(bound_home, bound_label, kind, redacted)
            sys.stderr.write(redacted + "\n")
            sys.stderr.flush()

    def bind(home: str, label: str, reason: str) -> bool:
        nonlocal upstream, bound_home, bound_label
        env = dict(os.environ)
        env.pop("ACP_MUX_AFFINITY", None)
        env.pop("ACP_MUX_AFFINITY_PIN", None)
        env.pop("ACP_MUX_AFFINITY_TTL_SECONDS", None)
        env.pop("ACP_MUX_AFFINITY_MAX_ENTRIES", None)
        env.pop("ACP_MUX_SESSION_ID", None)
        env.pop("ACP_MUX_SESSION_GC", None)
        env["HOME"] = home
        env["GEMINI_HOME"] = pinned_gemini_home(home)
        violation = mcp_config_violation(env["GEMINI_HOME"])
        if violation is not None:
            _log(f"mcp-config-guard {label}: {violation}")
            _mark_failure(home, label, "mcp-config", violation)
            return False
        try:
            upstream = subprocess.Popen(
                [PAR, "--uid="],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            _log(f"spawn-failed {label}: {exc}")
            return False
        bound_home = home
        bound_label = label
        _log(f"bound account {label} ({reason}) pid={upstream.pid}")
        out_thread = threading.Thread(target=pump_upstream_out, daemon=True)
        err_thread = threading.Thread(target=pump_upstream_err, daemon=True)
        pump_threads.extend((out_thread, err_thread))
        out_thread.start()
        err_thread.start()
        return True

    try:
        for line in sys.stdin:
            method = ""
            payload: object = None
            try:
                payload = json.loads(line)
                method = str(payload.get("method") or "") if isinstance(payload, dict) else ""
            except (json.JSONDecodeError, ValueError):
                pass
            if upstream is None:
                if not session_gc_run:
                    if os.environ.get("ACP_MUX_SESSION_GC") == "1":
                        prune_session_stores()
                    else:
                        _log("native session GC disabled (opt in: ACP_MUX_SESSION_GC=1)")
                    session_gc_run = True
                if not owner_prune_run:
                    prune_session_owners()
                    owner_prune_run = True
                resume_id = os.environ.get("ACP_MUX_SESSION_ID", "")
                owner = _resolve_session_owner(resume_id) if resume_id else None
                if owner is not None:
                    home, label = owner
                    reason = "session-owner"
                else:
                    home, label, reason = _pick_account(
                        affinity=os.environ.get("ACP_MUX_AFFINITY", ""),
                        pin_affinity=os.environ.get("ACP_MUX_AFFINITY_PIN") == "1",
                    )
                if reason == "registry-invalid":
                    sys.stderr.write(_REGISTRY_INVALID_MESSAGE)
                    return 2
                if not bind(home, label, reason):
                    # historical reference: a selected lane must never be replaced by
                    # a different account's HOME inside one client session.
                    sys.stderr.write(
                        "antigravity-acp-mux: selected lane spawn failed for "
                        f"lane={_lane_fingerprint(home, label)}; refusing a "
                        "silent account fallback (see mux log)\n"
                    )
                    return 2
                _log(f"selected {bound_label} via {reason} for {method or 'unknown'}")

            owner_error = owner_relay.before(payload, bound_home, bound_label)
            if owner_error is not None:
                sys.stdout.write(owner_error)
                sys.stdout.flush()
                continue
            assert upstream is not None and upstream.stdin is not None
            if upstream.poll() not in (None, 0):
                _mark_failure(bound_home, bound_label, "crash", f"exit={upstream.returncode}")
                return 0
            try:
                upstream.stdin.write(line)
                upstream.stdin.flush()
            except (OSError, ValueError):
                returncode = upstream.poll()
                if returncode not in (None, 0):
                    _mark_failure(bound_home, bound_label, "crash", f"exit={returncode}")
                return 0
    finally:
        if upstream is not None:
            if upstream.stdin is not None and not upstream.stdin.closed:
                try:
                    upstream.stdin.close()
                except OSError:
                    pass
            if upstream.poll() is None:
                try:
                    # Give a well-behaved ACP child a chance to flush its final
                    # JSON-RPC response and exit after stdin EOF.
                    upstream.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    upstream.terminate()
                    try:
                        upstream.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        upstream.kill()
                        upstream.wait(timeout=5)
            for thread in pump_threads:
                thread.join(timeout=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
