"""Durable learned native-session limits shared by Hermes profiles.

The official Antigravity ACP v1 protocol does not proactively expose its
checkpoint/trajectory budget. The provider therefore starts from the model
context ceiling and learns stricter server limits from failures. Learned
limits are operational metadata only -- model id, token count, source, and
timestamp -- and contain no credentials or conversation content.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator

from .hermes_compat import get_hermes_home

logger = logging.getLogger(__name__)

_STATE_VERSION = 1
_DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60


@dataclass(frozen=True)
class NativeLimitState:
    value: int
    source: str
    updated_at: float


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _profile_neutral_hermes_home(path: Path) -> Path:
    """Collapse a profile-scoped Hermes home to the shared Hermes root."""
    resolved = path.expanduser().resolve()
    if resolved.parent.name == "profiles":
        return resolved.parent.parent
    return resolved


def _state_path() -> Path:
    if override := os.environ.get(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", ""
    ).strip():
        return Path(override).expanduser()

    return (
        _profile_neutral_hermes_home(get_hermes_home())
        / "cache"
        / "antigravity-acp-native-limits.json"
    )


@contextlib.contextmanager
def _cross_process_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+", encoding="utf-8")
    try:
        with contextlib.suppress(OSError):
            os.chmod(lock_path, 0o600)
        try:
            import fcntl
        except ImportError:  # pragma: no cover - Windows fallback
            fcntl = None
        if fcntl is not None:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()


def _decode_state(raw: object) -> NativeLimitState | None:
    if not isinstance(raw, dict):
        return None
    try:
        value = int(raw.get("value") or 0)
        source = str(raw.get("source") or "").strip()
        updated_at = float(raw.get("updated_at") or 0)
    except (TypeError, ValueError):
        return None
    if value <= 0 or not source or updated_at <= 0:
        return None
    return NativeLimitState(value=value, source=source, updated_at=updated_at)


class NativeLimitRegistry:
    """Small cross-process cache of per-model native ACP session limits."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._memory: dict[str, dict[str, NativeLimitState]] = {}

    @staticmethod
    def _path_key(path: Path) -> str:
        return str(path.expanduser().resolve())

    @staticmethod
    def _ttl_seconds() -> int:
        return _positive_int_env(
            "HERMES_ANTIGRAVITY_ACP_LIMIT_TTL_SECONDS", _DEFAULT_TTL_SECONDS
        )

    def _purge(
        self, states: dict[str, NativeLimitState], now: float
    ) -> bool:
        cutoff = now - self._ttl_seconds()
        stale = [key for key, state in states.items() if state.updated_at < cutoff]
        for key in stale:
            states.pop(key, None)
        return bool(stale)

    @staticmethod
    def _read_file(path: Path) -> dict[str, NativeLimitState]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}
        if not isinstance(payload, dict) or payload.get("version") != _STATE_VERSION:
            return {}
        raw_limits = payload.get("limits")
        if not isinstance(raw_limits, dict):
            return {}
        decoded: dict[str, NativeLimitState] = {}
        for key, raw in raw_limits.items():
            state = _decode_state(raw)
            if state is not None:
                decoded[str(key)] = state
        return decoded

    @staticmethod
    def _write_file(path: Path, states: dict[str, NativeLimitState]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": _STATE_VERSION,
            "limits": {key: asdict(state) for key, state in states.items()},
        }
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
        )
        tmp_path = Path(tmp_name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    payload,
                    fh,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
            with contextlib.suppress(OSError):
                dir_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp_path.unlink()

    def get(self, model_key: str) -> NativeLimitState | None:
        if not model_key:
            return None
        path = _state_path()
        path_key = self._path_key(path)
        with self._lock:
            now = time.time()
            disk = self._read_file(path)
            changed = self._purge(disk, now)
            self._memory[path_key] = disk
            if changed:
                try:
                    with _cross_process_lock(path):
                        latest = self._read_file(path)
                        self._purge(latest, now)
                        self._write_file(path, latest)
                        self._memory[path_key] = latest
                except OSError as exc:
                    logger.debug(
                        "Could not prune stale Antigravity ACP native limits %s: %s",
                        path,
                        exc,
                    )
            return self._memory[path_key].get(model_key)

    def put(
        self,
        model_key: str,
        value: int,
        *,
        source: str,
        only_lower: bool = False,
    ) -> NativeLimitState | None:
        if not model_key or value <= 0:
            return None
        path = _state_path()
        path_key = self._path_key(path)
        state = NativeLimitState(
            value=int(value), source=str(source or "observed"), updated_at=time.time()
        )
        with self._lock:
            try:
                with _cross_process_lock(path):
                    states = self._read_file(path)
                    self._purge(states, state.updated_at)
                    existing = states.get(model_key)
                    if only_lower and existing is not None and existing.value <= state.value:
                        state = existing
                    else:
                        states[model_key] = state
                    self._write_file(path, states)
                    self._memory[path_key] = states
            except OSError as exc:
                logger.warning(
                    "Antigravity ACP native-limit checkpoint write failed for %s; "
                    "continuing with process-local state: %s",
                    path,
                    exc,
                )
                states = self._memory.setdefault(path_key, {})
                existing = states.get(model_key)
                if not (
                    only_lower
                    and existing is not None
                    and existing.value <= state.value
                ):
                    states[model_key] = state
                state = states.get(model_key, state)
            return state


native_limit_registry = NativeLimitRegistry()
