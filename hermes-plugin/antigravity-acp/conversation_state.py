"""Conversation state that outlives individual Hermes provider client objects.

Hermes is free to rebuild an ``AIAgent`` or request-scoped provider client when
its tool/config signature changes, after an interrupt, or during plugin reload.
The native Antigravity ACP session is a conversation resource, not a transport
client resource, so its resume metadata must survive those rebuilds.

The registry keeps a process-wide cache and a small 0600 JSON checkpoint. It
stores ACP session/frontier metadata plus aggregate usage totals keyed by an
explicit Hermes session ID. Usage totals contain no prompts, commands, paths,
or raw native ACP session IDs; the native identifier is stored only as a hash.
OAuth/access tokens and provider credentials are never persisted. A stale/moved
ACP session is harmless: ``session/resume`` will fail and the caller performs
one hardened full replay before replacing the checkpoint with the new session.
"""

from __future__ import annotations

import contextlib
import json
import logging
import math
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterator

from .hermes_compat import get_hermes_home

logger = logging.getLogger(__name__)

_STATE_VERSION = 1
_DEFAULT_TTL_SECONDS = 24 * 60 * 60
_DEFAULT_MAX_ENTRIES = 512
_USAGE_TOTALS_SCHEMA = "antigravity-acp-usage-totals-v1"
# Issue #33 R2: additive marker identifying the behaviorally-verified
# per-call-delta
# accumulation semantics.  Stamped on entries whose ENTIRE accumulated total
# was produced under this contract (fresh entries, or entries already
# carrying the marker).  A legacy entry that later receives a delta keeps the
# key ABSENT: its stored sum mixes pre-marker history and must not claim the
# verified classification.  Readers must treat a missing key as "pre-marker,
# same v1 accumulation contract".
_USAGE_TOTALS_SEMANTICS = "per_model_call_consumption_delta"
_USAGE_TOTALS_PROVENANCE = "acp.usage_update.delta_sum(main-agent-only, may under-report)"
_UNATTRIBUTED_MODEL = "__unattributed__"
# Fleet diagnostics (historical reference): every usage_update frame carrying ``used`` is
# counted once as frames_seen; a frame rejected before reaching add_usage_delta
# increments exactly one reason counter. Silent drops are the failure mode this
# exists to eliminate.
_USAGE_FRAME_COUNTER_KEYS = (
    "frames_seen",
    "dropped_invalid",
    "dropped_no_session_identity",
    "dropped_no_native_session",
    # Issue #6 gates: each is an explicit, non-silent drop reason.
    "dropped_semantics_unverified",
    "dropped_outside_prompt_turn",
    "dropped_zero",
    # Dynamic canary: server-reported inputTokens diverged from local growth
    # by an order of magnitude; the turn's usage was rejected before it could
    # reach the Core compression gate.
    "dropped_inflated_turn_usage",
)

# Dynamic consumption-semantics verdicts (replaces the retired hardcoded
# version whitelist).  Keyed by the ``name|title|version`` identity an ACP
# server self-reports at ``initialize``; a verdict is EARNED at runtime by the
# per-turn growth-consistency gate in client.py, never granted by a version
# string.  Promotion requires ``SEMANTICS_PROMOTE_AFTER`` consecutive
# consistent tested turns; any inconsistency demotes immediately.
# The verdict describes the SERVER's behavior, not this home's, so it lives in
# a machine-wide store shared by every profile home under the same Hermes root
# (see ``_semantics_store_path``): one home earns the verdict, every profile
# starts verified.  The per-turn safety gate in client.py stays per-process
# regardless — sharing verdicts never shares or delegates safety decisions.
_SEMANTICS_VERDICTS_SCHEMA = "antigravity-acp-usage-semantics-verdicts-v1"
_SEMANTICS_STORE_VERSION = 1
_SEMANTICS_VERDICT_VERIFIED = "behaviorally_verified"
_SEMANTICS_VERDICT_UNVERIFIED = "unverified"
SEMANTICS_PROMOTE_AFTER = 5
_SEMANTICS_MAX_IDENTITIES = 64


@dataclass(frozen=True)
class ACPConversationState:
    session_id: str
    context_fingerprint: str
    request_fingerprints: tuple[str, ...]
    response_fingerprint: str
    updated_at: float
    # Client-estimated native session size (tokens).  The ACP v1 protocol never
    # reports usage, so the plugin tracks its own conservative estimate and
    # rotates the session proactively before the effective native-session cap.
    # That cap starts from the model ceiling and may be lowered by durable
    # server/inferred observations in native_limit_state.py.
    native_tokens: int = 0
    # Fingerprint only: when the last native request was permission-denied,
    # retain the user objective's identity for one safe continuation/replay.
    # The objective text remains in Hermes' request history and is never written
    # to this checkpoint.
    denied_request_fingerprint: str = ""
    # ACP resume responses may omit model metadata; preserve the model actually
    # active for this native session so later completions remain attributable.
    effective_model: str = ""


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _state_path() -> Path:
    if override := os.environ.get("HERMES_ANTIGRAVITY_ACP_STATE_FILE", "").strip():
        return Path(override).expanduser()
    return get_hermes_home() / "cache" / "antigravity-acp-sessions.json"


def _semantics_store_path() -> Path:
    """Machine-wide verdict store shared by every profile home.

    A consumption-semantics verdict describes the SERVER's behavior (identity
    ``name|title|version``), not this home's, so one home's earned evidence
    must serve every profile under the same Hermes root instead of each home
    re-paying the promotion warm-up for the same server.  Resolution:

    - ``HERMES_ANTIGRAVITY_ACP_SEMANTICS_FILE`` overrides the full path.
    - ``<root>/profiles/<name>`` homes resolve to ``<root>/shared/...``.
    - A plain ``<root>`` home resolves to ``<root>/shared/...`` too, so the
      main home and its profiles land on the SAME file in both the
      ``~/.hermes`` and the deployed ``<root>/profiles/<name>`` layouts.

    The per-turn growth gate in client.py stays per-process: sharing verdicts
    never delegates safety.
    """
    if override := os.environ.get("HERMES_ANTIGRAVITY_ACP_SEMANTICS_FILE", "").strip():
        return Path(override).expanduser()
    home = get_hermes_home()
    try:
        resolved = home.resolve()
    except OSError:  # pragma: no cover - unreadable home during resolution
        resolved = home
    root = resolved.parent.parent if resolved.parent.name == "profiles" else resolved
    return root / "shared" / "antigravity-acp-semantics.json"


@contextlib.contextmanager
def _cross_process_lock(path: Path) -> Iterator[None]:
    """Best-effort process lock; thread locking still applies on every platform."""
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


def _decode_state(raw: object) -> ACPConversationState | None:
    if not isinstance(raw, dict):
        return None
    try:
        session_id = str(raw.get("session_id") or "").strip()
        context_fingerprint = str(raw.get("context_fingerprint") or "").strip()
        response_fingerprint = str(raw.get("response_fingerprint") or "").strip()
        fingerprints_raw = raw.get("request_fingerprints") or []
        request_fingerprints = tuple(str(item) for item in fingerprints_raw)
        updated_at = float(raw.get("updated_at") or 0)
    except (TypeError, ValueError):
        return None
    if not session_id or not context_fingerprint or not response_fingerprint or not updated_at:
        return None
    try:
        native_tokens = int(raw.get("native_tokens") or 0)
    except (TypeError, ValueError):
        native_tokens = 0
    denied_request_fingerprint = str(raw.get("denied_request_fingerprint") or "")
    effective_model = str(raw.get("effective_model") or "").strip()
    return ACPConversationState(
        session_id=session_id,
        context_fingerprint=context_fingerprint,
        request_fingerprints=request_fingerprints,
        response_fingerprint=response_fingerprint,
        updated_at=updated_at,
        native_tokens=max(0, native_tokens),
        denied_request_fingerprint=denied_request_fingerprint,
        effective_model=effective_model,
    )


class ConversationStateRegistry:
    """Shared ACP state with atomic, bounded disk persistence."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._memory: dict[str, dict[str, ACPConversationState]] = {}
        self._loaded_paths: set[str] = set()

    @staticmethod
    def _path_key(path: Path) -> str:
        return str(path.expanduser().resolve())

    @staticmethod
    def _ttl_seconds() -> int:
        return _positive_int_env(
            "HERMES_ANTIGRAVITY_ACP_STATE_TTL_SECONDS", _DEFAULT_TTL_SECONDS
        )

    @staticmethod
    def _max_entries() -> int:
        return _positive_int_env(
            "HERMES_ANTIGRAVITY_ACP_STATE_MAX_ENTRIES", _DEFAULT_MAX_ENTRIES
        )

    def _purge(self, states: dict[str, ACPConversationState], now: float) -> bool:
        changed = False
        cutoff = now - self._ttl_seconds()
        for key in [key for key, state in states.items() if state.updated_at < cutoff]:
            states.pop(key, None)
            changed = True
        max_entries = self._max_entries()
        if len(states) > max_entries:
            oldest = sorted(states.items(), key=lambda item: item[1].updated_at)
            for key, _ in oldest[: len(states) - max_entries]:
                states.pop(key, None)
                changed = True
        return changed

    @staticmethod
    def _read_payload(path: Path) -> dict[str, Any]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {"version": _STATE_VERSION, "states": {}}
        if not isinstance(payload, dict) or payload.get("version") != _STATE_VERSION:
            return {"version": _STATE_VERSION, "states": {}}
        raw_states = payload.get("states")
        if not isinstance(raw_states, dict):
            return {"version": _STATE_VERSION, "states": {}}
        decoded: dict[str, Any] = {
            "version": _STATE_VERSION,
            # Keep the original states payload intact when changing usage totals.
            "states": raw_states,
        }
        raw_totals = payload.get("usage_totals")
        if isinstance(raw_totals, dict):
            decoded["usage_totals"] = {
                key: value
                for key, value in raw_totals.items()
                if isinstance(key, str) and isinstance(value, dict)
            }
        raw_counters = payload.get("usage_drop_counters")
        if isinstance(raw_counters, dict):
            decoded["usage_drop_counters"] = {
                key: value
                for key, value in raw_counters.items()
                if isinstance(key, str)
                and isinstance(value, int)
                and not isinstance(value, bool)
                and value >= 0
            }
        raw_verdicts = payload.get("usage_semantics_verdicts")
        if isinstance(raw_verdicts, dict):
            decoded["usage_semantics_verdicts"] = {
                key: value
                for key, value in raw_verdicts.items()
                if isinstance(key, str) and key and isinstance(value, dict)
            }
        return decoded

    @staticmethod
    def _read_file(path: Path) -> dict[str, ACPConversationState]:
        payload = ConversationStateRegistry._read_payload(path)
        raw_states = payload["states"]
        decoded: dict[str, ACPConversationState] = {}
        for key, raw in raw_states.items():
            state = _decode_state(raw)
            if state is not None:
                decoded[str(key)] = state
        return decoded

    @staticmethod
    def _write_payload(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
        )
        tmp_path = Path(tmp_name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
            # Persist the rename itself where the filesystem supports directory fsync.
            with contextlib.suppress(OSError):
                dir_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp_path.unlink()

    @staticmethod
    def _write_file(
        path: Path,
        states: dict[str, ACPConversationState],
        usage_totals: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        existing = ConversationStateRegistry._read_payload(path)
        if usage_totals is None:
            usage_totals = existing.get("usage_totals", {})
        payload: dict[str, Any] = {
            "version": _STATE_VERSION,
            "states": {
                key: {
                    **asdict(state),
                    "request_fingerprints": list(state.request_fingerprints),
                }
                for key, state in states.items()
            },
        }
        if usage_totals:
            payload["usage_totals"] = usage_totals
        # A state save must not erase diagnostic counters written by
        # note_usage_frame between this read and the rename (historical reference follow-up).
        counters = existing.get("usage_drop_counters")
        if isinstance(counters, dict) and counters:
            payload["usage_drop_counters"] = counters
        # Legacy bridge: verdicts earned per-home before the shared-store move
        # stay readable (frozen) until this identity's first shared-store
        # record replaces them; a state save must not erase that evidence.
        verdicts = existing.get("usage_semantics_verdicts")
        if isinstance(verdicts, dict) and verdicts:
            payload["usage_semantics_verdicts"] = verdicts
        ConversationStateRegistry._write_payload(path, payload)

    @staticmethod
    def _valid_usage_number(value: Any) -> bool:
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return value >= 0
        return isinstance(value, float) and math.isfinite(value) and value >= 0

    def add_usage_delta(
        self,
        hermes_session_id: str,
        *,
        model: str,
        used: int | float,
        native_session_id_hash: str,
    ) -> None:
        """Atomically add one observed ACP usage delta for an explicit Hermes session."""
        session_id = str(hermes_session_id or "").strip()
        model_name = str(model or "").strip()
        native_hash = str(native_session_id_hash or "").strip()
        if (
            not session_id
            or not model_name
            or not native_hash.startswith("sha256:")
            or not self._valid_usage_number(used)
        ):
            return

        path = _state_path()
        with self._lock:
            try:
                with _cross_process_lock(path):
                    payload = self._read_payload(path)
                    raw_totals = payload.get("usage_totals")
                    totals = raw_totals if isinstance(raw_totals, dict) else {}
                    previous = totals.get(session_id)
                    now = time.time()
                    if (
                        isinstance(previous, dict)
                        and previous.get("schema") == _USAGE_TOTALS_SCHEMA
                        and previous.get("hermes_session_id") == session_id
                        and self._valid_usage_number(previous.get("summed_tokens"))
                        and isinstance(previous.get("frames_observed"), int)
                        and not isinstance(previous.get("frames_observed"), bool)
                        and previous["frames_observed"] >= 0
                        and self._valid_usage_number(previous.get("first_seen"))
                    ):
                        previous_sum = previous["summed_tokens"]
                        summed_tokens = previous_sum + used
                        frames_observed = previous["frames_observed"] + 1
                        first_seen = previous["first_seen"]
                        accumulated = True

                        raw_by_model = previous.get("by_model")
                        if isinstance(raw_by_model, dict) and all(
                            isinstance(name, str)
                            and name
                            and self._valid_usage_number(tokens)
                            for name, tokens in raw_by_model.items()
                        ):
                            by_model = dict(raw_by_model)
                            attributed_tokens = sum(by_model.values())
                            if attributed_tokens <= previous_sum:
                                unattributed_tokens = previous_sum - attributed_tokens
                                if unattributed_tokens:
                                    by_model[_UNATTRIBUTED_MODEL] = (
                                        by_model.get(_UNATTRIBUTED_MODEL, 0)
                                        + unattributed_tokens
                                    )
                            else:
                                by_model = {_UNATTRIBUTED_MODEL: previous_sum}
                        elif (
                            previous["frames_observed"] == 1
                            and isinstance(previous.get("model"), str)
                            and previous["model"].strip()
                        ):
                            # A legacy one-frame total is safely attributable;
                            # older multi-frame scalar totals may already mix models.
                            by_model = {previous["model"].strip(): previous_sum}
                        elif previous_sum:
                            by_model = {_UNATTRIBUTED_MODEL: previous_sum}
                        else:
                            by_model = {}
                    else:
                        summed_tokens = used
                        frames_observed = 1
                        first_seen = now
                        by_model = {}
                        accumulated = False

                    if not self._valid_usage_number(summed_tokens):
                        return
                    by_model[model_name] = by_model.get(model_name, 0) + used
                    aggregate_model = (
                        model_name if set(by_model) == {model_name} else None
                    )
                    totals[session_id] = {
                        "schema": _USAGE_TOTALS_SCHEMA,
                        "hermes_session_id": session_id,
                        "model": aggregate_model,
                        "summed_tokens": summed_tokens,
                        "by_model": by_model,
                        "frames_observed": frames_observed,
                        "first_seen": first_seen,
                        "last_seen": now,
                        "native_session_id_hash": native_hash,
                        "provenance": _USAGE_TOTALS_PROVENANCE,
                    }
                    # Issue #33 R2: stamp the semantics marker only when the
                    # whole accumulated total is produced under this contract
                    # (fresh entry, or an entry already carrying it).  A mixed
                    # legacy+verified aggregate keeps the key absent so it
                    # never claims the verified classification.
                    if not accumulated or "semantics" in (previous or {}):
                        totals[session_id]["semantics"] = _USAGE_TOTALS_SEMANTICS
                    payload["usage_totals"] = totals
                    self._write_payload(path, payload)
            except OSError as exc:
                logger.warning(
                    "Antigravity ACP usage totals checkpoint write failed; "
                    "response continues without the latest usage total: %s",
                    exc,
                )

    def note_usage_frame(self, key: str) -> None:
        """Persist one usage_update frame decision for fleet diagnostics (historical reference).

        Counters live additively beside ``usage_totals`` in the same store; a
        counter write failure never breaks the response path.
        """
        if key not in _USAGE_FRAME_COUNTER_KEYS:
            return
        path = _state_path()
        with self._lock:
            try:
                with _cross_process_lock(path):
                    payload = self._read_payload(path)
                    counters = payload.get("usage_drop_counters")
                    counters = dict(counters) if isinstance(counters, dict) else {}
                    current = counters.get(key)
                    counted = (
                        current
                        if isinstance(current, int) and not isinstance(current, bool) and current >= 0
                        else 0
                    )
                    counters[key] = counted + 1
                    payload["usage_drop_counters"] = counters
                    self._write_payload(path, payload)
            except OSError as exc:
                logger.warning(
                    "Antigravity ACP usage frame counters checkpoint write failed; "
                    "response continues without the diagnostic counter: %s",
                    exc,
                )

    @staticmethod
    def _read_shared_verdicts(path: Path) -> dict[str, Any]:
        """Decode the machine-wide verdict payload (empty on any defect)."""
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}
        if (
            not isinstance(payload, dict)
            or payload.get("version") != _SEMANTICS_STORE_VERSION
        ):
            return {}
        raw = payload.get("usage_semantics_verdicts")
        if not isinstance(raw, dict):
            return {}
        return {
            key: value
            for key, value in raw.items()
            if isinstance(key, str) and key and isinstance(value, dict)
        }

    @staticmethod
    def _legacy_verdict_entry(per_home_path: Path, identity_key: str) -> dict[str, Any] | None:
        """One identity's verdict from the retired per-home location, if any.

        Upgrade bridge only: verdicts earned in the per-home store before the
        shared-store move serve until this identity's first shared-store
        record replaces them.  No lock is taken here; the per-home file is
        replaced atomically, so a lock-free read yields a whole snapshot.
        """
        payload = ConversationStateRegistry._read_payload(per_home_path)
        verdicts = payload.get("usage_semantics_verdicts")
        if not isinstance(verdicts, dict):
            return None
        entry = verdicts.get(identity_key)
        return entry if isinstance(entry, dict) else None

    @staticmethod
    def _verdict_from_entry(entry: Any) -> str:
        if (
            isinstance(entry, dict)
            and entry.get("schema") == _SEMANTICS_VERDICTS_SCHEMA
            and entry.get("verdict") == _SEMANTICS_VERDICT_VERIFIED
        ):
            return _SEMANTICS_VERDICT_VERIFIED
        return _SEMANTICS_VERDICT_UNVERIFIED

    def semantics_verdict(self, identity_key: str) -> str:
        """Read one identity's consumption-semantics verdict (fail closed)."""
        if not identity_key:
            return _SEMANTICS_VERDICT_UNVERIFIED
        path = _semantics_store_path()
        with self._lock:
            try:
                with _cross_process_lock(path):
                    verdicts = self._read_shared_verdicts(path)
            except OSError:
                return _SEMANTICS_VERDICT_UNVERIFIED
        entry = verdicts.get(identity_key)
        if entry is None:
            entry = self._legacy_verdict_entry(_state_path(), identity_key)
        return self._verdict_from_entry(entry)

    def record_semantics_evidence(self, identity_key: str, *, ok: bool) -> dict[str, Any]:
        """Fold one growth-consistency observation into an identity's verdict.

        Promotion: ``SEMANTICS_PROMOTE_AFTER`` consecutive consistent tested
        turns.  Demotion: any inconsistent turn resets the consecutive streak
        and revokes a prior promotion (a server may re-earn verification after
        a fix).  Entries are bounded (least-recently-seen evicted); a write
        failure never breaks the response path.
        """
        identity_key = str(identity_key or "").strip()
        if not identity_key:
            return {}
        path = _semantics_store_path()
        updated: dict[str, Any] = {}
        with self._lock:
            try:
                with _cross_process_lock(path):
                    verdicts = self._read_shared_verdicts(path)
                    previous = verdicts.get(identity_key)
                    if previous is None:
                        # Upgrade bridge: continue the streak a per-home store
                        # earned before the shared-store move.
                        previous = self._legacy_verdict_entry(
                            _state_path(), identity_key
                        )
                    now = time.time()
                    if (
                        isinstance(previous, dict)
                        and previous.get("schema") == _SEMANTICS_VERDICTS_SCHEMA
                        and isinstance(previous.get("consistent_turns"), int)
                        and not isinstance(previous.get("consistent_turns"), bool)
                        and previous["consistent_turns"] >= 0
                        and isinstance(previous.get("rejected_turns"), int)
                        and not isinstance(previous.get("rejected_turns"), bool)
                        and previous["rejected_turns"] >= 0
                        and self._valid_usage_number(previous.get("first_seen"))
                    ):
                        consistent = previous["consistent_turns"]
                        rejected = previous["rejected_turns"]
                        first_seen = previous["first_seen"]
                        prior_verdict = str(previous.get("verdict") or "")
                    else:
                        consistent = 0
                        rejected = 0
                        first_seen = now
                        prior_verdict = _SEMANTICS_VERDICT_UNVERIFIED
                    if ok:
                        consistent += 1
                        verdict = (
                            _SEMANTICS_VERDICT_VERIFIED
                            if consistent >= SEMANTICS_PROMOTE_AFTER
                            else _SEMANTICS_VERDICT_UNVERIFIED
                        )
                    else:
                        consistent = 0
                        rejected += 1
                        verdict = _SEMANTICS_VERDICT_UNVERIFIED
                    updated = {
                        "schema": _SEMANTICS_VERDICTS_SCHEMA,
                        "verdict": verdict,
                        "consistent_turns": consistent,
                        "rejected_turns": rejected,
                        "first_seen": first_seen,
                        "last_seen": now,
                        "provenance": "behavioral_growth_correlation",
                    }
                    verdicts[identity_key] = updated
                    if len(verdicts) > _SEMANTICS_MAX_IDENTITIES:
                        oldest = sorted(
                            verdicts.items(),
                            key=lambda item: (
                                float(item[1]["last_seen"])
                                if isinstance(item[1], dict)
                                and self._valid_usage_number(item[1].get("last_seen"))
                                else 0.0
                            ),
                        )
                        for key, _ in oldest[: len(verdicts) - _SEMANTICS_MAX_IDENTITIES]:
                            if key != identity_key:
                                verdicts.pop(key, None)
                    self._write_payload(
                        path,
                        {
                            "version": _SEMANTICS_STORE_VERSION,
                            "usage_semantics_verdicts": verdicts,
                        },
                    )
            except OSError as exc:
                logger.warning(
                    "Antigravity ACP semantics verdict checkpoint write failed; "
                    "response continues without the verdict update: %s",
                    exc,
                )
                return updated or {}
        if updated.get("verdict") != prior_verdict:
            logger.info(
                "Antigravity ACP consumption-semantics verdict for server "
                "identity changed: %s -> %s (consistent_turns=%d, rejected_turns=%d)",
                identity_key,
                updated.get("verdict"),
                updated.get("consistent_turns", 0),
                updated.get("rejected_turns", 0),
            )
        return updated

    def _ensure_loaded(self, path: Path, path_key: str) -> dict[str, ACPConversationState]:
        states = self._memory.setdefault(path_key, {})
        if path_key not in self._loaded_paths:
            disk = self._read_file(path)
            states.update(disk)
            self._purge(states, time.time())
            self._loaded_paths.add(path_key)
        return states

    def get(self, affinity_key: str) -> ACPConversationState | None:
        if not affinity_key:
            return None
        path = _state_path()
        path_key = self._path_key(path)
        with self._lock:
            states = self._ensure_loaded(path, path_key)
            # Atomic replace makes lock-free reads safe.  Refresh the one requested
            # key from disk so a sibling gateway/process can advance the native ACP
            # frontier without this process serving a stale session id forever.
            disk_state = self._read_file(path).get(affinity_key)
            state = states.get(affinity_key)
            if disk_state is not None and (state is None or disk_state.updated_at > state.updated_at):
                states[affinity_key] = state = disk_state
            if state is None:
                return None
            if state.updated_at < time.time() - self._ttl_seconds():
                states.pop(affinity_key, None)
                try:
                    with _cross_process_lock(path):
                        disk = self._read_file(path)
                        disk.pop(affinity_key, None)
                        self._purge(disk, time.time())
                        self._write_file(path, disk)
                except OSError as exc:
                    logger.debug("Could not prune stale Antigravity ACP state %s: %s", path, exc)
                return None
            return state

    def put(self, affinity_key: str, state: ACPConversationState) -> None:
        if not affinity_key:
            return
        path = _state_path()
        path_key = self._path_key(path)
        with self._lock:
            # Conversation continuity must never depend on checkpoint I/O: publish
            # process-wide memory first, then persist best-effort.
            states = self._ensure_loaded(path, path_key)
            states[affinity_key] = state
            self._purge(states, time.time())
            try:
                with _cross_process_lock(path):
                    # Merge with the latest disk snapshot so another gateway/process
                    # cannot lose unrelated entries via last-writer-wins replacement.
                    disk = self._read_file(path)
                    existing = disk.get(affinity_key)
                    if existing is None or state.updated_at >= existing.updated_at:
                        disk[affinity_key] = state
                    self._purge(disk, time.time())
                    self._write_file(path, disk)
                    self._memory[path_key].update(disk)
            except OSError as exc:
                logger.warning(
                    "Antigravity ACP continuation checkpoint write failed for %s; "
                    "continuing with process-local state: %s", path, exc,
                )

    def delete(self, affinity_key: str) -> None:
        if not affinity_key:
            return
        path = _state_path()
        path_key = self._path_key(path)
        with self._lock:
            self._ensure_loaded(path, path_key).pop(affinity_key, None)
            try:
                with _cross_process_lock(path):
                    disk = self._read_file(path)
                    disk.pop(affinity_key, None)
                    self._purge(disk, time.time())
                    self._write_file(path, disk)
            except OSError as exc:
                logger.debug("Could not delete Antigravity ACP checkpoint %s: %s", path, exc)


conversation_registry = ConversationStateRegistry()
