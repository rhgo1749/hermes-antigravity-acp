#!/usr/bin/env python3
"""Resilient entrypoint for the Antigravity ACP account mux.

The base mux intentionally ignores arbitrary model text when classifying provider
failures.  Google's Antigravity runtime has one special failure surface, though:
a provider failure can arrive as an ``agent_message_chunk`` whose text starts
with the vendor-generated ``Agent execution error`` sentinel, followed by a
successful JSON-RPC completion for ``session/prompt``.

Hermes would otherwise treat that sentinel as an ordinary model answer, so its
bounded provider failover loop never runs.  This entrypoint keeps the base mux's
routing/state implementation, but recognizes only that exact vendor sentinel,
quarantines the selected account, and converts the in-flight prompt into a
JSON-RPC error.  The existing Hermes client then opens a fresh ACP session; the
base mux's health state remaps the same affinity away from the quarantined
account.

No Google credential files are read here.  Authentication remains entirely in
the official ACP runtime.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
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


def _pick_account_from_env() -> tuple[str, str, str]:
    return base._pick_account(
        affinity=os.environ.get("ACP_MUX_AFFINITY", ""),
        pin_affinity=os.environ.get("ACP_MUX_AFFINITY_PIN") == "1",
    )


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


def main() -> int:
    if sys.argv[1:2] in (["doctor"], ["--doctor"]):
        # Same resolved contract report as scripts/acp_mux.py doctor.
        return base.run_doctor()
    if sys.argv[1:2] in (["inventory"], ["--inventory"]):
        # Same read-only inventory report as scripts/acp_mux.py inventory.
        return base.run_inventory()
    if not base.PAR or not os.path.exists(base.PAR):
        sys.stderr.write(
            "antigravity-acp-mux: set ACP_MUX_PAR to the official agy_acp_server.par\n"
        )
        return 2

    upstream: subprocess.Popen[str] | None = None
    bound_home = ""
    bound_label = ""
    session_gc_run = False
    owner_prune_run = False
    pump_threads: list[threading.Thread] = []
    owner_relay = base._SessionOwnerRelay()

    prompt_lock = threading.Lock()
    pending_prompt_id: object | None = None
    failed_prompt_ids: set[object] = set()

    # Per-turn digest detection state (guarded by prompt_lock).
    turn_head = ""
    held_lines: list[str] = []
    turn_hold_open = False
    failed_turn_active = False
    turn_tool_activity = 0

    def _flush_held_locked() -> None:
        for held in held_lines:
            sys.stdout.write(held)
        held_lines.clear()

    def pump_upstream_out() -> None:
        nonlocal pending_prompt_id, turn_head, turn_hold_open, failed_turn_active
        nonlocal turn_tool_activity
        assert upstream is not None
        for line in upstream.stdout or ():
            try:
                payload: object = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                payload = None

            with prompt_lock:
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
                            turn_tool_activity += 1
                        if failed_turn_active and kind in (
                            "agent_message_chunk",
                            "agent_thought_chunk",
                        ):
                            # Suppress the remainder of an already-failed turn.
                            continue
                        if kind == "agent_message_chunk" and turn_hold_open:
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
                    request_id = pending_prompt_id
                    if request_id is not None:
                        pending_prompt_id = None
                        failed_prompt_ids.add(request_id)
                        failed_turn_active = True
                        held_lines.clear()
                        turn_hold_open = False
                    if request_id is not None:
                        # Do not expose the vendor failure sentinel as model
                        # output.  Turn the active prompt into a real ACP error
                        # so Hermes' bounded failover loop opens a new mux
                        # process immediately.
                        sys.stdout.write(_jsonrpc_provider_error(request_id, embedded))
                        sys.stdout.flush()
                        continue

                structural = _classify_structured_error(line)
                if structural is not None:
                    base._mark_failure(
                        bound_home, bound_label, structural[0], structural[1]
                    )

                if chunk_text is not None and turn_hold_open:
                    turn_head = (turn_head + chunk_text)[:_TURN_HEAD_LIMIT]
                    held_lines.append(line)
                    failure = _classify_inband_turn_head(turn_head)
                    if failure is not None:
                        base._mark_failure(
                            bound_home, bound_label, failure[0], failure[1]
                        )
                        request_id = pending_prompt_id
                        if request_id is not None:
                            pending_prompt_id = None
                            failed_prompt_ids.add(request_id)
                        failed_turn_active = True
                        held_lines.clear()
                        turn_hold_open = False
                        if request_id is not None:
                            # The vendor digest is not a model answer; convert
                            # the in-flight prompt into a JSON-RPC error.
                            sys.stdout.write(
                                _inband_provider_error(
                                    request_id,
                                    *failure,
                                    replay_safe=turn_tool_activity == 0,
                                )
                            )
                            sys.stdout.flush()
                        continue
                    if (
                        len(turn_head) >= _TURN_HEAD_LIMIT
                        or not _could_extend_into_digest(turn_head)
                    ):
                        # Ordinary answer: release everything held back.
                        _flush_held_locked()
                        turn_hold_open = False
                    continue

                if isinstance(payload, dict):
                    response_id = payload.get("id")
                    if response_id in failed_prompt_ids:
                        # The prompt was already failed synthetically above;
                        # suppress the official runtime's trailing success reply.
                        failed_prompt_ids.discard(response_id)
                        failed_turn_active = False
                        continue
                    if pending_prompt_id is not None and response_id == pending_prompt_id:
                        pending_prompt_id = None
                        _flush_held_locked()
                        turn_hold_open = False

                line = owner_relay.after(line, bound_home, bound_label)
                sys.stdout.write(line)
                sys.stdout.flush()

    def pump_upstream_err() -> None:
        assert upstream is not None
        for line in upstream.stderr or ():
            redacted = base._redact(line.rstrip("\n"))
            kind = _classify_failure_text(redacted)
            if kind:
                base._mark_failure(bound_home, bound_label, kind, redacted)
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
        # Pin the Gemini home per account lane: the official server roots all
        # token/global-MCP state at $GEMINI_HOME, and a stray parent value
        # would silently collapse every account onto one shared config.
        env["GEMINI_HOME"] = base.pinned_gemini_home(home)
        violation = base.mcp_config_violation(env["GEMINI_HOME"])
        if violation is not None:
            base._log(f"mcp-config-guard {label}: {violation}")
            base._mark_failure(home, label, "mcp-config", violation)
            return False
        try:
            upstream = subprocess.Popen(
                [base.PAR, "--uid="],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            base._log(f"spawn-failed {label}: {exc}")
            return False
        bound_home = home
        bound_label = label
        base._log(f"bound account {label} ({reason}) pid={upstream.pid}")
        out_thread = threading.Thread(target=pump_upstream_out, daemon=True)
        err_thread = threading.Thread(target=pump_upstream_err, daemon=True)
        pump_threads.extend((out_thread, err_thread))
        out_thread.start()
        err_thread.start()
        return True

    try:
        for line in sys.stdin:
            method = ""
            request_id: object | None = None
            payload: object = None
            try:
                payload = json.loads(line)
                if isinstance(payload, dict):
                    method = str(payload.get("method") or "")
                    request_id = payload.get("id")
            except (json.JSONDecodeError, ValueError):
                pass

            if upstream is None:
                if not session_gc_run:
                    gc_mode = os.environ.get("ACP_MUX_SESSION_GC", "")
                    if gc_mode == "1":
                        base.prune_session_stores()
                    elif gc_mode == "dry-run":
                        report = base.session_inventory()
                        totals = report.get("totals") or {}
                        base._log(
                            "session-inventory status={status} "
                            "bundles={bundles} bytes={bytes} "
                            "protected={checkpoint_protected} "
                            "owner-linked={owner_linked} "
                            "unowned={unowned_unprotected} "
                            "candidates-expired={gc_candidate_expired} "
                            "candidates-capacity={gc_candidate_capacity} "
                            "unsafe={unsafe} deletions=0".format(
                                status=report["status"],
                                **{
                                    key: totals.get(key, 0)
                                    for key in (
                                        "bundles",
                                        "bytes",
                                        "checkpoint_protected",
                                        "owner_linked",
                                        "unowned_unprotected",
                                        "gc_candidate_expired",
                                        "gc_candidate_capacity",
                                        "unsafe",
                                    )
                                }
                            )
                        )
                    else:
                        base._log(
                            "native session GC disabled (opt in: "
                            "ACP_MUX_SESSION_GC=1; read-only audit: "
                            "ACP_MUX_SESSION_GC=dry-run)"
                        )
                    session_gc_run = True
                if not owner_prune_run:
                    base.prune_session_owners()
                    owner_prune_run = True
                resume_id = os.environ.get("ACP_MUX_SESSION_ID", "")
                owner = base._resolve_session_owner(resume_id) if resume_id else None
                if owner is not None:
                    home, label = owner
                    reason = "session-owner"
                else:
                    home, label, reason = _pick_account_from_env()
                if reason == "registry-invalid":
                    sys.stderr.write(base._REGISTRY_INVALID_MESSAGE)
                    return 2
                if not bind(home, label, reason):
                    # historical reference: a selected lane must never be replaced by
                    # a different account's HOME inside one client session.
                    sys.stderr.write(
                        "antigravity-acp-mux: selected lane spawn failed for "
                        f"lane={base._lane_fingerprint(home, label)}; refusing "
                        "a silent account fallback (see mux log)\n"
                    )
                    return 2
                base._log(
                    f"selected {bound_label} via {reason} for {method or 'unknown'}"
                )

            if method == "session/prompt" and request_id is not None:
                with prompt_lock:
                    pending_prompt_id = request_id
                    turn_head = ""
                    held_lines.clear()
                    turn_hold_open = True
                    failed_turn_active = False
                    turn_tool_activity = 0

            config_id = ""
            if isinstance(payload, dict) and method == "session/set_config_option":
                params = payload.get("params")
                if isinstance(params, dict):
                    config_id = str(params.get("configId") or "").strip().lower()
            if (
                request_id is not None
                and (
                    method in ("session/new", "session/resume", "session/load")
                    or method == "session/set_model"
                    or (method == "session/set_config_option" and config_id == "model")
                )
            ):
                # TOCTOU re-check: a global MCP config written after bind-time
                # validation must still never reach the official server's
                # merge. The merge happens on session creation AND on model
                # rebuilds (session/set_model, set_config_option(configId
                # =model) both call _create_agent_config, verified in 1.2.1),
                # so model switches are guarded too.
                violation = base.mcp_config_violation(
                    base.pinned_gemini_home(bound_home)
                )
                if violation is not None:
                    base._mark_failure(
                        bound_home, bound_label, "mcp-config", violation
                    )
                    sys.stdout.write(_mcp_guard_error(request_id, violation))
                    sys.stdout.flush()
                    continue

            owner_error = owner_relay.before(payload, bound_home, bound_label)
            if owner_error is not None:
                sys.stdout.write(owner_error)
                sys.stdout.flush()
                continue

            assert upstream is not None and upstream.stdin is not None
            if upstream.poll() not in (None, 0):
                base._mark_failure(
                    bound_home,
                    bound_label,
                    "crash",
                    f"exit={upstream.returncode}",
                )
                return 0
            try:
                upstream.stdin.write(line)
                upstream.stdin.flush()
            except (OSError, ValueError):
                returncode = upstream.poll()
                if returncode not in (None, 0):
                    base._mark_failure(
                        bound_home, bound_label, "crash", f"exit={returncode}"
                    )
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
    raise SystemExit(main())
