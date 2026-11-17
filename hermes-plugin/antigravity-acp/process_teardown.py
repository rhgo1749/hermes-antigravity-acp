"""Bounded process-tree teardown with platform-guaranteed child reaping.

Stdlib-only by contract: the plugin's client, the warm-pool shutdown hooks,
and the hosted-CI process-tree verification script all import this module
without pulling in Hermes internals.

The ACP child the plugin spawns is often the account mux, which itself owns
the official ACP server child.  Killing only the direct child can orphan the
grandchild, so every forced teardown must reach the whole tree:

* POSIX — the plugin spawns managed processes in their own session
  (``start_new_session=True``), so the direct child is a process-group leader.
  Signals are delivered to the *group*, and after the direct child is reaped
  the group is explicitly swept: a leader that exits immediately on SIGTERM
  must not return the teardown while a SIGTERM-ignoring grandchild is still
  running (rework round 2, independent re-review of PR #31).
* Windows — there are no process groups, and ``TerminateProcess`` (what
  ``Popen.terminate()`` calls) reaches only the direct child; a Python SIGTERM
  handler never runs under it.  ``taskkill /T /F`` walks the parent-child tree
  instead, and its exit code decides whether reaping may be reported.

Ownership discipline: a group signal is only ever delivered to a group whose
leadership was verified while the leader was still resolvable by the kernel
(``getpgid(pid) == pid`` before any reap).  Once the leader has been reaped
elsewhere, PID/PGID reuse makes the group unverifiable, and this module
refuses to signal it blindly.  A process that is not a group leader is
signalled individually and never yields a claimed tree guarantee.

Cooperative shutdown is attempted first where a cooperative channel exists:
stdin EOF is the ACP shutdown contract (flush and exit), and on POSIX the
group SIGTERM lets the mux's own signal handler run its bounded child
teardown.  ``graceful_stdin`` is opt-in because closing a pipe another thread
is writing to races: only the thread that owns the request (or a parked
process with no writer at all) may close stdin.

Return value: ``True`` only when tree reaping was verified (POSIX: the owned
group observed empty; Windows: ``taskkill /T /F`` exit code 0).  ``None``
means reaping could not be verified (foreign process, already-reaped leader,
dead parent before a Windows tree walk) — callers must not treat ``None`` as
success.
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import time
from typing import Literal

logger = logging.getLogger(__name__)

# The mux's own bounded child teardown (stdin-close wait + terminate wait) can
# legitimately outlive a naive 2 s grace; the plugin must not force-kill the
# mux mid-teardown, and when it must escalate, the escalation has to reach the
# whole tree (issue #23 P1 review).
_GRACEFUL_TIMEOUT_SECONDS = 2.0
_TERM_TIMEOUT_SECONDS = 4.0
_KILL_TIMEOUT_SECONDS = 5.0
# After the direct child dies, surviving group members already received the
# same SIGTERM; give them this long to exit before the group SIGKILL.
_SWEEP_GRACE_SECONDS = 2.0
_SWEEP_TIMEOUT_SECONDS = 5.0


_NON_REAPING_SUPPORTED = (
    os.name != "nt"
    and hasattr(os, "waitid")
    and hasattr(os, "WNOWAIT")
    and hasattr(os, "WEXITED")
    and hasattr(os, "P_PID")
    and hasattr(os, "CLD_KILLED")
    and hasattr(os, "CLD_DUMPED")
)

# Runtime kill-switch: a platform that EXPOSES the waitid symbols but
# FAILS the call (EINVAL/ENOSYS at runtime) permanently degrades to the
# poll() fallback on first failure; see ``_non_reaping_probe``.
_non_reaping_enabled = True

_FALLBACK: Literal["fallback"] = "fallback"
_ALREADY_REAPED: Literal["reaped"] = "reaped"


def _non_reaping_probe(proc: subprocess.Popen):
    """One non-reaping WEXITED probe, or a sentinel telling the caller to
    use the legacy ``poll()`` semantics / that the child was reaped.

    Never raises.  An unexpected ``OSError`` from a present-but-broken
    ``waitid`` disables the non-reaping path process-wide (sticky) and
    logs once, because the caller must then knowingly accept the reaping
    fallback rather than crash.
    """
    global _non_reaping_enabled
    if not (_NON_REAPING_SUPPORTED and _non_reaping_enabled):
        return _FALLBACK
    try:
        return os.waitid(
            os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG
        )
    except ChildProcessError:
        return _ALREADY_REAPED
    except OSError as exc:
        if _non_reaping_enabled:
            _non_reaping_enabled = False
            logger.warning(
                "ACP non-reaping waitid failed (%s); permanently falling "
                "back to poll() semantics, which REAP the direct child "
                "(tree guarantees degrade as documented for the legacy path)",
                exc,
            )
        return _FALLBACK


def proc_dead_unreaped(proc: subprocess.Popen) -> bool:
    """Liveness check for lifecycle seams that hand off to teardown.

    Supported POSIX path: ``waitid(P_PID, WEXITED | WNOWAIT | WNOHANG)``
    reports a dead-but-unreaped child WITHOUT reaping and WITHOUT setting
    ``returncode``, so the zombie leader keeps group ownership resolvable
    and ``terminate_process_tree`` can still capture ownership and sweep.
    ``WNOWAIT`` is a ``waitid``-only flag — the legacy ``waitpid`` family
    rejects it with ``EINVAL``.

    Legacy fallback (Windows, POSIX builds missing the flags, or a runtime
    ``waitid`` failure): delegates to ``poll()``, which REAPS and sets
    ``returncode`` — the pre-existing semantics, unchanged, with the same
    pre-existing tree-guarantee degradation (issue #23 guard).  The
    "never reaps" property holds ONLY on the supported path and callers
    on the fallback must not assume ownership survives the check.
    """
    if proc.returncode is not None:
        return True
    probe = _non_reaping_probe(proc)
    if probe is _ALREADY_REAPED:
        # Dead, and ownership is unverifiable — the conservative teardown
        # guard applies downstream.
        return True
    if probe is _FALLBACK:
        return proc.poll() is not None
    return probe is not None


def proc_exit_status_unreaped(proc: subprocess.Popen) -> int | None:
    """Exit status of a dead child WITHOUT consuming it (supported path).

    Mirrors ``Popen.returncode`` semantics (``-signal`` for signal death)
    so early-exit diagnostics keep their exact message and trace shape
    while leaving the zombie — and therefore group ownership — intact for
    the teardown that follows.  ``None`` means the status is not (yet)
    observable without reaping; callers must treat it as unknown, never
    as zero.  On the legacy fallback this is ``poll()`` — reaping, with
    the same documented degradation as ``proc_dead_unreaped``.
    """
    if proc.returncode is not None:
        return proc.returncode
    probe = _non_reaping_probe(proc)
    if isinstance(probe, str):
        if probe == _ALREADY_REAPED:
            return None
        return proc.poll()
    if probe is None:
        return None
    if probe.si_code in (os.CLD_KILLED, os.CLD_DUMPED):
        return -probe.si_status
    return probe.si_status


def _group_id_if_resolvable(proc: subprocess.Popen) -> int | None:
    """The process's group id while the kernel can still resolve it.
    Valid only when it equals ``proc.pid`` (the child leads the group — the
    contract of ``start_new_session=True``).  After a reap this raises
    ProcessLookupError, which is exactly the point where ownership becomes
    unverifiable and group signalling must stop.
    """
    try:
        return os.getpgid(proc.pid)
    except OSError:
        return None


def _group_has_members(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Members exist but are unsignalable — treat as present, never as empty.
        return True


def _sweep_group(
    pgid: int, proc: subprocess.Popen, *, grace: float, timeout: float
) -> bool:
    """Ensure an owned process group is empty; escalate with group SIGKILL.

    The direct child is reaped opportunistically inside the loop: a killed but
    unreaped zombie would otherwise keep the group permanently non-empty.
    Returns True only when the group was observed empty.
    """
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        with contextlib.suppress(Exception):
            proc.poll()  # reap the direct child's zombie as soon as it dies
        if not _group_has_members(pgid):
            return True
        time.sleep(0.05)
    with contextlib.suppress(OSError):
        os.killpg(pgid, signal.SIGKILL)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(Exception):
            proc.poll()
        if not _group_has_members(pgid):
            return True
        time.sleep(0.05)
    logger.warning(
        "ACP process group %d still has members after group SIGKILL; "
        "tree reaping is NOT complete",
        pgid,
    )
    return False


def terminate_process_tree(
    proc: subprocess.Popen,
    *,
    graceful_stdin: bool = False,
    graceful_timeout: float = _GRACEFUL_TIMEOUT_SECONDS,
    term_timeout: float = _TERM_TIMEOUT_SECONDS,
    kill_timeout: float = _KILL_TIMEOUT_SECONDS,
    sweep_grace: float = _SWEEP_GRACE_SECONDS,
    sweep_timeout: float = _SWEEP_TIMEOUT_SECONDS,
) -> bool | None:
    """Terminate ``proc`` and reap its whole tree where that is verifiable.

    Ladder (POSIX, owned group): (optional) cooperative stdin EOF -> group
    SIGTERM -> reap the direct child -> sweep the group (grace, group SIGKILL,
    verify empty).  Ladder (Windows): (optional) cooperative stdin EOF ->
    ``taskkill /T /F`` whose exit code decides the reported guarantee.
    """
    if os.name == "nt":
        return _terminate_windows(
            proc,
            graceful_stdin=graceful_stdin,
            graceful_timeout=graceful_timeout,
            kill_timeout=kill_timeout,
        )
    # Capture group ownership BEFORE anything can reap the leader: Popen.poll()
    # reaps, and a reaped leader makes ownership unverifiable forever.
    pgid = _group_id_if_resolvable(proc)
    owned = pgid is not None and pgid == proc.pid

    if proc.poll() is not None:
        if not owned:
            logger.warning(
                "ACP teardown for pid %d started after the leader was already "
                "reaped; group ownership unverifiable — no group signal will "
                "be sent (PID/PGID reuse guard)",
                proc.pid,
            )
            return None
        assert pgid is not None  # owned implies resolvable
        with contextlib.suppress(Exception):
            proc.wait(timeout=1)  # reap the zombie leader
        return _sweep_group(pgid, proc, grace=sweep_grace, timeout=sweep_timeout)

    if not owned:
        # Foreign or legacy process: direct ladder only.  Its descendants (if
        # any) are unreachable without hitting the caller's own group, so no
        # tree guarantee may ever be claimed here.
        if graceful_stdin and proc.stdin is not None and not proc.stdin.closed:
            with contextlib.suppress(OSError, ValueError):
                proc.stdin.close()
            try:
                proc.wait(timeout=graceful_timeout)
                return None
            except subprocess.TimeoutExpired:
                pass
        with contextlib.suppress(OSError):
            proc.terminate()
        try:
            proc.wait(timeout=term_timeout)
            return None
        except subprocess.TimeoutExpired:
            pass
        with contextlib.suppress(OSError):
            proc.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=kill_timeout)
        return None

    # Owned group (start_new_session contract): cooperative first, then group
    # signals, then an explicit sweep — the direct child's death alone NEVER
    # ends the teardown.
    assert pgid is not None  # owned implies resolvable
    if graceful_stdin and proc.stdin is not None and not proc.stdin.closed:
        with contextlib.suppress(OSError, ValueError):
            proc.stdin.close()
        try:
            proc.wait(timeout=graceful_timeout)
        except subprocess.TimeoutExpired:
            pass
        else:
            return _sweep_group(pgid, proc, grace=sweep_grace, timeout=sweep_timeout)
    with contextlib.suppress(OSError):
        os.killpg(pgid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=term_timeout)
    return _sweep_group(pgid, proc, grace=sweep_grace, timeout=sweep_timeout)


def _terminate_windows(
    proc: subprocess.Popen,
    *,
    graceful_stdin: bool,
    graceful_timeout: float,
    kill_timeout: float,
) -> bool | None:
    if graceful_stdin and proc.stdin is not None and not proc.stdin.closed:
        with contextlib.suppress(OSError, ValueError):
            proc.stdin.close()
        try:
            proc.wait(timeout=graceful_timeout)
        except subprocess.TimeoutExpired:
            pass
        else:
            # The mux's own teardown ran, but Windows offers no way to verify
            # the descendant tree after the fact.
            return None
    if proc.poll() is not None:
        logger.warning(
            "ACP teardown for pid %d started after the parent had already "
            "exited; taskkill cannot walk a dead tree — descendants "
            "unverifiable",
            proc.pid,
        )
        return None
    try:
        result = subprocess.run(
            ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
            capture_output=True,
            timeout=15,
        )
    except Exception:  # noqa: BLE001 — best-effort escalation, reported below
        logger.warning(
            "ACP taskkill /T /F for pid %d raised; tree reaping NOT "
            "guaranteed", proc.pid, exc_info=True,
        )
        return None
    with contextlib.suppress(Exception):
        proc.wait(timeout=kill_timeout)
    if result.returncode != 0:
        logger.warning(
            "ACP taskkill /T /F for pid %d exited %d (%s); tree reaping NOT "
            "guaranteed",
            proc.pid,
            result.returncode,
            (result.stderr or b"").decode(errors="replace").strip()[:200],
        )
        return None
    return True
