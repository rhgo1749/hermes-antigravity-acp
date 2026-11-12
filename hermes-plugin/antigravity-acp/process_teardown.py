"""Bounded process-tree teardown with platform-guaranteed child reaping.

Stdlib-only by contract: the plugin's client, the warm-pool shutdown hooks,
and the hosted-CI process-tree verification script all import this module
without pulling in Hermes internals.

The ACP child the plugin spawns is often the account mux, which itself owns
the official ACP server child.  Killing only the direct child can orphan the
grandchild, so every forced teardown must reach the whole tree:

* POSIX — the plugin spawns managed processes in their own session
  (``start_new_session=True``), so the direct child is a process-group leader.
  SIGTERM/SIGKILL are delivered to the *group*, which reaps grandchildren even
  when the direct child dies first or the grandchild ignores SIGTERM.
* Windows — there are no process groups, and ``TerminateProcess`` (what
  ``Popen.terminate()`` calls) reaches only the direct child; a Python SIGTERM
  handler never runs under it.  ``taskkill /T /F`` walks the parent-child tree
  instead, which is the platform-guaranteed reaping mechanism.

Cooperative shutdown is always attempted first where a cooperative channel
exists: stdin EOF is the ACP shutdown contract (flush and exit), and on POSIX
the group SIGTERM lets the mux's own signal handler run its bounded child
teardown.  Force is the escalation, never the first move.

``graceful_stdin`` is opt-in because closing a pipe another thread is writing
to races: only the thread that owns the request (or a parked process with no
writer at all) may close stdin.  Stranger-thread cancellation relies on the
POSIX group SIGTERM cooperative path and, on Windows, on the forced tree kill.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess

# The mux's own bounded child teardown (stdin-close wait + terminate wait) can
# legitimately outlive a naive 2 s grace; the plugin must not force-kill the
# mux mid-teardown, and when it must escalate, the escalation has to reach the
# whole tree (issue #23 P1 review).
_GRACEFUL_TIMEOUT_SECONDS = 2.0
_TERM_TIMEOUT_SECONDS = 4.0
_KILL_TIMEOUT_SECONDS = 5.0


def _group_signal(proc: subprocess.Popen, sig: int) -> None:
    """Signal the direct child's whole process group, best effort.

    Managed processes are group leaders (``start_new_session=True``), so the
    group id equals the child pid even after the leader dies; a grandchild
    orphaned by a dead leader still belongs to that group and still receives
    the signal.  A process that is NOT a group leader is signalled individually
    — signalling an inherited group would reach the caller's own processes.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = proc.pid  # leader: the pgid survives as the leader's own pid
    if pgid == proc.pid:
        with contextlib.suppress(OSError):
            os.killpg(pgid, sig)
        return
    with contextlib.suppress(OSError):
        proc.send_signal(sig)


def terminate_process_tree(
    proc: subprocess.Popen,
    *,
    graceful_stdin: bool = False,
    graceful_timeout: float = _GRACEFUL_TIMEOUT_SECONDS,
    term_timeout: float = _TERM_TIMEOUT_SECONDS,
    kill_timeout: float = _KILL_TIMEOUT_SECONDS,
) -> None:
    """Terminate ``proc`` and guarantee its descendant tree is reaped.

    Ladder: (optional) cooperative stdin EOF -> cooperative group SIGTERM
    (POSIX) -> forced tree escalation (group SIGKILL / ``taskkill /T /F``).
    Every step is bounded; the function returns once the direct child is reaped
    or the final escalation has been delivered.
    """
    if proc.poll() is not None:
        return
    if graceful_stdin and proc.stdin is not None and not proc.stdin.closed:
        # Owner-thread path: stdin EOF is the ACP shutdown contract — flush
        # and exit — and lets the mux run its own bounded child teardown.
        with contextlib.suppress(OSError, ValueError):
            proc.stdin.close()
        try:
            proc.wait(timeout=graceful_timeout)
            return
        except subprocess.TimeoutExpired:
            pass
    if os.name == "nt":
        # No catchable signal exists for TerminateProcess, so the forced tree
        # walk IS the platform-guaranteed reaping mechanism here.
        with contextlib.suppress(Exception):
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True,
                timeout=15,
            )
        with contextlib.suppress(Exception):
            proc.wait(timeout=kill_timeout)
        return
    _group_signal(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=term_timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    _group_signal(proc, signal.SIGKILL)
    with contextlib.suppress(Exception):
        proc.wait(timeout=kill_timeout)
