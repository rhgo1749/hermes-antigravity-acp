"""Issue #25 slice: the reaped-leader boundary at lifecycle seams.

Known bug (evidence slice PR #49, point A): lifecycle code decides liveness
with ``proc.poll()``, which REAPS a dead child.  Once the group leader is
reaped, ``terminate_process_tree`` must refuse all group signalling
(issue #23 PID/PGID-reuse guard), so same-group vendor descendants survive
every permitted teardown path.

Minimal seam (independent source review): ``terminate_process_tree``
already captures group ownership BEFORE any reap and fully sweeps a
dead-but-UNREAPED owned leader.  The defect is any pre-teardown
``proc.poll()`` reap.  This slice adds a non-reaping liveness primitive
(``proc_dead_unreaped`` plus the non-consuming ``proc_exit_status_unreaped``
for exit-code diagnostics) and wires all six pre-teardown callsites:
three warm-pool checks and the three ``_session`` checks (request-wait
loop, early-exit diagnostic, finally dispose).

Scope locks: no warm-pool global cap, no GC, no mux lease, no deployment
drift, no vendor cooperation, no detached/setsid-descendant claims (that
remains a separate Gate B NO-GO condition), Windows keeps poll() semantics.
"""
from __future__ import annotations

import importlib.util
import inspect
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not Path("/proc").is_dir(),
    reason="POSIX group-ownership semantics under test",
)

ROOT = Path(__file__).resolve().parents[1]
_pt_spec = importlib.util.spec_from_file_location(
    "rl_teardown", ROOT / "hermes-plugin" / "antigravity-acp" / "process_teardown.py"
)
assert _pt_spec and _pt_spec.loader
teardown = importlib.util.module_from_spec(_pt_spec)
_pt_spec.loader.exec_module(teardown)

from test_standalone_client import _load  # noqa: E402


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


LEADER_SRC = """
import os, signal, subprocess, sys, time
child = subprocess.Popen([sys.executable, sys.argv[2], sys.argv[3]],
                         stdin=subprocess.DEVNULL)
with open(sys.argv[1], "w") as fh:
    fh.write(str(os.getpid()))
time.sleep(120)
"""

DESCENDANT_SRC = """
import os, sys, time
with open(sys.argv[1], "w") as fh:
    fh.write(str(os.getpid()))
time.sleep(120)
"""


class _Tree:
    """A group-leader child (mux stand-in) + one same-group descendant."""

    def __init__(self, tmp_path: Path, name: str):
        leader = tmp_path / f"{name}-leader.py"
        leader.write_text(LEADER_SRC)
        desc = tmp_path / f"{name}-desc.py"
        desc.write_text(DESCENDANT_SRC)
        self.leader_pidfile = tmp_path / f"{name}-leader.pid"
        self.desc_pidfile = tmp_path / f"{name}-desc.pid"
        self.proc = subprocess.Popen(
            [sys.executable, str(leader), str(self.leader_pidfile),
             str(desc), str(self.desc_pidfile)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, text=True,
            start_new_session=True,  # the plugin's ownership contract
        )
        assert _wait(lambda: self.leader_pidfile.exists()
                     and self.desc_pidfile.exists(), 15)

    @property
    def desc_pid(self) -> int:
        return int(self.desc_pidfile.read_text())

    def kill_leader(self) -> None:
        self.proc.kill()

    def cleanup(self) -> None:
        try:
            os.kill(self.desc_pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass
        if self.proc.poll() is None:
            self.proc.kill()
        try:
            self.proc.wait(timeout=5)
        except Exception:
            pass


@pytest.fixture
def trees(tmp_path):
    created: list[_Tree] = []

    def make(name: str) -> _Tree:
        t = _Tree(tmp_path, name)
        created.append(t)
        return t

    yield make
    for t in created:
        t.cleanup()


# ---------------------------------------------------------------------------
# 1. The primitive: liveness only, never wait/reap.
# ---------------------------------------------------------------------------

def test_helper_reports_running_without_reaping(trees):
    tree = trees("running")
    assert teardown.proc_dead_unreaped(tree.proc) is False
    assert tree.proc.returncode is None
    # Still fully waitable afterwards: a reaping helper would break this.
    assert teardown.proc_dead_unreaped(tree.proc) is False


def test_helper_reports_dead_but_never_reaps(trees):
    tree = trees("dead-unreaped")
    tree.kill_leader()
    assert _wait(lambda: teardown.proc_dead_unreaped(tree.proc), 10)
    assert tree.proc.returncode is None, "helper must not set returncode"
    # The zombie leader must remain kernel-resolvable: ownership evidence.
    assert os.getpgid(tree.proc.pid) == tree.proc.pid
    # Idempotent: repeated checks keep reporting dead without reaping.
    assert teardown.proc_dead_unreaped(tree.proc) is True
    assert os.getpgid(tree.proc.pid) == tree.proc.pid


def test_helper_fallback_semantics_without_wnowait(trees, monkeypatch):
    monkeypatch.setattr(teardown, "_NON_REAPING_SUPPORTED", False)
    tree = trees("fallback")
    assert teardown.proc_dead_unreaped(tree.proc) is False
    tree.kill_leader()
    assert _wait(lambda: teardown.proc_dead_unreaped(tree.proc), 10)


# ---------------------------------------------------------------------------
# 2. The gap (permanent evidence) and the closure, end to end.
# ---------------------------------------------------------------------------

def test_poll_first_pattern_loses_the_tree(trees):
    # RED evidence against the OLD warm-pool pattern: poll() reaps the
    # leader, teardown must refuse, same-group descendants survive.
    tree = trees("gap")
    tree.kill_leader()
    assert _wait(lambda: tree.proc.poll() is not None, 10)  # the bug: reap
    result = teardown.terminate_process_tree(tree.proc)
    assert result is not True, "a reaped leader must never claim a sweep"
    time.sleep(0.3)
    assert _alive(tree.desc_pid), "gap precondition: descendant survives"


def test_non_reaping_handoff_sweeps_group_and_reaps_leader(trees):
    tree = trees("closure")
    victim = tree.desc_pid
    tree.kill_leader()
    assert _wait(lambda: teardown.proc_dead_unreaped(tree.proc), 10)

    result = teardown.terminate_process_tree(tree.proc, graceful_stdin=True)
    assert result is True, (
        "dead-but-UNREAPED owned leader must still reach the verified "
        "group sweep (the ownership discipline already exists)"
    )
    assert _wait(lambda: not _alive(victim), 15), "same-group descendant swept"
    assert tree.proc.returncode is not None, "leader reaped by the teardown"


# ---------------------------------------------------------------------------
# 3. The actual seam: the client warm pool must hand off unreaped.
# ---------------------------------------------------------------------------

def test_warm_pool_dead_checks_use_the_non_reaping_primitive(monkeypatch):
    _facade, client, module = _load(monkeypatch)
    cls = type(client)
    for meth in ("_warm_acquire", "_warm_park"):
        src = inspect.getsource(getattr(cls, meth))
        assert "proc_dead_unreaped" in src, f"{meth} must not reap via poll()"
        assert ".poll()" not in src, f"{meth} still reaps with poll(): {meth}"


def test_warm_park_corpse_handoff_sweeps_descendants(monkeypatch, tmp_path):
    _facade, client, module = _load(monkeypatch)
    tree = _Tree(tmp_path, "park-corpse")
    try:
        victim = tree.desc_pid
        tree.kill_leader()
        assert _wait(lambda: teardown.proc_dead_unreaped(tree.proc), 10)
        key = ("home", ("aff",), "pin", "lane")
        entry = {"proc": tree.proc, "key": key, "idle_since": 0.0,
                 "par_pin": "", "inbox": None}
        client._warm_park(entry)
        assert _wait(lambda: not _alive(victim), 20), (
            "warm-pool corpse path must hand the UNREAPED leader to "
            "terminate_process_tree so the same-group descendant is swept"
        )
    finally:
        tree.cleanup()


# ---------------------------------------------------------------------------
# 4. Reviewer BLOCKER R1: the remaining _session lifecycle seams
#    (request wait loop, early-exit diagnostics, finally dispose) must
#    also hand the tree teardown an UNREAPED leader, and the exit-status
#    diagnostics must obtain codes without consuming them.
# ---------------------------------------------------------------------------

EXIT_SRC = """
import sys
sys.exit(7)
"""

SLEEP_SRC = """
import time
time.sleep(120)
"""


def _spawn(tmp_path, name, src):
    script = tmp_path / f"{name}.py"
    script.write_text(src)
    return subprocess.Popen([sys.executable, str(script)],
                            start_new_session=True)


def test_exit_status_helper_reports_code_without_reaping(tmp_path):
    proc = _spawn(tmp_path, "exit7", EXIT_SRC)
    assert _wait(lambda: teardown.proc_dead_unreaped(proc), 10)
    assert teardown.proc_exit_status_unreaped(proc) == 7
    assert proc.returncode is None, "exit-status probe must not reap"
    assert os.getpgid(proc.pid) == proc.pid
    # Ownership survives the probe: the teardown can still verify+sweep+reap.
    assert teardown.terminate_process_tree(proc) is True
    assert proc.returncode == 7


def test_exit_status_helper_matches_popen_signal_semantics(tmp_path):
    proc = _spawn(tmp_path, "sleepy", SLEEP_SRC)
    time.sleep(0.3)
    proc.kill()
    assert _wait(lambda: teardown.proc_dead_unreaped(proc), 10)
    assert teardown.proc_exit_status_unreaped(proc) == -9, (
        "signal death must mirror Popen.returncode semantics (-signal)"
    )
    teardown.terminate_process_tree(proc)


def test_exit_status_probe_feeds_tree_sweep_with_descendants(tmp_path):
    # The early-exit diagnostic position: probe the code, keep ownership,
    # then the same-group descendant must still be swept by the teardown.
    tree = _Tree(tmp_path, "diag-sweep")
    try:
        victim = tree.desc_pid
        tree.kill_leader()
        assert _wait(lambda: teardown.proc_dead_unreaped(tree.proc), 10)
        code = teardown.proc_exit_status_unreaped(tree.proc)
        assert code == -9
        assert teardown.terminate_process_tree(tree.proc) is True
        assert _wait(lambda: not _alive(victim), 15)
    finally:
        tree.cleanup()


def test_runtime_waitid_failure_falls_back_and_is_sticky(tmp_path, monkeypatch):
    monkeypatch.setattr(teardown, "_non_reaping_enabled", True)
    real_waitid = os.waitid

    def broken_waitid(*args, **kwargs):
        raise OSError(22, "EINVAL")

    proc = _spawn(tmp_path, "rtfail", SLEEP_SRC)
    try:
        monkeypatch.setattr(os, "waitid", broken_waitid)
        assert teardown.proc_dead_unreaped(proc) is False  # via poll fallback
        assert teardown._non_reaping_enabled is False, (
            "an OSError from a present waitid symbol must permanently "
            "degrade to the documented poll() semantics, not crash"
        )
        proc.kill()
        assert _wait(lambda: teardown.proc_dead_unreaped(proc), 10)
        assert proc.returncode is not None, (
            "the fallback reaps — the contract must state this, not hide it"
        )
    finally:
        monkeypatch.setattr(os, "waitid", real_waitid)
        monkeypatch.setattr(teardown, "_non_reaping_enabled", True)
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=5)


def test_fallback_path_reaps_by_contract(tmp_path, monkeypatch):
    # Requirement: the legacy fallback's reaping must be explicit, not
    # papered over by the "never reaps" wording of the supported path.
    monkeypatch.setattr(teardown, "_NON_REAPING_SUPPORTED", False)
    proc = _spawn(tmp_path, "fb", SLEEP_SRC)
    proc.kill()
    assert _wait(lambda: teardown.proc_dead_unreaped(proc), 10)
    assert proc.returncode is not None, (
        "fallback = poll() = reaping; documented degradation"
    )


def test_release_process_after_non_reaping_detection_sweeps_descendants(
    monkeypatch, tmp_path
):
    # The _session finally dispose position, driven through the REAL
    # _release_process -> terminate_process_tree path.
    _facade, client, _module = _load(monkeypatch)
    tree = _Tree(tmp_path, "finally-close")
    try:
        victim = tree.desc_pid
        tree.kill_leader()
        assert _wait(lambda: teardown.proc_dead_unreaped(tree.proc), 10)
        client._release_process(tree.proc)
        assert _wait(lambda: not _alive(victim), 20), (
            "non-reaping detection at the finally seam must let the real "
            "release path sweep the same-group descendant"
        )
    finally:
        tree.cleanup()


def test_release_process_after_poll_reap_loses_descendants(
    monkeypatch, tmp_path
):
    # Permanent gap evidence at the finally position on the OLD pattern.
    _facade, client, _module = _load(monkeypatch)
    tree = _Tree(tmp_path, "finally-gap")
    try:
        victim = tree.desc_pid
        tree.kill_leader()
        assert _wait(lambda: tree.proc.poll() is not None, 10)  # the bug
        client._release_process(tree.proc)
        time.sleep(0.5)
        assert _alive(victim), "gap: poll-reaped leader strands the descendant"
    finally:
        tree.cleanup()


def test_session_lifecycle_seams_use_the_non_reaping_primitive(monkeypatch):
    _facade, client, _module = _load(monkeypatch)
    cls = type(client)
    src = inspect.getsource(cls._session.__wrapped__)
    assert ".poll()" not in src, "_session still reaps with poll()"
    assert "proc_dead_unreaped" in src
    assert "proc_exit_status_unreaped" in src, (
        "early-exit exit-code diagnostics must not consume the status"
    )


def test_warm_park_sweep_terminates_dead_parked_sibling_untouched(
    monkeypatch, tmp_path
):
    _facade, client, module = _load(monkeypatch)
    dead = _Tree(tmp_path, "park-dead")
    live = _Tree(tmp_path, "park-live")
    try:
        key = ("home", ("aff",), "pin", "lane")
        dead.kill_leader()
        assert _wait(lambda: teardown.proc_dead_unreaped(dead.proc), 10)
        with module._warm_pool_lock:
            module._warm_pool[key] = [{"proc": dead.proc, "key": key,
                                       "idle_since": 0.0, "par_pin": "",
                                       "inbox": None}]
        fresh = {"proc": live.proc, "key": key, "idle_since": 0.0,
                 "par_pin": "", "inbox": None}
        client._warm_park(fresh)
        assert _wait(lambda: not _alive(dead.desc_pid), 20), (
            "dead parked entry's descendant must be swept via the "
            "non-reaping handoff"
        )
        assert _alive(live.desc_pid), "sibling lane work must be untouched"
        assert live.proc.poll() is None, "sibling leader must be untouched"
    finally:
        dead.cleanup()
        live.cleanup()
