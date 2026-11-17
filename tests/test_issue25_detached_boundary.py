"""Issue #25 slice: the detached/setsid descendant boundary (evidence only).

Question (Gate B condition, PR #49 docs §5): does the process-group based
teardown still bound native-store lifetime when a vendor descendant calls
``setsid()``/``setpgid()`` and leaves the mux's PGID/SID?

Source-confirmed ownership boundary (main 37828b1, read-only):
- plugin spawns the mux with ``start_new_session=True`` (client.py), so the
  mux is the session+group leader;
- the mux spawns the official child with a plain ``Popen`` (acp_mux.py
  ``popen_kwargs``): the child INHERITS the mux PGID/SID and the lease fd
  via ``pass_fds`` — no setsid/setpgid anywhere in mux code;
- vendor-spawned descendants inherit the group by accident of fork only;
  no code or contract here prevents ``setsid``/``setpgid``, and the mux
  lease fd is explicitly NOT passed to them (acp_mux.py review-B5 comment);
- ``terminate_process_tree`` signals exactly one group: ``killpg`` of the
  leader's PGID.  A detached process is outside the reachable set by
  construction.

These tests PIN the counterexample (they pass by demonstrating the gap,
like the PR #49 point-A/C evidence).  They prove nothing about the real
vendor 1.4.4 — that is separate read-only live evidence; a non-cooperating
fake is an admissible safety counterexample model, not observed vendor
behavior.

Scope locks: evidence only — no containment implementation, no GC, no mux
lease changes, no warm-pool cap, no deployment changes.
"""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not Path("/proc").is_dir(),
    reason="POSIX group/session semantics under test",
)

ROOT = Path(__file__).resolve().parents[1]
_pt_spec = importlib.util.spec_from_file_location(
    "det_teardown", ROOT / "hermes-plugin" / "antigravity-acp" / "process_teardown.py"
)
teardown = importlib.util.module_from_spec(_pt_spec)
assert _pt_spec.loader is not None
_pt_spec.loader.exec_module(teardown)


def _wait(pred, timeout=15.0, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return False


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _pgid(pid: int) -> int | None:
    try:
        return os.getpgid(pid)
    except (ProcessLookupError, OSError):
        return None


LEADER_SRC = """
import json, os, subprocess, sys, time
from pathlib import Path

here = Path(sys.argv[1])

# Same-group child: plain fork/exec inherits the leader's PGID/SID.
same = subprocess.Popen([sys.executable, str(here / "holder.py"),
                         str(here / "same.json"), str(here / "store.lock")])
# Detached descendant: start_new_session=True performs setsid() in the
# child — it leaves the leader's PGID AND SID, exactly like a vendor
# helper that daemonizes.
det = subprocess.Popen([sys.executable, str(here / "holder.py"),
                        str(here / "det.json"), str(here / "store.lock")],
                       start_new_session=True)
here.joinpath("pids.json").write_text(json.dumps(
    {"leader": os.getpid(), "same": same.pid, "det": det.pid}))
time.sleep(600)
"""

HOLDER_SRC = """
import fcntl, json, os, sys, time
from pathlib import Path

meta = {"pid": os.getpid(), "pgid": os.getpgid(0), "sid": os.getsid(0)}
Path(sys.argv[1]).write_text(json.dumps(meta))
lock = open(sys.argv[2], "a+b")
fcntl.flock(lock, fcntl.LOCK_SH)  # shared: models "still holds the store"
Path(str(Path(sys.argv[1]).parent) + "/fd-" + str(os.getpid())).write_text("x")
time.sleep(600)
"""


class _Tree:
    """Fake mux leader + same-PGID holder + setsid-detached holder.

    ``store.lock`` models the native store's advisory lock: whichever
    process holds flock still claims native-store lifetime.
    """

    def __init__(self, tmp_path, name):
        self.dir = tmp_path / name
        self.dir.mkdir()
        (self.dir / "store.lock").touch()
        (self.dir / "leader.py").write_text(LEADER_SRC)
        (self.dir / "holder.py").write_text(HOLDER_SRC)
        self.proc = subprocess.Popen(
            [sys.executable, str(self.dir / "leader.py"), str(self.dir)],
            start_new_session=True,
        )
        pids = self.dir / "pids.json"
        assert _wait(lambda: pids.exists(), 20), "fake tree failed to start"
        self.pids = json.loads(pids.read_text())
        metas = ["same.json", "det.json"]
        assert _wait(
            lambda: all((self.dir / m).exists() for m in metas), 20
        ), "holders failed to register"
        self.same = json.loads((self.dir / "same.json").read_text())
        self.det = json.loads((self.dir / "det.json").read_text())

    # -- introspection helpers -------------------------------------------
    def flock_holders(self) -> set[int]:
        st = os.stat(self.dir / "store.lock")
        key = (
            f"{os.major(st.st_dev):02x}:"
            f"{os.minor(st.st_dev):02x}:{st.st_ino}"
        )
        holders: set[int] = set()
        for line in Path("/proc/locks").read_text().splitlines():
            parts = line.split()
            # "N: FLOCK ADVISORY WRITE <pid> <maj:min:ino> <start> <end>"
            if len(parts) >= 6 and parts[1] == "FLOCK" and parts[5] == key:
                pid = int(parts[4])
                if pid > 0:
                    holders.add(pid)
        return holders

    def cleanup(self):
        for pid in (self.pids["det"], self.pids["same"], self.proc.pid):
            try:
                os.kill(pid, 9)
            except (ProcessLookupError, OSError):
                pass
        for pid in (self.pids["det"], self.pids["same"]):
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        with contextlib.suppress(Exception):
            self.proc.wait(timeout=10)


# ---------------------------------------------------------------------------


def test_baseline_group_teardown_sweeps_same_group_but_not_detached(tmp_path):
    tree = _Tree(tmp_path, "baseline")
    try:
        # Layout sanity: leader owns its group/session; same child inherits;
        # detached holder left BOTH group and session.
        assert tree.pids["leader"] == tree.proc.pid
        assert _pgid(tree.pids["leader"]) == tree.proc.pid
        assert tree.same["pgid"] == tree.proc.pid
        assert tree.same["sid"] == os.getsid(tree.proc.pid)
        assert tree.det["pgid"] != tree.proc.pid, "setsid model failed"
        assert tree.det["sid"] != os.getsid(tree.proc.pid)

        # Both holders claim the store lock's flock before teardown.
        assert _wait(lambda: {tree.same["pid"], tree.det["pid"]}
                     <= tree.flock_holders(), 15), "flock registration failed"

        result = teardown.terminate_process_tree(tree.proc)
        assert result is True, "owned-group sweep must still succeed"

        assert _wait(lambda: not _alive(tree.same["pid"]), 20), (
            "same-PGID descendant must be swept"
        )
        # THE GAP: the detached descendant is outside killpg's reach.
        time.sleep(0.5)
        assert _alive(tree.det["pid"]), (
            "unexpected: detached descendant died — the fake stopped "
            "modeling setsid escape; this test pins the GAP, not a fix"
        )
        # And it still claims native-store lifetime via the flock.
        assert tree.det["pid"] in tree.flock_holders(), (
            "detached survivor must keep holding the store flock for the "
            "counterexample to model native-store lifetime"
        )
    finally:
        tree.cleanup()


def test_sibling_lane_untouched_by_group_sweep(tmp_path):
    victim = _Tree(tmp_path, "victim")
    sibling = _Tree(tmp_path, "sibling")
    try:
        assert teardown.terminate_process_tree(victim.proc) is True
        assert _wait(lambda: not _alive(victim.same["pid"]), 20)
        time.sleep(0.5)
        for meta in (sibling.same, sibling.det):
            assert _alive(meta["pid"]), "sweep leaked into sibling lane"
        assert _alive(sibling.proc.pid)
    finally:
        victim.cleanup()
        sibling.cleanup()


def test_detached_survivor_outlives_even_the_reap_of_the_leader(tmp_path):
    # After teardown completes the leader is reaped; the detached holder
    # is reparented (ppid -> 1/init) and remains a fully independent
    # process: no plugin-side handle, no group membership, store flock held.
    tree = _Tree(tmp_path, "orphan")
    try:
        assert teardown.terminate_process_tree(tree.proc) is True
        assert tree.proc.returncode is not None, "teardown should reap leader"
        assert _wait(lambda: not _alive(tree.same["pid"]), 20)
        time.sleep(0.5)
        assert _alive(tree.det["pid"])
        with open(f"/proc/{tree.det['pid']}/stat") as fh:
            fields = fh.read().rsplit(")", 1)[1].split()
        ppid = int(fields[1])
        assert ppid != tree.proc.pid, (
            "detached holder must not remain a tracked child"
        )
        assert tree.det["pid"] in tree.flock_holders()
    finally:
        tree.cleanup()
