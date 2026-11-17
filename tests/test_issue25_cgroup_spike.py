"""Issue #25 slice: Linux cgroup-v2 containment spike (TEST-ONLY).

Purpose: prove or refute, on a DELEGATED cgroup only, that cgroup
membership is a containment primitive stronger than the process group:
a fake mux leader joined into a disposable cgroup keeps its
``setsid``-escaping descendant inside that cgroup (membership is
per-task and survives ``setsid``/``setpgid``/``exec``), and
``cgroup.kill=1`` sweeps the escaped descendant while a sibling tree in a
separate cgroup is untouched.

Fail-closed contract (reviewer-mandated):
- The spike runs ONLY when the environment explicitly points at a
  writable, delegated cgroup subtree via ``ACP_TEST_CGROUP_ROOT``
  (absolute, pre-existing, WRITABLE, exposes a writable ``cgroup.kill``,
  and is not the mount root).  Anything else — missing, read-only,
  root-owned, no ``cgroup.kill`` — SKIPS with a BLOCKED reason.  No
  sudo, no chmod, no mounts, no mutation of any pre-existing cgroup, no
  moving of any pre-existing process.
- Only processes this test spawns are ever written into a cgroup, and
  only into directories this test created under the delegated root.
- Cleanup kills only its own fakes and rmdir's only its own empty dirs.

On the deployment container (hermes) the preflight is BLOCKED: the only
cgroup2 mount is ``ro`` and root-owned (see
docs/issue25-cgroup-spike-preflight.md), so the spike SKIPS — recorded
as NOT RUN, never as PASS.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.skipif(
        os.name != "posix" or not Path("/proc").is_dir(),
        reason="Linux cgroup v2 semantics under test",
    ),
]

ROOT_ENV = "ACP_TEST_CGROUP_ROOT"


def _delegated_root() -> Path | None:
    """Return a usable delegated cgroup subtree, or None (fail closed)."""
    raw = os.environ.get(ROOT_ENV, "").strip()
    if not raw or not os.path.isabs(raw):
        return None
    root = Path(raw)
    try:
        if root.resolve() == Path("/sys/fs/cgroup").resolve():
            return None  # never operate on the mount root
        if not (root / "cgroup.procs").is_file():
            return None  # not a cgroup directory
        if not os.access(root, os.W_OK):
            return None
        if not os.access(root / "cgroup.procs", os.W_OK):
            return None
        if not (root / "cgroup.kill").is_file():
            return None
        if not os.access(root / "cgroup.kill", os.W_OK):
            return None
    except OSError:
        return None
    return root


DELEGATED = _delegated_root()

_spike_gate = pytest.mark.skipif(
    DELEGATED is None,
    reason=(
        "BLOCKED (fail-closed): no writable delegated cgroup subtree via "
        f"${ROOT_ENV}; the spike is NOT RUN, never recorded as PASS"
    ),
)


def _wait(pred, timeout=20.0, step=0.05):
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


LEADER_SRC = """
import json, os, subprocess, sys, time
from pathlib import Path

here = Path(sys.argv[1])
expect = sys.argv[2]

# Do NOT spawn anything until our OWN membership is confirmed: children
# inherit the cgroup at fork time, so a pre-join fork would leak them.
deadline = time.monotonic() + 20
while expect not in Path("/proc/self/cgroup").read_text():
    if time.monotonic() > deadline:
        raise SystemExit("leader never joined target cgroup")
    time.sleep(0.02)

same = subprocess.Popen([sys.executable, str(here / "sleep.py")])
det = subprocess.Popen([sys.executable, str(here / "sleep.py")],
                       start_new_session=True)   # setsid escape model
here.joinpath("pids.json").write_text(json.dumps(
    {"leader": os.getpid(), "same": same.pid, "det": det.pid}))
time.sleep(600)
"""


class _Spike:
    """One disposable child cgroup + fake tree joined into it."""

    def __init__(self, name: str):
        assert DELEGATED is not None
        self.dir = DELEGATED / name
        self.dir.mkdir()
        self.procs = self.dir / "cgroup.procs"
        self.killfile = self.dir / "cgroup.kill"
        self.work = Path(f"/tmp/{name}-work-{os.getuid()}")
        if self.work.exists():
            shutil.rmtree(self.work)
        self.work.mkdir()
        (self.work / "leader.py").write_text(LEADER_SRC)
        (self.work / "sleep.py").write_text("import time; time.sleep(600)\n")
        self.proc = subprocess.Popen(
            [sys.executable, str(self.work / "leader.py"),
             str(self.work), self.dir.name],
        )
        # The documented join path for a delegatee moving its own child.
        self.procs.write_text(f"{self.proc.pid}\n")
        pids = self.work / "pids.json"
        assert _wait(lambda: pids.exists(), 25), "fake tree failed to start"
        self.pids = json.loads(pids.read_text())

    def members(self) -> set[int]:
        try:
            return {int(x) for x in self.procs.read_text().split()}
        except (FileNotFoundError, ValueError):
            return set()

    def cgroup_of(self, pid: int) -> str:
        for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
            if line.startswith("0::"):
                return line[3:]
        return ""

    def populated(self) -> str:
        for line in (self.dir / "cgroup.events").read_text().splitlines():
            if line.startswith("populated"):
                return line.split("=", 1)[1].strip()
        return "?"

    def cleanup(self):
        for pid in (self.pids["det"], self.pids["same"], self.proc.pid):
            try:
                os.kill(pid, 9)
            except (ProcessLookupError, OSError):
                pass
        assert _wait(lambda: self.populated() == "0", 20), (
            "spike cgroup must be empty before rmdir"
        )
        try:
            self.dir.rmdir()  # only ever our own, only when empty
        except OSError:
            pass
        shutil.rmtree(self.work, ignore_errors=True)


# ---------------------------------------------------------------------------


@_spike_gate
def test_membership_survives_setsid_escape_and_cgroup_kill_sweeps():
    target = _Spike("acp25-target")
    sibling = _Spike("acp25-sibling")
    try:
        # Layout: escaped descendant left the PGID/SID but NOT the cgroup.
        assert os.getpgid(target.pids["det"]) != target.proc.pid, (
            "setsid escape model failed"
        )
        assert target.cgroup_of(target.pids["det"]).endswith(
            target.dir.name
        ), "cgroup membership must survive setsid escape"
        for key in ("leader", "same", "det"):
            assert target.pids[key] in target.members(), key
        for key in ("leader", "same", "det"):
            assert sibling.pids[key] not in target.members()

        # cgroup.kill sweep: everything in target dies, including the
        # group-escaped descendant; the sibling cgroup is untouched.
        target.killfile.write_text("1")
        for key in ("leader", "same", "det"):
            assert _wait(lambda k=key: not _alive(target.pids[k]), 20), (
                f"target {key} survived cgroup.kill"
            )
        time.sleep(0.5)
        for key in ("leader", "same", "det"):
            assert _alive(sibling.pids[key]), "sibling cgroup was hit"
        assert target.populated() == "0", "empty proof failed"
    finally:
        target.cleanup()
        sibling.cleanup()


def test_preflight_never_touches_non_delegated_roots():
    # Fail-closed unit: every malformed/unsafe root resolves to None.
    for bad in ("", "relative/path", "/sys/fs/cgroup", "/proc/self"):
        saved = os.environ.get(ROOT_ENV)
        os.environ[ROOT_ENV] = bad
        try:
            assert _delegated_root() is None, bad
        finally:
            if saved is None:
                os.environ.pop(ROOT_ENV, None)
            else:
                os.environ[ROOT_ENV] = saved
