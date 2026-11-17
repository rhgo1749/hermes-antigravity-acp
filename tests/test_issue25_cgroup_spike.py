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
  root-owned, no ``cgroup.kill`` — SKIPS with a BLOCKED reason.  A
  delegated root whose freshly created CHILD cgroup lacks a writable
  ``cgroup.kill`` or is not a plain ``domain`` is ALSO a BLOCKED skip.
  No sudo, no chmod, no mounts, no mutation of any pre-existing cgroup,
  no moving of any pre-existing process.
- Only processes this test spawns are ever written into a cgroup, and
  only into directories this test created under the delegated root.
- Termination truth: zombies are never "running" (``/proc`` state ``Z``
  is checked); the authoritative whole-cgroup proof is
  ``cgroup.events populated=0`` plus an empty ``cgroup.procs``; the
  direct leader child is explicitly reaped and its exit status
  inspected (signal death => negative returncode).
- Cleanup is safe against any partial-construction state, always reaps
  its direct child, and ``rmdir``s only its own directories — a failed
  or incomplete removal FAILS the test (no silent residue).

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

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not Path("/proc").is_dir(),
    reason="Linux cgroup v2 semantics under test",
)

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


class _BlockedEnv(Exception):
    """Delegated root accepted, but the child cgroup semantics failed."""


def _wait(pred, timeout=20.0, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return False


def _running(pid: int) -> bool:
    """True only for a live (non-zombie) process."""
    try:
        with open(f"/proc/{pid}/stat") as fh:
            state = fh.read().rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
        return False
    except (PermissionError, IndexError):
        return True
    return state != "Z"


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
    """One disposable child cgroup + fake tree joined into it.

    Every resource is tracked the moment it comes into existence; the
    constructor cleans up on ANY partial-construction failure, and
    ``cleanup`` tolerates every partially-built state.
    """

    def __init__(self, name: str):
        assert DELEGATED is not None
        self.dir: Path | None = None
        self.work: Path | None = None
        self.proc: subprocess.Popen | None = None
        self.pids: dict | None = None
        self.procs: Path | None = None
        self.killfile: Path | None = None
        try:
            self.dir = DELEGATED / name
            self.dir.mkdir()
            self.killfile = self.dir / "cgroup.kill"
            if not self.killfile.is_file() or not os.access(
                self.killfile, os.W_OK
            ):
                raise _BlockedEnv(
                    f"{name}: child cgroup lacks a writable cgroup.kill"
                )
            try:
                ctype = (self.dir / "cgroup.type").read_text().strip()
            except OSError:
                ctype = ""
            if ctype != "domain":
                raise _BlockedEnv(
                    f"{name}: child cgroup.type={ctype!r}, not domain"
                )
            self.procs = self.dir / "cgroup.procs"
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
            if not _wait(lambda: pids.exists(), 25):
                raise RuntimeError("fake tree failed to start")
            self.pids = json.loads(pids.read_text())
        except _BlockedEnv as exc:
            self.cleanup(strict=False)
            pytest.skip(f"BLOCKED (fail-closed): {exc}")
        except BaseException:
            self.cleanup(strict=False)
            raise

    def members(self) -> set[int]:
        try:
            return {int(x) for x in self.procs.read_text().split()}
        except (AttributeError, FileNotFoundError, ValueError):
            return set()

    def cgroup_of(self, pid: int) -> str:
        for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
            if line.startswith("0::"):
                return line[3:]
        return ""

    def populated(self) -> str:
        try:
            for line in (self.dir / "cgroup.events").read_text().splitlines():
                if line.startswith("populated"):
                    return line.split("=", 1)[1].strip()
        except (AttributeError, OSError):
            pass
        return "?"

    def cleanup(self, strict: bool = True):
        # Grandchildren first (their parent is our direct child), then the
        # direct child — which is ALWAYS reaped.
        if self.pids is not None:
            for pid in (self.pids["det"], self.pids["same"]):
                try:
                    os.kill(pid, 9)
                except (ProcessLookupError, OSError):
                    pass
        if self.proc is not None:
            try:
                self.proc.kill()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                if strict:
                    raise
        if self.dir is not None:
            state = self.populated()
            if state == "1":
                empty = _wait(lambda: self.populated() == "0", 20)
            else:
                # "0" (real, empty) or "?" (no cgroup.events — construction
                # failed before a real cgroup existed): attempt removal.
                empty = True
            if strict and not empty:
                raise AssertionError("spike cgroup never reached populated=0")
            if empty:
                self.dir.rmdir()  # R3: failures propagate in strict mode
                if strict and self.dir.exists():
                    raise AssertionError(f"residue: {self.dir} still exists")
        if self.work is not None:
            shutil.rmtree(self.work, ignore_errors=True)


# ---------------------------------------------------------------------------


@_spike_gate
def test_membership_survives_setsid_escape_and_cgroup_kill_sweeps():
    spikes: list[_Spike] = []
    try:
        target = _Spike("acp25-target")
        spikes.append(target)
        sibling = _Spike("acp25-sibling")
        spikes.append(sibling)
        # Construction completed: these attributes exist by contract.
        assert target.pids and target.dir and target.proc and target.killfile
        assert sibling.pids and sibling.proc

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

        # cgroup.kill sweep.  The leader is OUR direct child: reap it
        # explicitly and inspect the exit status (signal death => negative).
        target.killfile.write_text("1")
        try:
            rc = target.proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            raise AssertionError("direct leader survived cgroup.kill") from None
        assert rc < 0, f"leader exited {rc}, expected signal death"
        # Grandchildren: zombie-aware liveness only.
        for key in ("same", "det"):
            assert _wait(lambda k=key: not _running(target.pids[k]), 20), (
                f"target {key} survived cgroup.kill"
            )
        # Authoritative whole-cgroup termination proof:
        assert _wait(lambda: target.populated() == "0", 20), "populated stuck"
        assert target.members() == set(), "cgroup.procs not empty"
        time.sleep(0.5)
        for key in ("leader", "same", "det"):
            assert _running(sibling.pids[key]), "sibling cgroup was hit"
    finally:
        for spike in spikes:
            spike.cleanup()


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
