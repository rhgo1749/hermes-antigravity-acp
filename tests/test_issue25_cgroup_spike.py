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
  delegated cgroup subtree via ``ACP_TEST_CGROUP_ROOT`` (absolute,
  pre-existing, and EFFECTIVELY WRITABLE for this process — the gate is
  a capability check via ``os.access``, not an owner check — with a
  writable ``cgroup.kill``, and not the mount root).  Anything else —
  missing, read-only, no ``cgroup.kill`` — SKIPS with a BLOCKED reason.
  A delegated root whose freshly created CHILD cgroup lacks a writable
  ``cgroup.kill`` or is not a plain ``domain`` is ALSO a BLOCKED skip.
  No sudo, no chmod, no mounts, no mutation of any pre-existing cgroup,
  no moving of any pre-existing process.
- Migration containment: cgroup v2 only lets a process move between
  cgroups sharing a writable common ancestor INSIDE the delegated
  branch.  ``ACP_TEST_CGROUP_ROOT`` must therefore be the RUNNING
  pytest process's own cgroup subtree (e.g. a transient
  ``systemd-run --user --scope -p Delegate=yes`` scope — see
  docs/issue25-cgroup-spike-preflight.md §7); an arbitrary writable
  sibling (e.g. bare ``app.slice`` from a login shell) fails with
  EACCES on the child join, as observed in the 2026-11-17 real run.
- Resource ownership: every resource is owned ONLY after its own
  creation call succeeded (``dir_created`` / ``work_created`` flags);
  cgroup names carry a nonce; the work dir comes from
  ``tempfile.mkdtemp`` and a pre-existing path is NEVER deleted, only
  ever our own creations.
- Pid publication from the fake leader is atomic (temp file +
  ``os.replace``) and the parent tolerates empty/partial JSON while
  waiting; if construction dies before pids are known, cleanup still
  sweeps every member of OUR OWN created cgroup via its ``cgroup.kill``.
- Termination truth: zombies are never "running" (``/proc`` state ``Z``
  is checked); the authoritative whole-cgroup proof is
  ``cgroup.events populated=0`` plus an empty ``cgroup.procs``; the
  direct leader child is explicitly reaped and its exit status
  inspected (signal death => negative returncode).
- Cleanup order is deterministic (own cgroup.kill -> known grandchildren
  -> direct child kill+reap -> populated=0 -> own dir rmdir -> own work
  rmtree).  Strict cleanup failures FAIL the test; non-strict cleanup
  never masks the original exception (residue is chained into it).

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
import tempfile
import time
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix" or not Path("/proc").is_dir(),
    reason="Linux cgroup v2 semantics under test",
)

ROOT_ENV = "ACP_TEST_CGROUP_ROOT"


def _delegated_root() -> Path | None:
    """Return a usable delegated cgroup subtree, or None (fail closed).

    Capability check (effective writability), not an ownership check.
    """
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
        "BLOCKED (fail-closed): no effectively writable delegated cgroup "
        f"subtree via ${ROOT_ENV}; the spike is NOT RUN, never recorded as PASS"
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


def _read_pids(path: Path, timeout: float = 25.0) -> dict | None:
    """Wait for an ATOMICALLY published, complete pids.json.

    ``exists`` may become true before the write completes; only a fully
    parseable dict with all keys counts.  Empty/partial content is
    retried, never read as truth.
    """
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            data = json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            time.sleep(0.05)
            continue
        if isinstance(data, dict) and {"leader", "same", "det"} <= data.keys():
            return data
        time.sleep(0.05)
    return None


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


def _parse_populated(text: str) -> str:
    """Parse the canonical ``cgroup.events`` line ``populated <0|1>``.

    The kernel writes whitespace-separated key/value pairs (real format:
    ``populated 0\\nfrozen 0``).  Key and value are matched strictly; any
    malformed input fails closed to ``"?"`` — never an IndexError, never a
    guess.  (Real-run bug, 2026-11-17: a ``split("=", 1)[1]`` parser
    IndexError'd on the canonical format and aborted cleanup, leaving
    owned cgroup dirs behind.)
    """
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "populated" and parts[1] in {"0", "1"}:
            return parts[1]
    return "?"


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
# Atomic publication: temp file + os.replace, so the parent never sees
# a half-written pids.json.
payload = {"leader": os.getpid(), "same": same.pid, "det": det.pid}
tmp = here / "pids.json.tmp"
tmp.write_text(json.dumps(payload))
os.replace(tmp, here / "pids.json")
time.sleep(600)
"""


class _Spike:
    """One disposable nonce-named child cgroup + fake tree joined into it.

    Ownership flags (``dir_created``/``work_created``) are set ONLY after
    the corresponding creation call succeeded; cleanup touches nothing
    it does not own.
    """

    def __init__(self, role: str):
        assert DELEGATED is not None
        self._init_attrs()
        try:
            self._build(role)
        except _BlockedEnv as exc:
            self.cleanup(strict=False)
            self._chain_cleanup_errors(exc)
            pytest.skip(f"BLOCKED (fail-closed): {exc}")
        except BaseException as exc:
            self.cleanup(strict=False)
            self._chain_cleanup_errors(exc)
            raise

    def _init_attrs(self) -> None:
        self.dir: Path | None = None
        self.dir_created = False
        self.work: Path | None = None
        self.work_created = False
        self.proc: subprocess.Popen | None = None
        self.pids: dict | None = None
        self.procs: Path | None = None
        self.killfile: Path | None = None
        self.killfile_ready = False
        self.cleanup_errors: list[str] = []

    def _chain_cleanup_errors(self, exc: BaseException) -> None:
        if self.cleanup_errors:
            raise RuntimeError(
                f"original failure: {exc!r}; cleanup residue: "
                f"{self.cleanup_errors}"
            ) from exc

    def _build(self, role: str) -> None:
        """Construct every resource in order, tracking ownership."""
        delegated = DELEGATED
        assert delegated is not None
        # Nonce name: never collide with a foreign/pre-existing cgroup.
        self.dir = delegated / f"acp25-{role}-{uuid.uuid4().hex[:10]}"
        self.dir.mkdir()  # EEXIST propagates; dir_created stays False
        self.dir_created = True
        # Positive validation BEFORE claiming containment capability:
        # cleanup may only write cgroup.kill when killfile_ready is set.
        killfile = self.dir / "cgroup.kill"
        if not killfile.is_file() or not os.access(killfile, os.W_OK):
            raise _BlockedEnv(
                f"{self.dir.name}: child cgroup lacks a writable cgroup.kill"
            )
        try:
            ctype = (self.dir / "cgroup.type").read_text().strip()
        except OSError:
            ctype = ""
        if ctype != "domain":
            raise _BlockedEnv(
                f"{self.dir.name}: child cgroup.type={ctype!r}, not domain"
            )
        self.killfile = killfile
        self.killfile_ready = True
        self.procs = self.dir / "cgroup.procs"
        # mkdtemp creates a fresh unique dir; a pre-existing path is
        # never adopted or deleted.
        self.work = Path(tempfile.mkdtemp(prefix=f"acp25-{role}-work-"))
        self.work_created = True
        (self.work / "leader.py").write_text(LEADER_SRC)
        (self.work / "sleep.py").write_text("import time; time.sleep(600)\n")
        self.proc = subprocess.Popen(
            [sys.executable, str(self.work / "leader.py"),
             str(self.work), self.dir.name],
            # Parity with the real plugin->mux spawn (client.py uses
            # start_new_session=True): the fake leader owns its own
            # PGID/SID so group-escape semantics are faithful.
            start_new_session=True,
        )
        # The documented join path for a delegatee moving its own child.
        self.procs.write_text(f"{self.proc.pid}\n")
        self.pids = _read_pids(self.work / "pids.json")
        if self.pids is None:
            raise RuntimeError("fake tree failed to publish pids atomically")

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
            return _parse_populated((self.dir / "cgroup.events").read_text())
        except (AttributeError, OSError):
            return "?"

    def cleanup(self, strict: bool = True):
        """Deterministic order; owns-only; strict failures raise.

        1. OUR OWN created cgroup: cgroup.kill sweeps every member
           (covers grandchildren whose pids were never published).
        2. Known grandchildren.
        3. Direct child: kill + ALWAYS reap.
        4. populated=0 proof.
        5. Own dir rmdir (only if we created it).
        6. Own work rmtree (only if we created it).
        """
        errors: list[str] = []
        if self.dir_created and self.killfile_ready and self.killfile is not None:
            try:
                self.killfile.write_text("1")
            except OSError as exc:
                errors.append(f"cgroup.kill: {exc}")
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
            except subprocess.TimeoutExpired as exc:
                errors.append(f"direct child unreaped: {exc}")
        if self.dir_created and self.dir is not None:
            state = self.populated()
            if state == "1":
                if not _wait(lambda: self.populated() == "0", 20):
                    errors.append("populated stuck at 1")
            try:
                self.dir.rmdir()
            except OSError as exc:
                errors.append(f"rmdir {self.dir.name}: {exc}")
            else:
                if self.dir.exists():
                    errors.append(f"residue: {self.dir} still exists")
        if self.work_created and self.work is not None:
            shutil.rmtree(self.work, ignore_errors=True)
            if self.work.exists():
                errors.append(f"residue: {self.work} still exists")
        self.cleanup_errors.extend(errors)
        if errors and strict:
            raise AssertionError(f"cleanup failed: {errors}")


# ---------------------------------------------------------------------------


@_spike_gate
def test_membership_survives_setsid_escape_and_cgroup_kill_sweeps():
    spikes: list[_Spike] = []
    try:
        target = _Spike("target")
        spikes.append(target)
        sibling = _Spike("sibling")
        spikes.append(sibling)
        # Construction completed: these attributes exist by contract.
        assert target.pids and target.dir and target.proc and target.killfile
        assert sibling.pids and sibling.proc

        # Layout preconditions (faithful process-model): the leader owns
        # its own group/session (start_new_session parity with the real
        # plugin->mux spawn); the same-group child shares them; the
        # escaped child left BOTH group and session.
        assert os.getpgid(target.proc.pid) == target.proc.pid, (
            "leader must own its PGID (start_new_session parity)"
        )
        assert os.getsid(target.proc.pid) == target.proc.pid, (
            "leader must own its session"
        )
        assert os.getpgid(target.pids["same"]) == target.proc.pid, (
            "same-group child must share the leader PGID"
        )
        assert os.getsid(target.pids["same"]) == target.proc.pid, (
            "same-group child must share the leader session"
        )
        assert (
            os.getpgid(target.pids["det"]) == target.pids["det"]
            and os.getsid(target.pids["det"]) == target.pids["det"]
        ), "detached child must own its own PGID/SID"
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


# -- resource-ownership regression tests (run everywhere) -------------------


def _fake_delegated(tmp_path, monkeypatch) -> Path:
    """A fake delegated root that passes the capability gate."""
    root = tmp_path / "fakecg"
    root.mkdir()
    (root / "cgroup.procs").touch()
    (root / "cgroup.kill").touch()
    monkeypatch.setenv(ROOT_ENV, str(root))
    monkeypatch.setattr(
        sys.modules[__name__], "DELEGATED", _delegated_root()
    )
    assert sys.modules[__name__].DELEGATED == root
    return root


def test_cgroup_name_collision_leaves_existing_dir_untouched(tmp_path, monkeypatch):
    root = _fake_delegated(tmp_path, monkeypatch)
    # Pin the nonce so _build's name deterministically hits a pre-existing
    # directory we do NOT own.
    monkeypatch.setattr(
        "uuid.uuid4", lambda: type("_U", (), {"hex": "a" * 32})()
    )
    existing = root / "acp25-target-aaaaaaaaaa"
    existing.mkdir()
    sentinel = existing / "sentinel"
    sentinel.write_text("not mine")
    spike = _Spike.__new__(_Spike)
    spike._init_attrs()
    with pytest.raises(FileExistsError):
        spike._build("target")
    assert spike.dir_created is False, "ownership flag set without mkdir success"
    spike.cleanup(strict=False)
    assert spike.cleanup_errors == []
    assert sentinel.exists(), "cleanup touched a cgroup dir it never created"
    assert existing.exists(), "pre-existing colliding dir must survive"


def test_existing_work_path_is_never_deleted(tmp_path, monkeypatch):
    _fake_delegated(tmp_path, monkeypatch)
    # Fully isolate mkdtemp's location under tmp_path — the test never
    # creates, writes, or removes anything in the real /tmp.
    tmploc = tmp_path / "tmploc"
    tmploc.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmploc))
    legacy = tmploc / f"acp25-target-work-{os.getuid()}"
    legacy.mkdir()
    sentinel = legacy / "sentinel"
    sentinel.write_text("pre-existing")
    spike = _Spike.__new__(_Spike)
    spike._init_attrs()
    with pytest.raises(_BlockedEnv):
        spike._build("target")  # fake child fails the cgroup.kill gate
    spike.cleanup(strict=False)
    assert spike.work_created is False and spike.work is None
    assert sentinel.exists(), "work-dir logic touched a pre-existing path"
    assert spike.cleanup_errors == []


def test_missing_child_cgroup_kill_skips_with_zero_residue(tmp_path, monkeypatch):
    """Constructor-level: child created but no cgroup.kill => BLOCKED skip.

    cleanup must NOT attempt a cgroup.kill write (killfile_ready False);
    only the owned empty child dir is removed.
    """
    root = _fake_delegated(tmp_path, monkeypatch)
    with pytest.raises(pytest.skip.Exception):
        _Spike("target")
    assert {p.name for p in root.iterdir()} == {"cgroup.procs", "cgroup.kill"}, (
        "residue left under the fake delegated root"
    )


def test_partial_pid_publication_never_read_as_truth(tmp_path):
    path = tmp_path / "pids.json"
    # Empty file: never truth.
    path.write_text("")
    assert _read_pids(path, timeout=0.3) is None
    # Partial JSON: never truth.
    path.write_text('{"leader": 1, "same"')
    assert _read_pids(path, timeout=0.3) is None
    # Incomplete keys: never truth.
    path.write_text('{"leader": 1}')
    assert _read_pids(path, timeout=0.3) is None
    # Complete atomic publication: truth.
    path.write_text('{"leader": 1, "same": 2, "det": 3}')
    assert _read_pids(path, timeout=0.3) == {"leader": 1, "same": 2, "det": 3}


def test_cleanup_sweeps_unknown_members_via_own_cgroup_kill_only(tmp_path):
    """pids unknown -> cleanup must use OUR created cgroup's cgroup.kill.

    The fake dir's regular files make ``rmdir`` return ENOTEMPTY (real
    cgroup files are virtual and vanish with the cgroup); that single
    documented artifact is the only tolerated cleanup error here.
    """
    spike = _Spike.__new__(_Spike)
    spike._init_attrs()
    owned = tmp_path / "owned"
    owned.mkdir()
    spike.dir = owned
    spike.dir_created = True
    killfile = owned / "cgroup.kill"
    procs = owned / "cgroup.procs"
    spike.killfile = killfile
    spike.killfile_ready = True
    killfile.touch()
    spike.procs = procs
    procs.write_text("")  # already empty (fake)
    spike.cleanup(strict=False)  # must not raise
    assert killfile.read_text() == "1", (
        "cleanup must sweep unknown members via the owned cgroup.kill"
    )
    assert len(spike.cleanup_errors) == 1 and spike.cleanup_errors[0].startswith(
        "rmdir owned:"
    ), spike.cleanup_errors
    # Finish removal manually (fake files are not virtual cgroup files).
    killfile.unlink()
    procs.unlink()
    owned.rmdir()
    assert not owned.exists()


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


# -- cgroup.events parser regressions (run everywhere) ----------------------


def test_parse_populated_canonical_and_malformed():
    # Real kernel format is whitespace-separated key/value.
    assert _parse_populated("populated 0\nfrozen 0\n") == "0"
    assert _parse_populated("populated 1\nfrozen 0\n") == "1"
    # Malformed or non-canonical shapes fail closed to "?", never raise.
    for malformed in (
        "",
        "populated\n",
        "populated=0\n",       # legacy wrong assumption (the real-run bug)
        "populated 2\n",       # value outside {0,1}
        "populated 0 extra\n",  # not exactly key+value
        "frozen 0\n",          # key absent
        "POPULATED 0\n",       # key must match exactly
        "populated0\n",        # not whitespace-separated
    ):
        assert _parse_populated(malformed) == "?", repr(malformed)


def test_populated_method_parses_real_events_format(tmp_path):
    """Real-run bug: the old ``split('=', 1)[1]`` parser IndexError'd on
    ``populated 0``; the method must return the value, never raise."""
    spike = _Spike.__new__(_Spike)
    spike._init_attrs()
    d = tmp_path / "cg"
    d.mkdir()
    spike.dir = d
    (d / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    assert spike.populated() == "0"
    (d / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    assert spike.populated() == "1"
    (d / "cgroup.events").write_text("populated=0\n")
    assert spike.populated() == "?"
    spike.dir = d / "gone"
    assert spike.populated() == "?"


def test_cleanup_survives_real_events_format(tmp_path):
    """Real-run residue bug: cleanup aborted with IndexError on the
    canonical events format and left the owned dir behind.  Here the only
    tolerated artifact is the fake-file ENOTEMPTY rmdir (real cgroup files
    are virtual and vanish with the cgroup)."""
    spike = _Spike.__new__(_Spike)
    spike._init_attrs()
    owned = tmp_path / "owned"
    owned.mkdir()
    killfile = owned / "cgroup.kill"
    spike.dir = owned
    spike.dir_created = True
    spike.killfile = killfile
    spike.killfile_ready = True
    killfile.touch()
    spike.procs = owned / "cgroup.procs"
    spike.procs.write_text("")
    events = owned / "cgroup.events"
    events.write_text("populated 0\nfrozen 0\n")
    spike.cleanup(strict=False)  # must not raise IndexError
    assert killfile.read_text() == "1"
    assert len(spike.cleanup_errors) == 1 and spike.cleanup_errors[0].startswith(
        "rmdir owned:"
    ), spike.cleanup_errors
    # Finish removal manually (fake files are not virtual cgroup files).
    events.unlink()
    killfile.unlink()
    (owned / "cgroup.procs").unlink()
    owned.rmdir()
    assert not owned.exists()
