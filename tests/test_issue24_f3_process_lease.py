"""Issue #24 Phase 3 (F3): per-lane process lease protects live/parked children.

The native GC runs inside one mux process but scans stores shared with the
official ACP children of every other mux process (counterexample C1).  F3
gives each mux a shared flock lease on its bound lane; the GC and the
read-only inventory must treat a lane as protected unless the lease is
positively cleared:

- ``live``        - at least one exclusive probe failed: a holder is alive.
- ``grace``       - no holder, but the last heartbeat is within the grace.
- ``absent``      - no lease file exists (old mux build, never-bound lane):
  absence of evidence is NOT evidence of absence; protected.
- ``unsupported`` / ``unavailable`` - no flock or unreadable lease: fail closed.
- ``stale``       - no holder and the heartbeat is older than the grace: the
  only state in which bundles in that lane may be reclaimed.

Kernel lock semantics provide the crash/restart/PID-reuse evidence: flock is
released automatically when a holder dies, so no pid liveness heuristics are
needed.  F3 changes ZERO deletion mechanics and authorizes nothing new: it
only ever ADDS protection.  Credential-free fakes only; no live vendor.
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("f3_mux", ROOT / "scripts" / "acp_mux.py")
assert spec and spec.loader
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)

DAY = 86400
SID_LEASED = "f1f1f1f1-f1f1-4f1f-8f1f-f1f1f1f1f1f1"
SID_OTHER = "f2f2f2f2-f2f2-4f2f-8f2f-f2f2f2f2f2f2"
SID_B = "f3f3f3f3-f3f3-4f3f-8f3f-f3f3f3f3f3f3"


@pytest.fixture(autouse=True)
def _fleet_cutover_ack(monkeypatch):
    """Most F3 tests exercise post-cutover behavior.

    The fleet cutover fence itself (issue #24 review B2) is covered by the
    dedicated test_b2_* cases; everything else acknowledges the drain so it
    can reach the GC at all.  The F4 process-tree evidence ack is likewise
    acknowledged here; its own fence has dedicated tests in the F4 suite.
    """
    monkeypatch.setenv("ACP_MUX_F3_CUTOVER_ACK", "1")
    monkeypatch.setenv("ACP_MUX_F4_PROCESS_TREE_ACK", "1")


@pytest.fixture
def lanes(tmp_path, monkeypatch):
    monkeypatch.setenv("ACP_MUX_DEFAULT_HOME", str(tmp_path / "default-home"))
    monkeypatch.setattr(mux, "DEFAULT_HOME", str(tmp_path / "default-home"))
    monkeypatch.setattr(mux, "STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setattr(mux, "REGISTRY_PATH", str(tmp_path / "accounts.json"))
    monkeypatch.setattr(mux, "LOG_PATH", str(tmp_path / "mux.log"))
    monkeypatch.setattr(mux, "LEASE_GRACE_SECONDS", 600)
    a, b = tmp_path / "home-alpha", tmp_path / "home-beta"
    for home in (a, b):
        (home / ".gemini" / "antigravity-acp" / "conversations").mkdir(parents=True)
    Path(mux.REGISTRY_PATH).write_text(json.dumps({"accounts": [
        {"home": str(a), "label": "lane-alpha"}, {"home": str(b), "label": "lane-beta"}
    ]}))
    state_file = tmp_path / "acp-sessions.json"
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(state_file))
    state_file.write_text(json.dumps({"version": 1, "states": {}}))
    return a, b, state_file


def _bundle(home: Path, session_id: str, *, mtime: float) -> Path:
    store = home / ".gemini" / "antigravity-acp"
    db = store / "conversations" / f"{session_id}.db"
    db.write_text("fixture-payload")
    brain = store / "brain" / session_id
    brain.mkdir(parents=True, exist_ok=True)
    (brain / "note.md").write_text("brain")
    os.utime(db, (mtime, mtime))
    os.utime(brain, (mtime, mtime))
    return db


def _seed_expired(home: Path, session_id: str, now: float) -> Path:
    db = _bundle(home, session_id, mtime=now - 40 * DAY)
    # F4 review R2: deletion authority requires positive owner evidence;
    # F3 lease tests are about leases, so every seeded bundle carries a
    # valid ephemeral owner record for its lane.
    label = "lane-beta" if "beta" in str(home) else "lane-alpha"
    assert mux._record_session_owner(
        session_id, str(home), label, origin="agent", lifecycle="ephemeral"
    )
    return db


def _write_lease(home: Path, label: str, *, at: float) -> Path:
    path = Path(mux._lane_lease_path(str(home), label))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"at": at, "mux_pid": os.getpid()}))
    return path


class _HeldLease:
    """A live lease holder: shared flock held open for the object's lifetime."""

    def __init__(self, home: Path, label: str):
        self.path = Path(mux._lane_lease_path(str(home), label))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_SH)
        os.ftruncate(self.fd, 0)
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.write(self.fd, json.dumps({"at": time.time(), "mux_pid": os.getpid()}).encode())

    def release(self) -> None:
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


# ---------------------------------------------------------------------------
# 1. Lease state machine.
# ---------------------------------------------------------------------------

def test_absent_lease_reads_as_absent_not_stale(lanes):
    a, _b, _state = lanes
    assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "absent"


def test_held_lease_is_live(lanes):
    a, _b, _state = lanes
    holder = _HeldLease(a, "lane-alpha")
    try:
        assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "live"
    finally:
        holder.release()


def test_released_lease_within_grace_is_grace_then_stale(lanes):
    a, _b, _state = lanes
    now = time.time()
    _write_lease(a, "lane-alpha", at=now - 60)
    assert mux._lane_lease_state(str(a), "lane-alpha", now=now) == "grace"
    _write_lease(a, "lane-alpha", at=now - 601)
    assert mux._lane_lease_state(str(a), "lane-alpha", now=now) == "stale"


def test_corrupt_lease_fails_closed(lanes):
    a, _b, _state = lanes
    path = Path(mux._lane_lease_path(str(a), "lane-alpha"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("not-json{{")
    assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "unavailable"


def test_symlinked_lease_fails_closed(lanes, tmp_path):
    a, _b, _state = lanes
    real = tmp_path / "evil.json"
    real.write_text(json.dumps({"at": 0.0, "mux_pid": 1}))
    path = Path(mux._lane_lease_path(str(a), "lane-alpha"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(real)
    assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "unavailable"


def test_no_fcntl_reads_as_unsupported(lanes, monkeypatch):
    a, _b, _state = lanes
    monkeypatch.setattr(mux, "fcntl", None)
    assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "unsupported"


def test_only_stale_is_unprotected():
    for state in ("live", "grace", "absent", "unsupported", "unavailable"):
        assert mux._lane_lease_protected(state) is True
    assert mux._lane_lease_protected("stale") is False


def test_lease_state_probe_never_creates_files(lanes):
    a, _b, _state = lanes
    path = Path(mux._lane_lease_path(str(a), "lane-alpha"))
    before = set(os.listdir(path.parent)) if path.parent.exists() else set()
    assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "absent"
    assert not path.exists()
    after = set(os.listdir(path.parent)) if path.parent.exists() else set()
    assert after == before


# ---------------------------------------------------------------------------
# 2. Crash semantics come from the kernel, not from pid heuristics.
# ---------------------------------------------------------------------------

def test_sigkill_holder_releases_lease_into_grace(lanes):
    a, _b, _state = lanes
    lease_path = Path(mux._lane_lease_path(str(a), "lane-alpha"))
    lease_path.parent.mkdir(parents=True, exist_ok=True)
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import fcntl,json,os,sys,time\n"
         "fd=os.open(sys.argv[1],os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)\n"
         "fcntl.flock(fd,fcntl.LOCK_SH)\n"
         "os.ftruncate(fd,0);os.lseek(fd,0,os.SEEK_SET)\n"
         "os.write(fd,json.dumps({'at':time.time(),'mux_pid':os.getpid()}).encode())\n"
         "print('ready',flush=True)\n"
         "time.sleep(60)\n",
         str(lease_path)],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "ready"
        assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "live"
        holder.kill()
        holder.wait(timeout=10)
        # Kernel released the flock at death; the heartbeat is fresh: grace.
        deadline = time.time() + 5
        while time.time() < deadline:
            if mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "grace":
                break
            time.sleep(0.05)
        assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "grace"
    finally:
        if holder.poll() is None:
            holder.kill()


def test_second_holder_keeps_lane_live_after_first_dies(lanes):
    a, _b, _state = lanes
    first = _HeldLease(a, "lane-alpha")
    second = _HeldLease(a, "lane-alpha")
    try:
        assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "live"
    finally:
        first.release()
    try:
        assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "live"
    finally:
        second.release()


# ---------------------------------------------------------------------------
# 3. The GC deletes only behind a positively cleared (stale) lease.
# ---------------------------------------------------------------------------

def test_gc_deletes_expired_bundle_behind_stale_lease(lanes):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_LEASED, now)
    _write_lease(a, "lane-alpha", at=now - 601)
    _write_lease(Path(_b), "lane-beta", at=now - 601)
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 1
    assert not db.exists()


def test_gc_protects_expired_bundle_under_live_lease(lanes):
    a, b, _state = lanes
    now = time.time()
    leased_db = _seed_expired(a, SID_LEASED, now)
    _write_lease(Path(b), "lane-beta", at=now - 601)
    holder = _HeldLease(a, "lane-alpha")
    try:
        result = mux.prune_session_stores(now=now)
    finally:
        holder.release()
    assert result is not None and result["expired"] == 0
    assert leased_db.exists()


def test_gc_protects_expired_bundle_during_grace(lanes):
    a, b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_LEASED, now)
    _write_lease(a, "lane-alpha", at=now - 60)
    _write_lease(Path(b), "lane-beta", at=now - 601)
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert db.exists()


def test_absent_lease_fails_closed_in_gc(lanes):
    a, b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_LEASED, now)
    _write_lease(Path(b), "lane-beta", at=now - 601)
    # lane-alpha has NO lease file at all: unknown evidence, protected.
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert db.exists()


def test_leased_lane_never_starves_sibling_lane(lanes):
    a, b, _state = lanes
    now = time.time()
    leased_db = _seed_expired(a, SID_LEASED, now)
    sibling_db = _seed_expired(Path(b), SID_B, now)
    _write_lease(Path(b), "lane-beta", at=now - 601)
    holder = _HeldLease(a, "lane-alpha")
    try:
        result = mux.prune_session_stores(now=now)
    finally:
        holder.release()
    assert result is not None and result["expired"] == 1
    assert leased_db.exists() and not sibling_db.exists()


def test_unsupported_fcntl_gc_stays_fail_closed(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_LEASED, now)
    monkeypatch.setattr(mux, "fcntl", None)
    assert mux.prune_session_stores(now=now) is None
    assert db.exists()


# ---------------------------------------------------------------------------
# 4. Inventory reports lease states and its prediction matches the policy.
# ---------------------------------------------------------------------------

def _inventory(state_file: Path, *, now: float) -> dict:
    return mux.session_inventory(now=now, env={
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE": str(state_file)
    })


def _lane_by_bundles(report: dict, count: int) -> dict:
    return next(row for row in report["lanes"] if row["bundles"] == count)


def test_inventory_reports_live_lease_and_zero_candidates(lanes):
    a, b, state_file = lanes
    now = time.time()
    _seed_expired(a, SID_LEASED, now)
    _seed_expired(Path(b), SID_B, now)
    _write_lease(Path(b), "lane-beta", at=now - 601)
    holder = _HeldLease(a, "lane-alpha")
    try:
        report = _inventory(state_file, now=now)
    finally:
        holder.release()
    assert report["status"] == "ok"
    leased = _lane_by_bundles(report, 1)
    assert leased["lease"] == "live"
    assert leased["gc_candidate_expired"] == 0
    free = next(row for row in report["lanes"] if row["lease"] == "stale")
    assert free["gc_candidate_expired"] == 1
    # Protected: lane-alpha (live) plus the never-bound default-home lane
    # (absent lease: unknown evidence, protected by design).
    assert report["totals"]["lanes_lease_protected"] == 2
    assert report["totals"]["gc_candidate_expired"] == 1
    assert report["deletions_performed"] == 0


def test_inventory_absent_lease_counts_as_protected(lanes):
    a, b, state_file = lanes
    now = time.time()
    _seed_expired(a, SID_LEASED, now)
    _seed_expired(Path(b), SID_B, now)
    _write_lease(Path(b), "lane-beta", at=now - 601)
    report = _inventory(state_file, now=now)
    absent_lane = next(row for row in report["lanes"] if row["lease"] == "absent")
    assert absent_lane["gc_candidate_expired"] == 0
    # lane-alpha (absent) + the never-bound default-home lane (also absent).
    assert report["totals"]["lanes_lease_protected"] == 2
    assert report["totals"]["gc_candidate_expired"] == 1


def test_inventory_prediction_matches_gc_under_grace(lanes):
    a, b, state_file = lanes
    now = time.time()
    db = _seed_expired(a, SID_LEASED, now)
    _write_lease(a, "lane-alpha", at=now - 60)
    _write_lease(Path(b), "lane-beta", at=now - 601)
    report = _inventory(state_file, now=now)
    grace_lane = next(row for row in report["lanes"] if row["lease"] == "grace")
    assert grace_lane["gc_candidate_expired"] == 0
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert db.exists()


# ---------------------------------------------------------------------------
# 5. End-to-end: the mux takes the lease at bind and heartbeats on activity.
# ---------------------------------------------------------------------------

def _fake_vendor(tmp_path: Path) -> Path:
    fake = tmp_path / "fake_vendor.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys,time\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line); method=r.get('method')\n"
        " result={'home':__import__('os').environ['HOME']}\n"
        " if method=='session/new': result['sessionId']='e2e2e2e2-e2e2-4e2e-8e2e-e2e2e2e2e2e2'\n"
        " if method=='session/prompt': result['stopReason']='end_turn'\n"
        " print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),'result':result}),flush=True)\n"
    )
    fake.chmod(0o755)
    return fake


def _mux_env(tmp_path: Path, lanes) -> dict:
    env = os.environ.copy()
    env.update({
        "ACP_MUX_ACCOUNTS": mux.REGISTRY_PATH, "ACP_MUX_STATE": mux.STATE_PATH,
        "ACP_MUX_LOG": mux.LOG_PATH, "ACP_MUX_PAR": str(_fake_vendor(tmp_path)),
        "ACP_MUX_AFFINITY": "f3-affinity", "HOME": str(tmp_path),
        "HERMES_REAL_HOME": str(tmp_path),
    })
    return env


def _lease_at(home: Path, label: str) -> float:
    return json.loads(Path(mux._lane_lease_path(str(home), label)).read_text())["at"]


def test_mux_bind_takes_lease_and_sigkill_lands_in_grace(lanes, tmp_path):
    a, _b, _state = lanes
    env = _mux_env(tmp_path, lanes)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env=env, bufsize=1,
    )
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "session/new",
                                     "params": {}}) + "\n")
        proc.stdin.flush()
        replies = {}
        for _ in range(2):
            msg = json.loads(proc.stdout.readline())
            replies[msg["id"]] = msg
        assert "error" not in replies[2]
        assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "live"
        proc.kill()
        proc.wait(timeout=10)
        # Late-completion window: the mux died but its heartbeat is fresh.
        # The fake vendor exits on stdin EOF; poll until the whole lineage
        # (mux + inherited child fd) has released the lock.
        deadline = time.time() + 10
        state = "live"
        while time.time() < deadline:
            state = mux._lane_lease_state(str(a), "lane-alpha", now=time.time())
            if state != "live":
                break
            time.sleep(0.05)
        assert state == "grace"
    finally:
        if proc.poll() is None:
            proc.kill()


def _read_reply(proc, timeout: float = 20.0) -> dict:
    """One reply read bounded by a whole-line deadline (buffer-safe).

    A reader thread owns the blocking readline; the deadline governs the
    entire line and works regardless of TextIOWrapper read-ahead, which
    makes select-before-readline unsound for back-to-back replies.
    """
    import queue
    import threading

    box: queue.Queue = queue.Queue()

    def _reader() -> None:
        try:
            box.put(proc.stdout.readline())
        except Exception as exc:  # pragma: no cover - failure path
            box.put(exc)

    threading.Thread(target=_reader, daemon=True).start()
    try:
        line = box.get(timeout=timeout)
    except queue.Empty:
        raise AssertionError(
            f"mux produced no complete stdout line within {timeout}s"
        ) from None
    if isinstance(line, BaseException):
        raise line
    if not line:
        raise AssertionError("mux closed stdout before replying")
    return json.loads(line)


def test_shipped_entrypoint_bind_takes_lease(lanes, tmp_path):
    """The launcher ships antigravity-acp-mux.py, not acp_mux.py.

    Issue #24 follow-up: the entrypoint's duplicated ``bind`` predated F3 and
    never took the lane lease, so every deployed mux ran without lease
    evidence and the native GC fail-closed on ``absent`` for every lane
    forever.  The base-only tests above stayed green the whole time; this
    test pins the lease contract to the entrypoint that actually ships.
    """
    a, _b, _state = lanes
    env = _mux_env(tmp_path, lanes)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "antigravity-acp-mux.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env=env, bufsize=1,
    )
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "session/new",
                                     "params": {}}) + "\n")
        proc.stdin.flush()
        replies = {}
        for _ in range(2):
            msg = _read_reply(proc)
            replies[msg["id"]] = msg
        assert "error" not in replies[2]
        assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "live"
        proc.kill()
        proc.wait(timeout=10)
        deadline = time.time() + 10
        state = "live"
        while time.time() < deadline:
            state = mux._lane_lease_state(str(a), "lane-alpha", now=time.time())
            if state != "live":
                break
            time.sleep(0.05)
        assert state == "grace"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        # Failure-path cleanup: the fake vendor normally exits on stdin EOF,
        # but a mid-test failure must not leave it holding the lease.
        for pid in _vendor_pids(env["ACP_MUX_PAR"]):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_shipped_entrypoint_b1_surviving_child_keeps_lease_live(lanes, tmp_path):
    """B1 lease-fd inheritance must hold on the SHIPPED entrypoint too.

    Mirrors test_b1_surviving_vendor_child_keeps_lease_live_after_mux_sigkill
    against scripts/antigravity-acp-mux.py: the direct child inherits the
    lease fd, so SIGKILLing the mux leaves the lane ``live`` while the child
    survives, and only the full lineage's death makes it reclaimable.
    """
    a, _b, _state = lanes
    lease_path = mux._lane_lease_path(str(a), "lane-alpha")
    env = _mux_env(tmp_path, lanes)
    fake = _longlived_fake_vendor(tmp_path, lease_path)
    env["ACP_MUX_PAR"] = str(fake)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "antigravity-acp-mux.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env=env, bufsize=1,
    )
    child_pids: list[int] = []
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1,
                                     "method": "initialize"}) + "\n")
        proc.stdin.flush()
        reply = _read_reply(proc)
        assert reply["result"]["leaseInherited"] is True
        assert mux._lane_lease_state(str(a), "lane-alpha",
                                     now=time.time()) == "live"
        _age_lease_heartbeat(a, "lane-alpha",
                             at=time.time() - 10 * mux.LEASE_GRACE_SECONDS)
        assert mux._lane_lease_state(str(a), "lane-alpha",
                                     now=time.time()) == "live"
        child_pids = _vendor_pids(str(fake))
        assert child_pids, "fake vendor child did not start"
        proc.kill()
        proc.wait(timeout=10)
        assert _vendor_pids(str(fake)), "vendor child died with the mux"
        assert mux._lane_lease_state(str(a), "lane-alpha",
                                     now=time.time()) == "live"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        for pid in child_pids + _vendor_pids(str(fake)):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    deadline = time.time() + 10
    state = "live"
    while time.time() < deadline:
        state = mux._lane_lease_state(str(a), "lane-alpha", now=time.time())
        if state != "live":
            break
        time.sleep(0.05)
    assert state == "stale"


def test_mux_heartbeat_touches_lease_on_turn_completion(lanes, tmp_path):
    a, _b, _state = lanes
    env = _mux_env(tmp_path, lanes)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env=env, bufsize=1,
    )
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
        proc.stdin.flush()
        json.loads(proc.stdout.readline())
        lease_path = mux._lane_lease_path(str(a), "lane-alpha")
        # Age the heartbeat while the lease stays held, then complete a turn.
        aged = time.time() - 300
        fd = os.open(lease_path, os.O_RDWR | os.O_NOFOLLOW)
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, json.dumps({"at": aged, "mux_pid": 1}).encode())
        os.close(fd)
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 7,
                                     "method": "session/prompt",
                                     "params": {"sessionId": "x", "prompt": []}}) + "\n")
        proc.stdin.flush()
        reply = json.loads(proc.stdout.readline())
        assert reply["id"] == 7
        assert _lease_at(a, "lane-alpha") > aged
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_mux_graceful_exit_releases_lease_into_grace(lanes, tmp_path):
    a, _b, _state = lanes
    env = _mux_env(tmp_path, lanes)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env=env, bufsize=1,
    )
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
    proc.stdin.flush()
    json.loads(proc.stdout.readline())
    assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "live"
    proc.stdin.close()  # EOF: graceful teardown path
    proc.wait(timeout=15)
    assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "grace"


# ---------------------------------------------------------------------------
# 6. Independent-review counterexamples B1-B4 (issue #24 rework).
# ---------------------------------------------------------------------------

def _longlived_fake_vendor(tmp_path: Path, lease_path: str) -> Path:
    """ACP fake that reports lease-fd inheritance and survives stdin EOF.

    A busy or EOF-ignoring official child outlives a SIGKILLed mux; this
    fake reproduces that without any vendor binary or credentials.
    """
    fake = tmp_path / "longlived_vendor.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys,time\n"
        f"LEASE={lease_path!r}\n"
        "def inherited():\n"
        " try: expected=os.stat(LEASE).st_ino\n"
        " except OSError: return False\n"
        " for name in os.listdir('/proc/self/fd'):\n"
        "  try: target=os.readlink('/proc/self/fd/'+name)\n"
        "  except OSError: continue\n"
        "  if target==LEASE:\n"
        "   try:\n"
        "    if os.fstat(int(name)).st_ino==expected: return True\n"
        "   except OSError: pass\n"
        " return False\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line)\n"
        " result={'home':os.environ['HOME'],'leaseInherited':inherited()}\n"
        " if r.get('method')=='session/new':\n"
        "  result['sessionId']='b1b1b1b1-b1b1-4b1b-8b1b-b1b1b1b1b1b1'\n"
        " print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),\n"
        "                   'result':result}),flush=True)\n"
        "time.sleep(300)\n"
    )
    fake.chmod(0o755)
    return fake


def _age_lease_heartbeat(home: Path, label: str, *, at: float) -> None:
    fd = os.open(mux._lane_lease_path(str(home), label),
                 os.O_RDWR | os.O_NOFOLLOW)
    try:
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, json.dumps({"at": at, "mux_pid": 1}).encode())
    finally:
        os.close(fd)


def _vendor_pids(marker: str) -> list[int]:
    out = subprocess.run(["pgrep", "-f", marker],
                         capture_output=True, text=True)
    return [int(x) for x in out.stdout.split()]


def test_b1_surviving_vendor_child_keeps_lease_live_after_mux_sigkill(
    lanes, tmp_path
):
    """B1: kernel release of the *mux* fd must not mean vendor death.

    The lease fd is inherited by the direct official child, so the shared
    lock stays held while either the mux or that child is alive.  An aged
    heartbeat may only produce `stale` once both are gone.  (Vendor
    descendants beyond the direct child are the B5 boundary.)
    """
    a, _b, _state = lanes
    lease_path = mux._lane_lease_path(str(a), "lane-alpha")
    env = _mux_env(tmp_path, lanes)
    fake = _longlived_fake_vendor(tmp_path, lease_path)
    env["ACP_MUX_PAR"] = str(fake)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env=env, bufsize=1,
    )
    child_pids: list[int] = []
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1,
                                     "method": "initialize"}) + "\n")
        proc.stdin.flush()
        reply = json.loads(proc.stdout.readline())
        # The child must have received the lease fd (same open file
        # description), or the lock cannot cover it after mux death.
        assert reply["result"]["leaseInherited"] is True
        assert mux._lane_lease_state(str(a), "lane-alpha",
                                     now=time.time()) == "live"
        _age_lease_heartbeat(a, "lane-alpha",
                             at=time.time() - 10 * mux.LEASE_GRACE_SECONDS)
        assert mux._lane_lease_state(str(a), "lane-alpha",
                                     now=time.time()) == "live"
        child_pids = _vendor_pids(str(fake))
        assert child_pids, "fake vendor child did not start"
        proc.kill()
        proc.wait(timeout=10)
        # The vendor child is still alive and still holds the inherited fd.
        assert _vendor_pids(str(fake)), "vendor child died with the mux"
        assert mux._lane_lease_state(str(a), "lane-alpha",
                                     now=time.time()) == "live"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        for pid in child_pids + _vendor_pids(str(fake)):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    # Once the whole lineage is gone, the aged heartbeat makes the lane
    # reclaimable again: protection must not be permanent.
    deadline = time.time() + 10
    state = "live"
    while time.time() < deadline:
        state = mux._lane_lease_state(str(a), "lane-alpha", now=time.time())
        if state != "live":
            break
        time.sleep(0.05)
    assert state == "stale"


def test_b2_gc_refused_until_fleet_cutover_acknowledged(lanes, monkeypatch):
    """B2: a stale new-mux lease does not prove no pre-F3 mux is alive.

    During a rolling upgrade an old mux can hold the same lane without any
    flock.  Until the operator acknowledges the legacy drain, the GC must
    refuse to run even behind a positively-cleared (stale) lease.
    """
    a, _b, _state = lanes
    monkeypatch.delenv("ACP_MUX_F3_CUTOVER_ACK", raising=False)
    now = time.time()
    db = _seed_expired(a, SID_LEASED, now)
    _write_lease(a, "lane-alpha", at=now - mux.LEASE_GRACE_SECONDS - 60)
    _write_lease(Path(_b), "lane-beta", at=now - mux.LEASE_GRACE_SECONDS - 60)
    assert mux.prune_session_stores(now=now) is None
    assert db.exists()


def test_b2_gc_proceeds_after_cutover_ack(lanes, monkeypatch):
    a, _b, _state = lanes
    monkeypatch.setenv("ACP_MUX_F3_CUTOVER_ACK", "1")
    now = time.time()
    db = _seed_expired(a, SID_LEASED, now)
    _write_lease(a, "lane-alpha", at=now - mux.LEASE_GRACE_SECONDS - 60)
    _write_lease(Path(_b), "lane-beta", at=now - mux.LEASE_GRACE_SECONDS - 60)
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 1
    assert not db.exists()


def test_b3_heartbeat_writes_never_regress_timestamp(lanes, monkeypatch):
    """B3: a legal write interleaving must not shorten the grace window.

    Two shared holders may compute heartbeats in any order; the recorded
    `at` must never move backwards.
    """
    a, _b, _state = lanes
    clock = {"t": 100.0}
    monkeypatch.setattr(mux.time, "time", lambda: clock["t"])
    first = mux._LaneLease(str(a), "lane-alpha")
    second = mux._LaneLease(str(a), "lane-alpha")
    clock["t"] = 50.0  # earlier-computed write lands last
    second.touch()
    first.close()
    second.close()
    assert _lease_at(a, "lane-alpha") >= 100.0


def test_b3_parallel_heartbeat_writers_keep_lease_parseable(lanes):
    """B3: concurrent serialized writers must never tear the JSON file."""
    import threading

    a, _b, _state = lanes
    holders = [mux._LaneLease(str(a), "lane-alpha") for _ in range(2)]
    errors: list[BaseException] = []

    def hammer(lease):
        try:
            for _ in range(40):
                lease.touch()
        except BaseException as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [
        threading.Thread(target=hammer, args=(holders[i % 2],))
        for i in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert not errors
    for lease in holders:
        lease.close()
    payload = json.loads(
        Path(mux._lane_lease_path(str(a), "lane-alpha")).read_text()
    )
    assert isinstance(payload["at"], (int, float))


def test_b4_bind_refuses_without_spawning_while_exclusive_lease_held(
    lanes, tmp_path
):
    """B4: the advertised bind deadline must actually fire under contention."""
    a, _b, _state = lanes
    lease_path = Path(mux._lane_lease_path(str(a), "lane-alpha"))
    lease_path.parent.mkdir(parents=True, exist_ok=True)
    holder_fd = os.open(lease_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                        0o600)
    fcntl.flock(holder_fd, fcntl.LOCK_EX)
    marker = tmp_path / "child_spawned"
    fake = tmp_path / "spawn_marker.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib,sys\n"
        f"pathlib.Path({str(marker)!r}).write_text('1')\n"
        "sys.stdin.read()\n"
    )
    fake.chmod(0o755)
    env = _mux_env(tmp_path, lanes)
    env["ACP_MUX_PAR"] = str(fake)
    try:
        try:
            proc = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
                input=json.dumps({"jsonrpc": "2.0", "id": 1,
                                  "method": "initialize"}) + "\n",
                capture_output=True, text=True, env=env, timeout=25,
            )
        except subprocess.TimeoutExpired:
            pytest.fail(
                "B4: mux blocked forever on the exclusive lease holder; "
                "the LOCK_SH acquire must be non-blocking with a real deadline"
            )
        assert proc.returncode == 2
        assert not marker.exists(), "child spawned despite lease contention"
        assert "lease-unavailable" in Path(mux.LOG_PATH).read_text()
    finally:
        fcntl.flock(holder_fd, fcntl.LOCK_UN)
        os.close(holder_fd)


def _wrapper_vendor_with_grandchild(tmp_path: Path, lease_path: str) -> Path:
    """ACP fake that spawns a grandchild exactly like a vendor wrapper.

    The direct child inherits the lease fd (B1), then launches a grandchild
    with the default ``close_fds=True`` — the same shape as the official
    server -> local-harness process tree in issue #25.  The grandchild
    records whether it can see the lease fd.
    """
    grand = tmp_path / "grandchild_reporter.py"
    grand.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys\n"
        f"LEASE={lease_path!r}\n"
        "OUT=sys.argv[1]\n"
        "holds=False\n"
        "try: expected=os.stat(LEASE).st_ino\n"
        "except OSError: expected=-1\n"
        "for name in os.listdir('/proc/self/fd'):\n"
        " try: target=os.readlink('/proc/self/fd/'+name)\n"
        " except OSError: continue\n"
        " if target==LEASE:\n"
        "  try:\n"
        "   if os.fstat(int(name)).st_ino==expected: holds=True\n"
        "  except OSError: pass\n"
        "open(OUT,'w').write(json.dumps({'holds':holds}))\n"
        "import time; time.sleep(300)\n"
    )
    grand.chmod(0o755)
    wrapper = tmp_path / "wrapper_vendor.py"
    wrapper.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,subprocess,sys\n"
        f"GRAND={str(grand)!r}\n"
        f"OUT={str(tmp_path / 'grandchild_holds.json')!r}\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line)\n"
        " result={'home':os.environ['HOME']}\n"
        " if r.get('method')=='initialize':\n"
        "  subprocess.Popen([sys.executable,GRAND,OUT])\n"
        " if r.get('method')=='session/new':\n"
        "  result['sessionId']='b5b5b5b5-b5b5-4b5b-8b5b-b5b5b5b5b5b5'\n"
        " print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),\n"
        "                   'result':result}),flush=True)\n"
    )
    wrapper.chmod(0o755)
    return wrapper


def test_b5_grandchild_does_not_inherit_lease_fd(lanes, tmp_path):
    """B5 boundary: `pass_fds` covers the direct child only, not descendants.

    The official server may launch helper processes (issue #25: server ->
    local-harness) with the default `close_fds=True`, so a grandchild that
    outlives the direct child holds no lease fd.  This test pins that OS
    boundary so the F3 claim can never be over-generalized to "the whole
    vendor lineage": F3 protects the mux + its direct official child, and
    vendor-descendant liveness is an unproven gate that must be closed by
    issue #25 process-tree evidence before F4 may authorize deletion.
    """
    a, _b, _state = lanes
    lease_path = mux._lane_lease_path(str(a), "lane-alpha")
    env = _mux_env(tmp_path, lanes)
    wrapper = _wrapper_vendor_with_grandchild(tmp_path, lease_path)
    env["ACP_MUX_PAR"] = str(wrapper)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        env=env, bufsize=1,
    )
    report_path = tmp_path / "grandchild_holds.json"
    grand_pids: list[int] = []
    try:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1,
                                     "method": "initialize"}) + "\n")
        proc.stdin.flush()
        json.loads(proc.stdout.readline())  # wrapper replies
        # The grandchild (spawned with close_fds=True) reports whether it
        # inherited the lease fd.  It must NOT have it.
        deadline = time.time() + 15
        while time.time() < deadline and not report_path.exists():
            time.sleep(0.05)
        assert report_path.exists(), "grandchild never reported"
        report = json.loads(report_path.read_text())
        assert report["holds"] is False, (
            "grandchild unexpectedly holds the lease fd; the OS boundary "
            "this test pins has changed — revisit the F3 claim scope"
        )
        # The lane is still protected while the mux + direct child live.
        assert mux._lane_lease_state(str(a), "lane-alpha",
                                     now=time.time()) == "live"
        grand_pids = _vendor_pids(str(tmp_path / "grandchild_reporter.py"))
    finally:
        proc.kill()
        proc.wait(timeout=10)
        for pid in grand_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
