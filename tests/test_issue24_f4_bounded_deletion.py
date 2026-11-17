"""Issue #24 Phase 4 (F4): bounded deletion with a lease hold through the pass.

F4 closes the check-to-delete TOCTOU (review B5/F4 gate A) by holding an
exclusive lease lock over every deletion pass, adds conservative budgets,
per-bundle fresh revalidation, and separates audit (no-op) from real
deletion behind the issue #25 process-tree evidence ack (gate B).  Until
that evidence exists, real deletion authority stays NO-GO by default.
"""

from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "acp_mux_f4", ROOT / "scripts" / "acp_mux.py"
)
mux = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mux)

DAY = 86400
SID_1 = "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1"
SID_2 = "a2a2a2a2-a2a2-4a2a-8a2a-a2a2a2a2a2a2"
SID_3 = "a3a3a3a3-a3a3-4a3a-8a3a-a3a3a3a3a3a3"
SID_4 = "a4a4a4a4-a4a4-4a4a-8a4a-a4a4a4a4a4a4"
SID_5 = "a5a5a5a5-a5a5-4a5a-8a5a-a5a5a5a5a5a5"
SID_6 = "a6a6a6a6-a6a6-4a6a-8a6a-a6a6a6a6a6a6"


@pytest.fixture(autouse=True)
def _authorized_gates(monkeypatch):
    """Most F4 tests run with both operator gates acknowledged.

    The gates themselves (fleet cutover, process-tree evidence) have
    dedicated tests; everything else acknowledges them to reach deletion.
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
        (home / ".gemini" / "antigravity-acp" / "brain").mkdir(parents=True)
    Path(mux.REGISTRY_PATH).write_text(json.dumps({"accounts": [
        {"home": str(a), "label": "lane-alpha"},
        {"home": str(b), "label": "lane-beta"},
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
    return _bundle(home, session_id, mtime=now - 40 * DAY)


def _clear_lease(home: Path, label: str, *, at: float | None = None) -> Path:
    path = Path(mux._lane_lease_path(str(home), label))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(
        {"at": time.time() - 10 * mux.LEASE_GRACE_SECONDS if at is None else at,
         "mux_pid": os.getpid()}
    ))
    return path


def _log_text() -> str:
    try:
        return Path(mux.LOG_PATH).read_text()
    except FileNotFoundError:
        return ""


# ---------------------------------------------------------------------------
# Gate A — the exclusive lease hold closes the check-to-delete window.
# ---------------------------------------------------------------------------

def test_bind_cannot_acquire_lease_while_gc_holds_it(lanes, monkeypatch):
    """TOCTOU closure: a bind racing the deletion pass must be locked out.

    A simulated bind (shared flock, non-blocking) is attempted from inside
    the deletion pass itself.  With the F3 probe-then-release protocol the
    shared lock succeeds mid-pass (the counterexample); with the F4 hold it
    must be refused for the whole pass.
    """
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    observed = {}
    alpha_home = a
    real_records = mux._session_store_records

    def spy_records(store):
        # Mid-pass bind attempt on the lane being deleted: shared,
        # non-blocking, on the lane lease.
        if Path(store).parent.parent == alpha_home:
            path = Path(mux._lane_lease_path(str(alpha_home), "lane-alpha"))
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                observed["bind_allowed"] = True
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                observed["bind_allowed"] = False
            finally:
                os.close(fd)
        return real_records(store)

    monkeypatch.setattr(mux, "_session_store_records", spy_records)
    result = mux.prune_session_stores(now=now)
    assert result is not None
    assert observed.get("bind_allowed") is False, (
        "a bind acquired the lane lease inside the deletion pass: the "
        "check-to-delete TOCTOU is still open"
    )
    assert not db.exists()


def test_hold_is_released_after_the_pass(lanes):
    a, _b, _state = lanes
    now = time.time()
    _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    assert mux.prune_session_stores(now=now) is not None
    # After the pass a normal shared bind must succeed again.
    path = Path(mux._lane_lease_path(str(a), "lane-alpha"))
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def test_hold_released_even_when_the_pass_raises(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")

    def boom(*args, **kwargs):
        raise RuntimeError("mid-pass failure")

    monkeypatch.setattr(mux, "_session_store_records", boom)
    with pytest.raises(RuntimeError):
        mux.prune_session_stores(now=now)
    # The lease must not stay locked after a crashed pass.
    assert mux._lane_lease_state(str(a), "lane-alpha", now=time.time()) == "stale"


def test_contended_lane_is_skipped_fail_closed(lanes):
    """A lane whose lease cannot be taken exclusively is never deleted from."""
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    lease = _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    # A stale lease but an unexpected SH holder (e.g. a racing bind that
    # has not written a heartbeat yet): exclusive acquisition must fail and
    # the store must survive.
    fd = os.open(lease, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
        assert mux.prune_session_stores(now=now) is not None
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
    assert db.exists()


# ---------------------------------------------------------------------------
# Bounded per-pass deletion.
# ---------------------------------------------------------------------------

def test_deletion_count_budget_bounds_the_pass(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    monkeypatch.setattr(mux, "GC_MAX_DELETIONS", 3)
    dbs = [_seed_expired(a, sid, now) for sid in
           (SID_1, SID_2, SID_3, SID_4, SID_5, SID_6)]
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 3
    deleted = sum(0 if db.exists() else 1 for db in dbs)
    assert deleted == 3, "budget must bound actual deletions, not just totals"
    assert "budget-stopped" in _log_text()


def test_budget_is_shared_across_lanes(lanes, monkeypatch):
    a, b, _state = lanes
    now = time.time()
    monkeypatch.setattr(mux, "GC_MAX_DELETIONS", 4)
    for sid in (SID_1, SID_2, SID_3):
        _seed_expired(a, sid, now)
    for sid in (SID_4, SID_5, SID_6):
        _seed_expired(b, sid, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 4


def test_bytes_budget_bounds_the_pass(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    # One bundle is 14 (db) + 5 (brain note) bytes; allow exactly one.
    monkeypatch.setattr(mux, "GC_MAX_DELETIONS", 100)
    monkeypatch.setattr(mux, "GC_MAX_BYTES", 25)
    dbs = [_seed_expired(a, sid, now) for sid in (SID_1, SID_2)]
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 1
    assert result["bytes"] <= 25
    assert sum(0 if db.exists() else 1 for db in dbs) == 1


def test_deadline_stops_the_pass(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    monkeypatch.setattr(mux, "GC_PASS_DEADLINE_SECONDS", 0)
    dbs = [_seed_expired(a, sid, now) for sid in (SID_1, SID_2)]
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert all(db.exists() for db in dbs)
    assert "budget-stopped" in _log_text()


# ---------------------------------------------------------------------------
# Fresh per-bundle revalidation (no stale-snapshot reuse).
# ---------------------------------------------------------------------------

def test_bundle_revived_after_planning_is_skipped(lanes, monkeypatch):
    """A bundle touched between planning and its deletion slot survives."""
    a, _b, _state = lanes
    now = time.time()
    db1 = _seed_expired(a, SID_1, now)
    db2 = _seed_expired(a, SID_2, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    real_delete = mux._delete_session_bundle

    def spy_delete(store, record):
        if record["session_id"] == SID_1:
            # Revive the second bundle right before the second deletion.
            fresh = time.time()
            os.utime(db2, (fresh, fresh))
        return real_delete(store, record)

    monkeypatch.setattr(mux, "_delete_session_bundle", spy_delete)
    result = mux.prune_session_stores(now=now)
    assert result is not None
    assert not db1.exists()
    assert db2.exists(), "stale snapshot reused: revalidation must skip revived bundles"


def test_path_swap_to_symlink_is_refused(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    real_records = mux._session_store_records

    def spy_records(store):
        records = real_records(store)
        # Swap the payload for a symlink after inventory, before deletion.
        target = store / "conversations" / f"{SID_1}.db"
        if records is not None and target.exists():
            content = target.read_text()
            outside = store.parent / "outside-victim"
            outside.write_text(content)
            target.unlink()
            target.symlink_to(outside)
        return records

    monkeypatch.setattr(mux, "_session_store_records", spy_records)
    result = mux.prune_session_stores(now=now)
    assert result is not None
    victim = a / ".gemini" / "outside-victim"
    assert victim.exists(), "symlinked payload was followed and deleted"


# ---------------------------------------------------------------------------
# Gate B — process-tree evidence fence: audit/no-op first, real deletion only
# after the operator acknowledges issue #25 evidence.
# ---------------------------------------------------------------------------

def test_without_process_tree_ack_gc_only_audits(lanes, monkeypatch):
    monkeypatch.delenv("ACP_MUX_F4_PROCESS_TREE_ACK", raising=False)
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 1  # planned
    assert db.exists(), "deletion authority requires the process-tree ack"
    assert "session-gc-audit" in _log_text()


def test_with_process_tree_ack_deletion_proceeds(lanes):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 1
    assert not db.exists()
    assert "session-gc-audit" not in _log_text()


def test_fleet_cutover_fence_still_gates_everything(lanes, monkeypatch):
    monkeypatch.delenv("ACP_MUX_F3_CUTOVER_ACK", raising=False)
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    assert mux.prune_session_stores(now=now) is None
    assert db.exists()


# ---------------------------------------------------------------------------
# Inventory contract: budgets and gates are visible in the report.
# ---------------------------------------------------------------------------

def test_inventory_reports_f4_policy_and_gates(lanes):
    a, _b, state_file = lanes
    now = time.time()
    _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    report = mux.session_inventory(now=now, env={
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE": str(state_file)
    })
    policy = report["policy"]
    assert policy["gc_max_deletions"] == mux.GC_MAX_DELETIONS
    assert policy["gc_max_bytes"] == mux.GC_MAX_BYTES
    assert policy["gc_pass_deadline_seconds"] == mux.GC_PASS_DEADLINE_SECONDS
    assert policy["process_tree_ack"] is True
    assert "issue #25" in report["reclaim_certainty"]
    assert report["deletions_performed"] == 0


# ---------------------------------------------------------------------------
# End-to-end: the bind-time GC under GC=1 respects both gates and budgets.
# ---------------------------------------------------------------------------

def _fake_vendor(tmp_path: Path) -> Path:
    fake = tmp_path / "fake_vendor.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line); method=r.get('method')\n"
        " result={'home':__import__('os').environ['HOME']}\n"
        " if method=='session/new': result['sessionId']='f4f4f4f4-f4f4-4f4f-8f4f-f4f4f4f4f4f4'\n"
        " if method=='session/prompt': result['stopReason']='end_turn'\n"
        " print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),'result':result}),flush=True)\n"
    )
    fake.chmod(0o755)
    return fake


def test_bind_time_gc_requires_both_acks(lanes, tmp_path, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    env = os.environ.copy()
    env.update({
        "ACP_MUX_ACCOUNTS": mux.REGISTRY_PATH, "ACP_MUX_STATE": mux.STATE_PATH,
        "ACP_MUX_LOG": mux.LOG_PATH, "ACP_MUX_PAR": str(_fake_vendor(tmp_path)),
        "ACP_MUX_AFFINITY": "f4-affinity", "HOME": str(tmp_path),
        "HERMES_REAL_HOME": str(tmp_path),
        "ACP_MUX_SESSION_GC": "1",
        "ACP_MUX_F3_CUTOVER_ACK": "1",
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE": str(lanes[2]),
    })
    env.pop("ACP_MUX_F4_PROCESS_TREE_ACK", None)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
        input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n",
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert proc.returncode == 0
    assert db.exists(), "bind-time GC deleted without the process-tree ack"
    log = Path(mux.LOG_PATH).read_text()
    assert "session-gc-audit" in log
