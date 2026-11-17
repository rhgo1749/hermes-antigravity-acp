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


def _seed_expired(home: Path, session_id: str, now: float, *,
                  label: str = "lane-alpha", owner: bool = True,
                  lifecycle: str = "ephemeral", origin: str = "agent") -> Path:
    db = _bundle(home, session_id, mtime=now - 40 * DAY)
    # Deletion authority requires positive owner evidence (review R2); most
    # tests seed a valid ephemeral owner for the lane that owns the store.
    if owner:
        _seed_owner(home, label, session_id, lifecycle=lifecycle, origin=origin)
    return db


def _clear_lease(home: Path, label: str, *, at: float | None = None) -> Path:
    path = Path(mux._lane_lease_path(str(home), label))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(
        {"at": time.time() - 10 * mux.LEASE_GRACE_SECONDS if at is None else at,
         "mux_pid": os.getpid()}
    ))
    return path


def _seed_owner(home: Path, label: str, session_id: str, *,
                lifecycle: str = "ephemeral", origin: str = "agent") -> None:
    assert mux._record_session_owner(
        session_id, str(home), label, origin=origin, lifecycle=lifecycle
    )


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
        _seed_expired(b, sid, now, label="lane-beta")
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
    """A bundle touched between planning and its deletion slot survives.

    Store iteration order is not a fixed contract, so the revived target is
    "whichever expired bundle is still pending at the first delete slot",
    never a hard-coded session id.  The invariant under test is exactly:
    a bundle revived after planning survives its later fresh revalidation.
    """
    a, _b, _state = lanes
    now = time.time()
    dbs = {SID_1: _seed_expired(a, SID_1, now), SID_2: _seed_expired(a, SID_2, now)}
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    real_delete = mux._delete_session_bundle
    seen: list[str] = []
    revived: set[str] = set()

    def spy_delete(store, record, **kwargs):
        sid = record["session_id"]
        if not seen:
            # Revive the other still-pending bundle right before the
            # second deletion slot revalidates it.
            for other_sid, other_db in dbs.items():
                if other_sid != sid:
                    fresh = time.time()
                    os.utime(other_db, (fresh, fresh))
                    revived.add(other_sid)
                    break
        seen.append(sid)
        return real_delete(store, record, **kwargs)

    monkeypatch.setattr(mux, "_delete_session_bundle", spy_delete)
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 1
    assert len(revived) == 1
    survivor = dbs[next(iter(revived))]
    gone = dbs[next(sid for sid in dbs if sid not in revived)]
    assert not gone.exists()
    assert survivor.exists(), (
        "stale snapshot reused: revalidation must skip revived bundles"
    )


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


# ---------------------------------------------------------------------------
# Review R2 — owner/lifecycle positive evidence is part of the deletion
# predicate: readable ledger, existing owner digest, lane match, ephemeral.
# ---------------------------------------------------------------------------

def test_r2_bundle_without_owner_record_is_never_deleted(lanes):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now, owner=False)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert db.exists()


def test_r2_unknown_lifecycle_is_never_deleted(lanes):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now, lifecycle="")  # records as unknown
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert db.exists()


def test_r2_durable_lifecycle_is_never_deleted(lanes):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now, lifecycle="durable")
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert db.exists()


def test_r2_lane_mismatch_is_never_deleted(lanes):
    a, b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now, owner=False)
    # Owner evidence exists but names a different lane/home than the store
    # being deleted: not positive evidence for this store.
    _seed_owner(b, "lane-beta", SID_1)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert db.exists()


def test_r2_backend_origin_alone_never_licenses(lanes):
    a, _b, _state = lanes
    now = time.time()
    guarded = _seed_expired(a, SID_1, now, origin="backend", lifecycle="")
    allowed = _seed_expired(a, SID_2, now, origin="backend", lifecycle="ephemeral")
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 1
    assert guarded.exists(), "origin=backend with unknown lifecycle was deleted"
    assert not allowed.exists()


def test_r2_unreadable_owner_ledger_aborts_pass(lanes):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    Path(mux.STATE_PATH + ".owners.json").write_text("{corrupt", encoding="utf-8")
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert db.exists()
    assert "revalidation-aborted" in _log_text()


# ---------------------------------------------------------------------------
# Review R3 — a partial destructive failure consumes the reserved budget
# and stops the pass immediately; nothing is refunded or rolled back.
# ---------------------------------------------------------------------------

def test_r3_partial_failure_stops_pass_and_consumes_budget(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    monkeypatch.setattr(mux, "GC_MAX_DELETIONS", 2)
    dbs = [_seed_expired(a, sid, now) for sid in (SID_1, SID_2)]
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    real_unlink = os.unlink

    def failing_unlink(path, *args, **kwargs):
        if str(path).endswith(".db"):
            raise OSError("synthetic mid-delete failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(os, "unlink", failing_unlink)
    result = mux.prune_session_stores(now=now)
    assert result is not None
    assert result["failed"] == 1 and result["expired"] == 0
    # Exactly one bundle was partially destroyed (brain gone, .db intact);
    # the other was never touched.  No rollback is attempted or claimed.
    states = []
    for db in dbs:
        brain = a / ".gemini" / "antigravity-acp" / "brain" / db.stem
        states.append((db.exists(), brain.exists()))
    assert sorted(states) == [(True, False), (True, True)], (
        "partial failure must stop the pass with the remaining candidate "
        "untouched and the partial destruction left as-is"
    )
    assert "budget-stopped" in _log_text()


# ---------------------------------------------------------------------------
# Review R4 — capacity eligibility is recomputed fresh at each deletion
# slot; a stale oldest-first ranking is never executed.
# ---------------------------------------------------------------------------

def test_r4_capacity_ranking_is_recomputed_before_eviction(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    monkeypatch.setattr(mux, "AFFINITY_MAX_ENTRIES", 1)
    ttl = mux.AFFINITY_TTL_SECONDS
    expired = _seed_expired(a, SID_1, now)
    old_live = _bundle(a, SID_2, mtime=now - ttl / 2)
    new_live = _bundle(a, SID_3, mtime=now - 60)
    for sid in (SID_2, SID_3):
        _seed_owner(a, "lane-alpha", sid)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    real_delete = mux._delete_session_bundle

    def spy_delete(store, record, **kwargs):
        if record["session_id"] == SID_1:
            # Revive the planned-oldest live bundle mid-pass: by the time
            # the capacity slot runs it is the NEWEST bundle, so evicting
            # it would be executing a stale ranking.
            fresh = time.time()
            os.utime(old_live, (fresh, fresh))
        return real_delete(store, record, **kwargs)

    monkeypatch.setattr(mux, "_delete_session_bundle", spy_delete)
    result = mux.prune_session_stores(now=now)
    assert result is not None
    assert result["expired"] == 1 and result["capacity"] == 1
    assert not expired.exists()
    assert old_live.exists(), "stale capacity ranking evicted a revived bundle"
    assert not new_live.exists(), "the currently-oldest evictable bundle survived"


# ---------------------------------------------------------------------------
# Review R5 — the footprint is measured exactly once per slot; an
# unmeasurable estimate is never coerced to 0 bytes before a mutation.
# ---------------------------------------------------------------------------

def test_r5_unmeasurable_footprint_never_deletes(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    monkeypatch.setattr(
        mux, "_lane_bundle_bytes", lambda *_args, **_kwargs: None
    )
    delete_calls = {"n": 0}
    real_delete = mux._delete_session_bundle

    def spy_delete(store, record, **kwargs):
        delete_calls["n"] += 1
        return real_delete(store, record, **kwargs)

    monkeypatch.setattr(mux, "_delete_session_bundle", spy_delete)
    result = mux.prune_session_stores(now=now)
    assert result is not None
    assert result["expired"] == 0 and result["failed"] == 0
    assert delete_calls["n"] == 0, (
        "an unmeasurable footprint must never reach a destructive mutation"
    )
    assert db.exists()


def test_r5_footprint_is_measured_once_per_slot(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    real_bytes = mux._lane_bundle_bytes
    reads = {"n": 0}

    def counting_bytes(*args, **kwargs):
        reads["n"] += 1
        return real_bytes(*args, **kwargs)

    monkeypatch.setattr(mux, "_lane_bundle_bytes", counting_bytes)
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 1
    # One candidate slot means one measurement: the budget verdict and the
    # reservation must never re-read (a re-read is a budget TOCTOU, R5).
    assert reads["n"] == 1


# ---------------------------------------------------------------------------
# Review R8 — a bundle that grows past its reserved estimate between the
# slot's single measurement and the first mutation is refused
# non-destructively; the byte hard bound is enforced at the deleter.
# ---------------------------------------------------------------------------

def test_r8_bundle_grown_after_reservation_is_refused(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    real_active = mux._active_hermes_session_ids
    original_mtime = db.stat().st_mtime
    calls = {"n": 0}

    def spy_active(*, now=None, env=None):
        calls["n"] += 1
        if calls["n"] == 2:
            # After the slot's footprint measurement and before any
            # mutation the payload grows far past the reserved estimate.
            db.write_text("x" * 100_000)
            os.utime(db, (original_mtime, original_mtime))  # stay expired
        return real_active(now=now, env=env)

    monkeypatch.setattr(mux, "_active_hermes_session_ids", spy_active)
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0
    assert result["failed"] == 1
    # The bundle survives exactly as the race left it: the GC itself
    # performed zero mutations (no unlink, no partial destruction).
    assert db.exists() and db.stat().st_size == 100_000, (
        "grown bundle must survive untouched, not be deleted or truncated"
    )
    brain = a / ".gemini" / "antigravity-acp" / "brain" / SID_1
    assert brain.exists(), "refusal must be non-destructive (zero mutation)"


# ---------------------------------------------------------------------------
# Review R9 — fresh evidence that runs past the wall-clock budget stops the
# slot before any reservation or mutation (deadline hard bound).
# ---------------------------------------------------------------------------

def test_r9_deadline_elapsing_during_fresh_evidence_stops_before_mutation(
    lanes, monkeypatch
):
    a, _b, _state = lanes
    now = time.time()
    db = _seed_expired(a, SID_1, now)
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    monkeypatch.setattr(mux, "GC_PASS_DEADLINE_SECONDS", 1)
    real_active = mux._active_hermes_session_ids
    calls = {"n": 0}

    def slow_active(*, now=None, env=None):
        calls["n"] += 1
        if calls["n"] == 2:
            # The slot's fresh checkpoint read alone blows the budget.
            time.sleep(1.5)
        return real_active(now=now, env=env)

    monkeypatch.setattr(mux, "_active_hermes_session_ids", slow_active)
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 0 and result["failed"] == 0
    assert db.exists(), "a slot past its deadline must never mutate"
    assert "budget-stopped" in _log_text()


# ---------------------------------------------------------------------------
# Review R1 — a fresh checkpoint view that turns unreadable mid-pass aborts
# the remaining deletions (fail closed), never proceeds blind.
# ---------------------------------------------------------------------------

def test_r1_unreadable_fresh_checkpoint_view_aborts_remaining(lanes, monkeypatch):
    a, _b, _state = lanes
    now = time.time()
    dbs = [_seed_expired(a, sid, now) for sid in (SID_1, SID_2)]
    _clear_lease(a, "lane-alpha")
    _clear_lease(Path(_b), "lane-beta")
    real_active = mux._active_hermes_session_ids
    calls = {"n": 0}

    def spy_active(*, now=None, env=None):
        calls["n"] += 1
        if calls["n"] <= 2:  # pass-start read + first slot succeed
            return real_active(now=now, env=env)
        return None  # every later fresh read fails

    monkeypatch.setattr(mux, "_active_hermes_session_ids", spy_active)
    result = mux.prune_session_stores(now=now)
    assert result is not None and result["expired"] == 1
    # Store iteration order is not fixed; the invariant is that exactly the
    # first slot deleted and the abort left every later bundle untouched.
    assert sum(0 if db.exists() else 1 for db in dbs) == 1
    assert "revalidation-aborted" in _log_text()
