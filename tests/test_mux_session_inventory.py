"""Issue #24 Phase 1: the read-only native session inventory never deletes.

The inventory must (a) reuse the exact GC decision helpers so its candidate
prediction matches what ``prune_session_stores`` would delete, (b) report
only counts/bytes/buckets — never raw session ids, labels, homes, or paths,
and (c) fail closed on lock contention, unreadable inventories, and refused
store layouts without claiming candidates it cannot see.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("inventory_mux", ROOT / "scripts" / "acp_mux.py")
assert spec and spec.loader
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)

DAY = 86400
SID_OLD = "11111111-1111-4111-8111-111111111111"
SID_FRESH = "22222222-2222-4222-8222-222222222222"
SID_PROTECTED = "33333333-3333-4333-8333-333333333333"
SID_EXTRA = "44444444-4444-4444-8444-444444444444"


@pytest.fixture
def lanes(tmp_path, monkeypatch):
    monkeypatch.setenv("ACP_MUX_DEFAULT_HOME", str(tmp_path / "default-home"))
    monkeypatch.setattr(mux, "DEFAULT_HOME", str(tmp_path / "default-home"))
    monkeypatch.setattr(mux, "STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setattr(mux, "REGISTRY_PATH", str(tmp_path / "accounts.json"))
    monkeypatch.setattr(mux, "LOG_PATH", str(tmp_path / "mux.log"))
    a = tmp_path / "home-alpha"
    b = tmp_path / "home-beta"
    for home in (a, b):
        (home / ".gemini" / "antigravity-acp" / "conversations").mkdir(parents=True)
    Path(mux.REGISTRY_PATH).write_text(json.dumps({"accounts": [
        {"home": str(a), "label": "lane-alpha"}, {"home": str(b), "label": "lane-beta"}
    ]}))
    state_file = tmp_path / "acp-sessions.json"
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(state_file))
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


def _checkpoints(state_file: Path, session_ids, *, now: float) -> None:
    state_file.write_text(json.dumps({"version": 1, "states": {
        f"k-{i}": {"session_id": sid, "updated_at": now}
        for i, sid in enumerate(session_ids)
    }}))


def _inventory(state_file: Path, *, now: float) -> dict:
    return mux.session_inventory(now=now, env={
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE": str(state_file)
    })


def test_inventory_counts_protection_linkage_and_candidates(lanes):
    a, _b, state_file = lanes
    now = time.time()
    _bundle(a, SID_OLD, mtime=now - 72 * 3600)
    _bundle(a, SID_FRESH, mtime=now - 60)
    _bundle(a, SID_PROTECTED, mtime=now - 72 * 3600)
    _checkpoints(state_file, [SID_PROTECTED], now=now)
    assert mux._record_session_owner(SID_FRESH, str(a), "lane-alpha")

    report = _inventory(state_file, now=now)
    assert report["status"] == "ok", report["reasons"]
    assert report["deletions_performed"] == 0
    assert report["schema"] == "acp-mux-session-inventory-v1"
    assert "process lease" in report["reclaim_certainty"]

    lane_a = next(row for row in report["lanes"] if row["bundles"] == 3)
    assert lane_a["checkpoint_protected"] == 1
    assert lane_a["owner_linked"] == 1
    assert lane_a["unowned_unprotected"] == 1  # SID_OLD only
    assert lane_a["gc_candidate_expired"] == 1  # SID_OLD; protected stays safe
    assert lane_a["gc_candidate_capacity"] == 0
    assert lane_a["age_buckets"]["3_7d"] == 2
    assert lane_a["age_buckets"]["lt_1h"] == 1
    assert lane_a["bytes"] > 0
    assert lane_a["gc_candidate_bytes"] > 0
    assert lane_a["gc_candidate_bytes"] < lane_a["bytes"]

    lane_b = next(row for row in report["lanes"] if row["lane"] != lane_a["lane"])
    assert lane_b["status"] == "ok" and lane_b["bundles"] == 0
    assert report["totals"]["bundles"] == 3
    assert report["totals"]["gc_candidate_expired"] == 1


def test_inventory_never_calls_the_deleter(lanes, monkeypatch):
    a, _b, state_file = lanes
    now = time.time()
    stale = _bundle(a, SID_OLD, mtime=now - 72 * 3600)
    fresh = _bundle(a, SID_FRESH, mtime=now - 60)

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("the read-only inventory must never delete")

    monkeypatch.setattr(mux, "_delete_session_bundle", _forbidden)
    report = _inventory(state_file, now=now)
    assert report["status"] == "ok"
    assert report["totals"]["gc_candidate_expired"] == 1
    assert stale.exists() and fresh.exists()


def test_inventory_candidates_match_the_gc_outcome(lanes, monkeypatch):
    a, _b, state_file = lanes
    now = time.time()
    old = _bundle(a, SID_OLD, mtime=now - 72 * 3600)
    _bundle(a, SID_FRESH, mtime=now - 60)
    _checkpoints(state_file, [], now=now)

    report = _inventory(state_file, now=now)
    predicted_expired = report["totals"]["gc_candidate_expired"]
    predicted_bytes = report["totals"]["gc_candidate_bytes"]
    assert predicted_expired == 1

    result = mux.prune_session_stores(now=now)
    assert result["expired"] == predicted_expired
    assert result["bytes"] == predicted_bytes
    assert not old.exists()


def test_capacity_candidates_are_predicted_without_deletion(lanes, monkeypatch):
    a, _b, state_file = lanes
    now = time.time()
    older = _bundle(a, SID_OLD, mtime=now - 3 * 3600)
    newer = _bundle(a, SID_FRESH, mtime=now - 2 * 3600)
    _checkpoints(state_file, [], now=now)
    monkeypatch.setattr(mux, "AFFINITY_MAX_ENTRIES", 1)

    report = _inventory(state_file, now=now)
    assert report["totals"]["gc_candidate_expired"] == 0  # both within TTL
    assert report["totals"]["gc_candidate_capacity"] == 1  # cap forces one

    result = mux.prune_session_stores(now=now)
    assert result["capacity"] == 1
    assert not older.exists() and newer.exists()


def test_inventory_fails_closed_on_lock_contention(lanes):
    _a, _b, state_file = lanes
    with mux._session_gc_lock() as locked:
        assert locked
        report = _inventory(state_file, now=time.time())
    assert report["status"] == "incomplete"
    assert report["reasons"] == ["gc-lock-unavailable"]
    assert report["lanes"] == []
    assert report["deletions_performed"] == 0


def test_inventory_fails_closed_on_unreadable_checkpoint_inventory(lanes):
    a, _b, state_file = lanes
    _bundle(a, SID_OLD, mtime=time.time() - 72 * 3600)
    state_file.write_text("{corrupt")

    report = _inventory(state_file, now=time.time())
    assert report["status"] == "incomplete"
    assert "checkpoint-inventory-unavailable" in report["reasons"]
    assert report["lanes"] == []


def test_inventory_fails_closed_on_corrupt_ownership_ledger(lanes):
    _a, _b, state_file = lanes
    _checkpoints(state_file, [], now=time.time())
    Path(mux.STATE_PATH + ".owners.json").write_text("{corrupt")

    report = _inventory(state_file, now=time.time())
    assert report["status"] == "incomplete"
    assert "ownership-ledger-unavailable" in report["reasons"]


def test_refused_store_layout_reports_no_counts(lanes):
    a, b, state_file = lanes
    now = time.time()
    _bundle(a, SID_FRESH, mtime=now - 60)
    store_b = b / ".gemini" / "antigravity-acp"
    target = lanes[0].parent / "outside-store"
    target.mkdir()
    import shutil
    shutil.move(str(store_b), str(target / "moved-store"))
    store_b.symlink_to(target / "moved-store")

    report = _inventory(state_file, now=now)
    assert report["status"] == "incomplete"
    refused = [lane for lane in report["lanes"] if lane["status"] == "store-layout-refused"]
    assert len(refused) == 1
    assert refused[0]["bytes"] is None
    assert refused[0]["gc_candidate_expired"] == 0
    assert report["totals"]["bundles"] == 1  # only the clean lane is counted


def test_report_never_leaks_identifiers_labels_or_paths(lanes):
    a, _b, state_file = lanes
    now = time.time()
    _bundle(a, SID_OLD, mtime=now - 72 * 3600)
    _bundle(a, SID_FRESH, mtime=now - 60)
    _checkpoints(state_file, [SID_FRESH], now=now)

    blob = json.dumps(_inventory(state_file, now=now), sort_keys=True)
    for secret in (SID_OLD, SID_FRESH, str(a), "home-alpha", "lane-alpha"):
        assert secret not in blob


def test_cli_inventory_prints_json_and_exits_zero(lanes, monkeypatch):
    a, _b, state_file = lanes
    now = time.time()
    stale = _bundle(a, SID_OLD, mtime=now - 72 * 3600)
    _checkpoints(state_file, [], now=now)

    env = os.environ.copy()
    env.update({
        "ACP_MUX_ACCOUNTS": mux.REGISTRY_PATH,
        "ACP_MUX_STATE": mux.STATE_PATH,
        "ACP_MUX_LOG": mux.LOG_PATH,
        "ACP_MUX_DEFAULT_HOME": str(Path(mux.DEFAULT_HOME)),
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE": str(state_file),
    })
    env.pop("HERMES_HOME", None)
    env.pop("HERMES_REAL_HOME", None)
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py"), "inventory"],
        text=True, capture_output=True, env=env, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["status"] == "ok"
    assert report["totals"]["bundles"] == 1
    assert report["totals"]["gc_candidate_expired"] == 1
    assert report["deletions_performed"] == 0
    assert stale.exists()
    assert SID_OLD not in completed.stdout


@pytest.mark.parametrize("entrypoint", ["acp_mux.py", "antigravity-acp-mux.py"])
def test_bind_time_dry_run_logs_summary_and_keeps_bundles(lanes, tmp_path, entrypoint):
    a, _b, state_file = lanes
    now = time.time()
    stale = _bundle(a, SID_OLD, mtime=now - 72 * 3600)
    _checkpoints(state_file, [], now=now)

    fake = tmp_path / "fake.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        "for line in sys.stdin:\n"
        "    r=json.loads(line)\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),'result':{'ok':True}}),flush=True)\n"
    )
    fake.chmod(0o755)
    env = os.environ.copy()
    env.update({
        "ACP_MUX_ACCOUNTS": mux.REGISTRY_PATH,
        "ACP_MUX_STATE": mux.STATE_PATH,
        "ACP_MUX_LOG": mux.LOG_PATH,
        "ACP_MUX_PAR": str(fake),
        "ACP_MUX_SESSION_GC": "dry-run",
        "ACP_MUX_DEFAULT_HOME": str(Path(mux.DEFAULT_HOME)),
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE": str(state_file),
        "HOME": str(tmp_path),
    })
    env.pop("HERMES_HOME", None)
    env.pop("HERMES_REAL_HOME", None)
    env.pop("ACP_MUX_SESSION_ID", None)
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / entrypoint)],
        input=request, text=True, capture_output=True, env=env, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    log = Path(mux.LOG_PATH).read_text()
    assert "session-inventory" in log
    assert "deletions=0" in log
    assert "session-gc expired" not in log
    assert stale.exists(), "dry-run must never delete"
    assert SID_OLD not in log


def _run_bind(lanes, tmp_path, entrypoint, gc_mode=None):
    """Drive one bind through a fake server; returns the mux log text."""
    _a, _b, state_file = lanes
    fake = tmp_path / "fake-server.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        "for line in sys.stdin:\n"
        "    r=json.loads(line)\n"
        "    print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),'result':{'ok':True}}),flush=True)\n"
    )
    fake.chmod(0o755)
    env = os.environ.copy()
    env.update({
        "ACP_MUX_ACCOUNTS": mux.REGISTRY_PATH,
        "ACP_MUX_STATE": mux.STATE_PATH,
        "ACP_MUX_LOG": mux.LOG_PATH,
        "ACP_MUX_PAR": str(fake),
        "ACP_MUX_DEFAULT_HOME": str(Path(mux.DEFAULT_HOME)),
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE": str(state_file),
        "HOME": str(tmp_path),
    })
    if gc_mode is None:
        env.pop("ACP_MUX_SESSION_GC", None)
    else:
        env["ACP_MUX_SESSION_GC"] = gc_mode
    env.pop("HERMES_HOME", None)
    env.pop("HERMES_REAL_HOME", None)
    env.pop("ACP_MUX_SESSION_ID", None)
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / entrypoint)],
        input=request, text=True, capture_output=True, env=env, timeout=30, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return Path(mux.LOG_PATH).read_text()


def _expired_owner_record(lanes, *, now: float) -> Path:
    """One owner record whose bundle and checkpoint are gone and past grace."""
    lane_key = mux._ownership_accounts()[0][2]
    owners_path = Path(mux.STATE_PATH + ".owners.json")
    owners_path.write_text(json.dumps({"version": 2, "owners": {
        mux._owner_hash("gone-session"): {
            "lane": mux._owner_hash(lane_key),
            "at": now - 400 * DAY,
        }
    }}))
    return owners_path


@pytest.mark.parametrize("entrypoint", ["acp_mux.py", "antigravity-acp-mux.py"])
def test_dry_run_bind_preserves_expired_owner_records(lanes, tmp_path, entrypoint):
    """P1: dry-run must not mutate owner metadata either, only census it."""
    a, _b, state_file = lanes
    now = time.time()
    _bundle(a, SID_FRESH, mtime=now - 60)
    _checkpoints(state_file, [], now=now)
    owners_path = _expired_owner_record(lanes, now=now)
    before = owners_path.read_bytes()

    log = _run_bind(lanes, tmp_path, entrypoint, gc_mode="dry-run")

    assert owners_path.read_bytes() == before, (
        "dry-run must leave ownership records byte-identical"
    )
    assert "owner-records kept" not in log, "dry-run must not run the owner prune"


def test_normal_bind_still_prunes_expired_owner_records(lanes, tmp_path):
    """Regression: non-dry-run keeps the existing metadata-only cleanup."""
    a, _b, state_file = lanes
    now = time.time()
    _bundle(a, SID_FRESH, mtime=now - 60)
    _checkpoints(state_file, [], now=now)
    owners_path = _expired_owner_record(lanes, now=now)

    log = _run_bind(lanes, tmp_path, "acp_mux.py", gc_mode=None)

    assert "owner-records kept=0 removed=1" in log
    assert json.loads(owners_path.read_text())["owners"] == {}


def test_inventory_absent_lock_creates_no_files(lanes):
    """P2: a missing lock file must not be created by the inventory probe."""
    a, _b, state_file = lanes
    now = time.time()
    _bundle(a, SID_OLD, mtime=now - 72 * 3600)
    _checkpoints(state_file, [], now=now)
    lock_path = Path(mux.STATE_PATH + ".session-gc.lock")
    assert not lock_path.exists()

    report = _inventory(state_file, now=now)

    assert report["status"] == "ok"
    assert report["lock"] == "absent-unserialized"
    assert not lock_path.exists(), "inventory must not create the lock file"


def test_inventory_contended_lock_leaves_metadata_untouched(lanes):
    """P2: a contended probe must not chmod or rewrite the lock file."""
    _a, _b, state_file = lanes
    lock_path = Path(mux.STATE_PATH + ".session-gc.lock")
    with mux._session_gc_lock() as locked:
        assert locked
        lock_path.chmod(0o644)
        mode_before = lock_path.stat().st_mode
        report = _inventory(state_file, now=time.time())
    assert report["status"] == "incomplete"
    assert report["reasons"] == ["gc-lock-unavailable"]
    assert lock_path.stat().st_mode == mode_before, "probe must not change lock modes"


def test_inventory_lock_appeared_mid_scan_is_incomplete(lanes, monkeypatch):
    """P2: absent-bracket proof fails if a GC pass starts during the walk."""
    a, _b, state_file = lanes
    now = time.time()
    _bundle(a, SID_OLD, mtime=now - 72 * 3600)
    _checkpoints(state_file, [], now=now)
    lock_path = Path(mux.STATE_PATH + ".session-gc.lock")
    real = mux._lane_inventory
    fired = {"done": False}

    def spy(lane, home, active, owners, *, now):
        if not fired["done"]:
            fired["done"] = True
            lock_path.write_text("")  # simulate a GC pass starting mid-scan
        return real(lane, home, active, owners, now=now)

    monkeypatch.setattr(mux, "_lane_inventory", spy)

    report = _inventory(state_file, now=now)

    assert report["status"] == "incomplete"
    assert "gc-lock-appeared-mid-scan" in report["reasons"]
