"""Issue #24 Phase 2 (F2): explicit origin/lifecycle declaration at session/new.

The mux must stamp a validated ``origin`` (agent/backend) and ``lifecycle``
(ephemeral/durable) into the owner record it writes at ``session/new``, from
the per-connection declarations ``ACP_MUX_SESSION_ORIGIN`` and
``ACP_MUX_SESSION_LIFECYCLE``.  Absent or invalid declarations read as
``unknown`` — never as ``ephemeral``.  Owner records stay ``version: 2`` with
optional additive keys: legacy records stay readable, no migration or
backfill is ever performed, and every rewrite path preserves existing
declarations.  The read-only inventory gains a per-lane origin x lifecycle
matrix; nothing in F2 changes GC eligibility and nothing deletes.

Credential-free fake ACP only; no live vendor, no production state.
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("f2_mux", ROOT / "scripts" / "acp_mux.py")
assert spec and spec.loader
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)

DAY = 86400
SID_BACKEND = "b1b1b1b1-b1b1-4b1b-8b1b-b1b1b1b1b1b1"
SID_AGENT = "a2a2a2a2-a2a2-4a2a-8a2a-a2a2a2a2a2a2"
SID_UNDECLARED = "c3c3c3c3-c3c3-4c3c-8c3c-c3c3c3c3c3c3"
SID_UNOWNED = "d4d4d4d4-d4d4-4d4d-8d4d-d4d4d4d4d4d4"
SID_EPHEMERAL_AGENT = "e5e5e5e5-e5e5-4e5e-8e5e-e5e5e5e5e5e5"


@pytest.fixture
def lanes(tmp_path, monkeypatch):
    monkeypatch.setenv("ACP_MUX_DEFAULT_HOME", str(tmp_path / "default-home"))
    monkeypatch.setattr(mux, "DEFAULT_HOME", str(tmp_path / "default-home"))
    monkeypatch.setattr(mux, "STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setattr(mux, "REGISTRY_PATH", str(tmp_path / "accounts.json"))
    monkeypatch.setattr(mux, "LOG_PATH", str(tmp_path / "mux.log"))
    a, b = tmp_path / "home-alpha", tmp_path / "home-beta"
    for home in (a, b):
        (home / ".gemini" / "antigravity-acp" / "conversations").mkdir(parents=True)
    Path(mux.REGISTRY_PATH).write_text(json.dumps({"accounts": [
        {"home": str(a), "label": "lane-alpha"}, {"home": str(b), "label": "lane-beta"}
    ]}))
    state_file = tmp_path / "acp-sessions.json"
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(state_file))
    return a, b, state_file


def _owners() -> dict:
    return json.loads(Path(mux.STATE_PATH + ".owners.json").read_text())


def _entry(session_id: str) -> dict:
    return _owners()["owners"][mux._owner_hash(session_id)]


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


def _run_mux(tmp_path, declarations: dict[str, str], session_id: str) -> dict:
    """Drive one real mux process end-to-end; return the session/new reply."""
    fake = tmp_path / "fake_vendor.py"
    # The fake vendor child echoes any declaration env it received: F2 must
    # never expose the declaration variables to the official subprocess.
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line); method=r.get('method')\n"
        " result={'home':os.environ['HOME'],\n"
        "  'decl_env':{k:v for k,v in os.environ.items()\n"
        "    if k in ('ACP_MUX_SESSION_ORIGIN','ACP_MUX_SESSION_LIFECYCLE')}}\n"
        f" if method=='session/new': result['sessionId']={session_id!r}\n"
        " print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),'result':result}),flush=True)\n"
    )
    fake.chmod(0o755)
    env = os.environ.copy()
    env.update({
        "ACP_MUX_ACCOUNTS": mux.REGISTRY_PATH, "ACP_MUX_STATE": mux.STATE_PATH,
        "ACP_MUX_LOG": mux.LOG_PATH, "ACP_MUX_PAR": str(fake),
        "ACP_MUX_AFFINITY": "f2-affinity", "HOME": str(tmp_path),
        "HERMES_REAL_HOME": str(tmp_path),
    })
    env.pop("ACP_MUX_SESSION_ID", None)
    env.pop("ACP_MUX_SESSION_GC", None)
    env.pop("ACP_MUX_SESSION_ORIGIN", None)
    env.pop("ACP_MUX_SESSION_LIFECYCLE", None)
    env.update(declarations)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {}},
    ]
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "acp_mux.py")],
        input="".join(json.dumps(x) + "\n" for x in requests),
        text=True, capture_output=True, env=env, timeout=15, check=True,
    )
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    return next(reply for reply in replies if reply["id"] == 2)


# ---------------------------------------------------------------------------
# 1. Explicit declarations are stamped at session/new (end-to-end through the
#    real mux relay), and never cross into the vendor subprocess env.
# ---------------------------------------------------------------------------

def test_backend_ephemeral_declaration_stamped_at_session_new(lanes, tmp_path):
    reply = _run_mux(
        tmp_path,
        {"ACP_MUX_SESSION_ORIGIN": "backend", "ACP_MUX_SESSION_LIFECYCLE": "ephemeral"},
        SID_BACKEND,
    )
    assert "error" not in reply
    assert reply["result"]["decl_env"] == {}, (
        "declaration env must be stripped before the official subprocess spawn"
    )
    entry = _entry(SID_BACKEND)
    assert entry["origin"] == "backend"
    assert entry["lifecycle"] == "ephemeral"
    assert _owners()["version"] == 2


def test_agent_durable_declaration_stamped_at_session_new(lanes, tmp_path):
    reply = _run_mux(
        tmp_path,
        {"ACP_MUX_SESSION_ORIGIN": "agent", "ACP_MUX_SESSION_LIFECYCLE": "durable"},
        SID_AGENT,
    )
    assert "error" not in reply
    entry = _entry(SID_AGENT)
    assert entry["origin"] == "agent"
    assert entry["lifecycle"] == "durable"


# ---------------------------------------------------------------------------
# 2. Absent or invalid declarations resolve to unknown — never ephemeral.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("declarations,expected", [
    ({}, ("unknown", "unknown")),
    # The two fields are orthogonal: an invalid origin never contaminates a
    # valid lifecycle declaration, and vice versa — but the invalid value is
    # never stored verbatim.
    ({"ACP_MUX_SESSION_ORIGIN": "honcho",
      "ACP_MUX_SESSION_LIFECYCLE": "ephemeral"}, ("unknown", "ephemeral")),
    ({"ACP_MUX_SESSION_ORIGIN": "backend",
      "ACP_MUX_SESSION_LIFECYCLE": "EPHEMERAL"}, ("backend", "unknown")),
    ({"ACP_MUX_SESSION_ORIGIN": "backend",
      "ACP_MUX_SESSION_LIFECYCLE": "maybe-delete-later"}, ("backend", "unknown")),
    ({"ACP_MUX_SESSION_ORIGIN": "", "ACP_MUX_SESSION_LIFECYCLE": ""},
     ("unknown", "unknown")),
])
def test_absent_or_invalid_declaration_never_becomes_declared(
    lanes, tmp_path, declarations, expected
):
    reply = _run_mux(tmp_path, declarations, SID_UNDECLARED)
    assert "error" not in reply
    entry = _entry(SID_UNDECLARED)
    assert entry.get("origin", "unknown") == expected[0]
    assert entry.get("lifecycle", "unknown") == expected[1]
    # An invalid value is never persisted verbatim.
    for raw in declarations.values():
        if raw and raw not in ("agent", "backend", "ephemeral", "durable"):
            assert raw not in json.dumps(entry)


# ---------------------------------------------------------------------------
# 3. Legacy v2 records (no declaration keys) stay readable and routable.
# ---------------------------------------------------------------------------

def test_legacy_v2_records_read_as_unknown_and_route_unchanged(lanes):
    a, _b, _state = lanes
    digest = mux._owner_hash(SID_AGENT)
    Path(mux.STATE_PATH + ".owners.json").write_text(json.dumps({
        "version": 2,
        "owners": {digest: {"lane": mux._owner_hash(f"lane-alpha\t{a}"), "at": time.time()}},
    }))
    entries = mux._read_session_owners()
    assert entries is not None
    assert entries[digest].get("origin", "unknown") == "unknown"
    assert entries[digest].get("lifecycle", "unknown") == "unknown"
    assert mux._resolve_session_owner(SID_AGENT) == (str(a), "lane-alpha")


# ---------------------------------------------------------------------------
# 4. A record written by the new code must stay readable by the previous
#    (pre-F2) v2 reader: unknown extra keys are ignored, never rejected.
# ---------------------------------------------------------------------------

def _legacy_pre_f2_v2_reader(path: str) -> dict | None:
    """Byte-faithful copy of the pre-F2 v2 validation (only lane/at)."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError:
        return None
    if not isinstance(data, dict) or data.get("version") not in (1, 2):
        return None
    owners = data.get("owners")
    if not isinstance(owners, dict):
        return None
    entries: dict[str, dict] = {}
    for key, value in owners.items():
        if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
            return None
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("lane"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["lane"])
            or isinstance(value.get("at"), bool)
            or not isinstance(value.get("at"), (int, float))
            or not math.isfinite(value["at"])
        ):
            return None
        entries[key] = {"lane": value["lane"], "at": float(value["at"])}
    return entries


def test_new_format_record_readable_by_previous_v2_reader(lanes):
    a, _b, _state = lanes
    assert mux._record_session_owner(
        SID_BACKEND, str(a), "lane-alpha", origin="backend", lifecycle="ephemeral"
    )
    legacy = _legacy_pre_f2_v2_reader(mux.STATE_PATH + ".owners.json")
    assert legacy is not None, "pre-F2 reader must accept the additive record"
    digest = mux._owner_hash(SID_BACKEND)
    assert legacy[digest]["lane"] == mux._owner_hash(f"lane-alpha\t{a}")


# ---------------------------------------------------------------------------
# 5. Every owner-record rewrite preserves existing declarations.
# ---------------------------------------------------------------------------

def test_repeated_record_never_overwrites_existing_declaration(lanes):
    a, _b, _state = lanes
    assert mux._record_session_owner(
        SID_BACKEND, str(a), "lane-alpha", origin="backend", lifecycle="ephemeral"
    )
    # A later session/new on the same lane must not restamp the entry.
    assert mux._record_session_owner(
        SID_BACKEND, str(a), "lane-alpha", origin="agent", lifecycle="durable"
    )
    entry = _entry(SID_BACKEND)
    assert entry["origin"] == "backend"
    assert entry["lifecycle"] == "ephemeral"


def test_owner_prune_kept_entries_preserve_declarations(lanes):
    a, _b, _state = lanes
    now = time.time()
    assert mux._record_session_owner(
        SID_BACKEND, str(a), "lane-alpha", origin="backend", lifecycle="ephemeral"
    )
    assert mux._record_session_owner(SID_UNDECLARED, str(a), "lane-alpha")
    # Undeclared, bundle-less record past grace is prunable; the declared
    # record is inside grace and must survive with its keys intact.
    owners = _owners()
    owners["owners"][mux._owner_hash(SID_UNDECLARED)]["at"] = now - 2 * mux.OWNER_GRACE_SECONDS
    Path(mux.STATE_PATH + ".owners.json").write_text(json.dumps(owners))
    result = mux.prune_session_owners(now=now)
    assert result is not None and result["removed"] == 1
    survivors = _owners()["owners"]
    assert mux._owner_hash(SID_UNDECLARED) not in survivors
    kept = survivors[mux._owner_hash(SID_BACKEND)]
    assert kept["origin"] == "backend"
    assert kept["lifecycle"] == "ephemeral"


# ---------------------------------------------------------------------------
# 6. Concurrency and duplicate-owner protections hold with declarations.
# ---------------------------------------------------------------------------

def test_concurrent_writers_keep_declarations_and_file_valid(lanes):
    a, b, _state = lanes
    sids = [f"0000000{i}-0000-4000-8000-00000000000{i}" for i in range(8)]
    homes = {0: (a, "lane-alpha"), 1: (b, "lane-beta")}

    def write(index: int) -> bool:
        home, label = homes[index % 2]
        origin = "backend" if index % 2 == 0 else "agent"
        lifecycle = "ephemeral" if index % 3 == 0 else "durable"
        return mux._record_session_owner(
            sids[index], str(home), label, origin=origin, lifecycle=lifecycle
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert all(pool.map(write, range(8)))
    owners = _owners()["owners"]
    for index, sid in enumerate(sids):
        entry = owners[mux._owner_hash(sid)]
        assert entry["origin"] == ("backend" if index % 2 == 0 else "agent")
        assert entry["lifecycle"] == ("ephemeral" if index % 3 == 0 else "durable")


def test_duplicate_owner_cross_lane_rejected_and_declaration_untouched(lanes):
    a, b, _state = lanes
    assert mux._record_session_owner(
        SID_BACKEND, str(a), "lane-alpha", origin="backend", lifecycle="ephemeral"
    )
    assert mux._record_session_owner(
        SID_BACKEND, str(b), "lane-beta", origin="agent", lifecycle="durable"
    ) is False
    entry = _entry(SID_BACKEND)
    assert entry["lane"] == mux._owner_hash(f"lane-alpha\t{a}")
    assert entry["origin"] == "backend"
    assert entry["lifecycle"] == "ephemeral"


# ---------------------------------------------------------------------------
# 7-8. Inventory reports the origin x lifecycle matrix, unknown included.
# ---------------------------------------------------------------------------

def _matrix(lane_report: dict) -> dict:
    return lane_report["origin_lifecycle"]


def test_inventory_reports_origin_lifecycle_matrix(lanes):
    a, b, state_file = lanes
    now = time.time()
    _checkpoints(state_file, [], now=now)
    for sid in (SID_BACKEND, SID_AGENT, SID_UNDECLARED, SID_UNOWNED):
        _bundle(a, sid, mtime=now)
    _bundle(b, SID_EPHEMERAL_AGENT, mtime=now)
    assert mux._record_session_owner(
        SID_BACKEND, str(a), "lane-alpha", origin="backend", lifecycle="ephemeral"
    )
    assert mux._record_session_owner(
        SID_AGENT, str(a), "lane-alpha", origin="agent", lifecycle="durable"
    )
    assert mux._record_session_owner(SID_UNDECLARED, str(a), "lane-alpha")
    assert mux._record_session_owner(
        SID_EPHEMERAL_AGENT, str(b), "lane-beta", origin="agent", lifecycle="ephemeral"
    )
    report = _inventory(state_file, now=now)
    assert report["status"] == "ok"
    lane_a = next(row for row in report["lanes"] if row["bundles"] == 4)
    lane_b = next(row for row in report["lanes"] if row["bundles"] == 1)
    for lane_report in (lane_a, lane_b):
        matrix = _matrix(lane_report)
        assert set(matrix) == {"agent", "backend", "unknown"}
        for bucket in matrix.values():
            assert set(bucket) == {"ephemeral", "durable", "unknown"}
    assert _matrix(lane_a)["backend"]["ephemeral"] == 1
    assert _matrix(lane_a)["agent"]["durable"] == 1
    assert _matrix(lane_a)["unknown"]["unknown"] == 1  # undeclared owner record
    assert _matrix(lane_b)["agent"]["ephemeral"] == 1
    # The unowned bundle carries no declaration and never enters the matrix.
    assert sum(sum(b.values()) for b in _matrix(lane_a).values()) == 3
    totals = report["totals"]["origin_lifecycle"]
    assert totals["backend"]["ephemeral"] == 1
    assert totals["agent"]["durable"] == 1
    assert totals["agent"]["ephemeral"] == 1
    assert totals["unknown"]["unknown"] == 1


def test_uncheckpointed_undeclared_session_stays_unknown(lanes):
    a, _b, state_file = lanes
    now = time.time()
    _checkpoints(state_file, [], now=now)
    _bundle(a, SID_UNDECLARED, mtime=now)
    assert mux._record_session_owner(SID_UNDECLARED, str(a), "lane-alpha")
    report = _inventory(state_file, now=now)
    lane_a = next(row for row in report["lanes"] if row["bundles"] == 1)
    assert _matrix(lane_a)["unknown"]["unknown"] == 1
    assert _matrix(lane_a)["backend"]["ephemeral"] == 0
    assert lane_a["gc_candidate_expired"] == 0  # fresh bundle: policy unchanged
    assert report["deletions_performed"] == 0


def test_declaration_never_overrides_checkpoint_protection(lanes):
    a, _b, state_file = lanes
    now = time.time()
    _checkpoints(state_file, [SID_BACKEND], now=now)
    _bundle(a, SID_BACKEND, mtime=now - 40 * DAY)  # far past TTL
    assert mux._record_session_owner(
        SID_BACKEND, str(a), "lane-alpha", origin="backend", lifecycle="ephemeral"
    )
    report = _inventory(state_file, now=now)
    lane_a = next(row for row in report["lanes"] if row["bundles"] == 1)
    assert lane_a["checkpoint_protected"] == 1
    assert lane_a["gc_candidate_expired"] == 0, (
        "an ephemeral declaration must never license eviction of a "
        "checkpoint-protected session (F3/F4 territory)"
    )
    assert _matrix(lane_a)["backend"]["ephemeral"] == 1


# ---------------------------------------------------------------------------
# 9. Inventory and dry-run keep deleting nothing.
# ---------------------------------------------------------------------------

def test_inventory_and_dry_run_perform_zero_deletions(lanes, tmp_path):
    a, _b, state_file = lanes
    now = time.time()
    _checkpoints(state_file, [], now=now)
    bundles = [
        _bundle(a, sid, mtime=now - 40 * DAY)  # expired under current policy
        for sid in (SID_BACKEND, SID_AGENT, SID_UNDECLARED, SID_UNOWNED)
    ]
    assert mux._record_session_owner(
        SID_BACKEND, str(a), "lane-alpha", origin="backend", lifecycle="ephemeral"
    )
    owners_before = Path(mux.STATE_PATH + ".owners.json").read_bytes()
    report = _inventory(state_file, now=now)
    assert report["deletions_performed"] == 0
    assert report["totals"]["gc_candidate_expired"] == 4  # prediction only
    assert all(db.exists() for db in bundles)
    assert Path(mux.STATE_PATH + ".owners.json").read_bytes() == owners_before, (
        "inventory must not rewrite (or backfill) owner metadata"
    )
    # dry-run bind path: census log, zero mutation.
    reply = _run_mux(
        tmp_path,
        {"ACP_MUX_SESSION_GC": "dry-run"},
        SID_EPHEMERAL_AGENT,
    )
    assert "error" not in reply
    assert all(db.exists() for db in bundles)


# ---------------------------------------------------------------------------
# 10. Existing durable/resumable/sibling protections are untouched: the GC
#     predicate source must not consult the new fields at all in F2.
# ---------------------------------------------------------------------------

def test_gc_predicate_source_never_consults_declarations():
    import inspect

    for func in (mux._expired_gc_candidates, mux._capacity_gc_candidates,
                 mux._delete_session_bundle, mux.prune_session_stores):
        source = inspect.getsource(func)
        assert "origin" not in source
        assert "lifecycle" not in source
