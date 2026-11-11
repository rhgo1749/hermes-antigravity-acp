"""Ownership routing must not rely on evictable conversation affinity."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ownership_mux", ROOT / "scripts" / "acp_mux.py")
assert spec and spec.loader
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)
SID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


@pytest.fixture
def lanes(tmp_path, monkeypatch):
    monkeypatch.setattr(mux, "STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setattr(mux, "REGISTRY_PATH", str(tmp_path / "accounts.json"))
    monkeypatch.setattr(mux, "LOG_PATH", str(tmp_path / "mux.log"))
    a, b = tmp_path / "a", tmp_path / "b"
    for home in (a, b):
        (home / ".gemini" / "antigravity-acp" / "conversations").mkdir(parents=True)
    Path(mux.REGISTRY_PATH).write_text(json.dumps({"accounts": [
        {"home": str(a), "label": "a"}, {"home": str(b), "label": "b"}
    ]}))
    return a, b


def test_recorded_owner_survives_affinity_eviction_and_cooldown(lanes):
    a, b = lanes
    assert mux._record_session_owner(SID, str(a), "a")
    Path(mux.STATE_PATH).write_text(json.dumps({"version": 1, "accounts": {
        f"a\t{a}": {"cooldown_until": 99999999999}}, "affinities": {}, "cursor": {}}))
    assert mux._resolve_session_owner(SID) == (str(a), "a")


def test_legacy_store_search_is_exact_and_read_only(lanes):
    a, b = lanes
    path = b / ".gemini" / "antigravity-acp" / "conversations" / f"{SID}.db"
    path.write_bytes(b"do-not-read")
    before = path.stat().st_mtime_ns
    assert mux._resolve_session_owner(SID) == (str(b), "b")
    assert path.stat().st_mtime_ns == before


def test_ambiguous_store_and_symlink_fail_closed(lanes):
    a, b = lanes
    for home in (a, b):
        (home / ".gemini" / "antigravity-acp" / "conversations" / f"{SID}.db").write_text("x")
    assert mux._resolve_session_owner(SID) is None
    (b / ".gemini" / "antigravity-acp" / "conversations" / f"{SID}.db").unlink()
    (b / ".gemini" / "antigravity-acp" / "conversations" / f"{SID}.db").symlink_to(a / ".gemini" / "antigravity-acp" / "conversations" / f"{SID}.db")
    assert mux._resolve_session_owner(SID) is None


def test_corrupt_mapping_never_falls_back(lanes):
    a, _ = lanes
    (a / ".gemini" / "antigravity-acp" / "conversations" / f"{SID}.db").write_text("x")
    Path(mux.STATE_PATH + ".owners.json").write_text("{")
    assert mux._resolve_session_owner(SID) is None


@pytest.mark.parametrize("entrypoint", ["acp_mux.py", "antigravity-acp-mux.py"])
def test_fake_server_new_then_restart_resume_after_affinity_eviction(lanes, tmp_path, entrypoint):
    a, b = lanes
    fake = tmp_path / "fake.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,os,sys\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line); method=r.get('method'); result={'home':os.environ['HOME']}\n"
        f" if method=='session/new': result['sessionId']={SID!r}\n"
        " print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),'result':result}),flush=True)\n"
    )
    fake.chmod(0o755)
    env = os.environ.copy()
    env.update({"ACP_MUX_ACCOUNTS": mux.REGISTRY_PATH, "ACP_MUX_STATE": mux.STATE_PATH,
                "ACP_MUX_LOG": mux.LOG_PATH, "ACP_MUX_PAR": str(fake),
                "ACP_MUX_AFFINITY": "first", "HOME": str(tmp_path),
                "HERMES_REAL_HOME": str(tmp_path)})
    env.pop("ACP_MUX_SESSION_ID", None)
    env.pop("ACP_MUX_SESSION_GC", None)

    def run(requests, settings):
        result = subprocess.run([sys.executable, str(ROOT / "scripts" / entrypoint)],
            input="".join(json.dumps(x) + "\n" for x in requests), text=True,
            capture_output=True, env=settings, timeout=10, check=True)
        return [json.loads(line) for line in result.stdout.splitlines()]

    initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
    create = {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {}}
    replies = run([initialize, create], env)
    created = next(reply for reply in replies if reply["id"] == 2)
    owner = created["result"]["home"]
    assert owner in (str(a), str(b))
    state = json.loads(Path(mux.STATE_PATH).read_text())
    state["affinities"] = {}
    Path(mux.STATE_PATH).write_text(json.dumps(state))
    env.update({"ACP_MUX_SESSION_ID": SID, "ACP_MUX_AFFINITY": "different",
                "ACP_MUX_AFFINITY_PIN": "1"})
    resume = {"jsonrpc": "2.0", "id": 3, "method": "session/resume",
              "params": {"sessionId": SID}}
    replies = run([initialize, resume], env)
    assert next(reply for reply in replies if reply["id"] == 3)["result"]["home"] == owner


def test_duplicate_registry_home_and_symlink_are_rejected(lanes, tmp_path):
    a, _ = lanes
    registry = Path(mux.REGISTRY_PATH)
    registry.write_text(json.dumps({"accounts": [
        {"home": str(a), "label": "a"}, {"home": str(a), "label": "alias"}]}))
    assert mux._resolve_session_owner(SID) is None
    alias = tmp_path / "alias"
    alias.symlink_to(a, target_is_directory=True)
    registry.write_text(json.dumps({"accounts": [
        {"home": str(a), "label": "a"}, {"home": str(alias), "label": "alias"}]}))
    assert mux._resolve_session_owner(SID) is None


def test_duplicate_session_id_across_new_lanes_never_overwrites_owner(lanes):
    a, b = lanes
    assert mux._record_session_owner(SID, str(a), "a")
    assert not mux._record_session_owner(SID, str(b), "b")
    assert mux._resolve_session_owner(SID) == (str(a), "a")


def test_parallel_processes_keep_all_owner_records(lanes, tmp_path):
    a, _ = lanes
    script = ("import importlib.util,sys; "
              f"s=importlib.util.spec_from_file_location('m',{str(ROOT / 'scripts' / 'acp_mux.py')!r}); "
              "m=importlib.util.module_from_spec(s);s.loader.exec_module(m); "
              "sys.exit(0 if m._record_session_owner(sys.argv[1],sys.argv[2],'a') else 1)")
    env = os.environ.copy()
    env.update({"ACP_MUX_ACCOUNTS": mux.REGISTRY_PATH, "ACP_MUX_STATE": mux.STATE_PATH,
                "ACP_MUX_LOG": mux.LOG_PATH, "HOME": str(tmp_path),
                "HERMES_REAL_HOME": str(tmp_path)})
    ids = [f"fixture-{i}" for i in range(12)]
    def record(sid):
        return subprocess.run([sys.executable, "-c", script, sid, str(a)], env=env,
                              capture_output=True, timeout=10).returncode
    with ThreadPoolExecutor(max_workers=6) as pool:
        assert list(pool.map(record, ids)) == [0] * len(ids)
    assert all(mux._resolve_session_owner(sid) == (str(a), "a") for sid in ids)


def test_unknown_or_wrong_owner_rejected_before_upstream(lanes):
    a, b = lanes
    assert mux._record_session_owner(SID, str(a), "a")
    relay = mux._SessionOwnerRelay()
    request = {"id": 5, "method": "session/resume", "params": {"sessionId": SID}}
    assert relay.before(request, str(a), "a") is None
    assert "Session not found" in relay.before(request, str(b), "b")
    request["params"]["sessionId"] = "unknown"
    assert "Session not found" in relay.before(request, str(a), "a")


def test_lookup_waits_for_session_gc_lock(lanes):
    a, _ = lanes
    assert mux._record_session_owner(SID, str(a), "a")
    started = threading.Event()
    finished = threading.Event()
    results = []
    def lookup():
        started.set()
        results.append(mux._resolve_session_owner(SID))
        finished.set()
    with mux._session_gc_lock() as locked:
        assert locked
        worker = threading.Thread(target=lookup)
        worker.start()
        assert started.wait(2)
        assert not finished.wait(0.1)
    worker.join(timeout=2)
    assert finished.is_set()
    assert results == [(str(a), "a")]


@pytest.mark.parametrize("entrypoint", ["acp_mux.py", "antigravity-acp-mux.py"])
def test_unknown_resume_never_reaches_fake_server(lanes, tmp_path, entrypoint):
    fake = tmp_path / "fake.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        "for line in sys.stdin:\n"
        " r=json.loads(line)\n"
        " print(json.dumps({'jsonrpc':'2.0','id':r.get('id'),'result':{'seen':r.get('method')}}),flush=True)\n"
    )
    fake.chmod(0o755)
    env = os.environ.copy()
    env.update({"ACP_MUX_ACCOUNTS": mux.REGISTRY_PATH, "ACP_MUX_STATE": mux.STATE_PATH,
                "ACP_MUX_LOG": mux.LOG_PATH, "ACP_MUX_PAR": str(fake),
                "ACP_MUX_SESSION_ID": SID, "HOME": str(tmp_path),
                "HERMES_REAL_HOME": str(tmp_path)})
    env.pop("ACP_MUX_SESSION_GC", None)
    requests = [{"id": 1, "method": "initialize"}, {"id": 2, "method": "session/resume",
                "params": {"sessionId": SID}}]
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / entrypoint)],
        input="".join(json.dumps(x) + "\n" for x in requests), text=True,
        capture_output=True, env=env, timeout=10, check=True)
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    reply = next(x for x in replies if x["id"] == 2)
    assert "Session not found" in reply["error"]["message"]


def test_gc_reads_checkpoint_after_acquiring_gc_lock(lanes, monkeypatch):
    observed = []
    snapshot_called = threading.Event()
    def active(*, now=None, env=None):
        snapshot_called.set()
        return {SID}
    def prune(home, active_ids, *, now):
        observed.append(set(active_ids))
        return {"expired": 0, "capacity": 0, "bytes": 0, "failed": 0}
    monkeypatch.setattr(mux, "_active_hermes_session_ids", active)
    monkeypatch.setattr(mux, "_prune_session_store", prune)
    with mux._session_gc_lock() as locked:
        assert locked
        worker = threading.Thread(target=mux.prune_session_stores)
        worker.start()
        assert not snapshot_called.wait(0.1)
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert observed and all(ids == {SID} for ids in observed)


def test_gc_does_not_identify_an_active_uncheckpointed_session(lanes, monkeypatch):
    a, _ = lanes
    conversations = a / ".gemini" / "antigravity-acp" / "conversations"
    old = conversations / f"{SID}.db"
    old.write_text("fixture")
    assert mux._record_session_owner(SID, str(a), "a")
    other = conversations / "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb.db"
    other.write_text("fixture")
    os.utime(old, (100, 100))
    os.utime(other, (200, 200))
    monkeypatch.setattr(mux, "AFFINITY_MAX_ENTRIES", 1)
    result = mux._prune_session_store(str(a), set(), now=300)
    # A mapping alone does not register a process lease with existing GC.
    assert result["capacity"] == 1
    assert not old.exists()
    assert other.exists()





