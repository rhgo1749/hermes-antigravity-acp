"""Native session-store GC is opt-in; ownership cleanup is metadata-only.

Issue #3 interim operating policy: the destructive native GC must never run
without an explicit opt-in, and the always-on ownership-record cleanup must
fail closed (keep every entry) whenever the registry, ownership ledger,
checkpoint inventory, or a session store cannot be read.
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
spec = importlib.util.spec_from_file_location("gc_policy_mux", ROOT / "scripts" / "acp_mux.py")
assert spec and spec.loader
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)

SID_LIVE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
SID_DEAD = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
SID_GRACE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
SID_CHECK = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
SID_GHOST = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
DAY = 86400


@pytest.fixture
def lanes(tmp_path, monkeypatch):
    monkeypatch.setattr(mux, "STATE_PATH", str(tmp_path / "state.json"))
    monkeypatch.setattr(mux, "REGISTRY_PATH", str(tmp_path / "accounts.json"))
    monkeypatch.setattr(mux, "LOG_PATH", str(tmp_path / "mux.log"))
    monkeypatch.setattr(mux, "OWNER_GRACE_SECONDS", 3600)
    hermes_home = tmp_path / "hermes-home"
    (hermes_home / "cache").mkdir(parents=True)
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.delenv("ACP_MUX_SESSION_ID", raising=False)
    monkeypatch.delenv("HERMES_REAL_HOME", raising=False)
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_STATE_FILE", raising=False)
    a, b = tmp_path / "a", tmp_path / "b"
    for home in (a, b):
        (home / ".gemini" / "antigravity-acp" / "conversations").mkdir(parents=True)
    Path(mux.REGISTRY_PATH).write_text(json.dumps({"accounts": [
        {"home": str(a), "label": "a"}, {"home": str(b), "label": "b"}
    ]}))
    return a, b, hermes_home


def _bundle(home: Path, session_id: str, *, mtime: float) -> Path:
    path = home / ".gemini" / "antigravity-acp" / "conversations" / f"{session_id}.db"
    path.write_bytes(b"x" * 32)
    os.utime(path, (mtime, mtime))
    return path


def _write_owners(entries: dict[str, tuple[str, Path | str, float]]) -> None:
    owners = {
        mux._owner_hash(sid): {
            "lane": mux._owner_hash(f"{label}\t{home}"),
            "at": at,
        }
        for sid, (label, home, at) in entries.items()
    }
    Path(mux.STATE_PATH + ".owners.json").write_text(
        json.dumps({"version": 2, "owners": owners}, sort_keys=True)
    )


def _read_owners() -> dict:
    return json.loads(Path(mux.STATE_PATH + ".owners.json").read_text())["owners"]


def _checkpoint(hermes_home: Path, session_ids: list[str], now: float) -> None:
    payload = {
        "version": 1,
        "states": {
            sid: {"session_id": sid, "updated_at": now - 60} for sid in session_ids
        },
    }
    (hermes_home / "cache" / mux._SESSION_STATE_FILENAME).write_text(json.dumps(payload))


def test_owner_prune_removes_only_fully_retired_entries(lanes):
    a, _b, hermes_home = lanes
    now = time.time()
    live = _bundle(a, SID_LIVE, mtime=now - 10 * DAY)
    _write_owners({
        SID_LIVE: ("a", a, now - 10 * DAY),
        SID_DEAD: ("a", a, now - 10 * DAY),
        SID_GRACE: ("a", a, now - 60),
        SID_CHECK: ("a", a, now - 10 * DAY),
        SID_GHOST: ("ghost", "/ghost-home", now - 10 * DAY),
    })
    _checkpoint(hermes_home, [SID_CHECK], now)

    stats = mux.prune_session_owners(now=now)
    assert stats is not None
    assert stats["removed"] == 1 and stats["kept"] == 4
    remaining = set(_read_owners())
    assert remaining == {
        mux._owner_hash(sid) for sid in (SID_LIVE, SID_GRACE, SID_CHECK, SID_GHOST)
    }
    assert live.exists(), "ownership cleanup must never delete a session bundle"
    log = Path(mux.LOG_PATH).read_text()
    assert "owner-records kept=4 removed=1" in log
    assert f"bundles=1 bytes={32}" in log


def test_owner_prune_fail_closed_on_checkpoint_inventory(lanes):
    a, _b, hermes_home = lanes
    now = time.time()
    _write_owners({SID_DEAD: ("a", a, now - 10 * DAY)})
    (hermes_home / "cache" / mux._SESSION_STATE_FILENAME).write_text("{broken")
    assert mux.prune_session_owners(now=now) is None
    assert mux._owner_hash(SID_DEAD) in _read_owners()


def test_owner_prune_fail_closed_on_store_inventory(lanes):
    if os.geteuid() == 0:
        pytest.skip("permission-bit failure injection is meaningless as root")
    a, b, _hermes_home = lanes
    now = time.time()
    _bundle(b, SID_LIVE, mtime=now)
    _write_owners({SID_LIVE: ("a", a, now - 10 * DAY)})
    unreadable = b / ".gemini" / "antigravity-acp" / "conversations"
    unreadable.chmod(0o000)
    try:
        assert mux.prune_session_owners(now=now) is None
    finally:
        unreadable.chmod(0o755)
    assert mux._owner_hash(SID_LIVE) in _read_owners()


def test_owner_prune_fail_closed_on_corrupt_owners(lanes):
    Path(mux.STATE_PATH + ".owners.json").write_text("{")
    assert mux.prune_session_owners() is None


def test_owner_prune_fail_closed_on_invalid_registry(lanes):
    a, _b, _hermes_home = lanes
    now = time.time()
    _write_owners({SID_DEAD: ("a", a, now - 10 * DAY)})
    Path(mux.REGISTRY_PATH).write_text("[")
    assert mux.prune_session_owners(now=now) is None
    assert mux._owner_hash(SID_DEAD) in _read_owners()


def test_owner_prune_fail_closed_on_symlinked_store(lanes):
    a, b, _hermes_home = lanes
    now = time.time()
    _write_owners({SID_DEAD: ("a", a, now - 10 * DAY)})
    real_store = b / "outside-store"
    real_store.mkdir()
    (b / ".gemini" / "antigravity-acp" / "conversations").rmdir()
    (b / ".gemini" / "antigravity-acp" / "conversations").symlink_to(real_store)
    assert mux.prune_session_owners(now=now) is None
    assert mux._owner_hash(SID_DEAD) in _read_owners()


def test_owner_prune_is_noop_without_entries(lanes):
    stats = mux.prune_session_owners()
    assert stats == {"removed": 0, "kept": 0, "bundles": 0, "bytes": 0}
    assert not Path(mux.STATE_PATH + ".owners.json").exists()


def test_owner_records_v1_file_resolves_and_upgrades(lanes):
    a, _b, _hermes_home = lanes
    legacy = {
        "version": 1,
        "owners": {mux._owner_hash(SID_DEAD): mux._owner_hash(f"a\t{a}")},
    }
    path = Path(mux.STATE_PATH + ".owners.json")
    path.write_text(json.dumps(legacy))
    assert mux._resolve_session_owner(SID_DEAD) == (str(a), "a")
    assert mux._record_session_owner(SID_LIVE, str(a), "a")
    data = json.loads(path.read_text())
    assert data["version"] == 2
    assert data["owners"][mux._owner_hash(SID_DEAD)]["lane"] == mux._owner_hash(f"a\t{a}")
    assert data["owners"][mux._owner_hash(SID_LIVE)]["lane"] == mux._owner_hash(f"a\t{a}")


@pytest.mark.parametrize("entrypoint", ["acp_mux.py", "antigravity-acp-mux.py"])
def test_bind_time_keeps_stale_bundles_and_prunes_owner_records(lanes, tmp_path, entrypoint):
    a, _b, hermes_home = lanes
    now = time.time()
    stale = _bundle(a, SID_LIVE, mtime=now - 2 * DAY)
    _write_owners({
        SID_LIVE: ("a", a, now - 10 * DAY),
        SID_DEAD: ("a", a, now - 10 * DAY),
    })
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
        "ACP_MUX_SESSION_GC": "0",
        "HOME": str(tmp_path),
        "HERMES_REAL_HOME": str(tmp_path),
        "HERMES_HOME": str(hermes_home),
    })
    env.pop("HERMES_ANTIGRAVITY_ACP_NATIVE_GC", None)
    env.pop("ACP_MUX_SESSION_ID", None)
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n"
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / entrypoint)],
        input=request,
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert stale.exists(), "native GC must not run without the opt-in"
    remaining = set(_read_owners())
    assert remaining == {mux._owner_hash(SID_LIVE)}, "live-bundle entry must survive cleanup"
    log = Path(mux.LOG_PATH).read_text()
    assert "native session GC disabled" in log
    assert "session-gc expired" not in log
    assert "owner-records kept=1 removed=1" in log
