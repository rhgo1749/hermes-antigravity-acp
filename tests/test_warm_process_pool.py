"""Warm process pool regression tests.

The ACP protocol's intended topology is a persistent server process: one
``initialize`` handshake followed by many ``session/new`` round-trips on the
same stdio connection.  These tests pin the warm-pool contract:

* a healthy session's child is parked and reused (no second cold start),
* reuse is scoped to the exact launch identity (command/args/cwd/affinity),
* dead, expired, poisoned or resume-pinned children are never reused,
* JSON-RPC ids keep incrementing across sessions on one connection,
* pool shutdown terminates every parked child.
"""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"

FAKE_SERVER = '''
import json, os, sys

counter_path = sys.argv[1]
with open(counter_path, "a", encoding="utf-8") as handle:
    handle.write("spawn\\n")

def send(payload):
    sys.stdout.write(json.dumps(payload) + "\\n")
    sys.stdout.flush()

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    method = msg.get("method")
    rid = msg.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": 1, "agentCapabilities": {}}})
    elif method == "session/new":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "sessionId": f"s-{rid}",
            "models": {"availableModels": [{"modelId": "model-x"}]}}})
    elif method == "session/resume":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "sessionId": (msg.get("params") or {}).get("sessionId", f"s-{rid}"),
            "models": {"availableModels": [{"modelId": "model-x"}]}}})
    elif method == "session/set_model":
        send({"jsonrpc": "2.0", "id": rid, "result": {}})
    if os.path.exists(os.path.join(os.path.dirname(counter_path), "kill-after-new")):
        if method in ("session/new", "session/resume"):
            sys.exit(0)
'''


def _load_module(name: str):
    spec = importlib.util.spec_from_file_location(
        name,
        PLUGIN_DIR / "client.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def fake(request, tmp_path, monkeypatch):
    # The pool tests pin acp_cwd to tmp_path; a host-pinned workspace root
    # (HERMES_ANTIGRAVITY_ACP_WORKSPACE) would legitimately refuse it.
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_WORKSPACE", raising=False)
    module = _load_module(f"agy_client_warm_{request.node.name}")
    script = tmp_path / "fake_acp_server.py"
    script.write_text(FAKE_SERVER, encoding="utf-8")
    counter = tmp_path / "spawns.count"
    counter.touch()
    try:
        yield module, script, counter
    finally:
        module._shutdown_warm_pool()


def _client(module, tmp_path, script, counter):
    return module.AntigravityACPClient(
        acp_command=sys.executable,
        acp_args=[str(script), str(counter)],
        acp_cwd=str(tmp_path),
    )


def _spawns(counter) -> int:
    return counter.read_text(encoding="utf-8").count("spawn")


def test_parked_process_is_reused_across_client_instances(fake, tmp_path) -> None:
    """Two sequential clients on the same launch identity spawn the server once."""
    module, script, counter = fake
    first = _client(module, tmp_path, script, counter)
    assert first.list_models() == ["model-x"]
    first.close()
    second = _client(module, tmp_path, script, counter)
    assert second.list_models() == ["model-x"]
    second.close()
    assert _spawns(counter) == 1


def test_reuse_is_scoped_to_affinity_key(fake, tmp_path) -> None:
    module, script, counter = fake
    client = _client(module, tmp_path, script, counter)
    with client._session(30.0, affinity_key="conv-a"):
        pass
    with client._session(30.0, affinity_key="conv-a"):
        pass
    assert _spawns(counter) == 1
    with client._session(30.0, affinity_key="conv-b"):
        pass
    assert _spawns(counter) == 2


def test_dead_parked_process_is_respawned(fake, tmp_path) -> None:
    module, script, counter = fake
    client = _client(module, tmp_path, script, counter)
    with client._session(30.0):
        pass
    key = next(iter(module._warm_pool))
    entry = module._warm_pool[key][0]
    entry["proc"].kill()
    entry["proc"].wait(timeout=10)
    with client._session(30.0) as (session, _request, _stats):
        assert session.get("sessionId")
    assert _spawns(counter) == 2


def test_idle_ttl_expiry_forces_respawn(fake, tmp_path, monkeypatch) -> None:
    module, script, counter = fake
    client = _client(module, tmp_path, script, counter)
    with client._session(30.0):
        pass
    key = next(iter(module._warm_pool))
    module._warm_pool[key][0]["idle_since"] = time.monotonic() - 10_000
    with client._session(30.0):
        pass
    assert _spawns(counter) == 2


def test_resume_never_reuses_a_parked_process(fake, tmp_path) -> None:
    """Resume pins its session id through the spawn environment; a parked
    child was spawned without it and must not serve the resume."""
    module, script, counter = fake
    client = _client(module, tmp_path, script, counter)
    with client._session(30.0):
        pass
    with client._session(30.0, resume_session_id="resume-1") as (session, _, _):
        assert session.get("sessionId") == "resume-1"
    assert _spawns(counter) == 2


def test_poisoned_child_is_terminated_not_parked(fake, tmp_path) -> None:
    module, script, counter = fake
    (tmp_path / "kill-after-new").touch()
    client = _client(module, tmp_path, script, counter)
    with pytest.raises(Exception):
        # The fake exits right after session/new; the session body then
        # fails.  The dead child must never survive in the pool: either the
        # park-time liveness check rejects it or the next acquire reaps it.
        with client._session(30.0):
            raise RuntimeError("force session body failure")
    parked = [
        entry for entries in module._warm_pool.values() for entry in entries
    ]
    for entry in parked:
        entry["proc"].wait(timeout=10)
    assert all(entry["proc"].poll() is not None for entry in parked) or not parked
    # The next acquire reaps every dead parked child before serving.
    (tmp_path / "kill-after-new").unlink()
    with client._session(30.0) as (session, _, _):
        assert session.get("sessionId")
    parked = [
        entry for entries in module._warm_pool.values() for entry in entries
    ]
    assert all(entry["proc"].poll() is None for entry in parked)
    assert _spawns(counter) == 2


def test_jsonrpc_ids_continue_across_sessions_on_one_connection(fake, tmp_path) -> None:
    module, script, counter = fake
    client = _client(module, tmp_path, script, counter)
    with client._session(30.0) as (first, _, _):
        first_id = first.get("sessionId")
    with client._session(30.0) as (second, _, _):
        second_id = second.get("sessionId")
    assert first_id == "s-2"  # id 1 = initialize, id 2 = session/new
    assert second_id == "s-3"  # ids continue on the reused connection
    assert _spawns(counter) == 1


def test_shutdown_terminates_parked_children(fake, tmp_path) -> None:
    module, script, counter = fake
    client = _client(module, tmp_path, script, counter)
    with client._session(30.0):
        pass
    procs = [
        entry["proc"]
        for entries in module._warm_pool.values()
        for entry in entries
    ]
    assert procs and all(p.poll() is None for p in procs)
    module._shutdown_warm_pool()
    deadline = time.monotonic() + 10
    while any(p.poll() is None for p in procs) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert all(p.poll() is not None for p in procs)
