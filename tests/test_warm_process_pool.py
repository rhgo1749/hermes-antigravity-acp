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

import array
import errno
import importlib.util
import json
import os
import select
import signal
import socket
import subprocess
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


_PIDFD_UNSUPPORTED_ERRNOS = frozenset(
    getattr(errno, name)
    for name in ("ENOSYS", "EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP", "ENODEV")
    if hasattr(errno, name)
)


def _linux_pidfd_capability_gap() -> str | None:
    if sys.platform != "linux":
        return "requires Linux proc start-time identities, fork, and os.pidfd_open"
    if not Path("/proc").is_dir():
        return "requires /proc for start-time identity observation"
    if not all(hasattr(socket, name) for name in ("socketpair", "SCM_RIGHTS", "MSG_CTRUNC", "CMSG_SPACE")):
        return "requires AF_UNIX socketpair and SCM_RIGHTS fd passing"
    if not hasattr(os, "_exit"):
        return "requires os._exit"
    if not hasattr(os, "pidfd_open"):
        return "interpreter build lacks os.pidfd_open"
    return None


def _require_working_pidfd_open() -> None:
    gap = _linux_pidfd_capability_gap()
    if gap is not None:
        pytest.skip(gap)
    try:
        probe_fd = os.pidfd_open(os.getpid())
    except OSError as exc:
        if exc.errno in _PIDFD_UNSUPPORTED_ERRNOS:
            pytest.skip(f"kernel/runtime lacks working os.pidfd_open (errno={exc.errno})")
        raise
    os.close(probe_fd)


@pytest.mark.skipif(
    _linux_pidfd_capability_gap() is not None,
    reason=_linux_pidfd_capability_gap() or "requires Linux proc start-time identities, fork, and os.pidfd_open",
)
@pytest.mark.parametrize("hold_stdin_open", [False, True])
def test_parked_fixture_natural_exit_after_owner_hard_exit(fake, tmp_path, hold_stdin_open) -> None:
    """Observe the real fixture and grandchild without signals; retain a writer as a negative control."""
    _require_working_pidfd_open()
    from scripts.gateway_e2e import _live

    _, _, _ = fake
    fixture = PLUGIN_DIR.parent.parent / "scripts" / "gateway_fake_acp.py"
    events_file = tmp_path / "acp-events.jsonl"
    (tmp_path / "control.json").write_text(json.dumps({"mode": "reply", "text": "synthetic"}))
    parent, child = socket.socketpair()
    parent.settimeout(15)
    owner_code = '''
import array, importlib.util, os, socket, sys
from pathlib import Path
plugin, root, fixture, fd, hold = sys.argv[1:]
spec = importlib.util.spec_from_file_location("agy_owner", Path(plugin) / "client.py", submodule_search_locations=[plugin])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
child = socket.socket(fileno=int(fd))
child.settimeout(20)
try:
    client = module.AntigravityACPClient(acp_command=sys.executable, acp_args=[fixture, root], acp_cwd=root)
    with client._session(10.0):
        pass
    parked = [entry["proc"] for entries in module._warm_pool.values() for entry in entries]
    if len(parked) != 1 or parked[0].stdin is None or parked[0].poll() is not None:
        child.sendall(b"F")
        os._exit(1)
    rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [parked[0].stdin.fileno()]))] if hold == "1" else []
    child.sendmsg([b"R"], rights)
    if child.recv(1) != b"G":
        module._shutdown_warm_pool()
        os._exit(2)
    os._exit(0)  # Same hard-exit primitive as Core; skips the provider's atexit hook.
except BaseException:
    try:
        module._shutdown_warm_pool()
    finally:
        try:
            child.sendall(b"F")
        finally:
            os._exit(3)
'''
    try:
        owner = subprocess.Popen([sys.executable, "-c", owner_code, str(PLUGIN_DIR), str(tmp_path),
                                  str(fixture), str(child.fileno()), "1" if hold_stdin_open else "0"],
                                 pass_fds=(child.fileno(),))
    except BaseException:
        parent.close()
        child.close()
        raise
    child.close()
    held_fd = None
    owner_reaped = False
    identities = []
    try:
        message, ancillary, flags, _ = parent.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize))
        assert message == b"R" and not flags & socket.MSG_CTRUNC
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                received = array.array("i")
                received.frombytes(data[:len(data) - len(data) % received.itemsize])
                assert len(received) == 1
                held_fd = received[0]
        assert (held_fd is not None) == hold_stdin_open
        events = [json.loads(line) for line in events_file.read_text().splitlines()]
        started = [event for event in events if event.get("event") == "server_started"]
        assert len(started) == 1
        event = started[0]
        identities = [(event["pid"], event["started"]), (event["grandchild_pid"], event["grandchild_started"])]
        assert all(_live(pid, token) for pid, token in identities)
        parent.sendall(b"G")
        owner_pidfd = os.pidfd_open(owner.pid)
        try:
            assert select.select([owner_pidfd], [], [], 5)[0], "fixture owner did not exit within the bound"
            status = owner.wait(timeout=5)
            owner_reaped = True
            assert status == 0
        finally:
            os.close(owner_pidfd)
        initial_alive = tuple(_live(pid, token) for pid, token in identities)
        if hold_stdin_open:
            assert held_fd is not None
            # No signal is sent; keeping a genuine pipe writer open prevents stdin EOF.
            time.sleep(0.3)
            assert all(_live(pid, token) for pid, token in identities)
            assert not any(json.loads(line).get("event") == "server_exited"
                           for line in events_file.read_text().splitlines())
            os.close(held_fd)
            held_fd = None
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            events = [json.loads(line) for line in events_file.read_text().splitlines()]
            if (any(event.get("event") == "server_exited" for event in events)
                    and not any(_live(pid, token) for pid, token in identities)):
                break
            time.sleep(0.01)
        assert any(event.get("event") == "server_exited" for event in events)
        assert not _live(*identities[0]), "fixture did not exit naturally"
        assert not _live(*identities[1]), "fixture grandchild did not exit naturally"
        print(f"fixture_observation held_writer={hold_stdin_open} "
              f"initial_fixture_alive={initial_alive[0]} initial_grandchild_alive={initial_alive[1]} "
              "server_exited=True final_fixture_alive=False final_grandchild_alive=False observer_signals_sent=False")
    finally:
        if held_fd is not None:
            os.close(held_fd)
        parent.close()
        if not owner_reaped:
            if owner.poll() is None:
                owner.kill()
            owner.wait(timeout=5)
        # Only fixture-recorded identities; an observation timeout never becomes PASS.
        if not identities and events_file.exists():
            for line in events_file.read_text().splitlines():
                event = json.loads(line)
                if event.get("event") == "server_started":
                    identities.extend([(event["pid"], event["started"]),
                                       (event["grandchild_pid"], event["grandchild_started"])])
        for pid, token in identities:
            if _live(pid, token):
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + 2
        while any(_live(pid, token) for pid, token in identities) and time.monotonic() < deadline:
            time.sleep(0.01)
        for pid, token in identities:
            if _live(pid, token):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        deadline = time.monotonic() + 2
        while any(_live(pid, token) for pid, token in identities) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert not any(_live(pid, token) for pid, token in identities), "fixture cleanup left a live process"


@pytest.mark.skipif(
    sys.platform != "linux"
    or not Path("/proc").is_dir()
    or not all(hasattr(socket, name) for name in ("socketpair", "SCM_RIGHTS", "MSG_CTRUNC", "CMSG_SPACE")),
    reason="requires Linux /proc and SCM_RIGHTS fd passing",
)
def test_pidfd_guard_distinguishes_unsupported_runtime_from_real_failures(monkeypatch) -> None:
    monkeypatch.delattr(os, "pidfd_open", raising=False)
    assert _linux_pidfd_capability_gap() == "interpreter build lacks os.pidfd_open"
    with pytest.raises(pytest.skip.Exception):
        _require_working_pidfd_open()

    for err in (errno.ENOSYS, errno.EPERM):
        def _unsupported(_pid: int, _flags: int = 0, code: int = err) -> int:
            raise OSError(code, os.strerror(code))

        monkeypatch.setattr(os, "pidfd_open", _unsupported, raising=False)
        assert _linux_pidfd_capability_gap() is None
        with pytest.raises(pytest.skip.Exception):
            _require_working_pidfd_open()

    def _missing_pid(_pid: int, _flags: int = 0) -> int:
        raise ProcessLookupError(errno.ESRCH, "No such process")

    monkeypatch.setattr(os, "pidfd_open", _missing_pid, raising=False)
    with pytest.raises(ProcessLookupError):
        _require_working_pidfd_open()

    def _invalid_arg(_pid: int, _flags: int = 0) -> int:
        raise OSError(errno.EINVAL, "Invalid argument")

    monkeypatch.setattr(os, "pidfd_open", _invalid_arg, raising=False)
    with pytest.raises(OSError) as exc_info:
        _require_working_pidfd_open()
    assert exc_info.value.errno == errno.EINVAL
