"""Issue #23: request-scoped cancellation of non-HTTP ACP execution.

Credential-free fake-ACP regressions for the Core interrupt contract
(``agent/client_lifecycle.py::_abort_request_slot_client`` calls
``client.cancel()`` when the client type exposes it, before falling back to
HTTP socket shutdown). These tests pin the plugin side of that contract:

* ``cancel()`` is a class-level attribute (Core's gate is ``callable(getattr(
  type(client), "cancel", None))`` — dynamic instance attributes do not count).
* cancel stops this instance's in-flight prompt quickly and never touches
  parked warm-pool processes or other client instances' processes.
* cancel/completion races end in a clean, non-failover outcome with no leaked
  subprocesses.
* the mux reaps its official-server child on SIGTERM via the bounded
  stdin-close -> terminate -> kill teardown instead of orphaning it.

No live credentials, no real ACP binary, no Hermes Core import (CI is
credential-free; the Core-side hook itself is pinned upstream by
tests/agent/test_provider_client_cancel.py).
"""

from __future__ import annotations

import importlib.util
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"
REPO = Path(__file__).resolve().parent.parent
MUX_ENTRYPOINT = REPO / "scripts" / "antigravity-acp-mux.py"

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX signal semantics")


FAKE_SERVER = r'''
import json, os, signal, sys, time

log_path, pid_path = sys.argv[1], sys.argv[2]
prompt_delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
handshake_delay = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
t0 = time.monotonic()

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def log(event):
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"event": event, "t": round(time.monotonic() - t0, 3)}) + "\n")

def on_term(signum, frame):
    log("sigterm")
    sys.stdout.flush()
    os._exit(143)

signal.signal(signal.SIGTERM, on_term)
with open(pid_path, "w", encoding="utf-8") as fh:
    fh.write(str(os.getpid()))

for line in sys.stdin:
    try:
        msg = json.loads(line)
    except Exception:
        continue
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "session/new":
        if handshake_delay:
            time.sleep(handshake_delay)
        emit({"jsonrpc": "2.0", "id": mid, "result": {
            "sessionId": "fake-session-1",
            "configOptions": [{"id": "model", "category": "model",
                "currentValue": "gemini-3.8-flash-high",
                "options": [{"value": "gemini-3.1-pro"}, {"value": "gemini-3.8-flash-high"}]}],
        }})
    elif method in ("session/set_config_option", "session/set_model", "session/resume"):
        emit({"jsonrpc": "2.0", "id": mid, "result": {}})
    elif method == "session/prompt":
        log("prompt_received")
        time.sleep(prompt_delay)
        try:
            emit({"jsonrpc": "2.0", "method": "session/update", "params": {"sessionId": "fake-session-1",
                "update": {"sessionUpdate": "agent_message_chunk",
                           "content": {"type": "text", "text": "done"}}}})
            emit({"jsonrpc": "2.0", "id": mid, "result": {"stopReason": "end_turn"}})
            log("prompt_answered")
        except (BrokenPipeError, OSError):
            log("stdout_broken_pipe")
log("stdin_eof_exit")
'''


def _wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _events(log_path: Path):
    if not Path(log_path).exists():
        return []
    return [json.loads(line) for line in Path(log_path).read_text().splitlines() if line.strip()]


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class _Worker(threading.Thread):
    def __init__(self, client, timeout=None):
        super().__init__(daemon=True)
        self.client = client
        self.timeout = timeout
        self.result = None
        self.error = None

    def run(self):
        kwargs = {"timeout": self.timeout} if self.timeout else {}
        try:
            self.result = self.client.chat.completions.create(
                model="gemini-3.1-pro",
                messages=[{"role": "user", "content": "hello fake"}],
                **kwargs,
            )
        except BaseException as exc:  # noqa: BLE001
            self.error = exc
        self.done = time.monotonic()


class AcpHarness:
    """Fresh plugin module (fresh global warm pool) + fake-server plumbing."""

    def __init__(self, tmp_path: Path):
        self.dir = tmp_path / "agy"
        self.dir.mkdir()
        (self.dir / "fake_acp_server.py").write_text(FAKE_SERVER, encoding="utf-8")
        os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"] = str(self.dir / "conv-state.json")
        os.environ.pop("HERMES_ANTIGRAVITY_ACP_NATIVE_GC", None)
        registered = []

        class FakeProviderProfile:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        providers = types.ModuleType("providers")
        providers.register_provider = registered.append
        providers_base = types.ModuleType("providers.base")
        providers_base.ProviderProfile = FakeProviderProfile
        self._saved = {
            name: sys.modules.get(name) for name in ("providers", "providers.base")
        }
        sys.modules["providers"] = providers
        sys.modules["providers.base"] = providers_base
        name = f"agy_issue23_{abs(hash(str(tmp_path)))}"
        spec = importlib.util.spec_from_file_location(
            name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)])
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        self.module = module
        importlib.import_module(f"{name}.client")
        self.client_module = sys.modules[f"{name}.client"]
        self._module_name = name
        self._counter = 0

    def make_client(self, *, prompt_delay=0.0, handshake_delay=0.0):
        self._counter += 1
        tag = f"c{self._counter}"
        log_path = self.dir / f"{tag}.jsonl"
        pid_path = self.dir / f"{tag}.pid"
        args = [
            str(self.dir / "fake_acp_server.py"),
            str(log_path), str(pid_path), str(prompt_delay), str(handshake_delay),
        ]
        client = self.module.antigravity_acp.create_client(
            command=sys.executable, args=args, acp_cwd=str(self.dir),
            rate_limit_retries=0)
        return client, log_path, pid_path

    def live_pids(self):
        pids = []
        for pid_path in self.dir.glob("*.pid"):
            text = pid_path.read_text().strip()
            if text and _alive(int(text)):
                pids.append(int(text))
        return pids


@pytest.fixture()
def agy(tmp_path):
    return AcpHarness(tmp_path)


def _wait_prompt_received(log_path: Path, timeout=10.0):
    return _wait_for(
        lambda: any(e["event"] == "prompt_received" for e in _events(log_path)),
        timeout=timeout)


def test_cancel_hook_is_class_level_callable(agy):
    """Core's gate is class-level: callable(getattr(type(client), "cancel", None))."""
    client, _, _ = agy.make_client()
    cancel = getattr(type(client), "cancel", None)
    assert callable(cancel), (
        "AntigravityACPClient must expose a class-level cancel() so Hermes Core's"
        " _abort_request_slot_client stops falling through to the HTTP socket sweep"
        " (tcp_force_closed=0, issue #23)"
    )


def test_cancel_stops_inflight_prompt_fast(agy):
    client, log_path, pid_path = agy.make_client(prompt_delay=30)
    worker = _Worker(client)
    worker.start()
    assert _wait_prompt_received(log_path)
    pid = int(pid_path.read_text())
    t0 = time.monotonic()
    client.cancel()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert worker.error is not None and worker.result is None
    assert time.monotonic() - t0 < 3.0, "cancel must stop the prompt within 3s"
    assert not _alive(pid), "the cancelled request's process must exit"
    events = [e["event"] for e in _events(log_path)]
    assert events.count("prompt_received") == 1, f"cancel must not re-send the prompt: {events}"
    assert "prompt_answered" not in events
    assert agy.live_pids() == []


def test_cancel_preserves_sibling_client(agy):
    slow, slow_log, _ = agy.make_client(prompt_delay=4)
    fast, fast_log, _ = agy.make_client(prompt_delay=0.5)
    w_slow, w_fast = _Worker(slow), _Worker(fast)
    w_slow.start()
    w_fast.start()
    assert _wait_prompt_received(slow_log) and _wait_prompt_received(fast_log)
    slow.cancel()
    w_slow.join(timeout=5)
    w_fast.join(timeout=15)
    assert w_slow.error is not None and w_slow.result is None
    assert w_fast.error is None and w_fast.result is not None, (
        "a sibling client instance's in-flight request must never be cancelled"
    )


def test_cancel_after_completion_is_inert_and_parked_process_survives(agy):
    client, log_path, pid_path = agy.make_client(prompt_delay=0)
    worker = _Worker(client)
    worker.start()
    worker.join(timeout=15)
    assert worker.error is None, "clean completion must not error"
    parked_pid = int(pid_path.read_text())
    assert _alive(parked_pid), "a completed session's process parks warm, it is not killed"
    client.cancel()
    client.cancel()
    assert _alive(parked_pid), "cancel() must never touch parked warm-pool processes"
    # the parked process must still serve a new client instance (warm reuse intact)
    reuse, reuse_log, _ = agy.make_client(prompt_delay=0)
    # same launch identity as the parked process: reuse the same fake args
    reuse._acp_command = client._acp_command
    reuse._acp_args = list(client._acp_args)
    reuse._acp_cwd = client._acp_cwd
    w2 = _Worker(reuse)
    w2.start()
    w2.join(timeout=15)
    assert w2.error is None
    assert int(pid_path.read_text()) == parked_pid and _alive(parked_pid), (
        "the second request must reuse the parked process (warm-pool contract)"
    )
    reuse.close()


def test_repeated_cancel_is_idempotent(agy):
    client, log_path, _ = agy.make_client(prompt_delay=30)
    worker = _Worker(client)
    worker.start()
    assert _wait_prompt_received(log_path)
    client.cancel()
    client.cancel()
    client.cancel()
    worker.join(timeout=5)
    assert not worker.is_alive() and worker.error is not None
    assert agy.live_pids() == []


def test_cancel_during_handshake_prevents_prompt_send(agy):
    client, log_path, pid_path = agy.make_client(prompt_delay=30, handshake_delay=5)
    worker = _Worker(client)
    worker.start()
    assert _wait_for(pid_path.exists), "the fake must have been spawned"
    client.cancel()
    worker.join(timeout=5)
    assert not worker.is_alive() and worker.error is not None
    assert not any(e["event"] == "prompt_received" for e in _events(log_path)), (
        "a cancel that races process spawn must prevent session/prompt from ever being sent"
    )
    assert agy.live_pids() == []


def test_cancel_completion_race_is_clean(agy):
    """Cancel landing around completion never crashes, retries, or leaks."""
    allowed = ("_AcpCancelledError", "TimeoutError", "BrokenPipeError",
               "_AcpEarlyExitError", "RuntimeError", "ConnectionError")
    for attempt in range(6):
        client, log_path, _ = agy.make_client(prompt_delay=0.05)
        worker = _Worker(client)
        worker.start()
        time.sleep(random.uniform(0.02, 0.4))
        client.cancel()
        worker.join(timeout=10)
        assert not worker.is_alive(), f"attempt {attempt}: worker hung"
        if worker.error is not None:
            assert type(worker.error).__name__ in allowed, (
                f"attempt {attempt}: unexpected error {type(worker.error).__name__}: {worker.error!r}"
            )
        events = [e["event"] for e in _events(log_path)]
        assert events.count("prompt_received") <= 1, f"attempt {attempt}: retry amplification {events}"
    # attempts whose prompt completed park their process warm BY DESIGN;
    # drain the pool, then nothing may remain alive.
    agy.client_module._shutdown_warm_pool()
    assert agy.live_pids() == []


def test_timeout_leaves_no_live_child(agy):
    client, log_path, _ = agy.make_client(prompt_delay=30)
    worker = _Worker(client, timeout=1.5)
    worker.start()
    worker.join(timeout=15)
    assert not worker.is_alive()
    assert worker.error is not None and worker.result is None
    assert _wait_for(lambda: agy.live_pids() == [], timeout=5), (
        "a timed-out session must not leak a live child"
    )


# --- mux teardown (issue #23 AC: no orphaned official-server child) ------


def _mux_env(tmp_path: Path, tag: str, prompt_delay: float):
    home = tmp_path / "mux-home"
    (home / "lane").mkdir(parents=True, exist_ok=True)
    shim = tmp_path / f"{tag}_par_shim.py"
    shim.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"sys.argv = ['par', {str(tmp_path / f'{tag}_child.jsonl')!r},"
        f" {str(tmp_path / f'{tag}_child.pid')!r}, '{prompt_delay}', '0']\n"
        + FAKE_SERVER,
        encoding="utf-8")
    shim.chmod(0o755)
    env = dict(os.environ)
    env.update({
        "ACP_MUX_PAR": str(shim),
        "ACP_MUX_HOME": str(tmp_path / tag),
        "ACP_MUX_DEFAULT_HOME": str(home / "lane"),
        "ACP_MUX_STATE": str(tmp_path / f"{tag}_state.json"),
    })
    return env, Path(tmp_path / f"{tag}_child.jsonl"), Path(tmp_path / f"{tag}_child.pid")


def _start_mux(env):
    return subprocess.Popen(
        [sys.executable, str(MUX_ENTRYPOINT)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1, env=env)


def _send(mux, payload):
    mux.stdin.write(json.dumps(payload) + "\n")
    mux.stdin.flush()


@posix_only
def test_mux_sigterm_idle_child_exits_on_stdin_eof(tmp_path):
    """Idle mux + SIGTERM: the child must exit via stdin EOF, never a force-kill."""
    env, child_log, child_pid = _mux_env(tmp_path, "idle", prompt_delay=0)
    mux = _start_mux(env)
    _send(mux, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    _send(mux, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                "params": {"cwd": str(tmp_path), "mcpServers": []}})
    assert _wait_for(child_pid.exists)
    pid = int(child_pid.read_text())
    time.sleep(0.3)
    mux.send_signal(signal.SIGTERM)
    mux.wait(timeout=5)
    assert _wait_for(lambda: not _alive(pid), timeout=8), "the child must not be orphaned"
    events = [e["event"] for e in _events(child_log)]
    assert "stdin_eof_exit" in events, f"stdin-close teardown expected, got {events}"
    assert "sigterm" not in events, f"idle child must not be force-killed, got {events}"


@posix_only
def test_mux_sigterm_inflight_child_reaped_bounded(tmp_path):
    """SIGTERM to a mux with a prompt in flight must reap the child in bounded time."""
    env, child_log, child_pid = _mux_env(tmp_path, "inflight", prompt_delay=8)
    mux = _start_mux(env)
    _send(mux, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    _send(mux, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                "params": {"cwd": str(tmp_path), "mcpServers": []}})
    _send(mux, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
                "params": {"sessionId": "x", "prompt": [{"type": "text", "text": "slow"}]}})
    assert _wait_for(lambda: any(
        e["event"] == "prompt_received" for e in _events(child_log)), timeout=10)
    pid = int(child_pid.read_text())
    t0 = time.monotonic()
    mux.send_signal(signal.SIGTERM)
    mux.wait(timeout=5)
    assert _wait_for(lambda: not _alive(pid), timeout=6), (
        "the official-server child was orphaned: it outlived the mux by more than the"
        " bounded stdin-close -> terminate -> kill teardown window"
    )
    assert time.monotonic() - t0 < 6.0
    events = [e["event"] for e in _events(child_log)]
    assert "sigterm" in events, f"bounded escalation expected, got {events}"
    assert "prompt_answered" not in events, f"the abandoned prompt must not complete: {events}"


@posix_only
def test_mux_stdin_close_tears_down_inflight_child(tmp_path):
    """The graceful path (client closes the mux's stdin) already reaps cleanly."""
    env, child_log, child_pid = _mux_env(tmp_path, "stdinclose", prompt_delay=8)
    mux = _start_mux(env)
    _send(mux, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    _send(mux, {"jsonrpc": "2.0", "id": 2, "method": "session/new",
                "params": {"cwd": str(tmp_path), "mcpServers": []}})
    _send(mux, {"jsonrpc": "2.0", "id": 3, "method": "session/prompt",
                "params": {"sessionId": "x", "prompt": [{"type": "text", "text": "slow"}]}})
    assert _wait_for(lambda: any(
        e["event"] == "prompt_received" for e in _events(child_log)), timeout=10)
    pid = int(child_pid.read_text())
    mux.stdin.close()
    mux.wait(timeout=10)
    assert _wait_for(lambda: not _alive(pid), timeout=8)
    events = [e["event"] for e in _events(child_log)]
    assert "sigterm" in events and "prompt_answered" not in events
