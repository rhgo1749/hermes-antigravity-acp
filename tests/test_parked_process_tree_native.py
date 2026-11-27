"""Native OS & stdlib-only Parked-ACP process-tree teardown regressions (Issue #94 / F-3).

Runs via ``python -m unittest discover -s tests -p test_parked_process_tree_native.py -v``
(without pytest, matching Windows/macOS/Linux-arm64 CI) and pytest auto-discovery.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp" / "parked"


def _bootstrap_package() -> None:
    existing = sys.modules.get("antigravity_acp_mcp")
    if existing is not None and str(PLUGIN_DIR) in list(getattr(existing, "__path__", ())):
        return
    pkg = types.ModuleType("antigravity_acp_mcp")
    pkg.__file__ = str(PLUGIN_DIR / "__init__.py")
    pkg.__path__ = [str(PLUGIN_DIR)]
    pkg.__package__ = "antigravity_acp_mcp"
    sys.modules["antigravity_acp_mcp"] = pkg


_bootstrap_package()

import antigravity_acp_mcp.acp_connection as acp_connection_mod  # noqa: E402
from antigravity_acp_mcp.acp_connection import AcpConnection, AcpProcessExit  # noqa: E402

_FIXTURE_SCRIPT = r"""
import json, os, signal, subprocess, sys, time
from pathlib import Path

def _w(p):
    t = p.with_suffix(".tmp")
    t.write_text(str(os.getpid()), encoding="utf-8")
    t.replace(p)

def _wait(stop, secs):
    end = time.monotonic() + secs
    while time.monotonic() < end and not stop.exists():
        time.sleep(0.02)

def run_gc(sdir, cfg):
    if cfg.get("ignore_sigterm") and hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    _w(sdir / "grandchild.pid")
    _wait(sdir / "stop", float(cfg.get("max_seconds", 30.0)))

def run_child(sdir, cfg):
    if cfg.get("ignore_sigterm") and hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    _w(sdir / "child.pid")
    out = subprocess.DEVNULL if cfg.get("detach_descendant_stdout") else None
    subprocess.Popen(
        [sys.executable, __file__, "gc", str(sdir), json.dumps(cfg)],
        stdin=subprocess.DEVNULL,
        stdout=out,
        stderr=None,
    )
    if cfg.get("stall_stdin"):
        _wait(sdir / "stop", float(cfg.get("max_seconds", 30.0)))
        return
    if cfg.get("close_stdout_then_wait"):
        sys.stdout.close()
        _wait(sdir / "stop", float(cfg.get("max_seconds", 30.0)))
        return
    for raw in sys.stdin:
        msg = json.loads(raw)
        rid, m = msg.get("id"), msg.get("method")
        if rid is None:
            continue
        if m == "initialize":
            if cfg.get("fail_init_after_spawn"):
                end = time.monotonic() + 10.0
                while time.monotonic() < end and not (sdir / "grandchild.pid").is_file():
                    time.sleep(0.01)
                sys.exit(int(cfg.get("init_exit_code", 5)))
            if cfg.get("hang_init"):
                _wait(sdir / "stop", float(cfg.get("max_seconds", 30.0)))
                return
            res = {"protocolVersion": 1, "agentCapabilities": {}}
        elif m == "session/new":
            if cfg.get("fail_session_new"):
                sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "new failed"}}) + "\n")
                sys.stdout.flush()
                continue
            res = {"sessionId": "s-wrap-1", "models": {"availableModels": [{"modelId": "fake-model-a"}]}}
        elif m == "session/prompt":
            if cfg.get("hang_prompt"):
                _wait(sdir / "stop", float(cfg.get("max_seconds", 30.0)))
                return
            sid = (msg.get("params") or {}).get("sessionId", "s-wrap-1")
            sys.stdout.write(
                json.dumps({
                    "jsonrpc": "2.0",
                    "method": "session/update",
                    "params": {"sessionId": sid, "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "ok"}}},
                }) + "\n"
            )
            sys.stdout.flush()
            res = {"stopReason": "end_turn"}
        else:
            res = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}) + "\n")
        sys.stdout.flush()

def run_wrapper(sdir, cfg):
    _w(sdir / "wrapper.pid")
    out = subprocess.DEVNULL if cfg.get("detach_descendant_stdout") else None
    child = subprocess.Popen(
        [sys.executable, __file__, "child", str(sdir), json.dumps(cfg)],
        stdin=None,
        stdout=out,
        stderr=None,
    )
    if cfg.get("wrapper_exits_early"):
        end = time.monotonic() + 10.0
        while time.monotonic() < end and not (sdir / "grandchild.pid").is_file():
            time.sleep(0.01)
        sys.stderr.write("wrapper-exited-before-descendant\n")
        sys.stderr.flush()
        sys.exit(int(cfg.get("wrapper_exit_code", 0)))
    sys.exit(child.wait())

if __name__ == "__main__":
    {"wrapper": run_wrapper, "child": run_child, "gc": run_gc}[sys.argv[1]](Path(sys.argv[2]), json.loads(sys.argv[3]))
"""


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        import ctypes

        dll = ctypes.WinDLL("kernel32", use_last_error=True)
        dll.OpenProcess.restype = ctypes.c_void_p
        handle = dll.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not dll.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(code)):
                raise OSError(ctypes.get_last_error())
            return code.value == 259
        finally:
            dll.CloseHandle(ctypes.c_void_p(handle))
    stat_path = Path(f"/proc/{pid}/stat")
    if sys.platform.startswith("linux") and stat_path.exists():
        try:
            return stat_path.read_text(encoding="utf-8").split(")", 1)[1].split()[0] != "Z"
        except OSError:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait_until(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return bool(predicate())


def _read_pid(path: Path, timeout: float = 10.0) -> int:
    if not _wait_until(path.is_file, timeout=timeout):
        raise AssertionError(f"missing pid file: {path}")
    return int(path.read_text(encoding="utf-8").strip())


def _write_fixture(root: Path, name: str, cfg: dict) -> tuple[Path, Path, str, list[str]]:
    state_dir = root / name
    state_dir.mkdir(parents=True, exist_ok=True)
    script = root / "tree_fixture.py"
    if not script.exists():
        script.write_text(_FIXTURE_SCRIPT, encoding="utf-8")
    cfg_json = json.dumps(cfg)
    if cfg.get("shell_wrapper"):
        if os.name == "nt":
            wrapper = state_dir / "wrapper.cmd"
            wrapper.write_text(
                f'@echo off\r\n"{sys.executable}" "{script}" wrapper "{state_dir}" {subprocess.list2cmdline([cfg_json])}\r\n',
                encoding="utf-8",
            )
            return state_dir, script, str(wrapper), []
        wrapper = state_dir / "wrapper.sh"
        wrapper.write_text(
            "#!/bin/sh\n" + " ".join(shlex.quote(x) for x in (sys.executable, str(script), "wrapper", str(state_dir), cfg_json)) + "\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o700)
        return state_dir, script, str(wrapper), []
    return state_dir, script, sys.executable, [str(script), "wrapper", str(state_dir), cfg_json]


def _close_proc_streams(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    for st in (proc.stdin, proc.stdout, proc.stderr):
        if st is not None:
            with contextlib.suppress(OSError):
                st.close()


def _cleanup_state(state_dir: Path, pids: list[int], proc: subprocess.Popen | None = None) -> None:
    with contextlib.suppress(OSError):
        (state_dir / "stop").write_text("stop", encoding="utf-8")
    if not _wait_until(lambda: all(not _pid_alive(p) for p in pids), timeout=5.0):
        for pid in pids:
            if _pid_alive(pid):
                if os.name == "nt":
                    with contextlib.suppress(Exception):
                        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)], capture_output=True, timeout=10)
                else:
                    with contextlib.suppress(OSError):
                        os.kill(pid, 9)
        _wait_until(lambda: all(not _pid_alive(p) for p in pids), timeout=5.0)
    if proc is not None:
        with contextlib.suppress(Exception):
            proc.wait(timeout=2.0)
        _close_proc_streams(proc)


def _tree_pids(state_dir: Path) -> list[int]:
    return [_read_pid(state_dir / f"{n}.pid") for n in ("wrapper", "child", "grandchild")]


class ParkedProcessTreeNativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="acp-parked-tree-native-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_live_wrapper_tree_concurrent_close_reaps_once_and_verifies(self) -> None:
        state_dir, _, cmd, args = _write_fixture(self.root, "live_close", {"ignore_sigterm": True, "shell_wrapper": True})
        cwd = self.root / "cwd_live"
        cwd.mkdir()
        calls: list[int] = []
        orig_td = acp_connection_mod._process_teardown.terminate_process_tree
        conn = AcpConnection(cmd, args, str(cwd))
        pids: list[int] = []
        try:
            with patch.object(
                acp_connection_mod._process_teardown,
                "terminate_process_tree",
                side_effect=lambda proc, **kw: (calls.append(proc.pid), orig_td(proc, **kw))[-1],
            ):
                conn.start()
                conn.initialize(timeout=15)
                pids = _tree_pids(state_dir)
                self.assertTrue(all(_pid_alive(p) for p in pids))
                barrier, results, lock = threading.Barrier(4), [], threading.Lock()

                def _w() -> None:
                    barrier.wait()
                    out = conn.close()
                    with lock:
                        results.append(out)

                workers = [threading.Thread(target=_w) for _ in range(4)]
                for w in workers:
                    w.start()
                for w in workers:
                    w.join(timeout=10.0)
                self.assertTrue(all(not w.is_alive() for w in workers))
                self.assertEqual(results, [True, True, True, True])
                self.assertIs(conn.close(), True)
                self.assertIs(conn.teardown_verified, True)
                self.assertEqual(len(calls), 1)
                self.assertTrue(_wait_until(lambda: all(not _pid_alive(p) for p in pids), timeout=5.0))
        finally:
            with contextlib.suppress(Exception):
                conn.close()
            _cleanup_state(state_dir, pids, conn._proc)

    def test_close_with_stalled_stdin_writer_bounds_and_marks_unverified(self) -> None:
        s1, _, cmd1, args1 = _write_fixture(self.root, "stall", {"stall_stdin": True, "detach_descendant_stdout": True})
        cwd1 = self.root / "cwd_stall"
        cwd1.mkdir()
        conn1 = AcpConnection(cmd1, args1, str(cwd1))
        pids1, w_start, w_done = [], threading.Event(), threading.Event()

        def _stall() -> None:
            try:
                w_start.set()
                payload = {"jsonrpc": "2.0", "method": "x/flood", "params": {"blob": "A" * 131072}}
                for _ in range(64):
                    conn1._send(payload)
            except (OSError, ValueError):
                pass
            finally:
                w_done.set()

        try:
            conn1.start()
            pids1 = _tree_pids(s1)
            threading.Thread(target=_stall, daemon=True).start()
            self.assertTrue(w_start.wait(timeout=2.0))
            self.assertTrue(_wait_until(lambda: conn1._write_lock.locked(), timeout=5.0))
            with patch.object(conn1, "_terminate_owned_tree", return_value=None):
                t0 = time.monotonic()
                res = conn1.close()
                self.assertLess(time.monotonic() - t0, 4.0)
            self.assertIsNone(res)
            self.assertIsNone(conn1.teardown_verified)
            t1 = time.monotonic()
            self.assertIsNone(conn1.close())
            self.assertLess(time.monotonic() - t1, 0.5)
        finally:
            _cleanup_state(s1, pids1, conn1._proc)
            w_done.wait(timeout=5.0)
            with contextlib.suppress(Exception):
                acp_connection_mod._process_teardown.terminate_process_tree(conn1._proc, graceful_stdin=False)
            with contextlib.suppress(Exception):
                conn1.close()

        s2, _, cmd2, args2 = _write_fixture(self.root, "skip_stdin", {"hang_init": True})
        cwd2 = self.root / "cwd_skip"
        cwd2.mkdir()
        conn2, pids2 = AcpConnection(cmd2, args2, str(cwd2)), []
        try:
            conn2.start()
            pids2 = _tree_pids(s2)
            conn2._write_lock.acquire()
            try:
                t0 = time.monotonic()
                res2 = conn2.close()
                self.assertLess(time.monotonic() - t0, 4.0)
            finally:
                conn2._write_lock.release()
            self.assertIs(res2, False)
            self.assertIs(conn2.teardown_verified, False)
        finally:
            with contextlib.suppress(Exception):
                conn2.close()
            _cleanup_state(s2, pids2, conn2._proc)

    def test_terminate_windows_taskkill_fallback_kills_direct_child_and_never_verifies(self) -> None:
        teardown = acp_connection_mod._process_teardown
        for mode, mock_kw in (
            ("timeout", {"side_effect": subprocess.TimeoutExpired(["taskkill"], 15)}),
            ("nonzero", {"return_value": subprocess.CompletedProcess(["taskkill"], 1, b"", b"denied")}),
            ("zero_but_alive", {"return_value": subprocess.CompletedProcess(["taskkill"], 0, b"", b"")}),
        ):
            with self.subTest(mode=mode):
                proc = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    with patch.object(teardown.subprocess, "run", **mock_kw):
                        res = teardown._terminate_windows(proc, graceful_stdin=False, graceful_timeout=0.1, kill_timeout=0.5)
                    self.assertIsNotNone(proc.poll())
                    self.assertIs(res, False if mode == "zero_but_alive" else None)
                finally:
                    if proc.poll() is None:
                        with contextlib.suppress(OSError):
                            proc.kill()
                        with contextlib.suppress(Exception):
                            proc.wait(timeout=3.0)
                    _close_proc_streams(proc)

    @unittest.skipUnless(os.name == "nt", "Windows native dead-parent boundary check")
    def test_windows_dead_parent_unblocks_pending_request_without_claiming_verified(self) -> None:
        sdir, _, cmd, args = _write_fixture(self.root, "win_dead", {"wrapper_exits_early": True, "wrapper_exit_code": 7, "hang_init": True})
        cwd = self.root / "cwd_win_dead"
        cwd.mkdir()
        conn, pids = AcpConnection(cmd, args, str(cwd)), []
        try:
            conn.start()
            pids = _tree_pids(sdir)
            t0 = time.monotonic()
            with self.assertRaises(AcpProcessExit) as ctx:
                conn.initialize(timeout=6.0)
            self.assertLess(time.monotonic() - t0, 4.0)
            self.assertEqual(ctx.exception.exit_status, 7)
            self.assertTrue(conn.exited)
            self.assertIsNone(conn.teardown_verified)
            self.assertIsNone(conn.close())
        finally:
            with contextlib.suppress(Exception):
                conn.close()
            _cleanup_state(sdir, pids, conn._proc)

    @unittest.skipIf(os.name == "nt", "POSIX early exit & waitid fallback boundary")
    def test_posix_early_exit_inherited_stdout_waitid_active_and_fallback(self) -> None:
        teardown = acp_connection_mod._process_teardown
        orig_enabled, orig_killpg = teardown._non_reaping_enabled, teardown.os.killpg
        try:
            for case, code, runtime_fail, disable in (
                ("waitid_active", 9, False, False),
                ("disabled_before_start", 13, False, True),
                ("runtime_enosys", 17, True, False),
            ):
                with self.subTest(case=case):
                    sdir, _, cmd, args = _write_fixture(
                        self.root,
                        f"posix_{case}",
                        {"wrapper_exits_early": True, "wrapper_exit_code": code, "hang_init": True, "ignore_sigterm": True},
                    )
                    cwd = self.root / f"cwd_{case}"
                    cwd.mkdir()
                    teardown._non_reaping_enabled = not disable
                    conn, pids, killpg_calls = AcpConnection(cmd, args, str(cwd)), [], []
                    waitid_ctx = (
                        patch.object(teardown.os, "waitid", side_effect=OSError(errno.ENOSYS, "ENOSYS"))
                        if runtime_fail
                        else contextlib.nullcontext()
                    )
                    try:
                        with waitid_ctx, patch.object(
                            teardown.os,
                            "killpg",
                            side_effect=lambda p, s: (killpg_calls.append((p, s)), orig_killpg(p, s))[-1],
                        ):
                            conn.start()
                            pids = _tree_pids(sdir)
                            t0 = time.monotonic()
                            with self.assertRaises(AcpProcessExit) as ctx:
                                conn.initialize(timeout=6.0)
                            self.assertLess(time.monotonic() - t0, 4.0)
                        self.assertEqual(ctx.exception.exit_status, code)
                        self.assertTrue(conn.exited)
                        if case == "waitid_active":
                            self.assertIs(conn.teardown_verified, True)
                            self.assertTrue(_wait_until(lambda: all(not _pid_alive(p) for p in pids), timeout=5.0))
                            self.assertTrue(_wait_until(lambda: all(not t.is_alive() for t in conn._threads), timeout=2.0))
                        else:
                            self.assertFalse(teardown._non_reaping_enabled)
                            self.assertIsNone(conn.teardown_verified)
                            self.assertEqual(killpg_calls, [])
                            self.assertIsNone(conn.close())
                    finally:
                        with contextlib.suppress(Exception):
                            conn.close()
                        _cleanup_state(sdir, pids, conn._proc)
        finally:
            teardown._non_reaping_enabled = orig_enabled

    @unittest.skipIf(os.name == "nt", "POSIX zombie ownership & PID reuse guard")
    def test_posix_zombie_ownership_and_pid_reuse_guards(self) -> None:
        teardown = acp_connection_mod._process_teardown
        orig_enabled, orig_getpgid, orig_killpg = teardown._non_reaping_enabled, teardown.os.getpgid, teardown.os.killpg
        try:
            for case in (
                "zombie_recover",
                "waitid_disabled",
                "raw_waitpid",
                "pid_reuse",
                "waitid_disabled_pid_reuse",
                "foreign_pgid",
            ):
                with self.subTest(case=case):
                    teardown._non_reaping_enabled = True
                    sdir, script, _, _ = _write_fixture(self.root, f"z_{case}", {"ignore_sigterm": True})
                    proc = subprocess.Popen(
                        [sys.executable, str(script), "wrapper", str(sdir), json.dumps({"max_seconds": 30.0})],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        start_new_session=(case != "foreign_pgid"),
                    )
                    pids, killpg_calls = [], []
                    try:
                        pids = _tree_pids(sdir)
                        if case != "foreign_pgid":
                            proc.kill()
                            if case in ("raw_waitpid", "pid_reuse", "waitid_disabled_pid_reuse"):
                                os.waitpid(proc.pid, 0)
                            else:
                                self.assertTrue(_wait_until(lambda: teardown.proc_dead_unreaped(proc), timeout=5.0))
                        if case in ("waitid_disabled", "waitid_disabled_pid_reuse"):
                            teardown._non_reaping_enabled = False

                        def _fake_getpgid(pid: int) -> int:
                            if pid == proc.pid and case in ("zombie_recover", "waitid_disabled"):
                                raise ProcessLookupError(errno.ESRCH, "ESRCH")
                            if pid == proc.pid and case in ("pid_reuse", "waitid_disabled_pid_reuse"):
                                return proc.pid
                            return orig_getpgid(pid)

                        with patch.object(teardown.os, "getpgid", side_effect=_fake_getpgid), patch.object(
                            teardown.os,
                            "killpg",
                            side_effect=lambda p, s: (killpg_calls.append((p, s)), orig_killpg(p, s))[-1],
                        ):
                            conn = AcpConnection(sys.executable, [], str(self.root))
                            conn._proc, conn._spawned_session_leader = proc, True
                            res = conn._terminate_owned_tree(proc)

                        if case == "zombie_recover":
                            self.assertIs(res, True)
                            self.assertTrue(_wait_until(lambda: all(not _pid_alive(p) for p in pids), timeout=5.0))
                        else:
                            self.assertIsNone(res)
                            self.assertEqual(killpg_calls, [])
                            self.assertTrue(_pid_alive(pids[-1]))
                    finally:
                        with contextlib.suppress(Exception):
                            if proc.poll() is None and case not in ("raw_waitpid", "pid_reuse", "waitid_disabled_pid_reuse"):
                                proc.kill()
                        _cleanup_state(sdir, pids, proc)
        finally:
            teardown._non_reaping_enabled = orig_enabled

    def test_close_fails_pending_rpcs_and_preserves_on_response_race(self) -> None:
        sdir, _, cmd, args = _write_fixture(self.root, "close_race", {"hang_init": True})
        cwd = self.root / "cwd_race"
        cwd.mkdir()
        conn, pids = AcpConnection(cmd, args, str(cwd)), []
        on_resp_entered, on_resp_release, on_resp_calls = threading.Event(), threading.Event(), []
        res_ok, err_fail, err_during = [], [], []
        done_ok, done_fail, done_during = threading.Event(), threading.Event(), threading.Event()

        def _req(fn, out, ev) -> None:
            try:
                out.append(fn())
            except BaseException as exc:  # noqa: BLE001
                out.append(exc)
            finally:
                ev.set()

        try:
            conn.start()
            pids = _tree_pids(sdir)
            threading.Thread(
                target=_req,
                args=(
                    lambda: conn.request(
                        "x/fast",
                        {},
                        timeout=None,
                        on_response=lambda: (on_resp_calls.append(1), on_resp_entered.set(), on_resp_release.wait(3.0)),
                    ),
                    res_ok,
                    done_ok,
                ),
                daemon=True,
            ).start()
            self.assertTrue(on_resp_entered.wait(timeout=5.0))
            threading.Thread(target=_req, args=(lambda: conn.initialize(timeout=None), err_fail, done_fail), daemon=True).start()
            self.assertTrue(_wait_until(lambda: bool(conn._pending), timeout=5.0))
            pending_rid = next(iter(conn._pending))
            td_entered, td_release, exit_errs, orig_exit = (
                threading.Event(),
                threading.Event(),
                [],
                acp_connection_mod.AcpProcessExit,
            )
            close_th = threading.Thread(target=conn.close, daemon=True)
            with patch.object(
                conn, "_terminate_owned_tree", side_effect=lambda _p, **_k: (td_entered.set(), td_release.wait(3.0), None)[-1]
            ), patch.object(
                acp_connection_mod,
                "AcpProcessExit",
                side_effect=lambda *a, **kw: (exit_errs.append(orig_exit(*a, **kw)), exit_errs[-1])[-1],
            ):
                close_th.start()
                self.assertTrue(td_entered.wait(timeout=3.0))
                threading.Thread(
                    target=_req,
                    args=(lambda: conn.request("x/during", {}, timeout=5.0), err_during, done_during),
                    daemon=True,
                ).start()
                on_resp_release.set()
                td_release.set()
                close_th.join(timeout=4.0)
                self.assertFalse(close_th.is_alive())
            self.assertTrue(done_ok.wait(2.0) and done_fail.wait(2.0) and done_during.wait(2.0))
            self.assertEqual(res_ok, [{}])
            self.assertIsInstance(err_fail[0], AcpProcessExit)
            self.assertIsInstance(err_during[0], AcpProcessExit)
            conn._dispatch({"jsonrpc": "2.0", "id": pending_rid, "result": {"late": True}})
            self.assertEqual(on_resp_calls, [1])
            self.assertEqual(len(exit_errs), 1)
            self.assertTrue(conn._exit_finalized and conn.exited)
            t1 = time.monotonic()
            with self.assertRaises(AcpProcessExit):
                conn.request("x/after", {}, timeout=5.0)
            self.assertLess(time.monotonic() - t1, 0.5)
            self.assertIsNone(conn.close())
        finally:
            on_resp_release.set()
            _cleanup_state(sdir, pids, conn._proc)
            for t in conn._threads:
                t.join(timeout=2.0)
            with contextlib.suppress(Exception):
                conn.close()


if __name__ == "__main__":
    unittest.main()
