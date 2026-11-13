"""Probe cleanup regressions: real disposable wrapper/server, no vendor/accounts.

Also executable via unittest on native Windows without installing pytest into
Hermes' managed runtime. Pytest discovers the same cases on Linux.
"""
from __future__ import annotations

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "scripts/acp_probe.py"

SERVER = r'''
import ctypes, json, os, signal, sys, time
from pathlib import Path
root = Path(sys.argv[1])
# A native Windows no-delete-share handle models an installed running image
# lock. It is fixture-owned; the test never enumerates or kills foreign PIDs.
handle = None
if os.name == "nt":
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.CreateFileW.restype = ctypes.c_void_p
    handle = dll.CreateFileW(str(root / "locked.bin"), 0x80000000, 1, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error())
(root / "server.pid").write_text(str(os.getpid()))
request = json.loads(sys.stdin.readline())
if (root / "reply").exists():
    print(json.dumps({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":1}}), flush=True)
# Bounded fixture lifetime; stop file cleans pre-fix leaks without a PID kill.
deadline = time.monotonic() + 35
try:
    while time.monotonic() < deadline and not (root / "stop").exists():
        time.sleep(0.02)
finally:
    if handle is not None:
        dll.CloseHandle(ctypes.c_void_p(handle))
'''


def alive(pid):
    if os.name == "nt":
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
    status = Path(f"/proc/{pid}/stat")
    if sys.platform.startswith("linux") and status.exists():
        return status.read_text().split(")", 1)[1].split()[0] != "Z"
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def until(predicate, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class ProbeCleanupTests(unittest.TestCase):
    def run_wrapper(self, reply):
        with tempfile.TemporaryDirectory(prefix="acp-probe-owned-") as directory:
            root = Path(directory)
            (root / "server.py").write_text(SERVER, encoding="utf-8")
            (root / "locked.bin").write_bytes(b"fixture-only")
            if reply:
                (root / "reply").touch()
            if os.name == "nt":
                wrapper = root / "wrapper.cmd"
                wrapper.write_text(f'@echo off\n"{sys.executable}" "{root / "server.py"}" "{root}"\n', encoding="utf-8")
                command = [str(wrapper)]
            else:
                import shlex
                wrapper = root / "wrapper.sh"
                wrapper.write_text("#!/bin/sh\n" + " ".join(shlex.quote(s) for s in (sys.executable, str(root / "server.py"), str(root))) + "\n", encoding="utf-8")
                wrapper.chmod(0o700)
                command = [str(wrapper)]
            try:
                result = subprocess.run([sys.executable, str(PROBE), "--timeout", "5", "--", *command], capture_output=True, text=True, timeout=30)
                self.assertTrue((root / "server.pid").is_file(), "native server fixture must have executed")
                pid = int((root / "server.pid").read_text())
                self.assertTrue(until(lambda: not alive(pid), 2), "probe left its owned server alive behind the wrapper")
                if reply:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(json.loads(result.stdout)["protocolVersion"], 1)
                else:
                    self.assertNotEqual(result.returncode, 0)
                # Native Windows removal fails while the owned server's handle
                # is live; POSIX also exercises the identical lifecycle action.
                (root / "locked.bin").unlink()
            finally:
                (root / "stop").touch()
                if (root / "server.pid").is_file():
                    pid = int((root / "server.pid").read_text())
                    self.assertTrue(until(lambda: not alive(pid), 5), "fixture did not close after its stop signal")

    def test_initialize_reaps_owned_wrapper_tree_and_releases_file(self):
        self.run_wrapper(True)

    def test_timeout_also_reaps_owned_wrapper_tree(self):
        self.run_wrapper(False)

    def test_unverified_cleanup_cannot_report_initialize_success(self):
        spec = importlib.util.spec_from_file_location("probe_cleanup_contract", PROBE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # None/False tree results must fail closed even after initialize.
        for verified in (None, False):
            with self.subTest(verified=verified):
                with patch.object(module, "terminate_process_tree", create=True, return_value=verified):
                    proc = Mock()
                    proc.stdin = Mock()
                    response = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": 1}}) + "\n"
                    proc.stdout = iter([response])
                    proc.stderr = iter([])
                    with patch.object(module.subprocess, "Popen", return_value=proc), patch.object(sys, "argv", ["probe", "--", "fake"]):
                        with self.assertRaises(RuntimeError):
                            module.main()


if __name__ == "__main__":
    unittest.main()
