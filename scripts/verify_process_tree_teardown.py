#!/usr/bin/env python3
"""Verify platform-guaranteed process-tree teardown on the host OS (issue #23).

Hosted-CI companion to tests/test_issue23_request_cancel.py::
test_terminate_process_tree_reaps_sigterm_ignoring_grandchild.  The Windows
install lanes do not run pytest, so this stdlib-only script runs the same
scenario directly: a python parent that spawns a python grandchild (both
ignore SIGTERM where the platform delivers it), then the plugin's
``terminate_process_tree()`` must reap BOTH processes — on Windows via the
``taskkill /T /F`` tree walk (``TerminateProcess`` reaches only the direct
child), on POSIX via the process-group kill.

Exit 0 with a JSON evidence line on success; non-zero with a reason otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEARDOWN_MODULE_PATH = HERE.parent / "hermes-plugin" / "antigravity-acp" / "process_teardown.py"

PARENT_SCRIPT = """
import os, signal, subprocess, sys, time
signal.signal(signal.SIGTERM, lambda *a: None)
child = subprocess.Popen([sys.executable, sys.argv[2], sys.argv[3]])
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    fh.write(str(os.getpid()))
child.wait()
"""

GRANDCHILD_SCRIPT = """
import os, signal, sys, time
signal.signal(signal.SIGTERM, lambda *a: None)
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    fh.write(str(os.getpid()))
time.sleep(120)
"""


def _load_teardown():
    spec = importlib.util.spec_from_file_location("acp_process_teardown", TEARDOWN_MODULE_PATH)
    assert spec is not None and spec.loader is not None, TEARDOWN_MODULE_PATH
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        # os.kill(pid, 0) TERMINATES the target on Windows — never use it here.
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def main() -> int:
    teardown = _load_teardown()
    work = Path(tempfile.mkdtemp(prefix="acp-tree-teardown-"))
    parent_pid = work / "parent.pid"
    grand_pid = work / "grand.pid"
    parent_script = work / "parent.py"
    grand_script = work / "grand.py"
    parent_script.write_text(PARENT_SCRIPT, encoding="utf-8")
    grand_script.write_text(GRANDCHILD_SCRIPT, encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, str(parent_script), str(parent_pid),
         str(grand_script), str(grand_pid)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
        # Same contract as the plugin's _spawn on POSIX.
        start_new_session=(os.name != "nt"))
    gpid = None
    try:
        if not _wait_for(lambda: parent_pid.exists() and grand_pid.exists(), 15):
            print("FAIL: tree processes never started", file=sys.stderr)
            return 1
        gpid = int(grand_pid.read_text())
        t0 = time.monotonic()
        teardown.terminate_process_tree(proc)
        parent_dead = _wait_for(lambda: not _pid_alive(proc.pid), 10)
        grand_dead = _wait_for(lambda: not _pid_alive(gpid), 10)
        elapsed = round(time.monotonic() - t0, 3)
        if not (parent_dead and grand_dead):
            print(
                f"FAIL: parent_dead={parent_dead} grandchild_dead={grand_dead} "
                f"after {elapsed}s (platform={os.name})",
                file=sys.stderr,
            )
            return 1
        print(json.dumps({
            "result": "PASS",
            "platform": os.name,
            "mechanism": "taskkill /T /F" if os.name == "nt" else "process-group kill",
            "parent_pid": proc.pid,
            "grandchild_pid": gpid,
            "elapsed_seconds": elapsed,
        }))
        return 0
    finally:
        teardown.terminate_process_tree(proc)
        if gpid is not None and _pid_alive(gpid):
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/T", "/F", "/PID", str(gpid)], capture_output=True)
            else:
                try:
                    os.kill(gpid, signal.SIGKILL)
                except OSError:
                    pass


if __name__ == "__main__":
    sys.exit(main())
