#!/usr/bin/env python3
"""Trusted-fixture audit envelope around the unchanged public Hermes CLI entry point.

This is a Python audit boundary for trusted CI code, not a hostile-code sandbox.
No Core registry, factory, Gateway method or bootstrap is replaced.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import threading
import traceback

from gateway_docker import namespace_verified
from gateway_process_policy import PRUNE_BODY, scratch_command_verdict, shutdown_command_verified


def main() -> None:
    core, root, plugin = (Path(value).resolve(strict=True) for value in sys.argv[1:4])
    cli_argv = sys.argv[4:]
    receipt = root / ("contender-envelope.json" if os.environ.get("PHASE_C_CONTENDER") == "1" else "gateway-envelope.json")
    refused: list[str] = []
    owned_pids: dict[int, str] = {}
    owned_processes: list = []
    receipt_lock = threading.RLock()
    confined = namespace_verified()
    if not confined:
        raise PermissionError("verified_container_required")
    dependency_roots = [Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()]
    protected = [Path("/opt/data").resolve(), Path("/home/hermes").resolve()]
    allowed = [root, core, *dependency_roots]

    def path_of(value, dir_fd=None) -> Path | None:
        if isinstance(value, int) or value is None:
            return None
        path = Path(os.fsdecode(value))
        if not path.is_absolute() and isinstance(dir_fd, int) and dir_fd >= 0:
            path = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / path
        return path.resolve()

    def reject(reason: str) -> None:
        refused.append(reason)
        with (root / "audit-refusals.jsonl").open("a", encoding="utf-8") as stream:
            frames = [{"file": frame.filename, "line": frame.lineno, "function": frame.name}
                      for frame in traceback.extract_stack(limit=25)]
            stream.write(json.dumps({"reason": reason, "frames": frames}) + "\n")
        raise PermissionError("disposable_gateway_boundary")

    def audit(event: str, args: tuple) -> None:
        if event == "open":
            path = path_of(args[0])
            if path is None:
                return
            if path.is_relative_to(Path("/proc")):
                frame = sys._getframe(1)
                while frame is not None:
                    if (frame.f_code.co_name == "lineage_with_start_times"
                            and Path(frame.f_code.co_filename).resolve() == core / "hermes_constants_scratch.py"
                            and not confined):
                        reject("scratch_process_namespace_unverified")
                    frame = frame.f_back
            flags = args[2] if len(args) > 2 and isinstance(args[2], int) else 0
            writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            if writing and path != Path("/dev/null") and not path.is_relative_to(root):
                reject("write_outside_disposable_root")
            if not writing and any(path.is_relative_to(p) for p in protected) and not any(path.is_relative_to(p) for p in allowed):
                reject("operating_home_read")
        elif event in {"os.mkdir", "os.remove", "os.rmdir", "os.rename", "os.chmod"}:
            paths = [(args[0], args[2] if event in {"os.rename", "os.chmod"} and len(args) > 2 else args[1] if event in {"os.remove", "os.rmdir"} and len(args) > 1 else None)]
            if event == "os.rename":
                paths.append((args[1], args[3] if len(args) > 3 else None))
            for value, fd in paths:
                path = path_of(value, fd)
                if path is not None and not path.is_relative_to(root):
                    reject("mutation_outside_disposable_root")
        elif event in {"socket.connect", "socket.bind"}:
            address = args[1]
            if isinstance(address, tuple):
                if address[0] not in {"127.0.0.1", "::1"}:
                    reject("non_loopback_network")
            elif isinstance(address, (str, bytes)):
                path = path_of(address)
                if path is None or not path.is_relative_to(root):
                    reject("foreign_unix_socket")
        elif event == "socket.getaddrinfo":
            if args[0] not in {"127.0.0.1", "::1", "localhost", None}:
                reject("external_name_resolution")
        elif event == "subprocess.Popen":
            command = args[1]
            if not isinstance(command, (list, tuple)) or not command:
                reject("unapproved_subprocess")
            name = Path(os.fsdecode(command[0])).name
            if str(args[0]) != str(command[0]) or str(command[0]) != sys.executable and name != "git":
                if PRUNE_BODY not in command and name not in {"timeout", "gtimeout"}:
                    reject("subprocess_executable_mismatch")
            is_fixture = len(command) >= 3 and Path(str(command[1])).resolve() == root / "fake-acp.py" and str(command[2]) == str(root)
            git_args = list(command[1:])
            if len(git_args) >= 2 and git_args[0] == "-C" and Path(git_args[1]).resolve() == core:
                git_args = git_args[2:]
            is_readonly_git = name == "git" and bool(git_args) and git_args[0] in {"rev-parse", "describe", "status", "symbolic-ref", "log", "diff", "tag"}
            housekeeping = False
            if PRUNE_BODY in command:
                verdict = scratch_command_verdict(str(args[0]), command, root, core, sys.executable, sys.path)
                if verdict != "scratch_process_namespace_unverified" or not confined:
                    reject(verdict)
                housekeeping = True
            if name in {"timeout", "gtimeout"} and "bash" in command:
                if not confined or not shutdown_command_verified(str(args[0]), command, core, os.getpid()):
                    reject("shutdown_diagnostic_not_verified")
                housekeeping = True
            if not (is_fixture or is_readonly_git or housekeeping):
                reject("unapproved_subprocess")
        elif event in {"os.kill", "os.killpg"}:
            pid, signum = args
            if pid == os.getpid():
                return
            expected = owned_pids.get(pid)
            if expected is not None:
                try:
                    current = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
                except FileNotFoundError:
                    return  # let the original syscall report ESRCH; no live target exists
                if current == expected and (event == "os.kill" or os.getpgid(pid) == pid):
                    return
            if signum == 0:
                owner_record = root / "gateway-envelope.json"
                if owner_record.exists() and json.loads(owner_record.read_text()).get("pid") == pid:
                    return
            reject("foreign_or_reused_process_signal")
        elif event in {"os.system", "os.exec", "os.posix_spawn"}:
            reject("unapproved_process_launch")

    factory_hashes: set[str] = set()
    client_cancel_calls = 0

    def finish() -> None:
        with receipt_lock:
            bootstrap = sys.modules.get("hermes_bootstrap")
            origin = Path(getattr(bootstrap, "__file__", "")).resolve()
            value = {"pid": os.getpid(), "refusals": sorted(set(refused)),
                     "core_bootstrap_from_requested_source": origin == core / "hermes_bootstrap.py",
                     "loaded_provider_sha256": sorted(factory_hashes), "client_cancel_calls": client_cancel_calls,
                     "housekeeping": [{"kind": kind, "target": target, "returncode": process.poll()}
                                      for kind, target, process in owned_processes]}
            temporary = receipt.with_suffix(".tmp")
            temporary.write_text(json.dumps(value), encoding="utf-8")
            temporary.replace(receipt)

    def profile(frame, event, arg) -> None:
        nonlocal client_cancel_calls
        # Observe the ORIGINAL factory, including executor threads. No Core callable is replaced.
        # Core intentionally uses os._exit after its graceful drain, so atexit alone is insufficient.
        if (event == "return" and frame.f_code.co_name == "create_client"
                and Path(frame.f_code.co_filename).resolve() == plugin / "__init__.py" and arg is not None):
            factory_hashes.add(hashlib.sha256((plugin / "__init__.py").read_bytes()).hexdigest())
            finish()
        elif (event == "return" and frame.f_code.co_name == "cancel"
              and Path(frame.f_code.co_filename).resolve() == plugin / "client.py"):
            client_cancel_calls += 1
            finish()
        elif (event == "return" and frame.f_code.co_name == "__init__"
              and frame.f_globals.get("__name__") == "subprocess"):
            process = frame.f_locals.get("self")
            pid = getattr(process, "pid", None)
            if isinstance(pid, int):
                try:
                    started = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[22-3]
                except FileNotFoundError:
                    started = None
                command = getattr(process, "args", [])
                kind = "scratch" if PRUNE_BODY in command else "shutdown" if "bash" in command else "other"
                if kind != "other":
                    owned_processes.append((kind, str(command[5]) if kind == "scratch" else "", process))
                if started is not None:
                    owned_pids[pid] = started
                elif process.poll() is None:
                    reject("owned_child_identity_unavailable")
                with (root / "owned-core-children.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps({"pid": pid, "started": started, "exit_code": process.poll(), "kind": kind}) + "\n")
        elif event == "c_call" and arg is os._exit:
            finish()

    sys.addaudithook(audit)
    atexit.register(finish)
    sys.setprofile(profile)
    threading.setprofile(profile)
    sys.path.insert(0, str(core))
    sys.argv = [str(core / "hermes_cli" / "main.py"), *cli_argv]
    runpy.run_module("hermes_cli.main", run_name="__main__")


if __name__ == "__main__":
    main()
