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
from gateway_process_policy import (BASELINE_ENV, PRUNE_BODY, git_probe_context_verdict,
                                    mismatch_diagnostic, readonly_git_verdict, scratch_command_verdict,
                                    shutdown_command_verified)
from provider_origin import ProviderOrigin

# Engine-aware factory/client sources: since 0.9.0 the default Parked-MCP engine ships from
# parked/ while the Replay engine keeps the top-level modules. Order is irrelevant;
# ProviderOrigin.accepts() rejects non-matching paths without recording an error.
_FACTORY_SOURCES = ("parked/_plugin_entry.py", "__init__.py")
_CLIENT_SOURCES = ("parked/client.py", "client.py")


def _proc_start_time(pid: int) -> str:
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[22 - 3]


class _ChildIdentityUnavailable(Exception):
    """A live child has no readable /proc start identity to bind signals to."""


class _ChildLedger:
    """Child-process bookkeeping, separated from subprocess admission.

    Admission is the audit hook's decision alone: it verifies a housekeeping
    launch end to end and only then notes a one-shot token here. Observation is
    the profile hook's job: a child becomes housekeeping receipt evidence only
    by consuming a token the audit hook actually verified. Presence of
    PRUNE_BODY or "bash" in a command never classifies a child by itself, so a
    launch admission never verified cannot forge scratch/shutdown PASS evidence
    into the receipt. Every admitted launch still gets start-identity tracking
    for signal authorization and an owned-core-children.jsonl observation line.
    """

    def __init__(self, root: Path, start_time=_proc_start_time) -> None:
        self.root = root
        self.owned_pids: dict[int, str] = {}
        self.owned_processes: list = []
        self._start_time = start_time
        # One pending verdict per thread: the audit hook writes it for the launch it is
        # deciding on, and the profile hook consumes it when that child actually exists.
        # A shared list of tokens outlives a Popen that raised and then authorizes some
        # later child that merely carries the same argv.
        self._pending = threading.local()

    @staticmethod
    def _key(command) -> tuple:
        try:
            return tuple(os.fsdecode(value) for value in command)
        except TypeError:
            return ()

    def begin_launch_attempt(self) -> None:
        """Called by the audit hook for every admitted Popen, before any verdict is made.

        Clearing is the whole point: a launch that failed to spawn cannot leave a token
        behind, because the next attempt on this thread clears the slot before its own
        child can be observed.
        """
        self._pending.slot = None
        self._pending.refused_before_spawn = False

    def note_refused_before_spawn(self) -> None:
        """Remember a refusal raised inside the Popen audit event, before OS spawn."""
        self._pending.refused_before_spawn = True

    def note_verified_launch(self, kind: str, command) -> None:
        """Called by the audit hook only after a full housekeeping verdict passed."""
        self._pending.slot = (kind, self._key(command))

    def classify(self, command) -> tuple[str, str]:
        """Consume this thread's pending verdict; command membership alone is never housekeeping."""
        slot = getattr(self._pending, "slot", None)
        self._pending.slot = None
        key = self._key(command)
        if slot is None or not key or slot[1] != key:
            return "other", ""
        return slot[0], key[5] if slot[0] == "scratch" else ""

    def observe(self, process):
        """Record one admitted child: start identity, verified classification, evidence line."""
        if not hasattr(process, "poll"):
            return None
        pid = getattr(process, "pid", None)
        refused = getattr(self._pending, "refused_before_spawn", False)
        self._pending.refused_before_spawn = False
        if (refused and pid is None and getattr(process, "_child_created", None) is False):
            # CPython profiles an exception exit from Popen.__init__ as a return. An
            # audit-hook refusal happened before spawn, so there is no child to track;
            # the original sticky boundary refusal remains intact.
            self._pending.slot = None
            return None
        if not isinstance(pid, int) or pid <= 0:
            # An admitted child we cannot name never reaches the driver's cleanup pid set,
            # so a live one would leave child_cleanup PASSing over a smaller set than the
            # fixture actually owns. Refusing is the only honest outcome.
            raise _ChildIdentityUnavailable
        try:
            started = self._start_time(pid)
        except OSError:
            # /proc can fail with EPERM/EINVAL or a hidepid mount, not only ENOENT. Only
            # _ChildIdentityUnavailable becomes a recorded boundary refusal; any other type
            # would escape through the Gateway's own Popen.__init__ and corrupt that launch.
            started = None
        kind, target = self.classify(getattr(process, "args", []))
        if kind != "other":
            self.owned_processes.append((kind, target, process))
        if started is not None:
            self.owned_pids[pid] = started
        elif process.poll() is None:
            raise _ChildIdentityUnavailable
        record = {"pid": pid, "started": started, "exit_code": process.poll(), "kind": kind}
        with (self.root / "owned-core-children.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")
        return record

    def housekeeping(self) -> list:
        return [{"kind": kind, "target": target, "returncode": process.poll()}
                for kind, target, process in self.owned_processes]


def main() -> None:
    core, root, plugin = (Path(value).resolve(strict=True) for value in sys.argv[1:4])
    cli_argv = sys.argv[4:]
    receipt = root / ("contender-envelope.json" if os.environ.get("PHASE_C_CONTENDER") == "1" else "gateway-envelope.json")
    refused: list[str] = []
    ledger = _ChildLedger(root)
    receipt_lock = threading.RLock()
    confined = namespace_verified()
    if not confined:
        raise PermissionError("verified_container_required")
    provider_origin = ProviderOrigin(plugin, plugin.parents[2], core, owned_root=root)
    dependency_roots = [Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()]
    # The live Hermes home is env-pinned via HERMES_HOME (standard ~/.hermes fallback).
    hermes_home = Path(os.environ.get("HERMES_HOME") or (Path.home() / ".hermes")).resolve()
    protected = [hermes_home, Path.home().resolve()]
    allowed = [root, core, *dependency_roots]

    def path_of(value, dir_fd=None) -> Path | None:
        if isinstance(value, int) or value is None:
            return None
        path = Path(os.fsdecode(value))
        if not path.is_absolute() and isinstance(dir_fd, int) and dir_fd >= 0:
            path = Path(os.readlink(f"/proc/self/fd/{dir_fd}")) / path
        return path.resolve()

    def reject(reason: str, launch=None) -> None:
        refused.append(reason)
        with (root / "audit-refusals.jsonl").open("a", encoding="utf-8") as stream:
            stack = traceback.extract_stack(limit=25)
            frames = [{"file": frame.filename, "line": frame.lineno, "function": frame.name} for frame in stack]
            event = {"reason": reason, "frames": frames}
            if launch is not None:
                diagnostic = mismatch_diagnostic(launch[0], launch[1][0], sys.executable, core, stack, launch[1])
                if launch[2]:
                    diagnostic = ("systemctl_block_" + launch[2], diagnostic[1], diagnostic[2])
                event["diagnostic"] = diagnostic
                stream.write(json.dumps(event) + "\n")
                for category in sorted(launch[3]):
                    stream.write(json.dumps({"reason": reason,
                                             "diagnostic": (category, diagnostic[1], diagnostic[2])}) + "\n")
            else:
                stream.write(json.dumps(event) + "\n")
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
            # CPython supplies -1 when mkdir has no dir_fd; never resolve a
            # dir_fd-relative mkdir against the unrelated current directory.
            if event == "os.mkdir" and (len(args) != 3 or type(args[2]) is not int or args[2] != -1):
                reject("mutation_outside_disposable_root")
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
            # A rejection at this audit event is before CPython's OS spawn. Record
            # that fact separately from the sticky refusal so the profile callback
            # does not mistake the failed initializer for an untracked live child.
            ledger.begin_launch_attempt()

            def reject_launch(reason: str, launch=None) -> None:
                ledger.note_refused_before_spawn()
                reject(reason, launch)

            command = args[1]
            if not isinstance(command, (list, tuple)) or not command:
                reject_launch("unapproved_subprocess")
            name = Path(os.fsdecode(command[0])).name
            # systemctl is never admitted; a verified read-only mask makes it
            # absent from Core's lookup before this envelope starts.
            if str(args[0]) != str(command[0]) or str(command[0]) != sys.executable and name != "git":
                if PRUNE_BODY not in command and name not in {"timeout", "gtimeout"}:
                    reject_launch("subprocess_executable_mismatch", (args[0], command, "", set()))
            is_fixture = len(command) >= 3 and Path(str(command[1])).resolve() == root / "fake-acp.py" and str(command[2]) == str(root)
            # argv shape alone cannot make a git child read-only: the binary PATH resolves,
            # the repository the launch cwd selects, and the configuration the child inherits
            # are decided here, not in argv.
            is_readonly_git = readonly_git_verdict(command, core) and git_probe_context_verdict(
                command, core, args[2] if len(args) > 2 else None,
                args[3] if len(args) > 3 else None, BASELINE_ENV) == ""
            housekeeping = False
            if PRUNE_BODY in command:
                verdict = scratch_command_verdict(str(args[0]), command, root, core, sys.executable, sys.path)
                if verdict != "scratch_process_namespace_unverified" or not confined:
                    reject_launch(verdict)
                ledger.note_verified_launch("scratch", command)
                housekeeping = True
            if name in {"timeout", "gtimeout"} and "bash" in command:
                if not confined or not shutdown_command_verified(str(args[0]), command, core, os.getpid()):
                    reject_launch("shutdown_diagnostic_not_verified")
                ledger.note_verified_launch("shutdown", command)
                housekeeping = True
            if not (is_fixture or is_readonly_git or housekeeping):
                reject_launch("unapproved_subprocess")
        elif event in {"os.kill", "os.killpg"}:
            pid, signum = args
            if pid == os.getpid():
                return
            expected = ledger.owned_pids.get(pid)
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
            value = {"pid": os.getpid(), "refusals": sorted(set(refused + provider_origin.errors)),
                     "core_bootstrap_from_requested_source": origin == core / "hermes_bootstrap.py",
                     "provider_origin": provider_origin.receipt(),
                     "loaded_provider_sha256": sorted(factory_hashes), "client_cancel_calls": client_cancel_calls,
                     "housekeeping": ledger.housekeeping()}
            temporary = receipt.with_suffix(".tmp")
            temporary.write_text(json.dumps(value), encoding="utf-8")
            temporary.replace(receipt)

    def profile(frame, event, arg) -> None:
        nonlocal client_cancel_calls
        provider_origin.observe(frame, event, arg)
        # Observe the ORIGINAL factory, including executor threads. No Core callable is replaced.
        # Core intentionally uses os._exit after its graceful drain, so atexit alone is insufficient.
        # Since 0.9.0 the default (Parked-MCP) factory lives in parked/_plugin_entry.py and the
        # Replay factory in the top-level __init__.py; accepts_frame() binds whichever file the
        # frame actually executed to the installed candidate bytes, so provenance is identical.
        if (event == "return" and frame.f_code.co_name == "create_client" and arg is not None):
            for relative in _FACTORY_SOURCES:
                if provider_origin.accepts_frame(frame, relative):
                    factory_hashes.add(
                        hashlib.sha256((plugin / relative).read_bytes()).hexdigest())
                    finish()
                    break
        elif event == "return" and frame.f_code.co_name == "cancel":
            for relative in _CLIENT_SOURCES:
                if provider_origin.accepts_frame(frame, relative):
                    client_cancel_calls += 1
                    finish()
                    break
        elif (event == "return" and frame.f_code.co_name == "__init__"
              and frame.f_globals.get("__name__") == "subprocess"):
            try:
                ledger.observe(frame.f_locals.get("self"))
            except _ChildIdentityUnavailable:
                reject("owned_child_identity_unavailable")
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
