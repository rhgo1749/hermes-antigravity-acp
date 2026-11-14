#!/usr/bin/env python3
"""Disposable, credential-free real Hermes Gateway E2E (Linux x86_64).

Only the real public CLI and HTTP API are used. The candidate provider/factory,
Core Gateway and agent loop are unchanged; the upstream ACP peer is synthetic.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

try:
    import deploy_hermes_profiles as deployment
    from gateway_docker import namespace_verified, validate_confinement
    from provider_origin import ProviderOrigin
except ImportError:
    from scripts import deploy_hermes_profiles as deployment
    from scripts.gateway_docker import namespace_verified, validate_confinement
    from scripts.provider_origin import ProviderOrigin

REQUIRED_STAGES = (
    "isolation", "candidate_install", "enablement", "gateway_ready", "provider_factory",
    "initialize", "request_response", "permission_denial", "cancellation",
    "ownership_conflict", "owner_survives", "shutdown", "child_cleanup", "source_unchanged",
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def validate_receipt(receipt: object, candidate: str) -> list[str]:
    if not isinstance(receipt, dict):
        return ["receipt_not_object"]
    problems = []
    if type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1:
        problems.append("invalid_schema")
    if receipt.get("candidate_sha") != candidate or not HEX40.fullmatch(candidate):
        problems.append("candidate_identity_mismatch")
    if not isinstance(receipt.get("hermes_commit"), str) or not HEX40.fullmatch(receipt["hermes_commit"]):
        problems.append("core_identity_missing")
    if receipt.get("status") != "PASS":
        problems.append("overall_not_pass")
    if receipt.get("candidate_source_dirty") is not False:
        problems.append("candidate_source_dirty")
    if (not isinstance(receipt.get("scratch_cleanup"), dict)
            or receipt["scratch_cleanup"].get("status") != "PASS"
            or type(receipt["scratch_cleanup"].get("launch_count")) is not int
            or receipt["scratch_cleanup"]["launch_count"] < 1):
        problems.append("scratch_cleanup_not_pass")
    diagnostic = receipt.get("shutdown_diagnostic")
    if (not isinstance(diagnostic, dict) or diagnostic.get("status") != "PASS"
            or type(diagnostic.get("launch_count")) is not int or diagnostic["launch_count"] < 1):
        problems.append("shutdown_diagnostic_not_pass")
    origin = receipt.get("provider_origin")
    if (not isinstance(origin, dict) or origin.get("status") != "PASS" or origin.get("candidate_sha") != candidate
            or origin.get("errors") != [] or type(origin.get("frozen_copies")) is not int or origin["frozen_copies"] < 0
            or any(not isinstance(origin.get(key), str) or re.fullmatch(r"[0-9a-f]{64}", origin[key]) is None
                   for key in ("tree_sha256", "home_sha256"))):
        problems.append("provider_origin_not_verified")
    problems.extend(validate_confinement(receipt))
    stages = receipt.get("stages")
    if not isinstance(stages, dict):
        return [*problems, "stages_not_object"]
    for name in REQUIRED_STAGES:
        stage = stages.get(name)
        if not isinstance(stage, dict) or stage.get("status") != "PASS":
            problems.append(f"required_stage_not_pass:{name}")
    return problems


def is_ready(value: object, pid: int) -> bool:
    return (isinstance(value, dict) and type(value.get("pid")) is int and value["pid"] == pid
            and value.get("status") == "ok" and value.get("gateway_state") == "running")


def readiness_observation(value: object, pid: int, http_status: int) -> dict:
    """Bounded allowlisted diagnostics; never emit response text, PIDs or details."""
    statuses = {"ok", "degraded", "running", "starting", "draining", "stopped",
                "startup_failed", "unknown", "retrying", "unavailable"}
    def state(item):
        return item if isinstance(item, str) and item in statuses else "unrecognized"
    response = value if isinstance(value, dict) else {}
    readiness = response.get("readiness")
    checks = readiness.get("checks") if isinstance(readiness, dict) else None
    checks = checks if isinstance(checks, dict) else {}
    return {"http_status": http_status, "status": state(response.get("status")),
            "gateway_state": state(response.get("gateway_state")),
            "expected_pid": type(response.get("pid")) is int and response["pid"] == pid,
            "checks": {name: state(checks[name].get("status"))
                       for name in ("state_db", "session_store", "config", "model", "disk", "gateway", "background_queues")
                       if isinstance(checks.get(name), dict)}}


def transport_observation(error: BaseException) -> dict:
    """Classify the transport without leaking exception messages or target URLs."""
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    if isinstance(reason, ConnectionRefusedError):
        status = "connection_refused"
    elif isinstance(reason, ConnectionResetError):
        status = "connection_reset"
    elif isinstance(reason, TimeoutError):
        status = "timeout"
    else:
        status = "unavailable"
    return {"transport": status}


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True,
                                   stderr=subprocess.DEVNULL, timeout=20).strip()


def _snapshot(root: Path, payload: Path | None = None) -> str:
    digest = hashlib.sha256()
    for name in _git(root, "ls-files", "-z").split("\0"):
        if name:
            digest.update(name.encode())
            path = (payload or root) / name
            digest.update(path.read_bytes() if path.is_file() else b"MISSING")
    return digest.hexdigest()


def _live(pid: int, started: str | None = None) -> bool:
    try:
        # Only fixture-recorded PIDs, never host process enumeration or executable-name scans.
        value = Path(f"/proc/{pid}/stat").read_text()
        fields = value.rsplit(")", 1)[1].split()
        return fields[0] not in {"Z", "X"} and (started is None or fields[22-3] == started)
    except FileNotFoundError:
        return False


class GatewayFailure(RuntimeError):
    pass


class Run:
    def __init__(self, core: Path, repo: Path, root: Path, candidate: str, timeout: float):
        self.source_core, self.core, self.repo, self.root = core, core, repo, root
        self.timeout = timeout
        self.profile = root / "hermes" / "profiles" / "phasec"
        self.home = root / "hermes"
        self.plugin = self.profile / "plugins" / "model-providers" / "antigravity-acp"
        self.process: subprocess.Popen | None = None
        self.reservation: socket.socket | None = None
        self.contender: subprocess.Popen | None = None
        self.started = time.monotonic()
        self.key = secrets.token_urlsafe(24)  # transport-only fixture key, not a vendor credential
        self.port = 0
        self.record = {"schema_version": 1, "candidate_sha": candidate,
                       "hermes_commit": _git(core, "rev-parse", "HEAD"), "status": "FAIL",
                       "stages": {name: {"status": "NOT_RUN", "detail": "not_executed"} for name in REQUIRED_STAGES}}
        self.current = "isolation"
        if namespace_verified():
            proof = json.loads(Path("/gw/confinement.json").read_text())
            self.record["confinement"] = {key: proof[key] for key in ("status", "checks", "pid_namespace_sha256", "host_pid_namespace_sha256")}

    def pass_stage(self, name: str, detail: str) -> None:
        self.record["stages"][name] = {"status": "PASS", "detail": detail}

    def need(self, condition: bool, detail: str) -> None:
        if not condition:
            raise GatewayFailure(detail)

    def events(self) -> list[dict]:
        path = self.root / "acp-events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def event_count(self, name: str) -> int:
        return sum(value.get("event") == name for value in self.events())

    def control(self, mode: str) -> str:
        text = "offline-" + secrets.token_hex(16)
        path = self.root / "control.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"mode": mode, "text": text}), encoding="utf-8")
        temporary.replace(path)
        return text

    def environment(self, home: Path) -> dict[str, str]:
        # Positive allowlist: no operating account, channel, session, MCP, proxy or auth variables.
        return {"HOME": str(self.root / "os-home"), "HERMES_HOME": str(home),
                "PATH": str(Path(sys.executable).parent) + os.pathsep + "/usr/bin:/bin",
                "PYTHONPATH": str(self.core), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
                "XDG_CONFIG_HOME": str(self.root / "config"), "XDG_CACHE_HOME": str(self.root / "cache"),
                "XDG_DATA_HOME": str(self.root / "data"), "XDG_STATE_HOME": str(self.root / "state"),
                "XDG_RUNTIME_DIR": str(self.root / "runtime"),
                "TMPDIR": str(self.root / "t"), "TMP": str(self.root / "t"), "TEMP": str(self.root / "t"),
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC", "GIT_OPTIONAL_LOCKS": "0",
                "HERMES_DISABLE_LAZY_INSTALLS": "1", "HERMES_GATEWAY_NO_SUPERVISE": "1",
                "PHASE_C_DOCKER_POLICY": os.environ.get("PHASE_C_DOCKER_POLICY", ""),
                "API_SERVER_ENABLED": "true", "API_SERVER_HOST": "127.0.0.1",
                "API_SERVER_PORT": str(self.port), "API_SERVER_KEY": self.key}

    def http(self, method: str, path: str, body=None, *, auth=True):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = "Bearer " + self.key
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers=headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=3) as response:
            return json.loads(response.read(1024 * 1024))

    def wait(self, predicate, detail: str):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            if self.process is not None and self.process.poll() is not None:
                raise GatewayFailure("gateway_exited_before_stage")
            time.sleep(0.1)  # bounded condition wait, not a retry of a failed request
        raise GatewayFailure(detail)

    def ready(self):
        pid = self.process.pid if self.process is not None else -1
        try:
            value = self.http("GET", "/p/phasec/health/detailed")
        except urllib.error.HTTPError as exc:
            self.record["last_readiness"] = readiness_observation(None, pid, exc.code)
            if exc.code in {401, 403, 404}:
                raise GatewayFailure("gateway_profile_route_not_authenticated") from None
            return False
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            self.record["last_readiness"] = transport_observation(exc)
            return False
        self.record["last_readiness"] = readiness_observation(value, pid, 200)
        return self.process is not None and is_ready(value, self.process.pid)

    def start(self, *, contender=False):
        env = self.environment(self.profile if contender else self.home)
        if contender:
            env["PHASE_C_CONTENDER"] = "1"
        elif self.reservation is not None:
            self.reservation.close()
            self.reservation = None
        command = [sys.executable, "-u", str(self.repo / "scripts" / "gateway_cli_envelope.py"),
                   str(self.core), str(self.root), str(self.plugin), "gateway", "run", "--no-supervise"]
        # Raw logs never go to Actions stdout or uploaded artifacts.
        with (self.root / ("contender.log" if contender else "gateway.log")).open("wb") as output:
            return subprocess.Popen(command, cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                                    stdout=output, stderr=subprocess.STDOUT, start_new_session=True)

    def request(self, mode="reply") -> tuple[dict, str]:
        text = self.control(mode)
        value = self.http("POST", "/p/phasec/v1/runs", {"input": "synthetic-offline-request"})
        run_id = value.get("run_id")
        self.need(isinstance(run_id, str) and bool(run_id), "run_not_admitted")
        return self.wait_run(run_id), text

    def wait_run(self, run_id: str) -> dict:
        def terminal():
            value = self.http("GET", "/p/phasec/v1/runs/" + run_id)
            return value if value.get("status") in {"completed", "failed", "cancelled", "interrupted"} else None
        return self.wait(terminal, "request_completion_timeout")

    def verify_reply(self) -> None:
        result, expected = self.request()
        self.need(result.get("status") == "completed", "gateway_request_failed")
        self.need(expected in json.dumps(result), "response_not_from_challenge_bound_fake")
        provider = result.get("runtime", {}).get("provider")
        # Canonical-admission API results may omit the served pair. Candidate identity
        # is independently REQUIRED through the observed original factory + ACP challenge.
        self.need(not provider or provider == "antigravity-acp", "served_provider_mismatch")

    def prepare(self) -> None:
        self.need(namespace_verified(), "verified_container_required")
        self.need(sys.platform == "linux" and os.uname().machine in {"x86_64", "amd64"}, "unsupported_host")
        self.need(not self.root.is_symlink() and self.root.stat().st_uid == os.getuid(), "unowned_test_root")
        for name in ("os-home", "config", "cache", "data", "state", "runtime", "t"):
            (self.root / name).mkdir(mode=0o700)
        self.profile.mkdir(parents=True)
        self.home.chmod(0o700)
        for home in (self.home, self.profile):
            scratch = home / "cache" / "scratch"
            old = scratch / "phasec-idle-probe"
            old.mkdir(parents=True)
            seed = old / "fixture-only.txt"
            seed.write_text("disposable-cleanup-negative-control")
            idle = time.time() - 48 * 3600
            os.utime(seed, (idle, idle))
            os.utime(old, (idle, idle))
            (scratch / "phasec-active-probe").write_text("must-survive-original-prune")
        # Export exact Git bytes into the disposable root. No .git, install stamp, PM
        # selection or Core file is edited; the existing interpreter owns dependencies.
        archive = self.root / "core-source.tar"
        with archive.open("wb") as output:
            subprocess.run(["git", "-C", str(self.source_core), "archive", "--format=tar", "HEAD"],
                           stdout=output, check=True, timeout=30)
        self.core = self.root / "core"
        self.core.mkdir()
        with tarfile.open(archive) as source:
            source.extractall(self.core, filter="data")
        archive.unlink()
        self.need(_snapshot(self.source_core, self.core) == _snapshot(self.source_core), "exported_core_bytes_mismatch")
        self.record["core_launch_mode"] = "byte_identical_source_export"
        # Reserve a loopback port below the kernel's ephemeral range so runner
        # outbound connections cannot steal it, and hold the reservation until
        # the Gateway's own bind, closing it only at launch.
        low = 32768
        try:
            low = int(Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[0])
        except (OSError, ValueError, IndexError):
            pass
        candidates = list(range(20000, max(20001, low - 1)))
        random.Random(secrets.randbits(64)).shuffle(candidates)
        for port in candidates[:64]:
            reservation = socket.socket()
            try:
                reservation.bind(("127.0.0.1", port))
            except OSError:
                reservation.close()
                continue
            self.reservation, self.port = reservation, port
            break
        self.need(self.reservation is not None, "no_reserved_loopback_port")
        self.need(all(Path(value).is_relative_to(self.root) for key, value in self.environment(self.home).items()
                      if key in {"HOME", "HERMES_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
                                 "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"}), "home_isolation_failed")
        self.pass_stage("isolation", "fresh_private_root_clean_environment_loopback_reserved_nonephemeral_port")
        self.current = "candidate_install"
        config = {"model": {"provider": "antigravity-acp", "default": "phase-c-model", "context_length": 65536},
                  "agent": {"max_turns": 2, "environment_probe": False},
                  "model_catalog": {"enabled": False},
                  "auxiliary": {"title_generation": {"enabled": False, "model_upgrade_enabled": False}}, "compression": {"enabled": False},
                  "memory": {"memory_enabled": False, "user_profile_enabled": False},
                  "curator": {"enabled": False}, "checkpoints": {"enabled": False},
                  "kanban": {"dispatch_in_gateway": False}, "toolsets": {"api_server": []},
                  "plugins": {"enabled": ["antigravity-acp"], "auto_update_check_hours": 0, "auto_apply": False}, "gateway": {"multiplex_profiles": True}}
        for home in (self.home, self.profile):
            (home / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
            (home / ".env").write_text("API_SERVER_KEY=" + self.key + "\n", encoding="utf-8")
        source = self.repo / "hermes-plugin" / "antigravity-acp"
        deployment.install(source, self.home, apply=True)
        self.need(not deployment.verify(self.home), "candidate_install_verification_failed")
        shutil.copyfile(self.repo / "scripts" / "gateway_fake_acp.py", self.root / "fake-acp.py")
        for home in (self.home, self.profile):
            plugin = home / "plugins" / "model-providers" / "antigravity-acp"
            for name in deployment.REQUIRED:
                self.need((source / name).read_bytes() == (plugin / name).read_bytes(), "installed_candidate_bytes_mismatch")
            (plugin / "launch_config.json").write_text(json.dumps({
                "process_command": sys.executable, "process_args": [str(self.root / "fake-acp.py"), str(self.root)]}), encoding="utf-8")
        self.pass_stage("candidate_install", "existing_owned_installer_exact_candidate_payload")
        self.pass_stage("enablement", "explicit_enabled_provider_in_both_disposable_homes")
        self.control("reply")

    def execute(self) -> dict:
        before = _snapshot(self.core)
        try:
            self.prepare()
            self.current = "gateway_ready"
            self.process = self.start()
            self.wait(self.ready, "gateway_ready_timeout")
            self.pass_stage("gateway_ready", "authenticated_detailed_health_ready_running_expected_pid")
            self.current = "request_response"
            self.verify_reply()
            self.pass_stage("request_response", "real_gateway_agent_loop_exact_challenge_response")
            self.current = "provider_factory"
            envelope = json.loads((self.root / "gateway-envelope.json").read_text())
            expected = hashlib.sha256((self.plugin / "__init__.py").read_bytes()).hexdigest()
            self.need(envelope["core_bootstrap_from_requested_source"] and expected in envelope["loaded_provider_sha256"],
                      "candidate_factory_not_executed")
            actual_origin = envelope.get("provider_origin", {})
            expected_origin = ProviderOrigin(self.plugin, self.profile, self.core).receipt()
            self.need(all(actual_origin.get(key) == expected_origin[key] for key in ("tree_sha256", "home_sha256"))
                      and actual_origin.get("errors") == [], "candidate_home_runtime_provenance_mismatch")
            self.record["provider_origin"] = {"status": "PASS", "candidate_sha": self.record["candidate_sha"], **actual_origin}
            self.pass_stage("provider_factory", "original_candidate_factory_observed_in_real_gateway_worker")
            self.current = "initialize"
            self.need(self.event_count("initialize") > 0, "initialize_not_executed")
            self.pass_stage("initialize", "synthetic_credential_free_acp_initialize_executed")
            self.current = "ownership_conflict"
            lock = self.profile / "gateway.lock"
            lock_before = (lock.stat().st_ino, lock.read_bytes())
            self.contender = self.start(contender=True)
            try:
                rc = self.contender.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                raise GatewayFailure("contender_did_not_refuse") from None
            message = (self.root / "contender.log").read_text(errors="replace")
            reused = (rc == 0 and "The host gateway already serves profile 'phasec'" in message
                      and "nothing to start" in message and f"PID {self.process.pid} " in message)
            refused = rc in {1, 78} and any(value in message.lower() for value in (
                "already running", "owns profile", "cannot reserve", "already serves"))
            self.need(reused or refused, "contender_not_safely_reused_or_refused")
            self.need(lock.exists() and (lock.stat().st_ino, lock.read_bytes()) == lock_before,
                      "contender_damaged_owner_lock")
            self.pass_stage("ownership_conflict", "official_existing_owner_noop_lock_unchanged" if reused
                            else "same_served_profile_refused_owner_lock_unchanged")
            self.current = "owner_survives"
            self.need(self.process.poll() is None and self.ready(), "original_owner_not_healthy")
            self.verify_reply()
            self.pass_stage("owner_survives", "same_original_owner_processed_new_request_after_contention")
            self.current = "permission_denial"
            denied_before = self.event_count("permission_rejected")
            denied, _ = self.request("deny")
            self.need(denied.get("status") == "failed" and self.event_count("permission_rejected") > denied_before
                      and self.event_count("permission_wrongly_allowed") == 0, "native_permission_not_fail_closed")
            self.pass_stage("permission_denial", "real_gateway_native_permission_refused_no_native_execution")
            self.current = "cancellation"
            held_before = self.event_count("prompt_held")
            cancel_before = json.loads((self.root / "gateway-envelope.json").read_text()).get("client_cancel_calls", 0)
            self.control("hold")
            admitted = self.http("POST", "/p/phasec/v1/runs", {"input": "synthetic-cancellable-request"})
            run_id = admitted["run_id"]
            self.wait(lambda: self.event_count("prompt_held") > held_before, "cancellable_prompt_not_started")
            self.http("POST", "/p/phasec/v1/runs/" + run_id + "/stop", {})
            cancelled = self.wait_run(run_id)
            self.need(cancelled.get("status") == "cancelled", "request_not_cancelled")
            self.wait(lambda: json.loads((self.root / "gateway-envelope.json").read_text()).get("client_cancel_calls", 0) > cancel_before,
                      "original_acp_client_cancel_not_called")
            held = {event["pid"] for event in self.events() if event.get("event") == "prompt_held"}
            owned = [event for event in self.events() if event.get("event") == "server_started" and event["pid"] in held]
            self.wait(lambda: owned and all(not _live(event["pid"], event["started"])
                      and not _live(event["grandchild_pid"], event["grandchild_started"]) for event in owned),
                      "cancelled_request_tree_not_reaped")
            self.verify_reply()
            self.pass_stage("cancellation", "public_stop_original_client_cancel_owned_tree_exit_and_followup_response")
        except Exception as exc:
            detail = str(exc) if isinstance(exc, GatewayFailure) else type(exc).__name__
            self.record["stages"][self.current] = {"status": "FAIL", "detail": detail}
        finally:
            self.cleanup()
            if _snapshot(self.source_core) == before and _snapshot(self.source_core, self.core) == before and not _git(self.source_core, "status", "--porcelain", "--untracked-files=no"):
                self.pass_stage("source_unchanged", "official_core_tracked_bytes_and_git_state_unchanged")
            else:
                self.record["stages"]["source_unchanged"] = {"status": "FAIL", "detail": "core_source_changed"}
            self.record["status"] = "PASS" if all(self.record["stages"][name]["status"] == "PASS" for name in REQUIRED_STAGES) else "FAIL"
            self.record["duration_seconds"] = round(time.monotonic() - self.started, 3)
            self.record["vendor_inference_cancellation"] = {"status": "NOT_RUN", "detail": "synthetic_transport_only"}
        return self.record

    def cleanup(self) -> None:
        forced = False
        for process in (self.contender, self.process):
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    forced = True
                    os.killpg(process.pid, signal.SIGKILL)  # only our Popen session, never a host scan
                    process.wait(timeout=5)
        for event in self.events():
            if event.get("event") == "server_started":
                for key in ("pid", "grandchild_pid"):
                    pid = event[key]
                    token = event["started" if key == "pid" else "grandchild_started"]
                    if _live(pid, token):
                        forced = True
                        # A fixture stop file/self-bounded peer is preferable, but never leave it alive.
                        os.kill(pid, signal.SIGTERM)
        pids = {event[key]: event["started" if key == "pid" else "grandchild_started"]
                for event in self.events() if event.get("event") == "server_started" for key in ("pid", "grandchild_pid")}
        children = self.root / "owned-core-children.jsonl"
        if children.exists():
            for line in children.read_text().splitlines():
                child = json.loads(line)
                pids[child["pid"]] = child["started"]
        deadline = time.monotonic() + 6  # Core's original shutdown diagnostic is bounded to 5s.
        while any(_live(pid, token) for pid, token in pids.items()) and time.monotonic() < deadline:
            time.sleep(0.1)
        clean = not any(_live(pid, token) for pid, token in pids.items())
        self.record["owned_child_count"] = len(pids)
        self.record["live_owned_children_after_exit"] = sum(_live(pid, token) for pid, token in pids.items())
        boundary_ok = True
        housekeeping = []
        for name in ("gateway-envelope.json", "contender-envelope.json"):
            path = self.root / name
            if path.exists():
                envelope = json.loads(path.read_text())
                boundary_ok = boundary_ok and not envelope.get("refusals")
                housekeeping.extend(envelope.get("housekeeping", []))
        pruning = [item for item in housekeeping if item["kind"] == "scratch"]
        targets = {Path(item["target"]) for item in pruning}
        allowed_targets = {home / "cache" / "scratch" for home in (self.home, self.profile)}
        scratch_ok = bool(pruning) and targets.issubset(allowed_targets) and all(item["returncode"] == 0 for item in pruning)
        for target in targets & allowed_targets:
            log = target.parent.parent / "logs" / "scratch-prune.log"
            content = log.read_text(errors="replace") if log.exists() else ""
            scratch_ok = (scratch_ok and not (target / "phasec-idle-probe").exists()
                          and (target / "phasec-active-probe").is_file() and bool(content)
                          and not any(text in content.lower() for text in ("failed", "could not", "nothing deleted")))
        self.record["scratch_cleanup"] = {"status": "PASS" if scratch_ok and boundary_ok else "FAIL",
                                          "launch_count": len(pruning), "target_count": len(targets),
                                          "detail": "original_pruner_idle_removed_active_retained" if scratch_ok else "pruner_execution_not_verified"}
        diagnostics = [item for item in housekeeping if item["kind"] == "shutdown"]
        diagnostic_log = self.home / "logs" / "gateway-shutdown-diag.log"
        diagnostic_ok = bool(diagnostics) and diagnostic_log.exists() and "=== end ===" in diagnostic_log.read_text(errors="replace")
        self.record["shutdown_diagnostic"] = {"status": "PASS" if diagnostic_ok else "FAIL", "launch_count": len(diagnostics)}
        if not boundary_ok:
            self.record["stages"]["isolation"] = {"status": "BLOCKED", "detail": "sticky_boundary_refusal"}
        if not scratch_ok:
            self.record["stages"]["isolation"] = {"status": "FAIL", "detail": "original_scratch_cleanup_unverified"}
        if self.process is not None:
            success = self.process.returncode == 0 and not forced and diagnostic_ok
            self.record["stages"]["shutdown"] = {"status": "PASS" if success else "FAIL", "detail": "graceful_exit_and_original_diagnostic" if success else "unclean_exit_or_missing_diagnostic"}
        self.record["stages"]["child_cleanup"] = {"status": "PASS" if clean and not forced else "FAIL", "detail": "no_live_owned_children" if clean and not forced else "residual_or_forced_cleanup"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-root", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--keep-diagnostics", action="store_true", help="local development only; never upload raw logs")
    args = parser.parse_args(argv)
    repo = Path(__file__).resolve().parent.parent
    core = args.hermes_root.resolve(strict=True)
    if not HEX40.fullmatch(args.candidate_sha) or _git(repo, "rev-parse", "HEAD") != args.candidate_sha:
        parser.error("candidate must equal the full checkout HEAD")
    # Local development diagnostics may be dirty, but cannot become a candidate PASS.
    clean = not _git(repo, "status", "--porcelain", "--untracked-files=normal")
    if not HEX40.fullmatch(_git(core, "rev-parse", "HEAD")) or _git(core, "status", "--porcelain", "--untracked-files=no"):
        parser.error("Core must be a clean official source checkout")
    if args.keep_diagnostics and os.environ.get("GITHUB_ACTIONS") == "true":
        parser.error("raw diagnostic retention is local-only")
    directory = tempfile.mkdtemp(prefix="gw-")
    run = None
    try:
        root = Path(directory).resolve()
        run = Run(core, repo, root, args.candidate_sha, args.timeout)
        result = run.execute()
        clean = (clean and _git(repo, "rev-parse", "HEAD") == args.candidate_sha
                 and not _git(repo, "status", "--porcelain", "--untracked-files=normal"))
        result["candidate_source_dirty"] = not clean
        result["run_id"] = os.environ.get("GITHUB_RUN_ID", "local")
        result["run_attempt"] = os.environ.get("GITHUB_RUN_ATTEMPT", "local")
        result["driver_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        result["hermes_tree"] = _git(core, "rev-parse", "HEAD^{tree}")
        result["execution"] = {"python": sys.executable, "entry": "scripts/gateway_e2e.py", "cli": "hermes gateway run --no-supervise"}
        if not clean:
            result["status"] = "FAIL"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, sort_keys=True))
    finally:
        if run is not None and run.reservation is not None:
            run.reservation.close()
            run.reservation = None
        if args.keep_diagnostics:
            print("local_diagnostic_root=" + directory)
        else:
            shutil.rmtree(directory)
    return 1 if validate_receipt(result, args.candidate_sha) else 0


if __name__ == "__main__":
    raise SystemExit(main())
