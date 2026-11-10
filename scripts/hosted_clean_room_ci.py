#!/usr/bin/env python3
"""historical reference rework: hosted fresh-UID clean-room driver (GitHub Actions).

This driver executes the credential-free real-binary clean-room chain for
the official Google ACP 1.4.4 server inside a GitHub-hosted ``ubuntu-24.04``
runner VM, and it MUST run as a dedicated non-privileged OS UID created by
the workflow with ``useradd`` — never as root and never as the runner user.
The venue criteria (historical reference isolation ruling) are enforced here and
fail closed: dedicated UID, Ubuntu 24.04 userland, empty disposable
``HOME``/``HERMES_HOME``, and a scrubbed allowlisted process environment.

Output contract (historical reference `_server_stderr_summary` lineage, hardened):
untrusted text — server output, probe streams, anything not authored by
this repository — is never echoed, excerpted, or written into the evidence
JSONL. Every captured stream contributes only a bounded
``{lines, bytes, sha256_16}`` summary plus credential-shape CLASS names.
Text authored by this repository's own scripts may be disclosed only after
passing the repository's own secret scanners; any trip replaces the text
with its fingerprint. The evidence file itself is re-scanned fail-closed by
the workflow via ``--scan-file``.

The driver authenticates nothing: no `authenticate`/login/OAuth frame is
ever sent, no prompt is ever sent, and no credential is ever read. A real
model listing that the server gates behind authentication is recorded as a
fingerprinted auth-boundary event, never as a fabricated model list.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import audit_public_tree as audit  # noqa: E402
import install_acp  # noqa: E402  (reuse of the historical reference redaction contract)

EXPECTED_ACP_VERSION = "1.4.4"
EXPECTED_AGENT_INFO = {
    "name": "antigravity-acp",
    "title": "Google Antigravity",
    "version": "1.4.4",
}
EXPECTED_AUTH_METHOD_IDS = [
    "agent-platform",
    "gemini-api-key",
    "oauth-business",
    "oauth-personal",
]
EXPECTED_CAPABILITY_KEYS = [
    "_meta",
    "auth",
    "loadSession",
    "mcpCapabilities",
    "promptCapabilities",
    "sessionCapabilities",
]
# Exact variable set the workflow's `env -i` is permitted to set. Anything
# else in the environment fails the run closed.
ALLOWED_ENV_KEYS = frozenset(
    {
        "HOME",
        "USER",
        "LOGNAME",
        "PATH",
        "HERMES_HOME",
        "LANG",
        "LC_ALL",
        "ACP_EXPECTED_SHA256",
        "HERMES_CORE_REF",
        "CLEAN_ROOM_EVIDENCE_FILE",
    }
)
REQUIRED_ENV_KEYS = ALLOWED_ENV_KEYS - {"LANG", "LC_ALL"}
# Home entries the chain itself may legitimately create on top of the
# baseline captured at driver start (skel dotfiles, staged trees, decoys):
# only the installer/uv-owned trees. Anything else is a fail-closed finding.
ALLOWED_CREATED_ENTRIES = frozenset({".cache", ".config", ".local"})
# Expected step -> exit code for the whole chain (tests read this table).
STEP_EXPECTATIONS: dict[str, int] = {
    "h00-preflight": 0,
    "h01-official-status-preinstall": 1,
    "h02-official-verify-preinstall": 2,
    "h03-provider-status-preinstall": 1,
    "h04-official-install-download-1": 0,
    "h05-official-status-postinstall": 0,
    "h06-provider-install-register": 0,
    "h07-provider-status-registered": 0,
    "h08-provider-verify-initialize-1": 0,
    "h09-acp-probe-initialize-2": 0,
    "h10-official-uninstall": 0,
    "h11-official-status-post-uninstall": 1,
    "h12-official-verify-post-uninstall": 2,
    "h13-official-reinstall-download-2": 0,
    "h14-official-status-post-reinstall": 0,
    "h15-official-verify-post-reinstall": 0,
    "h16-foreign-launcher-uninstall-refused": 2,
    "h17-foreign-launcher-install-refused": 2,
    "h18-foreign-launcher-recovery": 0,
    "h19-provider-delete": 0,
    "h20-provider-status-after-delete": 1,
    "h21-provider-reinstall-download-3": 0,
    "h22-provider-verify-initialize-3": 0,
    "h23-hermes-commit-record": 0,
    "h23b-uv-version": 0,
    "h24-hermes-uv-sync": 0,
    "h25-hermes-unmodified": 0,
    "h26-hermes-provider-probe": 0,
}


class StepFailure(RuntimeError):
    def __init__(self, step: str, message: str = "") -> None:
        super().__init__(f"{step}: {message}" if message else step)
        self.step = step


def _stream_fingerprint(text: str) -> dict[str, object]:
    raw = (text or "").encode("utf-8", "replace")
    lines = [line for line in raw.decode("utf-8", "replace").splitlines() if line.strip()]
    return {
        "lines": len(lines),
        "bytes": len(raw),
        "sha256_16": hashlib.sha256(raw).hexdigest()[:16],
    }


def _shape_classes(text: str) -> list[str]:
    classes = sorted(
        name
        for name, pattern in install_acp._CREDENTIAL_SHAPES
        if any(pattern.search(line) for line in (text or "").splitlines())
    )
    return sorted(set(classes) | set(audit.scan_text(text or "")))


def _suppressed(text: str) -> dict[str, object]:
    """Bounded non-echoing summary for any captured stream (historical reference contract).

    Identical to the runtime's `_server_stderr_summary` shape: counts, a
    sha256-16 fingerprint for correlation, and credential-shape class names
    — never values, never server text.
    """
    summary = install_acp._server_stderr_summary(text or "")
    record = _stream_fingerprint(text)
    record["classes"] = _shape_classes(text)
    record["summary"] = summary
    return record


def _disclosure(text: str, cap: int = 6) -> dict[str, object]:
    """Gate repository-authored stream text behind the repo's own scanners.

    If the repository's own secret-content or credential-shape scanners find
    anything (which must never happen for these trusted scripts), the text
    is replaced by its fingerprint summary — fail closed, never echo.
    """
    record = _stream_fingerprint(text)
    findings = _shape_classes(text)
    if findings:
        record["disclosure"] = "suppressed_by_secret_scan"
        record["classes"] = findings
        return record
    record["disclosure"] = "published_repo_authored_text"
    record["tail"] = [line for line in (text or "").splitlines() if line.strip()][-cap:]
    return record


class Evidence:
    """Append-only sanitized JSONL evidence log (mode 0o644, world-readable)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        os.chmod(self.path, 0o644)

    def event(self, kind: str, **fields: object) -> None:
        record = {"event": kind, **fields}
        line = json.dumps(record, sort_keys=True)
        if _shape_classes(line):
            # Belt and braces: an event that trips the scanners is replaced
            # by a marker plus its fingerprint, and the run fails closed.
            safe = json.dumps(
                {
                    "event": "evidence_scan_trip",
                    "kind": kind,
                    "sha256_16": hashlib.sha256(line.encode()).hexdigest()[:16],
                },
                sort_keys=True,
            )
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(safe + "\n")
            print(safe, flush=True)
            raise StepFailure(kind, "evidence event tripped the secret scanners")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        print(line, flush=True)


class CleanRoom:
    def __init__(self, ev: Evidence) -> None:
        env = os.environ
        missing = REQUIRED_ENV_KEYS - set(env)
        if missing:
            raise StepFailure("startup", f"missing required env keys: {sorted(missing)}")
        unexpected = set(env) - ALLOWED_ENV_KEYS
        if unexpected:
            raise StepFailure("startup", f"unexpected env keys: {sorted(unexpected)}")
        self.home = Path(env["HOME"])
        self.hermes_home = Path(env["HERMES_HOME"])
        self.clone = self.home / "upstream-hermes"
        self.launcher = self.home / ".local" / "bin" / "antigravity-acp-official"
        self.expected_digest = env["ACP_EXPECTED_SHA256"].strip().lower()
        self.hermes_ref = env["HERMES_CORE_REF"].strip().lower()
        self.uid = os.getuid()
        self.ev = ev
        self.decoy_hashes: dict[str, str] = {}

    def step_env(self) -> dict[str, str]:
        return {key: value for key, value in os.environ.items() if key in ALLOWED_ENV_KEYS}

    def run_step(
        self,
        name: str,
        argv: list[str],
        *,
        cwd: Path | None = None,
        timeout: float = 120.0,
        mode: str = "trusted",
        expect_stderr_contains: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        expected = STEP_EXPECTATIONS[name]
        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                cwd=str(cwd or self.home),
                env=self.step_env(),
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.ev.event(
                "step",
                step=name,
                rc="timeout",
                expect_rc=expected,
                timeout_seconds=timeout,
            )
            raise StepFailure(name, f"exceeded {timeout:.0f}s hard limit") from None
        record: dict[str, object] = {
            "step": name,
            "rc": proc.returncode,
            "expect_rc": expected,
            "seconds": round(time.monotonic() - started, 2),
        }
        if mode == "fingerprint":
            record["stdout"] = _suppressed(proc.stdout)
            record["stderr"] = _suppressed(proc.stderr)
        else:
            record["stdout"] = _disclosure(proc.stdout)
            record["stderr"] = _disclosure(proc.stderr)
        if expect_stderr_contains is not None:
            record["stderr_contains_expected_messages"] = all(
                message in (proc.stderr or "") for message in expect_stderr_contains
            )
        self.ev.event("step", **record)
        if proc.returncode != expected:
            raise StepFailure(name, f"rc={proc.returncode} expected {expected}")
        if expect_stderr_contains is not None and not record[
            "stderr_contains_expected_messages"
        ]:
            raise StepFailure(name, "expected fail-closed message absent")
        return proc

    # -- venue and identity preflight ------------------------------------
    def preflight(self) -> None:
        if self.uid == 0:
            raise StepFailure("h00-preflight", "driver must not run as root")
        os_pretty = ""
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("PRETTY_NAME="):
                os_pretty = line.split("=", 1)[1].strip('"')
        if not os_pretty.startswith("Ubuntu 24.04"):
            raise StepFailure("h00-preflight", f"not an Ubuntu 24.04 userland: {os_pretty!r}")
        runner_home = Path("/home/runner")
        if not runner_home.is_dir():
            raise StepFailure("h00-preflight", "GitHub-hosted runner home absent (wrong venue)")
        runner_uid = runner_home.stat().st_uid
        if runner_uid == self.uid:
            raise StepFailure("h00-preflight", "clean-room user must differ from runner user")
        # OS-UID separation proof: the workflow plants a mode-0600 canary
        # owned by the runner user; DAC must deny this uid any read of it.
        canary = runner_home / ".cr94canary" / "private"
        isolated = False
        try:
            canary.read_bytes()
        except PermissionError:
            isolated = True
        except FileNotFoundError:
            raise StepFailure(
                "h00-preflight", "runner-user canary absent (workflow order changed)"
            ) from None
        if not isolated:
            raise StepFailure(
                "h00-preflight", "runner-user private canary readable by clean-room uid"
            )
        machine = platform.machine()
        if machine != "x86_64":
            raise StepFailure("h00-preflight", f"expected x86_64 hosted runner, got {machine}")
        from antigravity_acp.registry import VERSION, resolve_distribution

        dist = resolve_distribution("linux", "x86_64")
        if VERSION != EXPECTED_ACP_VERSION or dist.sha256.lower() != self.expected_digest:
            raise StepFailure("h00-preflight", "registry pin drifted from the reviewed digest")
        if self.home.stat().st_uid != self.uid:
            raise StepFailure("h00-preflight", "clean-room home is not owned by this uid")
        self._seed_decoys()
        # Baseline: whatever exists in HOME once the workflow staging and the
        # driver's own decoy seeding are done. Integrity then demands the
        # chain created nothing beyond the installer/uv-owned trees,
        # independent of runner-image skel customization.
        self.home_baseline = sorted(entry.name for entry in self.home.iterdir())
        sudo_rc: int | None = None
        try:
            sudo_rc = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                check=False,
                env=self.step_env(),
                timeout=15,
            ).returncode
        except (OSError, subprocess.TimeoutExpired):
            sudo_rc = None
        self.ev.event(
            "venue",
            os_pretty=os_pretty,
            kernel=platform.release(),
            machine=machine,
            uid=self.uid,
            user=os.environ["USER"],
            runner_uid=runner_uid,
            runner_private_canary_read="denied(PermissionError)",
            privilege_escalation_available=sudo_rc == 0,
            env_keys=sorted(os.environ),
            acp_version=VERSION,
            acp_sha256=dist.sha256,
        )
        if sudo_rc == 0:
            raise StepFailure("h00-preflight", "clean-room uid unexpectedly has sudo")

    def _decoy_bodies(self) -> dict[Path, str]:
        fake = "DECOYNOTAREALTOKEN" * 3
        return {
            self.home / ".env": f"GOOGLE_ACCESS_TOKEN={'ya29.' + fake}\n",
            self.home / "credentials.json": json.dumps(
                {"installed": {"client_id": f"{fake}-decoy.apps.example", "client_secret": fake}}
            ),
            self.home / ".config" / "gcloud" / "application_default_credentials.json": (
                json.dumps({"type": "authorized_user", "refresh_token": f"1//{fake}"})
            ),
        }

    def _seed_decoys(self) -> None:
        for path, body in self._decoy_bodies().items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        self.decoy_hashes = {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self._decoy_bodies()
        }

    # -- initialize metadata gate -----------------------------------------
    def check_initialize_stdout(self, name: str, stdout: str) -> None:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            raise StepFailure(name, "probe stdout was not a JSON summary") from None
        info = payload.get("agentInfo") or {}
        methods = sorted(
            str(method.get("id", "")) for method in (payload.get("authMethods") or [])
        )
        caps = sorted(payload.get("agentCapabilities") or {})
        checks = {
            "protocol_version": payload.get("protocolVersion") == 1,
            "agent_info_exact": info == EXPECTED_AGENT_INFO,
            "auth_method_ids_exact": methods == EXPECTED_AUTH_METHOD_IDS,
            "capability_keys_exact": caps == EXPECTED_CAPABILITY_KEYS,
        }
        record = dict(_stream_fingerprint(stdout))
        record.update(checks)
        record["observed_auth_method_ids"] = methods
        record["observed_capability_keys"] = caps
        self.ev.event("initialize_gate", step=name, **record)
        if not all(checks.values()):
            raise StepFailure(name, "real-server initialize metadata diverged from the pin")

    # -- main lifecycle -----------------------------------------------------
    def run_chain(self) -> None:
        official = str(SCRIPTS / "install_official.py")
        provider = str(SCRIPTS / "install_acp.py")
        probe = str(SCRIPTS / "acp_probe.py")
        self.preflight()
        self.run_step("h01-official-status-preinstall", [sys.executable, official, "--status"])
        self.run_step("h02-official-verify-preinstall", [sys.executable, official, "--verify"])
        self.run_step("h03-provider-status-preinstall", [sys.executable, provider, "status"])
        self.run_step(
            "h04-official-install-download-1",
            [sys.executable, official],
            timeout=900,
        )
        self.run_step("h05-official-status-postinstall", [sys.executable, official, "--status"])
        self.run_step("h06-provider-install-register", [sys.executable, provider, "install"])
        self.run_step("h07-provider-status-registered", [sys.executable, provider, "status"])
        self.run_step(
            "h08-provider-verify-initialize-1",
            [sys.executable, provider, "verify", "--timeout", "90"],
            timeout=360,
        )
        probe_proc = self.run_step(
            "h09-acp-probe-initialize-2",
            [sys.executable, probe, "--timeout", "120", "--", str(self.launcher)],
            timeout=360,
            mode="fingerprint",
        )
        self.check_initialize_stdout("h09-acp-probe-initialize-2", probe_proc.stdout)
        self.run_step("h10-official-uninstall", [sys.executable, official, "--uninstall"])
        self.run_step(
            "h11-official-status-post-uninstall", [sys.executable, official, "--status"]
        )
        self.run_step(
            "h12-official-verify-post-uninstall",
            [sys.executable, official, "--verify"],
            expect_stderr_contains=["Official ACP server binary is missing"],
        )
        self.run_step(
            "h13-official-reinstall-download-2",
            [sys.executable, official],
            timeout=900,
        )
        self.run_step("h14-official-status-post-reinstall", [sys.executable, official, "--status"])
        self.run_step("h15-official-verify-post-reinstall", [sys.executable, official, "--verify"])
        self._plant_foreign_launcher()
        self.run_step(
            "h16-foreign-launcher-uninstall-refused",
            [sys.executable, official, "--uninstall"],
            expect_stderr_contains=["Refusing to remove an unmanaged official ACP launcher"],
        )
        self.run_step(
            "h17-foreign-launcher-install-refused",
            [sys.executable, official],
            timeout=300,
            expect_stderr_contains=["Refusing to replace an unmanaged official ACP launcher"],
        )
        self._remove_foreign_launcher()
        self.run_step(
            "h18-foreign-launcher-recovery",
            [sys.executable, official],
            timeout=300,
        )
        self.run_step("h19-provider-delete", [sys.executable, provider, "delete"])
        self.run_step("h20-provider-status-after-delete", [sys.executable, provider, "status"])
        self.run_step(
            "h21-provider-reinstall-download-3",
            [sys.executable, provider, "install"],
            timeout=900,
        )
        self.run_step(
            "h22-provider-verify-initialize-3",
            [sys.executable, provider, "verify", "--timeout", "90"],
            timeout=360,
        )
        self._hermes_steps()
        self.integrity()

    def _plant_foreign_launcher(self) -> None:
        if not self.launcher.is_file():
            raise StepFailure("h16-foreign-launcher-uninstall-refused", "launcher absent")
        self.launcher.write_text(
            "#!/bin/sh\n# foreign unmanaged placeholder planted by the clean room\n"
            "exit 127\n",
            encoding="utf-8",
        )
        self.foreign_digest = hashlib.sha256(self.launcher.read_bytes()).hexdigest()

    def _remove_foreign_launcher(self) -> None:
        digest = hashlib.sha256(self.launcher.read_bytes()).hexdigest()
        if digest != self.foreign_digest:
            raise StepFailure(
                "h17-foreign-launcher-install-refused", "foreign launcher was modified"
            )
        self.launcher.unlink()

    def _hermes_steps(self) -> None:
        self.run_step(
            "h23-hermes-commit-record",
            [
                "git",
                "-C",
                str(self.clone),
                "rev-parse",
                "HEAD",
                "HEAD^{tree}",
            ],
            mode="fingerprint",
        )
        # Fail closed on the reviewed Hermes Core commit.
        rev = subprocess.run(
            ["git", "-C", str(self.clone), "rev-parse", "HEAD", "HEAD^{tree}"],
            capture_output=True,
            text=True,
            check=False,
            env=self.step_env(),
        )
        commit, _, tree = rev.stdout.partition("\n")
        if commit.strip().lower() != self.hermes_ref:
            raise StepFailure("h23-hermes-commit-record", "clone diverged from pinned commit")
        self.ev.event("hermes_core", commit=commit.strip(), tree=tree.strip())
        uv = shutil.which("uv", path=os.environ["PATH"])
        if uv is None:
            raise StepFailure("h24-hermes-uv-sync", "pinned uv not visible to clean-room uid")
        self.run_step(
            "h23b-uv-version",
            [uv, "--version"],
            cwd=self.home,
            timeout=60,
        )
        self.run_step(
            "h24-hermes-uv-sync",
            [uv, "sync", "--frozen", "--python", "3.14", "--group", "dev"],
            cwd=self.clone,
            timeout=1500,
            mode="fingerprint",
        )
        self.run_step(
            "h25-hermes-unmodified",
            ["git", "-C", str(self.clone), "diff", "--exit-code", "--quiet"],
            mode="fingerprint",
        )
        for argv in (
            ["git", "-C", str(self.clone), "diff", "--cached", "--exit-code", "--quiet"],
            ["git", "-C", str(self.clone), "status", "--porcelain", "--untracked-files=no"],
        ):
            proc = subprocess.run(
                argv, capture_output=True, text=True, check=False, env=self.step_env()
            )
            if proc.returncode != 0 or proc.stdout.strip():
                raise StepFailure("h25-hermes-unmodified", "Hermes Core source was modified")
        probe_script = SCRIPTS / "clean_room_provider_probe.py"
        self.run_step(
            "h26-hermes-provider-probe",
            [str(self.clone / ".venv" / "bin" / "python"), str(probe_script)],
            timeout=420,
            mode="trusted",
        )

    # -- integrity -----------------------------------------------------------
    def integrity(self) -> None:
        decoys_unchanged = all(
            hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
            for path, digest in self.decoy_hashes.items()
        )
        home_entries = sorted(entry.name for entry in self.home.iterdir())
        unexpected_home = sorted(
            set(home_entries) - set(self.home_baseline) - ALLOWED_CREATED_ENTRIES
        )
        gemini_state = (self.home / ".gemini").exists()
        owned = (
            self.launcher.stat().st_uid == self.uid
            and (self.home / ".local" / "opt" / "antigravity-acp").stat().st_uid == self.uid
        )
        scan = self._scan_hermes_home()
        self.ev.event(
            "integrity",
            decoy_files=len(self.decoy_hashes),
            decoys_unchanged=decoys_unchanged,
            home_entries=home_entries,
            baseline_home_entries=self.home_baseline,
            unexpected_home_entries=unexpected_home,
            vendor_state_created_by_server=gemini_state,
            install_owned_by_clean_room_uid=owned,
            hermes_home_files=scan["files"],
            hermes_home_shape_classes=scan["classes"],
            hermes_home_findings_outside_provider_source=scan["outside"],
        )
        if not decoys_unchanged or unexpected_home or gemini_state or not owned:
            raise StepFailure("integrity", "post-run integrity check failed")
        if scan["outside"]:
            raise StepFailure("integrity", "credential-shaped findings outside provider source")

    def _scan_hermes_home(self) -> dict[str, object]:
        provider_root = self.hermes_home / "plugins" / "model-providers" / "antigravity-acp"
        files = 0
        classes: set[str] = set()
        outside = 0
        for path in sorted(self.hermes_home.rglob("*")):
            if not path.is_file() or path.is_symlink() or path.stat().st_size > 2_000_000:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                continue
            files += 1
            found = set(_shape_classes(text))
            if not found:
                continue
            in_provider_source = path.resolve().is_relative_to(provider_root.resolve())
            # The plugin's own installed source trips the `api_key` parameter
            # annotation shape (documented false positive of the shape
            # classifier); everything else is a hard finding.
            if in_provider_source and found <= {"token-assignment"}:
                classes.update(found)
                continue
            outside += 1
            classes.update(found)
        return {"files": files, "classes": sorted(classes), "outside": outside}


def scan_file(path: Path) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = _shape_classes(text)
    if findings:
        print(
            f"clean-room evidence scan failed: {len(findings)} rule(s) tripped "
            f"({', '.join(findings)}); offending content suppressed",
            file=sys.stderr,
        )
        return 1
    print("clean-room evidence scan clean (no credential-shaped material)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scan-file",
        type=Path,
        default=None,
        help="scan a produced evidence file fail-closed and exit",
    )
    args = parser.parse_args(argv)
    if args.scan_file is not None:
        return scan_file(args.scan_file)
    evidence_path = Path(
        os.environ.get("CLEAN_ROOM_EVIDENCE_FILE", "/tmp/clean-room-evidence.jsonl")
    )
    ev = Evidence(evidence_path)
    started = time.monotonic()
    try:
        CleanRoom(ev).run_chain()
    except StepFailure as exc:
        ev.event(
            "result",
            status="FAILED",
            step=exc.step,
            error_type="StepFailure",
            steps=len(STEP_EXPECTATIONS),
            seconds=round(time.monotonic() - started, 1),
        )
        return 1
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        message = f"{type(exc).__name__}"
        detail = str(exc)
        if detail and not _shape_classes(detail):
            message = f"{message}: {detail[:200]}"
        ev.event(
            "result",
            status="FAILED",
            error=message,
            steps=len(STEP_EXPECTATIONS),
            seconds=round(time.monotonic() - started, 1),
        )
        return 1
    ev.event(
        "result",
        status="PASS",
        steps=len(STEP_EXPECTATIONS),
        real_initialize_executed=3,
        authenticate_frames_sent=0,
        prompts_sent=0,
        acp_sha256=os.environ["ACP_EXPECTED_SHA256"].strip().lower(),
        seconds=round(time.monotonic() - started, 1),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
