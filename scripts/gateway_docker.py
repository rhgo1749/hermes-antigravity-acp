#!/usr/bin/env python3
"""One disposable non-root Docker boundary for the existing Hosted Gateway lane.

No pulled image, daemon configuration, privilege grant, host-network listener,
Docker socket forwarding, operating-home mount or direct-execution fallback.
The tiny rootfs uses only read-only trusted runner binaries/dependency inputs.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET

POLICY = "/phasec-policy.json"
LIMIT = 128
CHECKS = ("nonroot", "capabilities_empty", "no_new_privileges", "readonly_root", "pid_namespace",
          "network_namespace", "proc_inventory", "outside_read_denied", "outside_write_denied",
          "source_write_denied", "root_write_denied", "external_connect_denied", "loopback_available")


def namespace_verified() -> bool:
    """Recheck kernel facts; an environment boolean or a writable receipt is not proof."""
    if os.environ.get("PHASE_C_DOCKER_POLICY") != POLICY:
        return False
    try:
        policy = json.loads(Path(POLICY).read_text())
        fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        return (os.getuid() == policy["uid"] != 0 and os.getgid() == policy["gid"]
                and int(fields["CapEff"].strip(), 16) == 0 and fields["NoNewPrivs"].strip() == "1"
                and os.readlink("/proc/self/ns/pid") == os.readlink("/proc/1/ns/pid") != policy["host_pid_ns"]
                and os.readlink("/proc/self/ns/net") != policy["host_net_ns"]
                and not Path(f'/proc/{policy["outside_pid"]}').exists()
                and Path("/gw/host-boundary-verified").is_file())
    except (OSError, ValueError, KeyError, TypeError):
        return False


def validate_confinement(record: dict) -> list[str]:
    proof = record.get("confinement")
    if not isinstance(proof, dict) or proof.get("status") != "PASS":
        return ["confinement_missing_or_nonpass"]
    checks = proof.get("checks")
    if not isinstance(checks, dict) or any(checks.get(name) is not True for name in CHECKS):
        return ["confinement_checks_incomplete"]
    identities = [proof.get(name) for name in ("pid_namespace_sha256", "host_pid_namespace_sha256")]
    if (any(not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value) for value in identities)
            or identities[0] == identities[1]):
        return ["namespace_identity_not_separated"]
    return []


def validate_docker_receipt(record: dict) -> list[str]:
    errors = validate_confinement(record)
    docker = record.get("docker_execution")
    required = ("config_verified", "owned_pid_namespace_verified", "outside_canary_unchanged", "container_removed", "image_removed")
    if (not isinstance(docker, dict) or docker.get("status") != "PASS"
            or any(docker.get(name) is not True for name in required)):
        errors.append("docker_execution_not_verified")
    if type(record.get("final_namespace_live_count")) is not int or record["final_namespace_live_count"] != 1:
        errors.append("container_process_residue")
    if type(record.get("final_namespace_process_count")) is not int or record["final_namespace_process_count"] != 1:
        errors.append("container_zombie_residue")
    regression = record.get("regression")
    if (not isinstance(regression, dict) or regression.get("status") != "PASS"
            or any(type(regression.get(name)) is not int for name in ("tests", "failures", "errors", "skipped"))
            or regression["tests"] < 1 or regression["failures"] != 0 or regression["errors"] != 0
            or not 0 <= regression["skipped"] <= regression["tests"]):
        errors.append("container_regression_not_pass")
    return errors


def mounts_for(repo: Path, core: Path) -> list[Path]:
    """No HOME prefix mounts: only exact source, interpreter and binary inputs."""
    candidates = [repo, core, Path(sys.prefix), Path(sys.base_prefix), Path("/usr/bin"), Path("/usr/lib")]
    candidates += [p for p in (Path("/usr/lib64"), Path("/usr/share/git-core"), Path("/usr/share/zoneinfo")) if p.exists()]
    result: list[Path] = []
    for path in sorted(set(p.resolve(strict=True) for p in candidates), key=lambda p: len(p.parts)):
        if path == Path("/") or path in {Path.home(), Path("/home"), Path("/opt/data"), Path("/var/run")}:
            raise ValueError("unsafe_mount")
        if not any(path.is_relative_to(parent) for parent in result):
            result.append(path)
    return result


def docker_options(uid: int, gid: int, mounts: list[Path], work: Path, policy: Path) -> list[str]:
    if uid <= 0 or gid <= 0:
        raise ValueError("nonroot_identity_required")
    options = ["--user", f"{uid}:{gid}", "--cap-drop=ALL", "--security-opt=no-new-privileges",
               "--network=none", "--ipc=none", "--read-only", "--pids-limit", str(LIMIT),
               "--memory=2g", "--memory-swap=2g", "--cpus=2", "--restart=no", "--pull=never"]
    for source in mounts:
        if "," in str(source):
            raise ValueError("unsafe_mount_spelling")
        options += ["--mount", f"type=bind,src={source},dst={source},readonly"]
    options += ["--mount", f"type=bind,src={work},dst=/gw",
                "--mount", f"type=bind,src={policy},dst={POLICY},readonly"]
    return options


def config_verified(inspect: dict, uid: int, gid: int, mounts: list[Path], work: Path, policy: Path) -> bool:
    host = inspect.get("HostConfig", {})
    expected = {str(path): (str(path), False) for path in mounts}
    expected.update({"/gw": (str(work), True), POLICY: (str(policy), False)})
    actual = {m["Destination"]: (m["Source"], m["RW"]) for m in inspect.get("Mounts", [])}
    return (inspect.get("Config", {}).get("User") == f"{uid}:{gid}"
            and host.get("Privileged") is False and host.get("ReadonlyRootfs") is True
            and host.get("NetworkMode") == "none" and host.get("PidMode") == ""
            and host.get("IpcMode") == "none" and host.get("PidsLimit") == LIMIT
            and host.get("Memory") == 2 * 1024**3 and host.get("MemorySwap") == 2 * 1024**3
            and host.get("NanoCpus") == 2 * 10**9 and not host.get("PortBindings")
            and not host.get("CapAdd") and host.get("CapDrop") == ["ALL"]
            and any(s in {"no-new-privileges", "no-new-privileges=true"} for s in host.get("SecurityOpt", []))
            and not host.get("Devices") and not host.get("DeviceRequests") and actual == expected)


def rootfs_bytes(uid: int, gid: int) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name in ("usr", "etc", "dev", "proc", "gw", "tmp", "run"):
            item = tarfile.TarInfo(name)
            item.type, item.mode = tarfile.DIRTYPE, 0o755
            archive.addfile(item)
        for name, target in (("bin", "usr/bin"), ("sbin", "usr/bin"), ("lib", "usr/lib"), ("lib64", "usr/lib64")):
            item = tarfile.TarInfo(name)
            item.type, item.linkname = tarfile.SYMTYPE, target
            archive.addfile(item)
        for name, data in {"etc/passwd": f"root:x:0:0::/:/bin/false\nfixture:x:{uid}:{gid}::/gw/os-home:/bin/false\n",
                           "etc/group": f"root:x:0:\nfixture:x:{gid}:\n",
                           "etc/nsswitch.conf": "passwd: files\ngroup: files\nhosts: files\n"}.items():
            item = tarfile.TarInfo(name)
            content = data.encode()
            item.mode, item.size = 0o644, len(content)
            archive.addfile(item, io.BytesIO(content))
    return output.getvalue()


def _open_denied(path: str, flags: int) -> bool:
    # No Python audit hooks are installed in this parent. Use libc as a negative
    # control anyway so Python hook refusals cannot masquerade as kernel proof.
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.open(os.fsencode(path), flags, 0o600)
    if fd >= 0:
        os.close(fd)
        return False
    return ctypes.get_errno() in {errno.ENOENT, errno.EACCES, errno.EPERM, errno.EROFS}


def inside() -> int:
    policy = json.loads(Path(POLICY).read_text())
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    with socket.socket() as connection:
        connection.settimeout(0.5)
        external = connection.connect_ex(("198.51.100.1", 443))
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        loopback = connection.getsockname()[0] == "127.0.0.1"
    import psutil
    inventory = {p.pid for p in psutil.process_iter()}
    checks = {"nonroot": os.getuid() == policy["uid"] != 0 and os.getgid() == policy["gid"],
              "capabilities_empty": int(status["CapEff"].strip(), 16) == 0,
              "no_new_privileges": status["NoNewPrivs"].strip() == "1",
              "readonly_root": any(parts[4] == "/" and "ro" in parts[5].split(",")
                                   for parts in (line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines())),
              "pid_namespace": os.getpid() == 1 and os.readlink("/proc/self/ns/pid") != policy["host_pid_ns"],
              "network_namespace": os.readlink("/proc/self/ns/net") != policy["host_net_ns"],
              "proc_inventory": inventory == {1} and not Path(f'/proc/{policy["outside_pid"]}').exists(),
              "outside_read_denied": _open_denied(policy["outside_file"], os.O_RDONLY),
              "outside_write_denied": _open_denied(policy["outside_file"], os.O_WRONLY),
              "source_write_denied": _open_denied(policy["repo"] + "/AGENTS.md", os.O_WRONLY),
              "root_write_denied": _open_denied("/etc/passwd", os.O_WRONLY),
              "external_connect_denied": external in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM},
              "loopback_available": loopback}
    boundary = {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks,
                "pid_namespace": os.readlink("/proc/self/ns/pid"),
                "pid_namespace_sha256": hashlib.sha256(os.readlink("/proc/self/ns/pid").encode()).hexdigest(),
                "host_pid_namespace_sha256": hashlib.sha256(policy["host_pid_ns"].encode()).hexdigest()}
    Path("/gw/confinement.json").write_text(json.dumps(boundary))
    if boundary["status"] != "PASS":
        return 1
    Path("/gw/boundary-ready").touch()
    deadline = time.monotonic() + 20
    while not Path("/gw/host-boundary-verified").exists():
        if time.monotonic() >= deadline:
            return 1
        time.sleep(0.05)
    if not namespace_verified():
        return 1
    # Run every test file with the same real Core dependencies, inside the
    # exercised boundary. Raw test output and case/session IDs stay private.
    environment = dict(os.environ)
    for name in ("os-home", "regression-home", "regression-tmp", "regression-config"):
        Path("/gw", name).mkdir(exist_ok=True)
    environment.update({"HOME": "/gw/os-home", "HERMES_HOME": "/gw/regression-home",
                        "TMPDIR": "/gw/regression-tmp", "XDG_CONFIG_HOME": "/gw/regression-config",
                        "PYTHONPATH": policy["core"], "TZ": "UTC", "LANG": "C.UTF-8",
                        "HERMES_DISABLE_LAZY_INSTALLS": "1", "OPENAI_API_KEY": "synthetic-offline-test-key"})
    with Path("/gw/regression.log").open("wb") as output:
        regression_run = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests",
                                         "--junitxml=/gw/regression.xml"], cwd=policy["repo"], env=environment,
                                        stdout=output, stderr=subprocess.STDOUT, timeout=180)
    suite = ET.parse("/gw/regression.xml").getroot().findall("testsuite")
    if len(suite) != 1:
        return 1
    regression: dict = {name: int(suite[0].get(name, "-1")) for name in ("tests", "failures", "errors", "skipped")}
    regression["status"] = "PASS" if (regression_run.returncode == 0 and regression["tests"] > 0
                                        and regression["errors"] == regression["failures"] == 0) else "FAIL"
    # Same real driver/CLI, inside this namespace; never execute it on the host.
    from gateway_e2e import REQUIRED_STAGES, _git, main as gateway_main
    if regression["status"] != "PASS":
        Path("/gw/verification.json").write_text(json.dumps({"schema_version": 1, "status": "FAIL",
            "candidate_sha": policy["candidate"], "hermes_commit": _git(Path(policy["core"]), "rev-parse", "HEAD"),
            "regression": regression, "stages": {name: {"status": "NOT_RUN"} for name in REQUIRED_STAGES}}))
        return 1
    result = gateway_main(["--hermes-root", policy["core"], "--candidate-sha", policy["candidate"],
                           "--output", "/gw/verification.json"])
    record = json.loads(Path("/gw/verification.json").read_text())
    record["regression"] = regression
    record["confinement"] = {key: boundary[key] for key in ("status", "checks", "pid_namespace_sha256", "host_pid_namespace_sha256")}
    while True:
        try:
            if os.waitpid(-1, os.WNOHANG)[0] == 0:
                break
        except ChildProcessError:
            break
    record["final_namespace_live_count"] = sum(p.status() != psutil.STATUS_ZOMBIE for p in psutil.process_iter())
    record["final_namespace_process_count"] = sum(1 for _ in psutil.process_iter())
    if record["final_namespace_process_count"] != 1:
        record["status"] = "FAIL"
        result = 1
    Path("/gw/verification.json").write_text(json.dumps(record, indent=2) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--hermes-root", type=Path)
    parser.add_argument("--candidate-sha")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.inside:
        return inside()
    if args.hermes_root is None or args.output is None or args.candidate_sha is None:
        parser.error("Core, candidate and output are required")
    try:
        from gateway_e2e import REQUIRED_STAGES, _git, validate_receipt
    except ImportError:
        from scripts.gateway_e2e import REQUIRED_STAGES, _git, validate_receipt
    repo, core = Path(__file__).resolve().parent.parent, args.hermes_root.resolve(strict=True)
    if _git(repo, "rev-parse", "HEAD") != args.candidate_sha:
        parser.error("candidate must equal checkout HEAD")
    record = {"schema_version": 1, "status": "FAIL", "candidate_sha": args.candidate_sha,
              "hermes_commit": _git(core, "rev-parse", "HEAD"),
              "stages": {name: {"status": "NOT_RUN", "detail": "not_executed"} for name in REQUIRED_STAGES}}
    image = container = None
    process = None
    directory = None
    started = time.monotonic()
    docker_env = {"HOME": "/nonexistent", "PATH": "/usr/bin:/bin", "DOCKER_HOST": "unix:///var/run/docker.sock"}
    def docker(*command, check=True, **kwargs):
        return subprocess.run(["docker", *command], env=docker_env, capture_output=True, timeout=30, check=check, **kwargs)
    try:
        if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
                or os.environ.get("RUNNER_OS") != "Linux" or not Path("/var/run/docker.sock").exists()):
            raise RuntimeError("hosted_docker_unavailable")
        if os.getuid() == 0 or os.getgid() == 0:
            raise RuntimeError("nonroot_runner_required")
        docker("version", "--format", "{{.Server.Version}}")
        directory = tempfile.mkdtemp(prefix="gateway-docker-")
        root = Path(directory).resolve()
        work = root / "work"
        work.mkdir()
        canary = secrets.token_hex(16)
        (root / "outside-canary").write_text(canary)
        policy = {"uid": os.getuid(), "gid": os.getgid(), "repo": str(repo), "core": str(core),
                  "candidate": args.candidate_sha, "host_pid_ns": os.readlink("/proc/self/ns/pid"),
                  "host_net_ns": os.readlink("/proc/self/ns/net"), "outside_pid": os.getpid(),
                  "outside_file": str(root / "outside-canary")}
        policy_file = root / "policy.json"
        policy_file.write_text(json.dumps(policy))
        mounts = mounts_for(repo, core)
        image = docker("import", "-", input=rootfs_bytes(os.getuid(), os.getgid())).stdout.decode().strip()
        if not image.startswith("sha256:"):
            raise RuntimeError("image_identity_missing")
        options = docker_options(os.getuid(), os.getgid(), mounts, work, policy_file)
        environment = {"HOME": "/gw/os-home", "HERMES_HOME": "/gw/outer-home", "TMPDIR": "/gw",
                       "PATH": str(Path(sys.executable).parent) + ":/usr/bin:/bin", "LD_LIBRARY_PATH": str(Path(sys.base_prefix) / "lib"),
                       "PYTHONDONTWRITEBYTECODE": "1", "PHASE_C_DOCKER_POLICY": POLICY, "GIT_OPTIONAL_LOCKS": "0",
                       "GITHUB_ACTIONS": "true", "OPENBLAS_NUM_THREADS": "1"}
        for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
            environment[key] = os.environ.get(key, "missing")
        for key, value in environment.items():
            options += ["--env", key + "=" + value]
        options += ["--workdir", str(repo), "--entrypoint", sys.executable]
        container = docker("create", *options, image, "-B", str(Path(__file__).resolve()), "--inside").stdout.decode().strip()
        facts = json.loads(docker("inspect", container).stdout)[0]
        if not config_verified(facts, os.getuid(), os.getgid(), mounts, work, policy_file):
            raise RuntimeError("docker_config_not_verified")
        with (root / "container.log").open("wb") as log:
            process = subprocess.Popen(["docker", "start", "--attach", container], env=docker_env, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 20
            while not (work / "boundary-ready").exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("container_boundary_not_ready")
                time.sleep(0.05)
            facts = json.loads(docker("inspect", container).stdout)[0]
            pid = facts["State"]["Pid"]
            observed = json.loads((work / "confinement.json").read_text())
            host_verified = (pid > 0 and os.readlink(f"/proc/{pid}/ns/pid") == observed["pid_namespace"] != policy["host_pid_ns"]
                             and config_verified(facts, os.getuid(), os.getgid(), mounts, work, policy_file))
            if not host_verified or observed.get("status") != "PASS":
                raise RuntimeError("owned_container_namespace_not_verified")
            (work / "host-boundary-verified").touch()
            process.wait(timeout=360)
        if not (work / "verification.json").exists():
            raise RuntimeError("container_gateway_receipt_missing")
        record = json.loads((work / "verification.json").read_text())
        if process.returncode != 0:
            record["status"] = "FAIL"
        record["docker_execution"] = {"status": "FAIL", "config_verified": True,
                                      "outside_canary_unchanged": (root / "outside-canary").read_text() == canary,
                                      "image_id": image, "owned_pid_namespace_verified": host_verified}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Preserve only the sanitized result before the private root is removed.
        args.output.write_text(json.dumps(record, indent=2) + "\n")
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        allowed = {"hosted_docker_unavailable", "nonroot_runner_required", "image_identity_missing", "docker_config_not_verified",
                   "container_boundary_not_ready", "owned_container_namespace_not_verified", "container_gateway_receipt_missing"}
        reason = str(exc) if isinstance(exc, RuntimeError) and str(exc) in allowed else type(exc).__name__
        record["status"] = "FAIL"
        record["stages"]["isolation"] = {"status": "BLOCKED", "detail": reason}
    finally:
        removed = image_removed = False
        if container:
            removal = docker("rm", "--force", container, check=False)
            inspect = docker("inspect", container, check=False)
            removed = removal.returncode == 0 and inspect.returncode != 0 and b"No such" in inspect.stderr
        if process is not None:
            process.wait(timeout=15)
        if image:
            removal = docker("image", "rm", image, check=False)
            inspect = docker("image", "inspect", image, check=False)
            image_removed = removal.returncode == 0 and inspect.returncode != 0 and b"No such" in inspect.stderr
        if directory is not None and (container is None or removed):
            shutil.rmtree(directory)
        record["docker_duration_seconds"] = round(time.monotonic() - started, 3)
        facts = record.setdefault("docker_execution", {})
        facts.update({"container_removed": removed, "image_removed": image_removed})
        facts["status"] = "PASS" if (removed and image_removed and facts.get("config_verified")
                                      and facts.get("owned_pid_namespace_verified") and facts.get("outside_canary_unchanged")) else "FAIL"
        if validate_docker_receipt(record) or validate_receipt(record, args.candidate_sha):
            record["status"] = "FAIL"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps(record, sort_keys=True))
    return 0 if record["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
