#!/usr/bin/env python3
"""Install and verify the official ACP server plus the generic Hermes provider.

This path is user-scoped and does not use Docker, sudo, account muxes, or private
profile/policy deployment wrappers. It manages only the versioned official server,
its launcher, and the provider code under the selected Hermes home.

historical reference boundary: the official server lifecycle is independent of provider
registration — installing, updating, verifying, or deleting the server never
touches catalog-managed plugin bytes, and the provider step refuses to overwrite
catalog-managed or unverifiable provider directories before writing anything.
The server is never downloaded or self-updated while Hermes loads ``plugin.yaml``.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(SCRIPTS))

import deploy_hermes_profiles as provider_installer  # noqa: E402
import install_official as official_installer  # noqa: E402


DEFAULT_PREFIX = Path.home() / ".local" / "opt" / "antigravity-acp"
DEFAULT_BIN_DIR = Path.home() / ".local" / "bin"
DEFAULT_HERMES_HOME = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes").expanduser()
PROBE = SCRIPTS / "acp_probe.py"

# Diagnostics NEVER echo raw server stderr. That text is NOT trusted: a server
# stuck in a login/headless-auth wait can print live credentials in shapes no
# fixed scrubber can exhaustively anticipate, so echoing even a "redacted" tail
# keeps raw untrusted text in the default error path. The default diagnostic
# carries only a deterministic, non-reversible summary — counts, a sha256
# fingerprint for correlation, and which credential-shape CLASS names were
# observed (never values). Operators who need raw output run the named manual
# probe under their own control.
_CREDENTIAL_SHAPES = (
    (
        "token-assignment",
        re.compile(
            r"(?i)\b(access[_ -]?token|refresh[_ -]?token|id[_ -]?token|api[_ -]?key|"
            r"client[_ -]?secret|oauth[_ -]?token)\b\s*[:=]"
        ),
    ),
    ("authorization-header", re.compile(r"(?i)\bauthorization\b\s*[:=]")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{6,}={0,2}")),
    ("oauth-url", re.compile(r"(?i)https?://[^\s]*(?:accounts\.google\.com|oauth)[^\s]*")),
    ("google-access-token-prefix", re.compile(r"\bya29\.[A-Za-z0-9._-]{4,}")),
    ("google-api-key-prefix", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}")),
    ("github-token-prefix", re.compile(r"\bgh[opurs]_[A-Za-z0-9]{20,}")),
    ("pem-private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("cookie-header", re.compile(r"(?i)\bcookie\b\s*[:=]")),
)


def _server_stderr_summary(text: str) -> str:
    """Non-echoing, non-reversible summary of untrusted server stderr.

    Deterministic for identical input; bounded; contains no substring of the
    server's output beyond fixed class names and the fingerprint.
    """
    raw = (text or "").encode("utf-8", "replace")
    decoded = raw.decode("utf-8", "replace")
    lines = [line for line in decoded.splitlines() if line.strip()]
    observed = sorted(
        name
        for name, pattern in _CREDENTIAL_SHAPES
        if any(pattern.search(line) for line in lines)
    )
    return (
        "server stderr suppressed (untrusted text is never echoed; "
        "credential-shaped material may be live): "
        f"{len(lines)} line(s), {len(raw)} byte(s), "
        f"sha256={hashlib.sha256(raw).hexdigest()[:16]}; "
        f"credential-shape classes observed: {', '.join(observed) if observed else 'none'}"
    )


def _launcher_name() -> str:
    return "antigravity-acp-official.cmd" if os.name == "nt" else "antigravity-acp-official"


def _provider_command(bin_dir: Path, *, require_existing: bool) -> str:
    override = os.environ.get("HERMES_ANTIGRAVITY_ACP_COMMAND", "").strip()
    override_has_path = False
    if override:
        command = override
        has_path = os.sep in command or (os.altsep is not None and os.altsep in command)
        override_has_path = has_path
        if has_path:
            resolved = Path(command).expanduser().resolve()
            command = str(resolved)
            executable = command if resolved.is_file() else None
        else:
            executable = shutil.which(command)
    else:
        launcher = bin_dir.expanduser().resolve() / _launcher_name()
        default_launcher = (Path.home() / ".local" / "bin" / _launcher_name()).resolve()
        if launcher == default_launcher:
            command = str(launcher)
            executable = command if launcher.is_file() else command
        else:
            command = _launcher_name().removesuffix(".cmd")
            executable = shutil.which(command)
    if require_existing:
        if not executable or not Path(executable).is_file():
            raise RuntimeError(
                "provider launcher is not executable from Hermes (failure "
                "class: PATH misconfiguration or missing launcher); add "
                "~/.local/bin to the Hermes process PATH or set "
                "HERMES_ANTIGRAVITY_ACP_COMMAND to the installed launcher "
                "path; run 'python3 scripts/install_acp.py install' if the "
                "launcher was never installed"
            )
        if os.name != "nt" and not os.access(executable, os.X_OK):
            raise RuntimeError(
                f"provider launcher {executable} is not executable; re-run "
                "'python3 scripts/install_acp.py install' or restore the "
                "executable bit on that launcher"
            )
    elif not executable and not override_has_path:
        raise RuntimeError(
            "custom bin directory is not on PATH; set HERMES_ANTIGRAVITY_ACP_COMMAND "
            "before installing"
        )
    return command


def _provider_status(
    hermes_home: Path,
    *,
    all_profiles: bool = False,
) -> tuple[bool, list[str]]:
    try:
        targets = provider_installer.homes(
            hermes_home.expanduser(), all_profiles=all_profiles
        )
        problems = provider_installer.verify(
            hermes_home.expanduser(), allow_missing=True, all_profiles=all_profiles
        )
    except (OSError, ValueError):
        return False, []
    present = all(
        (profile_home / "plugins" / "model-providers" / provider_installer.PROVIDER / "plugin.yaml").is_file()
        for _, profile_home in targets
    )
    return present and not problems, problems


def install(
    hermes_home: Path,
    prefix: Path,
    bin_dir: Path,
    runtime_prefix: Path | None = None,
    *,
    all_profiles: bool = False,
) -> None:
    """Install/update the pinned server and provider idempotently."""
    _provider_command(bin_dir, require_existing=False)
    hermes_home = hermes_home.expanduser()
    if hermes_home.is_symlink():
        raise ValueError("Refusing a symlinked Hermes home")
    hermes_home = hermes_home.resolve()
    hermes_home.mkdir(parents=True, exist_ok=True)
    official_installer.install(prefix, bin_dir, runtime_prefix)
    provider_installer.install(
        provider_installer.SOURCE,
        hermes_home,
        apply=True,
        files=provider_installer.REQUIRED,
        all_profiles=all_profiles,
    )
    installed, problems = _provider_status(hermes_home, all_profiles=all_profiles)
    if not installed:
        detail = "; ".join(problems[:5]) if problems else "provider files are missing"
        raise RuntimeError(
            f"provider registration verification failed after install: {detail}. "
            "Re-run 'python3 scripts/install_acp.py install'; if it repeats, "
            "inspect the provider tree under the selected Hermes home's "
            "plugins/model-providers directory"
        )
    _provider_command(bin_dir, require_existing=True)


def delete(
    hermes_home: Path,
    prefix: Path,
    bin_dir: Path,
    *,
    all_profiles: bool = False,
) -> list[str]:
    """Delete the standalone provider projections and the pinned server.

    Provider directories are removed only when this installer owns them;
    catalog-managed and unverifiable installs are refused untouched (use
    ``hermes plugins remove``). Nothing else in the Hermes home — config,
    credentials, account registries, sessions — is in scope.
    """
    hermes_home = hermes_home.expanduser()
    if hermes_home.is_symlink():
        raise ValueError("Refusing a symlinked Hermes home")
    hermes_home = hermes_home.resolve()
    reports: list[str] = []
    if hermes_home.is_dir():
        reports.extend(
            provider_installer.uninstall(hermes_home, all_profiles=all_profiles)
        )
    else:
        reports.append(f"nothing to delete (hermes home absent): {hermes_home}")
    for path in official_installer.uninstall(prefix, bin_dir):
        reports.append(f"removed: {path}")
    return reports


def status(
    hermes_home: Path,
    prefix: Path,
    bin_dir: Path,
    *,
    all_profiles: bool = False,
) -> dict[str, bool]:
    server = official_installer.status(prefix, bin_dir)
    provider_registered, _ = _provider_status(
        hermes_home.expanduser(), all_profiles=all_profiles
    )
    try:
        _provider_command(bin_dir, require_existing=True)
        executable_available = True
    except (OSError, RuntimeError):
        executable_available = False
    return {
        "official_server": server["server_installed"],
        "official_launcher": server["launcher_available"],
        "provider_registered": provider_registered,
        "provider_executable": executable_available,
    }


def verify(
    hermes_home: Path,
    prefix: Path,
    bin_dir: Path,
    runtime_prefix: Path | None = None,
    timeout: float = 30.0,
    *,
    all_profiles: bool = False,
) -> None:
    """Read-only verification of registration and an unauthenticated ACP handshake."""
    official = official_installer.verify(prefix, bin_dir, runtime_prefix)
    problems = provider_installer.verify(
        hermes_home.expanduser(), all_profiles=all_profiles
    )
    if problems:
        detail = "; ".join(problems[:5])
        raise RuntimeError(
            f"provider registration verification failed: {detail}. Re-run "
            "'python3 scripts/install_acp.py install' to redeploy the managed "
            "provider files (catalog-managed installs are never overwritten here)"
        )
    _provider_command(bin_dir, require_existing=True)
    manual_probe = f"python3 {PROBE} --timeout {timeout} -- {official['launcher']}"
    try:
        result = subprocess.run(
            [sys.executable, str(PROBE), "--timeout", str(timeout), "--", str(official["launcher"])],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired as exc:
        # Failure class: unauthenticated probe timeout / headless auth wait.
        # The official server was spawned but never finished the handshake and
        # even the probe process had to be killed. This command never
        # authenticates: an interactive or headless login wait belongs to the
        # vendor-approved auth path, outside this verify contract.
        raise RuntimeError(
            f"unauthenticated ACP initialize probe exceeded its {timeout + 5:.0f}s "
            "hard limit and was terminated (failure class: unresponsive server "
            "or headless authentication wait). This verify path never logs in, "
            "sends no prompt, and reads no credential file; completing a login "
            "belongs to a vendor-approved authentication path outside this "
            f"command. Inspect the unauthenticated handshake manually: '{manual_probe}'"
        ) from exc
    if result.returncode:
        raise RuntimeError(
            "unauthenticated ACP initialize probe failed: the official server "
            "did not complete the ACP initialize handshake (failure class: "
            "server-side initialize/login-surface failure — no login was "
            "attempted by this command and no credential was sent or read). "
            f"{_server_stderr_summary(result.stderr or '')}. "
            f"Run '{manual_probe}' to observe the handshake response directly "
            "(its timeout path also suppresses raw stderr); execute the server "
            "launcher yourself under your own control if raw server output is "
            "required"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "update", "status", "verify", "delete"), nargs="?", default="install")
    parser.add_argument("--hermes-home", type=Path, default=DEFAULT_HERMES_HOME)
    parser.add_argument("--prefix", type=Path, default=DEFAULT_PREFIX)
    parser.add_argument("--bin-dir", type=Path, default=DEFAULT_BIN_DIR)
    parser.add_argument("--runtime-prefix", type=Path, default=None)
    parser.add_argument(
        "--all-profiles",
        action="store_true",
        help="Also install or verify the provider in every named profile under the selected Hermes home",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)
    try:
        if args.action in {"install", "update"}:
            install(
                args.hermes_home,
                args.prefix,
                args.bin_dir,
                args.runtime_prefix,
                all_profiles=args.all_profiles,
            )
            print("official ACP server and Hermes provider installed; no authentication was attempted")
            return 0
        if args.action == "status":
            result = status(
                args.hermes_home,
                args.prefix,
                args.bin_dir,
                all_profiles=args.all_profiles,
            )
            for name, available in result.items():
                print(f"{name}={'available' if available else 'missing'}")
            return 0 if all(result.values()) else 1
        if args.action == "delete":
            for line in delete(
                args.hermes_home,
                args.prefix,
                args.bin_dir,
                all_profiles=args.all_profiles,
            ):
                print(line)
            print(
                "standalone provider projection and pinned official server deleted; "
                "catalog-managed installs are never removed here; no authentication or "
                "session state was touched"
            )
            return 0
        verify(
            args.hermes_home,
            args.prefix,
            args.bin_dir,
            args.runtime_prefix,
            args.timeout,
            all_profiles=args.all_profiles,
        )
        print("provider registration and unauthenticated ACP initialize verified")
        return 0
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"ACP {args.action} failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
