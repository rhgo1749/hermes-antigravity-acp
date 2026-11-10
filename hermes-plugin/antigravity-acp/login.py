"""Attended, vendor-owned ACP browser login driver (no model request).

The Google official ACP server owns the OAuth flow and its credential store.
This command sends only ACP ``initialize`` and ``authenticate``; it never
reads, copies, or inspects vendor credential files. Nothing about the account
or its models is hardcoded: authentication methods are validated against the
methods the server advertises, and the official binary is accepted only when
the launcher matches this project's installer-managed bytes exactly.

Run as ``python /path/to/plugins/model-providers/antigravity-acp/login.py``
from an interactive terminal, or let ``hermes model`` start it inline when
the server reports it is not logged in.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO
from urllib.parse import parse_qs, urlsplit

class LoginError(RuntimeError):
    """Safe, fixed-text failure without untrusted server output."""


_MAX_LINE = 65536
_PROMPT = "Open the following link to authenticate the ACP server: "
_MANAGED_MARKER = "# managed by hermes-antigravity-acp"
# The ACP protocol majors this driver speaks; the server's advertised
# protocolVersion must be one of these, never a single pinned literal.
_SUPPORTED_PROTOCOL_VERSIONS = frozenset({1})
_ENV_KEYS = frozenset({
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "TERM",
    "TMPDIR", "TEMP", "TMP", "PYTHONUTF8", "HERMES_REAL_HOME", "HERMES_HOME",
    "GEMINI_HOME", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC_COLLATE",
    "LC_MONETARY", "LC_NUMERIC", "LC_TIME", "SYSTEMROOT", "WINDIR",
    # Windows profile roots: HOME is usually unset in Windows shells, so
    # without these the official server has no home directory at all and
    # dies at startup before answering initialize (verified on hosted
    # windows-2022/windows-11-arm: full env OK, filtered env silent-timeout).
    "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
})


def _safe_auth_url(line: str) -> str | None:
    if not line.startswith(_PROMPT):
        return None
    candidate = line[len(_PROMPT):].strip()
    if any(ord(ch) < 33 or ord(ch) > 126 for ch in candidate):
        raise LoginError("Server supplied an invalid login URL; refused.")
    try:
        url = urlsplit(candidate)
        if (url.scheme != "https" or url.hostname != "accounts.google.com"
                or url.username is not None or url.password is not None
                or url.port not in (None, 443) or url.fragment
                or url.path not in ("/o/oauth2/auth", "/o/oauth2/v2/auth")):
            raise ValueError
        query = parse_qs(url.query, strict_parsing=True, keep_blank_values=True)
        forbidden = {"code", "access_token", "refresh_token", "id_token", "client_secret", "code_verifier"}
        if forbidden.intersection(key.lower() for key in query):
            raise ValueError
        redirect_values = query.get("redirect_uri", [])
        if len(redirect_values) != 1:
            raise ValueError
        redirect = urlsplit(redirect_values[0])
        if (redirect.scheme != "http" or redirect.hostname != "127.0.0.1"
                or redirect.port is None or not 1 <= redirect.port <= 65535
                or redirect.username is not None or redirect.password is not None
                or redirect.path != "/" or redirect.query or redirect.fragment):
            raise ValueError
        if query.get("response_type") != ["code"] or not query.get("client_id"):
            raise ValueError
    except (TypeError, ValueError):
        raise LoginError("Server supplied an invalid login URL; refused.") from None
    return candidate


def _child_env() -> dict[str, str]:
    # No ambient provider keys, mux control variables, or session identifiers.
    return {k: v for k, v in os.environ.items() if k.upper() in _ENV_KEYS}


def run_login(command: list[str], *, env: dict[str, str], method: str,
              timeout: float, output: TextIO,
              confirm_method=None) -> None:
    """Run the bounded stdio exchange; the command list is caller-validated.

    No server text is printed except a validated Google authorization URL to
    the user's terminal. Terminal recording or browser history may retain
    that URL. ``confirm_method`` receives the server's advertised method ids
    after ``initialize``; the requested method must be among them.
    """
    if not method or not isinstance(method, str):
        raise LoginError("An authentication method must be requested.")
    if not 0 < timeout <= 3600:
        raise LoginError("Invalid login timeout.")
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, text=True,
                                encoding="utf-8", errors="replace", bufsize=1)
    except OSError:
        raise LoginError("Could not start the official ACP server.") from None
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    child_in, child_out, child_err = proc.stdin, proc.stdout, proc.stderr
    events: queue.Queue[tuple[str, str | None]] = queue.Queue(maxsize=128)
    overflow = threading.Event()

    def emit(source: str, line: str | None) -> None:
        try:
            events.put_nowait((source, line))
        except queue.Full:
            overflow.set()

    def pump(source: str, stream: TextIO) -> None:
        try:
            while True:
                line = stream.readline(_MAX_LINE + 1)
                if not line:
                    break
                if len(line) > _MAX_LINE or not line.endswith("\n"):
                    overflow.set()
                    break
                emit(source, line)
        finally:
            emit(source, None)

    threads = [threading.Thread(target=pump, args=(name, stream), daemon=True)
               for name, stream in (("stdout", child_out), ("stderr", child_err))]
    for thread in threads:
        thread.start()

    def send(identifier: int, rpc_method: str, params: dict) -> None:
        try:
            child_in.write(json.dumps({"jsonrpc": "2.0", "id": identifier,
                                       "method": rpc_method, "params": params}) + "\n")
            child_in.flush()
        except (OSError, ValueError):
            raise LoginError("Official ACP server stopped before login completed.") from None

    deadline = time.monotonic() + timeout
    phase = "initialize"
    shown_url = False
    success = False
    auth_sent = False
    reported: LoginError | None = None
    try:
        send(1, "initialize", {
            "protocolVersion": 1,
            "clientCapabilities": {"fs": {"readTextFile": False, "writeTextFile": False},
                                   "terminal": False},
            "clientInfo": {"name": "antigravity-acp-login", "version": "1.0"},
        })
        while not success:
            if overflow.is_set():
                raise LoginError("Official ACP server output exceeded safety limits.")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LoginError("Login timed out; no automatic retry was attempted.")
            try:
                source, line = events.get(timeout=remaining)
            except queue.Empty:
                raise LoginError("Login timed out; no automatic retry was attempted.") from None
            if line is None:
                if source == "stdout":
                    raise LoginError("Official ACP server stopped before login completed.")
                continue
            if source == "stderr":
                url = _safe_auth_url(line)
                if url is not None:
                    if phase != "authenticate" or shown_url:
                        raise LoginError("Unexpected login URL; refused.")
                    output.write("Open this Google sign-in URL privately in your browser:\n" + url + "\n")
                    output.flush()
                    shown_url = True
                continue
            try:
                message = json.loads(line)
            except (ValueError, TypeError):
                raise LoginError("Official ACP server returned malformed protocol data.") from None
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise LoginError("Official ACP server returned malformed protocol data.")
            expected = 1 if phase == "initialize" else 2
            if type(message.get("id")) is not int or message["id"] != expected:
                raise LoginError("Unexpected ACP protocol message; login refused.")
            if "error" in message or not isinstance(message.get("result"), dict):
                raise LoginError("Official ACP server did not complete the requested step.")
            result = message["result"]
            if phase == "initialize":
                version = result.get("protocolVersion")
                methods = result.get("authMethods")
                if (type(version) is not int or version not in _SUPPORTED_PROTOCOL_VERSIONS
                        or not isinstance(methods, list)):
                    raise LoginError("Official ACP server returned an unsupported initialize result.")
                advertised = [
                    str(entry.get("id") or "")
                    for entry in methods if isinstance(entry, dict)
                ]
                if callable(confirm_method):
                    confirm_method(advertised)
                if method not in advertised:
                    raise LoginError("Requested authentication method is not advertised.")
                phase = "authenticate"
                auth_sent = True
                send(2, "authenticate", {"methodId": method})
            else:
                success = True
    except LoginError as exc:
        if auth_sent:
            reported = LoginError(
                f"{exc} Authentication may have completed; check before retrying."
            )
        else:
            reported = exc
        raise reported from None
    finally:
        cleanup_failed = False
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=3)
                except (subprocess.TimeoutExpired, OSError):
                    cleanup_failed = True
            except OSError:
                cleanup_failed = True
        for thread in threads:
            thread.join(timeout=2)
        try:
            child_in.close()
        except (OSError, ValueError):
            pass
        for stream, thread in zip((child_out, child_err), threads):
            # Closing a TextIOWrapper while another thread is blocked reading
            # can itself hang on its internal lock. Leave it to process exit.
            if thread.is_alive():
                cleanup_failed = True
            else:
                stream.close()
        if cleanup_failed:
            if success:
                # The authenticate response arrived before cleanup hung on a
                # pipe handle still held open by a server child process
                # (normal on Windows). The outcome is known; surfacing the
                # same failure text as a real failure sends users into
                # needless retries.
                output.write(
                    "Warning: server process cleanup was incomplete; "
                    "authentication itself completed.\n"
                )
            elif reported is not None:
                raise LoginError(
                    f"{reported} (server cleanup was also incomplete)"
                ) from None
            else:
                raise LoginError(
                    "Server cleanup did not complete; authentication outcome "
                    "may be unknown. Check before retrying."
                ) from None
    # Process any stderr lines that raced the final JSON-RPC response. This is
    # important for validating a promptly exiting server, including tests.
    while not events.empty():
        source, line = events.get_nowait()
        if source == "stderr" and line is not None:
            try:
                url = _safe_auth_url(line)
            except LoginError:
                raise LoginError(
                    "A login URL was refused after the server response; "
                    "authentication may have completed. Check before retrying."
                ) from None
            if url is not None:
                if phase != "authenticate" or shown_url:
                    raise LoginError(
                        "Unexpected login URL after the server response; "
                        "authentication may have completed. Check before retrying."
                    )
                output.write("Open this Google sign-in URL privately in your browser:\n" + url + "\n")
                output.flush()
                shown_url = True
    if overflow.is_set():
        raise LoginError(
            "Official ACP server output exceeded safety limits; "
            "authentication may have completed. Check before retrying."
        )


def _launcher_name() -> str:
    return "antigravity-acp-official.cmd" if os.name == "nt" else "antigravity-acp-official"


def _managed_launcher_bodies(target: str, args: tuple[str, ...] | list[str]) -> set[str]:
    """Exactly the launcher bodies the official installer writes (POSIX + cmd).

    Mirrors scripts/install_official._launcher_variants; a launcher is only
    ever spawned when its full text is one of these byte-for-byte.
    """
    if os.name == "nt":
        joined = " ".join(args)
        return {
            f'@echo off\nREM managed by hermes-antigravity-acp\n"{target}" {joined} %*\n',
            f'@echo off\n"{target}" {joined} %*\n',
        }
    quoted_target = target.replace("'", "'\\''")
    quoted_args = " ".join("'" + arg.replace("'", "'\\''") + "'" for arg in args)
    suffix = f" {quoted_args}" if quoted_args else ""
    command = f"exec '{quoted_target}'{suffix} \"$@\"\n"
    return {
        f"#!/bin/sh\n{_MANAGED_MARKER}\n{command}",
        f"#!/bin/sh\n{command}",
    }


@dataclass(frozen=True)
class _DistributionPin:
    url: str
    executable: str
    sha256: str
    args: tuple[str, ...] = ()


_PUBLISHER_VERSION = "1.4.4"
_PUBLISHER_PINS: dict[tuple[str, str], _DistributionPin] = {
    ("linux", "x86_64"): _DistributionPin(
        url=(
            "https://dl.google.com/agy-extensions/releases/linux/"
            f"agy-acp-server-{_PUBLISHER_VERSION}-linux-x86_64.zip"
        ),
        executable="agy_acp_server.par",
        sha256="baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a",
        args=("--uid=",),
    ),
    ("linux", "aarch64"): _DistributionPin(
        url=(
            "https://dl.google.com/agy-extensions/releases/linux/"
            f"agy-acp-server-{_PUBLISHER_VERSION}-linux-arm64.zip"
        ),
        executable="agy_acp_server.par",
        sha256="b0273227c07cfa1ea5c1d9ff869b64c5b2b39b98862081fcd4c597ec316e0c57",
        args=("--uid=",),
    ),
    ("darwin", "arm64"): _DistributionPin(
        url=(
            "https://dl.google.com/agy-extensions/releases/macos/"
            f"agy-acp-server-{_PUBLISHER_VERSION}-darwin-arm64.zip"
        ),
        executable="agy_acp_server.par",
        sha256="a3cf324046396380fcd8c055a4a4c83ac4ea74a38ea883ccbfce5ca1e9927ae9",
        args=(),
    ),
    ("windows", "amd64"): _DistributionPin(
        url=(
            "https://dl.google.com/agy-extensions/releases/windows/"
            f"agy-acp-server-{_PUBLISHER_VERSION}-windows-x86_64.zip"
        ),
        executable="agy_acp_server.exe",
        sha256="4b68e5936a3d7a60b520aa1ee9479c8be58c43e015f026dc41e7ad17ec54d427",
        args=(),
    ),
    ("windows", "arm64"): _DistributionPin(
        url=(
            "https://dl.google.com/agy-extensions/releases/windows/"
            f"agy-acp-server-{_PUBLISHER_VERSION}-windows-arm64.zip"
        ),
        executable="agy_acp_server.exe",
        sha256="655835b095e160d726ee894a10e56960a9a81b03503edbd348079336163b28de",
        args=(),
    ),
}


def _normalize_platform(system: str | None = None, machine: str | None = None) -> tuple[str, str]:
    import platform as _platform

    sys_name = (system or _platform.system()).strip().lower()
    mach_name = (machine or _platform.machine()).strip().lower()
    aliases = {
        "x86-64": "amd64" if sys_name == "windows" else "x86_64",
        "x64": "amd64" if sys_name == "windows" else "x86_64",
        "x86_64": "amd64" if sys_name == "windows" else "x86_64",
        "amd64": "amd64" if sys_name == "windows" else "x86_64",
        "aarch64": "arm64" if sys_name in {"darwin", "windows"} else "aarch64",
        "arm64": "arm64" if sys_name in {"darwin", "windows"} else "aarch64",
    }
    return sys_name, aliases.get(mach_name, mach_name)


def _registry_path() -> Path:
    """The publisher-pin registry source for this driver.

    Repository checkout by default; ``HERMES_ANTIGRAVITY_ACP_REGISTRY`` may
    point at an explicit registry file (used by offline tests and by any
    packaging layout that vendors the pin beside the plugin).
    """
    override = os.environ.get("HERMES_ANTIGRAVITY_ACP_REGISTRY", "").strip()
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parents[2] / "antigravity_acp" / "registry.py"


def _load_publisher_pins() -> dict[str, dict[tuple[str, str], _DistributionPin]]:
    """``{version: {(system, machine): DistributionPin}}`` from registry or embedded pins.

    When running inside an installed plugin without a repository checkout,
    the trustworthy publisher pins embedded in this plugin are used.
    ``HERMES_ANTIGRAVITY_ACP_REGISTRY`` may point to an explicit registry file
    (used by offline tests and custom layouts); missing explicit registry files
    fail closed.
    """
    override = os.environ.get("HERMES_ANTIGRAVITY_ACP_REGISTRY", "").strip()
    if override:
        registry_path = Path(override).expanduser()
        if not registry_path.is_file():
            raise LoginError("Publisher pin registry is unavailable; login refused.")
    else:
        registry_path = _registry_path()

    if registry_path.is_file():
        try:
            source = registry_path.read_text(encoding="utf-8")
            namespace: dict = {}
            exec(compile(source, str(registry_path), "exec"), namespace)
            version = str(namespace["VERSION"])
            raw_dists = namespace["_DISTRIBUTIONS"]
            pins: dict[tuple[str, str], _DistributionPin] = {}
            for key, dist in raw_dists.items():
                pins[key] = _DistributionPin(
                    url=getattr(dist, "url", ""),
                    executable=dist.executable,
                    sha256=dist.sha256,
                    args=tuple(getattr(dist, "args", ())),
                )
            return {version: pins}
        except (OSError, UnicodeError, SyntaxError, KeyError, TypeError, ValueError):
            raise LoginError("Publisher pin registry is unreadable; login refused.") from None

    return {_PUBLISHER_VERSION: dict(_PUBLISHER_PINS)}


def _pinned_digests() -> dict[str, dict[str, str]]:
    """``{version: {executable: sha256}}`` view from the publisher pin registry."""
    pins = _load_publisher_pins()
    return {
        version: {dist.executable: dist.sha256 for dist in dists.values()}
        for version, dists in pins.items()
    }


def _find_or_acquire_archive(version_dir: Path, dist: _DistributionPin) -> Path | None:
    """Find a retained, publisher-pinned archive without network access."""
    import hashlib as _hashlib
    import urllib.parse as _urlparse

    expected_sha = dist.sha256.strip().lower()
    if len(expected_sha) != 64 or any(c not in "0123456789abcdef" for c in expected_sha):
        return None

    candidate_names: list[str] = []
    if dist.url:
        parsed_name = Path(_urlparse.urlsplit(dist.url).path).name
        if parsed_name:
            candidate_names.append(parsed_name)
    candidate_names.extend(["official.zip", "archive.zip"])

    candidates: list[Path] = [version_dir / name for name in candidate_names]
    if version_dir.is_dir():
        for p in sorted(version_dir.iterdir()):
            if p.is_file() and not p.is_symlink() and p.suffix.lower() == ".zip":
                if p not in candidates:
                    candidates.append(p)

    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            try:
                digest = _hashlib.sha256()
                with candidate.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() == expected_sha:
                    return candidate
            except OSError:
                continue

    # Login must never download or replace files implicitly.
    return None


def _verify_binary_against_archive(
    target: Path, archive_path: Path, executable_name: str
) -> bool:
    """Verify that target executable bytes match the publisher archive member."""
    import zipfile as _zipfile

    try:
        with _zipfile.ZipFile(archive_path) as zf:
            members = [
                m
                for m in zf.infolist()
                if not m.is_dir() and Path(m.filename).name == executable_name
            ]
            if len(members) != 1:
                return False
            with zf.open(members[0]) as archived, target.open("rb") as installed:
                while True:
                    chunk = archived.read(1024 * 1024)
                    if chunk != installed.read(1024 * 1024):
                        return False
                    if not chunk:
                        return True
    except (OSError, _zipfile.BadZipFile, KeyError, RuntimeError):
        return False


def _resolve_official_command() -> tuple[list[str], list[str]]:
    """The installer-managed official launcher and its recorded extra args.

    The launcher is accepted only when its exact text is a body the official
    installer writes for a binary that (a) sits at the installer's versioned
    path, (b) matches the publisher's pinned archive executable byte-for-byte,
    and (c) whose archive matches the verified publisher SHA-256 pin. Returns
    (spawn_command, launcher_extra_args).
    """
    command = str(Path.home() / ".local" / "bin" / _launcher_name())
    launcher = Path(command)
    if not launcher.is_file() or launcher.is_symlink():
        raise LoginError("Official ACP launcher is missing; run the project installer first.")
    try:
        raw = launcher.read_bytes().decode("utf-8")
    except (OSError, UnicodeError):
        raise LoginError("Official ACP launcher is unreadable; login refused.") from None
    texts = {raw, raw.replace("\r\n", "\n")}

    pins = _load_publisher_pins()
    missing_archive = False
    verified_archive = False
    prefix = Path.home() / ".local" / "opt" / "antigravity-acp"
    for version, dists in pins.items():
        version_dir = prefix / version
        if version_dir.is_symlink() or not version_dir.is_dir():
            continue
        dist = dists.get(_normalize_platform())
        if dist is None:
            continue
        target = version_dir / dist.executable
        if target.is_symlink() or not target.is_file():
            continue
        archive_path = _find_or_acquire_archive(version_dir, dist)
        if archive_path is None:
            missing_archive = True
            continue
        verified_archive = True
        if not _verify_binary_against_archive(target, archive_path, dist.executable):
            continue
        for args in _candidate_launch_args(target):
            for body in _managed_launcher_bodies(str(target), args):
                if body in texts:
                    # Windows CreateProcess cannot execute a .cmd directly.
                    # After validating it, start the pinned executable itself.
                    if os.name == "nt":
                        return [str(target), *args], list(args)
                    return [command], list(args)
    if missing_archive and not verified_archive:
        raise LoginError("Verified official ACP archive is missing or invalid; run the project installer again.")
    raise LoginError("Official ACP launcher is not managed; login refused.")


def _candidate_launch_args(target: Path) -> tuple[tuple[str, ...], ...]:
    """Launcher argument sets this project's installers have shipped.

    Historical plus current contracts: no-args (user-scoped generic install)
    and the ``--uid=`` registry form. The launcher text must match one of
    these bodies byte-for-byte; unknown shapes are refused.
    """
    return ((), ("--uid=",))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method", default=None,
                        help="ACP authentication method id; defaults to oauth-personal "
                             "and is always re-validated against the server's advertised methods.")
    parser.add_argument("--timeout", type=float, default=330.0)
    args = parser.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Interactive terminal required; unattended login is refused.", file=sys.stderr)
        return 2
    if any(os.environ.get(key, "").strip() for key in (
        "HERMES_ANTIGRAVITY_ACP_COMMAND", "HERMES_ANTIGRAVITY_ACP_ARGS",
    )):
        print("Custom ACP command is set; select a direct official server instead.", file=sys.stderr)
        return 2
    plugin_dir = Path(__file__).resolve().parent
    if any((plugin_dir / name).exists() or (plugin_dir / name).is_symlink()
           for name in ("launch_config.json", "par.txt")):
        print("Custom provider launch configuration detected; direct login refused.", file=sys.stderr)
        return 2
    method = args.method or "oauth-personal"
    print("The official server performs login and manages its own credentials.")
    print("Confirm that this route is permitted by your Google terms before continuing.")
    print("Do not share the login URL or record the terminal. No model prompt is sent.")
    try:
        if input("Type LOGIN to continue: ").strip() != "LOGIN":
            print("Login cancelled.")
            return 1
        command, _ = _resolve_official_command()
        run_login(command, env=_child_env(), method=method,
                  timeout=args.timeout, output=sys.stdout)
    except (OSError, RuntimeError, ValueError, EOFError) as exc:
        # Vendor output and exception text are not trusted.
        message = str(exc) if isinstance(exc, LoginError) else "Login could not be completed."
        print(message, file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Login interrupted. If the server started, authentication may "
              "have completed; check before retrying.", file=sys.stderr)
        return 130
    print("Official ACP authenticate completed. Model inference was not run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
