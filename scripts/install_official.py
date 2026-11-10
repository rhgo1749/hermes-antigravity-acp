#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from antigravity_acp.registry import VERSION, resolve_distribution


def _launcher_name() -> str:
    return "antigravity-acp-official.cmd" if os.name == "nt" else "antigravity-acp-official"


def _validate_archive_pin(expected_sha256: str) -> str:
    """Fail closed before any download when the registry pin is unusable."""
    normalized = (expected_sha256 or "").strip().lower()
    if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
        raise RuntimeError("Official ACP archive has no verifiable SHA-256 pin")
    return normalized


def _verify_archive_digest(archive: Path, expected_sha256: str) -> None:
    """Compare the downloaded archive against the publisher pin before use."""
    expected = _validate_archive_pin(expected_sha256)
    digest = hashlib.sha256()
    with archive.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected:
        raise RuntimeError(
            "Official ACP archive SHA-256 mismatch: the downloaded archive does "
            "not match the reviewed publisher pin in antigravity_acp/registry.py "
            f"(expected {expected[:12]}..., got {actual[:12]}...). This is a "
            "tampered or corrupted download; the archive was rejected before "
            "extraction and no existing server or launcher was changed. Re-run "
            "'python3 scripts/install_official.py'; if the mismatch persists, "
            "do NOT install these bytes — re-verify the pin against Google's "
            "first-party update feed documented in antigravity_acp/registry.py"
        )


def _find_executable(root: Path, name: str) -> Path:
    matches = [p for p in root.rglob(name) if p.is_file()]
    if len(matches) != 1:
        raise RuntimeError(f"Expected exactly one {name!r} in archive, found {len(matches)}")
    return matches[0]


def _ensure_runtime_executables(version_dir: Path, executable: Path) -> None:
    if os.name == "nt":
        return
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    for companion in version_dir.rglob("localharness_external"):
        if companion.is_file():
            companion.chmod(
                companion.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            )


def _launcher_variants(target: Path, default_args: tuple[str, ...]) -> tuple[str, str]:
    """The current and legacy launcher bodies this installer considers managed."""
    if os.name == "nt":
        joined_args = " ".join(default_args)
        content = f'@echo off\nREM managed by hermes-antigravity-acp\n"{target}" {joined_args} %*\n'
        legacy = f'@echo off\n"{target}" {joined_args} %*\n'
    else:
        quoted_target = str(target).replace("'", "'\\''")
        quoted_args = " ".join("'" + arg.replace("'", "'\\''") + "'" for arg in default_args)
        suffix = f" {quoted_args}" if quoted_args else ""
        command = f"exec '{quoted_target}'{suffix} \"$@\"\n"
        content = f"#!/bin/sh\n# managed by hermes-antigravity-acp\n{command}"
        legacy = f"#!/bin/sh\n{command}"
    return content, legacy


def _write_launcher(path: Path, target: Path, default_args: tuple[str, ...]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content, legacy = _launcher_variants(target, default_args)
    if path.is_symlink():
        raise RuntimeError("Refusing to replace a symlinked official ACP launcher")
    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RuntimeError("Refusing to replace an unreadable official ACP launcher") from exc
        if existing not in {content, legacy}:
            raise RuntimeError("Refusing to replace an unmanaged official ACP launcher")
        if existing == content:
            return
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix=".antigravity-acp-launcher-",
        dir=path.parent, delete=False,
    ) as file:
        file.write(content)
        temporary = Path(file.name)
    try:
        temporary.chmod(temporary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def install(
    prefix: Path | None = None,
    bin_dir: Path | None = None,
    runtime_prefix: Path | None = None,
) -> dict[str, Path]:
    """Install the pinned server version without touching unrelated user state.

    The downloaded archive SHA-256 is verified against the registry's
    publisher pin before the archive is opened, staged, extracted, or
    renamed into place; any mismatch, interruption, or missing pin fails
    closed and leaves an existing installation and launcher untouched.
    """
    prefix = (prefix or Path.home() / ".local" / "opt" / "antigravity-acp").expanduser().resolve()
    bin_dir = (bin_dir or Path.home() / ".local" / "bin").expanduser().resolve()
    dist = resolve_distribution()
    version_dir = prefix / VERSION
    launcher = bin_dir / _launcher_name()

    def launch_target(executable: Path) -> Path:
        if runtime_prefix is None:
            return executable
        return runtime_prefix.expanduser() / VERSION / executable.relative_to(version_dir)

    if version_dir.is_symlink():
        raise RuntimeError("Refusing an unsafe pinned official ACP installation path")
    if version_dir.exists():
        if not version_dir.is_dir():
            raise RuntimeError("Refusing an unsafe pinned official ACP installation path")
        executable = _find_executable(version_dir, dist.executable)
        archive_name = Path(urllib.parse.urlsplit(dist.url).path).name or "official.zip"
        retained = version_dir / archive_name
        if retained.is_symlink():
            raise RuntimeError("Refusing a symlinked official ACP archive")
        if retained.exists():
            _verify_archive_digest(retained, dist.sha256)
        else:
            with tempfile.TemporaryDirectory(prefix=".antigravity-acp-archive-", dir=version_dir.parent) as tmp:
                archive = Path(tmp) / "official.zip"
                urllib.request.urlretrieve(dist.url, archive)
                _verify_archive_digest(archive, dist.sha256)
                # Do not replace an existing file if another writer raced us.
                os.link(archive, retained)
    else:
        version_dir.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=".antigravity-acp-install-", dir=version_dir.parent
        ) as temporary_dir:
            temporary = Path(temporary_dir)
            archive = temporary / "official.zip"
            expected_sha256 = _validate_archive_pin(dist.sha256)
            try:
                urllib.request.urlretrieve(dist.url, archive)
            except OSError as exc:
                # Failure class: interrupted download / network failure. The
                # partial archive lived only inside the staging directory,
                # which the context manager removes; nothing was extracted,
                # installed, or replaced, and any previously installed server
                # version and launcher stay exactly as they were.
                raise RuntimeError(
                    "Official ACP download failed or was interrupted before "
                    f"completion ({type(exc).__name__}: {exc}). The partial "
                    "archive was discarded; no server or launcher was "
                    "installed or changed, and any previously installed "
                    f"version under {prefix} is untouched. Check network "
                    "access to dl.google.com and re-run 'python3 "
                    "scripts/install_official.py' (the action is idempotent)"
                ) from exc
            _verify_archive_digest(archive, expected_sha256)
            stage = temporary / "stage"
            stage.mkdir()
            with zipfile.ZipFile(archive) as archive_file:
                root = stage.resolve()
                for member in archive_file.infolist():
                    destination = (stage / member.filename).resolve()
                    if not destination.is_relative_to(root):
                        raise RuntimeError("Official ACP archive contains an unsafe path")
                archive_file.extractall(stage)
            staged_executable = _find_executable(stage, dist.executable)
            _ensure_runtime_executables(stage, staged_executable)
            archive_name = Path(urllib.parse.urlsplit(dist.url).path).name or "official.zip"
            if not archive_name.endswith(".zip"):
                archive_name = "official.zip"
            shutil.copy2(archive, stage / archive_name)
            stage.rename(version_dir)
        executable = _find_executable(version_dir, dist.executable)

    _ensure_runtime_executables(version_dir, executable)
    _write_launcher(launcher, launch_target(executable), dist.args)
    return {"version_dir": version_dir, "executable": executable, "launcher": launcher}


def status(
    prefix: Path | None = None,
    bin_dir: Path | None = None,
) -> dict[str, bool]:
    prefix = (prefix or Path.home() / ".local" / "opt" / "antigravity-acp").expanduser().resolve()
    bin_dir = (bin_dir or Path.home() / ".local" / "bin").expanduser().resolve()
    dist = resolve_distribution()
    version_dir = prefix / VERSION
    launcher = bin_dir / _launcher_name()
    if version_dir.is_symlink() or not version_dir.is_dir():
        server_installed = False
    else:
        try:
            _find_executable(version_dir, dist.executable)
            server_installed = True
        except (OSError, RuntimeError):
            server_installed = False
    launcher_available = launcher.is_file() and not launcher.is_symlink()
    if os.name != "nt" and launcher_available:
        launcher_available = bool(
            launcher.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        )
    return {"server_installed": server_installed, "launcher_available": launcher_available}


def verify(
    prefix: Path | None = None,
    bin_dir: Path | None = None,
    runtime_prefix: Path | None = None,
) -> dict[str, Path]:
    prefix = (prefix or Path.home() / ".local" / "opt" / "antigravity-acp").expanduser().resolve()
    bin_dir = (bin_dir or Path.home() / ".local" / "bin").expanduser().resolve()
    dist = resolve_distribution()
    version_dir = prefix / VERSION
    launcher = bin_dir / _launcher_name()
    if version_dir.is_symlink():
        raise RuntimeError(
            f"Official ACP installation path {version_dir} is unsafe (symlinked); "
            "remove it manually and re-run 'python3 scripts/install_official.py'"
        )
    if not version_dir.is_dir():
        other_versions = (
            sorted(
                p.name
                for p in prefix.iterdir()
                if p.is_dir() and not p.name.startswith(".")
            )
            if prefix.is_dir()
            else []
        )
        if other_versions:
            raise RuntimeError(
                f"Official ACP server version mismatch: pinned {VERSION} is not installed "
                f"under {prefix} (installed: {', '.join(other_versions)}). Run "
                "'python3 scripts/install_acp.py update' (or scripts/install_official.py) "
                "to install the pinned version; never point Hermes at another version's launcher"
            )
        raise RuntimeError(
            f"Official ACP server binary is missing: pinned {VERSION} is not installed "
            f"under {prefix}. Install it first with 'python3 scripts/install_official.py' "
            "(server-only path; the server is never downloaded while Hermes loads plugin.yaml)"
        )
    executable = _find_executable(version_dir, dist.executable)
    if launcher.is_symlink():
        raise RuntimeError(
            f"Official ACP launcher {launcher} is unsafe (symlinked); remove it manually "
            "and re-run 'python3 scripts/install_official.py'"
        )
    if not launcher.is_file():
        raise RuntimeError(
            "Official ACP launcher is missing at "
            f"{launcher} (failure class: PATH misconfiguration — the server "
            "binary may be installed but its launcher directory is not how "
            "Hermes resolves the provider). Re-run "
            "'python3 scripts/install_official.py' and ensure its directory is on the "
            "Hermes process PATH (or set HERMES_ANTIGRAVITY_ACP_COMMAND to the launcher)"
        )
    if os.name != "nt" and not os.access(launcher, os.X_OK):
        raise RuntimeError(
            f"Official ACP launcher {launcher} is not executable; re-run "
            "'python3 scripts/install_official.py' or restore the executable bit "
            f"with 'chmod +x {launcher}', and ensure its directory is on the "
            "Hermes process PATH (or set HERMES_ANTIGRAVITY_ACP_COMMAND to the launcher)"
        )
    launcher_text = launcher.read_text(encoding="utf-8")
    expected_target = str(
        runtime_prefix.expanduser() / VERSION / executable.relative_to(version_dir)
        if runtime_prefix is not None else executable
    )
    if expected_target not in launcher_text:
        raise RuntimeError(
            "Official ACP launcher does not target the installed executable "
            f"(expected it to reference {expected_target}); re-run "
            "'python3 scripts/install_official.py install' to rewrite the managed launcher"
        )
    if os.name != "nt" and not os.access(executable, os.X_OK):
        raise RuntimeError(
            f"Official ACP executable {executable} is not executable; re-run "
            "'python3 scripts/install_official.py install' to restore runtime "
            "executable bits (no user-owned file is modified)"
        )
    return {"version_dir": version_dir, "executable": executable, "launcher": launcher}


def uninstall(
    prefix: Path | None = None,
    bin_dir: Path | None = None,
    runtime_prefix: Path | None = None,
) -> list[Path]:
    """Delete only the pinned version directory and the managed launcher.

    Ownership checks run before anything is deleted: unsafe paths and launcher
    files this installer did not write abort the call untouched. Other versions
    kept under the prefix (previous pins) are deliberately left for the user to
    review, and no Hermes/profile state is touched here. Catalog plugin files
    are outside this function's entire scope.
    """
    prefix = (prefix or Path.home() / ".local" / "opt" / "antigravity-acp").expanduser().resolve()
    bin_dir = (bin_dir or Path.home() / ".local" / "bin").expanduser().resolve()
    dist = resolve_distribution()
    version_dir = prefix / VERSION
    launcher = bin_dir / _launcher_name()
    if version_dir.is_symlink():
        raise RuntimeError("Refusing an unsafe pinned official ACP installation path")
    if version_dir.exists() and not version_dir.is_dir():
        raise RuntimeError("Refusing an unsafe pinned official ACP installation path")
    if launcher.is_symlink():
        raise RuntimeError(
            f"Refusing to remove a symlinked official ACP launcher at {launcher}"
        )
    if launcher.is_file():
        if version_dir.is_dir():
            launch_target = _find_executable(version_dir, dist.executable)
            if runtime_prefix is not None:
                launch_target = (
                    runtime_prefix.expanduser() / VERSION
                    / launch_target.relative_to(version_dir)
                )
        else:
            launch_target = version_dir / dist.executable
        content, legacy = _launcher_variants(launch_target, dist.args)
        try:
            existing = launcher.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RuntimeError(
                f"Refusing to remove an unreadable official ACP launcher at {launcher}"
            ) from exc
        if existing not in {content, legacy}:
            raise RuntimeError(
                f"Refusing to remove an unmanaged official ACP launcher at {launcher}; "
                "delete it manually only if you own it"
            )
    removed: list[Path] = []
    if launcher.is_file():
        launcher.unlink()
        removed.append(launcher)
    if version_dir.is_dir():
        shutil.rmtree(version_dir)
        removed.append(version_dir)
    return removed


def main() -> int:
    parser = argparse.ArgumentParser(description="Install Google's official Antigravity ACP server")
    parser.add_argument("--prefix", type=Path, default=Path.home() / ".local" / "opt" / "antigravity-acp")
    parser.add_argument("--bin-dir", type=Path, default=Path.home() / ".local" / "bin")
    parser.add_argument("--runtime-prefix", type=Path, default=None)
    parser.add_argument("--status", action="store_true", help="Report installation presence without changing files")
    parser.add_argument("--verify", action="store_true", help="Verify installation without authenticating")
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Delete the pinned version directory and the managed launcher only; "
        "unmanaged launcher files are refused",
    )
    args = parser.parse_args()
    try:
        if args.status:
            result = status(args.prefix, args.bin_dir)
            print("official_server=" + ("installed" if result["server_installed"] else "missing"))
            print("launcher=" + ("available" if result["launcher_available"] else "missing"))
            return 0 if all(result.values()) else 1
        if args.verify:
            verify(args.prefix, args.bin_dir, args.runtime_prefix)
            print("official ACP install verified; no authentication was attempted")
            return 0
        if args.uninstall:
            removed = uninstall(args.prefix, args.bin_dir, args.runtime_prefix)
            for path in removed:
                print("removed: " + str(path))
            if not removed:
                print("nothing installed to remove")
            print("other profile/catalog state was not touched")
            return 0
        install(args.prefix, args.bin_dir, args.runtime_prefix)
        print("official ACP server installed; no authentication was attempted")
        return 0
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"official ACP lifecycle action failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
