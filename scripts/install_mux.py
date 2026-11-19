#!/usr/bin/env python3
"""Opt-in packaging manager for the Antigravity ACP mux launcher (historical reference).

The public default install (scripts/install_acp.py) stays **Single-only**: it
never imports, installs, configures, or runs MUX.  This script is the separate
explicit opt-in that places the reviewed mux bundle (engine, hardened entry,
portable wrapper) into a bin directory and reports the resolved contract.

Contract honored here:
- MUX is activated only by the operator pointing a Hermes profile's provider
  command (``HERMES_ANTIGRAVITY_ACP_COMMAND``) at the installed mux launcher.
  This tool never writes profiles, env files, account registries, or secrets.
- Foreign bytes are never overwritten or deleted: install and uninstall abort
  fail-closed when an existing target is not byte-identical to this bundle as
  recorded in the install manifest.
- The Single launcher (``antigravity-acp-official``) and every file not listed
  in the manifest are preserved by uninstall.
- ``status`` reports paths and booleans only; registry contents, credentials,
  and account identifiers are never read or printed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

# Bundle: engine + hardened entry + portable wrapper (wrapper imports the
# entry/adjacent module by sibling path, so all three travel together).
BUNDLE_FILES = ("acp_mux.py", "antigravity-acp-mux.py", "antigravity-acp-mux")
MANIFEST_NAME = ".antigravity-acp-mux-packaging.json"
# Human-facing contract series for this bundle.  Bump only when the install
# contract itself changes.  The full version written into manifests is derived
# from the exact bundle bytes (see _bundle_version): a version string can no
# longer survive a code change while still claiming to be the old one — the
# 2026-11-19 production drift (F3/F4 merged, installed mux still reporting
# "105.1" from Nov 13) was invisible precisely because the version was a
# hand-maintained constant.
BUNDLE_SERIES = "105.1"
MUX_LAUNCHER_NAME = "antigravity-acp-mux"
OFFICIAL_LAUNCHER_NAME = "antigravity-acp-official"

DEFAULT_BIN_DIR = Path.home() / ".local" / "bin"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _source_hashes() -> dict[str, str]:
    sources: dict[str, Path] = {name: SCRIPTS / name for name in BUNDLE_FILES}
    missing = [str(p) for p in sources.values() if not p.is_file()]
    if missing:
        raise SystemExit(
            "install_mux: bundle sources missing from this checkout: "
            + ", ".join(missing)
        )
    return {name: _sha256(p) for name, p in sources.items()}


def _bundle_version() -> str:
    """Content-derived bundle version: the contract series plus a digest
    over the exact bytes this checkout would install."""
    digest = hashlib.sha256()
    for name, sha in sorted(_source_hashes().items()):
        digest.update(name.encode())
        digest.update(sha.encode())
    return f"{BUNDLE_SERIES}+{digest.hexdigest()[:12]}"


def _manifest_path(bin_dir: Path) -> Path:
    return bin_dir / MANIFEST_NAME


def _load_manifest(bin_dir: Path) -> dict | None:
    path = _manifest_path(bin_dir)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"files": {}, "corrupt": True}
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        return {"files": {}, "corrupt": True}
    return data


def _cmd_install(args: argparse.Namespace) -> int:
    bin_dir = Path(args.bin_dir).expanduser()
    sources = {name: SCRIPTS / name for name in BUNDLE_FILES}
    hashes = _source_hashes()
    manifest = _load_manifest(bin_dir)
    if manifest and manifest.get("corrupt"):
        print(
            f"install_mux: refusing to touch {bin_dir}: manifest "
            f"{MANIFEST_NAME} is unreadable; resolve manually",
            file=sys.stderr,
        )
        return 2
    recorded = (manifest or {}).get("files", {})

    # Pre-flight over EVERY target before any write: foreign bytes abort with
    # zero changes.
    conflicts: list[str] = []
    for name in BUNDLE_FILES:
        target = bin_dir / name
        if not target.exists():
            continue
        if recorded.get(name) and _sha256(target) == recorded[name]:
            continue  # ours, idempotent
        if not recorded.get(name) and _sha256(target) == hashes[name]:
            continue  # byte-identical to this bundle version
        conflicts.append(str(target))
    if conflicts:
        print(
            "install_mux: refusing to overwrite files not owned by this "
            "bundle (fail closed, nothing written):\n  "
            + "\n  ".join(conflicts)
            + "\nRemove or relocate them, then re-run.",
            file=sys.stderr,
        )
        return 2

    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in BUNDLE_FILES:
        target = bin_dir / name
        if target.exists() and _sha256(target) == hashes[name]:
            continue
        shutil.copyfile(sources[name], target)
        target.chmod(0o755)

    _manifest_path(bin_dir).write_text(
        json.dumps(
            {
                "bundle_version": _bundle_version(),
                "source_repo": "rhgo1749/hermes-antigravity-acp",
                "files": hashes,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"install_mux: installed mux bundle to {bin_dir}")
    print(
        "install_mux: MUX is NOT active yet. Activate it per Hermes profile by\n"
        f"  setting the provider command to {bin_dir / MUX_LAUNCHER_NAME}\n"
        "  (for example HERMES_ANTIGRAVITY_ACP_COMMAND) and providing the\n"
        "  account registry and launcher env per docs/mux-packaging.md.\n"
        "install_mux: nothing in the Single path was modified."
    )
    return 0


def _cmd_uninstall(args: argparse.Namespace) -> int:
    bin_dir = Path(args.bin_dir).expanduser()
    manifest = _load_manifest(bin_dir)
    if not manifest or manifest.get("corrupt"):
        print(
            f"install_mux: no readable install manifest under {bin_dir}; "
            "refusing to delete anything",
            file=sys.stderr,
        )
        return 2
    recorded = manifest["files"]

    # Verify every recorded target BEFORE deleting: tampered bytes abort and
    # nothing is removed.
    to_remove: list[Path] = []
    for name, expected in sorted(recorded.items()):
        target = bin_dir / name
        if not target.exists():
            continue
        if _sha256(target) != expected:
            print(
                f"install_mux: {target} no longer matches the installed "
                "bundle; preserving all files (fail closed, nothing deleted)",
                file=sys.stderr,
            )
            return 2
        to_remove.append(target)
    for target in to_remove:
        target.unlink()
    _manifest_path(bin_dir).unlink(missing_ok=True)
    print(
        f"install_mux: removed {len(to_remove)} bundle file(s) from {bin_dir}; "
        f"non-bundle files such as {OFFICIAL_LAUNCHER_NAME} were preserved"
    )
    return 0


def _first_env(*names: str) -> tuple[str, str]:
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value, name
    return "", ""


def _resolve_par() -> dict:
    value, source = _first_env("ACP_MUX_PAR", "HERMES_ANTIGRAVITY_ACP_PAR")
    if value:
        return {
            "par_resolved": True,
            "par_source": source,
            "par_path": str(Path(value).expanduser()),
            "par_exists": Path(value).expanduser().is_file(),
        }
    which = shutil.which(OFFICIAL_LAUNCHER_NAME)
    if which:
        return {
            "par_resolved": True,
            "par_source": "PATH",
            "par_path": which,
            "par_exists": True,
        }
    return {
        "par_resolved": False,
        "par_source": "",
        "par_path": "",
        "par_exists": False,
    }


def _resolve_registry() -> dict:
    value, source = _first_env("ACP_MUX_ACCOUNTS", "HERMES_ACP_ACCOUNTS")
    if not value:
        control_home, _ = _first_env("ACP_MUX_HOME", "HERMES_REAL_HOME")
        if not control_home:
            control_home = str(Path.home() / ".hermes")
            source = "HOME-default"
        else:
            source = "control-home"
        value = str(Path(control_home).expanduser() / "acp-accounts.json")
    path = Path(value).expanduser()
    # Paths and existence ONLY — registry contents are never read here.
    return {"registry_path": str(path), "registry_source": source,
            "registry_exists": path.is_file()}


def _cmd_status(args: argparse.Namespace) -> int:
    bin_dir = Path(args.bin_dir).expanduser()
    manifest = _load_manifest(bin_dir)
    if manifest and manifest.get("corrupt"):
        files_ok = False
        installed = all((bin_dir / name).exists() for name in BUNDLE_FILES)
        print("install_mux: manifest unreadable; treating bundle as tampered")
    elif manifest:
        installed = True
        files_ok = all(
            (bin_dir / name).is_file() and _sha256(bin_dir / name) == expected
            for name, expected in manifest["files"].items()
        ) and all((bin_dir / name).is_file() for name in BUNDLE_FILES)
    else:
        installed = any((bin_dir / name).exists() for name in BUNDLE_FILES)
        files_ok = False
        if installed:
            print(
                "install_mux: bundle files present without a manifest "
                "(foreign bytes); status cannot vouch for them",
                file=sys.stderr,
            )

    report = {
        "mux_installed": bool(installed),
        "mux_bundle_ok": bool(files_ok),
        "mux_launcher": str(bin_dir / MUX_LAUNCHER_NAME),
        "single_default_untouched": not (bin_dir / OFFICIAL_LAUNCHER_NAME).exists()
        or (bin_dir / OFFICIAL_LAUNCHER_NAME).is_file(),
        **_resolve_par(),
        **_resolve_registry(),
    }
    try:
        repo_hashes = _source_hashes()
    except SystemExit:
        # Status must not crash outside a full checkout; it just cannot
        # vouch for repo parity here.
        repo_hashes = None
    report["matches_repo_bundle"] = bool(
        manifest
        and not manifest.get("corrupt")
        and repo_hashes is not None
        and manifest.get("files") == repo_hashes
    )
    if not report["par_resolved"]:
        print(
            "install_mux: ACP_MUX_PAR / HERMES_ANTIGRAVITY_ACP_PAR / "
            f"{OFFICIAL_LAUNCHER_NAME} unresolved — MUX would fail closed",
            file=sys.stderr,
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.strict and not (report["mux_bundle_ok"] and report["matches_repo_bundle"]):
        # Machine gate for deploy pipelines and periodic ops checks: any
        # divergence between the installed bundle and this checkout's
        # bundle — or a missing/tampered manifest — exits non-zero.
        print("install_mux: strict drift gate FAILED", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
    )
    parser.add_argument("--bin-dir", default=str(DEFAULT_BIN_DIR))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("install", help="copy the reviewed mux bundle (opt-in)")
    sub.add_parser("uninstall", help="remove exactly the installed bundle")
    status = sub.add_parser("status", help="resolved contract report (no secrets)")
    status.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero unless the installed bundle is intact AND "
        "byte-identical to this checkout's bundle (deploy-pipeline gate)",
    )
    args = parser.parse_args(argv)
    handlers = {"install": _cmd_install, "uninstall": _cmd_uninstall,
                "status": _cmd_status}
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
