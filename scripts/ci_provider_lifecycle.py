#!/usr/bin/env python3
"""Shared credential-free installed-provider lifecycle for disposable CI homes.

Run after the real native installer and any provider/factory/security probes.
The public installer remains the sole owner of pin verification and removal.
No authentication, prompt, account access or Hermes Core modification is added.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    import install_acp
except ImportError:
    from scripts import install_acp


def verify_and_remove(hermes_home: Path, prefix: Path, bin_dir: Path, timeout: float = 60.0) -> dict:
    phase = "status_before"
    try:
        before = install_acp.status(hermes_home, prefix, bin_dir)
        if not before or not all(before.values()):
            raise RuntimeError("installed provider/server status is incomplete")
        phase = "verify"
        install_acp.verify(hermes_home, prefix, bin_dir, timeout=timeout)
        phase = "delete"
        install_acp.delete(hermes_home, prefix, bin_dir)
        phase = "status_after"
        after = install_acp.status(hermes_home, prefix, bin_dir)
        if set(after) != set(before) or any(after.values()):
            raise RuntimeError("managed provider/server state survived removal")
    except (OSError, RuntimeError, ValueError) as exc:
        # Keep the original exception type/exit failure. Never print raw
        # exception messages, paths, server output or session state.
        setattr(exc, "lifecycle_phase", phase)
        raise
    return {"stage": "install_status_verify_uninstall", "status": "PASS",
            "before": before, "after": after, "authenticated": False, "prompts": 0}


def failure_record(exc: Exception, hermes_home: Path, prefix: Path, bin_dir: Path) -> dict:
    """Fixed diagnostic vocabulary; no raw filename, exception text or IDs."""
    path_type = "unavailable"
    filename = getattr(exc, "filename", None)
    if isinstance(filename, str):
        path = Path(filename).absolute()
        roots = (
            (bin_dir.absolute(), "launcher"),
            ((hermes_home / "plugins/model-providers/antigravity-acp").absolute(), "provider_tree"),
            (prefix.absolute(), "official_install_tree"),
        )
        for root, kind in roots:
            if path.is_relative_to(root):
                path_type = kind
                if kind == "official_install_tree" and path.name == "agy_acp_server.exe":
                    path_type = "official_executable"
                break
        else:
            path_type = "outside_managed_roots"
    # The owning installer function disambiguates provider removal from
    # official-server removal without serializing any frame locals.
    operation = "unavailable"
    tb = exc.__traceback__
    while tb:
        name = Path(tb.tb_frame.f_code.co_filename).name
        function = tb.tb_frame.f_code.co_name
        if function == "uninstall" and name in {"install_official.py", "deploy_hermes_profiles.py"}:
            operation = "remove_official" if name == "install_official.py" else "remove_provider"
        tb = tb.tb_next
    result = {"stage": "install_status_verify_uninstall", "status": "FAIL",
              "phase": getattr(exc, "lifecycle_phase", "unavailable"),
              "operation": operation, "path_type": path_type, "error_class": type(exc).__name__}
    for key in ("errno", "winerror"):
        value = getattr(exc, key, None)
        if type(value) is int:
            result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-home", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, default=install_acp.DEFAULT_PREFIX)
    parser.add_argument("--bin-dir", type=Path, default=install_acp.DEFAULT_BIN_DIR)
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args(argv)
    try:
        result = verify_and_remove(args.hermes_home, args.prefix, args.bin_dir, args.timeout)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps(failure_record(exc, args.hermes_home, args.prefix, args.bin_dir)))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
