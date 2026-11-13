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
    before = install_acp.status(hermes_home, prefix, bin_dir)
    if not before or not all(before.values()):
        raise RuntimeError("installed provider/server status is incomplete")
    install_acp.verify(hermes_home, prefix, bin_dir, timeout=timeout)
    install_acp.delete(hermes_home, prefix, bin_dir)
    after = install_acp.status(hermes_home, prefix, bin_dir)
    if set(after) != set(before) or any(after.values()):
        raise RuntimeError("managed provider/server state survived removal")
    return {"stage": "install_status_verify_uninstall", "status": "PASS",
            "before": before, "after": after, "authenticated": False, "prompts": 0}


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
        print(json.dumps({"stage": "install_status_verify_uninstall", "status": "FAIL",
                          "error_class": type(exc).__name__}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
