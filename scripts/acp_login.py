#!/usr/bin/env python3
"""Repo-side entry point for the plugin-owned ACP login driver.

The driver lives with the provider plugin (``hermes-plugin/antigravity-acp/
login.py``) because the installed plugin — not this repository — is what
``hermes model`` invokes as the login command. This wrapper keeps the proven
repository CLI (``python scripts/acp_login.py --method …``) pointing at the
single implementation instead of a second copy.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_DRIVER = (
    Path(__file__).resolve().parents[1]
    / "hermes-plugin"
    / "antigravity-acp"
    / "login.py"
)


def _load_driver():
    spec = importlib.util.spec_from_file_location("antigravity_acp_login_driver", _DRIVER)
    if spec is None or spec.loader is None:
        raise RuntimeError("ACP login driver module is unreadable.")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    raise SystemExit(_load_driver().main())
