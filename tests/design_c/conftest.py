"""Pytest bootstrap for Design C tests without executing __init__.py or mutating sys.path."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp" / "parked"


def _bootstrap_package() -> None:
    existing = sys.modules.get("antigravity_acp_mcp")
    if existing is not None and str(PLUGIN_DIR) in list(getattr(existing, "__path__", ())):
        return
    pkg = types.ModuleType("antigravity_acp_mcp")
    pkg.__file__ = str(PLUGIN_DIR / "__init__.py")
    pkg.__path__ = [str(PLUGIN_DIR)]
    pkg.__package__ = "antigravity_acp_mcp"
    sys.modules["antigravity_acp_mcp"] = pkg


_bootstrap_package()

from antigravity_acp_mcp.acp_connection import AcpConnection  # noqa: E402

from ._support import FAKE_ACP  # noqa: E402


@pytest.fixture
def connect(tmp_path):
    """connect(behaviour, mux_env=None, initialize=True) -> started AcpConnection on the fake."""
    made = []

    def factory(behaviour=None, mux_env=None, initialize=True):
        cwd = tmp_path / "empty-cwd"
        cwd.mkdir(exist_ok=True)
        conn = AcpConnection(
            sys.executable,
            [FAKE_ACP, json.dumps(behaviour or {})],
            str(cwd),
            mux_env=mux_env,
        )
        conn.start()
        made.append(conn)
        if initialize:
            conn.initialize(timeout=20)
        return conn

    yield factory
    for conn in made:
        conn.close()


@pytest.fixture
def planted_secrets(monkeypatch):
    names = ("DISCORD_BOT_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GH_TOKEN")
    for n in names:
        monkeypatch.setenv(n, "planted-" + n.lower())
    monkeypatch.setenv("ACP_MUX_SESSION_ID", "ambient-must-not-leak")
    monkeypatch.setenv("ACP_MUX_PAR", "/ambient/par")
    return names
