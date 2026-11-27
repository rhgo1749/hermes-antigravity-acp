"""Shared helpers and paths for Design C credential-free tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from antigravity_acp_mcp.acp_connection import AcpConnection
from antigravity_acp_mcp.conversation import Conversation

ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp" / "parked"
FAKE_ACP = str(Path(__file__).with_name("fake_acp.py"))
FAKE_AGY = str(Path(__file__).with_name("fake_agy.py"))

SYS = {"role": "system", "content": "You are Hermes. SYS-MARK"}
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "fetch",
            "description": "fetch a key",
            "parameters": {"type": "object", "properties": {"k": {"type": "string"}}},
        },
    }
]


def dump(conn: AcpConnection) -> dict[str, Any]:
    return conn.request("x/dump", {}, timeout=10)


def asst(calls: list[Any]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": "",
        "tool_calls": [
            {
                "id": c.id,
                "type": "function",
                "function": {"name": c.name, "arguments": json.dumps(c.arguments)},
            }
            for c in calls
        ],
    }


def tool_rows(calls: list[Any], texts: list[str]) -> list[dict[str, Any]]:
    return [
        {"role": "tool", "tool_call_id": c.id, "content": t}
        for c, t in zip(calls, texts, strict=True)
    ]


def events(log: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


def make_conv(tmp_path: Path, script: list[Any], new_delay: float = 0, **kw: Any) -> tuple[Conversation, Path]:
    log = tmp_path / "agy.log"
    behaviour = json.dumps({"script": script, "log": str(log), "new_delay": new_delay})

    def spawn(key: str, cwd: str) -> AcpConnection:
        conn = AcpConnection(sys.executable, [FAKE_AGY, behaviour], cwd)
        conn.start()
        conn.initialize()
        return conn

    return Conversation("k1", spawn, **kw), log


def tree_helpers():
    import importlib.util
    import sys
    mod = sys.modules.get("test_parked_process_tree_native")
    if mod is not None:
        return mod
    spec = importlib.util.spec_from_file_location(
        "test_parked_process_tree_native", ROOT / "tests" / "test_parked_process_tree_native.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["test_parked_process_tree_native"] = mod
    spec.loader.exec_module(mod)
    return mod
