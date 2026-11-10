"""Thinking-level control: env/reasoning_effort resolution and live wiring.

The plugin maps caller intent (profile env override, then the request's
``reasoning_effort``) onto the official server's own ``thinking_level``
config option. Levels the server did not author are never force-sent; the
session default stands and a warning is logged.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import sys
import types
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent / "hermes-plugin" / "antigravity-acp"


def _load_client(monkeypatch, *, command: str, args: list[str], cwd: str):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(Path(cwd) / "acp-conversation-state.json"),
    )

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = lambda *a, **k: None
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)

    module_name = "antigravity_acp_thinking_e2e"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location(
        module_name, PLUGIN_DIR / "__init__.py", submodule_search_locations=[str(PLUGIN_DIR)]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module.antigravity_acp.create_client(
        command=command, args=args, acp_cwd=cwd, rate_limit_retries=0
    )


def _client_module():
    return sys.modules["antigravity_acp_thinking_e2e.client"]


def _write_fake_server(tmp_path: Path, *, thinking_options: list[str] | None) -> tuple[Path, Path]:
    script = tmp_path / "fake_acp_server.py"
    log_path = tmp_path / "fake_acp_log.jsonl"
    options = [{"value": value} for value in (thinking_options or [])]
    thinking_option = {
        "id": "thinking_level",
        "category": "thought_level",
        "currentValue": "high",
        "options": options,
    } if thinking_options is not None else None
    script.write_text(
        f"THINKING_OPTION = {thinking_option!r}\n"
        + r'''
import json
import os
import sys

log_path = sys.argv[1]

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def log(payload):
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")

for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    params = msg.get("params") or {}
    log({"id": msg.get("id"), "method": method, "params": params})
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/new":
        config_options = [{
            "id": "model",
            "category": "model",
            "currentValue": "gemini-3.8-flash",
            "options": [{"value": "gemini-3.8-flash"}],
        }]
        if THINKING_OPTION is not None:
            config_options.append(THINKING_OPTION)
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "sessionId": "session-1",
            "configOptions": config_options,
        }})
    elif method in ("session/set_config_option", "session/set_model"):
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
    elif method == "session/prompt":
        emit({"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": "session-1",
            "update": {"sessionUpdate": "agent_message_chunk",
                       "content": {"type": "text", "text": "OK"}},
        }})
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {"stopReason": "end_turn"}})
    else:
        emit({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
''',
        encoding="utf-8",
    )
    return script, log_path


def _logged_methods(log_path: Path) -> list[dict]:
    return [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]


def _complete(client, **kwargs):
    return client.chat.completions.create(
        model="gemini-3.8-flash",
        messages=[{"role": "user", "content": "hi"}],
        timeout=30,
        **kwargs,
    )


# --- pure resolution rules -------------------------------------------------


def test_reasoning_effort_mapping(monkeypatch, tmp_path) -> None:
    _load_client(monkeypatch, command=sys.executable, args=[], cwd=str(tmp_path))
    cm = _client_module()
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_THINKING_LEVEL", raising=False)
    assert cm._desired_thinking_level("low") == ("low", "reasoning_effort")
    assert cm._desired_thinking_level("MEDIUM") == ("medium", "reasoning_effort")
    assert cm._desired_thinking_level("xhigh") == ("high", "reasoning_effort")
    assert cm._desired_thinking_level("max") == ("high", "reasoning_effort")
    assert cm._desired_thinking_level("ultra") == ("high", "reasoning_effort")
    assert cm._desired_thinking_level("minimal") == ("low", "reasoning_effort")
    assert cm._desired_thinking_level("none") == ("low", "reasoning_effort")
    assert cm._desired_thinking_level("") == (None, "")
    assert cm._desired_thinking_level(None) == (None, "")
    assert cm._desired_thinking_level("nonsense") == (None, "")


def test_env_override_precedence_and_validation(monkeypatch, tmp_path) -> None:
    _load_client(monkeypatch, command=sys.executable, args=[], cwd=str(tmp_path))
    cm = _client_module()
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_THINKING_LEVEL", "low")
    assert cm._desired_thinking_level("xhigh") == ("low", "env")
    monkeypatch.setenv("HERMES_ANTIGRAVITY_ACP_THINKING_LEVEL", "ultra")
    # An invalid override never falls through into reasoning_effort either.
    assert cm._desired_thinking_level("low") == (None, "env")


# --- live protocol behaviour ------------------------------------------------


def test_offered_level_is_applied_on_fresh_session(tmp_path, monkeypatch, caplog) -> None:
    script, log_path = _write_fake_server(tmp_path, thinking_options=["low", "medium", "high"])
    client = _load_client(
        monkeypatch, command=sys.executable, args=[str(script), str(log_path)], cwd=str(tmp_path)
    )
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_THINKING_LEVEL", raising=False)
    with caplog.at_level(logging.INFO):
        completion = _complete(client, reasoning_effort="low")
    assert completion.choices[0].message.content == "OK"
    rows = _logged_methods(log_path)
    sets = [
        r for r in rows
        if r["method"] == "session/set_config_option"
        and r["params"].get("configId") == "thinking_level"
    ]
    assert [x["params"]["value"] for x in sets] == ["low"]
    assert "ACP thinking level" in caplog.text and "outcome=accepted" in caplog.text


def test_unoffered_level_keeps_server_default_and_warns(tmp_path, monkeypatch, caplog) -> None:
    script, log_path = _write_fake_server(tmp_path, thinking_options=["high"])
    client = _load_client(
        monkeypatch, command=sys.executable, args=[str(script), str(log_path)], cwd=str(tmp_path)
    )
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_THINKING_LEVEL", raising=False)
    with caplog.at_level(logging.WARNING):
        completion = _complete(client, reasoning_effort="low")
    assert completion.choices[0].message.content == "OK"
    rows = _logged_methods(log_path)
    assert not [
        r for r in rows
        if r["method"] == "session/set_config_option"
        and r["params"].get("configId") == "thinking_level"
    ]
    assert "does not offer thinking level" in caplog.text


def test_session_without_thinking_option_is_untouched(tmp_path, monkeypatch) -> None:
    script, log_path = _write_fake_server(tmp_path, thinking_options=None)
    client = _load_client(
        monkeypatch, command=sys.executable, args=[str(script), str(log_path)], cwd=str(tmp_path)
    )
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_THINKING_LEVEL", raising=False)
    completion = _complete(client, reasoning_effort="medium")
    assert completion.choices[0].message.content == "OK"
    rows = _logged_methods(log_path)
    assert not [
        r for r in rows
        if r["method"] == "session/set_config_option"
        and r["params"].get("configId") == "thinking_level"
    ]


def test_no_signal_sends_nothing(tmp_path, monkeypatch) -> None:
    script, log_path = _write_fake_server(tmp_path, thinking_options=["low", "medium", "high"])
    client = _load_client(
        monkeypatch, command=sys.executable, args=[str(script), str(log_path)], cwd=str(tmp_path)
    )
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_THINKING_LEVEL", raising=False)
    completion = _complete(client)
    assert completion.choices[0].message.content == "OK"
    rows = _logged_methods(log_path)
    assert not [
        r for r in rows
        if r["method"] == "session/set_config_option"
        and r["params"].get("configId") == "thinking_level"
    ]
