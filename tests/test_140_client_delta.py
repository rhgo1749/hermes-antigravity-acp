"""1.4.0 client-side delta regressions.

Contract source: docs/official-server-1.4.0-delta.md.  Covers what 1.4.0
adds into the adapter's blind spot:
  * the additive ``agentCapabilities._meta`` block (antigravity
    ``systemPrompt.append`` / ``tier``), which must pass the handshake
    untouched and never re-arm a spawn,
  * ``gemini-4-argon*`` model ids embedded in the 1.4.0 server, which must
    survive ``list_models`` and a model-selection request unchanged.
Fake subprocess only: no credentials, no Google binary.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"


def _load_client(monkeypatch, *, args: list[str], cwd: str, retries: int = 0):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE", str(Path(cwd) / "acp-state.json")
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE", str(Path(cwd) / "acp-limits.json")
    )
    registered: list = []

    class FakeProviderProfile:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    providers.register_provider = registered.append
    providers_base = types.ModuleType("providers.base")
    providers_base.ProviderProfile = FakeProviderProfile
    monkeypatch.setitem(sys.modules, "providers", providers)
    monkeypatch.setitem(sys.modules, "providers.base", providers_base)
    file_safety = types.ModuleType("agent.file_safety")
    file_safety.get_nt_namespace_error = lambda path, verb=None: None
    file_safety.get_read_block_error = lambda path: None
    monkeypatch.setitem(sys.modules, "agent.file_safety", file_safety)
    redact = types.ModuleType("agent.redact")
    redact.redact_sensitive_text = lambda text, force=True: text
    monkeypatch.setitem(sys.modules, "agent.redact", redact)

    module_name = "antigravity_acp_140"
    for name in list(sys.modules):
        if name == module_name or name.startswith(module_name + "."):
            monkeypatch.delitem(sys.modules, name, raising=False)
    spec = importlib.util.spec_from_file_location(
        module_name, PLUGIN_DIR / "__init__.py",
        submodule_search_locations=[str(PLUGIN_DIR)],
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module.antigravity_acp.create_client(
        command=sys.executable, args=args, acp_cwd=cwd, rate_limit_retries=retries
    )


# A 1.4.0-shaped server: the only observable additions over 1.3.0 in the
# handshake are the ``_meta`` capability block and argon model ids in the
# session/new model list (live-probed 2026-10-16, see contract doc).
FAKE = r'''
import json
import sys

MODE = MODE
REC = REC
counter = COUNTER
spawn_index = 0
if counter:
    with open(counter, "a", encoding="utf-8") as fh:
        fh.write("spawn\n")
    spawn_index = sum(1 for _ in open(counter, encoding="utf-8"))

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def record(obj):
    if REC:
        with open(REC, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj) + "\n")

def text_update(text):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
        "sessionUpdate": "agent_message_chunk",
        "content": {"type": "text", "text": text}}}})

AVAILABLE = [
    {"modelId": "gemini-3.8-flash-high", "name": "Gemini 3.8 Flash (High)"},
    {"modelId": "gemini-3.8-flash-medium", "name": "Gemini 3.8 Flash (Medium)"},
    {"modelId": "gemini-4-argon-high", "name": "Gemini 4 Argon (High)"},
    {"modelId": "gemini-4-argon-medium", "name": "Gemini 4 Argon (Medium)"},
    {"modelId": "gemini-4-argon-low", "name": "Gemini 4 Argon (Low)"},
]

for line in sys.stdin:
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": 1,
            "agentInfo": {"name": "antigravity-acp", "title": "Google Antigravity",
                          "version": "1.4.0"},
            "agentCapabilities": {
                "_meta": {"antigravity": {"systemPrompt": {"append": True}, "tier": True}},
                "loadSession": True,
                "sessionCapabilities": {"list": {}, "resume": {}},
                "promptCapabilities": {},
                "mcpCapabilities": {},
                "auth": {"logout": {}}},
            "authMethods": []}})
    elif method == "session/new":
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "sessionId": "s-140",
            "models": {"currentModelId": "gemini-3.8-flash-high",
                       "availableModels": AVAILABLE}}})
    elif method == "session/set_model":
        record(msg.get("params"))
        emit({"jsonrpc": "2.0", "id": rid, "result": {}})
    elif method == "session/prompt":
        text_update("ok-140")
        emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
'''


def _fake_server(tmp_path: Path, spawn_count: Path | None = None,
                 record_path: Path | None = None) -> list[str]:
    script = tmp_path / "fake_acp_140.py"
    header = (
        f"MODE = 'meta'\n"
        f"REC = {str(record_path) if record_path is not None else ''!r}\n"
        f"COUNTER = {str(spawn_count) if spawn_count is not None else ''!r}\n"
    )
    script.write_text(header + FAKE, encoding="utf-8")
    return [str(script)]


def test_meta_caps_block_completes_turn_with_single_spawn(monkeypatch, tmp_path) -> None:
    # The additive ``_meta`` block must not break the handshake and must not
    # re-arm failover: exactly one spawn, answer surfaces normally.
    counter = tmp_path / "spawns"
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, counter), cwd=str(tmp_path), retries=4
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10,
    )
    assert reply.choices[0].message.content == "ok-140"
    assert counter.read_text(encoding="utf-8").count("spawn") == 1


def test_argon_ids_survive_list_models(monkeypatch, tmp_path) -> None:
    # A 1.4.0 server exposing argon must hand every id to Hermes' picker with
    # no drop and no rename.
    client = _load_client(monkeypatch, args=_fake_server(tmp_path), cwd=str(tmp_path))
    models = client.list_models(timeout_seconds=10)
    assert models is not None
    assert "gemini-4-argon-high" in models
    assert "gemini-4-argon-medium" in models
    assert "gemini-4-argon-low" in models
    assert "gemini-3.8-flash-high" in models


def test_argon_selection_reaches_server_set_model(monkeypatch, tmp_path) -> None:
    # Selecting an argon id must produce a real session/set_model with the id
    # unchanged; the adapter must not silently fall back to the session model.
    record = tmp_path / "set-model.jsonl"
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, record_path=record),
        cwd=str(tmp_path),
    )
    reply = client.chat.completions.create(
        model="gemini-4-argon-medium",
        messages=[{"role": "user", "content": "hi"}], timeout=10,
    )
    assert reply.choices[0].message.content == "ok-140"
    lines = [json.loads(x) for x in record.read_text(encoding="utf-8").splitlines()]
    assert any(
        row.get("modelId") == "gemini-4-argon-medium" for row in lines
    ), "session/set_model never carried the requested argon id"
