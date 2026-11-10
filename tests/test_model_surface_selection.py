"""Both model surfaces must be offered *and* selectable.

Contract source: the live-probed official 1.4.4 session surface (2026-11-11).
The server authors two model axes with different contents:

  * a ``configOptions`` group with ``category == "model"`` carrying base model
    values (live: ``gemini-3.8-flash``), set with ``session/set_config_option``,
  * legacy ``models.availableModels`` rows carrying composite ids with their own
    ``currentModelId`` (live: ``gemini-3.8-flash-high/medium/low``), set with
    ``session/set_model`` -- probed ACCEPTED for all three composite ids.

The defect this file pins: routing every id through the config group made the
legacy rows unselectable no-ops while the picker still displayed them, so three
of four visible rows changed nothing.  The invariant is that every id the
adapter lists must resolve to a real request, and that a server offering more
models (a second family, or a second config group) widens the picker without an
adapter change.

Fake subprocess only: no credentials, no Google binary, no inference.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"


def _load_client(monkeypatch, *, args: list[str], cwd: str):
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

    module_name = "antigravity_acp_surface"
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
    return module, module.antigravity_acp.create_client(
        command=sys.executable, args=args, acp_cwd=cwd
    )


FAKE = r'''
import json
import sys

MODE = MODE
REC = REC

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

LEGACY = [
    {"modelId": "gemini-3.8-flash-high", "name": "Gemini 3.8 Flash (High)"},
    {"modelId": "gemini-3.8-flash-medium", "name": "Gemini 3.8 Flash (Medium)"},
    {"modelId": "gemini-3.8-flash-low", "name": "Gemini 3.8 Flash (Low)"},
]

MODEL_GROUP = {
    "id": "model", "category": "model", "type": "select",
    "currentValue": "gemini-3.8-flash",
    "options": [{"value": "gemini-3.8-flash", "name": "Gemini 3.8 Flash"}],
}
ARGON_GROUP = {
    "id": "model_family_b", "category": "model", "type": "select",
    "currentValue": "gemini-4-argon",
    "options": [{"value": "gemini-4-argon", "name": "Gemini 4 Argon"}],
}
THINKING_GROUP = {
    "id": "thinking_level", "category": "thought_level", "type": "select",
    "currentValue": "high",
    "options": [{"value": "low"}, {"value": "medium"}, {"value": "high"}],
}
MODE_GROUP = {
    "id": "mode", "category": "mode", "type": "select", "currentValue": "default",
    "options": [{"value": "default"}, {"value": "auto_edit"}, {"value": "yolo"}],
}

if MODE == "split":
    # A second model family authored as its own configOptions group.
    CONFIG_OPTIONS = [MODEL_GROUP, ARGON_GROUP, THINKING_GROUP, MODE_GROUP]
elif MODE == "single":
    # A server with no legacy surface at all.
    CONFIG_OPTIONS = [MODEL_GROUP, THINKING_GROUP, MODE_GROUP]
else:
    CONFIG_OPTIONS = [MODEL_GROUP, THINKING_GROUP, MODE_GROUP]

for line in sys.stdin:
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": 1,
            "agentInfo": {"name": "antigravity-acp", "title": "Google Antigravity",
                          "version": "1.4.4"},
            "agentCapabilities": {"loadSession": True,
                                  "sessionCapabilities": {"list": {}, "resume": {}},
                                  "promptCapabilities": {}, "mcpCapabilities": {},
                                  "auth": {"logout": {}}},
            "authMethods": []}})
    elif method == "session/new":
        result = {"sessionId": "s-surface", "configOptions": CONFIG_OPTIONS}
        if MODE != "single":
            result["models"] = {"currentModelId": "gemini-3.8-flash-high",
                                "availableModels": LEGACY}
        emit({"jsonrpc": "2.0", "id": rid, "result": result})
    elif method in ("session/set_model", "session/set_config_option"):
        record({"method": method, "params": msg.get("params")})
        emit({"jsonrpc": "2.0", "id": rid, "result": {}})
    elif method == "session/prompt":
        text_update("ok-surface")
        emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
'''


def _fake_server(tmp_path: Path, *, mode: str, record_path: Path | None) -> list[str]:
    script = tmp_path / f"fake_acp_surface_{mode}.py"
    script.write_text(
        f"MODE = {mode!r}\nREC = {str(record_path) if record_path is not None else ''!r}\n"
        + FAKE,
        encoding="utf-8",
    )
    return [str(script)]


def _selections(record_path: Path) -> list[dict]:
    if not record_path.exists():
        return []
    return [json.loads(line) for line in record_path.read_text(encoding="utf-8").splitlines()]


def test_legacy_composite_id_reaches_set_model(monkeypatch, tmp_path) -> None:
    # The dead-row regression: with a configOptions model group present, a
    # legacy composite id must still send a real session/set_model.
    record = tmp_path / "selections.jsonl"
    _, client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, mode="dual", record_path=record),
        cwd=str(tmp_path),
    )
    reply = client.chat.completions.create(
        model="gemini-3.8-flash-low",
        messages=[{"role": "user", "content": "hi"}], timeout=10,
    )
    assert reply.choices[0].message.content == "ok-surface"
    rows = _selections(record)
    assert any(
        row["method"] == "session/set_model"
        and row["params"].get("modelId") == "gemini-3.8-flash-low"
        for row in rows
    ), f"legacy composite id never reached session/set_model: {rows}"


def test_base_model_selects_through_its_config_group(monkeypatch, tmp_path) -> None:
    record = tmp_path / "selections.jsonl"
    _, client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, mode="dual", record_path=record),
        cwd=str(tmp_path),
    )
    client.chat.completions.create(
        model="gemini-3.8-flash",
        messages=[{"role": "user", "content": "hi"}], timeout=10,
    )
    rows = _selections(record)
    assert any(
        row["method"] == "session/set_config_option"
        and row["params"].get("configId") == "model"
        and row["params"].get("value") == "gemini-3.8-flash"
        for row in rows
    ), f"base model never reached its config group: {rows}"


def test_every_listed_model_resolves_to_a_request(monkeypatch, tmp_path) -> None:
    # The picker can only be trusted when every id it was handed is selectable.
    module, client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, mode="dual", record_path=None),
        cwd=str(tmp_path),
    )
    listed = client.list_models(timeout_seconds=10)
    assert listed
    assert "gemini-3.8-flash" in listed
    assert "gemini-3.8-flash-low" in listed
    client_mod = importlib.import_module(module.__name__ + ".client")
    with client._session(timeout_seconds=30.0, allow_file_requests=False) as (session, _, _):
        dead = [
            model_id
            for model_id in listed
            if client_mod._model_selection_request(session, model_id) is None
        ]
    assert not dead, f"listed models with no selection request: {dead}"


def test_models_split_across_two_config_groups_are_offered_and_selectable(
    monkeypatch, tmp_path
) -> None:
    # Dynamic expansion: a second model family in its own configOptions group
    # must appear and select through *that* group, with no adapter change.
    record = tmp_path / "selections.jsonl"
    module, client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, mode="split", record_path=record),
        cwd=str(tmp_path),
    )
    listed = client.list_models(timeout_seconds=10)
    assert "gemini-4-argon" in listed, f"second config group was not offered: {listed}"
    client.chat.completions.create(
        model="gemini-4-argon",
        messages=[{"role": "user", "content": "hi"}], timeout=10,
    )
    rows = _selections(record)
    assert any(
        row["method"] == "session/set_config_option"
        and row["params"].get("configId") == "model_family_b"
        and row["params"].get("value") == "gemini-4-argon"
        for row in rows
    ), f"second family did not select through its own group: {rows}"


def test_unauthored_model_sends_no_selection(monkeypatch, tmp_path) -> None:
    # Fail closed: an id neither surface authored must not be force-sent.
    record = tmp_path / "selections.jsonl"
    _, client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, mode="dual", record_path=record),
        cwd=str(tmp_path),
    )
    client.chat.completions.create(
        model="gemini-nonexistent",
        messages=[{"role": "user", "content": "hi"}], timeout=10,
    )
    rows = _selections(record)
    assert not any(
        row["params"].get("modelId") == "gemini-nonexistent"
        or row["params"].get("value") == "gemini-nonexistent"
        for row in rows
    ), f"unauthored model was force-sent: {rows}"


def test_single_surface_server_still_selects(monkeypatch, tmp_path) -> None:
    # A server that authors only a configOptions group keeps working.
    record = tmp_path / "selections.jsonl"
    _, client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, mode="single", record_path=record),
        cwd=str(tmp_path),
    )
    listed = client.list_models(timeout_seconds=10)
    assert listed == ["gemini-3.8-flash"], listed
    client.chat.completions.create(
        model="gemini-3.8-flash",
        messages=[{"role": "user", "content": "hi"}], timeout=10,
    )
    rows = _selections(record)
    assert any(row["method"] == "session/set_config_option" for row in rows), rows
