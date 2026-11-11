"""1.3.0 client-side delta regressions (pilot).

Contract source: docs/official-server-1.3.0-delta.md.  Covers the two wire
changes 1.3.0 introduces into the adapter's blind spot:
  * the new ``usage_update`` session update (must be tolerated, never spliced
    into the answer, never counted as model output),
  * sanitized Google-API execution digests that lose the historical
    ``Agent execution error:`` prefix (must surface as ordinary text, with no
    retry storm).
Fake subprocess only: no credentials, no Google binary.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import types

import pytest

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

    module_name = "antigravity_acp_130"
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


FAKE = r'''
import json
import sys

mode = MODE
counter = COUNTER
spawn_index = 0

def read_last():
    # last_reported_used is NATIVE-SESSION state on the official server:
    # it survives stdio reconnects and resumes, so the fake persists it in a
    # file rather than a process global.
    try:
        with open(LASTFILE, encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None

def write_last(value):
    with open(LASTFILE, "w", encoding="utf-8") as fh:
        fh.write(str(value))
if counter:
    with open(counter, "a", encoding="utf-8") as fh:
        fh.write("spawn\n")
    spawn_index = sum(1 for _ in open(counter, encoding="utf-8"))

def emit(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()

def usage_frame(used):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
        "sessionUpdate": "usage_update", "used": used, "size": 1048576}}})

def text_update(text):
    emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
        "sessionUpdate": "agent_message_chunk",
        "content": {"type": "text", "text": text}}}})

for line in sys.stdin:
    msg = json.loads(line)
    method, rid = msg.get("method"), msg.get("id")
    if method == "initialize":
        result = {"protocolVersion": 1}
        if mode.endswith("-verified"):
            # The observed official 1.4.x identity triple (issue #6 AC4-3 pin).
            result["agentInfo"] = {
                "name": "antigravity-acp",
                "title": "Google Antigravity",
                "version": "1.4.0",
            }
        emit({"jsonrpc": "2.0", "id": rid, "result": result})
    elif method == "session/new":
        if mode == "usage-sequence-verified":
            # Official server new-session placeholder: used=0, no consumption.
            write_last(0)
            usage_frame(0)
        emit({"jsonrpc": "2.0", "id": rid, "result": {"sessionId": "s-1"}})
    elif method == "session/resume":
        if mode == "usage-sequence-verified":
            # Protocol-level simulation of a nonzero re-report arriving
            # OUTSIDE any prompt window (the official server's
            # _apply_session_model re-report shape, or a late-drained
            # trailing frame).  The adapter must never count it.
            re_report = read_last()
            if re_report is not None:
                usage_frame(re_report)
        emit({"jsonrpc": "2.0", "id": rid, "result": {
            "sessionId": (msg.get("params") or {}).get("sessionId") or "s-1"}})
    elif method in ("session/set_model", "session/set_config_option"):
        if mode == "usage-sequence-verified":
            re_report = read_last()
            if re_report is not None:
                # Official _apply_session_model re-emits last_reported_used
                # with zero actual consumption, outside any prompt turn
                # (issue #6 AC4-2).
                usage_frame(re_report)
        emit({"jsonrpc": "2.0", "id": rid, "result": {}})
    elif method == "session/prompt":
        if mode == "usage-sequence-verified":
            write_last(500)
            usage_frame(500)
            text_update("ok-seq")
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        elif mode in ("usage-update", "usage-update-verified"):
            # 1.3.0 _maybe_send_usage_update: token counters around the reply.
            for used in (100, 250, 300):
                emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                    "sessionUpdate": "usage_update", "used": used, "size": 1048576}}})
            # Invalid later observations must not erase the latest valid snapshot.
            emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                "sessionUpdate": "usage_update", "used": -1, "size": "unknown"}}})
            emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                "sessionUpdate": "usage_update", "used": True, "size": 1048576}}})
            text_update("ok-130")
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        elif mode == "usage-update-malformed":
            for used, size in ((True, 1048576), (12000, "unknown"), (-1, -1)):
                emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                    "sessionUpdate": "usage_update", "used": used, "size": size}}})
            text_update("malformed-only")
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        elif mode in ("prompt-result-usage", "prompt-result-only"):
            if mode == "prompt-result-usage":
                emit({"jsonrpc": "2.0", "method": "session/update", "params": {"update": {
                    "sessionUpdate": "usage_update", "used": 800, "size": 1048576}}})
            text_update("usage-result")
            emit({"jsonrpc": "2.0", "id": rid, "result": {
                "stopReason": "end_turn", "usage": {
                    "inputTokens": 100, "outputTokens": 20, "thoughtTokens": 5,
                    "cachedReadTokens": 30, "totalTokens": 125,
                }}})
        elif mode == "par-echo":
            import os as _os
            text_update(_os.environ.get("ACP_MUX_PAR", "<none>"))
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        elif mode == "sanitized-digest":
            # 1.3.0 api_errors.format_execution_error: the Google-API branch
            # drops the old "Agent execution error:" prefix entirely.
            text_update("This model is currently experiencing high demand.")
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
        else:
            text_update("plain")
            emit({"jsonrpc": "2.0", "id": rid, "result": {"stopReason": "end_turn"}})
'''


def _fake_server(tmp_path: Path, mode: str, spawn_count: Path | None = None) -> list[str]:
    script = tmp_path / "fake_acp_130.py"
    header = (
        f"MODE = {mode!r}\n"
        f"COUNTER = {str(spawn_count) if spawn_count is not None else ''!r}\n"
        f"LASTFILE = {str(tmp_path / 'last_used.txt')!r}\n"
    )
    script.write_text(header + FAKE, encoding="utf-8")
    return [str(script)]


@pytest.fixture
def no_slash_env(monkeypatch):
    # Mode is baked into the fake script; nothing env-related needs cleanup.
    yield


@pytest.mark.parametrize("stream", [False, True])
def test_usage_update_is_non_billing_context_occupancy(monkeypatch, tmp_path, no_slash_env, stream) -> None:
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "usage-update"), cwd=str(tmp_path)
    )
    client_module = sys.modules["antigravity_acp_130.client"]
    monkeypatch.setattr(
        client_module, "get_runtime_session_env",
        lambda: ("hermes-session-130", "unused-session-key"),
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10, stream=stream,
    )
    if stream:
        content = reply[0].choices[0].delta.content
        usage = reply[-1].usage
    else:
        content = reply.choices[0].message.content
        usage = reply.usage
    # Issue #6 AC4-1/AC4-3: this fake self-reports no `agentInfo`, so the
    # server's consumption semantics are UNVERIFIED.  Frames are never
    # accumulated, never synthesized into completion.usage, and never priced:
    # usage stays None (Core's designed usage-less path) and the only
    # surviving signal is the ungated latest-valid occupancy reading.
    assert usage is None
    assert content == "ok-130"
    assert "usage" not in content and "1048576" not in content
    telemetry = reply.antigravity_usage_telemetry
    assert telemetry["schema_id"] == "antigravity-acp-usage-v1"
    assert telemetry["status"] == "unavailable"
    assert telemetry["provider"] == "antigravity-acp"
    assert telemetry["server_consumption_semantics"] == "unverified"
    assert telemetry["turn_consumption"] is None
    assert telemetry["request_usage"] == {
        "input_tokens": None,
        "output_tokens": None,
        "cache_read_tokens": None,
        "cache_write_tokens": None,
        "reasoning_tokens": None,
    }
    assert telemetry["context_occupancy"] == {
        "source": "acp.session/update:usage_update",
        "scope": "unverified_server_semantics",
        "is_billing_usage": False,
        "used": 300,
        "size": 1048576,
    }
    store_payload = json.loads((tmp_path / "acp-state.json").read_text(encoding="utf-8"))
    assert "usage_totals" not in store_payload
    assert store_payload["usage_drop_counters"]["dropped_semantics_unverified"] == 3
    assert telemetry["native_session_id_hash"].startswith("sha256:")
    assert telemetry["turn_id_hash"].startswith("sha256:")
    assert "s-1" not in json.dumps(telemetry)


def test_verified_identity_accumulates_consumption_without_synthetic_split(
    monkeypatch, tmp_path, no_slash_env
) -> None:
    """Issue #6 AC4-1/AC4-3: a source-verified identity accumulates observed
    consumption sums, but completion.usage stays None without the server's own
    per-turn breakdown — the fabricated prompt/completion split is gone."""
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "usage-update-verified"), cwd=str(tmp_path)
    )
    client_module = sys.modules["antigravity_acp_130.client"]
    monkeypatch.setattr(
        client_module, "get_runtime_session_env",
        lambda: ("hermes-session-verified", ""),
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10, stream=False,
    )
    assert reply.usage is None  # no session/prompt result usage in this fake
    assert reply.choices[0].message.content == "ok-130"
    telemetry = reply.antigravity_usage_telemetry
    assert telemetry["server_consumption_semantics"] == "verified"
    assert telemetry["turn_consumption"] == {
        "source": "acp.session/update:usage_update",
        "scope": "per_model_call_consumption_delta",
        "is_billing_usage": False,
        "semantics": "verified",
        "model_calls_observed": 3,
        "total_tokens": 650,
    }
    store_payload = json.loads((tmp_path / "acp-state.json").read_text(encoding="utf-8"))
    entry = store_payload["usage_totals"]["hermes-session-verified"]
    assert entry["summed_tokens"] == 650
    assert entry["frames_observed"] == 3
    assert "s-1" not in json.dumps(entry)


def test_verified_session_sequence_counts_only_real_consumption(
    monkeypatch, tmp_path, no_slash_env
) -> None:
    """Issue #6 review: full lifecycle on a verified fake server.

    new-session used=0 -> set_model re-report 0 -> real 500 -> resume with a
    nonzero re-report of 500 arriving outside any prompt window -> real 500.
    The durable total must be exactly 1000: the two zero placeholders land in
    dropped_zero, the nonzero re-report in dropped_outside_prompt_turn, and
    both real calls accumulate.
    """
    client = _load_client(
        monkeypatch,
        args=_fake_server(tmp_path, "usage-sequence-verified"),
        cwd=str(tmp_path),
    )
    client_module = sys.modules["antigravity_acp_130.client"]
    monkeypatch.setattr(
        client_module, "get_runtime_session_env",
        lambda: ("hermes-session-seq", ""),
    )
    first = client.chat.completions.create(
        model="model-a", messages=[{"role": "user", "content": "hi"}], timeout=10,
    )
    assert first.choices[0].message.content == "ok-seq"
    # Same conversation AND same model: the adapter resumes the native
    # session (a model change would deliberately rotate to a fresh session).
    # The resume response carries the simulated out-of-window re-report.
    second = client.chat.completions.create(
        model="model-a",
        messages=[
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "ok-seq"},
            {"role": "user", "content": "again"},
        ],
        timeout=10,
    )
    assert second.choices[0].message.content == "ok-seq"

    store_payload = json.loads((tmp_path / "acp-state.json").read_text(encoding="utf-8"))
    entry = store_payload["usage_totals"]["hermes-session-seq"]
    assert entry["summed_tokens"] == 1000
    assert entry["frames_observed"] == 2
    counters = store_payload["usage_drop_counters"]
    assert counters == {
        "frames_seen": 5,
        "dropped_zero": 2,
        "dropped_outside_prompt_turn": 1,
    }
    assert counters.get("dropped_semantics_unverified", 0) == 0
    # Per-turn telemetry stays honest too: the second turn observed exactly
    # one real call (500), not the re-report.
    assert second.antigravity_usage_telemetry["turn_consumption"]["total_tokens"] == 500
    assert second.antigravity_usage_telemetry["turn_consumption"]["model_calls_observed"] == 1


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("mode", ["prompt-result-usage", "prompt-result-only"])
def test_prompt_result_usage_is_exposed(monkeypatch, tmp_path, stream, mode) -> None:
    client = _load_client(monkeypatch, args=_fake_server(tmp_path, mode), cwd=str(tmp_path))
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10, stream=stream,
    )
    usage = reply[-1].usage if stream else reply.usage
    assert usage.prompt_tokens == 100
    assert usage.completion_tokens == 25
    assert usage.total_tokens == 125
    assert usage.completion_tokens_details.reasoning_tokens == 5
    assert usage.prompt_tokens_details.cached_tokens == 30


@pytest.mark.parametrize("field,bad", [
    ("inputTokens", -1), ("outputTokens", True), ("totalTokens", "10"),
    ("thoughtTokens", -1), ("cachedReadTokens", False), ("cachedWriteTokens", 1.5),
])
def test_invalid_prompt_usage_is_rejected(monkeypatch, tmp_path, field, bad) -> None:
    _load_client(monkeypatch, args=_fake_server(tmp_path, "plain"), cwd=str(tmp_path))
    module = sys.modules["antigravity_acp_130.client"]
    usage = {"inputTokens": 10, "outputTokens": 2, "totalTokens": 12}
    usage[field] = bad
    assert module._turn_usage_from_prompt_result({"usage": usage}) is None


def test_zero_usage_update_frames_create_no_totals_entry(monkeypatch, tmp_path, no_slash_env) -> None:
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "plain"), cwd=str(tmp_path)
    )
    client_module = sys.modules["antigravity_acp_130.client"]
    monkeypatch.setattr(
        client_module, "get_runtime_session_env",
        lambda: ("hermes-session-with-no-frames", ""),
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10,
    )
    assert reply.choices[0].message.content == "plain"
    store_payload = json.loads((tmp_path / "acp-state.json").read_text(encoding="utf-8"))
    assert "usage_totals" not in store_payload


def test_malformed_usage_updates_are_not_emitted(monkeypatch, tmp_path, no_slash_env) -> None:
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "usage-update-malformed"), cwd=str(tmp_path)
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10,
    )
    assert reply.usage is None
    assert reply.choices[0].message.content == "malformed-only"
    assert reply.antigravity_usage_telemetry["context_occupancy"] is None
    assert all(value is None for value in reply.antigravity_usage_telemetry["request_usage"].values())


def test_sanitized_google_api_digest_stays_plain_text_no_retry_storm(monkeypatch, tmp_path, no_slash_env) -> None:
    # 1.3.0 removed the "Agent execution error:" prefix for Google-API-shaped
    # failures.  Unknown in-band text must not re-arm failover: exactly one
    # spawn, and the text surfaces as the answer.
    counter = tmp_path / "spawns"
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "sanitized-digest", counter),
        cwd=str(tmp_path), retries=4,
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}],
        timeout=10,
    )
    assert "high demand" in reply.choices[0].message.content
    assert counter.read_text(encoding="utf-8").count("spawn") == 1
    assert reply.usage is None
    assert reply.antigravity_usage_telemetry["status"] == "unavailable"
    assert reply.antigravity_usage_telemetry["context_occupancy"] is None


def test_par_pin_reads_sibling_file_and_fails_closed(monkeypatch, tmp_path) -> None:
    # Loading the client package is what imports client.py; grab it back.
    _load_client(monkeypatch, args=["-c", "pass"], cwd=str(tmp_path))
    import importlib
    client_mod = importlib.import_module("antigravity_acp_130.client")
    original = client_mod.__file__
    try:
        fake = tmp_path / "client.py"
        fake.write_text("", encoding="utf-8")
        monkeypatch.setattr(client_mod, "__file__", str(fake))
        (tmp_path / "par.txt").write_text("", encoding="utf-8")
        assert client_mod._read_par_pin() is None
        real_par = tmp_path / "agy_acp_server.par"
        real_par.write_text("fake", encoding="utf-8")
        (tmp_path / "par.txt").write_text(f"  {real_par}  \n", encoding="utf-8")
        assert client_mod._read_par_pin() == str(real_par)
        (tmp_path / "par.txt").write_text(str(tmp_path / "gone.par"), encoding="utf-8")
        with pytest.raises(RuntimeError, match="par.txt pins missing PAR"):
            client_mod._read_par_pin()
    finally:
        monkeypatch.setattr(client_mod, "__file__", original)


def test_par_pin_injected_into_spawn_env_only_when_present(monkeypatch, tmp_path, no_slash_env) -> None:
    module_name = "antigravity_acp_130"
    client = _load_client(
        monkeypatch, args=_fake_server(tmp_path, "par-echo"), cwd=str(tmp_path)
    )
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}], timeout=10
    )
    assert reply.choices[0].message.content == "<none>"

    import importlib
    client_mod = importlib.import_module(module_name + ".client")
    real_par = tmp_path / "agy_acp_server.par"
    real_par.write_text("fake", encoding="utf-8")
    monkeypatch.setattr(client_mod, "_read_par_pin", lambda: str(real_par))
    reply = client.chat.completions.create(
        model="antigravity-acp", messages=[{"role": "user", "content": "hi"}], timeout=10
    )
    assert reply.choices[0].message.content == str(real_par)
