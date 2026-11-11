"""Truthful ACP usage telemetry and per-session delta contract gates.

Deterministic unit + fixture-contract coverage for the provider-side
`antigravity_usage_telemetry` boundary settled in docs/acp-usage-telemetry.md:

- the bridge copies the attribute unchanged onto StreamChunks (stream parity
  without widening generic OpenAI usage fields),
- usage_update occupancy remains latest-valid per turn while all valid used
  deltas accumulate only for an explicit Hermes session,
- the downstream Core/HGK boundary fixture documents the sessions-default
  zero/unknown projection and keeps the worker_session_id-missing class
  separate, without executing Hermes Core or HGK code.

Fake subprocess / pure units only: no credentials, no Google binary.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "acp-usage-hgk-boundary.json"


def _load_client_module(monkeypatch, tmp_path: Path):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(tmp_path / "antigravity-acp-telemetry-state.json"),
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        str(tmp_path / "antigravity-acp-telemetry-limits.json"),
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

    module_name = "antigravity_acp_telemetry_contract"
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
    return (
        importlib.import_module(module_name + ".client"),
        importlib.import_module(module_name + ".bridge"),
    )


def test_bridge_propagates_telemetry_onto_stream_chunks_unchanged(monkeypatch, tmp_path) -> None:
    _, bridge = _load_client_module(monkeypatch, tmp_path)
    telemetry = {
        "schema_id": "antigravity-acp-usage-v1",
        "status": "unavailable",
        "provider": "antigravity-acp",
        "model": "gemini-3.8-flash-high",
        "request_usage": {bucket: None for bucket in (
            "input_tokens", "output_tokens", "cache_read_tokens",
            "cache_write_tokens", "reasoning_tokens")},
        "provenance": {"source": "official_acp_v1.4.0"},
        "native_session_id_hash": "sha256:aa",
        "turn_id_hash": "sha256:bb",
        "context_occupancy": None,
    }
    completion = SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content="ok", tool_calls=None),
            finish_reason="stop",
        )],
        usage=None,
        model="gemini-3.8-flash-high",
        antigravity_usage_telemetry=telemetry,
    )

    chunks = bridge.completion_to_stream_chunks(completion)

    assert chunks.antigravity_usage_telemetry is telemetry
    # Generic OpenAI fields stay untouched: data chunk and usage chunk both
    # carry usage=None; the bridge never synthesizes a usage object.
    assert all(chunk.usage is None for chunk in chunks)
    assert not any(
        hasattr(chunk, "antigravity_usage_telemetry") for chunk in chunks
    )


def test_stream_chunks_are_json_free_of_raw_identity(monkeypatch, tmp_path) -> None:
    client, _ = _load_client_module(monkeypatch, tmp_path)
    telemetry = client._build_usage_telemetry(
        model="gemini-3.8-flash-high",
        session_id="raw-native-session-id",
        turn_id_hash=None,
        context_occupancy={"source": "acp.session/update:usage_update",
                           "scope": "per_model_call_consumption_delta",
                           "is_billing_usage": False,
                           "used": 12000, "size": 1048576},
    )
    serialized = json.dumps(telemetry)
    assert "raw-native-session-id" not in serialized
    assert telemetry["native_session_id_hash"].startswith("sha256:")
    assert telemetry["turn_id_hash"].startswith("sha256:")
    assert telemetry["context_occupancy"] == {
        "source": "acp.session/update:usage_update",
        "scope": "per_model_call_consumption_delta",
        "is_billing_usage": False,
        "used": 12000,
        "size": 1048576,
    }
    assert all(value is None for value in telemetry["request_usage"].values())


def test_context_occupancy_captures_latest_valid_observation(monkeypatch, tmp_path) -> None:
    client, _ = _load_client_module(monkeypatch, tmp_path)
    stats = {"turn_id_hash": "sha256:turn"}
    for update in (
        {"sessionUpdate": "usage_update", "used": 11840, "size": 1048576},
        {"sessionUpdate": "usage_update", "used": 12000},
        {"sessionUpdate": "usage_update", "used": "bogus", "size": True},
        {"sessionUpdate": "usage_update", "used": float("nan")},
        {"sessionUpdate": "usage_update", "used": -5, "size": -1},
    ):
        client._capture_context_occupancy(update, stats)
    assert stats["context_occupancy"] == {
        "source": "acp.session/update:usage_update",
        "scope": "unverified_server_semantics",
        "is_billing_usage": False,
        "used": 12000,
        "size": 1048576,
    }


def test_usage_update_deltas_accumulate_for_explicit_hermes_session(monkeypatch, tmp_path) -> None:
    client, _ = _load_client_module(monkeypatch, tmp_path)
    monkeypatch.setattr(
        client, "get_runtime_session_env",
        lambda: ("hermes-session-explicit", "session-key-must-not-key-totals"),
    )
    stats = {
        "native_session_id": "raw-native-session-identifier",
        "model": "gemini-3.8-flash-high",
        "prompt": "prompt text secret",
        "command": "private-command",
        "path": "/private/workspace",
        # Issue #6 gates: accumulation requires a source-verified server
        # identity and an in-flight prompt turn (see _capture_usage_delta).
        client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
        client._PROMPT_TURN_ACTIVE_KEY: True,
    }

    for used in (100, 250, 300):
        client._capture_usage_delta(
            {"sessionUpdate": "usage_update", "used": used, "size": 1048576},
            stats,
        )

    import os

    payload = json.loads(Path(os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"]).read_text())
    totals = payload["usage_totals"]
    assert set(totals) == {"hermes-session-explicit"}
    entry = totals["hermes-session-explicit"]
    assert entry["schema"] == "antigravity-acp-usage-totals-v1"
    assert entry["hermes_session_id"] == "hermes-session-explicit"
    assert entry["model"] == "gemini-3.8-flash-high"
    assert entry["summed_tokens"] == 650
    assert entry["by_model"] == {"gemini-3.8-flash-high": 650}
    assert entry["frames_observed"] == 3
    assert entry["first_seen"] <= entry["last_seen"]
    assert entry["native_session_id_hash"].startswith("sha256:")
    assert entry["provenance"] == (
        "acp.usage_update.delta_sum(main-agent-only, may under-report)"
    )
    serialized = json.dumps(payload)
    assert "raw-native-session-identifier" not in serialized
    assert "session-key-must-not-key-totals" not in serialized
    assert all(
        forbidden not in serialized
        for forbidden in ("prompt text secret", "private-command", "/private/workspace")
    )


def test_usage_totals_keep_truthful_model_breakdown_when_switching_back(monkeypatch, tmp_path) -> None:
    client, _ = _load_client_module(monkeypatch, tmp_path)
    monkeypatch.setattr(
        client, "get_runtime_session_env",
        lambda: ("hermes-session-model-switch", "unused-session-key"),
    )

    for model, used in (("model-a", 100), ("model-b", 200), ("model-a", 50)):
        client._capture_usage_delta(
            {"sessionUpdate": "usage_update", "used": used},
            {
                "native_session_id": f"raw-native-{model}",
                "model": model,
                client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
                client._PROMPT_TURN_ACTIVE_KEY: True,
            },
        )

    import os

    payload = json.loads(Path(os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"]).read_text())
    entry = payload["usage_totals"]["hermes-session-model-switch"]
    assert entry["summed_tokens"] == 350
    assert entry["by_model"] == {"model-a": 150, "model-b": 200}
    assert entry["model"] is None
    assert entry["frames_observed"] == 3


def test_legacy_mixed_total_stays_unattributed_on_first_breakdown_write(
    monkeypatch, tmp_path
) -> None:
    client, _ = _load_client_module(monkeypatch, tmp_path)
    import os

    state_path = Path(os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"])
    legacy_states = {"old-affinity": {"retained": True}}
    state_path.write_text(
        json.dumps({
            "version": 1,
            "states": legacy_states,
            "usage_totals": {
                "legacy-session": {
                    "schema": "antigravity-acp-usage-totals-v1",
                    "hermes_session_id": "legacy-session",
                    "model": "latest-model-b",
                    "summed_tokens": 300,
                    "frames_observed": 3,
                    "first_seen": 1,
                    "last_seen": 2,
                    "native_session_id_hash": "sha256:old-hash",
                    "provenance": (
                        "acp.usage_update.delta_sum(main-agent-only, may under-report)"
                    ),
                },
            },
        }),
        encoding="utf-8",
    )

    client.conversation_registry.add_usage_delta(
        "legacy-session",
        model="model-a",
        used=50,
        native_session_id_hash="sha256:new-hash",
    )

    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["states"] == legacy_states
    entry = payload["usage_totals"]["legacy-session"]
    assert entry["summed_tokens"] == 350
    assert entry["by_model"] == {"__unattributed__": 300, "model-a": 50}
    assert entry["model"] is None


def test_single_usage_delta_is_recorded_and_absent_identity_is_not_guessed(monkeypatch, tmp_path) -> None:
    client, _ = _load_client_module(monkeypatch, tmp_path)
    import os

    state_path = Path(os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"])
    monkeypatch.setattr(client, "get_runtime_session_env", lambda: ("only-session-id", ""))
    client._capture_usage_delta(
        {"sessionUpdate": "usage_update", "used": 17},
        {
            "native_session_id": "native-a",
            "model": "model-a",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: True,
        },
    )
    payload = json.loads(state_path.read_text(encoding="utf-8"))
    assert payload["usage_totals"]["only-session-id"]["summed_tokens"] == 17
    assert payload["usage_totals"]["only-session-id"]["frames_observed"] == 1

    # The second tuple value is a session key, not the explicit Hermes session
    # ID. A native id or session key must never be guessed as the totals key.
    # The drop itself is persisted as a diagnostic counter (historical reference): a silent
    # drop is the exact failure mode this store must keep observable.
    state_path.unlink()
    monkeypatch.setattr(
        client, "get_runtime_session_env", lambda: ("", "session-key-only")
    )
    client._capture_usage_delta(
        {"sessionUpdate": "usage_update", "used": 99},
        {
            "native_session_id": "native-b",
            "model": "model-b",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: True,
        },
    )
    payload = json.loads(state_path.read_text())
    assert not payload.get("usage_totals")
    assert payload["usage_drop_counters"] == {
        "frames_seen": 1,
        "dropped_no_session_identity": 1,
    }


def test_usage_frame_drop_counters_cover_every_gate(monkeypatch, tmp_path) -> None:
    client, _ = _load_client_module(monkeypatch, tmp_path)
    import os

    state_path = Path(os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"])
    monkeypatch.setattr(client, "get_runtime_session_env", lambda: ("", ""))

    # Non-candidate frames are never counted.
    client._capture_usage_delta({"sessionUpdate": "agent_message_chunk"}, {"native_session_id": "n"})
    client._capture_usage_delta({"sessionUpdate": "usage_update"}, {"native_session_id": "n"})
    assert not state_path.exists()

    # Candidate with a malformed value: dropped_invalid (still a seen frame).
    client._capture_usage_delta(
        {"sessionUpdate": "usage_update", "used": "bogus"},
        {
            "native_session_id": "native-a",
            "model": "model-a",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: True,
        },
    )
    # Candidate with an identity but no native session id: no_native counter.
    monkeypatch.setattr(client, "get_runtime_session_env", lambda: ("session-c", ""))
    client._capture_usage_delta(
        {"sessionUpdate": "usage_update", "used": 10},
        {
            "model": "model-a",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: True,
        },
    )
    counters = json.loads(state_path.read_text())["usage_drop_counters"]
    assert counters == {
        "frames_seen": 2,
        "dropped_invalid": 1,
        "dropped_no_native_session": 1,
    }

    # A fully valid frame increments frames_seen and no drop counter.
    client._capture_usage_delta(
        {"sessionUpdate": "usage_update", "used": 42},
        {
            "native_session_id": "native-a",
            "model": "model-a",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: True,
        },
    )
    payload = json.loads(state_path.read_text())
    assert payload["usage_drop_counters"]["frames_seen"] == 3
    assert payload["usage_totals"]["session-c"]["summed_tokens"] == 42

    # Issue #6 gates: each rejection names its own reason, never silently.
    client._capture_usage_delta(  # unverified server identity
        {"sessionUpdate": "usage_update", "used": 7},
        {"native_session_id": "native-a", "model": "model-a"},
    )
    client._capture_usage_delta(  # verified but outside the prompt-turn window
        {"sessionUpdate": "usage_update", "used": 7},
        {
            "native_session_id": "native-a",
            "model": "model-a",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
        },
    )
    client._capture_usage_delta(  # in-window zero placeholder
        {"sessionUpdate": "usage_update", "used": 0},
        {
            "native_session_id": "native-a",
            "model": "model-a",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: True,
        },
    )
    client._capture_usage_delta(  # zero from an UNVERIFIED server: still zero
        {"sessionUpdate": "usage_update", "used": 0},
        {"native_session_id": "native-a", "model": "model-a"},
    )
    counters = json.loads(state_path.read_text())["usage_drop_counters"]
    assert counters == {
        "frames_seen": 7,
        "dropped_invalid": 1,
        "dropped_no_native_session": 1,
        "dropped_semantics_unverified": 1,
        "dropped_outside_prompt_turn": 1,
        "dropped_zero": 2,
    }
    # The gated frames changed nothing in the totals.
    assert payload["usage_totals"]["session-c"]["summed_tokens"] == 42


def test_identical_used_values_in_window_both_accumulate_while_rerports_do_not(
    monkeypatch, tmp_path
) -> None:
    """Issue #6 AC4-2: retransmission discrimination is event-order based.

    Two legitimate model calls that happen to consume the SAME token count
    must both accumulate (no value-equality dedup), while a model-switch
    re-report of `last_reported_used` outside the prompt-turn window must not.
    """
    client, _ = _load_client_module(monkeypatch, tmp_path)
    import os

    monkeypatch.setattr(client, "get_runtime_session_env", lambda: ("dup-value-session", ""))
    state_path = Path(os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"])

    def stats(active: bool) -> dict:
        return {
            "native_session_id": "native-dup",
            "model": "model-a",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: active,
        }

    # Turn 1: two real calls consuming identical amounts.
    for _ in range(2):
        client._capture_usage_delta(
            {"sessionUpdate": "usage_update", "used": 500}, stats(True)
        )
    # Model switch between turns: server re-reports the SAME value with no
    # consumption.  Same number, different lifecycle position -> excluded.
    client._capture_usage_delta(
        {"sessionUpdate": "usage_update", "used": 500}, stats(False)
    )
    # Turn 2: another real identical call.
    client._capture_usage_delta(
        {"sessionUpdate": "usage_update", "used": 500}, stats(True)
    )

    payload = json.loads(state_path.read_text())
    entry = payload["usage_totals"]["dup-value-session"]
    assert entry["summed_tokens"] == 1500  # 3 real calls, not 2000, not 500
    assert entry["frames_observed"] == 3
    assert payload["usage_drop_counters"]["dropped_outside_prompt_turn"] == 1


def test_valid_used_with_invalid_size_is_rejected_by_every_consumer(
    monkeypatch, tmp_path
) -> None:
    """Issue #6 review: one validity contract for all three consumers.

    A frame whose `used` is valid but whose `size` is corrupt must be
    rejected identically by the durable sum (_capture_usage_delta), the turn
    sum (_capture_turn_usage) and occupancy (_capture_context_occupancy) —
    the surfaces can never disagree about which frames were real.  A frame
    carrying only `used` stays valid (partial frames are legal).
    """
    client, _ = _load_client_module(monkeypatch, tmp_path)
    import os

    monkeypatch.setattr(client, "get_runtime_session_env", lambda: ("split-frame-session", ""))
    state_path = Path(os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"])

    def stats() -> dict:
        return {
            "native_session_id": "native-split",
            "model": "model-a",
            "turn_id_hash": "sha256:turn",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: True,
        }

    corrupt = {"sessionUpdate": "usage_update", "used": 500, "size": "unknown"}
    partial = {"sessionUpdate": "usage_update", "used": 250}

    delta_stats = stats()
    turn_stats = stats()
    occupancy_stats = stats()
    for frame in (corrupt, partial):
        client._capture_usage_delta(frame, delta_stats)
        client._capture_turn_usage(frame, turn_stats)
        client._capture_context_occupancy(frame, occupancy_stats)

    # Durable sum: only the partial frame accumulated.
    payload = json.loads(state_path.read_text())
    entry = payload["usage_totals"]["split-frame-session"]
    assert entry["summed_tokens"] == 250
    assert entry["frames_observed"] == 1
    assert payload["usage_drop_counters"]["dropped_invalid"] == 1

    # Turn sum: same verdict.
    assert turn_stats[client._TURN_USAGE_SUM_KEY] == 250
    assert turn_stats[client._TURN_USAGE_CALLS_KEY] == 1

    # Occupancy: the corrupt frame contributed nothing; the partial frame
    # updated only `used` and never carried a bogus size.
    assert occupancy_stats["context_occupancy"]["used"] == 250
    assert "size" not in occupancy_stats["context_occupancy"]


def test_state_save_preserves_usage_drop_counters_and_totals(monkeypatch, tmp_path) -> None:
    # Live regression 2026-11-04: a counter write (frames_seen:3) was erased by
    # the very next state-save because _write_file rebuilt the document from
    # {version, states, usage_totals} only. Any state save must carry forward
    # every diagnostic block it read from disk inside the same critical section.
    client, _ = _load_client_module(monkeypatch, tmp_path)
    import os
    import time

    state_path = Path(os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"])
    registry = client.conversation_registry
    monkeypatch.setattr(client, "get_runtime_session_env", lambda: ("save-session", ""))
    client._capture_usage_delta(
        {"sessionUpdate": "usage_update", "used": "bogus"},
        {
            "native_session_id": "native-a",
            "model": "model-a",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: True,
        },
    )
    client._capture_usage_delta(
        {"sessionUpdate": "usage_update", "used": 11},
        {
            "native_session_id": "native-a",
            "model": "model-a",
            client._SERVER_CONSUMPTION_SEMANTICS_KEY: client._USAGE_SEMANTICS_VERIFIED,
            client._PROMPT_TURN_ACTIVE_KEY: True,
        },
    )
    before = json.loads(state_path.read_text())
    assert before["usage_drop_counters"] == {
        "frames_seen": 2,
        "dropped_invalid": 1,
    }
    assert before["usage_totals"]["save-session"]["summed_tokens"] == 11

    state = client.ACPConversationState(
        session_id="native-save-id",
        context_fingerprint="context-fingerprint",
        request_fingerprints=("request-fingerprint",),
        response_fingerprint="response-fingerprint",
        updated_at=time.time(),
        native_tokens=1,
    )
    registry.put("affinity-save", state)

    after = json.loads(state_path.read_text())
    assert after["usage_drop_counters"] == before["usage_drop_counters"]
    assert after["usage_totals"] == before["usage_totals"]
    assert "affinity-save" in after["states"]


def test_usage_totals_write_is_atomic_and_preserves_state_shape(monkeypatch, tmp_path) -> None:
    client, _ = _load_client_module(monkeypatch, tmp_path)
    import os
    import stat
    import time

    state_module = sys.modules[client.__package__ + ".conversation_state"]
    registry = client.conversation_registry
    state = client.ACPConversationState(
        session_id="native-state-id",
        context_fingerprint="context-fingerprint",
        request_fingerprints=("request-fingerprint",),
        response_fingerprint="response-fingerprint",
        updated_at=time.time(),
        native_tokens=23,
    )
    registry.put("affinity-key", state)
    state_path = Path(os.environ["HERMES_ANTIGRAVITY_ACP_STATE_FILE"])
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    before = json.loads(state_path.read_text(encoding="utf-8"))
    before_states = before["states"]

    replace_calls = []
    real_replace = state_module.os.replace

    def observe_replace(source, target):
        replace_calls.append((Path(source), Path(target)))
        real_replace(source, target)

    monkeypatch.setattr(state_module.os, "replace", observe_replace)
    registry.add_usage_delta(
        "hermes-session-atomic",
        model="model-a",
        used=7,
        native_session_id_hash="sha256:opaque-native-id",
    )

    after = json.loads(state_path.read_text(encoding="utf-8"))
    assert after["states"] == before_states
    assert replace_calls and replace_calls[-1][1] == state_path
    assert replace_calls[-1][0].parent == state_path.parent
    assert not replace_calls[-1][0].exists()
    persisted_state = registry.get("affinity-key")
    assert persisted_state is not None
    assert persisted_state.session_id == "native-state-id"
    assert after["usage_totals"]["hermes-session-atomic"]["summed_tokens"] == 7

    # A later legacy state write must preserve the additive totals section.
    registry.put("affinity-key", state)
    rewritten = json.loads(state_path.read_text(encoding="utf-8"))
    assert rewritten["states"] == before_states
    assert rewritten["usage_totals"] == after["usage_totals"]


def test_context_occupancy_requires_active_turn_and_valid_numbers(monkeypatch, tmp_path) -> None:
    client, _ = _load_client_module(monkeypatch, tmp_path)
    stats: dict = {}
    client._capture_context_occupancy(
        {"sessionUpdate": "usage_update", "used": 10, "size": 20}, stats)
    assert "context_occupancy" not in stats

    stats = {"turn_id_hash": "sha256:turn"}
    for update in (
        {"sessionUpdate": "agent_message_chunk", "used": 10, "size": 20},
        {"sessionUpdate": "usage_update", "used": "10"},
        {"sessionUpdate": "usage_update", "used": float("inf")},
        {"sessionUpdate": "usage_update"},
    ):
        client._capture_context_occupancy(update, stats)
    assert "context_occupancy" not in stats


def test_downstream_boundary_fixture_documents_known_zero_projection() -> None:
    """Reproducible boundary shape for the Core/HGK owners (historical reference).

    Hermes Core exits its usage recording before any per-model row exists when
    ``usage is None``; the sessions row then carries schema defaults (0 tokens,
    NULL billing provider). HGK's local_usage fallback treats those defaults as
    known usage and renders ``unknown/<model>: 0``. This fixture pins the exact
    boundary JSON that both owners must regress in their own repositories; it
    does not execute Core or HGK and does not modify either.
    """
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    provider = fixture["provider_response"]
    assert provider["usage"] is None
    telemetry = provider["antigravity_usage_telemetry"]
    assert telemetry["schema_id"] == "antigravity-acp-usage-v1"
    assert telemetry["status"] == "unavailable"
    assert telemetry["context_occupancy"] is None

    core = fixture["hermes_core_state"]
    assert core["session_model_usage_rows"] == []
    assert core["sessions_row_defaults"] == {
        "input_tokens": 0, "output_tokens": 0, "billing_provider": None,
    }

    # HGK fallback projection: with no per-model rows, sessions defaults are
    # accepted as known usage -> zero-token unknown provider display.
    projection = fixture["hgk_local_usage_projection"]
    defaults = core["sessions_row_defaults"]
    provider_label = defaults["billing_provider"] or "unknown"
    assert projection == {
        "model_key": f"{provider_label}/{telemetry['model']}",
        "input_tokens": defaults["input_tokens"],
        "output_tokens": defaults["output_tokens"],
        "total_tokens": defaults["input_tokens"] + defaults["output_tokens"],
    }

    # The worker_session_id-missing run-attribution class stays separate from
    # ACP usage absence and must never be folded into usage reporting.
    attribution = fixture["run_attribution_diagnostic"]
    assert attribution["class"] == "worker_session_id_missing"
    assert attribution["observed_runs"] == 173
    assert attribution["independent_of_acp_usage_unavailability"] is True
