"""Dynamic usage-semantics canary: growth gate + earned verdicts, no version pins.

Covers the replacement for the retired hardcoded ``agentInfo`` whitelist
(1.4.0/1.4.4 frozenset) that went stale the day 1.5.2 shipped:

- the per-turn growth-consistency gate rejects order-of-magnitude inflated
  ``inputTokens`` for EVERY server identity (2026-11-23 incident replay),
- verdicts are earned at runtime: consecutive consistent tested turns promote
  an identity to ``behaviorally_verified``; any divergence demotes it,
- verdicts persist in the durable store across registry instances and state
  saves, and unknown identities are unverified until earned (fail closed).

Pure units + fake identities only: no credentials, no Google binary, no real
vendor model names (AGENTS.md fixture rule).
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import sys
import time
import types
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"

FAKE_IDENTITY = "fake-acp|Fake ACP|9.9.9"


def _load_package(monkeypatch, tmp_path: Path):
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(tmp_path / "antigravity-acp-canary-state.json"),
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_SEMANTICS_FILE",
        str(tmp_path / "antigravity-acp-canary-semantics.json"),
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        str(tmp_path / "antigravity-acp-canary-limits.json"),
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

    module_name = "antigravity_acp_canary"
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
    client = importlib.import_module(module_name + ".client")
    conversation_state = importlib.import_module(module_name + ".conversation_state")
    client._TURN_USAGE_BASELINES.clear()
    return client, conversation_state


def _state_payload(tmp_path: Path) -> dict:
    path = tmp_path / "antigravity-acp-canary-state.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _semantics_payload(tmp_path: Path) -> dict:
    path = tmp_path / "antigravity-acp-canary-semantics.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# Growth-consistency gate (pure unit)


def _load_contract(monkeypatch, tmp_path):
    """The gate decisions moved to the shared single owner (parked/usage_contract)."""
    _load_package(monkeypatch, tmp_path)
    return importlib.import_module("antigravity_acp_canary.parked.usage_contract")


def test_growth_gate_rejects_incident_replay(monkeypatch, tmp_path) -> None:
    contract = _load_contract(monkeypatch, tmp_path)
    # 2026-11-23 incident: a ~3.2K local turn reported as ~499K growth.
    ok, actual, expected = contract.reported_usage_growth_consistent(
        prev_reported=119_000,
        reported=619_000,
        prev_local=30_000,
        local=33_200,
    )
    assert ok is False
    assert actual == 500_000
    assert expected == 3_200


def test_growth_gate_accepts_legitimate_server_overhead(monkeypatch, tmp_path) -> None:
    contract = _load_contract(monkeypatch, tmp_path)
    # Server adds its own per-turn records (reasoning/tool transcripts) the
    # local estimate never sees: several times the visible growth must pass.
    ok, _, _ = contract.reported_usage_growth_consistent(
        prev_reported=150_000,
        reported=188_000,
        prev_local=120_000,
        local=132_000,
    )
    assert ok is True
    # Edge of tolerance: exactly 8x growth passes.
    ok, _, _ = contract.reported_usage_growth_consistent(
        prev_reported=10_000,
        reported=10_000 + 8 * (1_000 + 1),
        prev_local=10_000,
        local=11_000,
    )
    assert ok is True


def test_growth_gate_accepts_negative_reanchor_within_slack(monkeypatch, tmp_path) -> None:
    contract = _load_contract(monkeypatch, tmp_path)
    # Context rotation re-anchors both sides downward by a similar amount.
    ok, _, _ = contract.reported_usage_growth_consistent(
        prev_reported=400_000,
        reported=120_000,
        prev_local=380_000,
        local=110_000,
    )
    assert ok is True
    # A server that silently collapses while the transcript keeps growing is
    # rejected (divergence far beyond the flat slack).
    ok, _, _ = contract.reported_usage_growth_consistent(
        prev_reported=400_000,
        reported=1_000,
        prev_local=380_000,
        local=390_000,
    )
    assert ok is False


# --------------------------------------------------------------------------
# Dynamic verdict lifecycle


def test_verdict_promotes_only_after_consecutive_consistent_turns(
    monkeypatch, tmp_path
) -> None:
    _, conversation_state = _load_package(monkeypatch, tmp_path)
    registry = conversation_state.ConversationStateRegistry()
    assert registry.semantics_verdict(FAKE_IDENTITY) == "unverified"
    for turn in range(conversation_state.SEMANTICS_PROMOTE_AFTER - 1):
        entry = registry.record_semantics_evidence(FAKE_IDENTITY, ok=True)
        assert entry["verdict"] == "unverified", f"promoted too early at turn {turn}"
    entry = registry.record_semantics_evidence(FAKE_IDENTITY, ok=True)
    assert entry["verdict"] == "behaviorally_verified"
    assert registry.semantics_verdict(FAKE_IDENTITY) == "behaviorally_verified"
    assert entry["provenance"] == "behavioral_growth_correlation"


def test_inconsistency_demotes_and_identity_can_re_earn(monkeypatch, tmp_path) -> None:
    _, conversation_state = _load_package(monkeypatch, tmp_path)
    registry = conversation_state.ConversationStateRegistry()
    for _ in range(conversation_state.SEMANTICS_PROMOTE_AFTER):
        registry.record_semantics_evidence(FAKE_IDENTITY, ok=True)
    assert registry.semantics_verdict(FAKE_IDENTITY) == "behaviorally_verified"
    entry = registry.record_semantics_evidence(FAKE_IDENTITY, ok=False)
    assert entry["verdict"] == "unverified"
    assert entry["consistent_turns"] == 0
    assert entry["rejected_turns"] == 1
    assert registry.semantics_verdict(FAKE_IDENTITY) == "unverified"
    for _ in range(conversation_state.SEMANTICS_PROMOTE_AFTER):
        entry = registry.record_semantics_evidence(FAKE_IDENTITY, ok=True)
    assert entry["verdict"] == "behaviorally_verified"


def test_verdicts_persist_across_registry_instances_and_state_saves(
    monkeypatch, tmp_path
) -> None:
    _, conversation_state = _load_package(monkeypatch, tmp_path)
    registry = conversation_state.ConversationStateRegistry()
    for _ in range(conversation_state.SEMANTICS_PROMOTE_AFTER):
        registry.record_semantics_evidence(FAKE_IDENTITY, ok=True)
    # A state save (put) must not erase earned verdicts.
    state = conversation_state.ACPConversationState(
        session_id="sess-1",
        context_fingerprint="ctx",
        request_fingerprints=("req",),
        response_fingerprint="resp",
        updated_at=time.time(),
        native_tokens=100,
    )
    registry.put("affinity-1", state)
    fresh = conversation_state.ConversationStateRegistry()
    assert fresh.semantics_verdict(FAKE_IDENTITY) == "behaviorally_verified"
    payload = _semantics_payload(tmp_path)
    assert payload["usage_semantics_verdicts"][FAKE_IDENTITY]["verdict"] == (
        "behaviorally_verified"
    )
    # The verdict moved OUT of the per-home store: a state save there can no
    # longer be the place verdicts live (shared-store move).
    assert FAKE_IDENTITY not in (
        _state_payload(tmp_path).get("usage_semantics_verdicts") or {}
    )


# --------------------------------------------------------------------------
# Machine-wide shared verdict store


def test_semantics_store_path_is_shared_across_profile_homes(
    monkeypatch, tmp_path
) -> None:
    _, conversation_state = _load_package(monkeypatch, tmp_path)
    monkeypatch.delenv("HERMES_ANTIGRAVITY_ACP_SEMANTICS_FILE", raising=False)
    root = tmp_path / "hermes-root"
    expected = root / "shared" / "antigravity-acp-semantics.json"
    for home in (root, root / "profiles" / "alpha", root / "profiles" / "beta"):
        monkeypatch.setattr(conversation_state, "get_hermes_home", lambda h=home: h)
        assert conversation_state._semantics_store_path() == expected


def test_verdict_earned_in_one_home_serves_another(monkeypatch, tmp_path) -> None:
    _, conversation_state = _load_package(monkeypatch, tmp_path)
    home_a = conversation_state._state_path()
    registry_a = conversation_state.ConversationStateRegistry()
    for _ in range(conversation_state.SEMANTICS_PROMOTE_AFTER):
        registry_a.record_semantics_evidence(FAKE_IDENTITY, ok=True)
    # A different per-home store (profile B) but the same machine-wide
    # semantics file: the verdict must already be there, no second warm-up.
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(tmp_path / "other-profile" / "antigravity-acp-canary-state.json"),
    )
    assert home_a != conversation_state._state_path()
    registry_b = conversation_state.ConversationStateRegistry()
    assert registry_b.semantics_verdict(FAKE_IDENTITY) == "behaviorally_verified"


def test_legacy_per_home_verdict_bridges_into_shared_store(
    monkeypatch, tmp_path
) -> None:
    _, conversation_state = _load_package(monkeypatch, tmp_path)
    registry = conversation_state.ConversationStateRegistry()
    legacy_entry = {
        "schema": conversation_state._SEMANTICS_VERDICTS_SCHEMA,
        "verdict": "behaviorally_verified",
        "consistent_turns": 7,
        "rejected_turns": 0,
        "first_seen": time.time() - 3600,
        "last_seen": time.time() - 60,
        "provenance": "behavioral_growth_correlation",
    }
    per_home = conversation_state._state_path()
    registry._write_payload(
        per_home,
        {
            "version": conversation_state._STATE_VERSION,
            "states": {},
            "usage_semantics_verdicts": {FAKE_IDENTITY: legacy_entry},
        },
    )
    # Read path: the shared store is empty; the legacy verdict still serves.
    assert registry.semantics_verdict(FAKE_IDENTITY) == "behaviorally_verified"
    # Write path: the first shared-store record continues the legacy streak.
    entry = registry.record_semantics_evidence(FAKE_IDENTITY, ok=True)
    assert entry["consistent_turns"] == 8
    assert entry["verdict"] == "behaviorally_verified"
    payload = _semantics_payload(tmp_path)
    assert payload["usage_semantics_verdicts"][FAKE_IDENTITY]["verdict"] == (
        "behaviorally_verified"
    )


# --------------------------------------------------------------------------
# Client-side identity extraction and dynamic lookup


def test_identity_extraction_fails_closed(monkeypatch, tmp_path) -> None:
    client, _ = _load_package(monkeypatch, tmp_path)
    assert client._server_identity_from_initialize(None) == ""
    assert client._server_identity_from_initialize({}) == ""
    assert client._server_identity_from_initialize({"agentInfo": {}}) == ""
    assert (
        client._server_identity_from_initialize(
            {"agentInfo": {"name": "fake-acp", "title": "Fake ACP"}}
        )
        == ""
    )
    assert (
        client._server_identity_from_initialize(
            {"agentInfo": {"name": "fake-acp", "title": "Fake ACP", "version": 9}}
        )
        == ""
    )
    assert (
        client._server_identity_from_initialize(
            {"agentInfo": {"name": "fake-acp", "title": "Fake ACP", "version": "9.9.9"}}
        )
        == FAKE_IDENTITY
    )


def test_unknown_identity_becomes_verified_only_after_earning_it(
    monkeypatch, tmp_path
) -> None:
    client, conversation_state = _load_package(monkeypatch, tmp_path)
    # A never-seen identity (the whole point: no version list needed) starts
    # unverified and becomes verified only through runtime evidence.
    assert client._usage_semantics_for_identity(FAKE_IDENTITY) == "unverified"
    assert client._usage_semantics_for_identity("") == "unverified"
    registry = conversation_state.ConversationStateRegistry()
    for _ in range(conversation_state.SEMANTICS_PROMOTE_AFTER):
        registry.record_semantics_evidence(FAKE_IDENTITY, ok=True)
    assert client._usage_semantics_for_identity(FAKE_IDENTITY) == "verified"


def test_no_hardcoded_consumption_identity_whitelist_remains(monkeypatch, tmp_path) -> None:
    client, _ = _load_package(monkeypatch, tmp_path)
    # Tripwire: the retired version-pinned frozenset must never come back.
    assert not hasattr(client, "_VERIFIED_CONSUMPTION_IDENTITIES")
    assert not hasattr(client, "_usage_semantics_from_initialize")


# --------------------------------------------------------------------------
# Guard helper wiring (baseline seeding, rejection, evidence, counters)


def test_guard_seeds_baseline_then_rejects_and_records_inflation(
    monkeypatch, tmp_path
) -> None:
    client, conversation_state = _load_package(monkeypatch, tmp_path)
    registry = conversation_state.ConversationStateRegistry()
    affinity = "affinity-guard"

    first = SimpleNamespace(prompt_tokens=100_000)
    kept = client._guard_reported_turn_usage(
        affinity_key=affinity,
        server_identity=FAKE_IDENTITY,
        turn_usage=first,
        native_tokens=90_000,
    )
    assert kept is first  # first turn: within absolute tolerance, baseline seeded

    inflated = SimpleNamespace(prompt_tokens=599_000)
    rejected = client._guard_reported_turn_usage(
        affinity_key=affinity,
        server_identity=FAKE_IDENTITY,
        turn_usage=inflated,
        native_tokens=93_200,
    )
    assert rejected is None
    payload = _state_payload(tmp_path)
    assert payload["usage_drop_counters"]["dropped_inflated_turn_usage"] == 1
    entry = _semantics_payload(tmp_path)["usage_semantics_verdicts"][FAKE_IDENTITY]
    assert entry["verdict"] == "unverified"
    assert entry["rejected_turns"] == 1

    # Baseline stayed at the last trusted point: a consistent next turn is
    # measured against (100_000, 90_000) and passes.
    consistent = SimpleNamespace(prompt_tokens=105_000)
    kept = client._guard_reported_turn_usage(
        affinity_key=affinity,
        server_identity=FAKE_IDENTITY,
        turn_usage=consistent,
        native_tokens=95_000,
    )
    assert kept is consistent
    assert registry.semantics_verdict(FAKE_IDENTITY) == "unverified"


def test_guard_rejects_inflated_first_turn_without_seeding_baseline(
    monkeypatch, tmp_path
) -> None:
    """Issue #87 replay: a long first turn must not pass through unconditionally.

    Fresh session, one long ACP turn: the server folds every internal model
    call into ``inputTokens`` (~1.4M cumulative cache reads) while the real
    transcript is ~110K.  The growth gate has no baseline on turn one, so the
    absolute level itself must be gated against the local estimate — the same
    decision the Parked-MCP engine makes, now owned by ``usage_contract``.
    """
    client, _ = _load_package(monkeypatch, tmp_path)
    affinity = "affinity-firstturn"

    inflated = SimpleNamespace(prompt_tokens=1_405_762)
    rejected = client._guard_reported_turn_usage(
        affinity_key=affinity,
        server_identity=FAKE_IDENTITY,
        turn_usage=inflated,
        native_tokens=110_141,
    )
    assert rejected is None
    # A rejected first report seeds nothing: turn two is gated on its own.
    assert affinity not in client._TURN_USAGE_BASELINES
    payload = _state_payload(tmp_path)
    assert payload["usage_drop_counters"]["dropped_inflated_turn_usage"] == 1

    sane = SimpleNamespace(prompt_tokens=115_000)
    kept = client._guard_reported_turn_usage(
        affinity_key=affinity,
        server_identity=FAKE_IDENTITY,
        turn_usage=sane,
        native_tokens=112_000,
    )
    assert kept is sane
    assert client._TURN_USAGE_BASELINES[affinity] == (115_000, 112_000)


def test_guard_without_identity_never_earns_verdicts(monkeypatch, tmp_path) -> None:
    client, _ = _load_package(monkeypatch, tmp_path)
    affinity = "affinity-anon"
    first = SimpleNamespace(prompt_tokens=50_000)
    assert (
        client._guard_reported_turn_usage(
            affinity_key=affinity,
            server_identity="",
            turn_usage=first,
            native_tokens=40_000,
        )
        is first
    )
    second = SimpleNamespace(prompt_tokens=52_000)
    assert (
        client._guard_reported_turn_usage(
            affinity_key=affinity,
            server_identity="",
            turn_usage=second,
            native_tokens=42_000,
        )
        is second
    )
    payload = _state_payload(tmp_path)
    assert "usage_semantics_verdicts" not in payload
    assert "usage_semantics_verdicts" not in _semantics_payload(tmp_path)
