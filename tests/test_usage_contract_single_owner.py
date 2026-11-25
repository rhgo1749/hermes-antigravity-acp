"""The turn-usage validity contract has ONE owner shared by both engines.

Class killed 2026-11-25 (issue #87): the first-turn absolute gate existed
only in the Parked-MCP engine; the Replay engine accepted a ~1.4M cumulative
first-turn ``inputTokens`` verbatim and fired premature Core compactions.
PR #88 fixed the behavior by hand-copying the parked gate into ``client.py``
— a mirror drifts again.  This gate fails the build when either engine
re-forks the constants, reimplements a decision, or diverges from the shared
behavior matrix.

Witnesses replaying the real drifts:
- against ``e92d19d`` (pre-#88): all 7 tests fail — the Replay engine
  accepted the inflated first turn unconditionally;
- against ``382625c`` (#88 merged): all 7 fail — the source-fork scan and
  the identity assertions directly (the contract exists as two hand-copies),
  the parity matrix because the shared module does not exist yet.
"""

from __future__ import annotations

import importlib
import re
import sys
import types
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"

ENGINE_FILES = {
    "Replay engine client": PLUGIN_DIR / "client.py",
    "Parked-MCP conversation": PLUGIN_DIR / "parked" / "conversation.py",
}
CONTRACT_FILE = PLUGIN_DIR / "parked" / "usage_contract.py"

# A decision or constant may only be DEFINED in the contract module.
FORK_PATTERNS = (
    re.compile(r"^(USAGE_GROWTH_FACTOR|_USAGE_GROWTH_FACTOR|USAGE_GROWTH_SLACK_TOKENS|_USAGE_GROWTH_SLACK_TOKENS)\s*="),
    re.compile(r"^def (_?reported_usage_growth_consistent|_?first_turn_report_plausible|_?usage_divergence_tolerance|_?estimate_tokens|estimate_tokens|_?transcript_tokens|transcript_tokens)\b"),
)


def _own_definitions(source: str) -> list[str]:
    owned = []
    for line in source.splitlines():
        for pattern in FORK_PATTERNS:
            if pattern.match(line):
                owned.append(line.split("(")[0].split("=")[0].strip())
    return owned


def test_contract_is_the_only_owner_of_gate_decisions() -> None:
    offenders = {}
    for label, path in ENGINE_FILES.items():
        owned = _own_definitions(path.read_text(encoding="utf-8"))
        if owned:
            offenders[label] = owned
    assert not offenders, (
        "turn-usage gate decisions/estimator/constants must live ONLY in "
        "hermes-plugin/antigravity-acp/parked/usage_contract.py; both engines "
        f"import them.  Re-forked in: {offenders}"
    )


def test_contract_module_defines_the_contract() -> None:
    owned = set(_own_definitions(CONTRACT_FILE.read_text(encoding="utf-8")))
    for name in (
        "USAGE_GROWTH_FACTOR",
        "USAGE_GROWTH_SLACK_TOKENS",
        "def reported_usage_growth_consistent",
        "def first_turn_report_plausible",
        "def estimate_tokens",
        "def transcript_tokens",
    ):
        assert any(name in entry for entry in owned), f"contract lost {name}"


def _load_package(monkeypatch, tmp_path: Path):
    """Load the plugin package (both engines) with stubbed Hermes providers."""
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(tmp_path / "antigravity-acp-contract-state.json"),
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_SEMANTICS_FILE",
        str(tmp_path / "antigravity-acp-contract-semantics.json"),
    )
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE",
        str(tmp_path / "antigravity-acp-contract-limits.json"),
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

    module_name = "antigravity_acp_contract"
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
    contract = importlib.import_module(module_name + ".parked.usage_contract")
    conversation = importlib.import_module(module_name + ".parked.conversation")
    client._TURN_USAGE_BASELINES.clear()
    return client, contract, conversation


# Issue #87 replay: a long first turn folded ~1.4M cumulative cache reads
# into inputTokens against a ~110K transcript.
INFLATED_FIRST_TURN_REPORT = 1_405_762
TRANSCRIPT_CHARS = 330_423  # -> estimate_tokens = 110_142


def _messages(chars: int) -> list[dict]:
    return [{"role": "user", "content": "x" * chars}]


def _parked_gate(conversation, baseline_state, reported: int, messages):
    """Drive the Parked-MCP gate without a live conversation (pure decision)."""
    conv = object.__new__(conversation.Conversation)
    conv._usage_baseline = baseline_state
    result = {
        "usage": {
            "inputTokens": reported,
            "outputTokens": 100,
            "totalTokens": reported + 100,
        }
    }
    kept = conv._gate_turn_consumption(result, messages)
    return kept, conv._usage_baseline


def _flat_gate(client, affinity: str, reported: int, native: int):
    kept = client._guard_reported_turn_usage(
        affinity_key=affinity,
        server_identity="",
        turn_usage=SimpleNamespace(prompt_tokens=reported),
        native_tokens=native,
    )
    return kept, client._TURN_USAGE_BASELINES.get(affinity)


def test_engines_share_the_identical_decision_objects(monkeypatch, tmp_path) -> None:
    client, contract, conversation = _load_package(monkeypatch, tmp_path)
    assert client.reported_usage_growth_consistent is contract.reported_usage_growth_consistent
    assert client.first_turn_report_plausible is contract.first_turn_report_plausible
    assert client.estimate_tokens is contract.estimate_tokens
    assert conversation.reported_usage_growth_consistent is contract.reported_usage_growth_consistent
    assert conversation.first_turn_report_plausible is contract.first_turn_report_plausible
    assert conversation.transcript_tokens is contract.transcript_tokens


def test_first_turn_replay_issue_87_parity(monkeypatch, tmp_path) -> None:
    """Both engines must reject the same inflated first turn and seed nothing."""
    client, contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(TRANSCRIPT_CHARS)
    local = contract.transcript_tokens(messages)

    kept_flat, baseline_flat = _flat_gate(
        client, "parity-firstturn", INFLATED_FIRST_TURN_REPORT, local
    )
    kept_parked, baseline_parked = _parked_gate(
        conversation, None, INFLATED_FIRST_TURN_REPORT, messages
    )
    assert kept_flat is None, "Replay engine accepted an inflated first turn (issue #87)"
    assert kept_parked is None
    assert baseline_flat is None, "rejected first report must not seed a baseline"
    assert baseline_parked is None


def test_sane_first_turn_parity_seeds_baseline(monkeypatch, tmp_path) -> None:
    client, contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(TRANSCRIPT_CHARS)
    local = contract.transcript_tokens(messages)
    reported = local + 5_000

    kept_flat, baseline_flat = _flat_gate(client, "parity-sane", reported, local)
    kept_parked, baseline_parked = _parked_gate(conversation, None, reported, messages)
    assert kept_flat is not None and kept_parked is not None
    assert baseline_flat == (reported, local)
    assert baseline_parked == (reported, local)


def test_growth_divergence_parity(monkeypatch, tmp_path) -> None:
    """2026-11-23 incident replay: ~500K reported growth on ~200K local."""
    client, contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(TRANSCRIPT_CHARS)
    local = contract.transcript_tokens(messages)
    first = local + 5_000

    _flat_gate(client, "parity-growth", first, local)
    kept_parked_first, parked_baseline = _parked_gate(conversation, None, first, messages)

    diverged = first + 500_000
    kept_flat, baseline_flat = _flat_gate(client, "parity-growth", diverged, local + 200)
    kept_parked, baseline_parked = _parked_gate(
        conversation, parked_baseline, diverged, _messages(TRANSCRIPT_CHARS + 600)
    )
    assert kept_flat is None and kept_parked is None
    # The last trusted baseline survives in both engines.
    assert baseline_flat == (first, local)
    assert baseline_parked == (first, local)


def test_consistent_growth_parity(monkeypatch, tmp_path) -> None:
    client, contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(TRANSCRIPT_CHARS)
    local = contract.transcript_tokens(messages)
    first = local + 5_000

    _flat_gate(client, "parity-consistent", first, local)
    _parked_gate(conversation, None, first, messages)

    grown = _messages(TRANSCRIPT_CHARS + 30_000)
    local2 = contract.transcript_tokens(grown)
    reported2 = first + (local2 - local) + 9_000  # modest server-side records

    kept_flat, baseline_flat = _flat_gate(client, "parity-consistent", reported2, local2)
    kept_parked, baseline_parked = _parked_gate(conversation, (first, local), reported2, grown)
    assert kept_flat is not None and kept_parked is not None
    assert baseline_flat == (reported2, local2)
    assert baseline_parked == (reported2, local2)
