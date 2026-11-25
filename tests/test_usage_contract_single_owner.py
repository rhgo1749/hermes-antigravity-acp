"""The turn-usage validity contract has ONE owner shared by both engines.

Class killed 2026-11-25 (issue #87): the first-turn absolute gate existed
only in the Parked-MCP engine; the Replay engine accepted a ~1.4M cumulative
first-turn ``inputTokens`` verbatim and fired premature Core compactions.
PR #88 fixed the behavior by hand-copying the parked gate into ``client.py``
— a mirror drifts again.  This gate fails the build when either engine
re-forks a contract name, bypasses the shared decision callables, or
diverges from the shared behavior matrix at the tolerance boundaries.

Defense layers (external review of PR #89 folded in):
- AST scan: neither engine may OWN any contract name (constants, estimator,
  CJK ranges, decision functions) — catches plain, annotated, and nested
  re-definitions;
- delegation spies: each engine's guard must actually CALL the decision
  callables it imports, with the right arguments, and adopt their verdict —
  catches inline re-implementation that keeps the imports;
- independent boundary matrix: both engines are driven with hardcoded
  expected verdicts at the exact tolerance edges (flat 64K and 8x scaled,
  +/-1), so a silently re-tuned copy fails;
- object identity: the engines' imported names ARE the contract's objects.
A re-implementation that agrees with the contract at every tested boundary
is behaviorally identical and is explicitly NOT claimed to be detectable.

Witnesses replaying the real drifts:
- against ``e92d19d`` (pre-#88): every gate test fails — the Replay engine
  accepted the inflated first turn unconditionally;
- against ``382625c`` (#88 merged): every gate test fails — the AST scan and
  identity assertions directly (the contract exists as two hand-copies), the
  behavior matrix because the shared module does not exist yet.
"""

from __future__ import annotations

import ast
import importlib
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"

ENGINE_FILES = {
    "Replay engine client": PLUGIN_DIR / "client.py",
    "Parked-MCP conversation": PLUGIN_DIR / "parked" / "conversation.py",
}
CONTRACT_FILE = PLUGIN_DIR / "parked" / "usage_contract.py"

# Names the contract owns; an engine defining any of these (module level,
# nested, or annotated) is a re-fork.
CONTRACT_NAMES = {
    "USAGE_GROWTH_FACTOR",
    "USAGE_GROWTH_SLACK_TOKENS",
    "_CJK_RANGES",
    "reported_usage_growth_consistent",
    "first_turn_report_plausible",
    "usage_divergence_tolerance",
    "estimate_tokens",
    "transcript_tokens",
}
# Underscore-prefixed historical spellings are equally forbidden.
FORBIDDEN_OWN_NAMES = CONTRACT_NAMES | {f"_{name}" for name in CONTRACT_NAMES}


def _owned_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    owned: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            owned.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    owned.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            owned.add(node.target.id)
    return owned


def test_contract_is_the_only_owner_of_gate_names() -> None:
    offenders = {}
    for label, path in ENGINE_FILES.items():
        re_forks = _owned_names(path) & FORBIDDEN_OWN_NAMES
        if re_forks:
            offenders[label] = sorted(re_forks)
    assert not offenders, (
        "turn-usage gate decisions/estimator/constants must live ONLY in "
        "hermes-plugin/antigravity-acp/parked/usage_contract.py; both engines "
        f"import them.  Re-forked in: {offenders}"
    )


def test_contract_module_owns_the_full_contract() -> None:
    owned = _owned_names(CONTRACT_FILE)
    missing = CONTRACT_NAMES - owned
    assert not missing, f"contract module lost its definitions of: {sorted(missing)}"


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


def _chars_for(local: int) -> int:
    """ASCII transcript length whose estimate_tokens is exactly ``local``."""
    return 3 * (local - 1)


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


# ---------------------------------------------------------------------------
# Delegation spies: the guards must CALL the contract, not merely import it.


def test_replay_guard_delegates_first_turn_decision(monkeypatch, tmp_path) -> None:
    client, _contract, _conversation = _load_package(monkeypatch, tmp_path)
    calls = []

    def spy(*, reported, local):
        calls.append((reported, local))
        return False

    monkeypatch.setattr(client, "first_turn_report_plausible", spy)
    kept, baseline = _flat_gate(client, "spy-first", 123, 456)
    assert calls == [(123, 456)], "Replay guard bypassed the shared first-turn decision"
    assert kept is None and baseline is None, "spy verdict was not adopted"

    monkeypatch.setattr(client, "first_turn_report_plausible", lambda **kw: True)
    kept, baseline = _flat_gate(client, "spy-first-2", 123, 456)
    assert kept is not None and baseline == (123, 456)


def test_replay_guard_delegates_growth_decision(monkeypatch, tmp_path) -> None:
    client, _contract, _conversation = _load_package(monkeypatch, tmp_path)
    _flat_gate(client, "spy-growth", 100_000, 90_000)  # seed baseline
    calls = []

    def spy(*, prev_reported, reported, prev_local, local):
        calls.append((prev_reported, reported, prev_local, local))
        return False, 7, 3

    monkeypatch.setattr(client, "reported_usage_growth_consistent", spy)
    kept, baseline = _flat_gate(client, "spy-growth", 105_000, 95_000)
    assert calls == [(100_000, 105_000, 90_000, 95_000)], (
        "Replay guard bypassed the shared growth decision or passed wrong arguments"
    )
    assert kept is None and baseline == (100_000, 90_000), (
        "spy verdict was not adopted / baseline not preserved"
    )


def test_parked_gate_delegates_decisions(monkeypatch, tmp_path) -> None:
    _client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(_chars_for(1_000))
    first_calls = []

    def spy_first(*, reported, local):
        first_calls.append((reported, local))
        return False

    monkeypatch.setattr(conversation, "first_turn_report_plausible", spy_first)
    kept, baseline = _parked_gate(conversation, None, 65_001, messages)
    assert first_calls == [(65_001, 1_000)], "parked gate bypassed the shared decision"
    assert kept is None and baseline is None

    growth_calls = []

    def spy_growth(*, prev_reported, reported, prev_local, local):
        growth_calls.append((prev_reported, reported, prev_local, local))
        return False, 7, 3

    monkeypatch.setattr(conversation, "reported_usage_growth_consistent", spy_growth)
    kept, baseline = _parked_gate(conversation, (100_000, 90_000), 105_000, messages)
    assert growth_calls == [(100_000, 105_000, 90_000, 1_000)]
    assert kept is None and baseline == (100_000, 90_000)


# ---------------------------------------------------------------------------
# Independent boundary matrix: hardcoded verdicts at the exact tolerance
# edges (tolerance = max(8*(ref+1), 64_000)), driven through BOTH engines.
# Expected values are written out, not computed from the contract.

FIRST_TURN_CASES = [
    # (reported, local, expect_accept) — flat 64K slack edge at tiny local
    pytest.param(65_000, 1_000, True, id="flat-edge-accept"),
    pytest.param(65_001, 1_000, False, id="flat-edge-plus-one-reject"),
    # 8x scaled edge at 100K local: tolerance = 8*(100_000+1) = 800_008
    pytest.param(900_008, 100_000, True, id="scaled-edge-accept"),
    pytest.param(900_009, 100_000, False, id="scaled-edge-plus-one-reject"),
]

GROWTH_CASES = [
    # baseline (100_000, 90_000); expected growth 1_000; tolerance 64_000
    pytest.param(164_000, 91_000, True, id="flat-slack-accept"),
    pytest.param(165_001, 91_000, False, id="flat-slack-plus-one-reject"),
    # expected growth 100_000; tolerance 8*100_001 = 800_008
    pytest.param(1_000_008, 190_000, True, id="scaled-edge-accept"),
    pytest.param(1_000_009, 190_000, False, id="scaled-edge-plus-one-reject"),
    # negative re-anchor within scaled tolerance
    pytest.param(120_000, 110_000, True, id="reanchor-accept"),
    # server collapse while transcript grows
    pytest.param(1_000, 390_000, False, id="collapse-reject"),
]

GROWTH_BASELINE = (100_000, 90_000)
REANCHOR_BASELINE = (400_000, 380_000)


def _growth_baseline(reported: int, local: int) -> tuple[int, int]:
    # collapse-reject measures against the re-anchored baseline; all other
    # growth cases measure against GROWTH_BASELINE.
    return REANCHOR_BASELINE if (reported, local) == (1_000, 390_000) else GROWTH_BASELINE


@pytest.mark.parametrize(("reported", "local", "accept"), FIRST_TURN_CASES)
def test_first_turn_boundary_matrix_parity(monkeypatch, tmp_path, reported, local, accept) -> None:
    client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    kept_flat, baseline_flat = _flat_gate(client, f"ft-{reported}", reported, local)
    kept_parked, baseline_parked = _parked_gate(
        conversation, None, reported, _messages(_chars_for(local))
    )
    assert (kept_flat is not None) is accept
    assert (kept_parked is not None) is accept
    assert (baseline_flat is not None) is accept
    assert (baseline_parked is not None) is accept


@pytest.mark.parametrize(("reported", "local", "accept"), GROWTH_CASES)
def test_growth_boundary_matrix_parity(monkeypatch, tmp_path, reported, local, accept) -> None:
    client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    prev_reported, prev_local = _growth_baseline(reported, local)
    _flat_gate(client, f"gr-{reported}", prev_reported, prev_local)  # seed
    kept_flat, baseline_flat = _flat_gate(client, f"gr-{reported}", reported, local)
    kept_parked, baseline_parked = _parked_gate(
        conversation, (prev_reported, prev_local), reported, _messages(_chars_for(local))
    )
    assert (kept_flat is not None) is accept
    assert (kept_parked is not None) is accept
    expected_baseline = (reported, local) if accept else (prev_reported, prev_local)
    assert baseline_flat == expected_baseline
    assert baseline_parked == expected_baseline


# ---------------------------------------------------------------------------
# Parity scenarios driving both engines' real entry points.


def test_first_turn_replay_issue_87_parity(monkeypatch, tmp_path) -> None:
    """Both engines must reject the same inflated first turn and seed nothing."""
    client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(TRANSCRIPT_CHARS)
    # The flat side's local estimate goes through the Replay engine's own
    # estimator wiring, not the contract module directly.
    local_flat = client.estimate_tokens("x" * TRANSCRIPT_CHARS)

    kept_flat, baseline_flat = _flat_gate(
        client, "parity-firstturn", INFLATED_FIRST_TURN_REPORT, local_flat
    )
    kept_parked, baseline_parked = _parked_gate(
        conversation, None, INFLATED_FIRST_TURN_REPORT, messages
    )
    assert kept_flat is None, "Replay engine accepted an inflated first turn (issue #87)"
    assert kept_parked is None
    assert baseline_flat is None, "rejected first report must not seed a baseline"
    assert baseline_parked is None


def test_sane_first_turn_parity_seeds_baseline(monkeypatch, tmp_path) -> None:
    client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(TRANSCRIPT_CHARS)
    local = client.estimate_tokens("x" * TRANSCRIPT_CHARS)
    reported = local + 5_000

    kept_flat, baseline_flat = _flat_gate(client, "parity-sane", reported, local)
    kept_parked, baseline_parked = _parked_gate(conversation, None, reported, messages)
    assert kept_flat is not None and kept_parked is not None
    assert baseline_flat == (reported, local)
    assert baseline_parked == (reported, local)


def test_growth_divergence_parity(monkeypatch, tmp_path) -> None:
    """2026-11-23 incident replay: ~500K reported growth on ~200K local."""
    client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(TRANSCRIPT_CHARS)
    local = client.estimate_tokens("x" * TRANSCRIPT_CHARS)
    first = local + 5_000

    _flat_gate(client, "parity-growth", first, local)
    _kept_first, parked_baseline = _parked_gate(conversation, None, first, messages)

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
    client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(TRANSCRIPT_CHARS)
    local = client.estimate_tokens("x" * TRANSCRIPT_CHARS)
    first = local + 5_000

    _flat_gate(client, "parity-consistent", first, local)
    _parked_gate(conversation, None, first, messages)

    grown = _messages(TRANSCRIPT_CHARS + 30_000)
    local2 = client.estimate_tokens("x" * (TRANSCRIPT_CHARS + 30_000))
    reported2 = first + (local2 - local) + 9_000  # modest server-side records

    kept_flat, baseline_flat = _flat_gate(client, "parity-consistent", reported2, local2)
    kept_parked, baseline_parked = _parked_gate(conversation, (first, local), reported2, grown)
    assert kept_flat is not None and kept_parked is not None
    assert baseline_flat == (reported2, local2)
    assert baseline_parked == (reported2, local2)
