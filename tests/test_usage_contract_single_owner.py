"""The turn-usage validity contract has ONE owner shared by both engines.

Class killed 2026-11-25 (issue #87): the first-turn absolute gate existed
only in the Parked-MCP engine; the Replay engine accepted a ~1.4M cumulative
first-turn ``inputTokens`` verbatim and fired premature Core compactions.
PR #88 fixed the behavior by hand-copying the parked gate into ``client.py``
— a mirror drifts again.  This gate fails the build when either engine
re-forks a contract name, bypasses the shared decision callables, or
diverges from the shared behavior matrix at the tolerance boundaries.

Defense layers (external reviews of PR #89 rounds 1-2 folded in):
- AST ownership scan: neither engine may bind any contract name anywhere
  (module level, nested, annotated, tuple/list destructuring, walrus) —
  implemented as every ``ast.Name`` in Store context plus def/class names;
- delegation spies with FORCED verdicts on counterfactual inputs: each
  guard must call the decision callables it imports with the right
  arguments AND adopt WHATEVER verdict they return — catches inline
  re-implementation and extra private vetoes that keep the imports;
- estimator delegation chain: the Parked gate's ``local`` yardstick must BE
  the return value of the shared ``transcript_tokens`` — catches inline
  ``sum(len(...) // 3 + 1)`` copies that are identical on ASCII and diverge
  on CJK/tool-calls;
- independent boundary matrix: hardcoded expected verdicts at the EXACT
  tolerance edges (upper and lower, +/-1, flat 64K and 8x scaled), driven
  through both engines, so a silently re-tuned copy fails;
- object identity: the engines' imported names ARE the contract's objects.
A re-implementation that agrees with the contract at every tested boundary
is behaviorally identical and is explicitly NOT claimed to be detectable.

Witnesses replaying the real drifts (round-2 hardened gate):
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

# Names the contract owns; an engine binding any of these (plain, annotated,
# nested, destructured, walrus) is a re-fork.
CONTRACT_NAMES = {
    "USAGE_GROWTH_FACTOR",
    "USAGE_GROWTH_SLACK_TOKENS",
    "_CJK_RANGES",
    "valid_context_limit",
    "nonnegative_usage_number",
    "usage_update_valid",
    "context_limit_from_usage_update",
    "report_within_context_limit",
    "reported_usage_growth_consistent",
    "first_turn_report_plausible",
    "usage_divergence_tolerance",
    "estimate_tokens",
    "transcript_tokens",
}
# Underscore-prefixed historical spellings are equally forbidden.
FORBIDDEN_OWN_NAMES = CONTRACT_NAMES | {f"_{name}" for name in CONTRACT_NAMES}


def _owned_names(path: Path) -> set[str]:
    """Every name the module binds: Store-context ``ast.Name`` + def/class names.

    Covers plain assignment, annotated assignment, tuple/list destructuring
    (``FACTOR, unused = (8, 0)``), walrus, for/comprehension targets, and
    nested defs — not just module-level ``Assign`` statements.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    owned: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            owned.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            owned.add(node.id)
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
    if hasattr(client, "_CONVERSATION_CONTEXT_LIMITS"):
        client._CONVERSATION_CONTEXT_LIMITS.clear()
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


def _parked_gate(
    conversation,
    baseline_state,
    reported: int,
    messages,
    *,
    context_limit=None,
):
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
    if context_limit is None:
        kept = conv._gate_turn_consumption(result, messages)
    else:
        kept = conv._gate_turn_consumption(result, messages, context_limit=context_limit)
    return kept, conv._usage_baseline


def _flat_gate(
    client,
    affinity: str,
    reported: int,
    native: int,
    *,
    context_limit=None,
):
    kwargs = {}
    if context_limit is not None:
        kwargs["context_limit"] = context_limit
    kept = client._guard_reported_turn_usage(
        affinity_key=affinity,
        server_identity="",
        turn_usage=SimpleNamespace(prompt_tokens=reported),
        native_tokens=native,
        **kwargs,
    )
    return kept, client._TURN_USAGE_BASELINES.get(affinity)


def test_engines_share_the_identical_decision_objects(monkeypatch, tmp_path) -> None:
    client, contract, conversation = _load_package(monkeypatch, tmp_path)
    assert client.valid_context_limit is contract.valid_context_limit
    assert client.nonnegative_usage_number is contract.nonnegative_usage_number
    assert client.usage_update_valid is contract.usage_update_valid
    assert client.context_limit_from_usage_update is contract.context_limit_from_usage_update
    assert client.report_within_context_limit is contract.report_within_context_limit
    assert client.reported_usage_growth_consistent is contract.reported_usage_growth_consistent
    assert client.first_turn_report_plausible is contract.first_turn_report_plausible
    assert client.estimate_tokens is contract.estimate_tokens
    assert conversation.valid_context_limit is contract.valid_context_limit
    assert conversation.usage_update_valid is contract.usage_update_valid
    assert conversation.context_limit_from_usage_update is contract.context_limit_from_usage_update
    assert conversation.report_within_context_limit is contract.report_within_context_limit
    assert conversation.reported_usage_growth_consistent is contract.reported_usage_growth_consistent
    assert conversation.first_turn_report_plausible is contract.first_turn_report_plausible
    assert conversation.transcript_tokens is contract.transcript_tokens


# ---------------------------------------------------------------------------
# Delegation spies with FORCED verdicts on counterfactual inputs: the guards
# must CALL the contract, pass the right arguments, and adopt WHATEVER
# verdict it returns.  A private extra veto (``or reported == X``) or an
# inline copy that ignores the shared verdict fails a forced-verdict case.


@pytest.mark.parametrize("verdict", [True, False])
@pytest.mark.parametrize("reported", [65_000, 65_001])
def test_replay_guard_first_turn_delegates_and_adopts_verdict(
    monkeypatch, tmp_path, reported, verdict
) -> None:
    client, _contract, _conversation = _load_package(monkeypatch, tmp_path)
    calls = []

    def spy(*, reported, local):
        calls.append((reported, local))
        return verdict

    monkeypatch.setattr(client, "first_turn_report_plausible", spy)
    # Full input x verdict cross: the REAL contract accepts 65_000 and
    # rejects 65_001 at local=1_000; the spy verdict must decide on EVERY
    # combination, so a private extra veto keyed on any input is caught by
    # the combination where it contradicts the forced verdict.
    kept, baseline = _flat_gate(client, f"spy-ft-{reported}-{verdict}", reported, 1_000)
    assert calls == [(reported, 1_000)], "Replay guard bypassed the shared first-turn decision"
    assert (kept is not None) is verdict
    assert (baseline is None) is (not verdict)
    if verdict:
        assert baseline == (reported, 1_000)


@pytest.mark.parametrize("verdict", [True, False])
@pytest.mark.parametrize("reported", [105_000, 600_000])
def test_replay_guard_growth_delegates_and_adopts_verdict(
    monkeypatch, tmp_path, reported, verdict
) -> None:
    client, _contract, _conversation = _load_package(monkeypatch, tmp_path)
    _flat_gate(client, f"spy-gr-{reported}-{verdict}", 100_000, 90_000)  # seed
    calls = []

    def spy(*, prev_reported, reported, prev_local, local):
        calls.append((prev_reported, reported, prev_local, local))
        return verdict, 7, 3

    monkeypatch.setattr(client, "reported_usage_growth_consistent", spy)
    # Full input x verdict cross: the REAL contract accepts 105_000 and
    # rejects 600_000 on this baseline; the spy verdict must decide on
    # EVERY combination.
    kept, baseline = _flat_gate(client, f"spy-gr-{reported}-{verdict}", reported, 90_000)
    assert calls == [(100_000, reported, 90_000, 90_000)], (
        "Replay guard bypassed the shared growth decision or passed wrong arguments"
    )
    assert (kept is not None) is verdict
    assert baseline == ((reported, 90_000) if verdict else (100_000, 90_000))


@pytest.mark.parametrize("verdict", [True, False])
@pytest.mark.parametrize("reported", [65_000, 65_001])
def test_parked_gate_first_turn_delegates_and_adopts_verdict(
    monkeypatch, tmp_path, reported, verdict
) -> None:
    _client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(_chars_for(1_000))
    calls = []

    def spy(*, reported, local):
        calls.append((reported, local))
        return verdict

    monkeypatch.setattr(conversation, "first_turn_report_plausible", spy)
    kept, baseline = _parked_gate(conversation, None, reported, messages)
    assert calls == [(reported, 1_000)], "parked gate bypassed the shared decision"
    assert (kept is not None) is verdict
    assert (baseline is None) is (not verdict)
    if verdict:
        assert baseline == (reported, 1_000)


@pytest.mark.parametrize("verdict", [True, False])
@pytest.mark.parametrize("reported", [105_000, 600_000])
def test_parked_gate_growth_delegates_and_adopts_verdict(
    monkeypatch, tmp_path, reported, verdict
) -> None:
    _client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    calls = []

    def spy(*, prev_reported, reported, prev_local, local):
        calls.append((prev_reported, reported, prev_local, local))
        return verdict, 7, 3

    monkeypatch.setattr(conversation, "reported_usage_growth_consistent", spy)
    # Full input x verdict cross (real contract: accept 105_000, reject
    # 600_000 on this baseline); the forced verdict must always decide.
    kept, baseline = _parked_gate(
        conversation, (100_000, 90_000), reported, _messages(_chars_for(90_000))
    )
    assert calls == [(100_000, reported, 90_000, 90_000)]
    assert (kept is not None) is verdict
    assert baseline == ((reported, 90_000) if verdict else (100_000, 90_000))


def test_parked_gate_delegates_estimator_on_both_gate_paths(
    monkeypatch, tmp_path
) -> None:
    """The gate's ``local`` yardstick must BE the shared estimator's output
    on BOTH the first-turn and the growth path.

    Round-2 review mutant: the gate inlined ``sum(len(m["content"]) // 3 + 1
    for m in messages)`` while keeping the import — identical on ASCII,
    divergent on CJK/tool-calls.  Round-3 review mutant N6: the inline copy
    placed AFTER the first-turn branch, so a first-turn-only sentinel test
    passed while the growth path lost the yardstick.  The estimator spy
    returns a sentinel no inline yardstick could produce; BOTH decision
    spies must receive it.
    """
    _client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    monkeypatch.setattr(conversation, "transcript_tokens", lambda messages: 4_242)

    # First-turn path.
    first_seen = []
    monkeypatch.setattr(
        conversation, "first_turn_report_plausible",
        lambda **kw: first_seen.append((kw["reported"], kw["local"])) or True,
    )
    kept, baseline = _parked_gate(conversation, None, 4_242, _messages(30))
    assert first_seen == [(4_242, 4_242)], (
        "parked first-turn path did not route its local estimate through the "
        "shared transcript_tokens (inline yardstick re-fork)"
    )
    assert kept is not None and baseline == (4_242, 4_242)

    # Growth path (N6: inline copy after the first-turn branch).
    growth_seen = []

    def spy_growth(**kw):
        growth_seen.append((kw["prev_reported"], kw["reported"], kw["prev_local"], kw["local"]))
        return True, 1, 1

    monkeypatch.setattr(conversation, "reported_usage_growth_consistent", spy_growth)
    kept, baseline = _parked_gate(conversation, (100_000, 90_000), 105_000, _messages(30))
    assert growth_seen == [(100_000, 105_000, 90_000, 4_242)], (
        "parked growth path did not route its local estimate through the "
        "shared transcript_tokens (N6 growth-only inline yardstick)"
    )
    assert kept is not None and baseline == (105_000, 4_242)


def test_replay_guard_adopts_native_tokens_as_local_yardstick(
    monkeypatch, tmp_path
) -> None:
    """The flat guard must hand its native_tokens to the decision unchanged.

    The Replay estimator wiring (``prior_native_tokens + estimate_tokens``)
    lives at the prompt-build call site; the identity assertion above pins
    the estimator object, this spy pins the argument plumbing.
    """
    client, _contract, _conversation = _load_package(monkeypatch, tmp_path)
    seen = []
    monkeypatch.setattr(
        client, "first_turn_report_plausible",
        lambda **kw: seen.append((kw["reported"], kw["local"])) or True,
    )
    _flat_gate(client, "spy-native", 999, 5_555)
    assert seen == [(999, 5_555)]


# ---------------------------------------------------------------------------
# Independent boundary matrix: hardcoded verdicts at the EXACT tolerance
# edges (tolerance = max(8*(|expected|+1), 64_000)), upper AND lower side,
# +/-1, driven through BOTH engines.  Expected values are written out, not
# computed from the contract.  First-turn lower edges are mathematically
# negative (no non-negative report can undershoot a small local estimate by
# 64K+), so lower edges are exercised in the growth matrix instead.

FIRST_TURN_CASES = [
    # tolerance = max(8*(local+1), 64_000); local = 1_000 -> 64_000
    pytest.param(65_000, 1_000, True, id="flat-upper-edge-accept"),
    pytest.param(65_001, 1_000, False, id="flat-upper-edge-plus-one-reject"),
    # local = 100_000 -> tolerance = 8*100_001 = 800_008
    pytest.param(900_008, 100_000, True, id="scaled-upper-edge-accept"),
    pytest.param(900_009, 100_000, False, id="scaled-upper-edge-plus-one-reject"),
]

GROWTH_CASES = [
    # baseline (100_000, 90_000), local 91_000 -> expected growth 1_000,
    # tolerance = max(8*1_001, 64_000) = 64_000; exact edges:
    pytest.param(165_000, 91_000, True, id="flat-upper-edge-accept"),
    pytest.param(165_001, 91_000, False, id="flat-upper-edge-plus-one-reject"),
    pytest.param(37_000, 91_000, True, id="flat-lower-edge-accept"),
    pytest.param(36_999, 91_000, False, id="flat-lower-edge-minus-one-reject"),
    # baseline (100_000, 90_000), local 190_000 -> expected 100_000,
    # tolerance = 8*100_001 = 800_008:
    pytest.param(1_000_008, 190_000, True, id="scaled-upper-edge-accept"),
    pytest.param(1_000_009, 190_000, False, id="scaled-upper-edge-plus-one-reject"),
    # baseline (1_000_000, 900_000), local 1_000_000 -> expected 100_000,
    # tolerance 800_008; lower edge report = 1_000_000 - 700_008:
    pytest.param(299_992, 1_000_000, True, id="scaled-lower-edge-accept"),
    pytest.param(299_991, 1_000_000, False, id="scaled-lower-edge-minus-one-reject"),
    # genuine shrink re-anchor within scaled tolerance
    pytest.param(120_000, 110_000, True, id="reanchor-shrink-accept"),
    # server grows while the transcript shrinks: divergence 210_000 > 80_008
    pytest.param(300_000, 80_000, False, id="server-grows-transcript-shrinks-reject"),
    # server collapse while transcript grows
    pytest.param(1_000, 390_000, False, id="collapse-reject"),
]

GROWTH_BASELINE = (100_000, 90_000)
BIG_BASELINE = (1_000_000, 900_000)
REANCHOR_BASELINE = (400_000, 380_000)
_BASELINE_BY_CASE = {
    (299_992, 1_000_000): BIG_BASELINE,
    (299_991, 1_000_000): BIG_BASELINE,
    (120_000, 110_000): REANCHOR_BASELINE,
    (1_000, 390_000): REANCHOR_BASELINE,
}


def _growth_baseline(reported: int, local: int) -> tuple[int, int]:
    return _BASELINE_BY_CASE.get((reported, local), GROWTH_BASELINE)


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


@pytest.mark.parametrize("seeded", [False, True])
@pytest.mark.parametrize("verdict", [True, False])
@pytest.mark.parametrize("reported", [1_048_576, 1_048_577])
def test_replay_guard_context_limit_delegates_and_adopts_verdict(
    monkeypatch, tmp_path, reported, verdict, seeded
) -> None:
    client, _contract, _conversation = _load_package(monkeypatch, tmp_path)
    affinity = f"spy-win-{seeded}-{reported}-{verdict}"
    if seeded:
        _flat_gate(client, affinity, 154_735, 150_000)

    calls = []
    downstream_calls = []

    def spy_limit(*, reported, context_limit):
        calls.append((reported, context_limit))
        return verdict

    def spy_downstream(**kw):
        downstream_calls.append(kw)
        return (True, 1, 1) if seeded else True

    monkeypatch.setattr(client, "report_within_context_limit", spy_limit)
    monkeypatch.setattr(
        client,
        "reported_usage_growth_consistent" if seeded else "first_turn_report_plausible",
        spy_downstream,
    )

    kept, baseline = _flat_gate(
        client, affinity, reported, 600_000, context_limit=1_048_576
    )
    assert calls == [(reported, 1_048_576)], (
        "Replay guard bypassed the shared window-cap decision"
    )
    assert (kept is not None) is verdict
    if verdict:
        assert len(downstream_calls) == 1
        assert baseline == (reported, 600_000)
    else:
        assert downstream_calls == [], (
            "Window-cap rejection must short-circuit before the 8x gates"
        )
        assert baseline == ((154_735, 150_000) if seeded else None)


@pytest.mark.parametrize("seeded", [False, True])
@pytest.mark.parametrize("verdict", [True, False])
@pytest.mark.parametrize("reported", [1_048_576, 1_048_577])
def test_parked_gate_context_limit_delegates_and_adopts_verdict(
    monkeypatch, tmp_path, reported, verdict, seeded
) -> None:
    _client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    messages = _messages(_chars_for(600_000))
    initial_baseline = (154_735, 150_000) if seeded else None

    calls = []
    downstream_calls = []

    def spy_limit(*, reported, context_limit):
        calls.append((reported, context_limit))
        return verdict

    def spy_downstream(**kw):
        downstream_calls.append(kw)
        return (True, 1, 1) if seeded else True

    monkeypatch.setattr(conversation, "report_within_context_limit", spy_limit)
    monkeypatch.setattr(
        conversation,
        "reported_usage_growth_consistent" if seeded else "first_turn_report_plausible",
        spy_downstream,
    )

    kept, baseline = _parked_gate(
        conversation, initial_baseline, reported, messages, context_limit=1_048_576
    )
    assert calls == [(reported, 1_048_576)], (
        "Parked gate bypassed the shared window-cap decision"
    )
    assert (kept is not None) is verdict
    if verdict:
        assert len(downstream_calls) == 1
        assert baseline == (reported, 600_000)
    else:
        assert downstream_calls == [], (
            "Window-cap rejection must short-circuit before the 8x gates"
        )
        assert baseline == initial_baseline


WINDOW_CAP_CASES = [
    pytest.param(1_048_575, 1_000_000, 1_048_576, True, id="limit-minus-one-accept"),
    pytest.param(1_048_576, 1_000_000, 1_048_576, True, id="limit-exact-accept"),
    pytest.param(1_048_577, 1_000_000, 1_048_576, False, id="limit-plus-one-reject"),
    pytest.param(1_048_577, 1_000_000, None, True, id="unknown-limit-falls-through"),
    pytest.param(1_048_577, 1_000_000, 0, True, id="zero-limit-ignored"),
    pytest.param(1_048_577, 1_000_000, -1, True, id="negative-limit-ignored"),
    pytest.param(1_048_577, 1_000_000, True, True, id="bool-limit-ignored"),
    pytest.param(1_048_577, 1_000_000, float("nan"), True, id="nan-limit-ignored"),
]


@pytest.mark.parametrize("seeded", [False, True])
@pytest.mark.parametrize(
    ("reported", "local", "context_limit", "accept"), WINDOW_CAP_CASES
)
def test_window_cap_boundary_matrix_parity(
    monkeypatch, tmp_path, seeded, reported, local, context_limit, accept
) -> None:
    client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    affinity = f"win-edge-{seeded}-{reported}-{context_limit}"
    prev = (950_000, 940_000) if seeded else None
    if seeded:
        _flat_gate(client, affinity, prev[0], prev[1])

    kept_flat, baseline_flat = _flat_gate(
        client, affinity, reported, local, context_limit=context_limit
    )
    kept_parked, baseline_parked = _parked_gate(
        conversation,
        prev,
        reported,
        _messages(_chars_for(local)),
        context_limit=context_limit,
    )
    assert (kept_flat is not None) is accept
    assert (kept_parked is not None) is accept
    expected = (reported, local) if accept else prev
    assert baseline_flat == expected
    assert baseline_parked == expected


@pytest.mark.parametrize(
    ("reported", "local"),
    [
        (1_077_303, 300_000),
        (2_610_753, 600_000),
        (6_164_316, 850_000),
        (11_227_431, 1_400_000),
    ],
)
def test_issue_99_proportional_inflation_parity(
    monkeypatch, tmp_path, reported, local
) -> None:
    """Issue #99 samples: proportional inflation passes 8x growth gate without a window cap,
    and MUST be rejected in both engines when the 1,048,576 context window is known.
    """
    client, contract, conversation = _load_package(monkeypatch, tmp_path)
    baseline = (154_735, 150_000)

    # Confirm the proportional numbers indeed cleared the 8x growth gate pre-fix.
    ok_without_cap, _, _ = contract.reported_usage_growth_consistent(
        prev_reported=baseline[0],
        reported=reported,
        prev_local=baseline[1],
        local=local,
    )
    assert ok_without_cap is True

    _flat_gate(client, f"i99-{reported}", baseline[0], baseline[1])
    kept_flat, baseline_flat = _flat_gate(
        client, f"i99-{reported}", reported, local, context_limit=1_048_576
    )
    kept_parked, baseline_parked = _parked_gate(
        conversation,
        baseline,
        reported,
        _messages(_chars_for(local)),
        context_limit=1_048_576,
    )
    assert kept_flat is None
    assert kept_parked is None
    assert baseline_flat == baseline
    assert baseline_parked == baseline


def _parked_drain_frame(
    conversation,
    frame: dict,
    *,
    prior_limit: int | None = None,
    prior_occupancy: dict | None = None,
):
    """Drive Parked-MCP Conversation._drain_updates on one frame."""
    import queue
    import threading

    q: queue.Queue = queue.Queue()
    q.put(frame)
    conv = object.__new__(conversation.Conversation)
    conv.lock = threading.Lock()
    conv.gen = 1
    conv.session = SimpleNamespace(updates=q)
    conv.occupancy = dict(prior_occupancy) if prior_occupancy is not None else None
    conv.frame_usage = None
    conv._context_limit = prior_limit
    conv.last_activity = 0.0
    conv._drain_updates(1)
    return conv.occupancy, conv._context_limit


def _replay_capture_frame(
    client,
    frame: dict,
    *,
    prior_limit: int | None = None,
    prior_occupancy: dict | None = None,
):
    """Drive Replay _capture_context_occupancy on one frame."""
    stats: dict = {
        "turn_id_hash": "sha256:single-owner-test",
        client._PROMPT_TURN_ACTIVE_KEY: True,
    }
    if prior_limit is not None:
        stats["context_limit"] = prior_limit
    if prior_occupancy is not None:
        stats["context_occupancy"] = dict(prior_occupancy)
    client._capture_context_occupancy(frame, stats)
    occ = stats.get("context_occupancy")
    if isinstance(occ, dict):
        occ = {k: occ[k] for k in ("used", "size") if k in occ}
    return occ, stats.get("context_limit")


@pytest.mark.parametrize("limit_verdict", [None, 42_424])
def test_both_engines_delegate_usage_update_context_limit_to_contract(
    monkeypatch, tmp_path, limit_verdict
) -> None:
    """Both Replay _capture_context_occupancy and Parked-MCP _drain_updates must
    call and adopt the shared usage_update_valid / context_limit_from_usage_update."""
    client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    frame = {"sessionUpdate": "usage_update", "used": 500, "size": 20_000}

    replay_valid_calls = []
    replay_limit_calls = []

    def spy_replay_valid(u):
        replay_valid_calls.append(u)
        return True

    def spy_replay_limit(u):
        replay_limit_calls.append(u)
        return limit_verdict

    monkeypatch.setattr(client, "usage_update_valid", spy_replay_valid)
    monkeypatch.setattr(client, "context_limit_from_usage_update", spy_replay_limit)
    _occ_r, limit_r = _replay_capture_frame(client, frame)
    assert replay_valid_calls == [frame]
    assert replay_limit_calls == [frame]
    assert limit_r == limit_verdict

    parked_valid_calls = []
    parked_limit_calls = []

    def spy_parked_valid(u):
        parked_valid_calls.append(u)
        return True

    def spy_parked_limit(u):
        parked_limit_calls.append(u)
        return limit_verdict

    monkeypatch.setattr(conversation, "usage_update_valid", spy_parked_valid)
    monkeypatch.setattr(conversation, "context_limit_from_usage_update", spy_parked_limit)
    _occ_p, limit_p = _parked_drain_frame(conversation, frame)
    assert parked_valid_calls == [frame]
    assert parked_limit_calls == [frame]
    assert limit_p == limit_verdict


USAGE_UPDATE_PARITY_CASES = [
    pytest.param(
        {"sessionUpdate": "usage_update", "used": 500, "size": 20_000},
        None,
        {"used": 500, "size": 20_000},
        20_000,
        id="valid-full-frame",
    ),
    pytest.param(
        {"sessionUpdate": "usage_update", "used": "bogus", "size": 20_000},
        15_000,
        None,
        15_000,
        id="corrupt-used-vetoes-size",
    ),
    pytest.param(
        {"sessionUpdate": "usage_update", "used": -1, "size": 20_000},
        15_000,
        None,
        15_000,
        id="negative-used-vetoes-size",
    ),
    pytest.param(
        {"sessionUpdate": "usage_update", "used": True, "size": 20_000},
        15_000,
        None,
        15_000,
        id="bool-used-vetoes-size",
    ),
    pytest.param(
        {"sessionUpdate": "usage_update", "used": 500, "size": float("nan")},
        15_000,
        None,
        15_000,
        id="nan-size-rejected",
    ),
    pytest.param(
        {"sessionUpdate": "usage_update", "size": 30_000},
        15_000,
        {"size": 30_000},
        30_000,
        id="valid-partial-size-only",
    ),
    pytest.param(
        {"sessionUpdate": "usage_update", "used": 500},
        15_000,
        {"used": 500},
        15_000,
        id="valid-partial-used-only-keeps-limit",
    ),
    pytest.param(
        {"sessionUpdate": "usage_update", "used": 500, "size": 0},
        15_000,
        {"used": 500, "size": 0},
        15_000,
        id="zero-size-keeps-prior-limit",
    ),
]


@pytest.mark.parametrize(
    ("frame", "prior_limit", "expected_occ", "expected_limit"),
    USAGE_UPDATE_PARITY_CASES,
)
def test_usage_update_whole_frame_validity_parity(
    monkeypatch, tmp_path, frame, prior_limit, expected_occ, expected_limit
) -> None:
    client, _contract, conversation = _load_package(monkeypatch, tmp_path)
    occ_r, limit_r = _replay_capture_frame(client, frame, prior_limit=prior_limit)
    occ_p, limit_p = _parked_drain_frame(conversation, frame, prior_limit=prior_limit)
    assert occ_r == expected_occ
    assert occ_p == expected_occ
    assert limit_r == expected_limit
    assert limit_p == expected_limit
