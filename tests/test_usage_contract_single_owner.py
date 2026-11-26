"""The usage contract has ONE owner shared by both engines (issue #102 shape).

Since issue #102 the contract is small: ``completion.usage`` is always ``None``
(never seeded from ACP consumption sums), ``usage_update`` frames are
protocol-validated once in ``parked/usage_contract.py``, and the token
estimator that the live canary's semantic checks hang off lives there too.

Defense layers kept from the pre-#102 file (they police the SINGLE-OWNER
discipline, which outlives any particular gate):
- AST ownership scan: neither engine may bind a contract name anywhere
  (module level, nested, annotated, destructuring, walrus) — imports are the
  only permitted binding path;
- object identity: the engines' imported names ARE the contract's objects;
- a small boundary matrix for the surviving frame-validity and estimator
  helpers, so a silently re-tuned copy fails.

New in #102: a removal pin.  The magnitude-gate machinery (#6 verdict store,
#87 growth/plausibility gates, #99 window cap) is retired; none of its names
may be bound anywhere in the plugin tree.  Re-introducing a gate is a design
change that must go through the contract module first.

Witnesses replaying the historical drifts:
- against ``e92d19d`` (pre-#88): the identity assertions fail — the contract
  existed as two hand-copies;
- against ``c52bc8e`` (pre-#102): the removal pin fails — the retired gate
  names are all bound in the engines.
"""

from __future__ import annotations

import ast
import importlib
import math
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN_DIR = ROOT / "hermes-plugin" / "antigravity-acp"

ENGINE_FILES = {
    "Replay engine client": PLUGIN_DIR / "client.py",
    "Parked-MCP conversation": PLUGIN_DIR / "parked" / "conversation.py",
}
CONTRACT_FILE = PLUGIN_DIR / "parked" / "usage_contract.py"

# Names the surviving contract owns; an engine BINDING any of these (plain,
# annotated, nested, destructured, walrus) is a re-fork.
CONTRACT_NAMES = {
    "_CJK_RANGES",
    "nonnegative_usage_number",
    "usage_update_valid",
    "estimate_tokens",
    "transcript_tokens",
}
FORBIDDEN_OWN_NAMES = CONTRACT_NAMES | {f"_{name}" for name in CONTRACT_NAMES}

# Issue #102 removal pin: the retired gate/verdict/limit machinery may not be
# bound ANYWHERE in the plugin tree (both engines, state, contract, bridge).
RETIRED_NAMES = {
    "USAGE_GROWTH_FACTOR",
    "USAGE_GROWTH_SLACK_TOKENS",
    "usage_divergence_tolerance",
    "valid_context_limit",
    "context_limit_from_usage_update",
    "report_within_context_limit",
    "reported_usage_growth_consistent",
    "first_turn_report_plausible",
    "prompt_result_usage_is_occupancy_eligible",
    "_turn_usage_from_prompt_result",
    "_guard_reported_turn_usage",
    "_gate_turn_consumption",
    "_usage_baseline",
    "_context_limit",
    "_context_limit_model",
    "_context_limit_effective_model",
    "_TURN_USAGE_BASELINES",
    "_CONVERSATION_CONTEXT_LIMITS",
    "_server_identity_from_initialize",
    "_usage_semantics_for_identity",
    "_SERVER_CONSUMPTION_SEMANTICS_KEY",
    "_SERVER_IDENTITY_KEY",
    "_SERVER_IDENTITY_ATTR",
    "_USAGE_SEMANTICS_ATTR",
    "_USAGE_SEMANTICS_VERIFIED",
    "_USAGE_DELTA_SCOPE",
    "record_semantics_evidence",
    "semantics_verdict",
    "dropped_semantics_unverified",
    "dropped_inflated_turn_usage",
    "server_consumption_semantics",
}


def _owned_names(path: Path) -> set[str]:
    """Every name the module binds: Store-context ``ast.Name`` + def/class names.

    Covers plain assignment, annotated assignment, tuple/list destructuring,
    walrus, for/comprehension targets, and nested defs — not just module-level
    ``Assign`` statements.  ``import`` bindings are ``ast.alias`` nodes and are
    deliberately NOT covered: importing the contract is the allowed path.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    owned: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            owned.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            owned.add(node.id)
    return owned


def test_engines_never_rebind_a_contract_name() -> None:
    for label, path in ENGINE_FILES.items():
        stolen = _owned_names(path) & FORBIDDEN_OWN_NAMES
        assert not stolen, f"{label} re-binds contract-owned name(s): {sorted(stolen)}"


def test_contract_module_owns_the_full_contract() -> None:
    owned = _owned_names(CONTRACT_FILE)
    missing = CONTRACT_NAMES - owned
    assert not missing, f"contract module lost its definitions of: {sorted(missing)}"


def test_retired_gate_machinery_is_gone_from_the_whole_plugin_tree() -> None:
    """Issue #102: no module in the plugin may bind a retired gate/verdict name."""
    offenders: dict[str, list[str]] = {}
    for path in sorted(PLUGIN_DIR.rglob("*.py")):
        hit = sorted(_owned_names(path) & RETIRED_NAMES)
        if hit:
            offenders[str(path.relative_to(PLUGIN_DIR))] = hit
    assert not offenders, f"retired usage-gate names re-appear: {offenders}"


def _load_package(monkeypatch, tmp_path: Path):
    """Load the plugin package (both engines) with stubbed Hermes providers."""
    monkeypatch.setenv(
        "HERMES_ANTIGRAVITY_ACP_STATE_FILE",
        str(tmp_path / "antigravity-acp-contract-state.json"),
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
    return client, contract, conversation


def _load_contract():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "antigravity_usage_contract_single_owner", CONTRACT_FILE
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_engines_import_the_contract_objects_themselves(monkeypatch, tmp_path) -> None:
    """Object identity: a hand-copied twin in either engine fails here even
    when it agrees at every boundary (kept from the pre-#102 file)."""
    client, contract, conversation = _load_package(monkeypatch, tmp_path)
    assert client.usage_update_valid is contract.usage_update_valid
    assert client.nonnegative_usage_number is contract.nonnegative_usage_number
    assert client.estimate_tokens is contract.estimate_tokens
    assert conversation.usage_update_valid is contract.usage_update_valid


@pytest.mark.parametrize("update,expected", [
    # Valid whole frames.
    ({"sessionUpdate": "usage_update", "used": 0, "size": 1048576}, True),
    ({"sessionUpdate": "usage_update", "used": 12000, "size": 1048576}, True),
    ({"sessionUpdate": "usage_update", "used": 12.5, "size": 1048576}, True),
    # Partial frames carrying only one valid field stay valid (field-wise merge).
    ({"sessionUpdate": "usage_update", "used": 12000}, True),
    ({"sessionUpdate": "usage_update", "size": 1048576}, True),
    # A frame carrying NEITHER field contributes nothing and is invalid.
    ({"sessionUpdate": "usage_update"}, False),
    # Any present-but-invalid field rejects the WHOLE frame: bools, negatives,
    # NaN/inf, strings — corrupt frames never contribute a sibling field.
    ({"sessionUpdate": "usage_update", "used": True, "size": 1048576}, False),
    ({"sessionUpdate": "usage_update", "used": 12000, "size": False}, False),
    ({"sessionUpdate": "usage_update", "used": -1, "size": 1048576}, False),
    ({"sessionUpdate": "usage_update", "used": 12000, "size": "unknown"}, False),
    ({"sessionUpdate": "usage_update", "used": math.nan, "size": 1048576}, False),
    ({"sessionUpdate": "usage_update", "used": math.inf, "size": 1048576}, False),
    ({"sessionUpdate": "agent_message_chunk"}, False),
    ("usage_update", False),
])
def test_usage_update_valid_boundary_matrix(update, expected) -> None:
    assert _load_contract().usage_update_valid(update) is expected


@pytest.mark.parametrize("value,expected", [
    (0, True), (10, True), (12.5, True),
    (-1, False), (float("nan"), False), (float("inf"), False),
    (True, False), (False, False), ("10", False), (None, False),
])
def test_nonnegative_usage_number_boundary_matrix(value, expected) -> None:
    assert _load_contract().nonnegative_usage_number(value) is expected


def test_estimator_is_deterministic_and_cjk_aware() -> None:
    """The canary's semantic yardstick: CJK-heavy text must not be estimated
    like ASCII (the historical ``len//3`` copies diverged exactly here)."""
    contract = _load_contract()
    ascii_tokens = contract.estimate_tokens("hello world " * 100)
    cjk_tokens = contract.estimate_tokens("안녕 세상 테스트 " * 100)
    assert ascii_tokens > 0 and cjk_tokens > 0
    assert cjk_tokens > ascii_tokens, "CJK must estimate above ASCII for equal length"
    assert contract.estimate_tokens("") == 0
    assert contract.estimate_tokens("hello world") == contract.estimate_tokens("hello world")
    messages = [
        {"role": "user", "content": "첫 번째 질문입니다"},
        {"role": "assistant", "content": "answer text here"},
    ]
    assert contract.transcript_tokens(messages) >= contract.estimate_tokens(
        "첫 번째 질문입니다 answer text here"
    )
