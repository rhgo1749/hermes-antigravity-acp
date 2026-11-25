"""Fake-lane fixtures must use synthetic model ids, never real vendor names.

Class recorded 2026-11-20 (issue #62 / ``4e1b52f``): fixtures mirrored real
catalog names (``gemini-3.8-flash-high`` …), the vendor retired one, and the
stale mirrored names read as current-catalog claims.  The rule was written
into AGENTS.md with no enforcer and a survivor immediately proved why a rule
without a gate is a repeat waiting to happen: ``test_llm_backend_policy_e2e.py``
still carried ``gemini-3-pro`` (introduced 2026-11-17, missed by the #62
sweep).  This lint is the enforcer.

Contract:
- string literals in ``tests/`` must not contain real vendor model ids
  (family prefix + digit, e.g. ``gemini-3.8-flash``, ``gpt-4``, ``claude-5``);
- use synthetic ids (``fake-model-a``, ``fake-model-b-high``, …) instead;
- real names are allowed ONLY in a labeled ``(live: …)`` observation string,
  in comments/docstrings, or in an allowlisted path-contract/model-surface
  test below (each with a reason).
"""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

# Real vendor model-id shape: a known family prefix immediately followed by a
# digit.  Synthetic fixture ids (fake-model-a, fake-model-b-high) never match.
REAL_MODEL_ID = re.compile(
    r"(?i)\b(gemini|claude|gpt|grok|llama|mistral|deepseek|palm|qwen|o[1-9])-?[0-9]"
)

# Files legitimately required to carry real vendor ids, with the reason and
# the human who approved the exception.  New exceptions need operator sign-off.
ALLOWLIST: dict[str, str] = {
    # Path contract: pins the model ids actually embedded in the official
    # ACP server binary under test; synthetic ids would test nothing.
    "test_140_client_delta.py": "path contract — real ids embedded in the pinned official ACP server (approved rhgo1749, 2026-11-25)",
    # Model-surface contract: exercises the real config-group shape the
    # vendor surface offers.
    "test_model_surface_selection.py": "model-surface contract — real config-group shape (approved rhgo1749, 2026-11-25)",
}

_LIVE_LABEL = "live:"


def _docstring_spans(source: str) -> set[tuple[int, int]]:
    """(row, col) starts of every module/class/function docstring node."""
    spans: set[tuple[int, int]] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                const = body[0].value
                spans.add((const.lineno, const.col_offset))
    return spans


def scan_file(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    docstrings = _docstring_spans(source)
    violations = []
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type != tokenize.STRING:
            continue
        if (tok.start[0], tok.start[1]) in docstrings:
            continue
        value = tok.string
        if _LIVE_LABEL in value:
            continue
        match = REAL_MODEL_ID.search(value)
        if match:
            violations.append(
                f"{path.relative_to(TESTS_DIR)}:{tok.start[0]}: real vendor model id "
                f"{match.group(0)!r} in a fixture string — use a synthetic id "
                f"(fake-model-a, fake-model-b-high, …) or label a real "
                f"observation with '(live: …)'"
            )
    return violations


def scan_tree(root: Path) -> list[str]:
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts or path.name in ALLOWLIST:
            continue
        offenders.extend(scan_file(path))
    return offenders


def test_fake_lane_fixtures_use_synthetic_model_ids() -> None:
    offenders = scan_tree(TESTS_DIR)
    assert not offenders, (
        "fake-lane fixtures must not mirror real vendor model ids — mirrored "
        "names go stale when the vendor retires a model and read as "
        "current-catalog claims (AGENTS.md, class of 2026-11-20):\n"
        + "\n".join(offenders)
    )
