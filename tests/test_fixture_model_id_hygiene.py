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
  (family prefix + digit, e.g. ``gemini-3.8-flash``, ``gpt-4``, or an
  o-series id like ``o3``);
- use synthetic ids (``fake-model-a``, ``fake-model-b-high``, …) instead;
- a real name is allowed ONLY inside a string carrying a scoped ``(live: …)``
  annotation before that occurrence, in a comment/docstring, or in an
  allowlisted historical fixture below (exact path + reason + approver).

Scanner guarantees and limits (external review of PR #89 folded in):
- operates on the AST, so adjacent literal concatenation (``"gemini-" "3"``)
  is caught as one value and f-string literal segments are caught per segment;
- docstring nodes are exempt by node identity, including implicitly
  concatenated and decorated/nested function docstrings;
- values assembled from runtime data (``f"x{user_input}"``, registry lookups)
  are outside any static lint and are NOT claimed to be caught.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

# Real vendor model-id shape: a known family prefix immediately followed by a
# digit, or a standalone o-series id (o1..o9).  Synthetic fixture ids
# (fake-model-a, fake-model-b-high) never match.
REAL_MODEL_ID = re.compile(
    r"(?i)\b(?:gemini|claude|gpt|grok|llama|mistral|deepseek|palm|qwen)-[0-9]"
    r"|\bo[1-9]\b"
)

# A real name is exempt only INSIDE a (live: …) annotation span — a label
# elsewhere in the same string cannot exempt unrelated occurrences.
_LIVE_ANNOTATION = re.compile(r"\(live:[^)]*\)")

# Exact relative paths legitimately required to carry real vendor ids, with
# the reason and the human who approved the exception.  New exceptions need
# operator sign-off.
ALLOWLIST: dict[str, str] = {
    # Historical fixture pinning the model ids actually observed in the
    # official ACP 1.4.0 server's responses; synthetic ids would test nothing.
    "test_140_client_delta.py": (
        "historical fixture pinning ids observed in the official ACP 1.4.0 "
        "server (approved rhgo1749, 2026-11-25)"
    ),
    # This scanner's own self-test fixtures necessarily embed the id shapes
    # it must detect; the file has no other fixture role.
    "test_fixture_model_id_hygiene.py": (
        "scanner self-test fixtures embed the detected shapes "
        "(approved rhgo1749, 2026-11-25)"
    ),
}


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """id()s of docstring Constant nodes (module/class/function, any nesting)."""
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", None)
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                docstrings.add(id(body[0].value))
    return docstrings


def _flagged_occurrences(value: str) -> list[str]:
    exempt_spans = [(m.start(), m.end()) for m in _LIVE_ANNOTATION.finditer(value)]
    hits = []
    for match in REAL_MODEL_ID.finditer(value):
        if any(start <= match.start() < end for start, end in exempt_spans):
            continue
        hits.append(match.group(0))
    return hits


def scan_source(source: str) -> list[tuple[int, str]]:
    """(lineno, offending id) for every real vendor model id in fixture strings.

    ast.walk descends into JoinedStr, so f-string literal segments are plain
    Constant nodes reached here; adjacent literals are already one merged
    Constant at parse time.
    """
    tree = ast.parse(source)
    docstrings = _docstring_nodes(tree)
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstrings:
                continue
            for hit in _flagged_occurrences(node.value):
                findings.append((node.lineno, hit))
    return findings


def scan_file(path: Path) -> list[str]:
    return [
        f"{path.relative_to(TESTS_DIR)}:{lineno}: real vendor model id {hit!r} "
        f"in a fixture string — use a synthetic id (fake-model-a, "
        f"fake-model-b-high, …) or annotate a real observation with '(live: …)'"
        for lineno, hit in scan_source(path.read_text(encoding="utf-8"))
    ]


def scan_tree(root: Path) -> list[str]:
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        if str(path.relative_to(root)) in ALLOWLIST:
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


# ---------------------------------------------------------------------------
# Scanner self-tests: the lint must catch the shapes a copy-paste agent
# actually writes, and must not flag the exempt shapes.

def test_scanner_catches_plain_literal() -> None:
    assert scan_source('model = "gemini-3-pro"') == [(1, "gemini-3")]


def test_scanner_catches_fstring_literal_segments() -> None:
    assert scan_source('model = f"gemini-3-pro{suffix}"') == [(1, "gemini-3")]


def test_scanner_catches_adjacent_literal_concatenation() -> None:
    assert scan_source('model = "gemini-" "3-pro"') == [(1, "gemini-3")]


def test_scanner_catches_standalone_o_series() -> None:
    assert scan_source('model = "o3"') == [(1, "o3")]
    assert scan_source('model = "o3-mini"') == [(1, "o3")]


def test_scanner_exempts_docstrings_including_nested_and_concatenated() -> None:
    source = (
        '"""module note about gemini-3.8-flash\n'
        'and a second line."""\n'
        "def f():\n"
        '    """inner note about gemini-3.8-flash."""\n'
        "    return 1\n"
    )
    assert scan_source(source) == []


def test_scanner_live_annotation_is_scoped_per_occurrence() -> None:
    # Annotated occurrence is exempt…
    assert scan_source('x = "(live: gemini-3.8-flash)"') == []
    # …but a label earlier in the same string does not exempt a second,
    # unannotated occurrence.
    assert scan_source('x = "(live: gemini-3.8-flash) and gemini-3-pro"') == [
        (1, "gemini-3")
    ]
    # A bare 'live:' without the annotation form does not exempt.
    assert scan_source('x = "gemini-3-pro live:"') == [(1, "gemini-3")]


def test_scanner_passes_synthetic_ids() -> None:
    assert scan_source('a="fake-model-a"; b="fake-model-b-high"; c="model-9"') == []
