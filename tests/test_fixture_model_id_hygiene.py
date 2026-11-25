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
  (family prefix + optional hyphen + digit, e.g. ``gemini-3.8-flash``,
  ``gpt-4``, ``qwen2.5-72b``, ``deepseek-v3``, or an o-series id like
  ``o3``);
- use synthetic ids (``fake-model-a``, ``fake-model-b-high``, …) instead;
- a real name is allowed ONLY inside a ``(live: …)`` annotation span, in a
  comment/docstring, or in an allowlisted historical fixture below (exact
  path + reason + named approver + expiry; expired or no-longer-needed
  entries fail the suite).

Scanner guarantees and limits (external reviews of PR #89 rounds 1-2 folded
in; limits are deliberate — no arbitrary expression evaluation):
- operates on the AST, so adjacent literal concatenation (``"gemini-" "3"``)
  is caught as one value and f-string literal segments are caught per segment;
- docstring nodes are exempt by node identity, including implicitly
  concatenated and decorated/nested function docstrings;
- this scanner's own self-test fixtures are exempt ONLY inside
  ``test_scanner_*`` functions, not file-wide;
- NOT caught (documented limits): values assembled from runtime data
  (``f"x{user_input}"``, registry lookups); statically-known splits that
  Python does not constant-fold (``f"gemini-{'3'}-pro"``,
  ``"gemini-" + "3-pro"``); a real id merely *placed inside* a
  ``(live: …)`` span in a fixture value — the annotation is syntactic, so
  use it only for genuine live observations; the compiler flag ``-O3`` is
  deliberately not flagged (the o-series rule requires no leading hyphen).
"""

from __future__ import annotations

import ast
import re
from datetime import date
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

# Real vendor model-id shape: a known family prefix + optional hyphen + digit
# (covers gemini-3, gpt-4, gpt4, llama3.2, qwen2.5), an explicit
# deepseek-vN shape, or a standalone o-series id (o1..o9) not preceded by a
# hyphen/word char (so the compiler flag -O3 is not flagged).  Synthetic
# fixture ids (fake-model-a, fake-model-b-high) never match.
REAL_MODEL_ID = re.compile(
    r"(?i)\b(?:gemini|claude|gpt|grok|llama|mistral|deepseek|palm|qwen)-?[0-9]"
    r"|\bdeepseek-v[0-9]"
    r"|(?<![-\w])o[1-9]\b"
)

# A real name is exempt only INSIDE a (live: …) annotation span — a label
# elsewhere in the same string cannot exempt unrelated occurrences.
_LIVE_ANNOTATION = re.compile(r"\(live:[^)]*\)")

# Exact relative paths legitimately required to carry real vendor ids, each
# with reason, named approver, and expiry.  New exceptions need operator
# sign-off; expired or no-longer-needed entries fail the suite below.
ALLOWLIST: dict[str, str] = {
    # Historical fixture pinning the model ids actually observed in the
    # official ACP 1.4.0 server's responses; synthetic ids would test nothing.
    "test_140_client_delta.py": (
        "historical fixture pinning ids observed in the official ACP 1.4.0 "
        "server (approved rhgo1749, 2026-11-25; expires 2027-11-25)"
    ),
}

# This scanner's self-tests embed the detected shapes on purpose; the
# exemption is scoped to these functions, not the whole file.
SELF_TEST_FILE = "test_fixture_model_id_hygiene.py"
_SELF_TEST_PREFIX = "test_scanner_"


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


def _self_test_exempt_nodes(tree: ast.AST) -> set[int]:
    """id()s of string Constant nodes inside test_scanner_* function BODIES.

    Round-3 review N9: line-RANGE exemptions covered the signature, so a
    real id in a default argument escaped.  Round-4 review N11: filtering
    by LINE conflates nodes sharing a line — a one-line function's default
    argument sits on the same line as its body.  Exempt by NODE IDENTITY
    within body subtrees; decorators, defaults, and annotations are not
    body nodes and stay flagged.
    """
    exempt: set[int] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name.startswith(_SELF_TEST_PREFIX)
        ):
            for stmt in node.body:
                for child in ast.walk(stmt):
                    if isinstance(child, ast.Constant) and isinstance(child.value, str):
                        exempt.add(id(child))
    return exempt


def _scan_parsed_tree(
    tree: ast.AST, exempt_constants: set[int] | None = None
) -> list[tuple[int, str]]:
    """Core string-literal scan over ONE parsed tree.

    ``exempt_constants`` is a set of node id()s from THIS tree — id()s
    across separately-parsed trees are unrelated objects and must never be
    mixed (round-4 review N11 follow-through).
    """
    docstrings = _docstring_nodes(tree)
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstrings:
                continue
            if exempt_constants is not None and id(node) in exempt_constants:
                continue
            for hit in _flagged_occurrences(node.value):
                findings.append((node.lineno, hit))
    return findings


def scan_source_with_self_test_exemption(source: str) -> list[tuple[int, str]]:
    """Scan one source, exempting string literals inside test_scanner_* bodies."""
    tree = ast.parse(source)
    return _scan_parsed_tree(tree, _self_test_exempt_nodes(tree))


def _is_self_test_file(path: Path) -> bool:
    """Exact path match — round-3 review N8: a basename match let ANY
    nested file named like the scanner claim the exemption."""
    return path.resolve() == (TESTS_DIR / SELF_TEST_FILE).resolve()


def scan_file(path: Path, root: Path | None = None) -> list[str]:
    source = path.read_text(encoding="utf-8")
    if _is_self_test_file(path):
        findings = scan_source_with_self_test_exemption(source)
    else:
        findings = scan_source(source)
    rel = path.relative_to(root) if root is not None else path.relative_to(TESTS_DIR)
    return [
        f"{rel}:{lineno}: real vendor model id {hit!r} "
        f"in a fixture string — use a synthetic id (fake-model-a, "
        f"fake-model-b-high, …) or annotate a real observation with '(live: …)'"
        for lineno, hit in findings
    ]


def scan_tree(root: Path) -> list[str]:
    offenders: list[str] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        if str(path.relative_to(root)) in ALLOWLIST:
            continue
        offenders.extend(scan_file(path, root))
    return offenders


def test_fake_lane_fixtures_use_synthetic_model_ids() -> None:
    offenders = scan_tree(TESTS_DIR)
    assert not offenders, (
        "fake-lane fixtures must not mirror real vendor model ids — mirrored "
        "names go stale when the vendor retires a model and read as "
        "current-catalog claims (AGENTS.md, class of 2026-11-20):\n"
        + "\n".join(offenders)
    )


_EXPIRY_RE = re.compile(r"expires (\d{4}-\d{2}-\d{2})")
# Structured metadata: a NAMED approver (non-empty token), an approval date,
# and an expiry date, in one anchored form.  Round-3 review N7: a bare
# "approved " substring check let ``approved ; expires …`` through.
_METADATA_RE = re.compile(
    r"\(approved (?P<approver>[A-Za-z0-9][A-Za-z0-9_.-]+), "
    r"(?P<approved>\d{4}-\d{2}-\d{2}); expires (?P<expires>\d{4}-\d{2}-\d{2})\)"
)


def test_allowlist_exceptions_are_documented_and_unexpired() -> None:
    """Every exception carries a real reason, a NAMED approver, and a
    not-yet-passed expiry."""
    today = date.today()
    for path, reason in ALLOWLIST.items():
        assert len(reason.split("(approved")[0].strip()) >= 10, (
            f"{path}: exception reason is too thin to audit"
        )
        match = _METADATA_RE.search(reason)
        assert match, (
            f"{path}: exception must carry "
            "'(approved <name>, YYYY-MM-DD; expires YYYY-MM-DD)'"
        )
        # Round-4 review N12: BOTH dates must be real calendar dates, not
        # just date-shaped strings.
        try:
            date.fromisoformat(match.group("approved"))
        except ValueError as exc:
            raise AssertionError(f"{path}: invalid approval date: {exc}") from exc
        assert date.fromisoformat(match.group("expires")) >= today, (
            f"{path}: exception expired on {match.group('expires')} — renew "
            "with operator sign-off or fix the fixture"
        )


def test_allowlist_exceptions_are_still_needed() -> None:
    """A stale allowlist entry (file gone or ids gone) is itself a failure."""
    for rel in ALLOWLIST:
        path = TESTS_DIR / rel
        assert path.exists(), f"allowlisted {rel} no longer exists — drop the entry"
        assert scan_source(path.read_text(encoding="utf-8")), (
            f"allowlisted {rel} no longer contains real vendor ids — drop the entry"
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


def test_scanner_catches_no_hyphen_family_ids() -> None:
    assert scan_source('m = "qwen2.5-72b-instruct"') == [(1, "qwen2")]
    assert scan_source('m = "llama3.2"') == [(1, "llama3")]
    assert scan_source('m = "gpt4"') == [(1, "gpt4")]


def test_scanner_catches_deepseek_v_shape() -> None:
    assert scan_source('m = "deepseek-v3"') == [(1, "deepseek-v3")]


def test_scanner_does_not_flag_compiler_optimization_flag() -> None:
    assert scan_source('cflags = "-O3"') == []


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


def test_scanner_self_test_exemption_is_body_scoped_exact_path() -> None:
    """The self-test exemption is exact-path and function-BODY scoped.

    Exercises the real scan_file/scan_tree paths (round-3 review: a test
    that merely duplicates the filtering proves nothing):
    - this file's own in-body self-test literals are exempt (scan of the
      real file yields no findings from inside test_scanner_* bodies);
    - a real id in a test_scanner_* DEFAULT ARGUMENT is still flagged (N9);
    - a nested file that merely SHARES this file's basename and defines
      test_scanner_* functions gets no exemption (N8).
    """
    # (a) the real file scans clean apart from documented allowlisted shapes
    assert scan_file(TESTS_DIR / SELF_TEST_FILE) == []

    # (b) default-argument id is NOT exempt, even when the default shares
    # its line with an exempt body literal (round-4 review N11: line-based
    # filtering conflated them; node identity does not)
    same_line_src = (
        'def test_scanner_r3(probe="gemini-3-pro") -> None:\n'
        '    return "gemini-3-body"\n'
    )
    flagged = scan_source_with_self_test_exemption(same_line_src)
    assert flagged == [(1, "gemini-3")], (
        "default-argument ids must be flagged; body literals exempt — "
        "exemption must key on node identity, not line"
    )
    one_line_src = 'def test_scanner_r4(probe="gpt-4"): return "gpt-4-body"\n'
    flagged = scan_source_with_self_test_exemption(one_line_src)
    assert flagged == [(1, "gpt-4")], (
        "one-line def: the default on the SAME line as the body must stay flagged (N11)"
    )

    # (c) nested same-basename impostor gets no exemption
    import shutil
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        impostor = root / "sub" / SELF_TEST_FILE
        impostor.parent.mkdir()
        shutil.copyfile(TESTS_DIR / SELF_TEST_FILE, impostor)
        offenders = scan_tree(root)
    assert any("gemini-3" in line or "gemini-4" in line for line in offenders), (
        "a nested file with the scanner's basename claimed the exemption (N8)"
    )
