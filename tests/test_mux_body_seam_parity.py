"""The two mux bodies share a relay loop; features must land in BOTH.

``scripts/acp_mux.py`` is the base engine. ``scripts/antigravity-acp-mux.py``
is the hardened entrypoint the launcher actually ships; its ``main()`` is a
hand-maintened copy of the base relay loop with one extra vendor-sentinel
surface. Because the two ``main()`` bodies are separate code, a lifecycle
seam added to one is silently absent from the other.

That has burned this repo repeatedly:

* ``37828b1`` added the F3 per-lane process lease to the base ``main()``; the
  shipped entrypoint ran every deployed mux WITHOUT the lease until the
  follow-up fix ``5d04faf`` (issue #24 F3).
* ``4206ba7`` added the issue #26 stage-trace seams to the base ``main()``;
  the shipped entrypoint produced no trace until ``cbfad63``.

This gate makes the class impossible to reintroduce: every module-level
symbol the base ``main()`` calls must also be referenced by the shipped
entrypoint (directly, via ``base.<symbol>``, or through a module-level
wrapper). A genuine base-only seam must be listed in ``BASE_ONLY_SEAMS``
with a reason and an expiry date, and the test fails once the expiry passes
so the exception cannot rot into a silent gap.
"""

from __future__ import annotations

import ast
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE_ENGINE = ROOT / "scripts" / "acp_mux.py"
ENTRYPOINT = ROOT / "scripts" / "antigravity-acp-mux.py"

# Seams the base main() calls that the shipped entrypoint legitimately does
# not. Each entry MUST carry a reason and an ISO expiry date; the gate fails
# when the expiry has passed so an exception cannot quietly become a gap.
BASE_ONLY_SEAMS: dict[str, dict[str, str]] = {}


def _module_level_symbols(tree: ast.Module) -> set[str]:
    symbols: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    symbols.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            symbols.add(node.target.id)
    return symbols


def _main_body(tree: ast.Module) -> ast.FunctionDef:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            return node
    raise AssertionError("no top-level main() found")


def _called_symbols(scope: ast.AST) -> set[str]:
    """Names used inside ``scope``, resolving ``base.X`` to ``X``.

    The entrypoint reaches shared helpers through ``base.<name>``, so the
    attribute tail is the comparable identity.
    """
    used: set[str] = set()
    for node in ast.walk(scope):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            base = node.value
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name) and base.id == "base":
                used.add(node.attr)
    return used


def _base_main_seams() -> set[str]:
    base_tree = ast.parse(BASE_ENGINE.read_text(encoding="utf-8"))
    symbols = _module_level_symbols(base_tree)
    base_main = _called_symbols(_main_body(base_tree))
    # Only symbols the base engine owns and main() actually touches.
    return {name for name in base_main if name in symbols}


def _missing_seams(entrypoint_source: str) -> set[str]:
    """Base-main seams absent from the given entrypoint source.

    The base side is scoped to its ``main()`` (those are the live lifecycle
    seams). The entrypoint side is scoped to the whole module: it legitimately
    reaches some seams through module-level wrappers and a monkey-patch, and
    what matters is that the shipped body exercises the seam at all.
    """
    seams = _base_main_seams()
    entry_calls = _called_symbols(ast.parse(entrypoint_source))
    return seams - entry_calls - set(BASE_ONLY_SEAMS)


def test_both_mux_bodies_exist():
    assert BASE_ENGINE.is_file(), BASE_ENGINE
    assert ENTRYPOINT.is_file(), ENTRYPOINT


def test_entrypoint_main_calls_every_base_seam():
    seams = _base_main_seams()
    assert seams, "base main() references no shared symbols: gate is vacuous"

    missing = sorted(_missing_seams(ENTRYPOINT.read_text(encoding="utf-8")))
    assert not missing, (
        "scripts/antigravity-acp-mux.py never references lifecycle seam(s) "
        f"that scripts/acp_mux.py main() uses: {missing}. The launcher ships "
        "the entrypoint, so a seam present only in the base engine never "
        "runs in production. Call it in the entrypoint main() (directly or "
        "via base.<name>), or add an approved, dated exception to "
        "BASE_ONLY_SEAMS."
    )


def test_base_only_seam_exceptions_are_human_approved_and_unexpired():
    today = date.today().isoformat()
    for seam, meta in BASE_ONLY_SEAMS.items():
        assert meta.get("reason"), f"{seam}: exception needs a reason"
        assert meta.get("approved_by"), f"{seam}: exception needs a human approver"
        expiry = meta.get("expires")
        assert expiry, f"{seam}: exception needs an ISO expiry date"
        assert expiry >= today, (
            f"{seam}: exception expired on {expiry}; re-approve or close the "
            "seam gap in the shipped entrypoint"
        )


def test_gate_fails_on_the_real_past_mistakes():
    """Witness: the gate must flag the two historical drifts, not pass them.

    Both mutations are edits of the REAL current entrypoint source, so the
    witness tracks the file instead of freezing a stale copy:

    * the pre-#57 shape (5d04faf^): the F3 lane-lease seam absent;
    * the pre-#26-port shape (before cbfad63): the stage-trace seams absent.
    """
    source = ENTRYPOINT.read_text(encoding="utf-8")

    stripped_lease = source.replace("base._LaneLease", "base._removed_lease")
    assert stripped_lease != source, "lane-lease seam vanished from the file"
    assert "_LaneLease" in _missing_seams(stripped_lease), (
        "gate went blind: an entrypoint without the F3 lane lease passed"
    )

    stripped_trace = source.replace("base._trace", "base._removed_trace")
    assert stripped_trace != source, "stage-trace seam vanished from the file"
    assert "_trace" in _missing_seams(stripped_trace), (
        "gate went blind: an entrypoint without stage tracing passed"
    )
