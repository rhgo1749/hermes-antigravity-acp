# hermes-antigravity-acp

Standalone integration for Google's official Antigravity ACP server. Keep vendor authentication inside the official ACP runtime; do not extract or reimplement OAuth tokens. Prefer standard ACP JSON-RPC over CLI/TUI scraping or proprietary stream-json bridges. Keep host-specific deployment glue optional and documented. Tests should exercise protocol behavior with fake ACP subprocesses and must not require live credentials.

## Rules and their enforcers

A rule without an enforcer is a judgment call for review, not a gate.

| Rule | Enforced by |
|---|---|
| Every file under `tests/` runs in CI via auto-discovery; a hardcoded test-file list in the workflow is forbidden. The only permitted exclusion is an explicit `--ignore` naming why (upstream-venv-only). | Discovery step in `.github/workflows/ci.yml` (`pytest -q tests --ignore=tests/test_upstream_hermes_runtime_contracts.py`); a file missing from a hand list is silently unexercised — class killed 2026-11-01 (12 test files added by merged PRs e60e2a8/918826b and others never ran) |
| The credential-free CI job selects its Python minor from `.python-version`. The separate upstream Hermes compatibility job explicitly requests Python 3.14 and is maintained separately; changes must consider both jobs. | `python-version-file: .python-version` in `ci.yml` job 1; job 2 explicitly uses `uv sync --frozen --python 3.14`. No automated cross-job synchronization is claimed. |
| CI tiers (issues #9/#28): Fast checks are required on every PR and main push. Ordinary main pushes classify a trusted `before`/`after` range by risk: OS lanes are required for install-surface code changes; Extended ARM (Windows ARM64, Linux aarch64) is required for packaging/architecture or unknown changes. Uncertain push metadata/history/diff requires the full matrix. Every `workflow_dispatch` requires all five native platforms; a dispatch with `candidate_sha` additionally requires the exact-candidate-SHA `Release gate`. Change detection may only WIDEN validation; the always-running, stable required `CI gate` fails closed when a scope-required lane failed, was cancelled, skipped, or never reported. Release verification does not grant publication or human approval. | `scripts/ci_change_scope.py` (widen-only classifier), `scripts/ci_gate_check.py` (fail-closed aggregator), `scripts/release_gate_check.py` (exact-SHA verifier), `tests/test_ci_tier_contract.py`, `tests/test_ci_push_scope.py`, `tests/test_release_gate_contract.py` |
