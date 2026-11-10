# hermes-antigravity-acp

Standalone integration for Google's official Antigravity ACP server. Keep vendor authentication inside the official ACP runtime; do not extract or reimplement OAuth tokens. Prefer standard ACP JSON-RPC over CLI/TUI scraping or proprietary stream-json bridges. Keep host-specific deployment glue optional and documented. Tests should exercise protocol behavior with fake ACP subprocesses and must not require live credentials.

## Rules and their enforcers

A rule without an enforcer is a judgment call for review, not a gate.

| Rule | Enforced by |
|---|---|
| Every file under `tests/` runs in CI via auto-discovery; a hardcoded test-file list in the workflow is forbidden. The only permitted exclusion is an explicit `--ignore` naming why (upstream-venv-only). | Discovery step in `.github/workflows/ci.yml` (`pytest -q tests --ignore=tests/test_upstream_hermes_runtime_contracts.py`); a file missing from a hand list is silently unexercised — class killed 2026-11-01 (12 test files added by merged PRs e60e2a8/918826b and others never ran) |
| The credential-free CI job selects its Python minor from `.python-version`. The separate upstream Hermes compatibility job explicitly requests Python 3.14 and is maintained separately; changes must consider both jobs. | `python-version-file: .python-version` in `ci.yml` job 1; job 2 explicitly uses `uv sync --frozen --python 3.14`. No automated cross-job synchronization is claimed. |
