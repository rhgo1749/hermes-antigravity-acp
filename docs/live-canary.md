# Live ACP canary (`scripts/acp_live_canary.py`)

Opt-in, operator-run verification of the real plugin client against an ACP server.
CI runs only credential-free fake ACP subprocesses (`tests/test_acp_live_canary*.py`);
live inference requires separate operator approval and is never automated.

## Engines

| `--engine` | Target | Status |
| --- | --- | --- |
| `replay` | legacy flat client (`client.py`) | frozen default |
| `parked` | Parked-MCP facade (`parked/client.py`, issue #93) | `--mode default` + explicit lane + POSIX `SIGALRM` |

The parked lane imports `parked/client.py` directly, tees ACP stdio via
`AcpConnection`, and drives three same-conversation completions with one
harness-owned MCP tool (`canary_echo`) plus a throwaway cancellation probe.

## Parked verdicts

1. **`model_selection`** — model is discovered via `client._session_model_ids`
   (`configOptions` or `models.availableModels`), selected (`session/set_model` or
   `session/set_config_option`), and accepted without RPC error.
2. **`plain_response`** — non-empty assistant answer.
3. **`parked_tool_round`** — if `canary_echo` is called, the driver returns a
   per-run sentinel (`canary-simulated-result-<hex>`); passes only when the
   sentinel returns in the final answer under one held `session/prompt` with
   `call_<32hex>` ids. Uncalled or unechoed rounds are `inconclusive` (exit 3).
4. **`follow_up_same_session`** — follow-up turn reuses the session without a
   second `session/new`.
5. **`usage_contract`** — checks issue #87 per turn against
   `parked.usage_contract`: each turn's server report (from the raw
   `session/prompt` result) is judged independently — accepted reports must be
   plausible, rejected ones are contract success. An anomalous report
   accepted on ANY turn is `fail` (`anomalous_accepted`); all-accepted
   plausible is `pass` (`plausible`); rejections without any accepted breach
   are `pass` (`anomalous_rejected`); nothing reported is `inconclusive`
   (`unavailable`). `billing_claim: none`.
6. **`containment`** — verifies `disabledTools` prefix on `session/new` matches
   `NATIVE_TOOLS` and fails if any non-MCP `session/request_permission` is
   allowed. (Active native permission refusal is exercised by fake-ACP tests;
   live runs evaluate observable frames only.)
7. **`cancel_path`** — starts a throwaway completion, waits for `session/prompt`,
   calls `client.cancel()`, and confirms `session/cancel` + interruption. A
   completion that finished before `cancel()` could be issued
   (`raced_completion`) is `inconclusive` — the verification opportunity was
   lost, not the cancel contract.
8. **`normal_teardown`** — confirms every direct ACP child spawned during the run
   exited (`[]` → `inconclusive`; unexited child → `fail`). F-3 descendant-tree
   reaping (issue #94) is out of scope (`not asserted`).

## Lanes and usage

- `--fake-acp-only` — credential-free; requires `--command <fake-bin>`, scrubs
  launcher env vars, and refuses resolved paths to the official launcher.
- `--operator-supervised-live` — real inference; requires interactive TTY and
  typing `RUN_ONE_SUPERVISED_CANARY`.
- The parked lane sends only its fixed synthetic prompts and refuses
  `--prompt`/`--follow-up` at preflight (exit 2), so arbitrary user text never
  reaches the evidence files; the replay lane keeps its prompt options.

```sh
uv run --python 3.11 scripts/acp_live_canary.py \
  --mode default --engine parked --fake-acp-only \
  --command /path/to/fake-acp --model <model-id> \
  --cwd /tmp/canary-ws --evidence /tmp/canary-evidence-$(date +%s)
```

- `--timeout` (default 600 s) uses POSIX `SIGALRM` on the main thread (refused
  at preflight with exit 2 where unavailable).
- Evidence (`summary.json`, `frames.jsonl`, `environment.json`) structurally
  redacts `sessionId`, loopback MCP paths, secret JSON fields, and credential
  patterns via `_ParkedRedactor` + `parked._upstream._redact_acp_error_detail`.
- Exit codes: `0` pass, `1` fail / error / timeout, `2` preflight refusal,
  `3` inconclusive.
