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
5. **`usage_contract`** — issue #102 semantics: the contract is that NO
   server-reported consumption sum may surface on a completion. Per turn:
   server reported usage and the engine suppressed it (`completion.usage`
   is `None`) → `pass` (`suppressed`); any completion carrying usage →
   `fail` (`surfaced_consumption_sum`); usage on a completion with no
   server report → `fail` (`invented_usage`); nothing reported at all →
   `inconclusive` (`unavailable`) — an unexercised condition is never a
   PASS. A breach on any turn fails the whole run. `billing_claim: none`.
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
   reaping (issue #94) is not asserted by the live canary (`not asserted`);
   descendant-tree contracts are verified offline by `tests/test_parked_process_tree_native.py`
   and `tests/design_c/` (`test_c_connection.py`, `test_c_conversation.py`).

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
