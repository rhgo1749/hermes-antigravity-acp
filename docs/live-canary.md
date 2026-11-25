# Live ACP canary (`scripts/acp_live_canary.py`)

The canary exercises the **real deployed provider/client** against the
official Antigravity ACP server, outside the Hermes gateway. It is an
opt-in, operator-run tool: CI never runs a live canary, and no test in
this repository reads a credential or calls a model.

## Engines

| `--engine` | Path | Status |
| --- | --- | --- |
| `replay` | legacy flat client (`client.py`) | historical default; behavior frozen, no feature extensions |
| `parked` | deployed Parked-MCP provider/client (`parked/client.py` via its Hermes-facing facade) | issue #93; requires an explicit execution lane |

The parked lane imports the engine from the plugin package exactly as the
gateway does — no mock engine, no protocol re-implementation. ACP stdio is
teed into the frame recorder by wrapping the engine's own `AcpConnection`
at spawn time. The driver speaks only the OpenAI-shaped facade contract
Hermes itself uses.

## What the parked lane verifies

One run performs three same-conversation completions with one harmless,
harness-owned MCP tool (`canary_echo`) advertised:

1. **model selection** — `session/set_model` (or `session/set_config_option`)
   observed for the requested model;
2. **plain response** — a non-empty answer;
3. **parked tool round** — if the model calls `canary_echo`, the driver
   answers the parked call with a canned string (`canary-simulated-result`,
   nothing executes on the host) and asserts the answer is delivered into
   the **same held `session/prompt`** (exactly one prompt request across the
   round) with plugin-minted `call_<32hex>` ids;
4. **follow-up turn** — a second user turn on the same conversation must
   continue without a second `session/new`;
5. **usage contract** — the final turn's server-reported usage as exposed by
   the facade (OpenAI-style `prompt_tokens`/`completion_tokens`/
   `total_tokens`), plus the engine's explicitly-labelled observations and
   the local transcript estimate. Rejections by the shared usage gate
   (issue #87 contract) surface in `engine_log_facts`;
6. **containment** — the `session/new` launch carries the engine's full
   `_meta.antigravity.disabledTools` declaration (native tools, including
   `run_command`, disabled);
7. **normal teardown** — every ACP direct child process is reaped. F-3
   (descendant-tree reaping, issue #94) is explicitly **not asserted**.

## Execution lanes (parked engine)

`--engine parked` refuses to run unless **exactly one** lane flag is given:

- `--fake-acp-only` — credential-free; `--command` must point at a fake ACP
  binary (the official launcher is refused in this lane). This is what CI
  exercises (`tests/test_acp_live_canary_parked.py`).
- `--operator-supervised-live` — real inference. Requires an attended
  interactive terminal **and** typing `RUN_ONE_SUPERVISED_CANARY`. Separate
  human approval per run; never CI.

Authentication for the live lane travels through the engine's own supported
resolution: `HERMES_ANTIGRAVITY_ACP_MCP_COMMAND` (e.g. the operator's MUX
launcher) or the official launcher. The canary never reads, extracts, or
copies credentials; the child environment is the engine's documented
allowlist.

## Running

```sh
# credential-free fake lane (safe; mirrors CI)
uv run --python 3.11 scripts/acp_live_canary.py \
  --mode default --engine parked --fake-acp-only \
  --command /path/to/fake-acp --model <model-id> \
  --cwd /tmp/canary-ws --evidence /tmp/canary-evidence-$(date +%s)

# supervised live lane (operator approval required per run)
uv run --python 3.11 scripts/acp_live_canary.py \
  --mode default --engine parked --operator-supervised-live \
  --model <model-id> \
  --cwd /tmp/canary-ws --evidence /tmp/canary-evidence-$(date +%s)
```

Evidence: `summary.json` (verdicts + facts), `frames.jsonl` (sanitized ACP
frames; the per-run loopback MCP bearer token is redacted),
`environment.json`. Exit codes: `0` no fail verdict (inconclusive verdicts
are reported, not hidden), `1` error or fail verdict, `2` refused
preflight.

## Verdict semantics

- `pass` — the contract was exercised and held.
- `fail` — the contract was exercised and breached (exit 1).
- `inconclusive` — the probe could not be exercised (e.g. the model chose
  not to call the advertised tool, or the server omitted usage). This is
  **not** a pass and **not** a failure; the summary says so explicitly.

## Limits (honest)

- Usage figures are server-reported telemetry gated against the local
  estimate; the canary makes **no billing claim** (`billing_claim: none`).
- Live results depend on model willingness; a run where the model never
  calls the tool leaves `parked_tool_round: inconclusive`.
- F-3 descendant-process reaping (issue #94) is out of scope here and is
  recorded as `not asserted`, never as a pass.
- The engine spawns its ACP child in its own dedicated cwd
  (`acp-mcp-cwd-*`); `--cwd` scopes the canary workspace, not the child.
- macOS Keychain GUI-prompt behaviour is not covered by any test here.
