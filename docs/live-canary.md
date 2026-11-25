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

One run drives three same-conversation completions with one harmless,
harness-owned MCP tool (`canary_echo`) advertised, plus two active probes.
Each has its own verdict; none is folded into another:

1. **`model_selection`** — the server must *advertise* the requested model
   id in `session/new`, the engine must send an *exact* selection request
   (`session/set_model` / `session/set_config_option`), and the server must
   answer it without an error. A selection request that errored is a `fail`,
   never a pass-by-existence.
2. **`plain_response`** — a non-empty answer.
3. **`parked_tool_round`** — if the model calls `canary_echo`, the driver
   answers the parked call with a canned, per-run-unique sentinel
   (`canary-simulated-result-<hex>`; nothing executes on the host). The
   round only **passes** when the sentinel is echoed back in the model's
   answer (proof the result was delivered to the model), inside the **same
   held `session/prompt`** (exactly one prompt request across the round),
   with plugin-minted `call_<32hex>` ids. A non-empty answer without the
   sentinel is `inconclusive`, never a pass.
4. **`follow_up_same_session`** — a second user turn on the same
   conversation continues without a second `session/new`.
5. **`usage_contract`** — the final turn's server-reported usage as exposed
   by the facade, gated by the shared usage contract (issue #87): a usage
   report the engine rejects (gate rejection in `engine_log_facts`, no
   usage on the completion) is a **fail** — the contract was exercised and
   breached. Present-but-plausible usage is a pass of the *reporting
   contract only*; the canary never claims billing accuracy.
6. **`containment_declaration`** — the `session/new` launch carries the
   engine's full `_meta.antigravity.disabledTools` declaration (all native
   tools, including `run_command`). The evidence recording is
   sanitizer-capped at 40 entries, so the summary checks the recorded
   prefix; the credential-free test compares the fake's raw request against
   the engine's `NATIVE_TOOLS` source list.
7. **`native_tool_execution_blocked`** — *enforcement*, separate from the
   declaration above: the fake sends a `session/request_permission` for a
   native tool (`run_command`) and the verdict requires the **engine's own
   permission gate to refuse it**.
8. **`cancel_path`** — the canary starts a throwaway completion on its own
   conversation, waits for the engine to actually issue the
   `session/prompt`, then calls `cancel()`. Pass requires both the
   vendor-visible `session/cancel` notification and the request being
   interrupted (not completing normally).
9. **`normal_teardown`** — every ACP direct child **this run spawned**
   (including children of retired conversations) is confirmed exited after
   the canary cancels in-flight work and closes the engine. A child that
   does not exit is a `fail`; only a run that spawned no observable child
   is `inconclusive`. F-3 (descendant-tree reaping, issue #94) is
   explicitly **not asserted**.

## Execution lanes (parked engine)

`--engine parked` refuses to run unless **exactly one** lane flag is given:

- `--fake-acp-only` — credential-free; an **explicit `--command` fake ACP
  binary is mandatory**. For the run, the engine's own resolution
  environment (`HERMES_ANTIGRAVITY_ACP_MCP_COMMAND`,
  `HERMES_ANTIGRAVITY_ACP_COMMAND`) is removed and restored afterwards, so
  the lane can never implicitly reach a real launcher, MUX configuration,
  authentication or inference; the command is additionally refused when it
  *resolves* (`realpath`, symlink-safe) to the official launcher. This is
  what CI exercises (`tests/test_acp_live_canary_parked.py`).
- `--operator-supervised-live` — real inference. Requires an attended
  interactive terminal **and** typing `RUN_ONE_SUPERVISED_CANARY`. Separate
  human approval per run; never CI.

Authentication for the live lane travels through the engine's own supported
resolution: `HERMES_ANTIGRAVITY_ACP_MCP_COMMAND` (e.g. the operator's MUX
launcher) or the official launcher. The canary never reads, extracts, or
copies credentials; the child environment is the engine's documented
allowlist.

For both parked lanes the canary scrubs `HERMES_SESSION_KEY` /
`HERMES_SESSION_ID` for the duration of the run: the canary is a standalone
client, not a Hermes conversation, and inside a Hermes-hosted process the
engine would otherwise collapse every canary probe onto one shared native
session.

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

`--timeout` (default 600 s) bounds the whole parked run on wall-clock
time. On timeout or any exception the canary still cancels in-flight
engine work, closes the client, reaps every child it spawned, and writes
the evidence before exiting.

Evidence: `summary.json` (per-check verdicts, `overall`, facts),
`frames.jsonl` (sanitized ACP frames), `environment.json`. Redaction in
every evidence file and log line: per-run session ids are replaced by
stable `sess_<hash>` placeholders, the loopback MCP bearer token and any
`Bearer`/`access_token`-shaped server content become placeholders, and the
loopback MCP URL's secret path component becomes `<path-redacted>`.

## Overall verdict and exit codes

`overall` is `fail` if any verdict is `fail` (or the run errored),
otherwise `inconclusive` if any verdict is `inconclusive`, otherwise
`pass`.

| exit | meaning |
| --- | --- |
| `0` | every check passed (`overall: pass`) |
| `1` | a check failed, the run errored, or `--timeout` fired |
| `2` | refused preflight (lane misuse, official launcher in the fake lane, raw-probe mode with the parked engine) |
| `3` | no failure, but at least one required check was `inconclusive` — the contract was **not** fully verified |

## Verdict semantics

- `pass` — the contract was exercised and held.
- `fail` — the contract was exercised and breached (exit 1).
- `inconclusive` — the probe could not be exercised (e.g. the model chose
  not to call the advertised tool, or usage was never reported). This is
  **not** a pass and **not** a failure; the overall verdict and exit code 3
  say the verification was incomplete.

## Limits (honest)

- Usage figures are server-reported telemetry gated against the local
  estimate; the canary makes **no billing claim** (`billing_claim: none`).
- Live results depend on model willingness; a run where the model never
  calls the tool leaves `parked_tool_round: inconclusive` (exit 3), which
  is a correct "not verified" result, not a failure of the engine.
- F-3 descendant-process reaping (issue #94) is out of scope here and is
  recorded as `not asserted`, never as a pass.
- The engine spawns its ACP child in its own dedicated cwd
  (`acp-mcp-cwd-*`); `--cwd` scopes the canary workspace, not the child.
- macOS Keychain GUI-prompt behaviour is not covered by any test here.
