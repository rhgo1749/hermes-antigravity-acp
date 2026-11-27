# ACP stage tracing (issue #26)

Opt-in, privacy-safe request/attempt tracing that explains **where an ACP
request spent time** and **why a turn looked stalled** — without ever
recording conversation content. This is a diagnostic surface, not a retry
policy: it records only events the plugin or the optional mux directly
observes, and records an explicit `unknown` whenever the underlying cause is
not exposed on the public ACP protocol.

## Enable / disable

| Surface | Env | Default |
|---|---|---|
| Plugin | `HERMES_ANTIGRAVITY_ACP_TRACE=1` | off — no file, no writes |
| Plugin trace file | `HERMES_ANTIGRAVITY_ACP_TRACE_FILE` | `<shared Hermes home>/logs/acp-stage-trace.jsonl` |
| Silence heartbeat threshold | `HERMES_ANTIGRAVITY_ACP_TRACE_SILENCE_SECONDS` | `60` (doubles per heartbeat, ≤8 per request) |
| Mux | `ACP_MUX_TRACE=1` | off — no file, no writes |
| Mux trace file | `ACP_MUX_TRACE_FILE` | `<mux control home>/logs/acp-mux-trace.jsonl` |

When the plugin spawns its ACP command (the mux wrapper in mux deployments),
it explicitly propagates `ACP_MUX_TRACE=1` to the child because the child
environment filter strips operator `ACP_MUX_*` keys by design. The mux
started directly by an operator reads its own environment instead.

## Event schema

Plugin trace — one JSONL line per event:

```json
{"t_mono": 12.345, "stage": "prompt_sent", "req_key": "sha256:…", "pid": 4711,
 "detail": {"turn_id_hash": "sha256:…", "requested_model": "unspecified",
            "effective_model": "gemini-3.8-flash", "prompt_text_bytes": 8123}}
```

* `t_mono` — seconds since tracer creation (`time.monotonic`). Never
  wall-clock: no cross-machine joins, no clock-skew corruption.
* `stage` — fixed enum: `initialize`, `session_new_or_resume`, `prompt_sent`,
  `first_update`, `prompt_response`, `cancel_requested`, `process_exit`,
  `response_rejected`, `retry_attempt`, `unknown` (plugin file) and
  `lane_bound`, `process_exit` (mux file).
* `req_key` — ephemeral salted hash. Per-attempt keys join the lifecycle
  stages of one ACP session attempt; `detail.request_key` (one per
  completion call, held in a request-scoped ContextVar — never per client
  instance) joins the attempts and events of one logical request
  (corrections, replays, failovers, and the `cancel_requested` emitted from
  the interrupt thread). A reused client instance therefore never merges
  two calls' events. Keys derive from fresh `uuid4` material:
  never a stable global identifier.
* `pid` — the plugin's direct child pid (the mux pid in mux deployments).
* `detail` — bounded classification only: elapsed ms, byte counts (UTF-8
  encoded, e.g. `prompt_text_bytes`), protocol method names, exit codes,
  requested-vs-effective model ids (ordinary names verbatim; credential- or
  UUID-shaped values are replaced by a request-scoped salted fingerprint
  `opaque:<16hex>` — irreversible and unlinkable across requests, yet
  comparable within the one event holding the pair — or `unrecognized`
  outside any request scope), `stop_reason`
  restricted to the ACP spec enum (`end_turn`, `max_tokens`,
  `max_turn_requests`, `refusal`, `cancelled`) with any other server string
  recorded as `unrecognized` — never verbatim, salted hashes,
  classification enums, explicit `unknown`. Structured values are redacted
  at the emit boundary; strings are truncated.

Mux trace — flat records: `{t_mono, stage, mux_pid, child_pid, lane, reason}`
for `lane_bound` and `{t_mono, stage, mux_pid, child_pid, exit_code}` for
`process_exit`. `lane` is the existing 12-hex lane fingerprint — the raw
account label is never written.

## Joining plugin and mux (optional MUX)

Single mode (no mux): one file, `pid` is the official ACP server itself.

MUX mode: two files. Join `plugin.pid == mux.mux_pid` (the plugin's direct
child is the mux), then `mux.child_pid` identifies the official-server
process and `lane` identifies the account lane without naming it. A
`lane_bound` event therefore answers "which lane served this request" and a
mux `process_exit` answers "did the server process die under us" — both
without any vendor-side claim.

## What each gap looks like

| Symptom | Trace signature |
|---|---|
| Waiting before the first ACP update | `prompt_sent`, then `unknown`/`waiting_for_upstream_no_protocol_events` heartbeats (doubling threshold), then either `first_update` or `unknown`/`deadline_exceeded` |
| Time spent receiving a response | `first_update.elapsed_ms` (time to first token) → `prompt_response.elapsed_ms` minus it (receive/decode), plus `prompt_response.session_updates` chunk count |
| Response rejected by local validation | `response_rejected` with `classification` ∈ `malformed_tool_call`, `orphan_call`, `orphan_result`, `unadvertised_tool`, `correction_exhausted` |
| Repeated / full-replay attempt | `retry_attempt` with `reason` ∈ `frontier_mismatch`, `rotation`, `resume_miss`, `transport_failover`, `malformed_correction` (+ `prompt_bytes` for full replays) |
| Client-requested cancellation | `cancel_requested` (source `hermes_interrupt`) — records **our** action only; vendor compute cancellation is never claimed |
| Local process termination | `process_exit` with `exit_code` and the method being awaited (plugin), mux `process_exit` with `child_pid` |

## The silence rule (what is NOT observable)

The public ACP protocol exposes no vendor retry, capacity (503), or queue
information. A silent wait is byte-for-byte identical whether the vendor is
backing off from capacity errors, the model is slow, or the turn is queued.
The tracer therefore **never** emits or implies `503`, a retry count, or a
queue position from silence — it emits `stage=unknown` with
`vendor_cause=unknown`. Vendor-internal state remains unobservable by
design; only the vendor-owned native session artifacts could ever say more,
and this tool does not read them.

`cancel_requested` likewise records the client-side stop only: whether the
vendor stopped compute is not observable on the public protocol.

## Bounds and retention

* ≤ 64 events per `req_key`, then exactly one `trace_truncated` marker.
* Trace file rotates at 200 KB into a single `.1` sibling (the mux log's
  existing pattern; no `fcntl`, identical behavior on Windows).
* The per-key counter table is capped; a failing write disables the tracer
  for the process lifetime (a trace must never stall or break a request).

## Privacy guarantees

Never recorded anywhere in trace output: prompt or model response text,
OAuth tokens or credentials, raw native session UUIDs (only salted hashes),
raw account labels or identifying account information, private filesystem
paths, or unbounded request history. Correlation identifiers are ephemeral
per attempt/request. The repo's repository-hygiene audit
(`scripts/audit_public_tree.py`) covers the committed trace code like any other
surface, and `tests/test_issue26_stage_trace.py` asserts zero leakage of
marked prompt text, session ids, labels, and paths from real fake-ACP runs.

## Interpretation guide for operators

1. A stalled-looking turn: find its `prompt_sent`; if only heartbeats follow,
   the wait is upstream of the first protocol event — the vendor cause is
   unknown, stop here (do not infer 503). If `first_update` arrived but
   `prompt_response` is late, the time is streaming/decode.
2. A long run with retries: count `retry_attempt` per `request_key` and read
   the `reason`; `response_rejected` tells you which local guard fired.
3. A suspected process death: plugin `process_exit` (with `exit_code`) and,
   in mux mode, the mux `process_exit` for the same pid chain.
4. A user stop: `cancel_requested` proves the stop reached the ACP layer for
   that attempt key.

## Explicitly out of scope

No Hermes Core change (Core already logs its own stall warning), no chat-UI
heartbeat rendering, no vendor HTTP status inference, no changes to retry
budgets, cancellation semantics, account routing, session affinity, or
native bundle GC.
