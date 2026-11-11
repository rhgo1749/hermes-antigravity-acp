# Truthful ACP usage telemetry contract

## Provider boundary

The standalone adapter exposes `antigravity_usage_telemetry` as a response-level
attribute. Streaming `StreamChunks` preserve that attribute through the bridge.
Google's official Antigravity ACP 1.4.0 did not expose the token breakdown in
`SessionPromptResult`. The 1.4.4 server can include `usage` in the completed
`session/prompt` result: the adapter uses this per-turn breakdown in
`completion.usage` when present and valid. `inputTokens` maps to
`prompt_tokens`; `outputTokens` plus `thoughtTokens` maps to `completion_tokens`,
with thoughts also exposed as `completion_tokens_details.reasoning_tokens`.
`totalTokens` is forwarded as reported, and `cachedReadTokens`, when present,
is exposed as `prompt_tokens_details.cached_tokens`. This is server-reported
usage, not an invoice; the server can omit it and excludes subagent usage.
Do not derive billing values from prompt characters, output length, or
`native_tokens`.

When the final result has no valid usage, `completion.usage` stays `None` and
Hermes Core's display-only estimate fallback remains in charge (issue #6
AC4-1). The separate `antigravity_usage_telemetry` attribute still uses
`status="unavailable"` and null `request_usage` buckets; those fields do not
describe the separate `completion.usage` value.

## Issue #6: no fabricated split in `completion.usage`

Earlier builds (v0.7.4–v0.7.8) synthesized `completion.usage` from
`usage_update` frames — latest call as `prompt_tokens`, earlier same-turn
calls as `completion_tokens`. That split was fabricated: the server reports
one undifferentiated per-call consumption number, and pricing it as an
input/output pair corrupted `/usage`, `state.db` stats, and cost views
(issue #6). The synthesis is removed. `completion.usage` is now populated
exclusively from the server's own `session/prompt` result `usage` breakdown.

The official server streams `usage_update` frames whose `used` is the
consumption of the latest model call (per-call, not cumulative; see below).
Observed frames feed two honest surfaces instead:

- `context_occupancy` in the telemetry attribute (latest valid observation,
  non-billing, ungated), and
- `turn_consumption` in the telemetry attribute plus the durable
  `usage_totals` store: the sum of gated per-call deltas observed during the
  turn, explicitly scoped, never priced.

Accumulation (turn sum and durable totals) is gated on three conditions,
each with its own drop counter:

1. **Verified server semantics** — the `initialize` result's `agentInfo`
   `(name, title, version)` must match a source-verified identity whose
   per-call delta semantics were confirmed against server source
   (`server_consumption_semantics: "verified"`). Pinned identities:
   `("antigravity-acp", "Google Antigravity", "1.4.0")` (stage-3 canary
   frames) and `("antigravity-acp", "Google Antigravity", "1.4.4")`
   (credential-free `initialize` against the official binary, enforced by
   `EXPECTED_AGENT_INFO` in `scripts/hosted_clean_room_ci.py`). The server
   reports its own binary version, so each verified release must be pinned
   explicitly; spec-compliant or unknown servers are never summed.
2. **Prompt-turn window** — frames are counted only between sending
   `session/prompt` and receiving its response. This is event-order
   correlation against the adapter's own request, NOT value equality: two
   real calls with identical `used` both accumulate, while a model-switch
   re-report of `last_reported_used` (emitted outside the window with zero
   consumption) is excluded.
3. **Nonzero** — the server's own `_maybe_send_usage_update` never reports a
   zero delta; a zero frame can only be the new-session placeholder. Zero is
   classified by value before the identity and window gates, so a
   placeholder is always `dropped_zero` regardless of server identity.

Known limits, stated so nobody re-reads these numbers as invoices: the server
omits zero-delta frames and excludes subagent calls, so the sum may
under-report; there is no true input/output split; failover-replayed attempts'
frames are not merged into the surfaced turn (the plugin's own usage store
still records them). When no valid frames are observed, `usage` stays `None`
and Hermes' estimate fallback remains in charge — a fabricated zero would
suppress it.

Every completed response uses this JSON-compatible shape:

```json
{
  "schema_id": "antigravity-acp-usage-v1",
  "status": "unavailable",
  "provider": "antigravity-acp",
  "model": "gemini-3.8-flash-high",
  "request_usage": {
    "input_tokens": null,
    "output_tokens": null,
    "cache_read_tokens": null,
    "cache_write_tokens": null,
    "reasoning_tokens": null
  },
  "provenance": {
    "source": "official_acp_v1.4.0",
    "request_usage": "populated in completion.usage ONLY from the server's own session/prompt result usage breakdown; never synthesized from usage_update frames (issue #6 AC4-1)",
    "context_occupancy": "usage_update.used is per-model-call consumption, not billing usage; size is the context window",
    "turn_consumption": "sum of gated per-model-call consumption deltas observed this turn (main-agent-only, may under-report); observed processing, not unique-context size, billed tokens, or account quota"
  },
  "server_consumption_semantics": "verified",
  "native_session_id_hash": "sha256:<opaque>",
  "turn_id_hash": "sha256:<opaque>",
  "context_occupancy": null,
  "turn_consumption": null
}
```

The status vocabulary is `measured`, `estimated`, and `unavailable` for forward
compatibility. This adapter currently emits only `unavailable`; it does not claim
estimated or measured request usage. The model value identifies the requested
model (or `antigravity-acp` when none is supplied).

## Per-model-call consumption deltas and context window

The official server's `usage_update.used` is the consumption delta for the
latest model call, not cumulative native-session context occupancy. `size` is
the context window. The response keeps the existing latest-valid observation
under `context_occupancy`, with
`source="acp.session/update:usage_update"` and `is_billing_usage=false`.
The `scope` label states the reading's MEANING, which depends on the server's
semantics: `per_model_call_consumption_delta` only for a source-verified
identity; `unverified_server_semantics` for everything else (the value is
retained as an opaque observation whose meaning this adapter has not
verified).
Only numeric, finite, nonnegative `used`/`size` values are retained for this
response field; booleans, strings, negative values, NaN, and infinities are
invalid. A frame carrying any present-but-invalid field is rejected as a whole
for occupancy, so a corrupt frame never contributes its otherwise-valid
sibling. Valid frames merge field-wise into the active prompt turn's latest
valid observation; malformed later frames never erase it, and a valid partial
frame updates only the fields it carries. An observation from an aborted
attempt is not carried into the next response. If no valid update is observed,
the field is `null`.

Separately, every observed `usage_update` with a valid nonnegative `used` value
is added to a durable per-Hermes-session total in
`cache/antigravity-acp-sessions.json`, under the additive top-level `usage_totals`
key. The key is only the explicit Hermes session ID from
`hermes_compat.get_runtime_session_env()` (its first return value); if that ID
is absent or empty, the adapter does not guess an identity and does not create
a totals entry. Each entry uses schema `antigravity-acp-usage-totals-v1` and
records the Hermes session ID, `summed_tokens` across all observed model calls,
`by_model` token totals keyed by model name, and `model` only when the aggregate
contains exactly one attributable model (it is `null` for mixed-model or
unattributed totals). For a legacy multi-frame scalar total that cannot be
reconstructed safely, the prior sum is retained under the reserved
`by_model.__unattributed__` bucket rather than being assigned to the latest
model. Entries also record `frames_observed`, numeric Unix-second
`first_seen`/`last_seen` timestamps, an opaque SHA-256 hash of the native ACP
session ID, and exact provenance
`acp.usage_update.delta_sum(main-agent-only, may under-report)`. The existing
`states` structure and store version remain unchanged and readable; totals
updates use the same atomic replace strategy. No entry is created before the
first observed valid frame.

The official server intentionally omits or loses some calls: zero-delta frames
are omitted; a cumulative-decrease re-anchor skips a call; an unknown context
window suppresses a frame; and subagent usage is excluded. These are known
under-reporting limits, not grounds for estimation. The stored sum is therefore
only the sum of valid updates actually observed by this main-agent adapter.
Replay, resume, tool-use continuations, retry/failover, and proactive rotation
do not convert history into request billing usage. `native_tokens` remains an
adapter-side context-rotation estimate only. An interrupted/partial turn does
not return a completed response telemetry object.

The native ACP session ID and per-prompt turn correlation are SHA-256 opaque
hashes only. The response does not contain prompt text, raw native IDs, account
credentials, quota endpoints, or vendor payloads.

## Downstream ownership and correlation

This repository owns only the provider-boundary attribute and the fake-ACP
contract tests. It does not change or deploy Hermes Core, Hermes GitHub Kanban
(HGK), installed PAR files, user profiles, databases, or running services.

- Hermes Core owns extraction and persistence of the response-level metadata.
  It must preserve provider/model identity and an explicit unavailable status
  rather than normalize missing request usage to numeric zero. It should attach
  the active profile/account-home context from Core's execution context, not
  infer it from this adapter payload.
- HGK owns reporting. It should consume the explicit status, exclude
  `unavailable` from numeric token totals, and render it as unavailable rather
  than treating a sessions-table default zero/NULL provider as known
  `unknown/<model>: 0` usage. Context occupancy may be displayed separately and
  must not enter billing totals.
- The adapter supplies provider/model plus opaque ACP session/turn correlations.
  Core/HGK own profile, board, task, run, and worker-session attribution from the
  scheduler/worker execution context. Those IDs are not inferable from ACP's
  prompt protocol and must not be fabricated by the provider.

`tests/fixtures/acp-usage-hgk-boundary.json` is a sanitized, reproducible boundary
example: `usage=null` and no per-model usage rows coexist with a sessions row
whose default input/output values are zero and provider is NULL; the current HGK
fallback can consequently project `unknown/gemini-3.8-flash-high: 0`. The hashes
in that fixture are synthetic placeholders. It documents the observed Core/HGK
seam; its fixture-shape test is not an execution test of Core or HGK. Their
owners must add the executable persistence/reporting regressions in their own
repositories.

The observed 173 `worker_session_id`-missing runs are a separate
run-attribution diagnostic class. They are not evidence of zero usage and are
not caused by ACP's lack of request usage. Core/HGK owners should resolve that
attribution class independently; this harness change does not alter it.

## Credential-free validation and bounded canary

Run the protocol regressions without Google credentials:

```sh
python -m pytest -q \
  tests/test_130_client_delta.py \
  tests/test_fake_acp_e2e.py \
  tests/test_121_client_stabilization.py \
  tests/test_usage_telemetry_contract.py
```

A live credentialed ACP canary is not authorized by this delivery. Once the
Core/HGK owner seams are implemented and separately approved, a bounded canary
plan is: run one isolated Antigravity worker turn; inspect only the status,
provider/model, opaque correlation hashes, and whether the result is measured,
explicitly estimated, or unavailable; verify HGK excludes unavailable values
from known token totals; then stop. Do not log prompts, credentials, raw native
session IDs, or vendor payloads. This plan is not an authorization to deploy,
query production databases, or run the canary now.

## Fleet diagnostics: `usage_drop_counters`

Every `usage_update` frame that carries a `used` value is a usage-delta
candidate. Each candidate increments `usage_drop_counters.frames_seen`; a
candidate rejected before `add_usage_delta` increments exactly one reason
counter: `dropped_invalid` (malformed value or missing activity stats),
`dropped_semantics_unverified` (server identity not in the source-verified
set), `dropped_outside_prompt_turn` (frame observed outside the adapter's own
in-flight `session/prompt` window — model-switch re-reports, session-init
placeholders, late-drained frames), `dropped_zero` (zero-value placeholder),
`dropped_no_session_identity` (no explicit Hermes session ID at capture time),
or `dropped_no_native_session` (no native session ID to correlate). Frames
that are not candidates are never counted. The counters live additively in
the same state document beside `usage_totals` and never gate the response
path. A store with `frames_seen > 0` but no totals for a session proves the
drop happened after frame delivery; `frames_seen == 0` while the adapter is
known to serve that session proves the adapter build itself predates the
capture code (profile fleet drift — redeploy with
`scripts/deploy_hermes_profiles.py`).
