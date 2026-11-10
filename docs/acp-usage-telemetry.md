# Truthful ACP usage telemetry contract

## Provider boundary

The standalone adapter exposes `antigravity_usage_telemetry` as a response-level
attribute. Streaming `StreamChunks` preserve that attribute through the bridge;
the OpenAI-compatible `usage` field is not widened. `completion.usage` remains
`None` for the current ACP protocol, including when `session/update` carries a
`usage_update`.

Google's official Antigravity ACP 1.4.0 `SessionPromptResult` has no per-request
input/output/cache/reasoning token accounting. Actual billed tokens are therefore
unavailable through the official API. Do not derive billing values from prompt
characters, output length, `native_tokens`, or ACP `usage_update`.

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
    "request_usage": "SessionPromptResult has no per-request token accounting",
    "context_occupancy": "usage_update.used is per-model-call consumption, not billing usage"
  },
  "native_session_id_hash": "sha256:<opaque>",
  "turn_id_hash": "sha256:<opaque>",
  "context_occupancy": null
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
`source="acp.session/update:usage_update"`,
`scope="per_model_call_consumption_delta"`, and `is_billing_usage=false`.
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
`dropped_no_session_identity` (no explicit Hermes session ID at capture time),
or `dropped_no_native_session` (no native session ID to correlate). Frames
that are not candidates are never counted. The counters live additively in
the same state document beside `usage_totals` and never gate the response
path. A store with `frames_seen > 0` but no totals for a session proves the
drop happened after frame delivery; `frames_seen == 0` while the adapter is
known to serve that session proves the adapter build itself predates the
capture code (profile fleet drift — redeploy with
`scripts/deploy_hermes_profiles.py`).
