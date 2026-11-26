# Truthful ACP usage telemetry contract

## The contract (issue #102)

`completion.usage` is **always `None`** in both engines (Replay and
Parked-MCP). Hermes Core treats `completion.usage.prompt_tokens` as the
authoritative single-request context occupancy: `normalize_usage` reconstructs
`prompt_tokens = input + cache_read + cache_write`, the value seeds the usage
anchor (`agent/usage_anchor.py`), and the anchored figure is never deferred by
the preflight-compaction gate (`agent/turn_context.py::_preflight_request_tokens`).
The ACP `session/prompt` result `usage` is a per-turn **consumption sum** over
the server's internal model calls — `cachedReadTokens` accumulates each hop's
cached prefix — and is never a verified single-request occupancy reading. No
field on the current ACP surface is one. Pinning `completion.usage=None` routes
Core to its designed local-estimate fallback (`estimate_request_tokens_rough`),
and normal context compaction keeps working off the adapter's transcript.

The rule is semantic, not numeric: no magnitude gate can make a consumption sum
safe as an occupancy anchor. The decision is hardcoded in both engines
(`parked/client.py::_completion`, `client.py` prompt-result handling); there is
no eligibility flag, no configuration, and no compatibility layer. If a future
ACP surface ever exposes a verified occupancy source, admitting it is a design
change to `parked/usage_contract.py` first — never a local engine fork.

### Why: the 2026-11-26 production samples (anonymized S1–S4)

The server's per-turn `cachedReadTokens` reached 861,529 against a ~57K durable
transcript (15x) and 6.03M against ~140K (43x). The cache bucket alone seeded
anchors up to 1.09M against a 1,048,576 window, firing premature compactions
while the real transcript was small. S4's shape defeats every magnitude gate:
`inputTokens≈0` passes growth gates and 861,529 passes any window cap — the
inflation mode moves the mass into the ungated field. This is why #6, #87 and
#99 (plausibility, 8x growth, window cap) each passed CI and still lost: they
policed a channel that must not exist.

## Retired machinery (issue #102 debt cleanup)

With `completion.usage` pinned to `None`, the following are removed from both
engines (not dormant — deleted; history lives in git):

- the 8x growth-consistency gate and its tolerance constants (#87/#6);
- the first-turn plausibility gate (#87);
- the active-model context-window cap and its per-model limit tracking (#99);
- per-conversation `(reported, local)` baseline storage;
- the machine-wide consumption-semantics **verdict** store, `agentInfo`
  identity extraction, and `server_consumption_semantics` telemetry key (#6);
- the drop counters `dropped_semantics_unverified` and
  `dropped_inflated_turn_usage`;
- the prompt-result usage parser (`_turn_usage_from_prompt_result` /
  `_consumption_from_prompt_result`) — the breakdown is no longer parsed at all.

## What consumption telemetry still exists (and what it does NOT claim)

`usage_update` frames remain visible as explicitly-scoped, non-billing
telemetry. Nothing here is an invoice, a quota reading, or a context-occupancy
claim; the scope label is the static `unverified_server_semantics` for every
identity (the behavioral-verdict ladder that used to promote it is retired):

### Two different data classes — what is kept, what is lost

- **Prompt-result usage** (the `usage` object inside the `session/prompt`
  RESULT: `inputTokens`/`outputTokens`/`thoughtTokens`/`cachedReadTokens`/
  `totalTokens`) is DISCARDED by both engines: only `stopReason` is read from
  the result; the numeric breakdown is parsed nowhere, stored nowhere, and
  exported nowhere (the parked engine's former parser was deleted as dead
  code with #102). This is the cumulative-consumption class that poisoned
  Core's occupancy anchor (S1–S4); its loss is intentional and it must never
  be re-admitted into any path reaching `completion.usage`.
- **`usage_update` frames** (per-model-call `used`/`size` observations
  streamed as `session/update` notifications) are KEPT, per engine:
  - Replay: `context_occupancy` + `turn_consumption` on the completion's
    `antigravity_usage_telemetry` attribute, plus durable `usage_totals` in
    `cache/antigravity-acp-sessions.json` (below).
  - Parked-MCP: the completion's `antigravity_usage_observations` attribute
    (latest occupancy reading plus frame token fields), explicitly
    unverified; nothing is persisted to disk by the parked engine.
- **Core `/usage` and downstream token statistics**: because
  `completion.usage` is `None`, Core's `record_response_usage` takes its
  usage-less path and records NO per-model usage rows for ACP turns; session
  token totals stay at their schema defaults. `/usage` and any report built
  on those rows therefore show zero token consumption for ACP sessions —
  honestly zero, where before #102 they carried inflated sums (S2: 6.03M
  cache-read tokens on a ~140K-token transcript). Rendering "this provider
  reports no billing usage" distinctly from "this session consumed nothing"
  is a downstream reporting concern, not a provider-boundary one (see
  Downstream ownership).

No new telemetry system was introduced: every kept field rides the
pre-existing attributes and state file above.

- `context_occupancy` in `antigravity_usage_telemetry`: the latest valid
  in-turn frame reading (`used`/`size`), `is_billing_usage: false`.
- `turn_consumption`: sum of valid nonzero frames observed inside the
  adapter's own in-flight `session/prompt` window, this turn.
- durable `usage_totals` in `cache/antigravity-acp-sessions.json`:
  per-Hermes-session sums keyed ONLY by the explicit Hermes session ID
  (never guessed; absent ID → no entry). Schema
  `antigravity-acp-usage-totals-v1` with `summed_tokens`, `by_model`,
  `frames_observed`, timestamps, opaque native-session hash, and provenance
  `acp.usage_update.delta_sum(main-agent-only, may under-report, semantics
  unverified)`.

Accumulation is gated on structural lifecycle only, each rejection naming
itself in `usage_drop_counters`: whole-frame validity (`dropped_invalid`),
prompt-turn window (`dropped_outside_prompt_turn` — model-switch re-reports
and session-init placeholders land here), zero placeholders (`dropped_zero`),
missing identities (`dropped_no_session_identity`, `dropped_no_native_session`).
Frames are protocol-validated once in `parked/usage_contract.py`
(`usage_update_valid`, `nonnegative_usage_number`) — the single owner shared by
both engines; neither engine may re-bind these names (AST-enforced in
`tests/test_usage_contract_single_owner.py`).

Known limits: the server omits zero-delta frames and excludes subagent calls,
so sums may under-report; there is no input/output split; failover-replayed
attempts' frames are not merged into the surfaced turn. When no valid frame is
observed the fields are `null` — a fabricated zero would suppress Core's
estimate, so it is never emitted.

Telemetry shape (all-null `request_usage` is the steady state, by contract):

```json
{
  "schema_id": "antigravity-acp-usage-v1",
  "status": "unavailable",
  "provider": "antigravity-acp",
  "model": "<requested model>",
  "request_usage": {
    "input_tokens": null, "output_tokens": null, "cache_read_tokens": null,
    "cache_write_tokens": null, "reasoning_tokens": null
  },
  "native_session_id_hash": "sha256:<opaque>",
  "turn_id_hash": "sha256:<opaque>",
  "context_occupancy": null,
  "turn_consumption": null
}
```

The native ACP session ID and per-turn correlation are SHA-256 opaque hashes
only. No prompt text, raw native IDs, credentials, or vendor payloads.

## Existing-anchor lifecycle (operational note)

`completion.usage=None` prevents NEW anchors only. An in-memory
`agent._usage_anchor` captured before this fix is NOT cleared by usage-less
responses (Core's usage-less path never touches it) and keeps matching while
the transcript prefix is stable. Already-tainted live sessions therefore need
a gateway/process restart (or a natural re-anchor) at rollout — no silent
database rewrite is performed. This is pinned by
`test_tainted_anchor_persists_through_real_usage_less_recording` in the
upstream lane, which drives Core's real `record_response_usage` for both the
poisoning turn and the later usage-less turns.

## Validation strategy: CI vs live canary

CI PASS is not equivalent to "the production outage is solved"; the layers and
their honest limits are recorded here so nobody re-conflates them.

### CI (credential-free, every PR — no new workflows)

- Engine contract (both engines + stateless `llm_backend`):
  `tests/test_130_client_delta.py`, `tests/test_fake_acp_e2e.py` (incl. the
  S4-shaped e2e), `tests/design_c/test_c_usage_semantics.py`,
  `tests/test_llm_backend_policy_e2e.py`, `tests/test_121_client_stabilization.py`.
  These prove: no `completion.usage` on ANY server-reported shape (plausible,
  inflated, S4, malformed), consumption telemetry survives with the honest
  scope, and no gate state exists (`RETIRED_NAMES` removal pin in
  `tests/test_usage_contract_single_owner.py`).
- Core boundary (upstream-compatibility job, unmodified Hermes):
  `tests/test_upstream_hermes_runtime_contracts.py` — S1–S4 regressions and
  C1/C2 controls run through Core's real
  `capture_usage_anchor` / `anchored_context_tokens` /
  `_preflight_request_tokens`. The RED witness replays the exact production
  payload at the boundary (old shape ⇒ ~15x inflated occupancy); the GREEN
  test drives the REAL plugin client against an S4 fake server and asserts the
  completion fails Core's usage-ingestion gate so the anchor is never seeded;
  C1/C2 assert needed compaction still sees the true transcript size with and
  without a valid anchor.
- Red→Green evidence: the new contract tests fail against `c52bc8e` (pre-fix)
  — verified in a throwaway worktree — and pass on this branch.

### Live credentialed canary (`scripts/acp_live_canary.py --parked-mcp`)

The canary is a SMOKE + semantic-regression lane against the real server, not
an endurance test:

- Smoke: connection, model selection, plain response, one parked MCP tool
  round with sentinel delivery, same-session follow-up, cancellation,
  direct-child teardown.
- Semantic regression (`usage_contract` verdict): for EVERY judged turn, the
  server's actual prompt-result usage is read off the wire and the engine's
  surfaced `completion.usage` is inspected. Server reported + engine
  suppressed → `suppressed` PASS. Engine surfaced the sum (or invented usage)
  → FAIL, exactly reproducing the production breach shape. Server never
  reported usage → `unavailable` = NOT OBSERVED (inconclusive) — never a PASS.
- NOT covered by the canary (CI-only or unverified): long multi-hour
  endurance, real Core-side compaction decisions in the canary process, and
  anchor lifecycle across restarts. Treat those as NOT RUN unless separately
  executed.

## Downstream ownership

This repository owns only the provider-boundary attribute and the fake-ACP
contract tests. It does not change or deploy Hermes Core, installed PAR
files, user profiles, databases, or running services.

- Hermes Core owns extraction and persistence of the response-level
  metadata. It must preserve provider/model identity and an explicit
  unavailable status rather than normalize missing request usage to numeric
  zero, and it owns how its own usage recording, session rows, and reporting
  surfaces interpret a provider that reports no billing usage.
- The adapter supplies provider/model plus opaque ACP session/turn
  correlations. Downstream attribution (profiles, tasks, runs, worker
  sessions) comes from the caller's execution context; those IDs are not
  inferable from ACP's prompt protocol and must not be fabricated here.

Downstream consumers that need persistence or reporting regressions for the
"provider reports no billing usage" case must add executable tests in their
own repositories; this repository pins only the provider-side boundary.

## Credential-free quick run

```sh
python -m pytest -q \
  tests/test_130_client_delta.py \
  tests/test_fake_acp_e2e.py \
  tests/test_121_client_stabilization.py \
  tests/test_usage_telemetry_contract.py \
  tests/test_usage_contract_single_owner.py
```

The upstream-boundary file runs only in the upstream-compatibility job
against an installed official Hermes checkout.
