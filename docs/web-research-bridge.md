# Web research through the Hermes tool bridge

## Ownership and supported path

In Hermes model-provider mode, the provider receives OpenAI-style function schemas from Hermes and renders those schemas into the ACP prompt. ACP has no OpenAI `tools` channel, so the model emits a `<tool_call>` envelope and the adapter returns a normal Hermes `tool_calls` response. The adapter does not execute those functions. Hermes remains responsible for its normal tool policy, approval, execution, and result handling; a subsequent provider turn receives the correlated `tool_call_id` and result.

Only a function whose name was present in the current Hermes-supplied schema list can be returned as a Hermes call. An unadvertised or guessed call is rejected before being exposed to Hermes. Native ACP tools are a separate path: native `run_command` is enabled and vetted native coding requests are auto-approved, bypassing Hermes terminal approval. Unknown native web/search permissions remain on the reject-or-cancel fail-closed path.

The bridge currently recognizes the exact Hermes function name `web_search` for the web-research availability status below. Other host-provided function names remain bridged when advertised, but the adapter does not infer that an arbitrary name is a web-search capability. The `web_search` name is not a claim that every Hermes installation exposes that tool or that the official ACP server has a native web tool.

## Observable status and provenance

Each completion carries `antigravity_tool_bridge` with schema ID `antigravity-acp-tool-bridge-v1`. It reports the advertised function names and a bounded list of observed call/result events. Each event includes the tool name, `origin=hermes_tool_bridge`, a one-way hash of the call ID, and a status. Tool arguments, search queries, result contents, URLs, credentials, and prompts are not included in this bridge telemetry.

`web_research_status` describes only adapter-observed bridge state:

- `NOT_AVAILABLE`: no `web_search` schema was advertised and no matching call/result is present in the active request.
- `NOT_ATTEMPTED`: `web_search` was advertised but the model did not emit a matching call/result.
- `PENDING`: the model returned a `web_search` call to Hermes, but the adapter has not yet observed the Hermes tool result.
- `COMPLETED`: an explicit successful Hermes tool result was returned for the call. This is a transport/result status, not independent verification of the source content.
- `RESULT_RECEIVED`: a correlated result arrived without an explicit success or failure status.
- `DENIED`, `CANCELLED`, or `FAILED`: the correlated Hermes result explicitly reports the corresponding outcome.

These states must not be collapsed into a generic “pre-tool hook denied” explanation. `NOT_ATTEMPTED` does not explain why the model did not call a tool. The model prompt instructs the agent to preserve the current research objective, identify the observed limitation, avoid unsupported claims of current-source verification, and cite only sources in a returned tool result. Tool output remains untrusted content; the adapter does not certify its accuracy.

For ACP-native activity, `antigravity_native_activity` preserves bounded status, safe tool name/origin where supplied, and opaque session/turn/call identifiers. Permission telemetry records offered option kinds, selected option kind, decision stage, and outcome. A Google-side pre-tool denial may appear as a failed `session/update` without any `session/request_permission`; a harness permission response is a distinct `harness_permission_response` event. ACP-native search input queries are not copied into activity records or telemetry. If the protocol omits the name or origin, the diagnostic reports `unknown` rather than guessing.

## Troubleshooting

1. Confirm the Hermes host actually supplied the authorized `web_search` function schema to the model-provider request. If not, the adapter reports `NOT_AVAILABLE`; it cannot enable a tool that Hermes did not provide.
2. If the schema is present but the trace is `NOT_ATTEMPTED`, do not attribute the cause to a policy hook without correlated evidence. Review the sanitized user-visible response and model behavior.
3. For `DENIED`, inspect whether the event is from a Hermes tool result, a native ACP permission response, or a server pre-tool failure. A native `server_pre_tool` event has no corresponding harness permission decision unless a separate `session/request_permission` was observed.
4. For `FAILED`, distinguish tool/service/network errors from policy denial using the explicit structured tool result. Do not turn a service failure into a permission claim.
5. Preserve the original research request. If no authorized independent tool is available, say current sources were not verified and leave the objective unresolved rather than substituting stale generalizations or fabricated citations.

## Incident status

A historical report contains user-reported output, not a correlated ACP session/tool trace. The actual tool name and origin, whether a search call was issued, and the denial stage remain **UNVERIFIED**. This implementation adds deterministic fake-ACP coverage for both a pre-tool failure without an ACP permission request and the separate Hermes bridge path; it does not establish which path occurred in the reported live incident.

## Validation, rollout, and rollback evidence

- Credential-free fake ACP tests cover the advertised/callable Hermes web tool, returned result provenance, unavailable and not-attempted states, policy denial, cancellation, service failure, unadvertised-call rejection, native pre-tool denial without a permission request, and fail-closed native permission handling.
- A real-provider canary was **NOT RUN**. It is optional and requires separate explicit authorization, a bounded harmless public query, non-mutating execution, and privacy-safe trace handling. If authorized later, record the exact official server version, advertised host tool name/origin, opaque correlated IDs, observed permission stage/options, and final status; never record the query or returned content in operational logs.
- No production configuration was changed, and no server was deployed or restarted for this change.
- Rollout should begin only after review and operator approval. First verify the Hermes tool schema and run the credential-free tests. If an approved canary exposes a regression, stop the canary and return to the previously pinned provider release using the normal Hermes plugin rollback procedure; do not weaken permission settings, enable generic native shell/MCP/network tools, or modify authentication state. Preserve sanitized evidence for follow-up.

## Test commands

```text
pytest tests/test_fake_acp_e2e.py
pytest tests/test_hotfix_permission_and_read.py
```
