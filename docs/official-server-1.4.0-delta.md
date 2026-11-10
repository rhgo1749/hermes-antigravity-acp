# Official Antigravity ACP server 1.4.0 behavior notes

This document records version-scoped protocol observations for the official ACP
server. It intentionally omits host paths, account labels, profile inventories,
and deployment outcomes.

## Protocol delta

The registry-pinned 1.4.0 distribution adds the following block to the
`initialize` response; the adapter tolerates it as an additive capability:

```json
{
  "agentCapabilities": {
    "_meta": {
      "antigravity": {
        "systemPrompt": { "append": true },
        "tier": true
      }
    }
  }
}
```

The `session/new` model-catalog shape remains compatible with the ACP client.
The provider passes model identifiers through model listing and session model
selection rather than assuming the catalog is static.

## Adapter invariants

- ACP v1 `session/prompt` does not provide token-usage telemetry to the adapter;
  completions retain `usage=None` rather than fabricating zero-token usage.
- Session continuation and trajectory-limit tracking remain independent of
  provider-client lifetime and are covered by credential-free tests.

## Native image input

- The provider maps active-turn inline image inputs to ACP image content when
  the server advertises image prompt support. It does not fetch remote image
  URLs; non-inline image inputs are left to the caller's normal preprocessing.
- Only images from the active user turn are sent in a prompt. Earlier image
  content remains part of the ACP session rather than being replayed as a new
  current-turn image.

## Permission handling and telemetry

- In the Hermes model-provider lane, Hermes owns tool execution and approval.
  Native ACP tool calls are not treated as Hermes-owned tool calls or globally
  auto-approved.
- The adapter uses only a vetted in-scope native read's offered `allow_once`
  choice. Other permission requests use a server-offered rejection option when
  available; without one, the adapter fails closed rather than inventing an
  option or granting permission.
- Permission telemetry contains bounded outcome metadata and opaque hashes,
  not command bodies, file contents, credentials, or raw permission input.
- The model-provider tool bridge is separate from native ACP tools: Hermes-provided
  function schemas are rendered into the prompt and returned as Hermes tool calls;
  the adapter does not execute them or infer a native web-search catalog. A denied
  `session/update` without `session/request_permission` is reported as a server-side
  pre-tool observation, not a harness permission response. The source and final
  authority of any Google-side predicate remain unverified without a correlated
  live protocol trace. See `web-research-bridge.md` for the bridge status contract.

## Active-request continuity

Credential-free fake-ACP regressions cover replay and continuation after a
denied native action. A denial is not converted into execution or an automatic
retry; the latest user message remains authoritative. These tests establish the
adapter's prompt and permission boundary, not model-level response fidelity or
live service behavior.

## Not verified by these notes

The semantics of the additive `systemPrompt.append` and `tier` capability
fields, future model entitlement/catalog changes, and permission predicates
inside Google's server are not asserted here. Do not infer account access or
production behavior from this protocol summary. The initialize probe and fake
ACP regression tests do not authenticate, send a prompt, or require credentials.

## Tests

Relevant local, credential-free coverage includes
`tests/test_140_client_delta.py`, `tests/test_vision_image_blocks.py`,
`tests/test_fake_acp_e2e.py`, and the permission regression tests. The exact
server-side behavior behind unverified fields remains a separate observation
boundary.
