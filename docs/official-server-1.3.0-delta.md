# Official Antigravity ACP server 1.3.0 — protocol delta

This source-level summary records version-specific ACP behavior relevant to the
generic adapter. It contains no live host, account, profile, or deployment
observations. Gateway and authentication behavior is not asserted without a
credential-free, supported verification surface.

## Changes relevant to the adapter

- The server may emit `usage_update` notifications containing `used` and
  `size`. The adapter tolerates this additive update kind without translating
  it into fabricated completion usage; `usage` remains `None` where the ACP
  response does not provide usage.
- Execution failures may be rendered as ordinary message text, with some
  structured public errors receiving different formatting. The adapter's
  retry policy remains conservative and does not replay uncertain tool actions.
- The `initialize` client identity can affect which model catalog entries the
  server advertises. The provider passes selected model identifiers through
  ACP rather than assuming the catalog is static.
- Subagent-only text updates are excluded from the root response stream.
- Browser-subagent startup recovery may disable a failing browser integration
  for the session and retry the turn within a bounded policy.
- When a proxy is configured, the server's loopback proxy exemption supports
  local harness communication. This does not change generic installer state.

## Preserved adapter contracts

- Session creation, resume, and model configuration continue to use ACP session
  methods; durable continuation is independent of provider-client lifetime.
- Unknown update kinds are tolerated without surfacing protocol metadata as
  user-facing model text.
- The provider preserves truthful `usage=None` completion telemetry when the
  server does not supply billed request usage.
- The 1.3.0 server can emit `usage_update` session updates with `used` and
  `size` context-occupancy fields. The provider records these separately as
  non-billing `context_occupancy`; they never populate request usage or
  `completion.usage`. See `docs/acp-usage-telemetry.md` and
  `tests/test_130_client_delta.py` for the credential-free contract.
- Generic installation does not configure gateway routes, authentication,
  account registries, Hermes user settings, or deployment-specific policy.

## Regression coverage

Credential-free tests cover additive usage-update tolerance, sanitized error
handling, ACP session continuity, and fake-server prompt behavior. See
`tests/test_130_client_delta.py`, `tests/test_fake_acp_e2e.py`, and
`tests/test_standalone_client.py`.

## Not verified here

Real authentication, gateway routing, user entitlement/catalog changes, and
production quota behavior are outside this source-level summary. A protocol
capability or model-catalog response must not be treated as evidence of access
or service availability.