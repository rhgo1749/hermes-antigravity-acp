# Official Antigravity ACP server 1.2.1 — protocol contract

This version-scoped summary records protocol behavior relevant to the generic
ACP adapter. It is based on source review and credential-free protocol tests;
it does not record live host, account, profile, or deployment state.

## Request and session behavior

- The server uses ACP v1 JSON-RPC over stdio. Session creation, resume, and
  prompt responses are handled as ACP protocol messages; a missing resumable
  session is a distinct error and does not imply a safe full replay.
- The server can merge its own global MCP configuration during session setup.
  An empty client-supplied MCP list is not a guarantee that server-side MCP
  integrations are disabled.
- `_meta.agy.disabledTools` applies to the server's built-in tools; it is not a
  universal permission boundary for server-configured MCP tools or client-side
  tools. Integrations must enforce their own explicit permission policy.
- Quota and connection-loss conditions may be represented in-band rather than
  as a JSON-RPC error. The adapter treats these cases conservatively and does
  not retry an action whose completion is uncertain.
- Version 1.2.1 does not provide token-usage updates to the adapter. Completion
  telemetry remains `usage=None`; the provider must not invent zero-token or
  estimated server usage.

## Authentication and configuration boundary

An `initialize` response may advertise authentication methods, but that alone
does not establish that a method is permitted for a particular user or client.
The generic installer only installs the official server and provider code; it
does not initiate authentication or change user-managed server settings.
Gateway and account-specific behavior is outside this adapter contract.

## Regression coverage

Credential-free fake-server tests cover ACP initialization, session behavior,
in-band errors, tool permission handling, and truthful usage reporting. The
tests do not authenticate or contact a live account. Relevant coverage includes
`tests/test_fake_acp_e2e.py`, `tests/test_standalone_client.py`, and the
version-specific client tests.

## Not verified here

Live authentication, user entitlements, gateway routing, and production quota
behavior are not asserted. A protocol advertisement or an unauthenticated
initialize probe must not be treated as evidence of account access or service
availability.