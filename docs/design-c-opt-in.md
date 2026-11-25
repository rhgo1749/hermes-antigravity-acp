# Design C Opt-In Provider (`antigravity-acp-mcp`)

This document describes the opt-in sibling Hermes model provider at [hermes-plugin/antigravity-acp-mcp](../hermes-plugin/antigravity-acp-mcp), which integrates Google's official Antigravity ACP server (`agy_acp_server 1.5.2`) by parking Hermes tool calls behind a per-session loopback Streamable-HTTP MCP endpoint instead of letting the ACP server run native tools directly.

> **Opt-in status:** `antigravity-acp` remains the repository's default installed provider and is untouched by this integration. `antigravity-acp-mcp` (alias `agy-mcp`) is a separate, opt-in sibling plugin tracked under `#81`.

## Provider Identity and Opt-In Selection

Installing or enabling `hermes-plugin/antigravity-acp-mcp` alongside `hermes-plugin/antigravity-acp` introduces no provider name, alias, or `base_url` collision.

| Attribute | Default provider (`antigravity-acp`) | Opt-in Design C provider (`antigravity-acp-mcp`) |
|---|---|---|
| Plugin directory | `hermes-plugin/antigravity-acp/` | `hermes-plugin/antigravity-acp-mcp/` |
| Manifest name | `antigravity-acp-provider` | `antigravity-acp-mcp-provider` |
| Registered provider name | `antigravity-acp` | `antigravity-acp-mcp` |
| Aliases | `antigravity-cli`, `agy`, `antigravity`, `agy-acp`, `antigravity-official-acp` | `agy-mcp` |
| Marker `base_url` | `acp://antigravity` | `acp://antigravity-mcp` |
| Default launcher | `~/.local/bin/antigravity-acp-official` (`.cmd` on Windows) | `~/.local/bin/antigravity-acp-official` (`.cmd` on Windows), then `PATH` lookup |
| Static `fallback_models` | `()` | `()` |

To opt in manually after installing the official Antigravity ACP launcher (`antigravity-acp-official`), copy the sibling plugin into Hermes' user provider plugin directory and select `antigravity-acp-mcp` (or `agy-mcp`) in Hermes:

```bash
mkdir -p "${HERMES_HOME:-$HOME/.hermes}/plugins/model-providers"
cp -R hermes-plugin/antigravity-acp-mcp \
  "${HERMES_HOME:-$HOME/.hermes}/plugins/model-providers/antigravity-acp-mcp"
```

Runtime launcher resolution checks environment overrides in strict precedence order: explicit `command=` argument, then `HERMES_ANTIGRAVITY_ACP_MCP_COMMAND`, then `HERMES_ANTIGRAVITY_ACP_COMMAND`, then `profile.process_command` (which defaults to the official launcher).

| Environment variable | Scope | Behavior |
|---|---|---|
| `HERMES_ANTIGRAVITY_ACP_MCP_COMMAND` | Launcher override (highest env priority) | Executable path or `PATH` command for the opt-in Design C provider |
| `HERMES_ANTIGRAVITY_ACP_COMMAND` | Shared launcher fallback | Used when `HERMES_ANTIGRAVITY_ACP_MCP_COMMAND` is unset or empty |
| `HERMES_ANTIGRAVITY_ACP_MCP_ARGS` | Launcher arguments | Extra arguments exposed through `ProviderProfile.process_args_env_var` |
| `HERMES_ANTIGRAVITY_ACP_MCP_THINKING_LEVEL` | Thinking level override | One of `low`, `medium`, `high`, `xhigh`; overrides Hermes `reasoning_effort` |

## Security and Isolation Boundaries

Design C keeps tool execution strictly inside Hermes while treating the ACP child process and its stdio streams as untrusted boundaries.

| Boundary | Control implemented in `hermes-plugin/antigravity-acp-mcp/` |
|---|---|
| Loopback MCP transport | `ParkedMcpServer` binds `127.0.0.1:0` (ephemeral port) with a per-session random server name (`hermes-<hex>`), random URL path (`/mcp/<token>`), and 32-byte URL-safe bearer token verified with `hmac.compare_digest`. |
| HTTP request validation | Rejects non-loopback `Host` and `Origin` headers with `403`, wrong paths with `404`, missing/invalid bearer headers with `401`, undeclared tool names with JSON-RPC `-32602`, and oversized bodies (`> 16 MiB`) with `400`. |
| Tool execution containment | `ParkedMcpServer` never executes tools; it suspends `tools/call` until Hermes supplies the tool result. Native ACP tools are disabled via `_meta.antigravity.disabledTools` (measured on `agy_acp_server 1.5.2`) and `clientCapabilities` advertises `fs=False` and `terminal=False`. |
| Permission gate and tripwire | `PermissionGate` allows only `session/request_permission` requests carrying verified `_meta.is_mcp_tool_call == True` for the active session's MCP server name and declared tool set, selecting `allow_once` only (never `allow_always`, never title matching). Running foreign/native `tool_call` updates (`in_progress` / `completed`) trip cancellation and connection teardown. |
| Child environment and cwd | Subprocess env is narrowed through the explicit allowlist in `_upstream._build_subprocess_env` (with profile-scoped XDG directory checks) plus explicit `MUX_ENV_KEYS` only. Each conversation defaults to a dedicated empty `0o700` temporary directory (`tempfile.mkdtemp`). |
| Stderr no-echo | Child stderr is drained into a bounded ring buffer and summarized only via `_acp_stderr_diagnostic` (line/byte count, truncated SHA-256 fingerprint, fixed credential-shape class names) and fixed retry classes; raw stderr bytes never reach exceptions or logs. |
| Redacted JSON-RPC errors | Incoming JSON-RPC `error.message` strings pass through `_redact_acp_error_detail` before constructing `AcpRpcError` (and before bubbling into `ProviderError`), scrubbing OAuth URLs, `Bearer` tokens, secret assignments/query parameters, bare auth codes/tokens, and bare `ya29.` access tokens, and bounding length to 512 characters. |

### M3 ACP-Completion Correlation Boundary

MCP HTTP `tools/call` does not carry ACP `toolCallId`, and `tool_call_update(status="completed")` summarizes `rawOutput` without repeating arguments. Post-completion cache eviction therefore uses a two-layer correlation boundary between `PermissionGate` and `ParkedMcpServer.mark_completed(tool_name, sig_keys)`:

| Layer / Condition | Behavior |
|---|---|
| Layer 1 (`rawInput` present — verified on `agy_acp_server 1.5.2`) | `tool_call` (`pending`), `session/request_permission`, and `tool_call_update` (`in_progress`) carry `toolCallId`, `_meta.mcp.{server, tool}`, and `rawInput` (exact MCP arguments, supporting both wrapped `{"arguments": {...}, ...}` and unwrapped `{...}` shapes). `PermissionGate` binds `toolCallId` to bounded 32-byte SHA-256 signature keys (no raw argument retention, 16 MiB streaming hash cap, 1024-entry map cap, popped on completion). `ParkedMcpServer.mark_completed(tool_name, sig_keys)` evicts only the exact matching signature and never evicts a concurrent same-name sibling with different arguments. |
| Layer 2 (`rawInput` omitted — `sig_keys == ()`) | Single-entry sequential calls with no in-epoch uncached answers (`is_error=True` or `> 8 MiB`) evict immediately. Concurrent same-name calls defer eviction until all same-name siblings (including uncached HTTP-200 answers, with epoch-fenced rollback on HTTP `_send` `OSError`) are accounted for, preventing wrong-sibling eviction on response loss. |
| Residual limitation (`rawInput` omitted + `status="failed"`) | If an ACP server omits `rawInput` and emits `status="failed"` (rather than `completed`) for an in-epoch `isError=True` answer alongside a cached same-name sibling, same-name Layer 2 entries intentionally fail safe by remaining cached until the next `clear_completed()` boundary (next `resume_held` round handoff or prompt end) rather than risking wrong-sibling eviction and double-execution. |
| Residual limitation (`rawInput` omitted + unretried concurrent loss) | If an ACP server omits `rawInput`, runs two concurrent same-name calls where one is lost and never retried, and the model intentionally repeats the succeeded sibling with identical arguments within the same step before `resume_held` or `end_turn`, deferred eviction returns the cached answer until that step boundary. |

## Scope and Known Limitations

> **Notice:** This initial opt-in integration intentionally isolates Design C as a sibling plugin without altering the default provider, installer closure, or existing release gates.

| Item | Current status in this slice | Follow-up tracking |
|---|---|---|
| Wrapper/grandchild process-tree teardown (`F-3`) | `AcpConnection.close()` terminates and kills the direct child PID only (`stdin` EOF -> `terminate()` -> `kill()`), which does not reap grandchildren spawned by intermediate wrapper scripts. | Deferred to a dedicated follow-up PR |
| Lost-response deduplication (`M3`) | Implemented: concurrent duplicate `tools/call` signatures share a parked call while parked, and answered non-error results remain cached for post-completion lost-response retries in a bounded 8 MiB / 32-entry fixed-key (SHA-256) cache with epoch fencing (`clear_completed`), `inflight_sends` delivery tracking, and two-layer ACP-completion correlation (exact SHA-256 signature eviction via `rawInput` on `agy_acp_server 1.5.2`, plus safe deferred batch eviction when `rawInput` is omitted; see M3 ACP-Completion Correlation Boundary above). | Implemented (`#81`, `#82`, `#83`) |
| Regression tracking (`#72`, `#74`, `#77`) | Retained as open regression requirements; this opt-in slice does not close `#72`, `#74`, or `#77`. | Tracked independently on those issues |
| Setup/login/discovery helpers | `setup_status`, `discover_models`, and `login.py` are intentionally omitted from the initial opt-in slice; authentication remains managed by the official ACP runtime (`antigravity-acp-official`). | Handled in subsequent integration slices |
| Upstream Hermes compatibility and default-provider migration | Default `antigravity-acp` installer, catalog floor gate, and any migration path remain unchanged. | Handled separately |
