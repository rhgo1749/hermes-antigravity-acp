# Parked-MCP Engine (Design C) — default since plugin 0.9.0

This document specifies the Parked-MCP execution engine at [hermes-plugin/antigravity-acp/parked](../hermes-plugin/antigravity-acp/parked), which integrates Google's official Antigravity ACP server (`agy_acp_server 1.5.2`) by parking Hermes tool calls behind a per-session loopback Streamable-HTTP MCP endpoint instead of letting the ACP server run native tools directly.

> **Status (0.9.0):** this engine is the **default** behind the public `antigravity-acp` provider id and the compatibility id `antigravity-acp-mcp` (alias `agy-mcp`). It was developed as the opt-in sibling plugin `hermes-plugin/antigravity-acp-mcp` (authored by Nanako0129, MIT-licensed; issues #81/#82/#83) and moved into `parked/` when it became the default. The pre-0.9.0 default remains fully selectable as `antigravity-acp-replay`; it is not deprecated. Engine choice is by provider id only — see [README "Engines"](../README.md#engines-parked-mcp-default-and-replay-selectable).

## Provider Identity and Engine Selection

One plugin package registers three disjoint model-provider profiles; there is no provider name, alias, or `base_url` collision between them.

| Attribute | Parked-MCP default (`antigravity-acp`) | Parked-MCP compatibility (`antigravity-acp-mcp`) | Replay engine (`antigravity-acp-replay`) |
|---|---|---|---|
| Plugin directory | `hermes-plugin/antigravity-acp/` | same package | same package |
| Engine source | `parked/` subpackage | same `parked/` subpackage | parent flat modules (`client.py` et al.) |
| Registered provider name | `antigravity-acp` | `antigravity-acp-mcp` | `antigravity-acp-replay` |
| Aliases | `antigravity-cli`, `agy`, `antigravity`, `agy-acp`, `antigravity-official-acp` | `agy-mcp` | (none) |
| Marker `base_url` | `acp://antigravity` | `acp://antigravity-mcp` | `acp://antigravity` |
| Default launcher | `~/.local/bin/antigravity-acp-official` (`.cmd` on Windows), then `PATH` lookup | same | same |
| Static `fallback_models` | `()` | `()` | `()` |

Selecting the engine is a profile-config change only:

```yaml
# Parked-MCP (default; also what pre-0.9.0 `antigravity-acp-mcp` configs resolve to)
model:
  provider: antigravity-acp
# Explicit Replay engine alternative
model:
  provider: antigravity-acp-replay
```

There is no automatic engine fallback in any failure mode: neither engine ever retries a side-effecting tool execution on the other.

Runtime launcher resolution checks environment overrides in strict precedence order: explicit `command=` argument, then `HERMES_ANTIGRAVITY_ACP_MCP_COMMAND`, then `HERMES_ANTIGRAVITY_ACP_COMMAND`, then `profile.process_command` (which defaults to the official launcher).

| Environment variable | Scope | Behavior |
|---|---|---|
| `HERMES_ANTIGRAVITY_ACP_MCP_COMMAND` | Launcher override (highest env priority) | Executable path or `PATH` command for the Parked-MCP profiles |
| `HERMES_ANTIGRAVITY_ACP_COMMAND` | Shared launcher fallback | Used when `HERMES_ANTIGRAVITY_ACP_MCP_COMMAND` is unset or empty |
| `HERMES_ANTIGRAVITY_ACP_MCP_ARGS` | Launcher arguments | Extra arguments exposed through `ProviderProfile.process_args_env_var` |
| `HERMES_ANTIGRAVITY_ACP_MCP_THINKING_LEVEL` | Thinking level override | One of `low`, `medium`, `high`, `xhigh`; overrides Hermes `reasoning_effort` |
| `HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS` | Live model-discovery cache TTL | Bounds the `session/new` model-surface probe cache |

## Security and Isolation Boundaries

Design C keeps tool execution strictly inside Hermes while treating the ACP child process and its stdio streams as untrusted boundaries.

| Boundary | Control implemented in `hermes-plugin/antigravity-acp/parked/` |
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

> **Notice (0.9.0):** this engine is now the default behind `antigravity-acp` / `antigravity-acp-mcp`; the installer deploys one plugin package containing both engines. The items below describe the engine's current contracts.

| Item | Current status | Follow-up tracking |
|---|---|---|
| Wrapper/grandchild process-tree teardown (`F-3`) | `AcpConnection.close()` terminates and kills the direct child PID only (`stdin` EOF -> `terminate()` -> `kill()`), which does not reap grandchildren spawned by intermediate wrapper scripts. **Assessed non-blocking for the default switch:** the default topology launches the official server directly (no wrapper), and under the optional MUX the lane children are MUX-daemon-owned by design (session affinity across turns), not orphans of the plugin child. | Deferred to a dedicated follow-up PR |
| Lost-response deduplication (`M3`) | Implemented: concurrent duplicate `tools/call` signatures share a parked call while parked, and answered non-error results remain cached for post-completion lost-response retries in a bounded 8 MiB / 32-entry fixed-key (SHA-256) cache with epoch fencing (`clear_completed`), `inflight_sends` delivery tracking, and two-layer ACP-completion correlation (exact SHA-256 signature eviction via `rawInput` on `agy_acp_server 1.5.2`, plus safe deferred batch eviction when `rawInput` is omitted; see M3 ACP-completion Correlation Boundary above). | Implemented (`#81`, `#82`, `#83`) |
| Replay-engine failure modes (`#72`, `#74`, `#77`) | The Parked-MCP engine has no frontier-replay path: one prompt per turn with delta continuation sends, per-call UUID tool ids, and no per-hop cold respawn (`test_two_hop_turn_is_one_prompt_then_continue_sends_only_the_delta` and the `tests/design_c/` suite pin these). The issues themselves track the Replay engine (`antigravity-acp-replay`), whose behavior is unchanged by the default switch. | Issues remain open as Replay-engine tracking |
| Setup/login/discovery helpers | `login.py` and `setup_status` live in the parent package and serve both engines; the Parked-MCP profiles offer live-only model surfaces through `session/new` discovery with a bounded TTL cache (`HERMES_ANTIGRAVITY_ACP_MCP_DISCOVERY_TTL_SECONDS`) and empty static `fallback_models`. | Implemented |
| Upstream Hermes compatibility and default-provider migration | The single package keeps the catalog floor `requires_hermes >=0.21.6` (floor-gate proven), keeps `antigravity-acp-mcp` resolving to the same engine for pre-0.9.0 configs, and the deployment installer manages the whole tree (see `scripts/deploy_hermes_profiles.py`). | Implemented in the 0.9.0 default-switch PR |
