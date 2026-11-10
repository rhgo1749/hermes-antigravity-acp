# Data, permissions, and processes (public disclosures)

Disclosure page for the supported public surface. Everything here is
observable from this repository's code and credential-free tests; anything
that happens inside Google's proprietary binary is attributed to the vendor
and marked as not observed here — never guessed.

## 1. Data sent to the official server and to Google services

- Hermes conversation content — prompts, replayed historical context blocks,
  tool-call/result payloads, session `new`/`resume` identifiers, model config
  options, and (when you attach media) `resource_link` path references —
  travels over **stdio JSON-RPC** from the Hermes process to the official
  `agy_acp_server` child process, and from there to Google's services.
- **Runtime model/protocol traffic to Google originates from the
  Google-distributed official binary.** The plugin itself opens no network
  connections of its own and holds no credentials: the manifest declares
  `requires_env: []` and the plugin never reads vendor token stores. On the
  download side there is one further repository-visible Google-bound fetch:
  the standalone installer (`scripts/install_official.py`) retrieves the
  pinned server archive over HTTPS from `dl.google.com` during an explicit
  install command — installer asset retrieval, not provider model/protocol
  traffic. This repository neither observes nor bounds any other networking
  inside the proprietary binary (section 4). The catalog admission
  description in `docs/plugin-catalog-entry.draft.yaml` states the same
  surface.
- Sign-in (whichever permitted route you choose) happens entirely inside
  Google's own runtime; this repository neither receives nor proxies OAuth
  material.
- What crosses back: protocol responses, streamed updates, `usage_update`
  frames, and error signatures. Response telemetry contains only opaque
  SHA-256 session/turn hashes — no prompt text, raw native IDs, account
  credentials, or vendor payloads (contract:
  `docs/acp-usage-telemetry.md`).

## 2. File and environment access scope

- **Plugin:** reads and writes only its own state files under the selected
  Hermes home (section 3). It requests no credential environment variables.
- **Hermes-side file tools** invoked through the ACP bridge stay behind
  Hermes' own policy: absolute-path requirements, path-root containment,
  credential-root denial, read redaction, and write-denial/approval checks. A
  policy call that raises is itself a denial, never a fallback
  (`docs/hermes-compatibility.md`).
- **ACP child environment** is narrowed to a minimum enumerated allowlist
  (`PATH`, `HOME`, locale, XDG bases resolving inside the child's own profile
  home, etc.). Ambient provider API keys (`OPENAI_API_KEY`,
  `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`), Tier-1 gateway tokens, ambient
  session identity variables, and inherited operator `ACP_MUX_*` environment
  configuration are **never** passed to the child
  (`docs/hermes-compatibility.md`, enforced by
  `tests/test_runtime_safety_isolation.py`). What deliberately does cross is
  a bounded set of plugin-synthesized routing/session metadata:
  `ACP_MUX_SESSION_ID` and `ACP_MUX_AFFINITY` (opaque continuation/affinity
  values for a resumed session), `ACP_MUX_SESSION_GC`,
  `ACP_MUX_AFFINITY_PIN`, affinity TTL and entry limits, and `ACP_MUX_PAR`
  when pinned. These are Hermes-side continuation bookkeeping values — not
  Google credentials — and the child gets no general environment inheritance
  beyond the allowlist.
- **Installer** writes are limited to: the versioned server under
  `~/.local/opt/antigravity-acp/`, the managed launcher in `~/.local/bin/`,
  the provider tree under the selected Hermes home, and backups under
  `~/.hermes/plugin-backups/`. No sudo, no system paths, no other users'
  files.
- **Installer-CLI probes** (`install_acp.py verify`, `install_official.py
  --verify`, `scripts/acp_probe.py`) start the official server as a child
  process with the caller's environment and no filesystem sandbox — this is
  not the Hermes runtime path and its environment is not narrowed to the
  allowlist above. What this repository observes of that child is its
  protocol traffic and printed output; whatever files the vendor binary
  reads or writes under the user account while answering is not observed
  here, is not claimed, and is not excluded. Nothing in this repository's
  credential-free evidence should be read as a sandbox or isolation guarantee
  for that child.

## 3. Persisted state, sessions, and cache

| File | Contents | Protections |
|---|---|---|
| `~/.hermes/cache/antigravity-acp-sessions.json` | Session-continuation checkpoints (opaque session/frontier hashes) and additive `usage_totals` per explicit Hermes session id | 0600, atomic replace, 24 h TTL, bounded entries; override `HERMES_ANTIGRAVITY_ACP_STATE_FILE` / `HERMES_ANTIGRAVITY_ACP_STATE_TTL_SECONDS` / `HERMES_ANTIGRAVITY_ACP_STATE_MAX_ENTRIES` |
| `~/.hermes/cache/antigravity-acp-native-limits.json` | Profile-neutral learned trajectory-limit observations | 0600, atomic replace, 7-day TTL; override `HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE` / `HERMES_ANTIGRAVITY_ACP_LIMIT_TTL_SECONDS` |
| Provider tree + `install-provenance.json` | The canonical 7-file plugin set plus ownership metadata | Ownership refusal protects foreign/catalog trees (`docs/quick-start.md`) |
| `~/.local/opt/antigravity-acp/<version>/` | Google's versioned server files as distributed | Managed by the installer; uninstall removes only these plus the managed launcher |

Google's own sign-in/session state lives wherever Google's runtime stores it
under your user account — managed by the vendor, not by this plugin. A resumed
ACP session may retain media already consumed in its earlier prompt
(`docs/provider-runtime.md`).

## 4. Telemetry

- **This plugin sends no telemetry.** Nothing is reported to this repository
  or any third-party endpoint by the plugin itself.
- Usage reporting is a **response-level attribute**, truthful by contract:
  `completion.usage=None` plus `antigravity_usage_telemetry` with
  `status="unavailable"` and null request-usage buckets, because the official
  server exposes no billed request tokens. `usage_update` counters are kept
  separately as non-billing `context_occupancy`
  (`docs/acp-usage-telemetry.md`). `/quota` is unavailable/unsupported — no
  quota command ships here.
- Any telemetry opt-in in the Hermes **user interface or core** belongs to
  Hermes, not this plugin.
- The proprietary official binary may perform its own network or background
  activity under Google's privacy practices. This repository neither observes
  nor vouches for it, and does not speculate about its contents. Review
  Google's terms (links in `docs/terms-and-licensing.md`) for what applies.

## 5. Shell and tool execution boundary

- **Hermes tools stay in Hermes.** Acting as a Hermes model backend does not
  grant the Antigravity runtime arbitrary native tool permissions; ACP-side
  tool activity is mapped through Hermes' own policy, approval, and execution
  path. Tool-call replay, duplicate suppression, and completed-action
  handling are described in `docs/provider-runtime.md`.
- The provider-mode **web research bridge** only relays function schemas
  Hermes explicitly supplies and returns calls to Hermes' policy/execution
  path; it never executes searches itself (`docs/web-research-bridge.md`).
- Opt-in extensions carry explicit trust warnings before elevation:
  native Telegram video (`HERMES_ANTIGRAVITY_ACP_NATIVE_VIDEO=1`, allowlist +
  TOCTOU limits in `docs/provider-runtime.md`) and trusted coding mode
  overrides (`HERMES_ANTIGRAVITY_ACP_WORKSPACE` /
  `HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE`). Default = off.
- If you want the full Antigravity agent runtime with native tools and MCP
  clients, run the official server as an external ACP **agent** — that is the
  vendor's own product surface, not this shim.

## 6. Child and background processes, permissions

- The default topology launches one short-lived official ACP server child
  process **per ACP session or attempt** (including retries; concurrent
  sessions can therefore yield more than one child process over a Hermes
  process lifetime). Each child is terminated when its session context
  exits, and closing the provider client terminates any active children —
  they are plugin-managed foreground processes, not a daemonized service.
  Each runs as the same OS user, with the narrowed environment from
  section 2. No daemonization, no self-updating process, no background
  services, no sudo, no fixed container.
- No account registry, no rotation logic, and no routing logic run in the
  plugin or default installer. CI tests the optional MUX with synthetic
  fixtures. An external general ACP endpoint can
  replace the child target via the command override and is then treated as
  one opaque ACP server. The separately installed optional MUX can select
  configured accounts for new sessions and apply failure cooldowns.
- Failure modes are fail-closed by design: startup is refused (rather than
  launched with a broadened environment or wrong cwd) when Hermes host policy
  is unavailable, per `docs/hermes-compatibility.md`.

## 7. What is deliberately NOT collected or supported

- No credential storage, no token extraction, no cookie/keystore access.
- No `/quota` command (no vendor-sanctioned quota source exists).
- No account selection or rotation in the default provider path. The optional
  MUX does perform multi-account selection; its use is subject to vendor terms.
- No prompt transcripts or conversation logs written by the plugin; durable
  state stores opaque hashes and counters only.
