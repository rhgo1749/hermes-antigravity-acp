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
- **ACP file callbacks** enforce absolute paths, path-root containment,
  credential-root denial, and Hermes read-block/redaction checks for reads.
  A failing read policy call denies access. All ACP file-write callbacks are
  denied; ordinary edits use Hermes `write_file` or `patch` tools, whose own
  policies apply (`docs/hermes-compatibility.md`).
- **Runtime boundary:** there is no filesystem sandbox. The
  vendor subprocess runs under the invoking account; this plugin does not
  observe or prevent direct filesystem operations by that subprocess.
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
  when pinned. The issue #24 F2 session-class declarations
  `ACP_MUX_SESSION_ORIGIN`/`ACP_MUX_SESSION_LIFECYCLE` are set by the
  plugin only for the explicit `llm_backend` one-shot policy **and only
  when the configured launch target is named as a mux entry point** per
  the mux packaging naming contract (`docs/mux-packaging.md`);
  Single-mode direct official-server children never receive them.  They
  are consumed by the mux itself — the mux strips both before spawning
  the official server. These are Hermes-side continuation bookkeeping
  values — not
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

The official server's native session bundles (the `conversations`/`brain`
stores under each account's `.gemini/antigravity-acp/`) are never deleted
automatically by the mux: the destructive native session-store GC is opt-in
(`HERMES_ANTIGRAVITY_ACP_NATIVE_GC=1` in the Hermes home, which sets
`ACP_MUX_SESSION_GC=1` for the mux child) until the native session lifetime
contract is finished. The mux's session-ownership ledger (a `.owners.json`
sidecar next to the mux routing-state file under the shared mux control home:
hashed session id → hashed account lane, no plaintext ids) is metadata-only:
an entry is retired only after a grace period
(`ACP_MUX_OWNER_GRACE_SECONDS`, default 24 h) once both
the native bundle and any Hermes continuation checkpoint reference are gone;
any unreadable registry, ledger, checkpoint inventory, or session store keeps
every entry.

### Native store lifecycle vs Hermes session pruning

`hermes sessions prune` and the ACP native session-store GC are different
operations on different stores, and neither one authorizes the other:

- `hermes sessions prune` is Hermes Core's own session-record cleanup
  (its session database rows and Hermes session directories).  It never
  touches Google's native session bundles, and running it is **not**
  authorization to delete anything under a `.gemini/antigravity-acp/`
  store.
- The native bundles are Google's server-owned state.  The mux's native
  GC (`ACP_MUX_SESSION_GC=1`, which the Hermes provider sets only when
  `HERMES_ANTIGRAVITY_ACP_NATIVE_GC=1`) is the only component in this
  project that deletes them.  It is opt-in, runs once at bind time, and
  preserves every bundle that an unexpired Hermes continuation checkpoint
  references; any unreadable inventory fails the whole pass closed.
- Read-only audit (issue #24 Phase 1): `python3 acp_mux.py inventory`
  prints a JSON census of the native stores — per-lane bundle counts,
  byte totals, age buckets, checkpoint/owner linkage, and the bundles the
  current GC policy *would* select — and deletes nothing.  Setting
  `ACP_MUX_SESSION_GC=dry-run` for a directly-launched mux logs the same
  summary at bind time instead of deleting; it also skips the expired
  owner-record cleanup, so a dry-run pass mutates neither native bundles
  nor owner metadata.  The report never contains raw session ids, account
  labels, homes, or paths; lanes appear only as positional indexes.
- Inventory locking makes zero filesystem changes: it never creates the
  lock file or changes any mode.  The report's `lock` field is
  `"acquired"` when the walk was serialized against GC/owner-prune passes,
  or `"absent-unserialized"` when no lock file existed — still a sound
  snapshot, because every pruning pass creates the lock file before
  deleting, so a lock file still absent after the walk proves no pass ran
  during it.  A lock file that appears mid-walk, or a contended lock,
  yields `status: "incomplete"` and no candidate claims.
- Candidate counts are a policy prediction, **not** a reclamation
  verdict: the GC consults per-lane process leases (issue #24 F3) and a
  fleet cutover fence, and since F4 (review R2) candidates additionally
  require positive owner evidence (registered lane, lifecycle declared
  `ephemeral`); unknown, durable, missing, or lane-mismatched evidence is
  never a candidate.  The inventory itself performs no deletion and no
  per-pass destructive hold, and production reclamation stays NO-GO until
  the issue #25 process-tree evidence ack (issue #24 counterexample C4;
  C1's live/parked-child exposure is mitigated — not globally closed — by
  F3 leases).
  Enabling the GC is a separately reviewed decision with its own bounds
  and rollback evidence (issue #24 Phases 2-3).

### Session origin and lifecycle declarations (issue #24 Phase 2 / F2)

Three cleanups share the word "delete" and must never be conflated:
**Hermes session pruning** (Core's own session records — see above),
**MUX owner-record metadata cleanup** (`prune_session_owners`, metadata
only, never touches a bundle), and **Google ACP native bundle deletion**
(the opt-in native GC, still disabled by default).

F2 adds classification only — it changes zero GC behavior:

- Two orthogonal fields, declared explicitly by the launching client at
  mux bind via `ACP_MUX_SESSION_ORIGIN` ∈ {`agent`, `backend`} and
  `ACP_MUX_SESSION_LIFECYCLE` ∈ {`ephemeral`, `durable`}.  The mux stamps
  the validated values into the owner record it writes at `session/new`
  — the only moment the creator's intent is known first-hand.
- Absent, empty, mis-cased, or unknown values record `unknown`.  Absence
  of a checkpoint, of resume history, or of prior tool calls is **never**
  evidence of `ephemeral`.  `origin` alone never licenses deletion.
- Storage stays `version: 2` with optional additive keys: legacy records
  read as `unknown`, no migration or backfill is ever performed, and
  every rewrite path (prune kept entries, repeated `session/new`)
  preserves existing declarations verbatim.  Old mux builds keep reading
  and writing these files unchanged.
- The only shipped declaration today is the explicit `llm_backend`
  one-shot policy declaring `backend`/`ephemeral`.  Agent-mode auxiliary
  calls share the main connection and cannot be individually declared;
  they stay undeclared (`unknown`) until a per-creation channel is a
  separate product decision.  No consumer declares anything ⇒ everything
  stays `unknown` ⇒ nothing becomes reclaimable: the correct resting
  state.
- The read-only inventory gains a per-lane `origin_lifecycle` count
  matrix (the `unknown` bucket is always present; unowned bundles carry
  no declaration and never enter the matrix).  It reports counts only —
  never raw ids, labels, homes, or paths — and `deletions_performed`
  remains a constant 0.

A `safe_to_reclaim` decision still requires everything F2 does not
provide: the per-lane process lease and in-flight protection (F3,
provided below; #23 cancellation teardown lands inside the same
post-death grace), continuation-checkpoint checks, a retention/recovery
grace, and F4 bounded per-pass deletion with audit evidence.  Until then
no declaration — including `backend`/`ephemeral` — makes any bundle
reclaimable.

### Per-lane process leases (issue #24 Phase 3 / F3)

F3 adds protection only — it grants zero new deletion authority and
deletes nothing.

- When the MUX binds a lane it takes a **shared `flock` lease** on
  `<state>.leases/<lane-fingerprint>.lease` (mode 0600, `O_NOFOLLOW`)
  *before* spawning the official ACP child, and holds it for the child's
  lifetime.  The lease fd is **inherited by the direct official child**
  (`pass_fds`), so the lock covers the mux and that child: a vendor
  process that outlives a SIGKILLed mux keeps the lane protected until it
  itself exits.  Kernel release of the *mux* fd alone is never treated as
  vendor death.  Every completed JSON-RPC request refreshes the lease
  heartbeat; orderly teardown records a final heartbeat and releases the
  lock.  A child process never runs without lease evidence, and lease
  acquisition is non-blocking with a hard 5-second deadline — contention
  that outlasts it fails the bind instead of spawning unleased.
- Heartbeat writes from multiple shared holders are serialized on a
  sidecar write lock (never on the lifetime lock) and the recorded `at`
  is monotone: a concurrent writer can neither tear the file nor shorten
  another holder's grace window.
- The native GC and the read-only inventory probe with a non-blocking
  **exclusive** lock.  States: `live` (a holder is proven alive by lock
  contention), `grace` (no holder, heartbeat within
  `ACP_MUX_LEASE_GRACE_SECONDS`), `stale` (no holder, heartbeat aged out:
  the **only** unprotected state), `absent` (no lease file — old mux
  build or never-bound lane: unknown evidence, protected),
  `unsupported`/`unavailable` (no flock, or unreadable/corrupt/symlinked
  lease: fail closed).  Absence of a lease file is never evidence of an
  idle lane.
- Crash, kill, restart, and PID reuse need no heuristics: the kernel
  releases the flock when **every** holder of the open file description
  (mux and the direct child that inherited the fd) has exited, and the
  lock lives on the file descriptor, not the pid.  Late completion after
  cancellation stays inside the grace window.
- **Descendant boundary (review B5), stated as a limit not a feature.**
  `pass_fds` propagates to the **direct** child only.  Processes the
  vendor itself spawns (the issue #25 observation: official server →
  local-harness, launched with default `close_fds`) hold no lease fd, and
  we cannot control vendor-internal spawn semantics; reparenting makes
  descendant liveness unprovable from the outside.  A stale lease
  therefore never proves vendor descendants are gone.  F3's protection
  claim is scoped to **mux + direct official child**; whether any vendor
  descendant outlives the direct child is pinned as a boundary test
  (`test_b5_grandchild_does_not_inherit_lease_fd`), and **issue #25
  process-tree evidence is a hard prerequisite for F4 deletion
  authorization**.  Until that evidence exists, "active/parked process
  protection" is *not* closed — F3 is a mitigation.
- **Fleet cutover fence (mixed-version rollout).**  A stale lease proves
  only that F3-aware holders are gone; a pre-F3 mux — which never writes
  a lease at all — can still be alive on the same lane during a rolling
  upgrade.  The native GC therefore refuses to run until the operator
  sets `ACP_MUX_F3_CUTOVER_ACK=1` in the environment of the mux that
  would run it, and only after taking process evidence (`ps`) that no
  pre-F3 mux remains.  Default (unset) is fail-closed: no deletion pass,
  logged reason.  The read-only inventory reports the fence state as
  `policy.fleet_cutover_ack` but still predicts lease-cleared candidates,
  which remain conditional on the fence.
- Protection is **lane-level**: while a lane is protected, no bundle in
  that lane's store is a candidate.  Which bundles a live child actually
  holds open is vendor-internal knowledge and is never inferred.
- Where `flock` does not exist (Windows) the GC's own cross-process lock
  is unavailable too, so no lease is taken and no GC can run: symmetric
  fail-closed, not a gap.
- The inventory reports a per-lane `lease` state token and a
  `lanes_lease_protected` total; a protected lane reports zero
  candidates so the dry-run prediction cannot drift from GC behavior.
  `deletions_performed` remains a constant 0.
- Residual race, stated honestly: a bind racing a GC pass — the GC probes
  the lane lease, releases the probe, and only then walks the store; a new
  mux can acquire the lease inside that window.  Nothing in F3 makes that
  safe on its own.  F4 (below) closes **both** (a) this window, with an
  exclusive lease hold plus bounded scope, and (b) the descendant boundary
  above, via the issue #25 process-tree evidence gate.  Until both gates
  are actually acknowledged in production, `GC=1` stays NO-GO and C1 is
  only *mitigated* (normal-path exposure), not globally closed.

### Bounded deletion and deletion authority (issue #24 Phase 4 / F4)

F4 turns the F3 lease from a *probe* into a *hold* and puts every real
deletion behind two independent operator gates.  The design goal is a
bounded blast radius with a verifiable postcondition — deleted files are
gone; nothing here pretends to roll them back.

- **Gate A — check-to-delete TOCTOU closed by an exclusive hold.**  A real
  deletion pass takes each registered lane's lease `LOCK_EX` and keeps it
  for the whole per-home pass, re-reading the heartbeat *under* the lock
  (never a reused probe).  A bind racing the pass cannot take its shared
  lease, so it never spawns against a store being deleted (its own bounded
  retries fail it closed first).  Contended, absent, grace, or unreadable
  lanes are skipped fail-closed; the hold is released even if the pass
  raises.
- **Gate B — process-tree evidence fence.**  A stale lease never proves
  vendor-spawned descendants (issue #25 server → local-harness; observed
  live with up to two harnesses under one server) are gone, and POSIX
  gives no primitive to bind a lifetime the mux never created.  Real
  deletion therefore requires `ACP_MUX_F4_PROCESS_TREE_ACK=1`, an
  operator attestation of first-hand process-tree evidence.  Without it
  the GC runs **audit-only**: identical selection, revalidation, and
  budget accounting, logged as `session-gc-audit`, zero unlinks.  Audit
  output is a plan, never a deletion result.
- **Bounded per-pass budgets** (`ACP_MUX_GC_MAX_DELETIONS` default 8,
  `ACP_MUX_GC_MAX_BYTES` default 64 MiB, `ACP_MUX_GC_PASS_DEADLINE_SECONDS`
  default 10, shared across lanes in deterministic *lane* order — bundle
  iteration inside a store is not an ordering contract): a pass that
  would exceed any budget stops early (`budget-stopped`) and leaves the
  rest to a later pass.  A bundle's footprint is measured exactly once
  per slot (review R5 — no re-read between verdict and reservation), and
  a bundle whose footprint cannot be measured is never admitted through
  a byte budget it cannot be checked against, let alone reserved as 0.
- **Fresh per-slot revalidation (review R1/R4):** immediately before each
  deletion slot the checkpoint inventory is re-read (a fresh view, never a
  pass-start snapshot), the bundle's activity is re-statted, and the
  budgets are re-checked.  Capacity eviction is not a stored plan: at every
  eviction slot the excess/evictable eligibility and the oldest-first
  ranking are *recomputed* from freshly re-statted activity, so a bundle
  revived after planning survives and only what is currently evictable is
  deleted.  An unreadable fresh checkpoint view aborts the remainder of the
  pass.  Path-swap and symlink counterexamples were already refused by the
  delete-time `lstat` checks and stay refused.
- **Owner/lifecycle positive evidence (review R2):** a bundle is deleted
  only with a fresh, positive proof read immediately before its own slot —
  the owner ledger is readable, an owner record exists for the session,
  its lane belongs to this store's registered lanes, and its declared
  lifecycle is exactly `ephemeral`.  Unknown, missing, durable, invalid,
  lane-mismatched, or unreadable evidence never deletes; `origin=backend`
  alone never licenses a deletion.  The evidence is re-read per slot (no
  lock-scoped snapshot is reused), and the inventory's candidate
  prediction applies the same gate so the two never drift.
- **Partial failure semantics (review R3/R8/R9):** each bundle's full
  budget cost (count + measured byte estimate) is *reserved* before its
  first destructive mutation and is never refunded — a bundle whose brain
  tree was removed but whose DB unlink failed still consumes the
  reservation.  Immediately before the deleter's first mutation the real
  delete-target footprint is re-measured and anything larger than the
  reserved estimate is refused non-destructively with zero mutation (R8 —
  the byte hard bound is never retroactively widened).  The wall-clock
  deadline is re-checked after all fresh evidence reads and before the
  reservation itself (R9), so a slow evidence read can never spend past
  the budget.  The first deletion failure or uncertain postcondition
  stops the rest of the pass immediately (fail-closed); later candidates
  stay untouched.  There is no rollback and none is claimed — the safety
  property is the bound itself plus per-bundle postconditions, not
  recovery.
- The inventory reports the budgets and both acks under `policy`
  (`gc_max_deletions`, `gc_max_bytes`, `gc_pass_deadline_seconds`,
  `process_tree_ack`); `deletions_performed` remains a constant 0.
- Production status: both acks are unset, `ACP_MUX_SESSION_GC` stays off.
  F4 code existing is not deletion authority; the gates being *closed
  with evidence* is.

## 4. Telemetry

- **This plugin sends no telemetry.** Nothing is reported to this repository
  or any third-party endpoint by the plugin itself.
- Usage reporting is a **response-level attribute**, truthful by contract:
  `antigravity_usage_telemetry` with `status="unavailable"` and null
  request-usage buckets; that separate attribute does not expose billing.
  `completion.usage` is populated **only** when the server itself supplies a
  valid per-turn usage breakdown in the ACP prompt result — the pinned
  official server currently never does, so completions carry
  `completion.usage=None` and Hermes applies its designed estimation
  fallback. The pre-v0.7.9 consumption-proxy split synthesized from
  `usage_update` frames was removed as fabricated (issue #6) and is never
  produced again.
  `usage_update` counters are kept
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

- **One approval-gated execution path for mutations.** Hermes tool calls use
  Hermes policy and approval. The ACP server's native coding tools are never
  auto-approved: native `run_command` is disabled at session launch
  (`agy.disabledTools`) and every native file-mutation or command permission
  frame is answered with the server's own reject option, so the model performs
  shell and file work through Hermes' approval-gated terminal and file tools
  via the Hermes `<tool_call>` bridge. The harness `fs/read_text_file` callback
  applies Hermes read-block and redaction policy. The `fs/write_text_file`
  callback is disabled and rejects every request, including workspace writes;
  file mutations must instead use Hermes tools.
  Tool-call replay and duplicate suppression are in `docs/provider-runtime.md`.
- The provider-mode **web research bridge** only relays function schemas
  Hermes explicitly supplies and returns calls to Hermes' policy/execution
  path; it never executes searches itself (`docs/web-research-bridge.md`).
- The former trusted-coding auto-approval was removed after the Hermes plugin
  catalog review; `HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE` and
  `HERMES_ANTIGRAVITY_ACP_WORKSPACE` are inert and no configuration re-enables
  native auto-approval. Native Telegram video remains opt-in with its own
  allowlist and TOCTOU limits.
- If you want the full Antigravity agent runtime with native tools and MCP
  clients, run the official server as an external ACP **agent** — that is the
  vendor's own product surface, not this shim.

## 6. Child and background processes, permissions

- The default topology launches one official ACP server child
  process **per ACP session or attempt** (including retries; concurrent
  sessions can therefore yield more than one child process over a Hermes
  process lifetime). A healthy child is parked after its session context
  exits and reused by the next session with the same launch identity
  (command, args, cwd, conversation affinity, publisher pin) until an idle
  TTL of 120
  seconds expires; a child that failed or timed out is never parked. Active
  children are terminated when the provider client closes, parked children
  are terminated at interpreter exit (atexit) or TTL expiry —
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
