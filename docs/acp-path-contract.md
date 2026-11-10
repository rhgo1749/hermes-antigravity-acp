# ACP portable path, registry, and account-layout contract (v1)

Scope: the optional ACP multiplexer (`scripts/acp_mux.py`,
`scripts/antigravity-acp-mux.py`, `scripts/antigravity-acp-mux`) and the
account registry it consumes. This document is the single source for how
those components decide paths; the `doctor` command is its executable
projection. It changes nothing about the default Single mode contract:
the public plugin never imports, configures, or discovers any of this, and
MUX remains opt-in; operators are responsible for reviewing terms, privacy,
and deployment requirements before using it.

## 1. Vocabulary

Two planes must never be conflated:

| Term | Meaning | Owner |
|---|---|---|
| `HERMES_HOME` | Hermes app-state home (per profile) | Hermes Core |
| `HERMES_REAL_HOME` | OS-user home published by Hermes when it rewrites `HOME` | Hermes Core |
| process `HOME` | The *current process* home; may be a rewritten profile temp home | host/session |
| `ACP_MUX_HOME` | Explicit control-plane home override | operator |
| control home | Resolved root for the default registry/state/log paths | this contract |
| `ACP_MUX_ACCOUNTS` | Explicit canonical registry path | operator |
| registry | Non-secret account lane list (`acp-accounts.json`) | operator |
| per-entry `home` | One account's **auth home** (the HOME the official server will run with) | operator |
| default home | Home for registry entries that omit `home` | this contract |
| `GEMINI_HOME` (child) | Vendor state root pinned to `<account home>/.gemini` per lane | this contract |

Rules the contract exists to enforce:

- The **control plane** (registry, health state, selection log, default home)
  is host-level control data: it follows `ACP_MUX_HOME`, then
  `HERMES_REAL_HOME`, then process `HOME`, then `expanduser("~")`.
- The **data plane** (per-account home, its `~/.gemini` auth store) is
  account-owned: it only ever comes from the registry (or the explicit
  default home). Process `HOME` is a *last-resort legacy* control-home
  resolver and is **never** an account-home resolver in a versioned registry.
- A home is not an auth store and not a control plane: `<home>/.gemini` is
  vendor-owned state; the mux never reads its contents (it only stats).

## 2. Path precedence (decision table)

One resolver, `resolve_layout(env)`, computes every control path from one
environment mapping. Import-time constants, `doctor`, and a fresh process
therefore always agree. Resolution happens **at process import / command
run**; changing environment variables requires a new process — already
imported modules keep their layout by design (documented restart semantics).
An **empty value counts as unset**.

| Output | Precedence (first non-empty wins) | Default |
|---|---|---|
| control home | `ACP_MUX_HOME` → `HERMES_REAL_HOME` → `HOME` → `expanduser("~")` | — |
| registry path | `ACP_MUX_ACCOUNTS` → `HERMES_ACP_ACCOUNTS` (legacy alias) | `<control home>/.hermes/acp-accounts.json` |
| state path | `ACP_MUX_STATE` → `ACP_MUX_CACHE` (legacy alias) | `<control home>/.hermes/cache/acp-mux-state.json` |
| log path | `ACP_MUX_LOG` | `<control home>/.hermes/logs/acp-mux.log` |
| server launcher | `ACP_MUX_PAR` → `HERMES_ANTIGRAVITY_ACP_PAR` | unset (mux refuses to run) |
| default account home | `ACP_MUX_DEFAULT_HOME` → registry `default_home` (schema v1) → control home *(legacy fallback, logged)* | control home |
| child `HOME` | per-entry `home` → default account home | — |
| child `GEMINI_HOME` | always pinned to `<child HOME>/.gemini`; a stray parent `GEMINI_HOME` is ignored (and `doctor` flags it) | — |

Legacy registries (no `schema_version`) keep byte-compatible behavior:
an entry omitting `home` still resolves to the control home, but the mux
now logs `account-legacy-home idx=N resolved=control-home-fallback` and
`doctor` reports it, so the silent case no longer exists.

## 3. Registry schema (version 1)

Non-secret by design: labels, paths, priorities. Never tokens, OAuth data,
or credential contents; the official runtime owns authentication end to end.

```json
{
  "schema_version": 1,
  "default_home": "/srv/acp/lanes/default",
  "accounts": [
    {"home": null, "label": "primary", "priority": 0},
    {"home": "/srv/acp/lanes/secondary", "label": "secondary", "priority": 0},
    {"home": "/srv/acp/lanes/fallback", "label": "fallback", "priority": 1}
  ]
}
```

Field rules:

- `schema_version` — optional integer; absent = legacy layout. An
  unsupported integer (e.g. `2`) fails closed; it is never read as legacy.
- `default_home` — optional absolute path. Explicit; removes all
  process-state ambiguity for entries with `home: null`.
- `accounts[].home` — absolute path, or null/omitted to select the default
  account home. Relative paths are rejected per entry (excluded + logged),
  not silently joined onto process state.
- `accounts[].label` — display/dedup identity only; never printed by
  `doctor` (lanes appear as a sha256 fingerprint prefix).
- `accounts[].priority` — optional integer, unchanged routing semantics.
- Account count is arbitrary (N ≥ 1); nothing in the contract assumes a
  specific count, user name, or absolute prefix.

## 4. Failure behavior (fail-closed matrix)

| Condition | Selection-time behavior | Mux exit |
|---|---|---|
| registry path absent | single-lane mode: default home only (`no-registry`) | runs |
| registry unreadable / malformed JSON / non-object / no `accounts` list | refuse selection | 2 + actionable message |
| `schema_version` unsupported | refuse selection | 2 + actionable message |
| versioned entry omits `home`, no explicit default home | entry excluded, logged | 2 if nothing selectable |
| versioned entry omits `home`, explicit default home set | resolves to default home | runs |
| legacy entry omits `home` | control-home fallback **with logged diagnostic** (compat) | runs |
| entry home relative / not absolute | entry excluded, logged | 2 if nothing selectable |
| selected lane spawn fails (missing binary, MCP-config guard) | **no silent re-route** to another lane | 2 + fingerprint |

Routing decisions that pick *between declared lanes* (priority tiers,
cooldown probes, affinity) are unchanged; the prohibition added here is
inventing an undeclared lane (process state) or swapping lanes after a
lane was already selected for the client session.

## 5. Docker and bind-mount topologies

One possible deployment shape is two container paths bind-mounted from the
same host directory, so a registry
"moving" between them is invisible unless path **identity** is checked.

Contract for deployments (documented, not enforced by code beyond `doctor`):

1. **One canonical control path.** Pick the registry location the *container
   image's* mounts guarantee to be durable; point `ACP_MUX_ACCOUNTS` at it
   explicitly instead of relying on home defaults. Explicit env beats any
   home rewriting.
2. **Legacy aliases are time-limited symlinks.** After moving a registry,
   leave the old path as a symlink to the canonical file, keep it only
   during migration, and verify with `doctor` (it reports alias pairs via
   device+inode identity, and flags divergence — two candidates that exist
   but are different objects).
3. **Never folder-merge** a registry home with a mount source; move files
   with an independent backup and a restore check first.
4. **Per-account homes are vendor state**, not control data: keep
   `<account home>/.gemini` on durable mounts, separate from the control
   plane. Container recreation with ephemeral layers loses tokens silently;
   `doctor` shows `auth-store-dir-exists=false` for lanes that lost
   persistence (the vendor auth store directory, never its contents).
5. **Symlink hazards**: `doctor` flags registry/state/log/home symlinks and
   broken links; the session-store GC already refuses to follow symlinked
   stores (unchanged).

## 6. Migration: legacy registry → schema v1

1. Run `python3 scripts/acp_mux.py doctor` (or the wrapper's `doctor`).
   Record the resolved registry path and every `warning:` line.
2. Back up the registry file itself (never the `.gemini` trees).
3. Add `"schema_version": 1` and a real absolute `"default_home"` (the
   home that the omitted-`home` entry was actually using — check it from
   `doctor` output, do not guess).
4. Re-run `doctor`: `registry-schema=1`, no legacy warnings. Exit 0/1
   (1 = remaining findings unrelated to the registry).
5. Roll back simply by restoring the file; the runtime reads the registry
   hot and supports the legacy layout indefinitely.

Environment-only case (Hermes profile rewrites `HOME`): set
`ACP_MUX_HOME` (control plane) and `ACP_MUX_DEFAULT_HOME` (account default)
explicitly in the launch environment; `HERMES_REAL_HOME` remains the
automatic fallback but must not be the *only* anchor in Docker topologies
with overlapping mounts.

## 7. `doctor`

`acp_mux.py doctor` / `antigravity-acp-mux.py doctor` /
`scripts/antigravity-acp-mux doctor` print the identical resolved contract:
sources per path, registry schema and count, per-account `lane=<fingerprint>`
lines (home, kind, `gemini-home-exists`, `auth-store-dir-exists`, status),
state record counts, log size, launcher resolution, per-lane
`auth-store-dir-exists`, and `warning:` lines
for legacy/default ambiguity, symlinks/broken links, duplicate homes,
parent `GEMINI_HOME`, and alias/overlapping-mount identity matches.

- Writes **nothing**. Opens no credential file (existence stats only).
- Prints **no labels and no tokens** — lanes are sha256 prefixes.
- Exit 0 clean; exit 1 findings; exit 2 registry present but unusable.

## 8. Non-goals

- No `/quota` adapter, quota APIs, or credential interpretation anywhere in
  this contract.
- No change to Single mode packaging, the public provider fileset, or the
  catalog.
- No automatic migration of live registries or homes; this repository does
  not mutate deployed state.
