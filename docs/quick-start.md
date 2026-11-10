# Standalone Quick Start: full lifecycle

Companion to the README "5-minute Quick Start". This page is the
complete, operator-followable lifecycle for the **currently reproducible**
install route: the credential-free standalone installer from a checkout of
this repository. The Quick Start route is what the hosted
clean-room executes as a dedicated OS UID on `ubuntu-24.04`
(`docs/official-server-1.4.4-clean-room-e2e-2026-11-07.md`), so an operator
with no prior documentation can reproduce it end to end.

The public Hermes plugin catalog does **not** carry this provider yet —
`hermes plugins install antigravity-acp-provider` does not resolve today.
Catalog registration is pending. Nothing
here assumes a personal mux, an account router, or a Hermes Core patch.

## Prerequisites

- Hermes `>=0.21.6` (the declared, CI-proven compatibility floor; the latest
  upstream release is checked in the README status table).
- `python3` and a checkout of this repository.
- Outbound HTTPS to `dl.google.com` during the explicit install step only.
- A system in the executed tier (Ubuntu 24.04 x86_64) or a registry-pinned
  tier (Linux aarch64, macOS arm64, Windows x64/arm64 — pinned-only, see the
  README verification tiers).
- No Docker, no sudo, no fixed container names, no account multiplexer, and
  no private profile infrastructure is required or assumed.

## 1. Install

```bash
python3 scripts/install_acp.py install
```

What this does, in order:

1. Resolves the pinned distribution for your platform from
   `antigravity_acp/registry.py` (currently server `1.4.4`) and downloads the
   archive over HTTPS from `dl.google.com`.
2. Verifies the archive against the first-party publisher SHA-256 pin **before
   the archive is opened, extracted, or installed**, and before any existing
   installation or launcher can be replaced. A tampered, truncated,
   interrupted, or unpinnable download fails closed and leaves an existing
   installation and launcher untouched.
3. Installs the versioned server under
   `~/.local/opt/antigravity-acp/<version>/` and the managed launcher
   `~/.local/bin/antigravity-acp-official`.
4. Projects the provider code into
   `$HERMES_HOME/plugins/model-providers/antigravity-acp/` (default
   `~/.hermes/plugins/model-providers/antigravity-acp/`) with an
   `install-provenance.json` ownership marker.

Scoping: the default targets only the selected Hermes home (the default
profile). Add `--all-profiles` to include named profiles under that home;
other profile homes are left untouched. For a non-default Hermes home, set
`HERMES_HOME` or pass `--hermes-home /path/to/.hermes` to each command (the
explicit option takes precedence). Custom launcher directory: put it on
Hermes' `PATH` or set `HERMES_ANTIGRAVITY_ACP_COMMAND` in the Hermes process
environment; the provider keeps any explicit command override.

The installer never downloads or self-updates the server during
`plugin.yaml` loading or plugin import — server installation is always this
explicit command.

## 2. Status and verify (credential-free)

```bash
python3 scripts/install_acp.py status
python3 scripts/install_acp.py verify
```

- `status` reports installation presence without mutation.
- `verify` checks the provider manifest and executable path, then its probe
  sends exactly one ACP request: an unauthenticated `initialize` carrying no
  auth method, no prompt, and no credential material. The claim is scoped to
  the harness: `verify` requires no credentials, sends none, and its own code
  reads no credential stores. It makes no claim about the vendor binary: the
  probe starts the proprietary server as a child with the caller's
  environment and no filesystem sandbox, so whatever file access that process
  performs under your user account is not observable from this repository —
  neither claimed nor excluded (vendor attribution:
  `docs/data-and-permissions.md`). Expect exactly class-2 evidence (see the
  README "Four distinct evidence classes"); it is not auth, model-discovery,
  or inference proof.

Direct probe, without the installer:

```bash
python3 scripts/acp_probe.py -- "$HOME/.local/bin/antigravity-acp-official"
```

On Linux the launcher automatically supplies Google's Registry argument
`--uid=`. A successful probe prints the negotiated protocol version, agent
name/version, and advertised auth methods — no login, no prompt.

## 3. Optional: official admission validation

```bash
hermes plugins validate hermes-plugin/antigravity-acp --install-deps
```

Run from this checkout with your installed Hermes CLI. This is the same
official catalog-admission validation the CI `catalog-floor-gate` job runs at
the `v0.21.6` floor and `upstream-hermes-compat` runs against upstream `main`.
Expected outcome: validation passes with zero core overrides; the documented
Catalog Rule 9 private-import warnings and the informational provider
`Isolation` note are enumerated in `docs/hermes-compatibility.md`.

## 4. Select the provider in Hermes

Start or reload Hermes and select **Antigravity ACP (official)** from the
provider/model selector. If the provider does not appear, see
`docs/troubleshooting.md` (loader/discovery class).

## 5. Authentication and first model call — conditional, NOT part of this guide

Sign-in and real model calls are **outside** this credential-free lifecycle.
They are permitted only through an authentication route the terms applying to
you allow (Google's FAQ names Gemini Enterprise or Google AI Studio API keys
for third-party coding agents) and only inside Google's official runtime.
Individual Antigravity subscription OAuth through third-party harnesses is a
documented Terms breach (README terms section;
`docs/terms-and-licensing.md`). This guide and the credential-free CI do not
validate authentication or real inference for the current release. An earlier
supervised canary used a different client version; its result is not a current
release end-to-end validation or a general terms approval.

## Server-only management

To manage just Google's server and launcher, without touching any provider
files (including catalog-pinned ones):

```bash
python3 scripts/install_official.py            # pinned server + launcher
python3 scripts/install_official.py --status
python3 scripts/install_official.py --verify   # unauthenticated initialize probe
python3 scripts/install_official.py --uninstall
```

`--uninstall` deletes only the versioned directory and the managed launcher;
unmanaged launcher files are refused untouched. Archive SHA-256 verification
still happens before extraction.

## Update, delete, backup, recovery

- `install`/`update` are idempotent. Upgrades retain legacy literal provider
  launch commands/arguments and an existing per-provider `par.txt` pin;
  changing those launch settings requires an explicit migration rather than
  an incidental generic update.
- Replaced provider code is backed up outside plugin discovery under
  `~/.hermes/plugin-backups/`. Inspect the preserved backup before restoring
  manually.
- `python3 scripts/install_acp.py delete` removes only standalone-owned
  projections plus the pinned server. A provider directory that is
  catalog-managed, installed via `hermes plugins install`, or otherwise
  provenance-unknown is refused **before the first write**, with an explicit
  statement of what was refused and the owner-appropriate recovery path
  (ambiguous ownership fails closed; a plain `cp -r` copy of this repository
  proves nothing and is refused).
- To recover, use the installer from the previously pinned release checkout
  and run `install`/`update` again.
- None of these commands modifies Hermes user config, authentication, account
  registries, conversations, or session state.
- The empty-`HERMES_HOME` lifecycle
  `install → status → verify → delete → reinstall` (reinstall re-verifying
  against the same reviewed publisher pin) is covered by credential-free
  regression tests (`tests/test_clean_env_e2e_smoke.py`).

## Using it from another ACP client

The contract is a child process whose stdin/stdout carry ACP v1 JSON-RPC:

```json
{
  "command": "antigravity-acp-official",
  "args": []
}
```

Use the full launcher path unless the client process `PATH` includes the
selected bin directory. See the README "Use with an ACP client" for harness
notes (Zed/JetBrains consume external ACP agents directly; `opencode acp` /
`pi-acp` expose those tools *as* agents — they are not clients of Antigravity
by themselves).

## Explicitly out of scope (availability ledger)

| Item | Status today |
|---|---|
| Public catalog install (`hermes plugins install ...`) | Not available until catalog publication |
| Live authentication / first model call | Not verified end-to-end on the current release |
| `/quota` visibility | Unavailable / unsupported — no vendor-sanctioned surface |
| Account selection | None in this route; optional MUX selects configured accounts and is subject to vendor terms |
| Optional MUX | Preview; not part of this route |

## Not part of this Quick Start: opt-in MUX preview

The strictly opt-in mux extension (`scripts/install_mux.py`) is
preview code. See
[mux packaging](mux-packaging.md). Nothing in this Quick Start installs,
imports, or enables it.
