# Troubleshooting

Symptom-indexed guide for the supported public surface. All
examples use sanitized placeholder paths and names. Start every triage with:

```bash
python3 scripts/install_acp.py status
```

which reports installation presence without mutation. Failure diagnostics
from the installers are distinct and actionable by design; read the printed
class before acting. Raw server stderr is never echoed by `verify`/probe
diagnostics (fingerprint-only summaries) to avoid leaking login material.

## The provider does not appear in Hermes after install

1. Restart or reload Hermes (provider discovery runs at load).
2. Confirm the projection exists:
   `status` must report the provider under the Hermes home you selected. If
   you installed with `--hermes-home /path/to/.hermes`, Hermes must run with
   the same `HERMES_HOME`.
3. Validate the plugin surface with the official validator:
   `hermes plugins validate hermes-plugin/antigravity-acp --install-deps`.
4. Profiles beyond the default one are only touched with `--all-profiles`;
   installing into the default home does not register the provider in other
   profile homes.

## Missing server binary

Symptom: diagnostics report the pinned server executable absent under
`~/.local/opt/antigravity-acp/<version>/`.

- Re-run `python3 scripts/install_acp.py install` (idempotent). The download
  comes only from `dl.google.com` and is SHA-256-verified before extraction.
- If the network fetch is interrupted or the archive fails the publisher-pin
  check, the run fails closed **before extraction** and an existing
  installation stays untouched. Retry; do not hand-place binaries — a foreign
  binary is provenance-unknown and will be refused.

## Missing or non-executable PATH launcher

Symptom: diagnostics distinguish "launcher not on PATH" from "launcher not
executable" from "pinned-version mismatch" — they are separate classes.

- The managed launcher is `~/.local/bin/antigravity-acp-official`. Ensure the
  bin directory is on the Hermes process `PATH`.
- Custom location: set `HERMES_ANTIGRAVITY_ACP_COMMAND` to the full launcher
  path in the Hermes process environment (an explicit override is kept, not
  rewritten).
- A non-managed file occupying the launcher path is refused untouched by
  uninstall/install; move it aside deliberately, then re-install.

## Pinned-version mismatch

Symptom: the installed server version directory does not match the version
pinned in `antigravity_acp/registry.py`.

- Re-run `install` or `update` from this checkout; the installer reconciles to
  the pinned version after digest verification.
- Do not edit `registry.py` to "match" an installed binary. Version/digest
  rotation is a reviewed, feed-sourced change (one commit bumping `VERSION`
  and all digests together).

## Interrupted, truncated, or tampered download

The archive digest is checked against the first-party publisher pin before
the archive is opened. On mismatch the command aborts; nothing is extracted,
no existing server/launcher is replaced, and the plugin tree is unchanged.
Retry the install. Persistent mismatch on a clean network suggests the pin or
the upstream feed moved — open an issue; never disable the check.

## `verify` times out or the server appears to wait for login

`verify` performs the **unauthenticated** ACP `initialize` handshake only. The
real official server may idle waiting for authentication behavior that `verify`
will never satisfy — that is the documented credential-free boundary, not a
bug. `--timeout` bounds the probe. A timeout is class-2 mechanics failure
only; it never means "auth failed" (auth was never attempted) and diagnostics
stay fingerprint-only.

## Real-server model list: "Authentication required"

Symptom: an unauthenticated `session/new` against the real server is refused
with an authentication-required error; model listing does not appear.

- This is the authentication boundary, expected in every credential-free
  environment (the clean-room records it as the model-discovery NO-GO line).
- Crossing it requires an authentication route the terms applying to you
  permit, completed inside Google's official runtime. Individual Antigravity
  subscription OAuth through this harness is a documented Terms breach —
  see `docs/terms-and-licensing.md`.
- Credential-free CI does not validate real authentication or inference.
  A supervised canary used an older client; current-release end-to-end
  validation is still outstanding.
  There is no supported noninteractive credential injection path here, and
  fabricating or extracting tokens is out of the question by design.

## Auth failures after you chose a permitted route

Sign-in state is owned by Google's runtime; this plugin requests no credential
environment variables (`requires_env: []`) and cannot read or repair vendor
auth state.

- Re-run the official server's own authentication flow interactively as the
  same OS user that runs Hermes.
- Verify which auth methods the server advertises without authenticating:
  `python3 scripts/acp_probe.py -- "$HOME/.local/bin/antigravity-acp-official"`.
- If your account is organizational, your administrator must grant access
  before sign-in succeeds.
- Do not copy credential directories between profiles or hosts, and never
  point the plugin at a vendor token yourself — that class of workaround is
  explicitly unsupported.

## Profile conflict: refused provider directory (ownership)

Symptom: `install`/`update`/`delete` refuse with an ownership statement naming
the provider directory they will not touch, **before any write**.

- The directory is catalog-managed (installed via `hermes plugins install`)
  or provenance-unknown. The refusal is intentional: the standalone installer
  never silently overwrites bytes another owner manages.
- Catalog-managed tree → use `hermes plugins update` / `hermes plugins
  remove` (the catalog owns those bytes).
- A `cp -r` copy of this repository → provenance-unknown by construction;
  remove the copy and run the real installer, which re-verifies digests.
- Wrong home entirely → point `--hermes-home` (or `HERMES_HOME`) at the home
  you actually own and re-run.
- Recovery backups from replaced trees live under
  `~/.hermes/plugin-backups/` (outside plugin discovery).

## Non-interactive gateway / cron failure modes

In non-interactive contexts (gateway sessions, cron jobs) the provider fails
**closed** rather than guessing:

- An active Hermes session/cron scope with an unavailable cwd resolver raises
  `RuntimeError` instead of falling back to the broader process cwd — run the
  profile in an environment where Hermes provides its session context.
- An unknown write origin never reuses a foreground ACP session across lanes;
  the turn is refused instead of leaking a conversation between lanes.
- Session identity falls back to `HERMES_SESSION_ID`/`HERMES_SESSION_KEY`
  process env only outside an active Hermes runtime (documented standalone
  behavior).
- Checkpoint persistence is fail-soft: a state-write failure degrades to
  process-local continuity rather than failing the model response, so a
  permissions problem on `~/.hermes/cache/` shows up as lost continuity, not
  an error.

Details: `docs/hermes-compatibility.md` (dependency register and
fail-closed consequences).

## Quota / usage reporting looks empty

Expected. `completion.usage=None` with `antigravity_usage_telemetry.status =
"unavailable"` is the truthful contract: the official server reports no billed
request tokens. Context-occupancy counters (when present) are per-call
consumption deltas, never billing figures. `/quota` is unavailable/
unsupported in the public product. See `docs/acp-usage-telemetry.md`.

## When to file an issue

Include: the installer command used, the diagnostic **class name** (not raw
server output), OS/arch, Hermes version, and this repository's commit. Redact
account identifiers, hostnames, and paths under your home. Never paste
vendor login output, tokens, or credential-shaped material into issues.
