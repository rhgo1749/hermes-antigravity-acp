# Official ACP 1.4.4 clean-room E2E evidence record

**Acceptance-venue provenance:** the clean-room acceptance evidence in this record is
the GitHub-hosted `ubuntu-24.04` dedicated-OS-UID CI run documented in the
"Hosted fresh-UID clean-room CI" section below. Everything before that
section is a **historical observation log** of the earlier private
Debian-container attempt: per the venue ruling, the prior in-container and
Docker-era attempts remain **NOT EXECUTED** as clean-room acceptance
evidence and are never retro-promoted. A scrubbed `env -i` process
environment with an empty disposable `HOME` is an env-only scrub — it does
not establish a separate OS UID, access isolation from the pre-existing OS
user's files/credential state, or any equivalent of that criterion.

Historical private-container log observed **2026-11-07 14:52:57Z –
14:54:39Z** (recorded observation only; **NOT EXECUTED** as acceptance
evidence). Scope: credential-free install and initialize only; authenticated
inference is outside this record. This
document retains the sanitized observational log of that attempt for the
chain
`download/pin → provider registration + official server install → status →
verify → real-server unauthenticated initialize → Hermes provider
selection/model discovery entry` plus clean uninstall/reinstall and
fail-closed diagnostics — as non-acceptance historical data, not an
acceptance artifact. No Google login, credential read, authenticated call,
prompt, inference, account change, catalog submission, or public-release
transition was performed at any point.

Machine-readable status tokens (parsed by
`tests/test_official_clean_room_e2e_evidence.py`; do not reword without
updating that test):

```text
FAKE-CI-SMOKE: VERIFIED (credential-free fake-ACP suite, tests/test_clean_env_e2e_smoke.py)
REAL-INITIALIZE: NOT EXECUTED (as clean-room acceptance evidence; the earlier private-container initialize below is a historical observation only, never retro-promoted — the accepted unauthenticated initialize evidence is HOSTED-REAL-INITIALIZE in the hosted section)
UNAUTHENTICATED-MODEL-DISCOVERY: NOT VERIFIED (server auth boundary code=-32000 "Authentication required"; the client sent zero authenticate/login frames)
AUTHENTICATED-SESSION: OUT OF SCOPE / NOT RUN
REAL-INFERENCE: NOT RUN / NO-GO (outside this record)
BLOCKER-CATALOG-PATH-A: NOT VERIFIED ('antigravity-acp-provider' is not yet in the public Hermes plugin catalog; submission is a separately approved task, see docs/plugin-catalog-entry.draft.yaml)
BLOCKER-FRESH-UID: NOT EXECUTED (as clean-room acceptance evidence; this sandbox has no sudo and unshare(CLONE_NEWUSER) returns EPERM, and a scrubbed env -i with a disposable empty HOME + HERMES_HOME is only a process-environment scrub — it does not establish a separate OS UID or isolation from pre-existing OS-user/credential state; the criterion was re-instrumented in the hosted dedicated-UID venue below)
```

## Environment fingerprints

| Item | Value |
|---|---|
| Host kernel | Linux x86_64 |
| Userland | Debian GNU/Linux 13 (trixie) container userland |
| Repository under test | Earlier project snapshot (clean worktree; not this release) |
| Official Hermes Core | `NousResearch/hermes-agent` @ commit `a9ff9799e273f525b82718cdc69fdec71b1dca5a`, tree `aef5c57545440533a9edf6e697f762c9aa158629` (shallow clone of `main`, remote `https://github.com/NousResearch/hermes-agent.git`) |
| Hermes install | `uv sync --frozen --python 3.14 --group dev` with `uv 0.13.5`; `uv.lock` SHA-256 `79c8ec9f62dd3a7ec221a61c04912b6a1bc3fd43840d25838a4a0975dee061be`; resolved CPython 3.14.5; 85 frozen dependencies |
| Hermes unmodified check | after `uv sync`: `git diff --exit-code`, `git diff --cached --exit-code`, and empty `git status --porcelain --untracked-files=no` all clean |
| Clean-room root | `$CR94` (disposable scratch root; removed after the run) |
| Clean-room process env | exactly `HOME=$CR94/home USER=cr94 LOGNAME=cr94 PATH=/usr/bin:/bin:/usr/local/bin HERMES_HOME=$CR94/hermes-home` (+ `LANG/LC_ALL/TMPDIR/GIT_CONFIG_*` in lifecycle steps); zero credential-shaped variables (recorded env dump) |
| Run window | `2026-11-07T14:52:57Z` – `2026-11-07T14:54:39Z` |

The literal "fresh OS user" criterion could not be executed here
(`BLOCKER-FRESH-UID` above): the environment has no `sudo` and
`unshare -r` fails with `Operation not permitted`. The scrubbed `env -i`
process environment with an empty disposable `HOME` and `HERMES_HOME` used
in its place removed environment-variable and home-directory state from the
child processes; it did **not** create a separate OS UID and therefore did
**not** by itself establish access-isolation from pre-existing OS-user or
credential state on the underlying machine (the container-era attempts
shared the operator's OS user). This in-container approximation is therefore **NOT EXECUTED**
as clean-room acceptance evidence — it is not retro-promoted — and the
criterion was re-instrumented in the hosted dedicated-UID CI venue recorded
in the "Hosted fresh-UID clean-room CI" section. The in-container integrity
checks below are retained as historical observations of what the scrub did
prove (no credential file was read or written by the observed processes),
not as proof of OS-user isolation.

## Supply chain and publisher pin

| Item | Value |
|---|---|
| Version | `1.4.4` (feed `version` field confirmed `1.4.4`) |
| Archive URL | `https://dl.google.com/agy-extensions/releases/linux/agy-acp-server-1.4.4-linux-x86_64.zip` |
| First-party feed | `https://dl.google.com/agy-extensions/releases/acp/feed/v1/next/1.4.3/acp_next.json` fetched `2026-11-07T14:44:52+09:00` (HTTP 200, 1544 B), JSON SHA-256 `3edd9385e5ce96cc2db7056b2799be16002d294c88c03b7f1a0ea69ce2555c0d` |
| Publisher digest (feed, `platforms.linux-x86_64.sha256`) | `baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a` |
| Registry pin (`antigravity_acp/registry.py`) | identical to the feed digest above |
| Independent recomputed archive SHA-256 (separate full re-download via `curl`, 336 847 567 B) | identical to the feed digest above |
| Server `Last-Modified` header | `Wed, 28 Oct 2026 19:18:29 GMT` |
| Extracted executable `agy_acp_server.par` SHA-256 | `bb53b0e506923f8d07c1b94166978e62bc5ac83c65c73fb78d32975ee023045d` |
| Feed-vs-registry comparison (all five pinned targets, 2026-11-07) | `linux-x86_64`, `linux-aarch64`, `darwin-aarch64`, `windows-x86_64`, `windows-aarch64`: all FEED_MATCH |

`scripts/install_official.py` verifies the downloaded archive against the
registry pin **before extraction** (steps S03/S13 passed, i.e. the bytes it
installed matched the publisher digest; a mismatch exits 2 and leaves
nothing installed — this gate is also covered credential-free in CI).
Google publishes no detached checksum file for the archive URLs themselves;
the feed JSON remains the only first-party digest source.

## Historical private-container step chain (Linux x86_64, real binary, unauthenticated) — recorded observation, NOT acceptance clean-room evidence

The rows below are the sanitized historical observations of the 2026-11-07
private Debian-container attempt against the repository scripts at
an earlier project revision. This chain is
**NOT EXECUTED** as clean-room acceptance evidence and is retained only as
non-acceptance historical data; the accepted real-binary execution record
is the hosted dedicated-UID section below. `rc` = observed process exit
code. Auth column: every observed step is credential-free; nothing below
authenticates or reads credential state.

| Step | Action | rc | Result |
|---|---|---|---|
| S00 | `install_official.py --status` pre-install | 1 | `official_server=missing launcher=missing` (fail-closed, actionable) |
| S01 | `install_official.py --verify` pre-install | 2 | names pinned `1.4.4` as missing + install-first recovery path |
| S02 | `install_acp.py status` pre-install | 1 | all four surfaces `missing` |
| S03 | `install_official.py install` — real HTTPS download from `dl.google.com`, SHA-256 pin check before extraction | 0 | 337 MB installed in 7.26 s; no authentication attempted |
| S05 | `install_official.py --status` post-install | 0 | `official_server=installed launcher=available` |
| S06 | `install_acp.py install` — standalone provider registration into empty `HERMES_HOME` | 0 | provider installed + post-verified |
| S07 | `install_acp.py status` | 0 | `official_server/official_launcher/provider_registered/provider_executable = available` |
| S08 | `install_acp.py verify` — provider manifest + **real unauthenticated ACP `initialize` probe through the harness** | 0 | `provider registration and unauthenticated ACP initialize verified` (1.05 s) |
| S09 | `scripts/acp_probe.py -- launcher` — direct real-server probe | 0 | full summary below |
| S10 | `install_official.py --uninstall` | 0 | removed exactly the pinned version dir + managed launcher |
| S11 | `--status` post-uninstall | 1 | back to `missing` |
| S12 | `--verify` post-uninstall | 2 | fail-closed missing-binary diagnostic naming the pin |
| S13 | `install_official.py install` reinstall (fresh download, same pin) | 0 | 16.82 s; SHA-256 verified again before extraction |
| S14/S15 | `--status` / `--verify` after reinstall | 0 | restored; `official ACP install verified; no authentication was attempted` |
| S16b | foreign (unmanaged) launcher file placed, then `--uninstall` | 2 | refused untouched: `Refusing to remove an unmanaged official ACP launcher`; version dir and foreign file intact |
| S16c | same state, `install` | 2 | refused: `Refusing to replace an unmanaged official ACP launcher` (fails before any write) |
| S17 | documented recovery (remove foreign file, re-run install) | 0 | managed state restored |
| S18 | `install_acp.py delete` | 0 | removed only the standalone provider projection + pinned server; report explicitly states catalog-managed installs are never removed and no auth/session state was touched |
| S19/S20/S21 | `install` → `status` → `verify` after delete | 0 | full clean-room reinstall cycle green again |
| T01 | official `hermes plugins validate hermes-plugin/antigravity-acp --install-deps` in clean Hermes | 0 | all admission checks pass; two pre-existing advisory warnings on private core imports in `hermes_compat.py` (non-blocking, unchanged from CI) |
| T02 | provider selection via real `providers.get_provider_profile("antigravity-acp")` in clean Hermes | 0 | registered; `display_name="Antigravity ACP (official)"`, `base_url="acp://antigravity"`, `auth_type="external_process"`; `process_command` natively resolved to the clean-room launcher; **no command override used** |
| T03/T07 | model discovery entry: real plugin `AntigravityACPClient.list_models()` → real server (unauthenticated) | 0 (bounded probe) | `session/new` refused by the real server — auth boundary, see below |
| T04 | `profile.fetch_models()` (exact Hermes picker entry point) | 0 | `None` (documented fail-soft picker floor when live discovery fails; provider keeps its curated fallback list) |
| T05 | `tests/test_vanilla_hermes_seam.py` under the clean-room official Hermes (`HERMES_STRICT_SEAM_TEST=1`, exact commit/tree binding) | 0 | 1 passed — registration + standalone client construction against real Hermes core |
| T06 | Path A: `hermes plugins install antigravity-acp-provider` (real catalog attempt) | 1 | `Error: 'antigravity-acp-provider' is not in the Hermes plugin catalog…` → `BLOCKER-CATALOG-PATH-A` |

### Real-server unauthenticated `initialize` (step S09; historical observation, not class-2 acceptance evidence)

Observed response from the official, unmodified Google binary 1.4.4
(protocol metadata only; no credentials can appear in this surface):

```json
{
  "protocolVersion": 1,
  "agentInfo": {
    "name": "antigravity-acp",
    "title": "Google Antigravity",
    "version": "1.4.4"
  },
  "authMethods": [
    {"id": "oauth-personal", "name": "Log in with Google", "description": "Log in with your Google account"},
    {"id": "oauth-business", "name": "Log in with Gemini Enterprise", "description": "Log in with your Gemini Enterprise account"},
    {"id": "gemini-api-key", "name": "Gemini API key", "description": "Use an API key with Gemini Developer API"},
    {"id": "agent-platform", "name": "Gemini Enterprise Agent Platform", "description": "Use Gemini Enterprise Agent Platform (formerly Vertex AI) with Application Default Credentials or an API key"}
  ],
  "agentCapabilities": {
    "loadSession": true,
    "promptCapabilities": {"image": true, "audio": true, "embeddedContext": true},
    "mcpCapabilities": {"http": true, "sse": true},
    "sessionCapabilities": {"list": {}, "additionalDirectories": {}, "resume": {}},
    "auth": {"logout": {}},
    "_meta": {"antigravity": {"tier": true, "systemPrompt": {"append": true}}}
  }
}
```

The client-side wire was, by construction of `scripts/acp_probe.py`, exactly
one `initialize` request — zero `authenticate`/login/OAuth frames were sent
in any step of this record.

### Model discovery entry and its auth boundary (steps T02–T04/T07)

Provider **selection** was observed in the private-container log (T02:
registered, natively resolved launcher — a historical observation, not
acceptance evidence). Real-server model **listing** was attempted through
the production seam (`AntigravityACPClient.list_models` → `session/new`) with
zero credential state present. The real server refused it (redacted
diagnostic, matching the repository's own redaction contract; sha256-16 of
the full message `8462be5234ff0a07`, 599 chars):

> `Antigravity ACP session/new failed: code=-32000; Authentication required;
> data.message=No authentication method selected. Either call the
> `authenticate` method (supports oauth-personal, gemini-api-key,
> agent-platform), or set `auth.type` in settings.json
> (`$CR94/home/.gemini/antigravity-acp/settings.json`) to one of: …`

The client failed closed and surfaced this bounded diagnostic without
issuing any `authenticate` frame (an auth method name is **advertised**,
never implicitly selected). Consequently **real unauthenticated model
listing is NOT VERIFIED — it is gated behind the server's authentication
boundary**, which this record did not cross. Real model listing requires an
authenticated session. The fake-ACP suite remains the evidence for listing
mechanics.

## Integrity: zero credential state, zero host mutation

These are private-container observations scoped to what the observed
processes touched inside the disposable `HOME`/`HERMES_HOME` and the
captured streams. They record no credential *use* by those processes; they
are not offered as proof of isolation from the pre-existing OS user's state
(see `BLOCKER-FRESH-UID` above).

- Decoy credential files seeded in the disposable HOME (`.env`,
  `.config/gcloud/application_default_credentials.json`,
  `credentials.json`): all three **byte-identical** to their pre-run SHA-256
  after every step (`UNCHANGED`).
- **No vendor state was created anywhere under the disposable HOME** by the
  official binary: outside installer-owned trees the only files present are
  the three seeded decoys (the server's own suggested
  `home/.gemini/antigravity-acp/settings.json` was named in an error string
  but never created).
- `HERMES_HOME` contains only Hermes-CLI-owned scaffolding; its 22 non-cache
  state files were shape-scanned with the repository's own credential-shape
  classes: the only matches were two function-signature annotations of the
  `api_key` parameter in the plugin's own installed source code (false
  positives of the shape classifier, no credential material).
- Host-level baseline: before the run, `~/.local/opt/antigravity-acp` and
  `~/.local/bin/antigravity-acp-official` were **absent** for the real user;
  after the run they remain **absent**. No pre-existing installation was
  created, changed, or removed outside `$CR94`.
- All 64 captured raw stdout/stderr files from every step were scanned with
  the repository's own `scripts/audit_public_tree.py` secret-content rules
  plus the `install_acp.py` credential-shape classes: **ZERO FINDINGS**.
- Environment audit: the scrubbed per-step environment contained no
  credential-shaped variables (recorded dump).

## Four evidence classes for the private-container log (never conflated)

| # | Class | Private-container log (historical, non-acceptance) |
|---|---|---|
| 1 | auth success | **NOT VALIDATED / NO-GO** — no authentication was attempted in this run |
| 2 | ACP `initialize` handshake | Historical observation only (S08 harness path + S09 direct probe, Linux x86_64, 1.4.4): **NOT EXECUTED** as class-2 clean-room acceptance evidence. The accepted class-2 execution is the hosted dedicated-UID run below (`HOSTED-REAL-INITIALIZE: EXECUTED`), in addition to fake-ACP CI verification |
| 3 | model list discovery | fake-ACP CI: VERIFIED. Real server: **NOT VERIFIED** — the container log observed a discovery entry (provider selection, real client seam, picker entry) but real listing is auth-gated by the server itself (`code=-32000`); no auth frame was sent |
| 4 | real model inference canary | **NOT VALIDATED / NO-GO** — out of scope; no prompt was sent in this run |

## Per-platform verification matrix (Linux is not cross-platform proof)

Registry pin = first-party feed digest present and matched (re-checked
2026-11-07). Fake CI smoke = credential-free registry-pinned install
mechanics in `tests/test_clean_env_e2e_smoke.py` (runs in CI for every
platform). Clean-room execution / real initialize / real inference refer to
**actual execution of the real Google binary in the venue accepted for the
class** — for Linux x86_64 clean-room execution and real initialize, the
hosted dedicated-UID CI chain below (the private-container attempt is not
counted).

| Platform target | registry pin | fake CI smoke | clean-room execution | real initialize | real inference |
|---|---|---|---|---|---|
| Linux x86_64 | MATCH (2026-11-07) | VERIFIED (CI) | **EXECUTED (2026-11-08, hosted dedicated-UID CI — see Hosted section below; the 2026-11-07 private-container attempt is NOT EXECUTED as acceptance evidence)** | **EXECUTED (2026-11-08, hosted CI, unauthenticated; the container-era observation is historical only)** | NOT RUN / NO-GO |
| Linux aarch64 | MATCH (2026-11-07) | VERIFIED (CI) | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED / NO-GO |
| macOS arm64 | MATCH (2026-11-07) | VERIFIED (CI) | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED / NO-GO |
| Windows x64 | MATCH (2026-11-07) | VERIFIED (CI) | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED / NO-GO |
| Windows arm64 | MATCH (2026-11-07) | VERIFIED (CI) | NOT VERIFIED | NOT VERIFIED | NOT VERIFIED / NO-GO |

No claim in this record about Linux x86_64 implies runtime proof on any
other platform; the other four targets remain registry-pinned, not
live-verified. The feed additionally publishes a `darwin-x86_64` target that
this repository does **not** pin; it is out of scope here.

## Explicit unresolved blockers (not PASS)

1. `BLOCKER-CATALOG-PATH-A` — the Issue's "catalog provider registration"
   was attempted for real through the official CLI (`hermes plugins
   install antigravity-acp-provider`, T06) and the public catalog has no
   entry yet ("is not in the Hermes plugin catalog"). Catalog submission is
   a separately approved task (draft entry:
   `docs/plugin-catalog-entry.draft.yaml`). What **was** executed is the
   documented standalone provider projection (`install_acp.py`, T02-verified
   in real Hermes) plus official `hermes plugins validate` admission (T01).
   Path A catalog install therefore remains NOT VERIFIED.
2. `BLOCKER-FRESH-UID` — a separate OS user id was not creatable in the
   private container (no sudo; `unshare` EPERM), and the scrubbed
   `env -i`/isolated-HOME substitution does not establish a separate OS UID
   or credential-state isolation; the private-container chain is
   **NOT EXECUTED** as clean-room acceptance evidence. The criterion was
   re-instrumented in the hosted dedicated-UID venue below, where
   `HOSTED-FRESH-UID: VERIFIED` is evidenced by a real created UID and a
   mode-0600 canary refusal.

## Evidence boundaries

This credential-free record does not establish authenticated inference,
terms compliance, catalog availability, or permission to publish. Those
questions require separate evidence and decisions.

## Reproduction recipe

Reproducing the historical private-container observation (not the accepted
acceptance venue — for re-instrumented acceptance execution use the hosted
`acp-clean-room` CI job documented in the Hosted section below):

From a clean checkout at the tested commit, with `CR94` a disposable root
containing empty `home/` and `hermes-home/` directories (all steps below run
with the scrubbed 5-variable environment documented above; `python3` =
CPython 3.14):

```sh
# pre-state fail-closed diagnostics (expect rc=1 / rc=2)
python3 scripts/install_official.py --status
python3 scripts/install_official.py --verify
python3 scripts/install_acp.py status
# real download + publisher-pin install, then the combined registration
python3 scripts/install_official.py
python3 scripts/install_acp.py install
python3 scripts/install_acp.py status
python3 scripts/install_acp.py verify          # real unauthenticated initialize
python3 scripts/acp_probe.py -- "$HOME/.local/bin/antigravity-acp-official"
# clean uninstall -> fail-closed -> reinstall -> re-verify
python3 scripts/install_official.py --uninstall
python3 scripts/install_official.py --verify   # expect rc=2 missing-binary diagnostic
python3 scripts/install_official.py
python3 scripts/install_acp.py delete
python3 scripts/install_acp.py install
python3 scripts/install_acp.py verify
# independent pin re-verification (compare against the feed JSON digest)
curl -sS https://dl.google.com/agy-extensions/releases/linux/agy-acp-server-1.4.4-linux-x86_64.zip -o /tmp/acp.zip
sha256sum /tmp/acp.zip
# Hermes side: official Hermes at a recorded commit, then provider selection +
# discovery entry probes:
git clone --depth 1 https://github.com/NousResearch/hermes-agent.git
(cd upstream-hermes && uv sync --frozen --python 3.14 --group dev)
upstream-hermes/.venv/bin/hermes plugins validate hermes-plugin/antigravity-acp --install-deps
upstream-hermes/.venv/bin/python -m pytest -q tests/test_vanilla_hermes_seam.py   # strict seam
```

Hermes Core must remain unmodified throughout (`git diff --exit-code` and a
clean `status --porcelain --untracked-files=no` inside the upstream clone
after every step).

## Hosted fresh-UID clean-room CI

The hosted CI job re-instrumented the
`BLOCKER-FRESH-UID` criterion **without deleting it**: the separate-OS-UID
clean room executes as a CI job (`acp-clean-room` in
`.github/workflows/ci.yml`) on a **GitHub-hosted `ubuntu-24.04`** VM. A
dedicated OS user is created with `useradd` and the entire real-binary
chain below runs as that UID with `env -i` (allowlisted variables only), an
empty disposable `HOME`, and an empty `HERMES_HOME`. The prior
private-container `env -i` account above is retained only as a historical
observation log: its status as clean-room acceptance evidence is
**NOT EXECUTED**, as are the earlier Docker-era attempts — none is
retro-promoted, and their env-only scrub never established a separate OS
UID or credential-state isolation.
Catalog submission/install is out of this job's scope; **no** `secrets.*`, Google credentials, login, inference,
or catalog action appears anywhere in the job.

Machine-readable hosted status tokens (parsed by
`tests/test_hosted_clean_room_ci.py`; do not reword without updating it):

```text
HOSTED-CI-CLEAN-ROOM: PASSED
HOSTED-FRESH-UID: VERIFIED
HOSTED-REAL-INITIALIZE: EXECUTED
HOSTED-UNAUTHENTICATED-MODEL-DISCOVERY: NOT VERIFIED (server auth boundary expected; zero authenticate/login frames sent by construction; a real listing requires authentication)
HOSTED-AUTHENTICATED-SESSION: NOT RUN (authentication is forbidden in this job)
HOSTED-REAL-INFERENCE: NOT RUN / NO-GO
HOSTED-CATALOG-INSTALL: OUT OF SCOPE
```

These tokens describe a historical hosted run, not the status of the current
revision. Its original job summary is not available in this recreated
repository. A claim for a particular revision requires a green Actions run
for that exact revision; an older run is never evidence for a newer head.
Inspect this repository's Actions history for the `acp-clean-room` job and
its associated commit before claiming current-revision acceptance. Until then,
no acceptance claim may be made from the pending citation below.

```text
HOSTED-CI-RUN-ID: PENDING
HOSTED-CI-RUN-URL: PENDING
HOSTED-CI-RUN-HEAD: PENDING
HOSTED-CI-JOB: acp-clean-room
```

The following facts were recorded in an earlier historical run. Its original
job summary is unavailable here, so these details cannot be independently
verified from this repository:

| Fact | Value |
|---|---|
| Runner OS | Ubuntu 24.04.5 LTS, kernel `7.0.0-1017-azure`, x86_64 |
| Clean-room identity | `acpcr94` uid=1002 (runner uid=1001); `sudo` unavailable |
| OS-UID separation proof | runner-private mode-0600 canary → `denied(PermissionError)` |
| Scrubbed child env | exactly the 10 allowlisted `env -i` keys |
| Official binary | ACP 1.4.4; archive sha256 `baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a` verified before extraction on all 3 downloads |
| Hermes Core | unmodified `a9ff9799e273f525b82718cdc69fdec71b1dca5a`; `git diff`, `git diff --cached`, `status --porcelain` all clean |
| Chain | 28/28 fail-closed steps PASS in 45.1 s, executed entirely as uid 1002 |
| Real unauthenticated `initialize` | 3 executions (harness `verify`, `acp_probe.py`, provider `verify`); response metadata matched the pinned gate exactly |
| Model discovery | server auth boundary reached; 0 authenticate/login/prompt frames; server answer recorded only as counts, a sha256-16 fingerprint, and class names |
| Uninstall/reinstall | clean official uninstall→reinstall and provider delete→reinstall cycles (3 full redownloads) |
| Fail-closed diagnostics | rc=1/rc=2 states pre- and post-install; foreign-launcher ownership refusals (install and uninstall refused; documented recovery) |
| Integrity as the UID | 3 decoy credentials byte-identical; no `.gemini` vendor state; installs owned by uid 1002; zero unexpected HOME entries against the run's baseline; zero `HERMES_HOME` findings outside the plugin's own installed source |
| Runner end-state | runner user confirmed free of ACP/Hermes/Google state at job end |

### Contract executed by the job (driver: `scripts/hosted_clean_room_ci.py`)

- Venue controls, all fail closed: `runs-on: ubuntu-24.04`; driver refuses
  root; refuses to start unless `/etc/os-release` reports Ubuntu 24.04 and
  `/home/runner` exists; refuses any environment variable outside the
  allowlisted `env -i` set; refuses to proceed if the clean-room UID has
  `sudo`.
- OS-UID separation proof: the runner user plants a mode-0600 private
  canary file; the driver fails closed unless reading it raises
  `PermissionError` for the clean-room UID, and the driver's UID differs
  from both root and the runner user.
- Supply chain: the workflow preflight asserts the registry pin equals the
  reviewed digest `baf31b7a97602dee359cf2a43f72b6e11c6bf354be874987d80660cd3526bb6a`
  and version `1.4.4`; `install_official.py` verifies the digest **before
  extraction** on each of the three downloads the chain performs.
- Step chain (identical expectations in `STEP_EXPECTATIONS`): pre-install
  fail-closed diagnostics (rc=1/rc=2/rc=1), real install, provider
  registration, status/verify including real unauthenticated `initialize`
  through the harness, a second real `initialize` via `scripts/acp_probe.py`
  with the response metadata strictly gate-verified against the pinned
  expectations (protocolVersion 1; exact agentInfo; the four advertised auth
  **method ids**, never used to authenticate), uninstall, post-uninstall
  fail-closed diagnostics, reinstall, foreign-launcher ownership refusals
  (uninstall refused, install refused, documented recovery), provider
  delete/reinstall cycle, and a third real `initialize` via `verify`.
- Hermes side (official unmodified Core at the reviewed pinned commit,
  installed with `uv sync --frozen --python 3.14 --group dev` **as the
  clean-room UID**): `git diff`/`git diff --cached`/`status --porcelain`
  stay clean; then `scripts/clean_room_provider_probe.py` executes real
  `providers.get_provider_profile("antigravity-acp")` selection (exact
  `display_name`/`base_url`/`auth_type`, native override-free launcher
  resolution under the clean-room `HOME`) and the model-discovery entry
  (`AntigravityACPClient.list_models` -> real server). The listing attempt
  is expected to hit the server's authentication boundary; whatever the
  server answers is recorded only as counts, boolean boundary flags, a
  sha256-16 fingerprint, and credential-shape class names — never server
  text, never model ids. `profile.fetch_models()` must return `None`
  (documented fail-soft picker floor). Zero `authenticate`/login/prompt
  frames by construction: the probe has no authentication code path.
- Output hygiene: every captured stream becomes a
  `{lines, bytes, sha256_16}` summary plus class names
  (`_server_stderr_summary` contract); repository-authored text is disclosed
  only after passing the repository's own scanners. The produced evidence
  JSONL is re-scanned fail-closed by a dedicated workflow step before it is
  published to the run summary, and a final step asserts the runner user
  has no live ACP/Hermes/Google state at the end.
- Integrity as the UID: three seeded decoy credential files must stay
  byte-identical; no vendor state (`.gemini`) may appear anywhere under
  the disposable HOME; installed trees must be owned by the clean-room
  UID; the `HERMES_HOME` tree is scanned with the repository's own
  credential-shape classes and any finding outside the plugin's own
  installed source (the documented `api_key` annotation false positive)
  fails the job.

Per-step results, runner fingerprints, UIDs, the exact Hermes commit/tree,
auth-boundary fingerprints, and the Actions run identity are recorded from
the executed run only — they are filled in below the PENDING tokens by the
delivery commit after the job first goes green on the PR head, and until
then this section supports no pass claim.

## Evidence inventory

Per-step structured records (name, exit code, timestamp, byte counts, and
SHA-256 of each captured stdout/stderr stream), the scrubbed environment
dump, feed snapshot, decoy hash baselines, and the integrity report were
produced during the run under the disposable `$CR94/evidence/` tree. Raw
streams are retained in the worker handoff metadata scope, not committed:
they contain absolute clean-room paths and are covered by the repository's
own audit rules only after sanitization (this document is the sanitized,
committed artifact; `scripts/audit_public_tree.py` runs over it in CI).
