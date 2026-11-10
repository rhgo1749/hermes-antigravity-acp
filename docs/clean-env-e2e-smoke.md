# Clean-environment E2E smoke: evidence record and verification boundary

Companion to `tests/test_clean_env_e2e_smoke.py` for clean Hermes
environment install and diagnostic reproducibility. This page is
the verification-reporting artifact: it names exactly what the credential-free
suite proves, what it never proves, and how the four evidence classes stay
separated.

## What the suite covers

One fresh user, an empty (absent) `HERMES_HOME`, and no Docker, profile-mux,
account-mux, custom Hermes Core patches, or `/quota` skill:

- **install → status → verify → delete → reinstall** through the combined
  standalone script (`scripts/install_acp.py`), with the reinstall
  re-verifying against the same reviewed publisher pin (SHA-preserved
  reinstall).
- **Path A + Path B composition**: a catalog-managed provider (Hermes core's
  install record + sidecar) is never overwritten or deleted by the server
  lifecycle; server-only uninstall is the documented recovery; listing keeps
  working from the catalog bytes.
- **provider registration + model listing** from the installed plugin tree
  against a fake ACP launcher, with `/quota` nowhere present, plus truthful
  telemetry (`usage=None`, `status="unavailable"`) in a simulated turn.
- **failure-mode equivalence classes** with safe, actionable diagnostics:
  missing server binary, PATH misconfiguration, pinned-version mismatch,
  interrupted download, tampered archive, unauthenticated probe timeout /
  headless login-wait (raw server stderr never echoed — fingerprint-only
  summaries), and the subprocess hard-limit timeout path.
- **RED tripwires**: the suite goes RED if any step opens a credential-shaped
  file, forwards `GOOGLE_ACCESS_TOKEN` to the provider child (the documented
  no-Hermes fallback allowlist), issues an `authenticate`/login/OAuth method
  on the ACP wire, echoes raw or credential-shaped server stderr or leaks
  secrets in a default diagnostic, or conflates the evidence classes below.
- **registry-pinned platform smoke** (fake archives): every platform in
  `antigravity_acp/registry.py` installs through the same mechanics with its
  pinned executable name and launcher arguments. This validates pin
  well-formedness and install mechanics only — it is not live OS execution.

Run it with:

```sh
python3 -m pytest -q tests/test_clean_env_e2e_smoke.py
```

## Four evidence classes (never conflated)

The suite's fake-ACP JSONL logs bucket every observed wire method. Delivery
time status for this repository's CI and test environment:

| # | Class | Meaning | Status in this environment | Evidence source |
|---|-------|---------|---------------------------|-----------------|
| 1 | **auth success** | a permitted authentication completed | **NOT VALIDATED / NO-GO** — no user-approved ToS-compliant auth path is available here; tests never authenticate | (none; must never be inferred from class 2–4) |
| 2 | **ACP `initialize` handshake** | unauthenticated ACP v1 handshake completes | **VERIFIED against fake ACP** (credential-free protocol mechanics). Real-server `initialize` executed by this suite: NOT EXECUTED (this suite never installs the real proprietary binary). The separate hosted dedicated-UID `acp-clean-room` CI chain is described in `docs/official-server-1.4.4-clean-room-e2e-2026-11-07.md`; it is not suite evidence. An earlier private-container run remains NOT EXECUTED as clean-room acceptance evidence — an env-only scrub does not establish a separate OS UID or credential-state isolation. | fake-ACP log rows, method `initialize` |
| 3 | **model list discovery** | server advertises models through a session | **VERIFIED against fake ACP**, with `/quota` absent and listing unaffected by its absence. Real-server listing is outside this credential-free suite; unauthenticated `session/new` returns `Authentication required`. | fake-ACP log rows, method `session/new` + non-empty model payload |
| 4 | **real model inference canary** | a real model answered a prompt | **NOT VALIDATED / NO-GO** — real inference may only run via a user-approved, ToS-compliant auth path; nothing here approximates it, and no NO-GO here may be reported as a pass elsewhere | (empty by construction — the real server binary is never downloaded or executed by tests) |

A fake-ACP `session/prompt` appears only in the protocol-simulation bucket
(`simulated_turn`), used to prove the wire and the truthful-telemetry shape
(`completion.usage=None`, `antigravity_usage_telemetry.status="unavailable"`
with `/quota` absent). It is never class-4 evidence.

## OS verification tiers

See README "OS support and verification tiers". Summary: Linux x86_64 is the
executed clean-room tier — first-party digest checks run in CI, and the
real-binary install → status → verify → unauthenticated `initialize` →
uninstall → reinstall lifecycle was executed by the hosted dedicated-UID
`acp-clean-room` CI job, cited with its green Actions run in
`docs/official-server-1.4.4-clean-room-e2e-2026-11-07.md`. The earlier
2026-11-07 private-container attempt is retained there as a historical
observation log only and remains **NOT EXECUTED** as clean-room acceptance
evidence; it must not be retroactively promoted. This
suite still never executes the real binary.
macOS arm64, Windows x64,
Windows arm64, and Linux aarch64 are registry-pinned with first-party
digests and covered only by the credential-free CI install mechanics smoke;
on all four the real Google binary lifecycle remains **NOT EXECUTED in CI
and not live-verified**.

## Standing boundaries

- No test, script, or CI step in this suite authenticates, reads credential
  files or credential-bearing environment variables into the provider child,
  downloads the real Google binary, or issues a real model call.
- The real-inference canary remains **NO-GO until a maintainer explicitly
  approves a ToS-compliant authenticated path**; promoting any tier or any
  evidence class requires fresh, executed, recorded evidence.
- `status` and `verify` remain strictly non-authenticating: their only ACP
  wire traffic is the unauthenticated `initialize` handshake (asserted).
