# Release verification matrix (issue #28 Phase B)

This is the version-controlled contract for what a release candidate of
this plugin must prove on each native target before it may be published.
The machine-readable source of truth is
[`release/verification-matrix.json`](../release/verification-matrix.json);
this page explains the stages and records the honest current status. The
enforcement is `scripts/release_gate_check.py` wired as the conditional
`Release gate` job in `.github/workflows/ci.yml` — not a manual checklist.

## How release verification runs

1. Cut nothing yet: pick the exact candidate commit SHA on `main`
   (full 40 hex).
2. `gh workflow run ci.yml -f candidate_sha=<sha>` — every lane checks
   out exactly that SHA and refuses to run on anything else.
3. `candidate-identity` binds the candidate to the remote history
   (object exists, reachable from a branch, relation to current `main`
   head).
4. Each evidence lane attests its own `git rev-parse HEAD` plus the list
   of matrix stages its steps actually executed.
5. `Release gate` fails closed unless every required target×stage cell is
   attested by a *successful* lane at *exactly* the candidate SHA.

The gate blocks, at minimum:

- evidence from any other SHA (attested HEAD ≠ candidate);
- a required lane that failed, was cancelled, was skipped, or never
  reported;
- a lane that stopped running a stage while still claiming it (the
  drift guard in `tests/test_release_gate_contract.py` ties each
  attestation string to the command fragments in the same lane block);
- an optional lane's success substituting a required cell (coverage is
  evaluated per covering lane, never globally);
- partial-platform aggregation (every required cell is checked
  individually; one FAIL is the whole verdict FAIL);
- unknown job names or malformed inputs (fail closed, no defaults).

The gate does NOT auto-tag or publish. Publication remains the existing
manual `publication-gate.yml` + `scripts/publication_gate.py` flow; the
tag-time policy should require that a `Release gate` PASS exists for the
exact tag SHA (that policy lives outside this repo's control and is a
maintainer step).

## Stages

| stage | meaning |
| --- | --- |
| `binary_publisher_pin_sha256` | the official GitHub Release asset is fetched and its SHA-256 equals the pinned value before anything executes |
| `install_status_verify_uninstall` | real installer `install` → `status` → `verify` → `--verify-only` → `--uninstall` against a throwaway Hermes home |
| `provider_registration_enabled` | `antigravity-acp` appears in `hermes plugins list` as enabled in a clean Hermes home |
| `provider_selection_factory` | the provider is selectable and the factory constructs the ACP-backed provider (clean-room probe) |
| `acp_initialize_unauthenticated` | ACP `initialize` round-trip against the real binary with no account credentials |
| `platform_security_hardening` | target-specific hardening evidence (clean-UID child / process-tree teardown on Windows) |
| `error_timeout_permission_failclosed` | protocol-level error, timeout, and permission-denied paths fail closed |
| `session_resume_recovery` | session resume/recovery semantics hold |

The last two are protocol-level: they are verified once on the shared
fake-ACP harness (`fake-acp` lane) and recorded per target as
`shared_with: fake-acp`. They are not re-executed per OS, and the matrix
says so explicitly rather than pretending otherwise.

## Current honest status (2026-11-13, pre-first-hosted-run)

Evidence class per cell lives in the JSON; this table mirrors it.

| target | binary pin | install/verify | provider reg | selection/factory | initialize | hardening | error/timeout | resume |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| linux-x64 | PASS | PASS | PASS | PASS | PASS | PASS | PASS¹ | PASS¹ |
| windows-x64 | PASS | PASS | PASS | **NOT_RUN** | PASS | PASS | PASS¹ | PASS¹ |
| windows-arm64 | PASS | PASS | PASS | **NOT_RUN** | PASS | **BLOCKED** | PASS¹ | PASS¹ |
| macos-arm64 | PASS | PASS | **BLOCKED²** | **BLOCKED²** | **BLOCKED²** | **BLOCKED** | PASS¹ | PASS¹ |
| linux-aarch64 | PASS | PASS | **BLOCKED²** | **BLOCKED²** | **BLOCKED²** | **BLOCKED** | PASS¹ | PASS¹ |

¹ shared protocol-level evidence from the `fake-acp` lane.

² These hosted lanes (macOS ARM64, Linux aarch64 provider registration,
selection/factory probe, and `initialize`) are introduced by this Phase B
change and have not executed on GitHub-hosted runners yet. They stay
BLOCKED with `evidence_class: not_executed` until a real run URL exists;
the first green hosted run at a candidate SHA flips them to PASS with the
run cited in the JSON. Until then the README's platform-support claims
stay limited to what is proven.

Remaining known limitations:

- Windows x64/arm64 `provider_selection_factory`: the hosted Windows
  lanes have no Hermes provider selection UI; the clean-room probe is
  Linux-only. NOT_RUN, optional.
- `platform_security_hardening` beyond the Windows process-tree teardown
  and the clean-UID child: no target-specific harness yet. BLOCKED,
  optional.
- `session_resume_recovery` per-OS with the real binary: only the
  shared fake-ACP protocol evidence exists.

## What Phase B does and does not change for day-to-day CI

Phase B adds a dispatch-only verification path. It does not shorten the
normal `main` push pipeline; that reduction is the separate Phase A
follow-up PR gated on this phase's evidence (see
[`ci-cost-phase-b.md`](ci-cost-phase-b.md)).
