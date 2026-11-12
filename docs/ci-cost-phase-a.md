# CI cost: Issue #28 Phase A

Scope: PR changed-path classification only. Baseline `origin/main`:
`f298c28ff52dc1d5a1d193d1243124d2be3563b0`.
This is not a release gate or a Gateway/eval replacement. No merge, tag,
release, production deployment, required-check or ruleset change is included.

## Policy and review boundary

Only these exact, content-reviewed test files take the fast route:

- `tests/test_acp_thinking_level.py`: reasoning-effort/environment mapping and
  server-authored thinking-level requests against Python fake ACP children.
- `tests/test_model_surface_selection.py`: merging and selecting server-authored
  legacy/config-option models against Python fake ACP children and stub providers.

Neither test selects native archives, invokes an installer, asserts native OS/ABI
behavior, or uses a real vendor binary. The list is intentionally small; it does
not certify every other fake-transport test. New paths, renamed tests, fixtures,
helpers, platform, native-binary, packaging, deployment and MUX tests remain
strongest-scope until explicitly reviewed. Review responsibilities again before
putting platform-sensitive assertions into a listed file. A path list cannot
prove semantic neutrality of future edits; this remains a code-review boundary.

This list controls **lane applicability, never pytest discovery**. The workflow
and gate implementation are unchanged. All tests still auto-discover in `fake-acp`
with the same single documented upstream-runtime-only exclusion, which still runs
in the strict Core jobs. Unknown `tests/` paths are checked before Markdown globs,
so a new Markdown test fixture no longer silently counts as documentation.

Ordinary plugin changes retain Linux x64, Windows x64 and macOS ARM64 validation.
Main pushes and manual dispatch still require **all five native targets** regardless
of path. No schedule or new job is introduced.

## Before / after path simulation

The table was produced by executing `classify_paths` from the exact baseline and
candidate source on the same inputs. These are **local policy results**, not
hosted executions of synthetic PRs. New reviewed files must be explicitly admitted
to the policy in a reviewed change; a new filename is never implicitly trusted.

`F`: the three unconditional fast jobs (discovery/static/security audit plus latest
and minimum-supported Hermes strict gates); `OS`: Linux x64 clean room, Windows
x64, macOS ARM64; `ARM`: Windows ARM64, Linux aarch64. Change scope and `CI gate`
run for every case. Delete/rename/move uses real `git diff --no-renames` tests.

| Change | Before | After |
|---|---|---|
| Docs only | F | F |
| Plugin only | F+OS | F+OS |
| Reviewed thinking-level test only | F+OS+ARM | F |
| Reviewed model-selection test only | F+OS+ARM | F |
| Plugin + reviewed test | F+OS+ARM | F+OS |
| Platform/installer test | F+OS+ARM | F+OS+ARM |
| Installer | F+OS+ARM | F+OS+ARM |
| Registry / publisher pin | F+OS+ARM | F+OS+ARM |
| MUX packaging | F+OS+ARM | F+OS+ARM |
| MUX runtime | F+OS+ARM | F+OS+ARM |
| CI workflow | F+OS+ARM | F+OS+ARM |
| Gate script | F+OS | F+OS |
| CI contract test | F+OS+ARM | F+OS+ARM |
| Unknown new test | F+OS+ARM | F+OS+ARM |
| Unknown path | F+OS+ARM | F+OS+ARM |
| Unreviewed test Markdown fixture | F | F+OS+ARM |
| Delete installer | F+OS+ARM | F+OS+ARM |
| Move installer to docs (both paths) | F+OS+ARM | F+OS+ARM |
| Rename reviewed test (both paths) | F+OS+ARM | F+OS+ARM |
| Move native test onto reviewed name | F+OS+ARM | F+OS+ARM |
| Any `main` push, including docs-only | F+OS+ARM | F+OS+ARM |
| Manual full-matrix dispatch | F+OS+ARM | F+OS+ARM |
| Empty diff, missing/invalid commit or git error | F+OS+ARM | F+OS+ARM |

## What the lanes actually prove

| Lane group | Executed boundary retained |
|---|---|
| `fake-acp` | Automatic credential-free regression discovery, Ruff and public-tree/security/distribution audit; fake archives/transport are not native execution. |
| `upstream-hermes-compat`, `catalog-floor-gate` | Unconditional official catalog admission and strict real-Core provider/runtime/delegate-affinity seams on latest upstream `main` and floor `v0.21.6`; fake ACP, no vendor inference. |
| Linux x64 | Official pinned binary lifecycle in a dedicated-UID clean room, Hermes provider selection/discovery entry and fail-closed diagnostics. The clean-room Core ref is its existing pin, not the latest-Core lane. |
| Windows x64 / ARM64 | Actual Windows installer, native-architecture assertion, enabled Hermes provider registration, unauthenticated ACP `initialize`, login-helper execution-path probes without login. Not identical to the Linux clean-room isolation contract. |
| macOS ARM64 / Linux aarch64 | Native-arch assertion, publisher-pinned download + SHA-256, install/status/verify/unauthenticated initialize/uninstall/absence. No Hermes provider registration on either lane, no dedicated-UID isolation. |

SHA-256 verification and all five registry targets are unchanged. No lane proves
authentication, authenticated model discovery, or real model inference.

## Observed pre-change baseline

Raw source: GitHub REST `GET /repos/rhgo1749/hermes-antigravity-acp/actions/runs?per_page=100`
and `GET /repos/rhgo1749/hermes-antigravity-acp/actions/runs/{run_id}/jobs`.
The 20 newest CI runs at collection after tier introduction contain 16 PR runs and
4 main pushes, **not** a representative mix of every scope. Every sampled run
executed all ten jobs; 196 job conclusions were success and 4 failure. Each run's
latest returned job set is used once (not all historical attempts). Run
`43192276794` is attempt 2. Run `43255929068` was initially in progress but its
job snapshot was completed; its success/head was subsequently read back.

Execution = `completed_at - started_at`. Delay = observable
`started_at - created_at` from each job object. This is **not a verified pure
runner-queue measurement**: these timestamps do not separate scheduler, startup,
concurrency or dependency waiting. In particular, do not add dependency duration
to this delta or assume the job was created at workflow start. The downloadable
row ledger also retains run-creation-to-job-start lead time, which includes graph
waiting and must not be called queue time. There is no separate `queued_at` field.
Eight negative created-to-start records in attempt-2 run `43192276794` are
excluded from delay statistics only; no explanation for those API timestamps is
asserted. Execution sample sizes remain unchanged. No missing data is called zero.

All units below are **seconds**. P95 uses linear interpolation at `(n-1)*0.95`;
small samples (especially four pushes) are descriptive, not forecasts.

| Event | Job | Execution n | Median | P95 | Delay n | Delay median | Delay P95 |
|---|---|---:|---:|---:|---:|---:|---:|
| pull_request | ci-gate | 16 | 5.00 | 11.25 | 16 | 2.00 | 2.25 |
| pull_request | catalog-floor-gate | 16 | 51.00 | 59.00 | 15 | 2.00 | 3.30 |
| pull_request | change-scope | 16 | 6.00 | 19.25 | 15 | 2.00 | 2.30 |
| pull_request | fake-acp | 16 | 67.00 | 84.25 | 15 | 2.00 | 3.00 |
| pull_request | acp-clean-room | 16 | 91.00 | 157.50 | 15 | 2.00 | 2.00 |
| pull_request | linux-aarch64 | 16 | 16.00 | 49.25 | 15 | 4.00 | 4.00 |
| pull_request | upstream-hermes-compat | 16 | 58.50 | 76.75 | 15 | 2.00 | 3.00 |
| pull_request | windows-arm64 | 16 | 1076.50 | 1301.25 | 15 | 2.00 | 2.00 |
| pull_request | windows-x64 | 16 | 305.50 | 332.75 | 15 | 2.00 | 2.30 |
| pull_request | macos-arm64 | 16 | 16.00 | 37.25 | 16 | 4.00 | 391.50 |
| push | ci-gate | 4 | 4.50 | 5.85 | 4 | 2.00 | 2.00 |
| push | catalog-floor-gate | 4 | 50.00 | 109.65 | 4 | 2.00 | 3.70 |
| push | change-scope | 4 | 5.50 | 6.00 | 4 | 1.50 | 2.00 |
| push | fake-acp | 4 | 68.00 | 70.70 | 4 | 2.00 | 2.00 |
| push | acp-clean-room | 4 | 100.50 | 145.45 | 4 | 2.00 | 2.00 |
| push | linux-aarch64 | 4 | 15.00 | 18.40 | 4 | 4.00 | 4.00 |
| push | upstream-hermes-compat | 4 | 58.50 | 59.00 | 4 | 2.00 | 2.00 |
| push | windows-arm64 | 4 | 1140.50 | 1394.50 | 4 | 2.00 | 3.70 |
| push | windows-x64 | 4 | 301.50 | 320.00 | 4 | 2.00 | 2.00 |
| push | macos-arm64 | 4 | 16.50 | 19.70 | 4 | 303.00 | 603.00 |

Windows ARM64 still dominates execution: PR median 1076.50 s, push median
1140.50 s. The longest individual measured step was **1250 s** in
`Install official Hermes without interactive setup`. That step includes fetching
and executing the official installer; the data does **not** isolate download,
dependency installation or emulation costs. Windows x64 PR median is 305.50 s.
Do not attribute the entire difference to network download or ARM emulation.

### Reproducible sample identities

| Run | Event | Attempt | HEAD SHA |
|---|---|---:|---|
| [43192276794](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43192276794) | pull_request | 2 | `115863b8f01961d60819e87d2415ec6cbcbe3c45` |
| [43198795406](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43198795406) | pull_request | 1 | `8c054be1eaa4230a87b4e5f9f23a56e3fe74ae09` |
| [43207664192](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43207664192) | pull_request | 1 | `cd0bf1a52a341c053e175ed7f476fbb8750e2ed7` |
| [43213027903](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43213027903) | push | 1 | `874eea1a5084cc04367ae916b89b22e30d274d5a` |
| [43219227184](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43219227184) | pull_request | 1 | `4940117fdc46b0f2b6da64a30805a00671016919` |
| [43219722838](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43219722838) | pull_request | 1 | `4fc8a0be77ab70b7c299aae3497ac2e19acb20e6` |
| [43224725538](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43224725538) | pull_request | 1 | `0685e50e61d6868e1ad37c6276add7feace4893a` |
| [43226435362](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43226435362) | pull_request | 1 | `fe45501bfd9ec22bda187c1f7954677d3e14d044` |
| [43227457811](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43227457811) | pull_request | 1 | `a1bd54bbfa0a02e50237483390033de8bc266ee0` |
| [43228275833](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43228275833) | pull_request | 1 | `b3c2613327bf755d95950c198fb03bf908102428` |
| [43229528605](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43229528605) | pull_request | 1 | `14ac4ed4dae8830f65e4cc6284f2e01646eb8254` |
| [43232687159](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43232687159) | push | 1 | `5a1938c6625be331cf951da2957935e7d985aa7e` |
| [43232767380](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43232767380) | pull_request | 1 | `97c0fc8d8e4a8442927bfd3db7c3715af46d9ead` |
| [43238628092](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43238628092) | pull_request | 1 | `7762c321a808abebe9e1d65f4343c21ba95a1457` |
| [43240222027](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43240222027) | pull_request | 1 | `ffd1f3f1ec5d804b403d9b7d23ff4f990f5b0cc6` |
| [43241073859](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43241073859) | pull_request | 1 | `0c77cb3ca1fdb5c7fb77cc0bdadbfc2c543ca269` |
| [43241671661](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43241671661) | pull_request | 1 | `1ffbc49d19e31fa29b7db842911ccaa5bf3ff88f` |
| [43242062938](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43242062938) | push | 1 | `dbc6e6db2cb4829f380ad99a4e5b092704758504` |
| [43246272128](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43246272128) | pull_request | 1 | `c3b898c189f2167f7b8fa337f392c1caebe95c9e` |
| [43255929068](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43255929068) | push | 1 | `f298c28ff52dc1d5a1d193d1243124d2be3563b0` |

Fetch each linked run's jobs using the endpoint above and compute the timestamp
deltas as defined here. Raw API snapshots and the 200-row CSV are retained with
the local evidence handoff, not installed as runtime inputs or new CI tooling.

## Counterfactual estimate versus observed savings

**Measured baseline:** durations above are actual hosted timestamps.
**Local result:** neutral test-only changes select F; plugin + reviewed neutral
test selects F+OS rather than F+OS+ARM.
**Estimated resource reduction:** for each of the 16 sampled PRs, sum the two ARM
job execution durations, then take the median: **1096.0 s (18.27 runner-minutes)**
per analogous plugin+reviewed-test PR. Test-only F would omit five native jobs:
paired-sum median **1548.5 s (25.81 runner-minutes)**. These counterfactuals assume
the historical lanes would otherwise have run and do not predict future timings.
They are not measured post-change reductions. Concurrent runner-minutes are
summed resources, **not** elapsed workflow time. The median difference in max job
execution length with/without ARM is 781.0 s; even that is only an idealized
critical-lane estimate, not actual workflow/queue savings.

**Observed post-change optimized-scope hosted savings: NOT RUN.** This PR changes
the CI contract test itself (intentionally full scope), so its hosted run exercises
the whole matrix rather than an optimized ordinary-plugin scope. Synthetic cases
above are not labeled hosted PASS. The final PR body records the exact candidate
HEAD, run URL, all job conclusions and real candidate timing when available.

**Money:** the repository API reports `private=false`. All observed runner labels
are standard labels (`ubuntu-latest`, `ubuntu-24.04`, `ubuntu-24.04-arm`,
`windows-2022`, `windows-11-arm`, `macos-15`). Per
[GitHub Actions billing](https://docs.github.com/en/billing/managing-billing-for-your-products/managing-billing-for-github-actions/about-billing-for-github-actions),
standard hosted compute is free for public repositories. Therefore this work
reduces resource use/latency, not a demonstrated paid runner bill. Account invoices,
storage/cache charges and larger runners were not measured. No private-repository
rate multiplier or estimated dollars are presented as actual spend.

## Regression evidence and remaining risk

The pre-change CI contract suite passed 42 tests. Adding the Phase A regression
cases against unchanged baseline production code produced **9 failed, 115 passed**
(exit 1): four neutral-test classification cases, four real Git add/modify/delete/
move cases, and the unreviewed Markdown fixture tripwire. After the classifier
change the same suite produced **124 passed** (exit 0). Native/installer/registry/
MUX/workflow/unknown scope, invalid commits, diff errors, every required job's
failure/cancellation/missing/skipped outcome, unexpected jobs, malformed/missing/
contradictory flags and workflow-needs sync remain covered. Required scope skips
fail; only explicitly nonrequired lane skips are accepted.

Local full auto-discovery with real Core source and strict seam mode produced
**1147 passed** with Python 3.14.9, pytest 9.1.1 and pytest-asyncio 1.4.0, using
unchanged official Core `2bd378ed1b8d6bf2192cb26e0a55ff3091e6bd19`.
The workflow-parity fake lane separately produced **1126 passed, 8 skipped**
(the existing Core-dependent cases; strict execution is reported separately).
An initial all-tests attempt without the Core import path failed collection; a
second using the upstream venv failed three async tests because that venv lacked
pytest-asyncio. Both failures are retained, not counted as PASS. Reusing the
already available test-tool environment plus real Core source resolved those
environment prerequisites without a code change, dependency installation or test
exclusion. Latest-Core and minimum-floor freshness are proven by the hosted
candidate run, not by this older local checkout.

The stable `CI gate`, strict flag parsing and job-needs policy are unchanged;
live main ruleset read-back requires `CI gate` (integration ID 15368). No ruleset
write is permitted. The classifier's two exact admissions are reviewable policy,
not semantic analysis. Unreviewed tests deliberately still cost the full matrix.
Main pushes still incur full Windows ARM64 cost. Phase B must establish enforceable
full-matrix verification of the **exact release SHA** before reducing post-merge
frequency; it is not implemented here. Cross-platform evidence remains asymmetric.
Phase C gateway boot/eval replacement and credentialed canaries are not covered.
