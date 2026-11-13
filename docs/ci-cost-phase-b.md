# Phase B CI cost: measured records and forecast boundaries

Snapshot: **2026-11-13T03:18:05.122243+00:00**, GitHub API window `2026-10-30..2026-11-13`.
The snapshot contains **83** workflow executions; every API page and each run's job total were checked before aggregation.

## Definitions and limits

- Runner elapsed = job `completed_at - started_at`, excluding skipped jobs. It measures allocated-job elapsed, not CPU time or invoiced cost.
- Start delay = job `started_at - created_at`. GitHub reports queue/provisioning timestamps; this is not a direct measurement of scarce-runner queue alone. Workflow DAG dependency time and overall wall time are not added to runner-minutes.
- Wall time = last job completion minus workflow creation. No OS pricing multiplier or dollar cost is invented; public repository billing/credits are not available from these timing records.
- The historical window spans changing CI contracts. All-five-native frequency is reported separately; older runs before those lanes existed are not mislabeled failed or optimized. Five native targets first appeared in this snapshot on 2026-11-12T08:34:19Z.

## Event frequency (actual attempts, not a policy estimate)

| Event group | Runs | All five native jobs started | All five native jobs succeeded |
|---|---:|---:|---:|
| Ordinary PR events (excluding scenario branches) | 42 | 23 | 23 |
| main push only | 36 | 6 | 6 |
| Non-main push / policy scenarios | 4 | 0 | 0 |
| workflow_dispatch | 1 | 1 | 1 |

Since Phase A's merged-main run `43294010951` in this snapshot: 1 main push and 1 PR, both full-native. The PR is this packaging/CI change; there is **no post-A ordinary fast-only PR speedup measurement** here.

## Platform timing

Baseline main: [run 43294010951](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43294010951), SHA `a5b526bc672ed32ec71b78ace3cf79f4347507f7`.
Initial Phase B PR (not release approval): [run 43321929587](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43321929587), SHA `93db79996c56f6c1455b25ec29fea54bbc86c558`.

| Platform | Main runner / delay (s) | Initial Phase B PR runner / delay (s) | Historical successful samples | Historical runner median / max (s) |
|---|---:|---:|---:|---:|
| linux-x86_64 | 188 / 2 | 165 / 2 | 77 | 96.0 / 278 |
| windows-x64 | 278 / 2 | 320 / 2 | 70 | 306.5 / 654 |
| windows-arm64 | 1072 / 3 | 1079 / 2 | 70 | 1100.5 / 1654 |
| macos-arm64 | 20 / 7 | 53 / 306 | 30 | 18.0 / 89 |
| linux-aarch64 | 15 / 4 | 58 / 4 | 30 | 16.0 / 122 |

Main total: **29.92 runner-min**, **18.17 min wall**. Initial Phase B PR: **31.28 runner-min**, **18.27 min wall**.
Windows ARM64 accounts for 59.7% of baseline allocated runner elapsed. Its installer/registration/initialize checks remain; the new removal assertions add coverage rather than replace any old check.

## Release-candidate cost and Phase B impact

**Phase B does not reduce main CI time or full-matrix frequency.** It adds provider/factory work on the two ARM POSIX lanes, completes the Windows lifecycle contract, and adds dispatch-only identity/final-gate overhead. A before/after timing difference is observational, not causal savings: runner images, downloads and caches vary.

The initial PR run above skipped Candidate identity and Release gate. It is **not** evidence that the SHA-bound gate executed. The final exact-HEAD dispatch URL, artifact identity and measured candidate runner/wall timings are recorded in [Draft PR #37](https://github.com/rhgo1749/hermes-antigravity-acp/pull/37) and the delivered verification receipts; never borrow the old PR/main success as candidate approval.

## Forecast for the separate Phase A main-push follow-up (not implemented)

These are component-sum forecasts from the measured **Phase A main baseline**, not observations of a reduced pipeline. They exclude Phase B added coverage/dispatch overhead and are not promised runtimes.

| Proposed ordinary-main scope | Baseline components (runner-min) | Forecast reduction vs full baseline |
|---|---:|---:|
| Docs / reviewed neutral-only: Fast | 3.70 | 26.22 runner-min |
| Plugin change: Fast + required OS | 11.80 | 18.12 runner-min |
| Packaging / unknown / release candidate: full native | 29.92 | 0.00 runner-min |

**Measured main-policy saving from Phase B: none; the policy was not reduced.** A controlled post-review follow-up must measure its own ordinary PR/main events, runner elapsed and start delays. Exact-SHA release dispatch stays all-five; unknown changes stay fail-closed full.

Raw evidence consists of paginated workflow/job metadata (`actions-runs-and-jobs.json`) and `actions-cost-summary.json` in the verification bundle. The snapshot includes non-main scenario pushes explicitly; calling every `push` a main push would inflate the frequency.
