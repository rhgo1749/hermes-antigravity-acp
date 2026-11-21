# Main-push CI scope — Issue #28 Phase A follow-up

## Prerequisite actually verified

Phase B PR #37 was independently approved at
`dfdcae7291eb7d384ff47218aaf32a00efc3140c` (operator-reported review), then
merged normally as `6a6187f2e148e8e78018e03feedcbab5d0c64075`.
The new merge SHA was separately executed, not certified using PR-HEAD results:

- [Main push 43389328402](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43389328402): 10 active jobs PASS.
- [Exact-main dispatch 43389340725](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43389340725): 12/12 PASS, attempt 1.
- [Actual release record](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43389340725/artifacts/14020788081): 34/34 required PASS, five optional NOT_RUN; repository/run/attempt/SHA, branch start/end and matrix digest read back.

This follow-up is a separate Draft implementation, not authorization to merge,
publish, tag, deploy or change production. Issue #28 stays OPEN for this policy's
independent review and Phase C Gateway CI.

## Policy (existing path classifier reused)

Fast means auto-discovered fake-ACP tests/static/hygiene, the mandatory stable
official Core v0.23.1 strict seam and minimum supported Core v0.21.6 strict
seam, plus `CI gate`. Per the 2026-11-16 baseline policy
([hermes-compatibility.md](hermes-compatibility.md#baseline-policy--stable-v0231-current-2026-11-16)),
the latest-`main` strict seam is a separate advisory diagnostic: it runs and
reports, may fail without blocking, and is not compatibility evidence.
OS means Linux x86_64 clean room, Windows x64 actual installer and macOS ARM64.
Extended ARM means Windows ARM64 actual installer and Linux aarch64.

| Event / risk | Fast | OS | Extended ARM |
|---|---|---|---|
| PR: documentation / exact reviewed neutral tests | required | not required | not required |
| PR: ordinary plugin / reviewed non-packaging scripts | required | required | not required |
| Trusted routine main push | required | same risk rules as PR | same risk rules as PR |
| Packaging / architecture / unknown paths | required | required | required |
| Uncertain push metadata / graph / diff | required | required | required |
| Every workflow_dispatch, including exact-SHA candidates | required | required | required |

No path allowlist was expanded. New/unreviewed tests still require full native
coverage; pytest discovery itself is never filtered by this classification.
macOS ARM64 remains first-class OS coverage, not optional merely because ARM.

## A push is not a PR diff

Workflow inputs come directly from GitHub event/context expressions via `env`,
never shell interpolation or the payload's potentially bounded `commits` list:

1. `before` and `after` must be literal nonzero lowercase 40-hex commit IDs.
   Refs, abbreviations, missing values and annotated tag objects are rejected.
2. Ref must be `refs/heads/main`; created/deleted/forced flags must each be the
   explicit string `false`. Missing or malformed flags do not default to normal.
3. Event `after` must equal Actions execution SHA and actual checked-out HEAD.
   Full fetched history is required; even a shallow clone containing both
   endpoints is not accepted as complete graph evidence.
4. Both exact objects must be commits and `before` must be an ancestor of
   `after`. A false forced flag cannot substitute for fast-forward proof.
5. Compare the **two endpoint trees** with
   `git diff --no-renames --name-only -z BEFORE AFTER --`. This includes the
   complete pushed delta across multiple commits and merge commits, not just
   HEAD's last parent. Rename detection is disabled so deletions and additions
   both classify. NUL-delimited UTF-8 paths retain spaces/Unicode/newlines.

A missing object, Git failure/timeout, malformed NUL output, path decode failure
or empty diff falls back to full coverage. Git calls are bounded and argument
arrays contain only validated IDs; detection does not fetch an arbitrary user
revision or silently continue from a truncated comparison. PR merge-base
behavior stays unchanged. Dispatch returns full scope before push parsing.

## Preserved contracts

The stable required `CI gate` graph/strict flags/missing-or-skipped denial,
stable-v0.23.1/minimum Core strict checks (latest-`main` moved to the separate
non-blocking advisory diagnostic under the 2026-11-16 baseline policy; the
historical runs recorded above were executed under the former mandatory-latest
rule), pytest discovery, publisher SHA-256,
Windows x64/ARM64 installers, #31 cancellation/tree regressions, macOS support,
exact-SHA release identity/stages/artifact and separate privacy/publication
human authorization are unchanged. An unrequired skipped lane is NOT an
executed PASS; an unrequired lane that runs and fails still fails `CI gate`.

Tests include real disposable Git histories for multi-commit pushes, a two-parent
merge, non-ancestor force pushes, shallow clones, deleted/renamed installers,
docs/neutral/generic/platform/packaging/unknown paths, missing/bad hashes and
flags, checkout substitution, empty changes, actual public CLI wiring and
required OS missing/skipped/cancelled/failed negatives. New regressions first
failed on the merged base (13 failed / 50 passed), then passed after the change.

## Cost: observations versus forecasts

Baseline is the **new merged-main** push above, not an old PR with a different
workflow. Allocated runner elapsed = job completed_at - started_at; start delay
= job started_at - created_at. Neither is billed CPU/dollars or pure queue time.

| Baseline main measurement | Observed |
|---|---:|
| All active jobs combined | 32.35 runner-min |
| Workflow wall time | 21m12s |
| Windows ARM64 runner / reported start delay | 1255s / 2s |
| Windows x64 runner / reported start delay | 303s / 1s |

Component-sum forecasts using those SAME baseline jobs: Fast-only **3.32
runner-min**; Fast + OS, excluding the two Extended ARM jobs, **10.77
runner-min**. These are not observed optimized runs, not guaranteed wall times,
and not a controlled before/after saving. Caches/installers/Core updates vary.

**At rollout, optimized-scope hosted execution was not yet verified.** The
implementation PR changed CI wiring and added an unreviewed policy test file,
so it required the full matrix. Such a run can establish regression correctness,
not reduced-scope cost. Do not add a dispatch bypass, weaken the classifier or
invent a push to obtain an optimized-scope sample.

The protected `AGENTS.md` tier row now matches this policy after the formal
protected-file edit gate permitted the scoped correction. README, workflow
comments and the classifier retain the same risk rules; release verification
still does not grant publication or human approval.

### Observed Fast-only main push (Issue #42)

[Run `44723147194`, attempt 1](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/44723147194)
was a normal `push` to `refs/heads/main` (forced, created and deleted flags all
`false`). The [Change scope job](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/44723147194/job/136243740156)
recorded `before=4e1b52fab839e744d5bc8b244aeb9d9be15afe3d` and
`after=1b0958930260515858b4766ac4464e8128caf5f6` (also the execution SHA).
The [pushed range](https://github.com/rhgo1749/hermes-antigravity-acp/compare/4e1b52fab839e744d5bc8b244aeb9d9be15afe3d...1b0958930260515858b4766ac4464e8128caf5f6)
changed `docs/issue25-cgroup-delegation-plan.md`,
`docs/issue25-cgroup-spike-preflight.md`, `docs/issue25-process-tree-evidence.md`,
`docs/issue25-rehearsal/acp25-p1-rehearsal-run.sh` and
`docs/issue25-rehearsal/acp25-p1-rehearsal-runbook.md`. All five matched the
Fast-only `docs/*` rule, including the rehearsal shell file under `docs/`.
Outputs: `os_lanes=false`, `extended_arm=false`, `reason=path-classified`.

| Job | Runner label | Conclusion | Allocated seconds | Reported start delay (s) |
|---|---|---|---:|---:|
| Change scope | `ubuntu-latest` | PASS | 12 | 2 |
| Fake ACP regressions and static checks | `ubuntu-latest` | PASS | 166 | 1 |
| Catalog admission + seam at Hermes floor v0.21.6 | `ubuntu-latest` | PASS | 59 | 2 |
| Vanilla NousResearch Hermes provider API (includes Gateway E2E) | `ubuntu-latest` | PASS | 122 | 1 |
| Advisory upstream main compatibility | `ubuntu-latest` | FAIL (non-blocking) | 54 | 2 |
| CI gate | `ubuntu-latest` | PASS | 4 | 7 |
| Fresh-UID clean room | `ubuntu-24.04` | SKIPPED (OS not required) | — | — |
| Windows x64 | `windows-2022` | SKIPPED (OS not required) | — | — |
| macOS ARM64 | `macos-15` | SKIPPED (OS not required) | — | — |
| Windows ARM64 | `windows-11-arm` | SKIPPED (Extended ARM not required) | — | — |
| Linux aarch64 | `ubuntu-24.04-arm` | SKIPPED (Extended ARM not required) | — | — |
| Candidate identity and Release gate | `ubuntu-latest` | Both SKIPPED (not a release-candidate dispatch) | — | — |

No required job was missing or skipped, and the
[required CI gate](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/44723147194/job/136245059692)
passed. The workflow conclusion was `failure` because the advisory job failed.
The advisory still counts toward elapsed runner time: **417 runner-seconds
(6.95 runner-min)** across the six jobs that ran; **179 s wall**. Wall is run
`updated_at - run_started_at` for the completed attempt; summed job elapsed
can exceed wall because jobs overlap. The reported start delays above are
job `started_at - created_at`, not isolated queue measurements.

For comparison, the [natural full-scope reference `43863385318`](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43863385318)
ran 11 jobs for **2,009 runner-seconds (33.48 runner-min)** and **1,130 s wall**.
Its push touched the workflow and other paths; the classifier reported
`os_lanes=true`, `extended_arm=true`, `reason=unknown-paths-fail-closed (24 path(s))`.
All required lanes and `CI gate` passed. The Windows ARM64 job on `windows-11-arm`
alone accounted for **1,113 s** of elapsed time, with a **2 s** reported start delay.
The [later forced push `44762256445`](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/44762256445)
selected full coverage for `push-event-flags-fail-closed`, not for documentation
path risk, so it is not an optimized-scope sample.

This is one Fast-only observation, not a Fast+OS measurement, a billed cost,
or a controlled or generalizable saving estimate. The two runs used different
pushed trees and job conditions; neither cache effects nor queue effects are isolated.
