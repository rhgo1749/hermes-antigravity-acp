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

Fast means auto-discovered fake-ACP tests/static/hygiene, latest official Core
strict seam and minimum supported Core v0.21.6 strict seam, plus `CI gate`.
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
latest/minimum Core strict checks, pytest discovery, publisher SHA-256,
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

**Actual optimized-scope Hosted execution and savings: NOT VERIFIED.** This
Draft changes CI wiring and adds an unreviewed policy test file, so its normal
PR deliberately requires the full matrix. Its green result can establish
regression correctness, never reduced-scope cost. Do not add a dispatch bypass,
weaken a classifier or invent a main push merely to obtain a savings chart.
Post-review rollout must observe actual routine main events and compare their
selected lanes and allocated runner time. No follow-up merge is authorized here.

The protected `AGENTS.md` baseline tier row still requires reconciliation before
merge; it was left unchanged when its separate write approval was not granted.
README, workflow comments and this policy describe the proposed behavior.
