# CI cost evidence for Phase B (issue #28)

All numbers are measured from GitHub Actions run records of
`rhgo1749/hermes-antigravity-acp` (job `started_at`→`completed_at` for
execution, `created_at`→`started_at` for queue delay). No estimates are
mixed into the measured tables.

## 1. Measured per-job cost, current main pipeline (post Phase A)

Run `43294010951` — push `a5b526b` (main, first post-Phase-A main push,
full matrix by policy), conclusion success:

| job | exec | queue |
| --- | --- | --- |
| Windows install and unauthenticated ACP (arm64) | **17.9 min** | 3 s |
| Windows install and unauthenticated ACP (x64) | 4.6 min | 2 s |
| Fresh-UID clean room with official ACP binary | 3.1 min | 2 s |
| Fake ACP regressions and static checks | 1.7 min | 2 s |
| Vanilla NousResearch Hermes provider API | 1.1 min | 2 s |
| Catalog admission + seam at Hermes floor | 0.8 min | 2 s |
| macOS arm64 install and unauthenticated ACP | 0.3 min | 7 s |
| Linux aarch64 install and unauthenticated ACP | 0.2 min | 4 s |
| Change scope / CI gate | 0.2 min | 2 s |
| **total runner-minutes** | **29.9 min** | — |

Windows ARM64 alone is 60 % of runner time; Windows x64 adds 15 %.
macOS ARM64 and Linux aarch64 hosted jobs are nearly free (≤ 20 s each).

Median over the last 12 completed runs (5 main pushes, 6 PRs, 1 dispatch,
all full-matrix events): Windows ARM64 exec median 18.1 min (max 23.9),
Windows x64 5.0 min (max 6.0), clean room 1.8 min, fake-acp 1.2 min,
compat 1.0 min, catalog 0.8 min, macOS 0.3 min, Linux aarch64 0.25 min.
Queue delay is 2–7 s on every lane except one macOS outlier (603 s).

## 2. Event frequency (2026-10-30 → 2026-11-13)

- `pull_request` full-matrix runs: 41 (pre-Phase-A policy; wall median 18.4 min)
- `push` (main) runs: 35 (wall median 19.9 min)
- `workflow_dispatch`: 1

Phase A (merged 2026-11-12 in `a5b526b`) re-tiered PR runs to
risk-selected lanes. **No post-Phase-A non-packaging PR has executed yet**
— this PR is the first candidate for that measurement, so the PR-tier
reduction is currently *expected*, not yet *measured*: a docs/test-only PR
should run only the four fast jobs (≈ 3.5 runner-min vs ≈ 30).

## 3. What Phase B itself costs

- On ordinary PR/push events: zero added native cost. The two new jobs
  (`candidate-identity`, `release-gate`) are dispatch-only and gated on
  `inputs.candidate_sha`; they skip instantly otherwise.
- On a release-candidate dispatch: the same full matrix as a main push
  (≈ 30 runner-min, ≈ 18 min wall) plus ≈ 0.5 min for the identity and
  gate jobs.

**Phase B does not reduce main CI time.** It is the prerequisite that
makes later reduction safe: until a candidate SHA can be fully verified
on demand, every main push doubles as the release verification net.

## 4. Expected reduction after the Phase A follow-up (NOT applied in this PR)

Per the issue's target policy (risk-selected PR tiers; main push keeps
fast + required OS lanes; packaging changes widen; unknown fails closed):

| event | today (measured) | after follow-up (expected) |
| --- | --- | --- |
| non-packaging PR | ≈ 30 runner-min (pre-A) / ≈ 3.5 (post-A, first measurement pending) | ≈ 3.5 min |
| main push | ≈ 30 runner-min | unchanged in Phase B; candidate for later policy |
| packaging/arch PR | ≈ 30 runner-min | ≈ 30 runner-min (by design) |
| release candidate | n/a (was: hope) | ≈ 30.5 runner-min, dispatch-only |

The only large lever left is Windows ARM64 (18 min/run). It stays on
main-push + packaging + release-candidate cadence; it must not be
weakened or removed to save time (issue #28 §4).

## 5. GO / PARTIAL / NO-GO input

- Fail-closed SHA binding, matrix, gate, drift guard: implemented and
  unit-proven (RED 28 → GREEN 234 on the contract suite).
- Hosted evidence at an exact candidate SHA: produced by the
  `release-verify` dispatch recorded in the PR body.
- main CI reduction: **not started** — correct sequencing is Phase B
  evidence first, reduction PR second.
