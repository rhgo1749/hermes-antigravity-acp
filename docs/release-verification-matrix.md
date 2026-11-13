# Cross-platform release verification (Issue #28 Phase B)

The existing `.github/workflows/ci.yml` owns both ordinary CI and candidate
verification. There is no second native matrix or publishing workflow.
`release/verification-matrix.json` versions the five targets, eight stages,
required/optional flags, evidence classes and historical coverage snapshot.
**The snapshot is not approval of a new SHA.** Only a fresh `Release gate`
result and its run-bound JSON artifact certify the candidate under test.

## Exact-SHA enforced path

Dispatch against the branch whose current HEAD is the candidate. For example,
from the clean, already-pushed candidate checkout:

```bash
branch=$(git branch --show-current)
candidate=$(git rev-parse HEAD)
test -n "$branch" &&
  gh workflow run ci.yml --repo rhgo1749/hermes-antigravity-acp \
    --ref "$branch" -f "candidate_sha=$candidate"
```

The same existing workflow runs the full native matrix on dispatch. It never
creates a tag, release or deployment. An omitted `candidate_sha` means a normal
full-matrix diagnostic dispatch, **not** release approval.

1. Every checkout pins `github.sha`, never an independently supplied commit.
   The common `candidate_identity.py --attest-checkout` driver checks the
   actual checkout against the candidate **and** the Actions execution SHA.
   A bad candidate fails change-scope before native lanes are selected.
2. `Candidate identity` additionally validates full lowercase 40-hex syntax,
   remote commit/tree provenance and the exact advertised `github.ref` branch
   HEAD. A reachable ancestor is insufficient. Tags are not candidate branches.
3. All eight test lanes attest their tested SHA after successful execution;
   native/protocol lanes also attest their own stages. `needs` is from this
   workflow execution, not an API search for an older green run.
4. `Release gate` waits for the existing `CI gate`, identity, scope and all
   test lanes. Missing, pending, failed, cancelled, skipped, unknown or
   wrong-SHA required evidence fails closed. An optional PASS cannot fill a
   required cell owned by another lane.
5. At the end the gate independently checks its checkout, `GITHUB_SHA`,
   `GITHUB_WORKFLOW_SHA` and a fresh remote branch HEAD against the candidate.
   Movement of the selected branch fails even if every platform passed.
   A PASS produces `release-verification-RUN_ID-ATTEMPT`, containing the SHA,
   tree, start/end identity, repository/run/attempt/workflow provenance,
   matrix SHA-256, job conclusions and all forty per-target stage results.
   The uploader runs only after successful verification; missing output is
   an error. Artifacts are retained for 30 days.

Branch protection's ordinary check remains `CI gate`; `Release gate` is
intentionally dispatch-only. A normal PR's Actions SHA can be a synthetic
merge commit, so its green native jobs are **not** substituted for the exact
PR HEAD dispatch. Branch movement after certification also invalidates use of
that result for a different candidate: a later publishing integration must
consume the recorded exact SHA and revalidate its current target.

### Existing publication gate: separate responsibility

This repository has **no `publication-gate.yml` or release/tag publisher**.
`scripts/publication_gate.py` is the existing privacy/exposure and explicit
human-authorization gate; it is not a native-platform result aggregator and
is preserved unchanged. Neither a privacy decision nor a candidate PASS
supplies the other's authorization. Phase B implements executable CI candidate
certification, not a new publisher or permission to bypass maintainer review.

## Platform contract and honest evidence boundaries

R = required; O = optional. Binary/native evidence executes the official
Google CDN distribution under `antigravity_acp/registry.py`'s publisher
SHA-256 **before extraction/execution**, not a redistributed GitHub asset.

| Stage | Linux x86_64 | Windows x64 | Windows ARM64 | macOS ARM64 | Linux aarch64 |
|---|---|---|---|---|---|
| Publisher pin + SHA-256 | R / real binary | R / real binary | R / real binary | R / real binary | R / real binary |
| Install/status/verify/remove/absence | R / clean-room driver | R / common lifecycle | R / common lifecycle | R / common lifecycle | R / common lifecycle |
| Provider registered/enabled | R / real Core | R / real Core CLI | R / real Core CLI | R / real Core | R / real Core |
| Provider selection + factory | R / real Core | O / NOT_RUN | O / NOT_RUN | R / real Core | R / real Core |
| Unauthenticated ACP initialize | R / real binary | R / real binary | R / real binary | R / real binary | R / real binary |
| Error/timeout/permission denial | R / shared fake protocol | R / shared fake protocol | R / shared fake protocol | R / shared fake protocol | R / shared fake protocol |
| Session resume/recovery | R / shared fake protocol | R / shared fake protocol | R / shared fake protocol | R / shared fake protocol | R / shared fake protocol |
| Extra platform hardening | R / dedicated UID | O / owned process tree | O / NOT_RUN | O / NOT_RUN | O / NOT_RUN |

Historical statuses and citations are in the JSON. The first executed macOS
and Linux aarch64 registration/factory evidence is run
[43321929587](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43321929587)
at `93db79996c56f6c1455b25ec29fea54bbc86c558`; it is a baseline, not approval
of subsequent commits. Previous Windows jobs did **not** execute removal;
that full-stage snapshot stays BLOCKED pending the new common driver's
execution. The required stage cannot be approved without fresh successful
same-SHA attestation. Read the dispatch artifact for the actual candidate's
PASS/FAIL status, not this historical table.

`scripts/ci_provider_lifecycle.py` reuses the public installer's status,
integrity/initialize verification and owned removal, then requires every
managed-state flag absent. Windows retains its actual `.cmd` installer,
architecture/provider checks and restricted-environment initialize; x64
also retains the #31 request-scoped cancel/process-tree regression. The
POSIX provider/factory probe is shared with the Linux clean room. The
clean-room driver remains separate because its dedicated UID and canary
isolation assertions are stronger, not interchangeable OS adapters.

The fake-protocol stages execute once on Linux, not once per native OS.
They do not prove OS-native authenticated resume, vendor recovery, auth
success or inference. Windows selection/factory remains unverified because
the real-Core probe assumes POSIX UID/launcher semantics. macOS and Linux
ARM now have real-Core registration/factory evidence, but not dedicated-UID
isolation. No lane claims live-account validation or authenticated inference.
Latest upstream Hermes `main` and minimum `v0.21.6` strict seams remain
required; the native probe's reviewed Core commit pin is preserved.

## Tests, cost and the subsequent main-push change

Auto-discovered pytest covers wrong/missing SHA, pending/missing/cancelled/
skipped/failed jobs, optional substitution, malformed records, actual scratch
remote HEAD movement with a still-pinned checkout, historical-vs-run status,
and the real shared attestation CLI. RED receipts for the previously accepted
identity substitutions and missing lifecycle wiring are retained with PR
verification evidence. Publisher pins and all existing cancel/security tests
are unchanged.

Phase B **does not reduce main CI time**. Main pushes and dispatches still
force all native lanes. PR Fast/OS/ARM classification remains Phase A's
conservative policy; unknown changes still widen to the full matrix.
Measured Actions records, queue/runner definitions and estimated-vs-measured
boundaries are documented in [ci-cost-phase-b.md](ci-cost-phase-b.md).

Only after independent verification of this gate may a separate Phase A
follow-up change `ci_change_scope.py::scope_for_event`'s push policy and its
workflow/contract tests: routine main push = Fast + risk-required OS;
packaging/architecture = affected full native coverage; unknown/detection
failure = full coverage; release dispatch = all five exact-SHA targets.
That follow-up must retain publisher checks, Windows ARM installation,
latest/minimum strict seams, pytest discovery, #31 regressions and both
fail-closed gates, then measure the resulting ordinary-main savings.
