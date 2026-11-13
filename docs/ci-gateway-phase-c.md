# Issue #28 Phase C: disposable real-Core Gateway verification

## Status: implementation draft, NO-GO for adoption

The credential-free functional path has executed in a disposable local fixture.
It is **not yet a compliant replacement for operating `gateway-eval` verification**.
The stricter scratch/process boundary is BLOCKED on the available local runner.
A dirty development run is not a candidate-SHA verification receipt. No merge,
release, operating deployment or production service change is authorized.

## Evidence classes and existing coverage

Existing CI retains automatically discovered fake-ACP protocol regressions,
latest and minimum supported strict real-Core provider seams, publisher integrity,
and five native platform installation/registration/initialize/removal lanes.
None of those is a real Gateway boot and request proof by itself.

The new driver reuses the latest-Core Linux x86_64 environment; it does not
start Gateway instances on Windows ARM64 or add five duplicate Gateway lanes.
It executes the unchanged public `hermes_cli.main` foreground CLI and official
HTTP `/p/phasec/health/detailed`, `/p/phasec/v1/runs`, run status and run stop APIs.
The network peer is a synthetic stdio ACP server, **not** Google's vendor runtime.
No vendor login, credential injection or authenticated inference occurs.

The source checkout is exported with `git archive HEAD` into the newly created
root. All tracked source bytes are compared before and after execution. The
existing interpreter supplies dependencies; this is **byte-identical source-export
mode**, not self-managed installation/bootstrap acceptance. No Core code, private
registry or Gateway method is patched. The CLI envelope observes original factory
and cancel method returns; it never supplies a replacement client or Gateway.

## Fourteen required evidence stages

| Stage | Required executed observation |
|---|---|
| isolation | Fresh private homes, explicit clean child environment, dynamic loopback listener, no sticky boundary refusal |
| candidate_install | Existing owned projection installer, exact candidate payload bytes |
| enablement | Explicit enabled provider in launch and named profile configuration |
| gateway_ready | Authenticated detailed health, `status=ok`, running state, expected live PID |
| provider_factory | Original installed candidate `create_client()` observed in real Gateway worker |
| initialize | Synthetic ACP peer actually receives initialize |
| request_response | Real Gateway/agent request yields unpredictable fixture challenge response |
| permission_denial | Native execute permission rejected; no native execution |
| ownership_conflict | Same served profile contender safely refused or documented existing-owner no-op, owner lock unchanged |
| owner_survives | Original process remains healthy and processes a new request after contention |
| cancellation | Public run stop invokes original client `cancel()`, owned request tree exits, follow-up request succeeds |
| shutdown | Owned Gateway exits gracefully without fallback force kill |
| child_cleanup | Tracked fixture/Core children have no live start-time-matching survivor |
| source_unchanged | Official checkout and exported tracked source bytes remain unchanged |

`cancel()` in this candidate terminates its request-owned stdio process tree. It
does not send `session/cancel`. Process teardown and a terminal cancelled API run
are **not evidence of vendor-side inference cancellation or exactly-once effects**.
Canonical-admission run metadata can omit the served provider; exact source factory
observation and the unpredictable ACP challenge independently establish selection.

The observed current official Core contender contract is a successful no-op:
`The host gateway already serves profile 'phasec' — nothing to start.` The receipt
requires the original owner PID and unchanged lock plus a subsequent real request;
exit zero alone is insufficient. This is safe reuse, not rejection.

## Strict scratch approval: unresolved process isolation

Operator approval permits original Core scratch housekeeping **only inside the
new fixture root**, with executable, argv, target, alias/symlink and lifecycle
verification. It does not authorize operating GC or ACP MUX native-session GC.

The investigated official Core is
`97039b436b9ddc30ba9aa6f1ae8e62de511fa866`:

- `hermes_constants_scratch_detach.py:23-45`: original command is the running
  Python, `-I -B -c`, the fixed `_CHILD` body, exact scratch target, ancestor
  lineage, and original `sys.path`. `-I` means the parent Python audit hook is
  **not inherited** by this child.
- `hermes_constants_scratch.py:195-211`: computing lineage before Popen reads
  ancestors outside the fixture. Checking only target containment is insufficient.
- `hermes_constants_scratch.py:298-369,433-461`: a cleanup pass calls
  `psutil.process_iter` even when no entry is eligible for deletion. Therefore
  an empty scratch directory does not prove no outside-process access.
- `gateway/shutdown_forensics.py:120-165`: the unchanged signal-shutdown diagnostic
  starts a bounded shell with host process listings. It also cannot be admitted
  under a no-outside-process-access assertion.

The earlier development result with all fourteen stage labels PASS predates this
strict boundary review and used an inadequate child allow rule. It is explicitly
**superseded as isolation evidence**, not a successful candidate verification.

The hardened envelope denies scratch ancestry reads/child launch and the host
shutdown diagnostic instead of broadly admitting their executable names. Refusals
are sticky: a zero Core exit code or caught PermissionError cannot certify PASS.
`gateway_process_policy.py` checks exact original command spelling, launcher,
import path, owned absolute target, dot segments and symlink aliases; even a valid
command remains `scratch_process_namespace_unverified`. No opt-in boolean fabricates
namespace proof and no cleanup-complete stamp is created by the fixture.

Local capability probe: `unshare --user --map-root-user --pid --fork --mount-proc
true` returned `Operation not permitted`; no Docker socket was available. A genuine
isolated process namespace or an upstream supported confined cleanup contract is
needed before this stage can become PASS. This repository does not patch Core or
expand host privileges to obtain it. No new upstream issue has been filed without
separate authorization; existing related incident links remain in Issue #28.

## CI gating policy

The existing `os_lanes` risk decision conservatively also requires Gateway E2E.
Provider/client/permission/cancel/install changes require it; docs and the two
exact reviewed neutral tests can omit it; unreviewed paths and ambiguous metadata
widen to full validation. This adds no classifier flag or new job. Latest/floor
strict seams continue running regardless of the optional Gateway step.

The existing latest-Core job publishes the actual Gateway step outcome and a
receipt validated against the candidate and the separately resolved Core SHA.
`CI gate` independently requires that outcome and every mandatory stage when OS
scope is required; an enclosing job success alone is insufficient. Every exact-SHA
Release verification requires the Gateway receipt too and includes it in the
result document alongside, not instead of, the unchanged forty native matrix cells.
Missing, skipped, failed, cancelled, malformed or wrong-SHA evidence fails closed.
CI-generated upstream checkout/provenance/receipt paths are excluded only in the
runner-local `.git/info/exclude`; candidate source modifications still fail the
clean-tree check. No test discovery exclusion is added.

## Results, privacy and cost

`gateway-e2e-verification.json` contains exact plugin/Core SHAs, fixed per-stage
PASS/FAIL/BLOCKED/NOT_RUN labels, elapsed seconds and child counts. Only that sanitized
record is suitable for CI artifacts. Raw Gateway logs, prompts, API keys and original
session IDs are not uploaded. Local diagnostic retention is explicitly local-only.

The driver returns nonzero for any missing or non-PASS required stage, or a dirty
candidate. Previous-SHA or dirty functional results cannot approve another candidate.
Final clean-HEAD local/Hosted results and costs must be recorded separately in the
Draft PR. Do not claim a full pytest PASS from the narrow policy suite, a Hosted PASS
from workflow text, or cost savings from a full-matrix implementation PR.

Historical development run: 25.070 seconds, 16 tracked child identities, zero live
tracked survivors; **dirty overall FAIL and superseded isolation evidence**. This
is not measured Hosted runner-min or a verified CI overhead delta. Final Hosted and
Release results remain NOT RUN until the exact candidate actually executes there.

Production profiles, operating accounts/session databases, s6 and Multiplexer
settings remain outside this work. The existing operating `gateway-eval` is not
stopped or removed. Live vendor/account canaries and post-deployment smoke remain
separate responsibilities; no green synthetic protocol run can replace them.
