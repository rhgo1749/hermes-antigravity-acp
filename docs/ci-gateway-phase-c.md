# Issue #28 Phase C: disposable real-Core Gateway verification

## Status: implementation draft, NO-GO for adoption

The credential-free functional path has executed in a disposable local fixture.
It is **not yet a compliant replacement for operating `gateway-eval` verification**.
The available local runner is BLOCKED; the conditionally approved Hosted Docker
boundary is implemented but must pass actual execution before adoption.
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

## Conditionally approved Hosted Docker boundary

The operator authorized a non-root container **only on the existing Linux GitHub
Hosted disposable VM**. No operating-host container launch, sudo/security-policy
change, privileged container, host PID/network mode, published port, forwarded
Docker socket, operating HOME/profile/credentials mount, Core patch, cleanup-stamp
spoof, or direct-host Gateway fallback is permitted.

`scripts/gateway_docker.py` imports a tiny credential-free rootfs locally into the
existing daemon; it pulls no image. Only exact source/interpreter roots and necessary
system binary/library inputs are mounted read-only. The one fresh `/gw` bind is
writable. The container uses explicit non-root UID/GID, cap-drop ALL,
no-new-privileges, network none, default private PID namespace, IPC none, readonly
root, 128-PID / 2-GiB / 2-CPU limits and a 360-second outer execution deadline.
The original Gateway READY deadline remains 60 seconds: no blind timeout increase.

Before any Core execution, the same container process tests actual UID, effective
capabilities, no-new-privileges, readonly root mount, private PID/network namespace,
PID1-only psutil inventory and the absence of its known external fixture parent.
Raw libc open controls must deny an unmounted external fixture canary, source
write and rootfs write; kernel routing must reject an external connect while
container loopback bind works. The host separately inspects exact Docker settings,
mount set and the owned live container PID namespace before releasing execution.
Only compared namespace hashes, fixed statuses and counts enter the receipt.

Every pytest file runs inside the exercised boundary with the real dependency
interpreter (180-second suite deadline; sanitized JUnit counts only), followed by
the original Gateway driver in the same container. Native Fast/OS/Extended ARM,
latest/floor strict seams and the stable CI/Release aggregators remain unchanged.
This extra full regression is measured as part of container cost, not concealed
as free reuse. The local CI-equivalent credential-free suite remains separate
from this full real-Core run.

The original Core `python -I` scratch child is admitted only after exact executable,
argv, import-path and canonical owned-target checks **and actual namespace proof**.
A bare allow flag cannot admit it. Fresh idle probe entries (not prune stamps) must
be removed by the original pruner while fresh active probes survive; observed
original child return codes and native prune audit logs are required. Original
shutdown forensics are admitted only for the exact source-derived literal/f-string
script and canonical timeout executable. Its completion footer and child cleanup
are required. No Core callable or file is replaced. Python audit refusals remain
sticky, even if Core catches PermissionError or exits zero.

The final container inventory must contain only PID1, with zombies reaped. The
host verifies removal of its exact container and private imported image. Missing
Docker, unavailable isolation, failed controls, nonzero/timeout execution, dirty
source, missing scratch/diagnostic completion or unverified teardown cannot PASS.
No shared Docker prune or name-based process kill is used.

Historical analysis of official Core `97039b4` found ancestry walking in
`hermes_constants_scratch.py:195-211`, whole-process enumeration even for an empty
scratch in `:298-369,433-461`, the isolated child in
`hermes_constants_scratch_detach.py:23-45`, and shutdown scans in
`gateway/shutdown_forensics.py:118-165`. The earlier bare-child development PASS
is superseded as isolation evidence. Local unshare remains EPERM and no Docker
socket is available: local container execution is **BLOCKED**, not a reason to
run the Gateway directly. Real container acceptance remains NOT RUN until the
clean candidate executes on the authorized Hosted VM.

The prior Hosted READY timeout remains a distinct unresolved observation. The
same `b51a30c` Core reproduced all 13 functional stages locally in a dirty diagnostic
run, with isolation BLOCKED. This does not approve a candidate or prove a port-race,
disk or Python-version cause. New `last_readiness` records contain only fixed HTTP,
transport, expected-PID and allowlisted readiness check states, never raw errors,
paths, prompt/session text or credentials. A later container PASS is not retrospective
proof of the old failure's cause. The harness now reserves its loopback port below
the kernel ephemeral range (read from `ip_local_port_range`) and holds the
reservation socket until the Gateway's own bind, closing it only at launch. This
removes the kernel-allocation steal window entirely for the tested class; whether
it was the prior failure's actual cause is only answered by a new-HEAD Hosted run.

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
is not measured Hosted runner-min or a verified CI overhead delta. Prior Hosted run 43470290348 FAILED on d27e12f/PR-merge b417341 with official
Core b51a30c (READY timeout). New-HEAD Hosted and Release results remain NOT RUN
until that exact candidate actually executes; previous results cannot be reused.

## Scope realignment and Docker preflight follow-up

The original Phase C contract is real Gateway boot/candidate load, synthetic ACP
request/denial/cancel/ownership and clean disposable teardown. Non-root Docker,
cap-drop ALL, no-new-privileges, private PID/network, readonly root/source inputs,
limited fresh writes and no operating state are the later explicitly approved
execution boundary; they remain unchanged. `Init=false`, PID1-only inventory,
2-GiB/2-CPU/128-PID limits and the second full pytest are implementation choices,
not additional original Issue #28 requirements. No such choice is silently removed.

Hosted run 43491983597 on PR head `f7786ee` actually checked out synthetic merge
`a65c9c5011515e2fcbeb799322d8cb9178460723`, official Core
`438008f475fd89dd661ab2fda8355303a9f7bda6`. It stopped before container start at
`docker_config_not_verified`; all Gateway functional stages were NOT_RUN. The old
receipt did not retain inspect fields, so it cannot establish a complete historical
field-by-field verdict or prove that Init was the only mismatch.

A concrete command/verifier defect is source-backed: Docker CLI v28.5.1
`cli/command/container/opts.go` only sets `HostConfig.Init` when the flag changed;
Moby's API uses an optional bool, and its OCI launcher treats unset as the daemon's
setting. The old command omitted `--init` while requiring literal `false`.
The fix explicitly sends `--init=false`; null/missing remain rejected. The RED
option-contract test failed before the fix, then passed. This does not broaden
security policy or claim an old Hosted field observation that was never recorded.

Fixed-name PASS/MISMATCH/MISSING checks now explain every prestart/running inspect
condition without dumping values, paths, environment or credentials. Teardown
uses successful structured exact-container-ID listing / exact-image-ID absence
rather than matching the human `No such` error string. Offline tests reject rm
failure, list failure and actual residue. Actual container cleanup is not inferred
from these unit fixtures. A failed removal/readback still fails closed.

No CI tier, workflow trigger, test discovery, protected check or Release requirement
changes. Full pytest inside Docker duplicates Fast discovery; native Docker init
could replace the custom reaper only with revised inventory evidence; the custom
rootfs avoids pulling an image but adds loader-layout risk. These are review
candidates, not authorization for a broad rewrite. Readonly host-process reads on
a disposable Hosted VM were not explicitly prohibited by the original Issue, but
the later approved private-PID/no-outside-process boundary still controls. Relaxing
it requires separate approval even if process identities are less sensitive there.

The watcher now runs `gh run watch --exit-status` directly (or preserves its saved
exit code explicitly). The already-failed run was read back with actual exit 1,
without creating a new CI run. This fixes shell-status distortion only: notification
arrival does not prove admission, model execution or automatic continuation.

Production profiles, operating accounts/session databases, s6 and Multiplexer
settings remain outside this work. The existing operating `gateway-eval` is not
stopped or removed. Live vendor/account canaries and post-deployment smoke remain
separate responsibilities; no green synthetic protocol run can replace them.
