# Issue #28 Phase C: disposable real-Core Gateway verification

## Status: Draft; acceptance is bound to an executed exact-candidate receipt

This document is not a PASS stamp. See Draft PR #39 for the latest candidate,
Core SHA, real Hosted outcomes and remaining unverified items. Historical failed
runs below remain evidence for their own identities only.

## Approved frozen-copy compatibility

The operator approved a bounded frozen-copy adaptation and negative tests. Core
is not patched and no registry/callable is replaced. `scripts/provider_origin.py`
observes the original `providers/plugin_reload.py::_snapshot` return before its
code is imported. A copy is bound only to the exact installed provider directory
of the expected HOME, under the canonical owner-private original Core snapshot
root (and the existing disposable root for Gateway execution).

The installed and runtime **entire payload file/hash maps** must match the
pre-lookup candidate baseline, ignoring only bytecode cache directories. Core's
size/mtime cache fingerprint is not treated as content identity. Unobserved copies,
identical sibling-home copies, stale bytes with preserved size/mtime, symlinks,
missing/extra files, nonprivate roots and post-binding drift are negative controls.
The minimum-Core direct installed path remains supported under the same byte map.

The strict SDK helper retains genuine Core module provenance and calls the real
public lookup. The Gateway's existing profiler now validates both the bound
source tree and the executing factory/cancel code object against compiled exact
candidate source; a fabricated matching `co_filename` is not sufficient. Receipts
carry only tree/HOME hashes, copy counts and fixed error codes. Missing/malformed
origin evidence or wrong candidate SHA fails the existing CI/Release validators.
This instrumentation is for trusted CI code, not a hostile-Python sandbox.

Local loader-shape fixtures are explicitly offline mocks, not real Core runtime
proof. Real stable-v0.23.3/floor compatibility and Gateway acceptance still require
their unchanged Hosted lanes (latest-`main` is the separate non-blocking
advisory diagnostic under the 2026-11-16 baseline policy). No local Gateway/Docker fallback or additional security
grant is introduced by frozen-copy compatibility.


The credential-free functional path has executed in a disposable local fixture.
It is **not yet a compliant replacement for operating `gateway-eval` verification**.
The available local runner is BLOCKED; the conditionally approved Hosted Docker
boundary is implemented but must pass actual execution before adoption.
A dirty development run is not a candidate-SHA verification receipt. No merge,
release, operating deployment or production service change is authorized.

## Evidence classes and existing coverage

Existing CI retains automatically discovered fake-ACP protocol regressions,
stable v0.23.3 and minimum supported strict real-Core provider seams (the
latest-`main` seam is the separate advisory diagnostic since 2026-11-16), publisher integrity,
and five native platform installation/registration/initialize/removal lanes.
None of those is a real Gateway boot and request proof by itself.

The new driver reuses the required strict-Core Linux x86_64 environment —
since the 2026-11-16 baseline policy (stable lane promoted to v0.23.3 on
2026-11-21) that is the mandatory stable v0.23.3 lane
(the Gateway receipt is required against the stable baseline; the former
latest-`main` job is the separate advisory diagnostic); it does not
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

## Fault-cleanup negative lane (Issue #41)

One deterministic injected failure runs inside the same verified Docker boundary, in a
non-blocking lane (`.github/workflows/gateway-fault.yml`) that triggers only on Gateway
harness changes. After `initialize`, the driver admits a synthetic run, waits until the
fake ACP peer holds the prompt with the owned server+grandchild tree verified live, then
raises `injected_fault_while_prompt_held`. The expected receipt is a FAIL: exactly ten
stages PASS, four post-injection stages stay `NOT_RUN`, `injected_fault` FAILs, and
`scripts/gateway_fault_check.py` certifies only detection plus containment — graceful
owner exit (`zero`, no forced reasons, measured positive `owner_exit_seconds`), complete
fixture shutdown, container/image removal read-back, and a PID1-only final namespace.
A falsely successful or contradictory receipt is rejected; the failed operation is never
relabeled as success.

First hosted run `43873946068` proved the checker rejects false PASS: it refused a receipt
whose owner was SIGKILLed at the harness's 20-second idle-gateway grace while Core was
still inside its documented busy-shutdown leash (drain 0 + watchdog grace 60 s,
`gateway/shutdown_watchdog.py`). The harness grace was realigned to that contract
(owner 75 s; contender unchanged at 20 s); every fail-closed invariant is unchanged.

## Validation responsibility contract v2 (PR #39 redesign)

The operator explicitly approved removing full in-container pytest as a Gateway
prerequisite. This is a **changed assurance**, not equivalent coverage or a PASS
for historical failures. Run 43603573261 had 180 failures / 0 errors / 2 skips
in 1,693 JUnit records; cgroup OOM-kill delta was zero and memory peak 924,061,696
bytes. Gateway's fourteen stages were NOT_RUN. Those failures remain unresolved
observations, not established ACP product defects.

| Owner | Required evidence | Does not establish |
|---|---|---|
| Fast | Entire automatically discovered credential-free suite, Ruff, public-tree audit | Compatibility of that entire suite with the restricted container filesystem/process budget |
| Stable v0.23.3 + floor strict Core (latest-`main` is the separate non-blocking advisory diagnostic, not compatibility evidence) | Official unmodified provider API, candidate/home/frozen-byte provenance, credential boundary and delegate affinity | A running Gateway |
| Docker boundary | Non-root, empty capabilities, no-new-privileges, separate PID/network namespaces, network none, read-only roots and exact mounts, loopback, host-verified ownership | Full-suite PASS inside the container; the official Docker Hub image runtime is not independently tested by this source-checkout/scratch-rootfs boundary |
| Real Gateway in that boundary | All fourteen required stages, original scratch/shutdown checks, source bytes unchanged, PID1-only final inventory | Authenticated Google inference or vendor-side cancellation |

Only after actual kernel controls AND the host ownership handshake pass does the
same container process call the existing Gateway driver. No pytest process runs
there first. The 2-GiB/128-PID limits, all platform/strict lanes and scope policy
are unchanged. No skip/xfail, synthetic regression PASS or ignored failed suite is
used. There is no extra Hosted job, diagnostic framework or direct-host fallback.

Docker receipts add integer `docker_contract_version: 2` and `checkout_sha` equal
to the executed candidate SHA. The Gateway receipt itself uses schema 2 and
all fourteen stages. CI and Release reject missing/old/wrong-typed Docker contract
versions, conflicting checkout/candidate/Core identities, legacy `regression*`
fields, incomplete confinement, process residue, failed owned cleanup and any
non-PASS required Gateway stage. The workflow exports the independently resolved
official Core SHA alongside the receipt so both outer gates bind the same target.
For a PR the executed candidate/checkout is the synthetic merge; the PR source
HEAD is separately recorded from GitHub. Dispatch-only exact-SHA Release semantics
are unchanged; no Release dispatch is authorized by this redesign.

The unused whole-suite JUnit/memory/PID diagnostics and their dedicated tests are
removed, not repurposed as an isolation gate. The validated uncommitted PID work
is preserved in an operator-local evidence bundle outside the repository with
full source copies, `pid-work.patch` and validation hashes. Historical Hosted
receipts remain evidence only for their original SHA/Core/run identities.

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

The host's `/usr/bin` remains a read-only binary input. The single `systemctl`
entry is covered by a separate read-only bind of the runner's verified non-executable
`/usr/lib/os-release` data file, not an executable replacement. Exact source,
destination, read-only status, non-root execution and the rest of the mount set
are verified. The container checks the source inode has one hard link, belongs to
root and has no executable or group/other write bits; the masked paths must name
that inode. With zero effective capabilities, a non-owner cannot chmod it, even if
a symlink reaches the inode from a writable directory. Kernel checks require write
opens and direct execution via `/usr/bin`, `/bin`, and `/sbin` to be denied.
Before Core runs, the verified container must report no `systemctl`
from either the fixture PATH or Core's documented system-directory extension,
no systemd PID 1, and no system/user D-Bus or systemd private socket. Unexpected
systemctl launches remain sticky audit refusals. This intentionally excludes
systemd service management and systemctl integration from this Gateway E2E; it
still tests the unmodified Core's ordinary no-systemd Gateway/Provider path.

The original Gateway driver runs directly after the exercised boundary passes.
Full pytest remains in Fast and the purpose-specific official Core strict lanes,
not as a duplicate in-container prerequisite. This intentionally drops the
whole-suite-in-container guarantee described in the historical v1 contract.
Native Fast/OS/Extended ARM and stable-v0.23.3/floor strict obligations remain
required (latest-`main` is the non-blocking advisory diagnostic); the stable
CI/Release aggregators enforce the v2 Docker/Gateway receipt against the stable
baseline.

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

## 2026-11-15 confirmed Hosted READY root cause (runs 43470290348 and 43611722789)

Both Hosted READY timeouts share one confirmed cause: Core's `api_server` adapter requires
`aiohttp`, which Core declares only in optional extras (`messaging`/`slack`/`matrix`). The
Gateway E2E job provisioned Core with base `uv sync --frozen --group dev`, so
`check_api_server_requirements()` returned False, `start_gateway` logged
`No adapter available for api_server` and booted with no HTTP listener. The harness observed
bare `connection_refused` for the full 60-second window. `b51a30c` already imported aiohttp,
so the older failure had the same cause; the port-reservation change stays as hardening but
the port-stealing theory is retired as the explanation for these runs.

Local dirty diagnostics (never candidate evidence) on Core `e8bef69f` with the harness's exact
disposable-home configuration: without aiohttp the process stayed alive 240 seconds without
ever binding; with `aiohttp==3.14.5` it listened in 5.8s and reached READY in 6.4s, and with
the full audit+profile envelope (namespace gate patched, 2-CPU emulation) READY took 11.0s.
The 60-second deadline was never the constraint.

A second latent defect would have kept CI red after the dependency fix: the envelope's
read-only git allowlist was stale against Core `e8bef69f` version fingerprinting
(`branch --show-current`, `rev-list --count`, `--no-optional-locks status`), producing sticky
`unapproved_subprocess` refusals and an isolation FAIL. The verdict moved into
`gateway_process_policy.readonly_git_verdict` with positive/negative tests. Independent
review proved a verb-only allowlist is unsafe (`branch -D`, `branch <name>`, `tag <name>`,
`tag -d` all passed). A further regression test showed `rev-list --output` can write a
file from the git child. The current policy admits only enumerated Core probe shapes;
unknown options and verbs are refused. Status probes require `--no-optional-locks`,
and no unobserved `symbolic-ref` form is admitted. This is an in-process audit policy,
not an independently enforced kernel sandbox.

Argv shape alone cannot make the git *process* read-only, and a follow-up review confirmed
three reproductions against real git under shapes the allowlist admits: a `PATH` swap runs a
foreign binary named `git`, `GIT_TRACE`/`GIT_TRACE2_EVENT` write a file from an otherwise
read-only probe, and a hostile repository selected only by the `Popen` cwd executes
`core.fsmonitor`. Core's own version fingerprinting passes `cwd=str(repo_dir)` with no `-C`
(`version_info.py:64`), so the launch cwd is the only thing selecting that repository, and the
audit hook sees cwd and environment only as `Popen` arguments. `git_probe_context_verdict`
therefore pins the launch context alongside the shape: the resolved executable must be the
system git and unwritable by the running uid, `PATH`/`HOME`/`XDG_CONFIG_HOME` may not change,
`GIT_TRACE*`/`GIT_EXEC_PATH`/repository-relocating variables are refused, the
`GIT_CONFIG_KEY_n` block must equal Core's own hardening overrides, and the effective
repository (explicit `-C`, else the launch cwd) must be the pinned Core checkout. Every config
file the child will actually load — the checkout's own, plus `$HOME/.gitconfig` and
`$XDG_CONFIG_HOME/git/config` and the system file unless the child pins them to the null
device — must carry no execution-capable setting, and no `include`/`includeIf` directive, since
git folds the included file into its effective configuration and a scan of the first file alone
would see nothing executable. That config rule closes a reproduction the first review left as a
residual risk: the container's fixture `HOME` lives under `/gw`, the
only writable mount, so a planted `~/.gitconfig` carrying `core.fsmonitor` made the admitted
read-only `--no-optional-locks status --porcelain` execute an external program. A second review
round closed six more reproductions, all of them gaps in that same screen rather than new
subsystems: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `EDITOR` and `SSH_ASKPASS` reached the child because
only `GIT_*` and `PAGER` names were screened (now: anything the launch adds or edits outside the
named set is refused, and dropping a git variable counts as an edit); a variable written into
`os.environ` by the in-process Gateway was invisible because the diff read live `os.environ`
(CPython emits no audit event for an environment write, so the diff is against the launch
snapshot `BASELINE_ENV`); config values were folded to lower case although git folds keys and
*not* values, so `pager = CAT` passed as `pager = cat`; section headers were parsed only for a
line ending in `]`, so `[core] ; comment` hid a whole `[core]` block and a tab before a
subsection quoted it out of the `filter.*.process` pattern; and an injected `GIT_CONFIG_KEY_n`
name passed on "not known to be dangerous", so the injection block is now restricted to Core's
own override names with Core's own values. Repository-level config resolution follows a linked
worktree to what git actually reads: a worktree has no `<gitdir>/config`, so scanning only that
path admitted a probe whose *common* config (`<commondir>/config`, named by the gitdir's
`commondir` file) carried `core.fsmonitor`, and the admitted read-only status probe executed it
against real git; `<commondir>/config` and `<gitdir>/config.worktree` are now both scanned. A
third round closed the header line itself: git ends a section header at the first `]` and then
keeps parsing the *same line* as an assignment, so a single `[core] fsmonitor = <hook>` line is a
setting `git config --get` reports and the admitted read-only probe executes, while a parser that
consumed only the header rated the file inert; the same blind spot hid the one-line
`[include] path = <file>` form the include rule exists to deny. A line git itself cannot parse is
now refused rather than skipped. These controls bound which binary, repository and configuration
a probe can reach. They do not make git incapable of writing inside the disposable root, and the
read-only container mount, not this policy, is what bounds where such a write can land.

Child observation is bound to the launch that earned it. The audit hook clears a per-thread
slot for every admitted `Popen` and writes a housekeeping verdict into it only after a full
verdict; the profile hook consumes that slot when the child actually exists. A shared token
list let a `Popen` that raised after the audit event leave a token that a later, unrelated
child carrying the same argv then consumed, and let one thread's token authorize another
thread's child. A `Popen`-shaped child whose pid or `/proc` start identity cannot be read now
raises the boundary refusal instead of returning no record: an untracked child never enters
the driver's cleanup pid set, so a live one would have let `child_cleanup` PASS over a smaller
set than the fixture owns.

`scratch_cleanup launch_count=0` is downstream of READY, not an independent defect: Core
spawns the detached pruner only from `get_scratch_dir(prune=True)` call sites (for example
per-request prompt building), and the boot temp-env hook skips when `TMPDIR` is preset. No
READY meant no request meant no prune attempt. The envelope-parity local run confirmed the
original pruner is admitted, removes the fresh idle probe, retains the active probe and
writes a non-empty prune log.

Known diagnostic gap (schema 1, run 43626772404): `cleanup()` overwrote an isolation
`BLOCKED sticky_boundary_refusal` with the scratch FAIL detail, and raw `gateway.log`
stayed inside the disposable root; the refusal's identity is unavailable. Schema 2
records a sorted unique set of refusal strings, not occurrence counts. Run 43666846085
recorded `subprocess_executable_mismatch`; the executable and call site were not retained.
The successful-receipt validator now rejects any recorded refusal, missing child evidence
or nonzero live-child count; this consistency check does not establish receipt authenticity.
The driver fails fast with the fixed
`api_server_dependency_missing` detail when the interpreter lacks aiohttp, so a
provisioning gap cannot masquerade as a Gateway startup timeout.

## CI gating policy

Gateway E2E is mandatory on every CI event under the stable v0.23.3 policy.
The existing risk classifier still decides which native OS and extended ARM lanes
are required; it no longer controls Gateway execution. The advisory latest-`main`
strict seam runs independently and does not gate the stable result.

The existing required strict-Core job (the stable v0.23.3 baseline lane —
mandatory since the 2026-11-16 policy, promoted to v0.23.3 on 2026-11-21) publishes the actual Gateway step outcome and a
receipt validated against the candidate and the separately resolved Core SHA.
`CI gate` independently requires that outcome and every mandatory stage at every
scope; an enclosing job success alone is insufficient. Every exact-SHA
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
