# Issue #25 — cgroup-v2 containment spike: preflight verdict BLOCKED (spike NOT RUN)

Slice mandate: test-only spike proving cgroup membership survives
`setsid`/`setpgid` escape and `cgroup.kill` sweeps escaped descendants,
runnable ONLY on an already-delegated writable subtree; fail closed with
no sudo/chmod/mount/pre-existing-cgroup mutation otherwise.

**Verdict: BLOCKED — spike NOT RUN on the deployment environment.
F4 Gate B recommendation remains NO-GO.**

## 1. Preflight evidence (2026-11-17 KST, container `hermes`; all probes
read-only except one explicitly non-destructive failed-create probe —
`mkdir` under `/sys/fs/cgroup`, which returned EACCES and created
nothing)

| probe | observed |
|---|---|
| fs type | `stat -fc %T /sys/fs/cgroup` → `cgroup2fs` |
| mount flags | `/proc/mounts`: `cgroup2 ro,nosuid,nodev,noexec,relatime,nsdelegate,...` — **read-only** |
| controllers (root) | `cpuset cpu io memory hugetlb pids rdma misc dmem` |
| root `cgroup.subtree_control` | empty (no controllers distributed to children) |
| our cgroup | `/proc/self/cgroup` → `0::/` (we are AT the namespace root) |
| ownership/writability | `/sys/fs/cgroup` `drwxr-xr-x root root`; `cgroup.procs`/`cgroup.subtree_control`/`cgroup.kill` all not-writable for uid 1000; non-destructive `mkdir` probe → **EACCES** (nothing created) |
| other cgroup2 mounts | none (`awk` over `/proc/mounts`: exactly one, `ro`) |
| systemd CLI route | `systemctl`/`systemd-run` **absent in this container** — the systemd transient-scope delegation route is unavailable HERE; this does not claim delegation is impossible on hosts that do run a user manager |
| namespace identity | live mux `12053` and self share `cgroup:[4026534418]` — production vendor trees live inside this same read-only container cgroup namespace |

No sudo/root used; no chmod; no pre-existing cgroup touched; the single
`mkdir` probe failed and left nothing behind.

## 2. Why this is the decisive fail-closed case

- GO condition was "an already-delegated safe subtree or a disposable
  user transient scope creatable without sudo". Neither exists HERE: the
  only visible cgroupfs is `ro` + root-owned, and this container has no
  user manager CLI route.
- The production plugin/mux/vendor run **inside this container**, in the
  same cgroup namespace. So the **in-container `Popen` containment seam
  is blocked without a deployment-level delegation change** (e.g. the
  container runtime delegating a writable cgroup subtree), which is
  explicitly outside this slice's authority. This is a statement about
  the current deployment topology, not about cgroup v2 semantics.

## 3. Spike protocol (implemented, fail-closed; `tests/test_issue25_cgroup_spike.py`)

- Gate: `ACP_TEST_CGROUP_ROOT` must be absolute, pre-existing,
  EFFECTIVELY WRITABLE (capability check via `os.access`, not an owner
  check), non-mount-root, with a writable `cgroup.kill`; anything else →
  skip with BLOCKED reason, never PASS. The root must additionally be
  inside the RUNNING pytest process's own cgroup subtree — see §7 for
  the migration-containment requirement proven by the 2026-11-17 real
  run. A created CHILD cgroup without a
  writable `cgroup.kill` or with `cgroup.type != domain` is also a
  BLOCKED skip. The gate unit (`test_preflight_never_touches_non_delegated_roots`
  — always RUNs) plus ownership regression tests cover malformed roots,
  name collisions, work-path safety, partial pid publication, and the
  cleanup sweep order.
- Ownership: cgroup names carry a nonce; the work dir comes from
  `tempfile.mkdtemp`; `dir_created`/`work_created` flip only after the
  creation call succeeded and `killfile_ready` only after positive
  validation of the created child's writable `cgroup.kill` + `domain`
  type — cleanup may write `cgroup.kill` only when ready, so a
  child-without-`cgroup.kill` environment reaches the BLOCKED skip with
  zero residue (constructor-level regression test); cleanup never
  deletes or removes anything it did not create.
- Process-model parity: the fake outer leader is spawned with
  `start_new_session=True` (same as the real plugin→mux spawn); the
  spike asserts leader PGID==SID==leader pid, same-group child sharing
  both, and the escaped child owning its own PGID/SID.
- Protocol: fake leader is spawned then joined via `cgroup.procs`;
  it refuses to fork descendants until its own `/proc/self/cgroup`
  confirms membership (kills the pre-join fork race that would leak
  children into the parent cgroup); pids are published atomically
  (temp + `os.replace`) and only accepted once fully parseable.
  Same-group child + `setsid`-escaped child; sibling tree in a separate
  cgroup.
- Proofs: escaped child's `/proc/<pid>/cgroup` still names the target;
  membership in `cgroup.procs`; `cgroup.kill=1` → target leader (explicit
  reap, negative exit code) + same + escaped all not-running
  (zombie-aware); sibling all alive; `cgroup.events populated=0` plus
  empty `cgroup.procs` as the authoritative whole-cgroup proof;
  deterministic cleanup (own `cgroup.kill` sweep → known grandchildren →
  direct child reap → empty proof → own-dir removal), strict failures
  fail the test.

On this host: containment spike **SKIPPED (NOT RUN)**; fail-closed unit
passes. Once this rework passes independent review, the spike is
intended to run as-is on a host that delegates a subtree (e.g. a
systemd user scope with `Delegate=`, or a container runtime that mounts
a writable delegated cgroup subtree).

## 4. Platform contract assessment (design only, per mandate §5)

- Linux-only containment (cgroup v2) can be gated as a **platform-split
  production authority**: F4 deletion authority on Linux could
  additionally require cgroup-attested teardown, while Windows/macOS keep
  their existing (weaker, group/poll-based) contracts unchanged. Nothing
  in the current codebase couples the platforms' teardown guarantees, so
  a Linux-only ACK precondition is contractually expressible.
  **Expressible ≠ resolved**: this says nothing about Windows/macOS
  descendant-containment being solved; their detached-descendant gap
  remains open on those platforms too.
- Production seam candidate (design ONLY, not implemented): exactly one
  assignment point at plugin `Popen(mux, …)` (spawn into a delegated
  child cgroup, or fail-closed fall back to today's group teardown with
  containment=UNKNOWN recorded) + one teardown abstraction preferring
  `cgroup.kill` when the tree's cgroup is known. Windows Job Object and
  macOS alternatives explicitly NOT explored per mandate.

## 5. Gate B recommendation

**NO-GO (unchanged).** Candidate B is blocked by the deployment
environment, not by the primitive's semantics. ACK additionally requires
deployment-level cgroup delegation + live-tree attestation, or the
vendor-contract route (candidate A).

## 6. Next minimal action (proposed, not run)

Run this spike (after this ownership rework passes review) on a
delegated environment — requires an operator-approved deployment change
to delegate a cgroup subtree to this container, or a separate delegated
host. No production wiring until the spike PASSes there.

## 7. Real-kernel run (2026-11-17 KST, host gonus-X870E, operator-executed) — FAIL, root-cause split

Operator ran HEAD 2b2acbc as `gonus` with
`ROOT=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice`:
**1 failed, 6 passed, RC=1**; three empty `acp25-target-*` dirs left
(gonus-owned, `populated 0`, `cgroup.procs` empty — no process leak,
known residue, operator-cleared, not agent-cleared).

Two independent real-kernel findings:

1. **Migration containment (test-environment error, not a code bug).**
   The failing join was `PermissionError` writing the target child's
   `cgroup.procs`: the leader was spawned from `session-80.scope`, and
   `app.slice` is a SIBLING under `user@1000.service`. cgroup v2 only
   allows moving a process between cgroups whose common ancestor
   (`user-1000.slice` here) is itself inside the writable delegated
   branch; the ancestor was outside it, so EACCES is expected regardless
   of the destination file mode. **Contract: `ACP_TEST_CGROUP_ROOT` must
   be the RUNNING pytest process's own cgroup subtree**, not an
   arbitrary writable sibling.
2. **`cgroup.events` parser bug (code bug, fixed in this rework).**
   `populated()` parsed with `line.split("=", 1)[1]`, but the canonical
   kernel format is whitespace (`populated 0`). The resulting
   `IndexError` aborted cleanup before the owned-dir rmdir — that is why
   the three empty dirs remained. Fixed by a strict `_parse_populated()`
   (exact key, value in `{0,1}`, fail closed to `"?"`) plus real-format
   unit and cleanup regression tests.

### Recommended execution route (host systemd 259.5, Ubuntu)

`Delegate=` on transient user scopes is supported at this systemd
version. The agent could not exercise the user bus (DevSpace uid 997 has
no access to the gonus user manager), so **step 0 is the operator-run
on-host verification of the exact invocation** before the real run:

```sh
# 0) verify the invocation is accepted (transient scope running `true`):
systemd-run --user --scope -p Delegate=yes --unit=acp25-verify true

# 1) enter a disposable delegated scope (auto-named if --unit omitted):
systemd-run --user --scope -p Delegate=yes

# 2) inside the scope, derive the root from the LIVE cgroup and run:
R="$(awk -F: '$1=="0"{print $3}' /proc/self/cgroup)"
ACP_TEST_CGROUP_ROOT="/sys/fs/cgroup${R}" \
  pytest tests/test_issue25_cgroup_spike.py
```

Inside the delegated scope the spike creates only its own nonce child
cgroups and moves only its own spawned children — every join stays
within the delegated subtree, satisfying migration containment. Gate B
recommendation remains **NO-GO** until a run on such a delegated scope
PASSes; the three leftover dirs stay as known residue until the
operator removes them.
