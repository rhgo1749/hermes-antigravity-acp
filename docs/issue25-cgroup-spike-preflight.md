# Issue #25 — cgroup-v2 containment spike: container preflight BLOCKED; spike EXECUTED PASS on a host delegated scope

Slice mandate: test-only spike proving cgroup membership survives
`setsid`/`setpgid` escape and `cgroup.kill` sweeps escaped descendants,
runnable ONLY on an already-delegated writable subtree; fail closed with
no sudo/chmod/mount/pre-existing-cgroup mutation otherwise.

**Verdicts, kept environment-separate:
- Deployment container: preflight BLOCKED — spike NOT RUN
  there (§1–§2, historical record, unchanged).
- Operator's host, transient delegated scope at HEAD `fd03122`:
  spike EXECUTED — 10 passed / 0 skipped, RC=0, zero residue (§8).
  Linux cgroup-v2 containment hypothesis CONFIRMED on the host.
F4 Gate B recommendation remains NO-GO: no production mux wiring or
deployment-level delegation exists yet.**

## 1. Preflight evidence (2026-11-17 KST, deployment container; all probes
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

On the deployment container: containment spike **SKIPPED (NOT RUN)**;
fail-closed units pass. The spike has since run AS-IS (test file
unmodified, HEAD `fd03122`) on a host transient delegated scope and
**PASSED** — see §8.

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
environment, not by the primitive's semantics — the §8 host run now
CONFIRMS the primitive's semantics (membership survives `setsid`,
`cgroup.kill` sweeps escaped descendants, sibling untouched). ACK
additionally requires deployment-level cgroup delegation + live-tree
attestation in the production topology, or the vendor-contract route
(candidate A).

## 6. Next minimal action (proposed 2026-11-17; EXECUTED — see §8)

Run this spike (after this ownership rework passes review) on a
delegated environment — requires an operator-approved deployment change
to delegate a cgroup subtree to this container, or a separate delegated
host. No production wiring until the spike PASSes there. Executed
2026-11-18 on the host via a transient delegated scope (§8); the
container-side deployment delegation remains the open production item.

## 7. Real-kernel run (2026-11-17 KST, operator's host, operator-executed) — FAIL, root-cause split

Operator ran HEAD 2b2acbc as their desktop user with
`ROOT=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice`:
**1 failed, 6 passed, RC=1**; three empty `acp25-target-*` dirs left
(operator-owned, `populated 0`, `cgroup.procs` empty — no process leak,
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
no access to the operator's user manager), so **step 0 is the operator-run
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

**One-shot pitfall:** the interactive `--scope` route above derives `R`
inside the scope's own shell, so it is unaffected. A ONE-SHOT
`systemd-run` invocation must pass `--expand-environment=no`: the
default `--expand-environment=yes` pre-expands `$R` in the unit command
argv against systemd-run's CLIENT environment (where `R` is unset)
before the unit ever starts, silently corrupting
`ACP_TEST_CGROUP_ROOT`. The executed one-shot recipe is §8.

Inside the delegated scope the spike creates only its own nonce child
cgroups and moves only its own spawned children — every join stays
within the delegated subtree, satisfying migration containment. Gate B
recommendation remains **NO-GO** until a run on such a delegated scope
PASSes (since satisfied by §8 — Gate B itself stays NO-GO pending
production delegation/attestation); the three leftover dirs were
operator-cleared (§8 fresh host read confirms `app.slice` `acp25-*`
residue 0).

## 8. Delegated-scope real run (2026-11-18 KST, host operator host, operator-executed, HEAD `fd03122`) — EXECUTED, PASS

The spike test file was UNMODIFIED from `fd03122` (this section is
docs-only evidence closure; tests/source untouched).

Invocation actually used — a transient delegated SERVICE (not the §7
interactive scope); `…` abbreviates the pytest command carrying
`ACP_TEST_CGROUP_ROOT` derived inside the unit:

```sh
systemd-run --user --unit=acp25-spike-004214 \
  --wait --collect --pipe --expand-environment=no \
  -p Delegate=yes …
```

Observed (operator-reported live state + reviewer fresh host read):

- Live cgroup inside the unit:
  `/user.slice/user-1000.slice/user@1000.service/app.slice/acp25-spike-004214.service`
  — the transient unit's OWN cgroup, i.e. the running pytest process's
  own subtree; `Delegate=yes` makes it a writable delegated branch, so
  every join stays inside the delegated subtree and the §7
  migration-containment contract is satisfied by construction.
- Result: **10 passed / 0 skipped** (9 fail-closed/regression units +
  the gated containment spike), pytest status 0 / unit SUCCESS,
  `systemd-run` RC=0.
- Reviewer fresh host read after the run: pytest/leader/sleep.py
  processes 0; transient-unit residue 0; `app.slice` `acp25-*`
  residue 0. The §7 residue bug did not recur — deterministic cleanup
  held on the real kernel.

Reproduction recipe (one-shot; reflects the confirmed flags of the
executed invocation; run from the host repo checkout at `fd03122` as
the user owning the systemd user manager):

```sh
systemd-run --user --unit="acp25-spike-$(date +%H%M%S)" \
  --wait --collect --pipe --expand-environment=no \
  -p Delegate=yes \
  bash -c 'R="$(awk -F: "\$1==\"0\"{print \$3}" /proc/self/cgroup)"; \
    ACP_TEST_CGROUP_ROOT="/sys/fs/cgroup${R}" \
    exec pytest tests/test_issue25_cgroup_spike.py'
```

`--expand-environment=no` is REQUIRED (§7 pitfall note); `--wait
--collect --pipe` leaves the transient unit fully collected after exit
(residue 0 confirmed above).

**Assessment: the Linux cgroup-v2 containment hypothesis is CONFIRMED
on the host** — membership survived the `setsid` escape, `cgroup.kill`
swept leader + same-group + escaped descendant while the sibling
cgroup stayed alive, and `populated=0` + empty `cgroup.procs` +
owned-dir removal all held. This is a HOST delegated-scope proof, NOT
production attestation: the container's cgroupfs is still `ro` (§1)
and no production mux wiring exists. Gate B remains **NO-GO** until
the production topology delegates a subtree and live-tree attestation
passes.
