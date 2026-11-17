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

- Gated on `ACP_TEST_CGROUP_ROOT`: absolute, pre-existing, writable,
  non-root, with a writable `cgroup.kill`; anything else → skip with
  BLOCKED reason (never PASS). The gate itself is unit-tested against
  malformed/unsafe roots (`test_preflight_never_touches_non_delegated_roots`
  — this part RUNs and passes everywhere).
- When runnable: fake leader is spawned then joined via `cgroup.procs`;
  it refuses to fork descendants until its OWN `/proc/self/cgroup`
  confirms membership (kills the pre-join fork race that would leak
  children into the parent cgroup). Same-group child + `setsid`-escaped
  child; sibling tree in a separate child cgroup.
- Proofs: escaped child's `/proc/<pid>/cgroup` still names the target;
  membership in `cgroup.procs`; `cgroup.kill=1` → target leader + same +
  escaped all dead, sibling all alive; `cgroup.events populated=0`;
  cleanup `rmdir`s only its own empty dirs.

On this host: containment spike **SKIPPED (NOT RUN)**; fail-closed unit
passes. The spike is ready to run unmodified on any host that delegates
a subtree (e.g. a systemd user scope with `Delegate=`, or a container
runtime that mounts a writable delegated cgroup subtree).

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

Run the existing spike unmodified on a delegated environment (requires
an operator-approved deployment change to delegate a cgroup subtree to
this container, or a separate delegated host). No production wiring
until the spike PASSes there.
