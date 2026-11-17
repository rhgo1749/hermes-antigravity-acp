# Issue #25 — Linux production cgroup-delegation plan (GO-ready, PROPOSAL ONLY)

Status: **PROPOSED — nothing in this document has been applied.** No compose,
systemd, container, or live-process change was made for this plan. Gate B
remains **NO-GO** until the canary below passes AND the operator approves the
production mutation. This document is the Phase-3 deliverable for the
containment seam (PR #53, stacked on #50); the seam itself is inert
(`containment=UNKNOWN`) until the conditions in §3 hold.

## 1. Topology fresh-read (2026-11-18, read-only evidence)

Container (`hermes`, this workspace):

| probe | observed |
|---|---|
| `/proc/mounts` / `findmnt` | `cgroup2` on `/sys/fs/cgroup` mounted **`ro`**,`nosuid,nodev,noexec,nsdelegate,...` (superblock itself `rw`) |
| `/proc/self/cgroup` (PID 1 and shell) | `0::/` — **private cgroup namespace** (ns inode `4026534423`) |
| `/proc/self/status` caps | `CapEff=0000000000000000` (gateway runs as uid 1000, zero caps) |
| `/.dockerenv` | present — Docker container |
| image init tree | s6-overlay; `/etc/cont-init.d/{01-hermes-setup,015-supervise-perms,02-reconcile-profiles}`; `01-hermes-setup` execs `/opt/hermes/docker/stage2-hook.sh` (root stage). **No user-extensible root-stage hook** (no run-parts from `/opt/data`), and **no cgroup handling anywhere** in `/opt/hermes/docker/*.sh` |
| `/opt/data` bind | host `/home/gonus/hermes-cloudcli/state/nous-migration-20261109-143536/data` (ext4 rw) |

Host (`gonus-X870E`, via devspace read-only; docker socket not readable by the
devspace-agent service account — least privilege, expected):

| probe | observed |
|---|---|
| `/sys/fs/cgroup` | cgroup v2, controllers `cpuset cpu io memory hugetlb pids rdma misc dmem`, root `root:root 555`, `systemctl is-system-running` = running |
| container placement | `system.slice/docker-<64hex>.scope` × 7 — Docker **systemd cgroup driver**, default `cgroupns=private` |
| canonical compose | `/home/gonus/hermes-cloudcli/docker-compose.nous.yml` (project `nous-hermes`, image `nousresearch/hermes-agent:v0.23.2`, container `hermes`): **no cgroup-related keys at all** — no `cgroupns`, `cgroup_parent`, `cap_add`, `privileged`, no delegation |

Consequence: inside the container the cgroupfs view is namespaced to the
container's own subtree and mounted read-only, and the gateway has no
capabilities. The PR #53 gate therefore evaluates `delegated_root() → None`
and every production spawn is `containment=UNKNOWN` — exactly the fail-closed
behavior the seam was built with. The 2026-11-17 host spike (docs §8) proved
the kernel primitive; what is missing is a **usable delegated subtree inside
the container's own cgroup namespace**.

## 2. Kernel constraints that shape the design

* cgroup-v2 unprivileged self-migration (`cgroup_procs_write_permission`,
  kernel ≥ 5.14) requires ALL of:
  1. write access on the destination's `cgroup.procs`;
  2. destination **and** source inside the caller's cgroup namespace;
  3. **write access to `cgroup.procs` of the destination's ancestor at the
     source's level** (the "common ancestor" rule).
* Rule 3 is what the 2026-11-17 bare-`app.slice` EACCES proved in the
  negative, and why the host spike passed: `systemd-run --user` with
  `Delegate=yes` chowns the WHOLE delegated scope subtree — scope root
  `cgroup.procs` included — to the unit owner. Chowning only a leaf dir is
  NOT delegation: a uid-1000 trampoline whose source sits at the scope root
  would pass the PR #53 gate and still fail the join with EACCES.
* Two ways to satisfy rule 3 for this container: (a) chown the scope root's
  `cgroup.procs` — REJECTED: uid 1000 is uid 1000 in EVERY container here,
  so a same-uid process in another container could migrate itself INTO this
  scope (cross-container interference vector); or (b) **relocate the
  container's own process tree one level down into the delegated subtree** so
  the ancestor becomes the delegated dir itself (owned by 1000). This plan
  uses (b): the relocation is performed by root (which bypasses the
  permission checks) at setup time, and afterwards every unprivileged join
  the seam performs has source and destination inside the delegated subtree.
* No controllers are needed: the seam uses only `cgroup.procs`,
  `cgroup.events`, `cgroup.kill` (always present on v2 ≥ 5.14) — no
  `cgroup.subtree_control` mutation anywhere.
* Mount flag flips on the container's cgroupfs MUST be per-mount
  (self-bind + `remount,bind,...`). A plain `remount,rw` would flip the
  SHARED cgroup2 superblock and make the HOST's cgroupfs rw — forbidden.
* The PR #53 gate additionally requires (by design) the root to sit under
  `/sys/fs/cgroup` within the process's own namespace subtree, be canonical
  (resolved), pre-existing, and effectively writable. After the §4
  relocation a container process's own path IS `/acp-delegate`, which the
  gate accepts (`root == own-subtree base`).

## 3. Minimal runtime delegation conditions (production, ALL five)

1. A directory `acp-delegate` exists as a direct child of the container's
   own scope cgroup, `chown -R 1000:1000` (the container's hermes uid),
   created by root — it must survive as long as the container.
2. **The container's process tree is relocated into `acp-delegate`** (root
   writes the pids in the scope root's `cgroup.procs` into
   `acp-delegate/cgroup.procs` once, at setup), so unprivileged
   self-migration satisfies the common-ancestor rule with the 1000-owned
   delegate dir (§2 rule 3).
3. That subtree is visible **rw** inside the container at
   `/sys/fs/cgroup/acp-delegate` via per-mount flag flips only (self-bind of
   the ns-visible path; the parent mount keeps its original ro flags; the
   shared superblock is never touched).
4. `HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT=/sys/fs/cgroup/acp-delegate` set in
   the `hermes-gateway` environment.
5. Nothing else: no controllers, no `cgroup_parent`, no namespace changes,
   no capability changes to the gateway process itself.

## 4. Options (proposed diffs — NOT applied)

### P1 (recommended): host-side delegation helper + env var only — zero container capability change

Host systemd unit (new, e.g. `acp-cgroup-delegate.service`, triggered on the
Docker `start` event for `hermes` / after recreate) running as root:

```sh
set -eu
CID=$(docker inspect -f '{{.Id}}' hermes)
PID=$(docker inspect -f '{{.State.Pid}}' hermes)
[ "$PID" -gt 0 ] || { echo "container not running"; exit 1; }
# Verify the scope path actually belongs to THIS container before touching it.
test "$(cat "/proc/$PID/cgroup")" = "0::/system.slice/docker-${CID}.scope"
S="/sys/fs/cgroup/system.slice/docker-${CID}.scope"
D="$S/acp-delegate"
mkdir -p "$D"
chown -R 1000:1000 "$D"
# (2) relocate the container's process tree into the delegate subtree.
#     Root bypasses migration permission checks; systemd/docker scope stop
#     kills the whole subtree (children included) and stats aggregate
#     recursively — the canary (§5 step 6) VERIFIES those lifecycle claims
#     rather than assuming them.
while read -r p; do echo "$p" > "$D/cgroup.procs"; done < "$S/cgroup.procs"
# (3) make ONLY the delegate subtree rw INSIDE the container's mount ns.
#     No parent rw is needed or performed: the mount point already exists
#     (created host-side in step 1) and a bind mount does not require write
#     access to the underlying mount — only CAP_SYS_ADMIN, which the host
#     root helper has.  The parent keeps its ORIGINAL ro mount untouched;
#     exactly one new mount exists, the delegate's own rw self-bind.
#     mountpoint guard makes re-runs idempotent (bind-over-bind would
#     otherwise STACK mount layers, not replace).
nsenter -t "$PID" -m -- sh -eu -c '
  mountpoint -q /sys/fs/cgroup/acp-delegate ||
    mount --bind /sys/fs/cgroup/acp-delegate /sys/fs/cgroup/acp-delegate
  mount -o remount,bind,rw /sys/fs/cgroup/acp-delegate'
# Post-attestation (fail closed): delegate rw inside the ns, parent ro again
# (it never stopped being ro), and EXACTLY ONE mount attached to the delegate
# path.  findmnt -T is useless here (it selects the single covering mount, so
# stacked binds would still print one line); enumerate exact-target entries in
# mountinfo instead — more than one line means stacked layers -> fail.
nsenter -t "$PID" -m -- findmnt -T /sys/fs/cgroup/acp-delegate -o OPTIONS | grep -qw rw
nsenter -t "$PID" -m -- findmnt /sys/fs/cgroup -o OPTIONS | grep -qw ro
test "$(nsenter -t "$PID" -m -- awk '$5=="/sys/fs/cgroup/acp-delegate"' /proc/self/mountinfo | wc -l)" -eq 1
```

If any step fails, the unit exits non-zero and the seam stays UNKNOWN —
partial states are visible (`findmnt`, `mountinfo`), never papered over.
Re-runs are idempotent (`mkdir -p`; `mountpoint` guard skips an existing
bind; `remount,bind,rw` on already-rw is a no-op; relocating already-
relocated pids is a no-op); on container recreation the unit re-runs for the
new scope id.

Compose diff (production, the ONLY service change):

```yaml
     HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE: "trusted-coding"
     HERMES_ANTIGRAVITY_ACP_WORKSPACE: "/ws"
+    HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT: "/sys/fs/cgroup/acp-delegate"
```

Why this is safe: the delegate subtree is the container's OWN territory —
kernel namespace rules still confine every unprivileged migration inside it
(any destination outside requires write access to root-owned files elsewhere);
uid-1000 write power never touches the scope root or any other container's
cgroups; the gateway keeps `CapEff=0`; if the unit is absent or fails, the
gate sees a missing or unwritable root → `UNKNOWN` → today's behavior
(fail-closed, no promotion).

### P2: `cap_add: [SYS_ADMIN]` + root-stage setup inside the container

Same §3 shape executed by the container's own root stage (entrypoint
override). Requires overriding `entrypoint:` — the official image has **no
supported root-stage extension point** and the deployment AGENTS.md says do
not set `entrypoint:` — and grants a broad capability. Not recommended for
production; used ONLY as the disposable canary shape (§5), where the
entrypoint override is acceptable precisely because the canary is throwaway.

### P3: `privileged: true` — REJECTED (security regression for a containment
nice-to-have; also makes `/sys/fs/cgroup` rw for every process in the
container).

### Explicitly NOT proposed

`cgroup_parent`/`cgroupns: host` changes (break the gate's own-subtree
invariant or widen host visibility), scope-root `cgroup.procs` chown
(cross-container same-uid interference vector, §2), Podman runtime migration
(out of scope), any Windows/macOS mechanism (mandate §5).

## 5. Disposable canary procedure (production-equivalent, throwaway)

A separate compose project (`nous-hermes-acp-canary`), same image
`nousresearch/hermes-agent:v0.23.2`, **verified-copy** state dirs (the compose
header rule: never share a state dir with the live gateway), container name
`hermes-acp-canary`, `cap_add: [SYS_ADMIN]` (P2 shape standing in for the P1
host helper — the kernel-relevant end state is identical: relocated process
tree + rw delegate subtree + env var), removed entirely afterwards.

1. Start canary with entrypoint override (root stage, disposable). The
   sequence reaches P1's EXACT mount end-state (parent = original ro,
   delegate = rw self-bind; no stacked mounts, no shared-superblock flips).
   Ordering is load-bearing: the temporary parent self-bind exists ONLY for
   the `mkdir` (the one operation that DOES need a rw parent); it is unmounted
   BEFORE the delegate bind is created, so no child is ever stacked under it
   and the original ro parent mount reappears intact. PID 1 relocates into
   the delegate before `/init` execs, so every container process — gateway,
   mux, vendor children — is BORN inside it (§3 condition 2). The findmnt
   pre-flight is INSIDE the executable chain before `exec` — a literal
   copy/paste cannot bypass it:
   `mount --bind /sys/fs/cgroup /sys/fs/cgroup && mount -o remount,bind,rw /sys/fs/cgroup && mkdir -p /sys/fs/cgroup/acp-delegate && chown 1000:1000 /sys/fs/cgroup/acp-delegate && echo 1 > /sys/fs/cgroup/acp-delegate/cgroup.procs && umount /sys/fs/cgroup && mount --bind /sys/fs/cgroup/acp-delegate /sys/fs/cgroup/acp-delegate && mount -o remount,bind,rw /sys/fs/cgroup/acp-delegate && findmnt /sys/fs/cgroup -o OPTIONS | grep -qw ro && findmnt -T /sys/fs/cgroup/acp-delegate -o OPTIONS | grep -qw rw && test "$(awk '$5=="/sys/fs/cgroup/acp-delegate"' /proc/self/mountinfo | wc -l)" -eq 1 && exec /init gateway run`
   With `HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT=/sys/fs/cgroup/acp-delegate`.
   Any `&&` link failing aborts the entrypoint before `/init` ever starts.
2. Gate attestation (inside canary, as hermes uid 1000):
   `python -c "from cgroup_containment import delegated_root; print(delegated_root())"`
   must print the root — else STOP (fail-closed, §6).
3. **Unprivileged-join gate** — the real seam tests (the two that SKIP
   everywhere else, PR #53), run as uid 1000:
   `pytest tests/test_issue25_cgroup_containment_seam.py -k real -q`
   → must be **2 passed, 0 skipped**. These ARE the unprivileged-join proof:
   the trampoline (uid 1000) self-migrates under the common-ancestor rule;
   EACCES here would mean §2 rule 3 is unmet. They also pin
   membership-before-first-fork, escaped-descendant sweep via `cgroup.kill`,
   sibling cgroup untouched, empty proof, own-dir removal.
4. Production-equivalent live check: run one real ACP request through the
   canary gateway (mux + vendor children spawn normally). During the request:
   every mux/vendor descendant's `/proc/<pid>/cgroup` ends in
   `/acp-delegate/acpmux-<nonce>` (fork-before-containment race closed);
   a normal request completes with unchanged latency/semantics.
5. After teardown (session close / idle teardown):
   zero `acpmux-*` nonce dirs remain under `acp-delegate` (**residue 0**;
   each nonce's `cgroup.events populated 0` + `cgroup.procs` empty precedes
   its removal by the ladder); `acp-delegate` itself legitimately persists
   and holds the relocated container processes; sibling cgroups (other
   containers, host services) untouched.
6. **Lifecycle-parity verification** (turns §4's systemd/Docker assumptions
   into evidence, with measurable criteria — `docker stats` nonzero alone
   proves nothing since it could reflect the gateway alone):
   - **Aggregation:** take `docker stats --no-stream` CPU for the canary
     while idle, then again DURING a busy ACP request (mux + vendor children
     active). Criterion: the busy reading materially exceeds the idle one
     AND, on the host, `cat <canary-scope>/cpu.stat` and
     `<canary-scope>/acp-delegate/cpu.stat` both show nonzero `usage_usec`
     growth over the same window (children's usage lands in the scope
     aggregate because stats recurse).
   - **Stop semantics:** `docker stop hermes-acp-canary` completes within
     `stop_grace_period` (no SIGKILL fallback needed). Then on the host,
     with `SCOPE=/sys/fs/cgroup/system.slice/docker-<canary-id>.scope`,
     distinguish the FOUR states explicitly (GNU find's `-exec … +`
     PROPAGATES grep's exit: 1 on "no file matched" is the DESIRED empty
     state, so raw nonzero-find-exit must not be the criterion):
     `if [ ! -d "$SCOPE" ]; then echo "SCOPE-ABSENT (vacuous pass — recorded)";
     else out=$(find "$SCOPE" -name cgroup.procs -exec grep -l . {} + 2>/dev/null); rc=$?;
     if [ "$rc" -ge 2 ]; then echo "TRAVERSAL ERROR rc=$rc (FAIL)"; exit 1; fi;
     if [ -n "$out" ]; then echo "ORPHANS: $out (FAIL)"; exit 1; fi;
     echo "SCOPE-PRESENT, ALL cgroup.procs EMPTY (PASS)"; fi`
     — `grep -l .` lists any `cgroup.procs` whose CONTENTS contain a pid
     (content-based on purpose: `test -s` is vacuous on cgroupfs
     pseudo-files, st_size is 0 regardless of pids); rc 0/1 are both normal
     (0 = orphans found, listed in `$out`; 1 = none), rc ≥ 2 = genuine
     traversal/read error. Additionally `pgrep -fa 'nous-hermes-acp-canary'`
     (the concrete quoted compose project marker used at canary creation)
     must be empty.
7. Teardown canary: `docker compose -p nous-hermes-acp-canary down` + delete
   the copy dirs. No production artifact touched at any step.

**Canary success criteria = steps 2–6 all PASS with zero nonce residue.
Anything else = FAIL/NOT RUN → Gate B stays NO-GO; production untouched.**

## 6. Fail-closed criteria (already enforced by the seam itself)

* Root missing / not canonical / mount-root / not writable / no writable
  `cgroup.kill` / outside own namespace subtree → `delegated_root()=None` →
  `containment=UNKNOWN`, legacy spawn+teardown byte-identical to today.
* Trampoline join EACCES (common-ancestor rule unmet) → exit 87, no exec,
  kill+reap, own-cgroup-only abort, respawn UNKNOWN — a mis-delegated
  environment degrades, never half-contains.
* Trampoline exec verdict failure → same UNKNOWN fallback, never promoted.
* Teardown ownership/inode/empty-proof failure → `None` (UNVERIFIED) + legacy
  escalation, or `False` (verified-dead + own-dir residue logged) — never a
  silent success; foreign objects never touched.
* Canary step 2 or 3 failing ⇒ no production mutation is even proposed.

## 7. Rollback (production, post-approval)

```sh
set -eu
# (1) STOP THE HELPER FIRST: an event-triggered unit would otherwise re-run
#     the delegation the moment anything re-triggers its start event.
systemctl disable --now acp-cgroup-delegate.service
CID=$(docker inspect -f '{{.Id}}' hermes)
PID=$(docker inspect -f '{{.State.Pid}}' hermes)
S="/sys/fs/cgroup/system.slice/docker-${CID}.scope"
# (2) VERIFIED unmount of the delegate bind — no '|| true': if the kill
#     switch cannot be pulled, rollback STOPS loudly (fail closed) instead
#     of leaving an env-configured root writable and claiming success.
nsenter -t "$PID" -m -- umount /sys/fs/cgroup/acp-delegate
nsenter -t "$PID" -m -- mountpoint -q /sys/fs/cgroup/acp-delegate \
  && { echo "ROLLBACK INCOMPLETE: delegate bind still mounted"; exit 1; }
# (3) move the container's processes back to the scope root (root may do
#     this), then remove the now-empty delegate dir.
while read -r p; do echo "$p" > "$S/cgroup.procs"; done < "$S/acp-delegate/cgroup.procs"
rmdir "$S/acp-delegate"   # refuses non-empty; residue stays visible
```

If step (2) fails, the delegate bind remains and the seam may still see a
usable root — that is a KNOWN, LOUD rollback-incomplete state: leave the
env var REMOVED (next recreate → gate `None` → UNKNOWN regardless) and
investigate the mount state (`findmnt`) before retrying. Removing
`HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT` from compose at the next approved
recreate window is the belt-and-braces second switch; when the unmount
succeeds, the umount alone is the effective kill switch and needs NO
container restart (the gate sees the root vanish → `UNKNOWN` on the very
next spawn). The seam writes no state; rollback cannot orphan anything the
seam created (nonce dirs are removed by teardown or left visible as logged
residue).

## 8. Open decision for the operator (exactly one)

Approve (or reject) running **§5 canary** — a disposable container, zero
production contact — as the next step. Production mutation (§4 P1) is proposed
only after canary PASS and requires its own explicit approval; merge of
#49–#54 remains separately gated.

## 9. Consistency with prior evidence

* #49/#50/#51/#52/#53 semantics unchanged; this plan mutates nothing.
* The 2026-11-17 bare-`app.slice` EACCES finding is exactly §2's rule-3
  demonstration; the host spike (`fd03122`, `Delegate=yes` full-scope
  delegation) is its positive control. The canary re-proves both in the
  container shape production actually runs.
