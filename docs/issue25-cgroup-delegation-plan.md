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
the kernel primitive; what is missing is a **writable delegated subtree inside
the container's own cgroup namespace**.

## 2. Kernel constraints that shape the design

* cgroup-v2 self-migration (what the trampoline does) requires, for an
  unprivileged process: write access on the destination `cgroup.procs`, and
  (kernel ≥ 5.14 `cgroup_procs_write_permission`) destination **and** source
  inside the caller's cgroup namespace. A delegated directory from OUTSIDE the
  container's scope is therefore useless even if bind-mounted rw.
* The destination must be a real descendant of the container's own
  `docker-<id>.scope`, and the container's mount of it must not be `ro`-blocked.
* No controllers are needed: the seam uses only `cgroup.procs`,
  `cgroup.events`, `cgroup.kill` (always present on v2 ≥ 5.14) — no
  `cgroup.subtree_control` mutation anywhere.
* The PR #53 gate additionally requires (by design) the root to sit under
  `/sys/fs/cgroup` within the process's own namespace subtree, be canonical
  (resolved), pre-existing, and effectively writable.

## 3. Minimal runtime delegation conditions (production, ALL four)

1. A directory `acp-delegate` exists as a direct child of the container's own
   scope cgroup, `chown 1000:1000` (the container's hermes uid), created by a
   privileged actor — it must survive as long as the container.
2. That directory is visible **rw** inside the container at a path under
   `/sys/fs/cgroup` (so the gate's own-subtree check passes and writes are not
   `EROFS`-blocked).
3. `HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT=/sys/fs/cgroup/acp-delegate` set in the
   `hermes-gateway` environment.
4. Nothing else: no controllers, no `cgroup_parent`, no namespace changes, no
   capability changes to the gateway process itself.

## 4. Options (proposed diffs — NOT applied)

### P1 (recommended): host-side delegation helper + env var only — zero container capability change

Host systemd unit (new, e.g. `acp-cgroup-delegate.service` + `.path` or a
`docker events`-driven oneshot) that, on container (re)start of `hermes`:

```sh
CID=$(docker inspect -f '{{.Id}}' hermes)
PID=$(docker inspect -f '{{.State.Pid}}' hermes)
D="/sys/fs/cgroup/system.slice/docker-${CID}.scope/acp-delegate"
mkdir -p "$D" && chown 1000:1000 "$D"
# The container's cgroupfs mount is ro, so the mount POINT cannot exist yet.
# Flag flips MUST be per-mount (self-bind + remount,bind,...): a plain
# remount,rw would flip the SHARED cgroup2 superblock and make the HOST's
# cgroupfs rw too.  The self-bind recipe touches only this mount namespace;
# the parent is restored to per-mount ro, leaving exactly one rw path: the
# delegate bind submount.
nsenter -t "$PID" -m -- sh -c "
  mount --bind /sys/fs/cgroup /sys/fs/cgroup &&
  mount -o remount,bind,rw /sys/fs/cgroup &&
  mkdir -p /sys/fs/cgroup/acp-delegate &&
  mount --bind '$D' /sys/fs/cgroup/acp-delegate &&
  mount -o remount,bind,rw /sys/fs/cgroup/acp-delegate &&
  mount -o remount,bind,ro /sys/fs/cgroup"
```

Compose diff (production, the ONLY service change):

```yaml
     HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE: "trusted-coding"
     HERMES_ANTIGRAVITY_ACP_WORKSPACE: "/ws"
+    HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT: "/sys/fs/cgroup/acp-delegate"
```

Rationale: the bind submount is created by a privileged host process, so the
container's `ro` cgroupfs mount does not block it; the destination is inside
the namespace (kernel check passes); the gateway keeps `CapEff=0`; the seam
gate passes unchanged. Cost: one small host unit tracking container restarts
(bind is lost on container recreation — the unit re-runs on the `start`
docker event). If the unit is ever absent/failing, the gate sees a missing or
unwritable root → `UNKNOWN` → today's behavior (fail-closed, no promotion).

### P2: `cap_add: [SYS_ADMIN]` + root-stage remount inside the container

Requires an entrypoint/init override (the official image has **no supported
root-stage extension point**, and the deployment AGENTS.md says do not set
`entrypoint:`), and grants a broad capability to the container. Not
recommended for production; acceptable shape for the disposable canary (§5).

### P3: `privileged: true` — REJECTED (security regression for a containment
nice-to-have; also makes `/sys/fs/cgroup` rw for every process in the
container).

### Explicitly NOT proposed

`cgroup_parent`/`cgroupns: host` changes (break the gate's own-subtree
invariant or widen host visibility), Podman runtime migration (out of scope),
any Windows/macOS mechanism (mandate §5).

## 5. Disposable canary procedure (production-equivalent, throwaway)

A separate compose project (`nous-hermes-acp-canary`), same image
`nousresearch/hermes-agent:v0.23.2`, **verified-copy** state dirs (the compose
header rule: never share a state dir with the live gateway), container name
`hermes-acp-canary`, `cap_add: [SYS_ADMIN]` (P2 shape — chosen only because a
canary may override the entrypoint; production will use P1), no host network
exposure beyond defaults, removed entirely afterwards.

1. Start canary with entrypoint override (root stage, disposable; per-mount
   flag flips only — the shared superblock is never touched):
   `mount --bind /sys/fs/cgroup /sys/fs/cgroup && mount -o remount,bind,rw /sys/fs/cgroup && mkdir -p /sys/fs/cgroup/acp-delegate && chown 1000:1000 /sys/fs/cgroup/acp-delegate && exec /init gateway run`
   with `HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT=/sys/fs/cgroup/acp-delegate`.
   (Here the delegate dir is a real child of the container's namespace root —
   no bind submount needed; the seam creates its nonce dirs inside it.)
2. Gate attestation (inside canary, as hermes):
   `python -c "from cgroup_containment import delegated_root; print(delegated_root())"`
   must print the root — else STOP (fail-closed, §6).
3. Real seam tests (the two that SKIP everywhere else, PR #53):
   `pytest tests/test_issue25_cgroup_containment_seam.py -k real -q`
   → must be **2 passed, 0 skipped** (membership-before-first-fork; escaped
   descendant swept by `cgroup.kill`, sibling cgroup untouched, empty proof,
   own-dir removal).
4. Production-equivalent live check: run one real ACP request through the
   canary gateway (mux + vendor children spawn normally). During the request:
   every mux/vendor descendant's `/proc/<pid>/cgroup` ends in
   `/acp-delegate/acpmux-<nonce>` (fork-before-containment race closed);
   a normal request completes with unchanged latency/semantics.
5. After teardown (session close / idle teardown):
   `cgroup.events populated 0`, `cgroup.procs` empty, `acpmux-*` dir removed
   by the ladder, **residue 0** (`ls /sys/fs/cgroup/acp-delegate` empty), and
   the canary's own scope (`cgroup.procs` of the scope root, minus the
   delegate subtree) shows no leaked descendants; sibling cgroups (other
   containers, host services) untouched.
6. Teardown canary: `docker compose -p nous-hermes-acp-canary down` + delete
   the copy dirs. No production artifact touched at any step.

**Canary success criteria = steps 2–5 all PASS with zero residue. Anything
else = FAIL/NOT RUN → Gate B stays NO-GO; production untouched.**

## 6. Fail-closed criteria (already enforced by the seam itself)

* Root missing / not canonical / mount-root / not writable / no writable
  `cgroup.kill` / outside own namespace subtree → `delegated_root()=None` →
  `containment=UNKNOWN`, legacy spawn+teardown byte-identical to today.
* Trampoline join or exec verdict failure → kill+reap, own-cgroup-only abort,
  respawn with original argv (UNKNOWN), never promoted.
* Teardown ownership/inode/empty-proof failure → `None` (UNVERIFIED) + legacy
  escalation, or `False` (verified-dead + own-dir residue logged) — never a
  silent success; foreign objects never touched.
* Canary step 2 or 3 failing ⇒ no production mutation is even proposed.

## 7. Rollback (production, post-approval)

1. Remove `HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT` from compose; `docker compose
   up -d hermes-gateway` (approved recreate window) → gate `None` → UNKNOWN
   immediately; legacy path is the byte-identical pre-seam behavior.
2. `systemctl disable --now acp-cgroup-delegate*`; `nsenter -t $PID -m umount
   /sys/fs/cgroup/acp-delegate`; `rmdir` the host dir when empty (refuses
   non-empty — residue stays visible, never force-removed).
3. No state, credential, or workspace data is ever written by the seam;
   rollback cannot orphan anything the seam created (nonce dirs are removed by
   teardown or left visible as logged residue).

## 8. Open decision for the operator (exactly one)

Approve (or reject) running **§5 canary** — a disposable container, zero
production contact — as the next step. Production mutation (§4 P1) is proposed
only after canary PASS and requires its own explicit approval; merge of
#49–#53 remains separately gated.

## 9. Consistency with prior evidence

* #49/#50/#51/#52/#53 semantics unchanged; this plan mutates nothing.
* The 2026-11-17 bare-`app.slice` EACCES finding is exactly why §2's namespace
  rule and the gate's own-subtree check exist.
* Host spike (docs §8, `fd03122`) proved kernel mechanics under a systemd
  transient scope; the canary re-proves them in the container shape that
  production actually runs.
