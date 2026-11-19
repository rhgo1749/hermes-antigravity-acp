# Issue #25 — Linux production cgroup-delegation plan (APPLIED on operator host, 2026-11-19)

Status: **APPLIED on the operator host (2026-11-19) after both gates closed.**
Gate B canary: PASS (run 20261118-225037, see PR #54 review comments). Gate C
P1 production-shape rehearsal: PASS (run 20261119-144120, EXIT=0, PR #54
comment `7000962504`). Production now runs the §4 P1 shape: compose env
`HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT` + host unit `acp-cgroup-delegate.service`
(docker start-event listener → pinned helper) on the operator's `hermes`
container; verified live (`delegated_root()` returns the delegate path; env
absent ⇒ `None`, i.e. zero dependency for regular plugin users). The plugin
itself is NOT yet installed in production; the seam stays inert until it is.
The rehearsal artifacts (helper v6, rollback v4.4, runner, unit, listener,
runbook) are committed under `docs/issue25-rehearsal/` with the md5 chain
recorded in PR #54. Sections below retain their as-authored "proposed / NOT
applied" wording as the pre-gate record; this paragraph is the current truth.

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
`nousresearch/hermes-agent:v0.23.2`, **verified-copy** state (the compose
header rule: never share a state dir with the live gateway). The copy is a
WHITELIST, not the full state tree: config.yaml, .env, auth.json, `.hermes`
ACP registry, the ACP mux (`data/.local/bin`), and the ACP account homes
under `home/.agy-acp` minus per-account `conversations/`, `brain/` history
and `.local/` duplicate CLI installs (auth core ~120M; the full tree is
~270G and its caches/backups have zero bearing on the gate —
operator veto 2026-11-18, SSD wear). The ACP CLIENT BINARIES
(`.local/opt/antigravity-acp`, ~2.1G immutable versioned installs) are
mounted READ-ONLY from production, never copied: the isolation rule
targets mutable state, and Block D attests both mounts are ro. Everything
else (state.db, sessions, profiles, cron) regenerates at boot; verified by
booting the same image
with an empty `/opt/data` (2026-11-18 probe: all s6 services started).
The plugin dir is built from the reviewed seam PLUS the production
deployment artifact `launch_config.json` (the mux `process_command`
override; untracked in git, present in the installed plugin tree): without
it the plugin falls back to the official launcher, skipping the mux and
per-account HOME switching, and `session/new` dies with `Authentication
required` (observed in the 2026-11-18 canary run).
Container name
`hermes-acp-canary`, `cap_add: [SYS_ADMIN]` (P2 shape standing in for the P1
host helper — the kernel-relevant end state is identical: relocated process
tree + rw delegate subtree + env var), removed entirely afterwards.
**Validation scope (stated honestly after the 2026-11-18 independent
review):** the P2 canary proves the kernel end-state shape, the seam
behavior, and the §5 gate mechanics. It does NOT exercise the P1 host
helper's operational path — one-time traversal/migration of a LIVE
production scope's PIDs, the mount-namespace helper against a running
container, and their race windows. The P1 helper below is therefore
**NOT production-validated by Gate B**; applying it requires a separate
explicitly-approved P1 rehearsal gate (staged dry-run + rollback plan)
before touching the live `hermes` container.

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
   copy/paste cannot bypass it. The `chown` MUST be recursive: cgroup2
   interface files (`cgroup.procs`, `cgroup.kill`) are created root-owned at
   `mkdir`, and a directory-only chown leaves them unwritable for uid 1000,
   failing `delegated_root()`'s capability checks (observed in the 2026-11-18
   canary run: non-recursive chown → `delegated_root()` returned None). The
   ns-root's own `cgroup.procs` is chowned to uid 1000 as a canary-only
   accommodation: `cgroup_procs_write_permission()` requires MAY_WRITE on the
   cgroup.procs of the src/dst COMMON ANCESTOR, and the docker-exec test
   session starts in the ns-root (dockerd-created, root-owned); production
   spawns the seam from the gateway's tree inside the delegate, so the scope's
   `cgroup.procs` is never a migration ancestor there (observed in the
   2026-11-18 canary run: uid-1000 trampoline join → EACCES):
   `mount --bind /sys/fs/cgroup /sys/fs/cgroup && mount -o remount,bind,rw /sys/fs/cgroup && chown 1000:1000 /sys/fs/cgroup/cgroup.procs && mkdir -p /sys/fs/cgroup/acp-delegate && chown -R 1000:1000 /sys/fs/cgroup/acp-delegate && echo 1 > /sys/fs/cgroup/acp-delegate/cgroup.procs && umount /sys/fs/cgroup && mount --bind /sys/fs/cgroup/acp-delegate /sys/fs/cgroup/acp-delegate && mount -o remount,bind,rw /sys/fs/cgroup/acp-delegate && findmnt /sys/fs/cgroup -o OPTIONS | grep -qw ro && findmnt -T /sys/fs/cgroup/acp-delegate -o OPTIONS | grep -qw rw && test "$(awk '$5=="/sys/fs/cgroup/acp-delegate"' /proc/self/mountinfo | wc -l)" -eq 1 && exec /init /opt/hermes/docker/main-wrapper.sh gateway run`
   With `HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT=/sys/fs/cgroup/acp-delegate`.
   Any `&&` link failing aborts the entrypoint before `/init` ever starts.
   The final `exec` targets `/opt/hermes/docker/main-wrapper.sh gateway run`
   — the production container's actual main command (read from the live
   container's rc.init process arguments); a bare `gateway run` is not an
   executable and dies with `gateway: not found` (observed in the 2026-11-18
   canary run).
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
   `/acp-delegate/acpmux-<nonce>` (fork-before-containment race closed).
   The check must sweep BOTH directions: (i) enumerate every ACP-signature
   process inside the container (`antigravity-acp-mux`, `agy_acp_server`,
   `localharness`) and assert each one's cgroup ends in an `acpmux-<nonce>`
   path — an escaped descendant fails the gate; (ii) sample each nonce
   cgroup's members and confirm the expected mux + vendor pair is present.
   A normal request completes with unchanged latency/semantics.
5. After teardown (idle eviction / shutdown): each evicted nonce's
   `cgroup.events populated 0` + `cgroup.procs` empty PRECEDES its removal
   by the ladder — this per-entry precondition is enforced by the seam code
   and pinned by the step-3 real seam tests. Mid-run eviction is LAZY
   (expired entries are swept only by the next same-key `_warm_acquire`,
   and warm reuse refreshes `idle_since`), so a bounded "at least one
   request-1 tree torn down while the gateway lives" observation is the
   correct mid-run criterion; global residue 0 is guaranteed at shutdown by
   the atexit warm-pool shutdown and must be attested after `docker stop`
   (no-orphans + no-project-procs). `acp-delegate` itself legitimately
   persists while the container runs and holds the relocated container
   processes; sibling cgroups (other containers, host services) untouched.
6. **Lifecycle-parity verification** (turns §4's systemd/Docker assumptions
   into evidence, with measurable criteria — `docker stats` nonzero alone
   proves nothing since it could reflect the gateway alone):
   - **Aggregation:** ACP requests are I/O-bound (the mux waits on the
     remote LLM), so a `docker stats` busy/idle CPU% RATIO is NOT a valid
     busy signal (it false-failed a healthy canary run on 2026-11-18 at
     1.01% vs 0.69%; the ratio readings are retained as receipt evidence
     only). The criterion is HIERARCHICAL ARITHMETIC over `cpu.stat
     usage_usec` (hierarchical in cgroup v2) across a busy window:
     nonce-cgroup CPU burned inside the window > 0 — per-tree
     baseline-matched (a tree present at both samples contributes its
     delta; a tree born mid-window contributes full usage; an evicted
     tree drops out) — AND `nonce_delta <= delegate_delta <= scope_delta`
     (contained accounting rolls up). All three levels must show nonzero
     growth over the window.
   - **Stop semantics:** `docker stop hermes-acp-canary` completes within
     `stop_grace_period` (no SIGKILL fallback needed). Then on the host,
     with `SCOPE=/sys/fs/cgroup/system.slice/docker-<canary-id>.scope`,
     traversal and content inspection are SEPARATED so no exit status is
     ever ambiguous (find rc is checked alone, without -exec and without
     stderr suppression; each file is then read individually):
     `if [ ! -d "$SCOPE" ]; then
       echo "SCOPE-ABSENT (vacuous pass — recorded)"
     else
       files=$(find "$SCOPE" -name cgroup.procs) || { echo "TRAVERSAL ERROR (FAIL)"; exit 1; }
       [ -n "$files" ] || { echo "NO cgroup.procs FOUND (FAIL — unexpected)"; exit 1; }
       orphans=""
       while IFS= read -r f; do
         if content=$(cat -- "$f" 2>/dev/null); then
           [ -n "$content" ] && orphans="$orphans $f(pids:$content)"
         else
           echo "READ ERROR: $f (FAIL)"; exit 1
         fi
       done <<< "$files"
       if [ -n "$orphans" ]; then echo "ORPHANS:$orphans (FAIL)"; exit 1; fi
       echo "SCOPE-PRESENT, ALL $(printf '%s\n' "$files" | wc -l) cgroup.procs EMPTY (PASS)"
     fi`
     — five distinct outcomes: SCOPE-ABSENT (recorded vacuous pass),
     traversal error (find's own rc, FAIL), zero cgroup.procs found
     (unexpected for a live-or-just-stopped scope → FAIL, not silent
     silence), per-file read error (FAIL), nonempty CONTENTS (ORPHANS with
     the pids listed, FAIL). Content-based by design: `test -s` is vacuous
     on cgroupfs pseudo-files (st_size is 0 regardless of pids).
     Additionally `pgrep -fa 'nous-hermes-acp-canary'` (the concrete quoted
     compose project marker used at canary creation) must be empty.
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
