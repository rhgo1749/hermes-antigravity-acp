#!/usr/bin/env bash
# acp25-p1-helper v6 — host-side cgroup delegation helper for the `hermes`
# container (plan §4 P1). Usage: sudo acp25-p1-helper.sh [CONTAINER]
# v1 = plan §4 verbatim. v2 adds the RELOCATION RE-PASS loop: the v1
# `while read` loop migrates a snapshot; children forked into the scope root
# during the loop are missed and v1's post-attestation never re-checks
# $S/cgroup.procs for residue.
# v4 (live rehearsal failure 20261119-002102): pass cap 3->50 + 50ms settle
# pacing + residue forensics on FAIL. The 3-pass cap died on a live s6
# supervision tree still settling: new long-lived s6-supervise processes were
# born AFTER the last pass read (etimes-proven), not short fork-race children.
# Convergence: once every spawner sits in the delegate, new scope-root tasks
# cannot be born (no docker-exec runs during the helper); each pass drains all
# current scope-root tasks, so bounded spawner generations => bounded passes.
# Idempotent by design (plan §4): mkdir -p, mountpoint guard, remount no-op,
# relocating already-relocated pids is a no-op.
# NEVER: touch any scope other than the target container's own; never
# restart/stop the container.
set -eu

CONTAINER="${1:-hermes}"
CID=$(docker inspect -f '{{.Id}}' "$CONTAINER")
PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")
[ "$PID" -gt 0 ] || { echo "container not running"; exit 1; }
# Verify the scope path actually belongs to THIS container before touching it.
# v5.1 (Block H live fail 20261119-012654): PREFIX match, not equality —
# after a successful delegation PID1 itself lives under the scope (in
# acp-delegate), so the v1 equality test made the helper's own idempotent
# re-run die silently (set -e, zero output). Ownership boundary = "inside
# this container's scope (root or any subtree of it)".
cg=$(cat "/proc/$PID/cgroup")
case "$cg" in
  "0::/system.slice/docker-${CID}.scope"|"0::/system.slice/docker-${CID}.scope/"*) ;;
  *) echo "FAIL: pid1 cgroup '$cg' is not this container's scope"; exit 1;;
esac
S="/sys/fs/cgroup/system.slice/docker-${CID}.scope"
D="$S/acp-delegate"
MI="/proc/$PID/mountinfo"
# v6 (Block I live fail 20261119-142003): DESCENDANT-AWARE enumeration.
# The gateway creates per-session child cgroups (acpmux-*) under its own
# cgroup; a flat read of one cgroup.procs misses tasks living inside child
# cgroups — they would silently escape delegation (helper) or hold a parent
# rmdir busy (rollback). Enumerate the scope root PLUS every cgroup.procs
# under it except the delegate subtree itself.
scope_procs() {
  { cat "$S/cgroup.procs" 2>/dev/null
    find "$S" -mindepth 1 -path "$D" -prune -o -type f -name cgroup.procs -print 2>/dev/null \
      | while read -r f; do cat "$f" 2>/dev/null; done
  } | sort -un
}
mkdir -p "$D"
chown -R 1000:1000 "$D"

# (2) relocate the container's process tree into the delegate subtree,
#     re-passing until NOTHING remains outside the delegate (bounded).
pass=0
while :; do
  pass=$((pass+1))
  if [ "$pass" -gt 50 ]; then
    echo "FAIL: tasks still outside the delegate after 50 passes"
    echo "--- residue processes ---"
    for rp in $(scope_procs); do
      ps -o pid,ppid,stat,etimes,args --no-headers -p "$rp" 2>/dev/null || echo "$rp GONE"
    done
    exit 1
  fi
  for p in $(scope_procs); do
    # A pid from the snapshot may exit before its write: ESRCH on a vanished
    # pid is benign; failure on a still-alive pid is a hard FAIL.
    echo "$p" > "$D/cgroup.procs" 2>/dev/null || {
      if [ -e "/proc/$p" ]; then echo "FAIL: migration write failed for live pid $p"; exit 1; fi; }
  done
  residue=$(scope_procs) || { echo "FAIL: cannot enumerate scope tasks"; exit 1; }
  if [ -z "$residue" ]; then break; fi
  # Settle pacing (v4): give the supervision tree time between drains;
  # churn comes from spawners not yet migrated, which drain monotonically.
  sleep 0.05
done
echo "RELOCATION-OK passes=$pass"

# (3) make ONLY the delegate subtree rw INSIDE the container's mount ns.
#     Parent keeps its ORIGINAL ro mount.
# v5 (live rehearsal 20261119-003309): the mountpoint guard moved HOST-SIDE.
# A procfs instance is bound to the PID namespace it was mounted in; a
# process that entered only the mount ns (nsenter -m) has no pid in the
# container's /proc, so /proc/self -> ENOENT there (fs/proc self-link
# resolution), and findmnt/mountpoint/umount(8) all read that table.
# Reproduced identically on the production container -> not kernel-specific.
# mount(8) bind/remount themselves worked (syscalls don't read the table),
# so only the guard and the attestation change. A dead in-ns mountpoint
# guard would otherwise STACK a second bind on every re-run.
# v5 (live rehearsal 20261119-003309): the mountpoint guard moved HOST-SIDE.
dcount=$(awk -v t=/sys/fs/cgroup/acp-delegate '$5==t' "$MI" | wc -l)
if [ "$dcount" -eq 0 ]; then
  nsenter -t "$PID" -m -- mount --bind /sys/fs/cgroup/acp-delegate /sys/fs/cgroup/acp-delegate
elif [ "$dcount" -ne 1 ]; then
  echo "FAIL: $dcount mounts already on the delegate path (stacking)"; exit 1
fi
nsenter -t "$PID" -m -- mount -o remount,bind,rw /sys/fs/cgroup/acp-delegate

# Post-attestation (fail closed), judged from the HOST against the kernel's
# own table for this mount ns: EXACTLY ONE mount on the delegate path
# (stacked binds each add a mountinfo line), delegate rw, parent cgroupfs
# exactly one mount and ro.
test "$(awk -v t=/sys/fs/cgroup/acp-delegate '$5==t' "$MI" | wc -l)" -eq 1
awk -v t=/sys/fs/cgroup/acp-delegate '$5==t {print $6}' "$MI" | grep -qw rw
test "$(awk '$5=="/sys/fs/cgroup"' "$MI" | wc -l)" -eq 1
awk '$5=="/sys/fs/cgroup" {print $6}' "$MI" | grep -qw ro
# v3: scope root must be EMPTY OF CONTENT (never [ -s ]: st_size is 0 on
# cgroupfs pseudo-files regardless of pids).
final_content=$(scope_procs) || { echo "FAIL: cannot enumerate scope tasks for residue proof"; exit 1; }
if [ -n "$final_content" ]; then echo "FAIL: tasks outside delegate after re-pass: $final_content"; exit 1; fi
echo "HELPER-OK container=$CONTAINER cid=${CID:0:12}"
