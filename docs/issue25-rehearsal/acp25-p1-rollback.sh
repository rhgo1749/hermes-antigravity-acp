# acp25-p1-rollback.sh v4 — plan §7, parameterized.
# Usage: sudo acp25-p1-rollback.sh CONTAINER [rehearsal|production]  (default: rehearsal)
# v2 (r5 BLOCKER2/MAJOR3): GLOBAL unit control ONLY in production mode.
# v3 (r7): guarded rc idiom + is-active judged by STATE STRING (systemd
# returns rc 3 for inactive; rc-only judgement would reject a stopped unit).
# Rehearsal mode never touches any systemd unit (r5: unconditional
# `systemctl disable --now` of a global unit during a rehearsal was a
# production-mutation risk). Production mode distinguishes absent /
# enabled-active / enabled-inactive / query-error and HARD-FAILS if it
# cannot establish the unit is stopped while it exists (§7 "stop the helper
# FIRST"). Rehearsal asserts the unit is ABSENT instead.
# Rollback of host-side delegation. Fail-closed: no '|| true' on the unmount —
# if the kill switch cannot be pulled, this STOPS loudly (KNOWN, LOUD
# rollback-incomplete state; leave env var removed and investigate findmnt).
set -eu

CONTAINER="${1:-hermes}"
MODE="${2:-rehearsal}"
UNIT=acp-cgroup-delegate.service
# (1) STOP THE HELPER FIRST (production mode only — r5 BLOCKER2): an
#     event-triggered unit would otherwise re-run the delegation the moment
#     anything re-triggers its start event.
case "$MODE" in
  production)
    # r6: explicit systemctl cat rc — 0 exists, 1 absent, >1 query error.
    crc=0; systemctl cat "$UNIT" >/dev/null 2>&1 || crc=$?
    if [ "$crc" -eq 0 ]; then
      systemctl disable --now "$UNIT" || { echo "FAIL: cannot disable+stop $UNIT (unit exists; §7 stop-first unmet)"; exit 1; }
      # r7: judge by STATE STRING, not rc — systemd is-active exits 3 for
      # inactive (rc semantics vary); only the printed state is authoritative.
      arc=0; ust=$(systemctl is-active "$UNIT" 2>/dev/null) || arc=$?
      case "$ust" in
        inactive|failed) echo "UNIT-STOPPED-OK (disable --now; state=$ust rc=$arc)";;
        active|reloading) echo "FAIL: $UNIT state=$ust after disable --now"; exit 1;;
        *) echo "FAIL: cannot establish $UNIT state (state='$ust' rc=$arc)"; exit 1;;
      esac
    elif [ "$crc" -eq 1 ]; then
      echo "UNIT-ABSENT-OK (production mode: nothing to stop)"
    else
      echo "FAIL: cannot query $UNIT (rc=$crc) — refusing to assume absent"; exit 1
    fi
    ;;
  rehearsal)
    # Rehearsal NEVER controls global units; assert absence read-only.
    # r6: only systemctl cat rc==1 counts as absent; rc>1 is a query error.
    crc=0; systemctl cat "$UNIT" >/dev/null 2>&1 || crc=$?
    if [ "$crc" -eq 0 ]; then
      echo "FAIL: $UNIT exists on this host — rehearsal must run before unit installation (read-only check, nothing touched)"; exit 1
    elif [ "$crc" -ne 1 ]; then
      echo "FAIL: cannot query $UNIT (rc=$crc) — cannot establish absence for rehearsal precondition"; exit 1
    fi
    echo "UNIT-OPS-SKIPPED-OK (rehearsal mode; unit absent as expected)"
    ;;
  *) echo "FAIL: unknown mode $MODE (use rehearsal|production)"; exit 1;;
esac
CID=$(docker inspect -f '{{.Id}}' "$CONTAINER")
PID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER")
test "$(docker inspect -f '{{.State.Running}}' "$CONTAINER")" = "true" || { echo "container not running"; exit 1; }
# v4.1 (sync with helper v5.1): PREFIX match — after delegation PID1 lives in
# the acp-delegate subtree; equality here would silently kill rollback at
# the exact moment it is needed (set -e, zero output).
cg=$(cat "/proc/$PID/cgroup")
case "$cg" in
  "0::/system.slice/docker-${CID}.scope"|"0::/system.slice/docker-${CID}.scope/"*) ;;
  *) echo "FAIL: pid1 cgroup '$cg' is not this container's scope"; exit 1;;
esac
S="/sys/fs/cgroup/system.slice/docker-${CID}.scope"
# (2) VERIFIED unmount of the delegate bind — no '|| true'.
# v4 (sync with helper v5): umount(8)/mountpoint(8) read /proc/self/mounts,
# which is ENOENT for a process that entered only the mount ns (procfs is
# bound to its PID ns). Use the container's own interpreter for a bare
# umount2(2) — path resolves in the container's mount ns, zero table reads.
# Verification is HOST-SIDE mountinfo: the exact-target entry must be gone.
# v4.2 (live fail 20261119-140732 Block I): python has os.mount (3.12+) but
# NO os.umount (os.unmount arrived only in 3.14) — the v4.1 line died with
# AttributeError. ctypes umount2(2) works on any python3 and keeps the
# fail-closed contract: nonzero rc raises with errno, set -e stops loudly.
nsenter -t "$PID" -m -- /opt/hermes/.venv/bin/python -c '
import ctypes, os, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
if libc.umount2(sys.argv[1].encode(), 0) != 0:
    err = ctypes.get_errno()
    raise OSError(err, "umount2 %s: %s" % (sys.argv[1], os.strerror(err)))
' /sys/fs/cgroup/acp-delegate
if awk -v t=/sys/fs/cgroup/acp-delegate '$5==t' "/proc/$PID/mountinfo" | grep -q .; then
  echo "ROLLBACK INCOMPLETE: delegate bind still mounted"; exit 1
fi
echo "UNMOUNT-VERIFIED-OK"
# v4.4 (live fail 20261119-142457): cgroup destruction is ASYNCHRONOUS —
# after the last task leaves, css offline (memory controller reclaim via
# workqueue) still trails, so an immediate rmdir transiently hits EBUSY on a
# logically-empty cgroup (acpmux-d6a1244fa0e2: the surviving warm tree,
# tasks already migrated). Bounded drain+rmdir loop: rmdir semantics remain
# the fail-closed backstop (a cgroup holding tasks NEVER disappears; the cap
# prints ps forensics — unmovable STAT=Z zombies included, since writing a
# zombie's pid to cgroup.procs is ESRCH by kernel design).
pass=0
while :; do
  pass=$((pass+1))
  for f in $(find "$S/acp-delegate" -name cgroup.procs 2>/dev/null | sort -r); do
    while read -r p; do
      echo "$p" > "$S/cgroup.procs" 2>/dev/null || true
    done < "$f"
  done
  find "$S/acp-delegate" -depth -type d -exec rmdir {} + 2>/dev/null || true
  if [ ! -e "$S/acp-delegate" ]; then
    echo "DELEGATE-DIR-REMOVED-OK passes=$pass"
    break
  fi
  if [ "$pass" -ge 50 ]; then
    echo "FAIL: delegate subtree still present after $pass drain+rmdir passes"
    find "$S/acp-delegate" 2>/dev/null
    for f in $(find "$S/acp-delegate" -name cgroup.procs 2>/dev/null); do
      echo "== $f"
      while read -r p; do ps -o pid,stat,etimes,args --no-headers -p "$p" 2>/dev/null || echo "$p GONE"; done < "$f"
    done
    exit 1
  fi
  sleep 0.1
done
echo "ROLLBACK-OK container=$CONTAINER"
