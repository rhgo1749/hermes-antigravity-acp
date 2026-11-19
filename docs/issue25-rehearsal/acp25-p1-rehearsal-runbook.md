# acp25-p1-rehearsal-runbook.md — P1 host-helper rehearsal gate (Gate C)
# Target: DISPOSABLE container `hermes-acp-p1` in PRODUCTION SHAPE (no
# cap_add, no entrypoint override, env var set at boot) + the REAL P1 host
# helper (acp25-p1-helper.sh v6) run against it while live, plus the REAL
# rollback script (acp25-p1-rollback.sh, plan §7). Production `hermes` is
# NEVER a target of any command here except read-only inspection.
# Fail-closed: any failed assertion stops the run; cleanup guidance printed,
# never auto-run. sudo required (helper/rollback); preflighted in Block A.
#
# Proves what Gate B (P2 canary) could NOT (plan §5 scope note):
#   R1 pre-delegation: delegated_root()=None with env var set (UNKNOWN)
#   R2 live-PID relocation of a RUNNING container (helper v6 re-pass loop;
#      fork-race probe: 50 short-lived children spawned immediately before)
#   R3 nsenter mount helper against a running container (parent ro, delegate
#      rw self-bind, exactly one mountinfo entry)
#   R4 gate FLIPS to delegated_root()=<root> WITHOUT container restart
#   R5 real ACP request under P1 shape: hardened sampler containment
#      (gateway-spawned trampoline = production spawn shape)
#   R6 idempotency: helper re-run = no-ops, exactly one mount, no stacking
#   R7 rollback (§7): umount kill switch → gate UNKNOWN again, container
#      still serves a request, no restart, delegate dir gone
#   R8 re-delegate + stop semantics: docker stop in grace, no SIGKILL,
#      5-state orphan scan, no-project-procs
#   R9 teardown + production no-change (hard comparisons)

## Block 0 — production ACP idle gate (READ-ONLY; BUSY ⇒ STOP)

```bash
GATE_B_BLOCK_0
```

## Block A — baseline receipt (READ-ONLY) + sudo preflight

```bash
GATE_B_BLOCK_A
if ! sudo -n true; then echo "FAIL: sudo credentials required — run 'sudo -v' first, then re-run"; exit 1; fi
echo SUDO-PREFLIGHT-OK
```

## Block B — disposable P1-SHAPE project prep (Gate B prep with production-shape compose)

Gate B Block B transformed: names p1; compose WITHOUT cap_add and WITHOUT
entrypoint override; B6 entrypoint byte-identity check removed (no override
to check). Env var HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT stays set at boot.

```bash
GATE_B_BLOCK_B_P1
```

## Block C — canary up + PRE-delegation attestation (gate UNKNOWN with env set)

```bash
set -euo pipefail
: "${R:?}"
docker compose -p nous-hermes-acp-p1 -f /home/gonus/acp-p1/docker-compose.acp-p1.yml up -d
ok=0; for i in $(seq 1 12); do [ "$(docker inspect -f '{{.State.Status}}' hermes-acp-p1 2>/dev/null)" = running ] && { ok=1; break; }; sleep 5; done
[ "$ok" = 1 ] || { echo 'FAIL: p1 container never reached running'; docker logs --tail 80 hermes-acp-p1; exit 1; }
docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' hermes-acp-p1 | grep -qx 'running exit=0'
echo CONTAINER-UP-OK
P1CID=$(docker inspect -f '{{.Id}}' hermes-acp-p1)
S="/sys/fs/cgroup/system.slice/docker-${P1CID}.scope"
if [ -d "$S/acp-delegate" ]; then echo "FAIL: delegate exists before helper"; exit 1; fi
echo PRE-DELEGATION-SCOPE-ROOT-OK
# gate UNKNOWN despite env var (root absent) — proven uid-1000 recipe
docker exec -i -u 1000 hermes-acp-p1 sh -c 'cd /acp-seam/hermes-plugin/antigravity-acp && /opt/hermes/.venv/bin/python -' <<'PY' > "$R/delegated-root-pre.txt"
import importlib.util as u
s = u.spec_from_file_location("cgc", "cgroup_containment.py")
m = u.module_from_spec(s); s.loader.exec_module(m)
print(m.delegated_root())
PY
grep -qx 'None' "$R/delegated-root-pre.txt" || { echo "FAIL: delegated_root() not None pre-helper:"; cat "$R/delegated-root-pre.txt"; exit 1; }
echo GATE-UNKNOWN-PRE-OK
# api_server readiness (proven Gate B recipe)
KEY=$(cat "$R/.apik")
ok=0; for i in $(seq 1 36); do curl -sf -o /dev/null --max-time 5 -H "Authorization: Bearer $KEY" http://127.0.0.1:18642/health && { ok=1; break; }; sleep 5; done
[ "$ok" = 1 ] || { echo 'FAIL: p1 api_server never became healthy'; docker logs --tail 80 hermes-acp-p1; exit 1; }
echo API-READY-OK
# Identity anchors for transition re-attestation (r5 MAJOR2): every later
# gate must prove the SAME container instance (no silent restart).
P1PID0=$(docker inspect -f '{{.State.Pid}}' hermes-acp-p1)
P1START0=$(docker inspect -f '{{.State.StartedAt}}' hermes-acp-p1)
test -n "$P1PID0" -a -n "$P1START0"
# Rehearsal precondition: the global delegate unit must NOT exist yet
# (read-only query; rollback also enforces this in rehearsal mode).
crc=0; systemctl cat acp-cgroup-delegate.service >/dev/null 2>&1 || crc=$?
if [ "$crc" -eq 0 ]; then
  echo "FAIL: acp-cgroup-delegate.service exists — rehearsal must precede unit installation"; exit 1
elif [ "$crc" -ne 1 ]; then
  echo "FAIL: cannot query acp-cgroup-delegate.service (rc=$crc) — cannot establish absence"; exit 1
fi
echo UNIT-ABSENT-PRECOND-OK
```

## Block D — fork-race probe + helper v6 run (sudo)

```bash
set -euo pipefail
# (D1) 50 short-lived children INSIDE the container: the scope-root snapshot
#      goes stale during relocation — deterministic race exercise for the
#      v2 re-pass loop.
docker exec -d hermes-acp-p1 sh -c 'for i in $(seq 1 50); do sleep 3 & done; wait'
sleep 1
# (D2) run the REAL helper (artifact under rehearsal = this exact file)
if ! sudo bash /home/gonus/acp-p1-files/acp25-p1-helper.sh hermes-acp-p1 2>&1 | tee "$R/helper-run1.txt"; then echo "FAIL: helper run1 nonzero"; exit 1; fi
grep -q "HELPER-OK" "$R/helper-run1.txt" || { echo "FAIL: no HELPER-OK"; exit 1; }
grep -q "RELOCATION-OK passes=" "$R/helper-run1.txt" || { echo "FAIL: no RELOCATION-OK"; exit 1; }
# (D3) race evidence: passes>1 = probe caught the v1 snapshot gap and the
#      re-pass handled it; passes=1 = window missed this sample (recorded).
awk -F'passes=' '/RELOCATION-OK/{p=$2+0; if (p>1) {print "R2-RACE-HANDLING-EXERCISED passes="p" (mid-migration forks landed on scope root and were migrated)"} else {print "R2-RACE-HANDLING-NOT-EXERCISED passes=1 (fork race never hit scope root in this sample — re-pass path NOT RUN; recorded, not a proof)"}}' "$R/helper-run1.txt"
# (D4) host view: scope root empty of container procs; delegate holds them
root_content=$(cat "$S/cgroup.procs") || { echo "FAIL: cannot read scope-root cgroup.procs"; exit 1; }
if [ -n "$root_content" ]; then echo "FAIL: scope-root residue post-helper: $root_content"; exit 1; fi
N_DELEG=$(wc -l < "$S/acp-delegate/cgroup.procs")
[ "$N_DELEG" -ge 1 ] || { echo "FAIL: delegate has no procs"; exit 1; }
echo "RELOCATED-OK delegate_procs=$N_DELEG"
```

## Block E — post-delegation attestation + gate flip WITHOUT restart

```bash
set -euo pipefail
# (E1) mount end-state asserted independently of the helper's own attestation.
# v5: HOST-SIDE /proc/$P1PID/mountinfo (sudo: root-owned target process).
# nsenter -m + findmnt/mountinfo is unusable here — the container's /proc is
# bound to its PID ns and has no /proc/self entry for a host-pid reader
# (ENOENT; reproduced on the production container too, kernel-independent).
P1PID=$(docker inspect -f '{{.State.Pid}}' hermes-acp-p1)
test "$(sudo awk -v t=/sys/fs/cgroup/acp-delegate '$5==t' "/proc/$P1PID/mountinfo" | wc -l)" -eq 1
sudo awk -v t=/sys/fs/cgroup/acp-delegate '$5==t {print $6}' "/proc/$P1PID/mountinfo" | grep -qw rw
test "$(sudo awk '$5=="/sys/fs/cgroup"' "/proc/$P1PID/mountinfo" | wc -l)" -eq 1
sudo awk '$5=="/sys/fs/cgroup" {print $6}' "/proc/$P1PID/mountinfo" | grep -qw ro
echo MOUNT-ENDSTATE-OK
# (E2) chown recursion proof: interface files uid-1000-owned
[ "$(stat -c '%u' "$S/acp-delegate/cgroup.procs")" = "1000" ] || { echo "FAIL: delegate cgroup.procs not uid 1000"; exit 1; }
[ "$(stat -c '%u' "$S/acp-delegate/cgroup.kill")" = "1000" ] || { echo "FAIL: delegate cgroup.kill not uid 1000"; exit 1; }
echo CHOWN-RECURSIVE-OK
# (E3) THE flip: same container, no restart
docker exec -i -u 1000 hermes-acp-p1 sh -c 'cd /acp-seam/hermes-plugin/antigravity-acp && /opt/hermes/.venv/bin/python -' <<'PY' > "$R/delegated-root-post.txt"
import importlib.util as u
s = u.spec_from_file_location("cgc", "cgroup_containment.py")
m = u.module_from_spec(s); s.loader.exec_module(m)
print(m.delegated_root())
PY
grep -qx '/sys/fs/cgroup/acp-delegate' "$R/delegated-root-post.txt" || { echo "FAIL: delegated_root() did not flip:"; cat "$R/delegated-root-post.txt"; exit 1; }
echo GATE-FLIP-NO-RESTART-OK
P1PID1=$(docker inspect -f '{{.State.Pid}}' hermes-acp-p1)
P1START1=$(docker inspect -f '{{.State.StartedAt}}' hermes-acp-p1)
if [ "$P1PID1" = "$P1PID0" ] && [ "$P1START1" = "$P1START0" ]; then echo "IDENTITY-STABLE-OK after flip (pid=$P1PID1 started=$P1START1)"; else echo "FAIL: container instance changed across flip ($P1PID0/$P1START0 -> $P1PID1/$P1START1)"; exit 1; fi
```

## Block F — real ACP request under P1 shape + hardened sampler (Gate B F verbatim, renamed)

```bash
GATE_B_BLOCK_F
```

## Block G — TTL eviction retry (Gate B G verbatim, renamed)

```bash
GATE_B_BLOCK_G
```

## Block H — idempotency (helper re-run)

```bash
set -euo pipefail
if ! sudo bash /home/gonus/acp-p1-files/acp25-p1-helper.sh hermes-acp-p1 2>&1 | tee "$R/helper-run2.txt"; then echo "FAIL: helper re-run nonzero"; exit 1; fi
grep -q "HELPER-OK" "$R/helper-run2.txt" || { echo "FAIL: re-run no HELPER-OK"; exit 1; }
P1PID=$(docker inspect -f '{{.State.Pid}}' hermes-acp-p1)
# v5: host-side mountinfo (see Block E1 note — nsenter /proc/self is ENOENT here)
test "$(sudo awk -v t=/sys/fs/cgroup/acp-delegate '$5==t' "/proc/$P1PID/mountinfo" | wc -l)" -eq 1 || { echo "FAIL: mount stacking after re-run"; exit 1; }
echo IDEMPOTENT-RERUN-OK
```

## Block I — rollback rehearsal (§7) + kill switch WITHOUT restart

```bash
set -euo pipefail
if ! sudo bash /home/gonus/acp-p1-files/acp25-p1-rollback.sh hermes-acp-p1 rehearsal 2>&1 | tee "$R/rollback-run.txt"; then echo "FAIL: rollback nonzero — LOUD rollback-incomplete state; investigate the failed umount before retry"; exit 1; fi
grep -q "UNMOUNT-VERIFIED-OK" "$R/rollback-run.txt" || { echo "FAIL: no UNMOUNT-VERIFIED-OK"; exit 1; }
grep -q "ROLLBACK-OK" "$R/rollback-run.txt" || { echo "FAIL: no ROLLBACK-OK"; exit 1; }
if [ -d "$S/acp-delegate" ]; then echo "FAIL: delegate dir survived rollback"; exit 1; fi
echo DELEGATE-DIR-GONE-OK
docker exec -i -u 1000 hermes-acp-p1 sh -c 'cd /acp-seam/hermes-plugin/antigravity-acp && /opt/hermes/.venv/bin/python -' <<'PY' > "$R/delegated-root-rolledback.txt"
import importlib.util as u
s = u.spec_from_file_location("cgc", "cgroup_containment.py")
m = u.module_from_spec(s); s.loader.exec_module(m)
print(m.delegated_root())
PY
grep -qx 'None' "$R/delegated-root-rolledback.txt" || { echo "FAIL: gate not UNKNOWN after rollback:"; cat "$R/delegated-root-rolledback.txt"; exit 1; }
echo GATE-UNKNOWN-AFTER-ROLLBACK-OK
# container still serves on the legacy UNKNOWN path (no restart)
KEY=$(cat "$R/.apik")
curl -sS --max-time 300 -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  -d '{"model":"gemini-3.8-flash","reasoning_effort":"low","provider":"antigravity-acp","messages":[{"role":"user","content":"What is 17 plus 25? Answer with only the number."}]}' \
  "http://127.0.0.1:18642/v1/chat/completions" > "$R/request-rolledback.json"
A=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['choices'][0]['message']['content'])" "$R/request-rolledback.json")
[ "$A" = 42 ] || { echo "FAIL: post-rollback answer=$A"; exit 1; }
echo POST-ROLLBACK-SERVICE-OK
P1PID2=$(docker inspect -f '{{.State.Pid}}' hermes-acp-p1)
P1START2=$(docker inspect -f '{{.State.StartedAt}}' hermes-acp-p1)
if [ "$P1PID2" = "$P1PID0" ] && [ "$P1START2" = "$P1START0" ]; then echo "IDENTITY-STABLE-OK after rollback (pid=$P1PID2 started=$P1START2)"; else echo "FAIL: container instance changed across rollback ($P1PID0/$P1START0 -> $P1PID2/$P1START2)"; exit 1; fi
```

## Block J — re-delegate + stop semantics + orphan scan (Gate B stop-semantics, renamed)

```bash
set -euo pipefail
if ! sudo bash /home/gonus/acp-p1-files/acp25-p1-helper.sh hermes-acp-p1 2>&1 | tee "$R/helper-run3.txt"; then echo "FAIL: re-delegate nonzero"; exit 1; fi
grep -q "HELPER-OK" "$R/helper-run3.txt" || { echo "FAIL: re-delegate no HELPER-OK"; exit 1; }
echo RE-DELEGATION-OK
P1PID3=$(docker inspect -f '{{.State.Pid}}' hermes-acp-p1)
P1START3=$(docker inspect -f '{{.State.StartedAt}}' hermes-acp-p1)
if [ "$P1PID3" = "$P1PID0" ] && [ "$P1START3" = "$P1START0" ]; then echo "IDENTITY-STABLE-OK before stop (pid=$P1PID3 started=$P1START3)"; else echo "FAIL: container instance changed before stop ($P1PID0/$P1START0 -> $P1PID3/$P1START3)"; exit 1; fi
GATE_B_STOP_SEMANTICS
```

## Block K — teardown + production no-change (Gate B I+J, renamed)

```bash
GATE_B_BLOCK_I
GATE_B_BLOCK_J
```

## Success criteria

R1..R9 all PASS with zero residue and production identity/envhash unchanged.
R2-RACE-HANDLING-NOT-EXERCISED is a recorded observation, not a failure (re-pass logic is
additionally exercised by idempotent re-runs). Anything else = FAIL → P1
stays NO-GO, production untouched, evidence preserved.
