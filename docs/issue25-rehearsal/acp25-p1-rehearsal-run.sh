#!/usr/bin/env bash
# ACP #25 P1 host-helper REHEARSAL runner v4 GENERATED from
# acp25-p1-rehearsal-runbook.md + Gate B proven blocks (renamed to
# hermes-acp-p1 / nous-hermes-acp-p1; compose diff: NO cap_add, NO
# apparmor:unconfined, NO entrypoint override, B6 removed = production
# shape; env var set at boot so the gate must flip live). Gate B bodies
# are v27-renamed + r6 census-rc HARDEN v2 (5 deviations, guarded
# `v=0; var=$(cmd) || v=$?` idiom — r7 CRITICAL), reviewed r8.
# Rehearses the
# REAL acp25-p1-helper.sh v4 + acp25-p1-rollback.sh v3 (§7) against a live
# disposable container: pre-gate UNKNOWN, fork-race relocation, nsenter
# mount, gate flip no-restart, sampler containment, idempotency,
# rollback kill switch, re-delegate + stop semantics, production
# no-change. sudo required (preflighted). Fail-closed: any failure stops
# and prints cleanup guidance WITHOUT auto-running it.
# Run as gonus (docker+sudo): bash acp25-p1-rehearsal-run.sh 2>&1 | tee ~/acp-p1-run-$(date +%Y%m%d-%H%M%S).log; echo EXIT=${PIPESTATUS[0]}
# Transfer as a FILE; chat pasting mangles '||'.
set -euo pipefail
trap 'code=$?; if [ "$code" -ne 0 ]; then echo; echo "=== RUN FAILED (exit $code) - STOP. Preserve evidence, then run Emergency cleanup (rehearsal objects only): ==="; echo "sudo bash /home/gonus/acp-p1-files/acp25-p1-rollback.sh hermes-acp-p1 rehearsal 2>/dev/null || true"; echo "docker compose -p nous-hermes-acp-p1 -f /home/gonus/acp-p1/docker-compose.acp-p1.yml down --remove-orphans 2>/dev/null || true"; echo "docker rm -f hermes-acp-p1 2>/dev/null || true"; echo "docker run --rm -v /home/gonus/acp-p1:/x --entrypoint /bin/sh nousresearch/hermes-agent:v0.23.2 -c \"chmod -R u+rwX /x 2>/dev/null; rm -rf /x/* /x/.[!.]*\" 2>/dev/null || true; rm -rf /home/gonus/acp-p1"; echo "rm -f \"${R:-/nonexistent}/.apik\" 2>/dev/null || true"; echo "NEVER: docker stop/restart hermes (production), host umount, host cgroup rmdir."; fi' EXIT
echo; echo "################ Block 0 — production ACP idle gate (READ-ONLY; BUSY ⇒ STOP) ################"
set -uo pipefail
CID=$(docker inspect -f '{{.Id}}' hermes)
SCOPE=/sys/fs/cgroup/system.slice/docker-$CID.scope
[ -d "$SCOPE" ] || { echo 'IDLE-GATE: FAIL production scope not found'; exit 1; }
PIDS=$(cat "$SCOPE/cgroup.procs")   # EXACT production-container membership
# Measure CPU of the ACP TREE ONLY (mux + vendor descendants), never the
# whole container: the production gateway (assistant sessions, kanban,
# heartbeats) lives in the same container and is never idle — a
# container-wide delta is permanently BUSY (observed 2026-11-18: delta
# 1163 jiffies caused entirely by the reviewing session's own work).
# Prints "cpu strict broad err": strict = ACP-tree processes; broad = any
# cmdline mentioning antigravity/agy (pattern-drift tripwire); err =
# observation failures. Unobservable is NEVER idle (r8 finding #1).
acp_snap() {
  local s=0 cl p err=0 strict=0 broad=0
  for p in $PIDS; do
    [ -d "/proc/$p" ] || continue   # exited between snapshot and read: not observable, not an error
    cl=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null) || { err=$((err+1)); continue; }
    case "$cl" in
      *antigravity*|*agy*)
        broad=$((broad+1))
        case "$cl" in
          *antigravity-acp-mux*|*agy_acp_server*|*agy-linux*|*localharness*)
            strict=$((strict+1))
            if [ -r "/proc/$p/stat" ]; then s=$((s + $(awk '{print $14+$15}' "/proc/$p/stat"))); else err=$((err+1)); fi ;;
        esac ;;
    esac
  done
  echo "$s $strict $broad $err"
}
read -r T0S T0M T0B T0E <<< "$(acp_snap)"
sleep 15
read -r T1S T1M T1B T1E <<< "$(acp_snap)"
if [ "$T0E" -ne 0 ] || [ "$T1E" -ne 0 ]; then echo "IDLE-GATE: FAIL observation errors (T0=$T0E T1=$T1E) — cannot attest idle; STOP"; exit 1; fi
if [ $((T0M + T1M)) -eq 0 ] && [ $((T0B + T1B)) -gt 0 ]; then echo "IDLE-GATE: FAIL ACP-shaped procs present (broad=$((T0B + T1B))) but zero strict matches — pattern drift (vendor upgrade?) — STOP"; exit 1; fi
DELTA=$((T1S-T0S))
# Negative delta = an ACP-tree process (with accumulated lifetime CPU) EXITED
# during the window — i.e. ACP tree churn (eviction/teardown of a recently
# active tree). That is NOT attestable idle: FAIL CLOSED (r7 review finding #1:
# clamping negatives to 0 is fail-open when survivors burn CPU).
if [ "$DELTA" -lt 0 ]; then echo "IDLE-GATE: ACP-tree churn during window (delta=$DELTA) — cannot attest idle; STOP"; exit 1; fi
DATA_SRC=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/opt/data"}}{{.Source}}{{end}}{{end}}' hermes)
LOG="$DATA_SRC/logs/agent.log"
[ -f "$LOG" ] || { echo 'IDLE-GATE: FAIL agent.log missing — cannot attest idleness'; exit 1; }
LOG_AGE=$(( $(date +%s) - $(stat -c %Y "$LOG") ))
RECENT_ACP=0
if [ "$LOG_AGE" -lt 300 ]; then
  # model=gemini* = ACTUAL ACP provider request lines. Do NOT grep bare
  # 'antigravity-acp': unrelated github-kanban maintenance lines contain the
  # repo name 'antigravity-acp-harness' and false-fail this gate (observed
  # 2026-11-18). Tool-call text does not enter agent.log (verified), so this
  # pattern cannot be polluted by the reviewing session itself.
  RECENT_ACP=$(tail -n 200 "$LOG" | grep -cE 'model=gemini' || true)
fi
echo "IDLE-GATE: acp_tree_cpu_delta=$DELTA acp_procs_strict=$(( (T0M + T1M) / 2 )) log_age_s=$LOG_AGE recent_acp_hits=$RECENT_ACP"
if [ "$DELTA" -lt 150 ] && [ "$RECENT_ACP" -eq 0 ]; then echo 'IDLE-GATE: IDLE — proceed'; else echo 'IDLE-GATE: BUSY — STOP'; exit 1; fi
echo; echo "################ Block A — baseline receipt (READ-ONLY) + sudo preflight ################"
set -euo pipefail
R=/home/gonus/acp-p1-rehearsal-receipt-$(date +%Y%m%d-%H%M%S); mkdir -p "$R"; chmod 700 "$R"; export R; echo "RECEIPT_DIR=$R"
docker inspect -f '{{.Id}} {{.State.Status}} pid={{.State.Pid}} started={{.State.StartedAt}}' hermes > "$R/prod-identity.base"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' hermes | sort | sha256sum > "$R/prod-envhash.base"
sha256sum /home/gonus/hermes-cloudcli/docker-compose.nous.yml | awk '{print $1}' > "$R/compose-hash.base"
docker ps --format '{{.Names}}' | sort > "$R/ps-names.base"
{
date -Is; hostname; uname -r; docker version --format '{{.Server.Version}}'
cat "$R/prod-identity.base"
} > "$R/baseline.txt" 2>&1
# ACK/GC/CGROUP env: independent rc, then content (never conflate rc with no-match)
if ! PENV=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' hermes 2>&1); then echo 'FAIL: cannot inspect production env'; exit 1; fi
if printf '%s\n' "$PENV" | grep -E 'ACP_MUX_F4_PROCESS_TREE_ACK|ACP_MUX_SESSION_GC|ACP_CGROUP'; then
  echo 'BASELINE: unexpected flag present — STOP'; exit 1
else rc=$?; [ "$rc" -eq 1 ] && echo 'ACK/GC/CGROUP absent (expected)' || { echo "FAIL: grep observation error rc=$rc"; exit 1; }; fi
CID=$(docker inspect -f '{{.Id}}' hermes); S=/sys/fs/cgroup/system.slice/docker-$CID.scope
ls -ld "$S" >> "$R/baseline.txt" 2>&1
wc -l < "$S/cgroup.procs" > "$R/prod-scope-procs.base"
if ! SLS=$(ls "$S" 2>&1); then echo "FAIL: cannot enumerate production scope: $SLS"; exit 1; fi
if printf '%s\n' "$SLS" | grep -i acp; then
  echo 'BASELINE: acp residue under production scope — STOP'; exit 1
else rc=$?; [ "$rc" -eq 1 ] && echo 'no acp-* under production scope (expected)' || { echo "FAIL: grep observation error rc=$rc"; exit 1; }; fi
findmnt -T /sys/fs/cgroup -o TARGET,OPTIONS >> "$R/baseline.txt"; systemctl is-system-running >> "$R/baseline.txt"
RES=$(find /sys/fs/cgroup/system.slice -maxdepth 1 \( -name '*canary*' -o -name '*acp*' \) -print 2>/dev/null) || { echo 'FAIL: residue scan traversal error'; exit 1; }
[ -z "$RES" ] || { echo "BASELINE: residue found: $RES — STOP"; exit 1; }
echo 'no canary/acp scope residue'
[ ! -e /home/gonus/acp-p1 ] || { echo 'BASELINE: stale acp-canary dir — remove manually, then rerun'; exit 1; }
echo 'no stale canary dir'
# disk guard: whitelist copies are ~1.2G; margin covers state.db growth and
# docker layers. A full disk mid-copy is the worst failure mode (partial
# state + lost evidence). Fail BEFORE writing.
AVAIL=$(df -BG --output=avail /home | tail -1 | tr -dc '0-9')
[ "${AVAIL:-0}" -ge 20 ] || { echo "FAIL: /home has only ${AVAIL}G free; canary needs ~20G — free disk first"; exit 1; }
echo "DISK-OK: ${AVAIL}G free on /home"
cat "$R/baseline.txt"
# artifact-under-rehearsal integrity: the rehearsal must run THESE exact files
if ! echo 'ca9bcc2b6c25080240493c809f070c8d  /home/gonus/acp-p1-files/acp25-p1-helper.sh' | md5sum -c --status; then
  echo "FAIL: helper md5 mismatch (expected ca9bcc2b6c25080240493c809f070c8d) — place the exact artifact files in /home/gonus/acp-p1-files/"; exit 1
fi
if ! echo '51d8e9dd6b96ad7e8bd9825c33a7648e  /home/gonus/acp-p1-files/acp25-p1-rollback.sh' | md5sum -c --status; then
  echo "FAIL: rollback md5 mismatch (expected 51d8e9dd6b96ad7e8bd9825c33a7648e)"; exit 1
fi
echo ARTIFACT-MD5-OK
if ! sudo -n true; then echo "FAIL: sudo credentials required — run 'sudo -v' first, then re-run"; exit 1; fi
echo SUDO-PREFLIGHT-OK
echo; echo "################ Block B — disposable P1-SHAPE project prep (Gate B prep with production-shape compose) ################"
set -euo pipefail
: "${R:?run Block A first (R not set)}"
AVAIL_KB=$(df --output=avail -k /home/gonus | tail -1 | tr -d ' ')
[ "$AVAIL_KB" -gt 20971520 ] || { echo "FAIL: <20G free on /home/gonus (whitelist copies land here)"; exit 1; }
if ! SSO=$(ss -ltn 2>&1); then echo "FAIL: cannot list sockets: $SSO"; exit 1; fi
if printf '%s\n' "$SSO" | grep -qE ':18642\b'; then
  echo 'FAIL: host port 18642 already in use — STOP'; exit 1
else rc=$?; [ "$rc" -eq 1 ] && echo PORT-18642-FREE-OK || { echo "FAIL: grep observation error rc=$rc pattern=':18642\b'"; exit 1; }; fi
BASE=/home/gonus/acp-p1
# re-entry after a failed copy: tar/cp preserve restrictive source modes
# (agy-acp account homes carry production perms; prior canary boots also
# leave root-owned objects) — restore owner-writability before rm.
if [ -e "$BASE" ]; then
  chmod -R u+rwX "$BASE" 2>/dev/null || true
  rm -rf "$BASE" 2>/dev/null || true
  if [ -e "$BASE" ]; then
    # root-owned objects created by the canary's root-side boot (cont-init)
    # against the mounted copies — privileged cleanup, canary dir only
    # (observed 2026-11-18: data/installs, data/profiles root-owned).
    docker run --rm -v "$BASE":/x --entrypoint /bin/sh nousresearch/hermes-agent:v0.23.2 \
      -c 'chmod -R u+rwX /x 2>/dev/null; rm -rf /x/* /x/.[!.]*' || true
    rm -rf "$BASE" || { echo 'FAIL: cannot clear stale canary dir even privileged'; exit 1; }
  fi
fi
mkdir -p "$BASE/ws"
# B1. seam source at the EXACT reviewed head
gh repo clone rhgo1749/hermes-antigravity-acp "$BASE/seam-src"
git -C "$BASE/seam-src" checkout --quiet --detach 961607aed610f821a7b60b4ea15c9c80d6b3ec46
[ "$(git -C "$BASE/seam-src" rev-parse HEAD)" = 961607aed610f821a7b60b4ea15c9c80d6b3ec46 ]
# working-tree (not just object) assert — pins the 2026-11-18 15:20 mystery
# where cp found seam-src/hermes-plugin GONE at B4 with no remover in the script
[ -f "$BASE/seam-src/hermes-plugin/antigravity-acp/cgroup_containment.py" ] || { echo 'FAIL: seam working tree missing right after checkout (B1)'; exit 1; }
echo SEAM-TREE-OK
# B2. WHITELIST state copies (sources read from the LIVE container; live
# dirs are NEVER mounted rw). 2026-11-18 operator veto: the original
# full-state copy (~270G/run) is unacceptable SSD wear. The gate reads
# config/secrets/ACP-auth state only; everything else regenerates at boot
# (evidence: the 2026-11-18 bind-probe container started ALL s6 services
# with an empty /opt/data). Isolation invariant preserved: the canary
# never shares a state dir with the live gateway. Copies run as root
# INSIDE a disposable container with the source mounted READ-ONLY (the
# production state contains root-owned files host user gonus cannot read
# — cp -a as gonus EACCESes, observed 2026-11-18), then chowned to uid
# 1000 (= host user gonus = the canary's HERMES_UID).
src() { docker inspect -f '{{range .Mounts}}{{if eq .Destination "'"$1"'"}}{{.Source}}{{end}}{{end}}' hermes; }
copyas() { # $1=host src dir (mounted ro), $2=dest name under $BASE, $3=extra tar --exclude opts
  # bash (not sh) inside the container: pipefail so the PRODUCER tar's rc is
  # visible (r9 #1: plain sh pipeline masks source-side failure). GNU tar rc=1
  # = "file changed as we read it" — expected on a live snapshot, tolerated;
  # rc>=2 = fatal read/IO error, fail closed. chown/mkdir failures propagate.
  # v12: copyas is used ONLY for the agy-acp account homes; $3 excludes
  # per-account conversations/ and brain/ history (~7G of 8.1G; the auth
  # core that Block F's real ACP request depends on is ~1G).
  docker run --rm -u 0 -v "$1":/src:ro -v "$BASE":/dst \
    --entrypoint /bin/bash nousresearch/hermes-agent:v0.23.2 -c "
      set -uo pipefail
      mkdir -p '/dst/$2' || { echo MKDIR-FAIL; exit 1; }
      tar $3 -cf - -C /src . | tar -xf - -C '/dst/$2'
      # r10 #1: pipefail reports the RIGHTMOST nonzero rc, not the first —
      # capture BOTH sides explicitly; any component rc>=2 is fatal.
      rcs=(\${PIPESTATUS[@]}); rcp=\${rcs[0]}; rcx=\${rcs[1]}
      if [ \"\$rcp\" -gt 1 ] || [ \"\$rcx\" -gt 1 ]; then echo \"COPY-FATAL producer=\$rcp extractor=\$rcx\"; exit 1; fi
      if [ \"\$rcp\" -eq 1 ] || [ \"\$rcx\" -eq 1 ]; then echo \"COPY-WARN: source changed during live snapshot (producer=\$rcp extractor=\$rcx, tolerated)\"; fi
      chown -R 1000:1000 '/dst/$2' || { echo CHOWN-FAIL; exit 1; }
      exit 0"
  [ -n "$(ls -A "$BASE/$2")" ] || { echo "FAIL: copy $2 is empty"; exit 1; }
}
# B2a. config/secrets/identity whitelist — the ONLY production data files
# the gate semantics depend on (measured 2026-11-18: ~30KB + .hermes 1.5M).
mkdir -p "$BASE/data" "$BASE/home/.local/opt/antigravity-acp"
docker run --rm -u 0 -v "$(src /opt/data)":/src:ro -v "$BASE/data":/dst \
  --entrypoint /bin/bash nousresearch/hermes-agent:v0.23.2 -c '
    set -euo pipefail
    cp /src/config.yaml /src/.env /src/auth.json /dst/
    mkdir -p /dst/.local/opt/antigravity-acp
    cp -a /src/.local/bin /dst/.local/bin
    cp -a /src/.hermes /dst/.hermes
    rm -rf /dst/.hermes/cache /dst/.hermes/logs /dst/.hermes/desktop-attachments
    ln -sfn /opt/data/.hermes/acp-accounts.json /dst/acp-accounts.json
    chown -R 1000:1000 /dst'
for f in config.yaml .env auth.json .hermes/acp-accounts.json .local/bin/antigravity-acp-mux.py; do
  [ -s "$BASE/data/$f" ] || { echo "FAIL: whitelist copy missing/empty: $f"; exit 1; }
done
echo WHITELIST-COPY-OK
# B2b. ACP account homes — auth state ONLY. Excluded per account:
# conversations/ + brain/ history (~7G) and .local (rhgo1746 carries a
# duplicate 1G CLI install the live tree never executes — production
# processes run the MAIN-home 1.4.4, verified from live cmdline). Auth
# core across 5 accounts measured ~120M (2026-11-18). Block F fires a
# REAL ACP request, so these credentials are load-bearing.
copyas "$(src /opt/data/home)/.agy-acp" agy-acp "--exclude=*/conversations --exclude=*/brain --exclude=*/.local"
# ACP CLIENT BINARIES ARE NOT COPIED — mounted READ-ONLY in compose
# (immutable versioned installs: data/.local/opt 1.5.0 + home/.local/opt
# 1.4.4, ~2.1G; the live tree executes 1.4.4). The never-share-state rule
# targets MUTABLE state; a ro bind of an immutable binary tree shares no
# writable bytes and copies zero. Block D attests both mounts are ro.
docker run --rm -u 0 -v "$(src /etc/machine-id)":/src:ro -v "$BASE":/dst \
  --entrypoint /bin/sh nousresearch/hermes-agent:v0.23.2 \
  -c 'cp /src /dst/machine-id && chown 1000:1000 /dst/machine-id'
[ -s "$BASE/machine-id" ] || { echo 'FAIL: machine-id copy empty'; exit 1; }
[ -f "$BASE/data/config.yaml" ] || { echo 'FAIL: config.yaml missing in data copy'; exit 1; }
# B3. NEUTER the copies (image python + ruamel — zero host deps), then INVENTORY-VERIFY:
docker run --rm -i -u 0 -v "$BASE/data/config.yaml":/cfg.yaml --entrypoint /opt/hermes/.venv/bin/python nousresearch/hermes-agent:v0.23.2 - <<'PY'
from ruamel.yaml import YAML
y = YAML()
c = y.load(open("/cfg.yaml")) or {}
c.setdefault("platforms", {}).setdefault("telegram", {})["enabled"] = False
c["platforms"].setdefault("webhook", {})["enabled"] = False
c.setdefault("kanban", {})["dispatch_in_gateway"] = False
y.dump(c, open("/cfg.yaml", "w"))
print("NEUTER-DONE")
PY
docker run --rm -i -u 0 -v "$BASE/data/config.yaml":/cfg.yaml:ro --entrypoint /opt/hermes/.venv/bin/python nousresearch/hermes-agent:v0.23.2 - <<'PY'
from ruamel.yaml import YAML
c = YAML(typ="safe").load(open("/cfg.yaml")) or {}
plats = c.get("platforms") or {}
enabled = [k for k, v in plats.items() if isinstance(v, dict) and v.get("enabled")]
assert not enabled, f"FAIL: platforms still enabled: {enabled}"
assert (c.get("kanban") or {}).get("dispatch_in_gateway") is False, "FAIL: kanban dispatch not disabled"
print("NEUTER-VERIFY-OK: zero enabled platforms, kanban dispatch off")
PY
# cron is NOT copied (whitelist) — the gateway starts with zero jobs.
if [ -e "$BASE/data/cron/jobs.json" ]; then echo 'FAIL: cron jobs.json present in canary state'; exit 1; fi
echo CRON-ABSENT-OK
# B4. plugin dir is built from the reviewed seam ONLY (the production
# plugin dir — 151M — was always replaced wholesale by the seam anyway).
mkdir -p "$BASE/data/plugins/model-providers"
cp -a "$BASE/seam-src/hermes-plugin/antigravity-acp" "$BASE/data/plugins/model-providers/antigravity-acp"
[ -f "$BASE/data/plugins/model-providers/antigravity-acp/cgroup_containment.py" ]
# Deployment-artifact overlay: the production installed plugin tree carries
# launch_config.json (mux process_command override; untracked in git).
# Without it the plugin falls back to _default_official_command(), skips the
# mux and per-account HOME switching, and session/new dies with
# "Authentication required" (observed 2026-11-18).
printf '%s' '{"process_args": ["--uid="], "process_command": "antigravity-acp-mux"}' > "$BASE/data/plugins/model-providers/antigravity-acp/launch_config.json"
[ "$(cat "$BASE/data/plugins/model-providers/antigravity-acp/launch_config.json")" = '{"process_args": ["--uid="], "process_command": "antigravity-acp-mux"}' ] && echo LAUNCH-CONFIG-OVERLAY-OK
# final-state inventory (any type at the two control levels must be exactly the allowlist):
TOP=$(find "$BASE/data/plugins" -mindepth 1 -maxdepth 1 | sed 's|.*/||' | sort | tr '\n' ' ')
MID=$(find "$BASE/data/plugins/model-providers" -mindepth 1 -maxdepth 1 | sed 's|.*/||' | sort | tr '\n' ' ')
[ "$TOP" = "model-providers " ] && [ "$MID" = "antigravity-acp " ] && echo PLUGINS-INVENTORY-OK
# B5. canary compose. NOTE `$$(...)`: compose interpolation collapses $$ to $,
KEY=$(openssl rand -hex 24); printf '%s' "$KEY" > "$R/.apik"; chmod 600 "$R/.apik"
cat > "$BASE/docker-compose.acp-p1.yml" <<'YAML'
name: nous-hermes-acp-p1
services:
  hermes-gateway:
    image: nousresearch/hermes-agent:v0.23.2
    container_name: hermes-acp-p1
    command: ["/opt/hermes/docker/main-wrapper.sh", "gateway", "run"]
    restart: "no"
    stop_grace_period: 30s
    stdin_open: true
    tty: true
    network_mode: bridge          # canary-local; api port published to host loopback only
    ports:
      - "127.0.0.1:18642:8642"
    working_dir: /ws
    shm_size: "1gb"
    # CapEff a82425fb both). Disposable canary only: bridge network,
    environment:
      HERMES_UID: "1000"
      HERMES_GID: "1000"
      HERMES_DASHBOARD: "0"
      HERMES_SKIP_CONFIG_MIGRATION: "1"
      PYTHONUNBUFFERED: "1"
      HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE: "trusted-coding"
      HERMES_ANTIGRAVITY_ACP_WORKSPACE: "/ws"
      HERMES_ANTIGRAVITY_ACP_CGROUP_ROOT: "/sys/fs/cgroup/acp-delegate"
      HERMES_ANTIGRAVITY_ACP_WARM_TTL_SECONDS: "15"
      API_SERVER_KEY: "APIKEYPLACEHOLDER"
      API_SERVER_HOST: "0.0.0.0"
      API_SERVER_PORT: "8642"
    volumes:
      - { type: bind, source: /home/gonus/acp-p1/data,       target: /opt/data,               bind: { create_host_path: false } }
      - { type: bind, source: /home/gonus/acp-p1/home,       target: /opt/data/home,          bind: { create_host_path: false } }
      - { type: bind, source: /home/gonus/acp-p1/agy-acp,    target: /opt/data/home/.agy-acp, bind: { create_host_path: false } }
      # ACP client binaries: production trees mounted READ-ONLY (immutable
      # versioned installs; zero copy; isolation rule targets mutable state).
      - { type: bind, source: /home/gonus/hermes-cloudcli/state/nous-migration-20261109-143536/data/.local/opt/antigravity-acp, target: /opt/data/.local/opt/antigravity-acp, read_only: true, bind: { create_host_path: false } }
      - { type: bind, source: /home/gonus/hermes-cloudcli/state/nous-migration-20261109-143536/home/.local/opt/antigravity-acp, target: /opt/data/home/.local/opt/antigravity-acp, read_only: true, bind: { create_host_path: false } }
      - { type: bind, source: /home/gonus/acp-p1/ws,         target: /ws,                     bind: { create_host_path: false } }
      - { type: bind, source: /home/gonus/acp-p1/machine-id, target: /etc/machine-id,         read_only: true, bind: { create_host_path: false } }
      - { type: bind, source: /home/gonus/acp-p1/seam-src,   target: /acp-seam,               read_only: true, bind: { create_host_path: false } }
YAML
sed -i "s/APIKEYPLACEHOLDER/$KEY/" "$BASE/docker-compose.acp-p1.yml"
grep -q "$KEY" "$BASE/docker-compose.acp-p1.yml" && echo APIKEY-INJECTED-OK
# The copied /opt/data/.env OVERRIDES container env at runtime
# (override=True; observed in the 2026-11-18 canary boot warning
# "API_SERVER_KEY is set in both ... the .env value wins"). Align the copied
# .env so api_server actually serves the key Blocks D/F/H authenticate with.
if [ -f "$BASE/data/.env" ]; then
  sed -i "s/^API_SERVER_KEY=.*/API_SERVER_KEY=$KEY/" "$BASE/data/.env"
  grep -q "^API_SERVER_KEY=$KEY\$" "$BASE/data/.env" || { echo 'FAIL: .env API_SERVER_KEY alignment unverified'; exit 1; }
  echo ENVKEY-ALIGNED-OK
fi
echo PREP-OK
echo; echo "################ Block C — canary up + PRE-delegation attestation (gate UNKNOWN with env set) ################"
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
echo; echo "################ Block D — fork-race probe + helper v6 run (sudo) ################"
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
echo; echo "################ Block E — post-delegation attestation + gate flip WITHOUT restart ################"
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
echo; echo "################ Block F — real ACP request under P1 shape + hardened sampler (Gate B F verbatim, renamed) ################"
set -euo pipefail
: "${R:?}"
KEY=$(cat "$R/.apik")
req() { # $1=query text, $2=outfile — synchronous chat/completions THROUGH the gateway
  curl -sS --max-time 300 -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d "{\"model\":\"gemini-3.8-flash\",\"reasoning_effort\":\"low\",\"provider\":\"antigravity-acp\",\"messages\":[{\"role\":\"user\",\"content\":\"$1\"}]}" \
    "http://127.0.0.1:18642/v1/chat/completions" > "$2"
}
answer() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['choices'][0]['message']['content'])" "$1"; }
# background membership sampler, BOTH directions every 2s during the request.
# Each iteration is tagged "I<n>" and preceded by "ITER <n> rc=<docker-exec-rc>"
# so a silently-failed sweep is impossible: the host wrapper checks the
# docker-exec status; the in-container sweep prints ESCAPE for any
# ACP-signature process whose cgroup is not an acpmux-* path, GONE for a
# process that vanished between ps and inspection (re-confirmed absent), and
# SWEEP-INCOMPLETE for ANY observation degradation (ps/grep failure, living
# process with unreadable cgroup) — any INCOMPLETE line is a hard FAIL; a
# clean census ends with "SWEEP-COMPLETE <n>" (bracket patterns avoid
# self-matching the sampler shell itself).
( for i in $(seq 1 240); do
    if out=$(docker exec hermes-acp-p1 sh -c 'for d in $(ls -d /sys/fs/cgroup/acp-delegate/acpmux-* 2>/dev/null); do for p in $(cat "$d/cgroup.procs"); do printf "%s %s " "$p" "$(basename "$d")"; tr "\0" " " < /proc/$p/cmdline | cut -c1-70; echo; done; done; ps_out=$(ps -eo pid,args 2>&1); prc=$?; if [ "$prc" -ne 0 ]; then echo "SWEEP-INCOMPLETE ps_rc=$prc"; else sig=$(printf "%s\n" "$ps_out" | grep -E "[a]ntigravity-acp-mux|[a]gy_acp_server|[l]ocalharness"); grc=$?; if [ "$grc" -gt 1 ]; then echo "SWEEP-INCOMPLETE grep_rc=$grc"; else n=0; bad=0; for p in $(printf "%s\n" "$sig" | awk "{print \$1}"); do n=$((n+1)); [ -d "/proc/$p" ] || { echo "GONE $p"; continue; }; [ -r "/proc/$p/cgroup" ] || { echo "SWEEP-INCOMPLETE alive-unreadable $p"; bad=1; continue; }; cg=$(cut -d: -f3 "/proc/$p/cgroup" 2>/dev/null); crc=$?; if [ "$crc" -ne 0 ]; then if [ -d "/proc/$p" ]; then echo "SWEEP-INCOMPLETE alive-readfail $p rc=$crc"; bad=1; else echo "GONE $p"; fi; continue; fi; case "$cg" in /acp-delegate/acpmux-*) ;; *) echo "ESCAPE $p $cg";; esac; done; [ "$bad" -eq 0 ] && echo "SWEEP-COMPLETE $n" || echo "SWEEP-INCOMPLETE per-proc-errors n=$n"; fi; fi' 2>&1); then rc=0; else rc=$?; fi
    echo "ITER $i rc=$rc"
    printf '%s\n' "$out" | sed "s/^/I$i /"
    sleep 2
  done ) > "$R/membership-req1.txt" 2>/dev/null &
SAMPLER=$!
req 'What is 17 plus 25? Answer with only the number.' "$R/request1.json" || { kill $SAMPLER 2>/dev/null; echo 'FAIL: request 1 transport error'; cat "$R/request1.json"; exit 1; }
kill $SAMPLER 2>/dev/null || true; wait $SAMPLER 2>/dev/null || true
A1=$(answer "$R/request1.json"); echo "request1 answer: $A1"
[ "$A1" = 42 ] || { echo "FAIL: request 1 answer != 42"; exit 1; }
# sampler integrity FIRST (a failed observation must never look clean):
brc=0; bad=$(grep -E '^ITER [0-9]+ rc=[^0]' "$R/membership-req1.txt" 2>/dev/null) || brc=$?
if [ "$brc" -gt 1 ]; then echo "FAIL: ITER-rc census grep rc=$brc (observation error — never treat as clean)"; exit 1; fi
if [ -n "$bad" ]; then echo 'FAIL: sampler iteration(s) with nonzero docker-exec rc:'; printf '%s
' "$bad"; exit 1; fi
irc=0; inc=$(grep 'SWEEP-INCOMPLETE' "$R/membership-req1.txt" 2>/dev/null) || irc=$?
if [ "$irc" -gt 1 ]; then echo "FAIL: SWEEP-INCOMPLETE census grep rc=$irc (observation error — never treat as clean)"; exit 1; fi
if [ -n "$inc" ]; then echo 'FAIL: degraded sweep observation (never treat an incomplete census as clean):'; printf '%s
' "$inc" | sort -u; exit 1; fi
wrc=0; SWEEPS_OK=$(awk '$2=="SWEEP-COMPLETE" && $3+0>=1 {c++} END{print c+0}' "$R/membership-req1.txt" 2>/dev/null) || wrc=$?
[ "$wrc" -eq 0 ] || { echo "FAIL: SWEEP-COMPLETE census awk rc=$wrc"; exit 1; }
[ "$SWEEPS_OK" -ge 3 ] || { echo "FAIL: only $SWEEPS_OK sweep iteration(s) observed >=1 ACP-signature process (need >=3) — escape coverage not sustained"; exit 1; }
echo SWEEP-HEALTH-OK
erc=0; esc=$(awk '$2=="ESCAPE"' "$R/membership-req1.txt" 2>/dev/null) || erc=$?
if [ "$erc" -ne 0 ]; then echo "FAIL: ESCAPE census awk rc=$erc (observation error — never treat as clean)"; exit 1; fi
if [ -n "$esc" ]; then echo "FAIL: escaped ACP-signature process observed:"; printf '%s
' "$esc" | sort -u; exit 1; fi
echo NO-ESCAPE-OK
grep -q 'antigravity-acp-mux' "$R/membership-req1.txt" || { echo 'FAIL: mux never observed inside a nonce cgroup'; exit 1; }
grep -qE 'agy_acp_server|localharness' "$R/membership-req1.txt" || { echo 'FAIL: vendor descendants never observed inside the nonce cgroup'; exit 1; }
awk '$1 ~ /^I[0-9]+$/ && $3 ~ /^acpmux-/ { k=$1 FS $3; if ($0 ~ /antigravity-acp-mux/) m[k]=1; if ($0 ~ /agy_acp_server|localharness/) v[k]=1 } END { for (k in m) if (k in v) { found=1; break } exit !found }' "$R/membership-req1.txt" \
  || { echo 'FAIL: no SAME sampler iteration observed a nonce cgroup containing BOTH the mux AND a vendor descendant'; exit 1; }
echo MUX-VENDOR-PAIR-OK
awk '$3 ~ /^acpmux-/ {print $3}' "$R/membership-req1.txt" | sort -u > "$R/nonces-req1.txt"
[ -s "$R/nonces-req1.txt" ] || { echo 'FAIL: no nonce cgroup during request'; exit 1; }
echo LIVE-REQUEST-OK
echo; echo "################ Block G — TTL eviction retry (Gate B G verbatim, renamed) ################"
set -euo pipefail
: "${R:?}"
KEY=$(cat "$R/.apik")
req() {
  curl -sS --max-time 300 -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
    -d "{\"model\":\"gemini-3.8-flash\",\"reasoning_effort\":\"low\",\"provider\":\"antigravity-acp\",\"messages\":[{\"role\":\"user\",\"content\":\"$1\"}]}" \
    "http://127.0.0.1:18642/v1/chat/completions" > "$2"
}
answer() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['choices'][0]['message']['content'])" "$1"; }
# nonce from F must be PARKED right now (same gateway process holds it).
# find (not ls+glob): rc>0 ONLY on real traversal error; no-match = rc 0 + empty.
if ! OUT1=$(docker exec hermes-acp-p1 find /sys/fs/cgroup/acp-delegate -maxdepth 1 -name 'acpmux-*' 2>&1); then echo "FAIL: nonce enumeration error: $OUT1"; exit 1; fi
[ -n "$OUT1" ] || { echo 'FAIL: no parked nonce after request 1 — warm pool did not retain the tree'; exit 1; }
printf '%s\n' "$OUT1" | sort > "$R/nonces-after-req1.txt"
echo '--- TTL (15s) expiry; same-session requests through the SAME gateway evict request 1 trees; warm reuse refreshes idle_since, so retry until eviction fires ---'
sleep 20
GONE=""
for attempt in 1 2 3 4; do
  req 'What is 17 plus 25? Answer with only the number.' "$R/request2-$attempt.json"
  A2=$(answer "$R/request2-$attempt.json"); echo "request2-$attempt answer: $A2"
  [ "$A2" = 42 ] || { echo "FAIL: request2-$attempt answer != 42"; exit 1; }
  sleep 3
  if ! OUT2=$(docker exec hermes-acp-p1 find /sys/fs/cgroup/acp-delegate -maxdepth 1 -name 'acpmux-*' 2>&1); then echo "FAIL: nonce enumeration error: $OUT2"; exit 1; fi
  printf '%s\n' "$OUT2" | sort > "$R/nonces-after-req2-$attempt.txt"
  GONE=$(comm -23 "$R/nonces-after-req1.txt" "$R/nonces-after-req2-$attempt.txt")
  if [ -n "$GONE" ]; then echo "eviction observed on attempt $attempt"; break; fi
  echo "attempt $attempt: every request-1 tree was warm-reused (idle_since refreshed) — sending another same-session request"
  sleep 25
done
[ -n "$GONE" ] || { echo "FAIL: no request-1 nonce was torn down by in-gateway eviction after 4 attempts (survivors: $(tr '\n' ' ' < "$R/nonces-after-req2-4.txt"))"; exit 1; }
echo "NONCE1-TORN-DOWN-OK evicted=$(printf '%s\n' "$GONE" | xargs -n1 basename | tr '\n' ' ')"
nrc=0; newn=$(comm -13 "$R/nonces-after-req1.txt" "$R/nonces-after-req2-$attempt.txt" 2>/dev/null) || nrc=$?
if [ "$nrc" -ne 0 ]; then echo "FAIL: nonce-set comparison comm rc=$nrc (observation error)"; exit 1; fi
if [ -n "$newn" ]; then echo NEW-SPAWN-AFTER-EVICTION-OK; else echo "NOTE: request reused a surviving warm tree (no new spawn this attempt; spawn path proven by request 1)"; fi
[ "$(docker inspect -f '{{.State.Status}}' hermes-acp-p1)" = running ] || { echo 'FAIL: canary gateway died'; exit 1; }
echo TEARDOWN-IN-GATEWAY-LIVE-OK
echo '--- production untouched (sibling no-impact) ---'
CID=$(docker inspect -f '{{.Id}}' hermes)
echo "production scope procs: base=$(cat "$R/prod-scope-procs.base") now=$(wc -l < /sys/fs/cgroup/system.slice/docker-$CID.scope/cgroup.procs) (natural drift allowed)"
if ! PENV=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' hermes 2>&1); then echo 'FAIL: cannot inspect production env'; exit 1; fi
if printf '%s\n' "$PENV" | grep -i canary; then
  echo 'FAIL: canary env leaked into production'; exit 1
else rc=$?; [ "$rc" -eq 1 ] && echo PROD-ENV-STILL-CLEAN-OK || { echo "FAIL: grep observation error rc=$rc pattern=canary"; exit 1; }; fi
echo; echo "################ Block H — idempotency (helper re-run) ################"
set -euo pipefail
if ! sudo bash /home/gonus/acp-p1-files/acp25-p1-helper.sh hermes-acp-p1 2>&1 | tee "$R/helper-run2.txt"; then echo "FAIL: helper re-run nonzero"; exit 1; fi
grep -q "HELPER-OK" "$R/helper-run2.txt" || { echo "FAIL: re-run no HELPER-OK"; exit 1; }
P1PID=$(docker inspect -f '{{.State.Pid}}' hermes-acp-p1)
# v5: host-side mountinfo (see Block E1 note — nsenter /proc/self is ENOENT here)
test "$(sudo awk -v t=/sys/fs/cgroup/acp-delegate '$5==t' "/proc/$P1PID/mountinfo" | wc -l)" -eq 1 || { echo "FAIL: mount stacking after re-run"; exit 1; }
echo IDEMPOTENT-RERUN-OK
echo; echo "################ Block I — rollback rehearsal (§7) + kill switch WITHOUT restart ################"
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
echo; echo "################ Block J — re-delegate + stop semantics + orphan scan (Gate B stop-semantics, renamed) ################"
set -euo pipefail
if ! sudo bash /home/gonus/acp-p1-files/acp25-p1-helper.sh hermes-acp-p1 2>&1 | tee "$R/helper-run3.txt"; then echo "FAIL: re-delegate nonzero"; exit 1; fi
grep -q "HELPER-OK" "$R/helper-run3.txt" || { echo "FAIL: re-delegate no HELPER-OK"; exit 1; }
echo RE-DELEGATION-OK
P1PID3=$(docker inspect -f '{{.State.Pid}}' hermes-acp-p1)
P1START3=$(docker inspect -f '{{.State.StartedAt}}' hermes-acp-p1)
if [ "$P1PID3" = "$P1PID0" ] && [ "$P1START3" = "$P1START0" ]; then echo "IDENTITY-STABLE-OK before stop (pid=$P1PID3 started=$P1START3)"; else echo "FAIL: container instance changed before stop ($P1PID0/$P1START0 -> $P1PID3/$P1START3)"; exit 1; fi
P1CID2=$(docker inspect -f '{{.Id}}' hermes-acp-p1)
SCOPE=/sys/fs/cgroup/system.slice/docker-$P1CID2.scope
echo '--- stop semantics ---'
T_START=$(date -Is); S0=$SECONDS
docker stop hermes-acp-p1
DUR=$((SECONDS-S0))
docker events --since "$T_START" --until "$(date -Is)" --filter container=hermes-acp-p1 --filter event=kill --format '{{json .}}' > "$R/kill-events-during.txt"
python3 - "$R/kill-events-during.txt" <<'PY'
import json, sys
lines = [l for l in open(sys.argv[1]).read().splitlines() if l.strip()]
sigs = []
for i, l in enumerate(lines):
    try:
        ev = json.loads(l)
    except Exception:
        print("FAIL: kill event line unparseable:", l[:120]); sys.exit(1)
    sig_raw = ((ev.get("Actor") or {}).get("Attributes") or {}).get("signal")
    if sig_raw is None or isinstance(sig_raw, bool) or (isinstance(sig_raw, str) and not sig_raw.strip()):
        print("FAIL: kill event missing/null signal (cannot prove non-SIGKILL):", l[:120]); sys.exit(1)
    sig = str(sig_raw).strip()
    if not (sig.isdigit() or sig.isalpha()):
        print("FAIL: kill event malformed signal attribute:", repr(sig)[:60]); sys.exit(1)
    if sig in ("9", "KILL", "SIGKILL"):
        print("FAIL: SIGKILL during stop (event", i, ")"); sys.exit(1)
    sigs.append(sig)
print("NO-SIGKILL-OK", len(lines), "kill event(s); signals:", sorted(set(sigs)) or "none")
PY
[ "$DUR" -lt 30 ] || { echo "FAIL: stop took ${DUR}s (>= grace 30s)"; exit 1; }
echo "STOP-CLEAN-OK duration=${DUR}s no-sigkill"
echo '--- 5-state orphan attestation (verbatim reviewed recipe) ---'
if [ ! -d "$SCOPE" ]; then
  echo "SCOPE-ABSENT (vacuous pass — recorded)" | tee "$R/orphan-attestation.txt"
else
  { files=$(find "$SCOPE" -name cgroup.procs) || { echo "TRAVERSAL ERROR (FAIL)"; exit 1; }
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
  echo "SCOPE-PRESENT, ALL $(printf '%s\n' "$files" | wc -l) cgroup.procs EMPTY (PASS)"; } | tee "$R/orphan-attestation.txt"
fi
grep -q FAIL "$R/orphan-attestation.txt" && { echo 'FAIL: orphan attestation contains FAIL'; exit 1; }
if pgrep -fa 'nous-hermes-acp-p1'; then echo 'FAIL: canary project processes remain'; exit 1; else rc=$?; if [ "$rc" -eq 1 ]; then echo NO-PROJECT-PROCS-OK; else echo "FAIL: pgrep observation error rc=$rc"; exit 1; fi; fi
echo; echo "################ Block K — teardown + production no-change (Gate B I+J, renamed) ################"
set -euo pipefail
: "${R:?}"
docker compose -p nous-hermes-acp-p1 -f /home/gonus/acp-p1/docker-compose.acp-p1.yml down --remove-orphans
if ! NAMES=$(docker ps -a --format '{{.Names}}' 2>&1); then echo 'FAIL: cannot list containers'; exit 1; fi
if printf '%s\n' "$NAMES" | grep -qx hermes-acp-p1; then
  echo 'FAIL: container remains'; exit 1
else rc=$?; [ "$rc" -eq 1 ] && echo CONTAINER-GONE-OK || { echo "FAIL: grep observation error rc=$rc pattern=hermes-acp-p1"; exit 1; }; fi
chmod -R u+rwX /home/gonus/acp-p1 2>/dev/null || true
rm -rf /home/gonus/acp-p1 2>/dev/null || true
if [ -e /home/gonus/acp-p1 ]; then
  docker run --rm -v /home/gonus/acp-p1:/x --entrypoint /bin/sh nousresearch/hermes-agent:v0.23.2 \
    -c 'chmod -R u+rwX /x 2>/dev/null; rm -rf /x/* /x/.[!.]*' || true
  rm -rf /home/gonus/acp-p1
fi
[ -e /home/gonus/acp-p1 ] && { echo 'FAIL: canary dirs remain'; exit 1; }
echo CANARY-DIRS-GONE-OK
rm -f "$R/.apik" && echo APIKEY-REMOVED-OK
set -euo pipefail
: "${R:?}"
RES=$(find /sys/fs/cgroup/system.slice -maxdepth 1 \( -name '*canary*' -o -name '*acp*' \) -print 2>/dev/null) || { echo 'FAIL: cgroup residue scan traversal error'; exit 1; }
[ -z "$RES" ] || { echo "FAIL: cgroup residue: $RES"; exit 1; }
echo RESIDUE-NONE-OK
if ! NAMES=$(docker ps -a --format '{{.Names}}' 2>&1); then echo 'FAIL: cannot list containers'; exit 1; fi
if printf '%s\n' "$NAMES" | grep -iE 'canary|acp'; then
  echo 'FAIL: container residue'; exit 1
else rc=$?; [ "$rc" -eq 1 ] && echo CONTAINER-RESIDUE-NONE-OK || { echo "FAIL: grep observation error rc=$rc pattern='canary|acp'"; exit 1; }; fi
[ ! -e /home/gonus/acp-p1 ] && echo DIR-RESIDUE-NONE-OK
docker inspect -f '{{.Id}} {{.State.Status}} pid={{.State.Pid}} started={{.State.StartedAt}}' hermes > "$R/prod-identity.after"
cmp "$R/prod-identity.base" "$R/prod-identity.after" && echo PROD-IDENTITY-IDENTICAL-OK
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' hermes | sort | sha256sum > "$R/prod-envhash.after"
cmp "$R/prod-envhash.base" "$R/prod-envhash.after" && echo PROD-ENVHASH-IDENTICAL-OK
if ! PENV=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' hermes 2>&1); then echo 'FAIL: cannot inspect production env'; exit 1; fi
if printf '%s\n' "$PENV" | grep -E 'ACP_MUX_F4_PROCESS_TREE_ACK|ACP_MUX_SESSION_GC|ACP_CGROUP'; then
  echo 'FAIL: ACK/GC/CGROUP env appeared'; exit 1
else rc=$?; [ "$rc" -eq 1 ] && echo ACK-GC-CGROUP-STILL-ABSENT-OK || { echo "FAIL: grep observation error rc=$rc pattern='ACP_MUX_F4_PROCESS_TREE_ACK|ACP_MUX_SESSION_GC|ACP_CGROUP'"; exit 1; }; fi
CID=$(docker inspect -f '{{.Id}}' hermes)
if ! SLIST=$(ls "/sys/fs/cgroup/system.slice/docker-$CID.scope" 2>&1); then echo "FAIL: cannot enumerate production scope: $SLIST"; exit 1; fi
if printf '%s\n' "$SLIST" | grep -i acp; then
  echo 'FAIL: acp objects appeared under production scope'; exit 1
else rc=$?; [ "$rc" -eq 1 ] && echo PRODUCTION-SCOPE-STILL-CLEAN-OK || { echo "FAIL: grep observation error rc=$rc pattern=acp"; exit 1; }; fi
if ! NSLIST=$(docker exec hermes ls /sys/fs/cgroup 2>&1); then echo "FAIL: cannot enumerate production ns cgroupfs: $NSLIST"; exit 1; fi
if printf '%s\n' "$NSLIST" | grep -i acp; then
  echo 'FAIL: acp objects in production ns'; exit 1
else rc=$?; [ "$rc" -eq 1 ] && echo PRODUCTION-NS-STILL-CLEAN-OK || { echo "FAIL: grep observation error rc=$rc pattern=acp"; exit 1; }; fi
sha256sum /home/gonus/hermes-cloudcli/docker-compose.nous.yml | awk '{print $1}' > "$R/compose-hash.after"
cmp "$R/compose-hash.base" "$R/compose-hash.after" && echo COMPOSE-FILE-UNCHANGED-OK
docker ps --format '{{.Names}}' | sort > "$R/ps-names.after"
diff "$R/ps-names.base" "$R/ps-names.after" > /dev/null && echo DOCKER-PS-NAMES-IDENTICAL-OK
echo; echo "################ RUN COMPLETE - paste the receipt bundle below ################"
echo "RECEIPT_DIR=$R"
miss=0
for f in "$R/delegated-root-pre.txt" "$R/delegated-root-post.txt" "$R/delegated-root-rolledback.txt" "$R/helper-run1.txt" "$R/helper-run2.txt" "$R/helper-run3.txt" "$R/rollback-run.txt" "$R/membership-req1.txt" "$R/nonces-req1.txt" "$R/request1.json" "$R"/request2-*.json "$R"/nonces-after-req2-*.txt "$R/request-rolledback.json" "$R/kill-events-during.txt" "$R/orphan-attestation.txt"; do if [ -e "$f" ]; then cat "$f" || { echo "READ-FAIL: $f"; miss=$((miss+1)); }; echo; else echo "MISSING-EVIDENCE: $f"; miss=$((miss+1)); fi; done; [ "$miss" -eq 0 ] || { echo "FAIL: $miss mandatory receipt artifact(s) missing/unreadable"; exit 1; }
