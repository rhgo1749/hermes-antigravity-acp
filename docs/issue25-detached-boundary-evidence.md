# Issue #25 — detached/setsid descendant boundary: evidence + closure design (no implementation)

Slice question (Gate B condition from `issue25-process-tree-evidence.md` §5):
does the process-group based teardown still bound native-store lifetime when
a vendor descendant leaves the mux's PGID/SID via `setsid()`/`setpgid()`?

**Verdict: INCONCLUSIVE — F4 Gate B ACK recommendation: NO-GO.**
The gap is real and pinned deterministically; the current vendor happens to
keep everything in-group at audit time, but nothing in any contract requires
it, and `setsid`/`setpgid`-related strings/symbols are present in the
shipped vendor binaries (reachability and runtime use unproven — §4).

## 1. Ownership boundary (source-confirmed, main `37828b1` + PR #50 head `ac781de`)

```
plugin (client.py)
  └─ Popen(mux, start_new_session=True)          # mux = session+group leader
       └─ mux (scripts/acp_mux.py)
            └─ Popen(agy_acp_server.par, pass_fds=(lease,))   # plain Popen:
                 │    # inherits mux PGID/SID; the repo guarantees lease-fd
                 │    # inheritance through the DIRECT official child only
                 └─ vendor-spawned descendants (localharness_external, …)
                      # group membership comes from fork inheritance alone;
                      # whether the vendor closes or retains inherited fds in
                      # further descendants is neither guaranteed by any
                      # contract nor verified by this slice;
                      # no code/contract prevents setsid()/setpgid()
teardown (process_teardown.py): killpg(leader PGID) — reachable set is
exactly "processes still in that group". Detached ⇒ unreachable by design.
```

PR #50 (`proc_dead_unreaped`) fixed *when* we reap (ownership preserved for
in-group sweeps). It does not and cannot widen *whom* `killpg` can reach.

## 2. Deterministic fake evidence (`tests/test_issue25_detached_boundary.py`, 3/3)

Credential-free fake: leader (`start_new_session`) + same-PGID holder +
`start_new_session=True` holder (models `setsid` escape; leaves PGID **and**
SID). Both holders claim a shared flock on a store-lock file (models
native-store lifetime). Pinned facts:

1. `terminate_process_tree(leader) is True` — owned-group sweep succeeds —
   same-PGID holder dies; **detached holder survives and still holds the
   store flock**. `killpg` cannot reach it; the result `True` proves nothing
   about it.
2. Sibling lanes untouched by the sweep (no over-reach).
3. After teardown reaps the leader, the detached holder is reparented, has
   no plugin-side handle, no group membership, and keeps the store flock.

Model limits (do not over-read): this is an admissible safety counterexample
model, **not** observed vendor 1.4.4 teardown behavior. The fake proves the
teardown's reachability boundary, nothing about vendor intent.

## 3. Live read-only vendor evidence (no signals, no restarts)

Snapshot 2026-11-17 21:21:27 KST, `/proc` reads only (raw dump:
`/opt/data/cache/scratch/g25-detached-live.txt`, sha256 prefix
`183612ddcde35f49`; fleet is dynamic — a later reviewer snapshot of
7 trees / 16 descendants / 0 detached is consistent, not contradictory):

- 8 mux trees (`antigravity-acp-mux.py`), 19 descendants total
  (`agy_acp_server.par` + `localharness_external`): **0 detached** — every
  descendant had PGID == SID == its mux pid.
- Open-fd scan of all vendor descendants: at sample time they held **no
  store-file fds** (only self-inspection `/proc/<self>`, `/sys/fs/cgroup`
  reads; `agy_acp_server.par` holds its glog files + the `.par` itself).

Limits: point-in-time observation of mostly-idle lanes. Store access may be
request-scoped/transient; "no store fd held now" is not "cannot hold one
while detached". Observed-same-group ≠ contract-guaranteed.

## 4. Contract evidence

- **ACP v1 spec** (agentclientprotocol.com, overview + transports +
  cancellation, fetched 2026-11-17; independently re-confirmed by reviewer):
  stdio transport defines only "the client launches the agent as a
  subprocess" plus the stdin/stdout JSON-RPC message contract (stdout
  message purity, stderr logging).  Cancellation only says a supporting
  implementation **MAY** cancel corresponding request activity and nested
  activities — and the capability itself is optional.  **The ACP standard
  is NOT a containment contract**: nothing in it guarantees vendor
  descendants keep the parent's PGID/SID, forbids `setsid`, requires child
  termination on parent exit, or requires native-store fd closure.  Do not
  read "ACP standard contract = containment" anywhere in this document.
- **Vendor 1.4.4 binaries** (static `strings`, read-only):
  `localharness_external` contains `setsid`/`setpgid`-related
  strings/symbol names (`Setsid`, `Setpgid`, `SetSID` — matching Go
  `syscall.SysProcAttr` field names); `agy_acp_server.par` contains
  `setsid`-related strings.  Static string/symbol-name presence does
  **not** prove these are reachable from a relevant descendant-spawn path
  or used at runtime — reachability and runtime use are **unproven**.
- **Google vendor docs**: none published in-repo or referenced by our docs
  that promise in-group descendants or store-fd release on child exit.
- Our own repo docs promise the *plugin* never daemonizes; they make no
  claims binding the vendor's descendants.

Conclusion: "currently observed same-group" and "contractually guaranteed"
are strictly separate.  Only the former holds, and the separation is
three-way: (1) live same-PGID observation — true at audit time, (2)
ACP standard — silent on containment, (3) vendor-specific contract — does
not exist in published form.  Candidate A in §5 therefore means a NEW
vendor-specific contract (or ACP RFD), not enforcement of an existing one.

## 5. Candidate closures (minimal design comparison only — nothing implemented)

| | A. vendor cooperation / explicit child-shutdown contract | B. OS containment stronger than process group (Linux cgroup v2) | C. stable ownership registry for detached descendants |
|---|---|---|---|
| Guarantee | depends entirely on vendor honoring a new contract | membership is per-task: inherited at fork, **survives `setsid`/`setpgid`/`exec`**; `cgroup.kill` sweeps all members | best-effort: detached processes leave the ppid tree at reparent; attribution of unknown PIDs is racy |
| Portability | protocol-level, OS-neutral | Linux-only; Windows analog (Job Objects) and macOS (no cgroups) need separate mechanisms | `/proc`-style assumptions; no Windows/macOS equivalent |
| Deploy risk | needs Google upstream change (ACP is silent; would be an upstream RFD + vendor release) | needs delegated cgroup (write to `cgroup.procs`/`cgroup.kill`); permission model varies (systemd user scopes vs cgroupfs); must fail-closed when unavailable | low infra risk, high correctness risk (registry races = false confidence) |
| Scope | outside our repo | one spawn-site seam + teardown seam, Linux-gated, flag-off default | new long-lived subsystem |
| Verdict | cleanest guarantee, not in our control | strongest primitive we can operate today; must prove membership-survives-escape on the real deployment | rejected: cannot close the exact gap it targets |

`PR_SET_CHILD_SUBREAPER` alone is **not** a closure: it changes who
*reaps*, not who is *reachable by signal* — detached groups still escape
`killpg`, and discovery of the new group is the unsolved half.

## 6. Residual counterexamples (all OPEN)

1. setsid-escaping descendant holding native-store state through every
   permitted teardown (pinned in §2.1).
2. `setsid`/`setpgid`-related strings/symbols present in the vendor
   binaries, with no contract against detaching; reachability and runtime
   use unproven (§4).
3. Detached survivor reparents and becomes unattributable to its lane
   (§2.3) — no plugin-side handle survives.
4. `terminate_process_tree` returning `True` is silent about out-of-group
   survivors — the current API cannot express "swept everything I own,
   ownership of the rest unknown".

## 7. Gate B recommendation

**NO-GO.** ACK additionally requires at least one of:
(a) a vendor/ACP contract guaranteeing in-group descendants and store-state
release on child exit, verified against the shipped binary; or
(b) a stronger-than-group containment (candidate B) implemented, deployed,
and attested on the live host (membership-survives-escape + sweep proof on
real vendor trees).
One unknown ⇒ NO-GO stands. Flags stay off (`ACP_MUX_F4_PROCESS_TREE_ACK`
unset, `ACP_MUX_SESSION_GC` off).

## 8. Next minimal implementation slice (exactly one, proposed — not run)

**Linux cgroup-v2 containment spike (test-only, no production wiring):**
on this host, create a delegated user cgroup; spawn the fake mux tree inside
it; assert (i) a `setsid`-escaping descendant stays a cgroup member,
(ii) `cgroup.kill=1` sweeps it while a sibling cgroup is untouched,
(iii) the spike fails closed when delegation is unavailable. Deliverable is
the proof + a go/no-go for a follow-up production seam at the single
`Popen(mux, …)` site. No GC, no ACK, no deployment.
