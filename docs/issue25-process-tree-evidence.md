# Issue #25 slice: process-tree / descendant lifetime evidence for F4 Gate B

Question (verbatim): does the end of a mux lane/process lease sufficiently
guarantee that the official ACP server AND its vendor-spawned descendants
(`localharness_external`) have ended native-store access?

**Verdict: INCONCLUSIVE → F4 Gate B ACK recommendation: NO-GO.**
Reviewer points A/B/C have executable counterexamples; point D shows the
deployed fleet currently has zero lease coverage (drift).

All evidence is from: real `scripts/acp_mux.py` (main `37828b1`) +
credential-free fake vendor/descendants (`tests/test_issue25_process_tree_lifetime.py`,
9 tests, all green), plus read-only `/proc`/`ps` observation of live trees.
No live process was signalled, no vendor binary executed, no GitHub mutation.

## 1. Source vs deployed identity (drift — reported separately, not fixed here)

| identity | value |
| --- | --- |
| canonical source | main `37828b1`, `scripts/acp_mux.py` sha256 `231ffda9…`, 120267 B |
| deployed launcher | `/opt/data/.local/bin/antigravity-acp-mux` sha256 `4aa93a25…` |
| deployed mux body | `/opt/data/.local/bin/antigravity-acp-mux.py` sha256 `5b665c5b…`, 25741 B (2026-11-13 build) |
| lease code in deployed | **absent** (`_LaneLease`/`pass_fds`/`_lane_lease` grep count = 0) |

The deployed mux matches no recent main commit for this file; it predates
F2/F3. Consequence: every live lane runs with **no lease fd at all** — a
read-only `/proc/*/fd` scan found **zero** holders of any production lease
file (`/opt/data/.hermes/cache/acp-mux-state.json.leases/` contains one
stale file, unheld). F3's coverage claims are therefore untestable against
the deployed fleet; GC remains off, which is the only reason this is not
actively dangerous.

## 2. Process-tree ownership (source + live)

Source contract: plugin spawns mux with `start_new_session=True` (mux leads
its own session/group); mux spawns the official child with **no**
`start_new_session` (child inherits mux's group) and `pass_fds=(lease_fd,)`
(lease covers mux + direct child only — the source comment itself defers
descendants to issue #25); mux `finally` runs a **direct-child-only**
ladder (stdin EOF → wait 2 → terminate → wait 3 → kill). No tree sweep in
the mux. `terminate_process_tree` (plugin side) does group kill + verified
sweep, and **refuses all group signalling once the leader was reaped**
(PID/PGID-reuse guard; issue #23 contract).

Live (read-only, 2026-11-17 20:19 KST, 8 vendor trees — 12053, 82578,
87446, 95069, 96104, 96482, 101014, 101102; one extra `mux.py`-matching
shell pipeline entry from the audit itself is excluded as a non-vendor
transient): every `agy_acp_server.par`
and every `localharness_external` has `PGID == SID == mux PID` — no setsid
escape observed in vendor 1.4.4. 4 mux trees are orphaned (`ppid=0`, plugin
client died; whole tree survives together).

## 3. Deterministic fake evidence (9 tests → reviewer points A–D)

| point | test | result |
| --- | --- | --- |
| B | `test_graceful_lane_close_releases_lease_while_descendant_holds_store` | PASS — flock shows zero holders while a live descendant holds the store fd |
| B | `test_grace_expiry_exposes_surviving_descendant_to_gc` | PASS — after the fixed grace window the GC predicate treats the lane unprotected while the descendant still accesses the store |
| B | `test_vendor_crash_releases_lease_and_orphans_descendant` | PASS — vendor crash → lease released, orphan (not zombie) descendant keeps store |
| A | `test_reaped_leader_refuses_sweep_and_leaves_whole_vendor_tree` | PASS — leader reaped via `poll()` → `terminate_process_tree` refuses (`result is not True`) → descendants survive, then lease dies with the direct child |
| C | `test_group_teardown_misses_setsid_detached_descendant` | PASS — a setsid-detached descendant escapes even a **verified** (`True`) group sweep |
| C-live | tree dump above | no detach observed in 1.4.4 — but nothing in any contract prevents it |
| — | `test_mux_sigkill_lane_stays_live_until_direct_child_exits` | PASS — positive control: inherited-fd coverage covers the DIRECT child only |
| — | `test_plugin_group_teardown_reaches_same_group_descendant` | PASS — positive control: plugin group sweep covers same-group descendants (parked server, 2 descendants) |
| — | `test_sibling_lane_teardown_leaves_other_lane_live` / `test_vendor_propagating_teardown_is_safe_but_not_guaranteed` | PASS — sibling isolation; full safety only when the vendor itself reaps descendants |

`scripts/verify_process_tree_teardown.py` proves ONLY "group-inheriting fake
grandchild + explicit `terminate_process_tree`". It does NOT cover vendor
detach or spontaneous parent exit; not extended here.

## 4. Live read-only exposure of the counterexample paths

* Warm-pool liveness uses `proc.poll()` (`client.py:4117/4145/4157`): a dead
  parked mux's zombie leader is reaped there, and the following
  `_terminate_parked` → `terminate_process_tree` then **must refuse** the
  group signal. A hung vendor (or any surviving descendant) then keeps the
  tree alive with no permitted teardown path. Mechanism confirmed in code;
  no such tree observed alive at audit time (all 8 trees intact or orphaned
  whole).
* Orphaned mux trees (`ppid=0`) show the adjacent already-realized path:
  plugin death leaves full trees running; with the deployed lease-less mux
  they are simultaneously invisible to F3 and unbounded (issue #25 proper).

## 5. F4 Gate B decision conditions (proposal)

ACK requires ALL of:
1. Deployed mux == audited source (SHA match) — currently FAIL (drift).
2. A store-access barrier that covers descendants, not just the direct
   child: either the vendor passes the lease fd to descendants (no vendor
   contract exists), or every native-store consumer must hold a store-level
   advisory lock the GC probes (vendor cooperation required), or
   descendants are proven by contract + attestation to always die with the
   direct child (no such contract exists).
3. A teardown path that still reaches descendants after the group leader
   was reaped. Closing this needs EITHER a non-reaping liveness path that
   preserves verifiable ownership/containment before any reap, OR a
   containment/ownership primitive stronger than process groups (Linux
   `pidfd` stabilizes task identity but alone grants no descendant
   containment and does not auto-own/enumerate a surviving group whose
   leader was already terminated and reaped).  Alternatively, proof that
   no lifecycle path reaps the leader before sweeping — the warm-pool
   `poll()` path currently refutes that.
4. Live attestation loop: after each lane close, zero descendant processes
   with open store fds survive the grace window.

Any of these UNKNOWN ⇒ NO-GO. Simple parent-PID disappearance or a stale
lease alone must never ACK.

## 6. Next minimal actions (NOT executed in this slice)

1. Boundary closure requirement (NOT an implementation decision, and not
   implemented in this PR): closing the reaped-leader refusal path needs
   either a non-reaping liveness path that preserves verifiable
   ownership/containment before any reap, or a containment/ownership
   primitive stronger than process groups.  Do NOT expand into the
   warm-pool global-cap refactor here.
2. Redeploy the audited mux build (drift closure) — separate approval.
3. Independent re-review of this evidence via WebGPT task.
