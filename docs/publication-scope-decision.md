# Publication scope decision and audit gate

Standing decision for publishing this repository's code publicly. This document
is the durable decision record; the machine-readable evaluation is produced by
`scripts/publication_gate.py` over a sanitized `scripts/audit_exposure.py`
report. Both tools are read-only: nothing in this repository flips visibility,
rewrites Git history, mutates GitHub assets, tests or rotates credentials,
creates an export, or grants publication approval.

## Decision (current)

- **The source repository remains private.** No in-place publicization is
  approved or planned by any tool, and none may be performed while this
  decision stands.
- **In-place publicization of the current repository (with its full Git
  history and GitHub-visible historical assets): NO-GO.** The evidence does not
  confirm an exposure incident, but it also cannot certify the historical
  record clean: expired Actions material, inaccessible historical assets,
  external references that were never fetched, and local object-store items
  outside verified traversal remain explicitly typed `NOT_VERIFIED` /
  `OUTSIDE_VERIFIED_SCOPE`. Unresolved sensitive exposure or material coverage
  gaps are sufficient for NO-GO; unverified is never presented as clean.
- **The only conditional public candidate is a separately created clean-room,
  scrubbed minimum-code repository/export** built from the verified current
  tree only — never from this repository's history. Publication of such an
  export requires an **explicit human maintainer authorization record**, which
  is **not granted as of this writing**. The gate records such a record when
  one is provided; it can never create, imply, or infer one.

## What a clean-coverage claim requires

A current-tree check (however green) never substitutes for historical and
remote coverage. A clean-coverage claim requires all of the following, at the
exact target HEAD, in the same audit generation:

1. the credential-free current-tree check passes;
2. local advertised refs and all reachable commits/blobs were traversed with
   no missing/shallow boundary;
3. the local object-store boundary was probed and its unreachable/dangling
   items are explicitly typed `OUTSIDE_VERIFIED_SCOPE` (counted, never
   inspected — their mere presence blocks a claim that the *object store* is
   clean, which is why the gate treats them as unresolved);
4. every GitHub-visible surface (API refs and reachable history, Issue/PR
   discussions, comments, reviews, Actions runs/logs/artifacts, releases and
   assets, discovered attachments) was enumerated with completed pagination;
5. no surface reports a `FINDING`, `NOT_VERIFIED`, or `OUTSIDE_VERIFIED_SCOPE`
   item, every partition is valid, and the report is no older than the gate's
   7-day freshness limit; and
6. an explicit maintainer authorization record bound to the same repository
   and scope is recorded by the gate.

Anything unavailable, expired, external, unsupported, oversized, or out of the
verified traversal stays typed as a gap and keeps the verdict NO-GO. Private
risk classifications of any `FINDING` items live only in the external,
sanitized audit report — never in this repository, PRs, Issues, CI logs, or
task handoffs.

## Gate procedure (operator-run, read-only)

```sh
python3 scripts/audit_public_tree.py

python3 scripts/audit_exposure.py \
  --root /path/to/checkout \
  --github OWNER/REPO \
  --format json \
  --output /path/outside/repo-and-all-worktrees/exposure-audit.json

python3 scripts/publication_gate.py \
  --report /path/outside/repo-and-all-worktrees/exposure-audit.json \
  --root /path/to/checkout \
  --github OWNER/REPO \
  --format markdown \
  --output /path/outside/repo-and-all-worktrees/publication-gate-decision.md
```

Optional explicit authorization record (created and held only by a human
maintainer, outside the repository; the gate only records its digest and
fixed-scope verdicts):

```json
{
  "schema": "publication-authorization-v1",
  "authorized": true,
  "scope": "clean_room_minimum_code_export",
  "source_repository": "OWNER/REPO",
  "authorized_by": "maintainer-held identity, never copied into reports"
}
```

Route semantics: `NO_GO` (material blockers), `NOT_AUTHORIZED` (no explicit
maintainer authorization recorded for that route and scope),
`CONDITIONALLY_ELIGIBLE` (all objective gates passed; the human decision to
publish still belongs to the maintainer alone). `approval_granted_by_gate` is
structurally always `false`.

## Live credential response route

If a future or past audit classifies a potential **active credential** among
its sanitized findings, the response is a **separate, independently approved
private deactivation/rotation plan** owned by the human maintainer. Neither the
audit nor the gate ever tests credential usability, deactivates, or rotates
anything, and no finding detail (raw value, filename, path, account identity,
or URL) may be copied into public issues, CI logs, or reports. While such a
review is open, the gate adds `live_credential_review_open` to the in-place
route blockers regardless of other coverage.

## Safe summary — authenticated rerun at target `main` HEAD

Scope: current tree; local advertised refs/reachable commits/blobs; local
object-store boundary; GitHub-visible refs and reachable history; Issue/PR
discussions, comments and reviews; Actions runs, logs and artifacts; releases
and assets; discovered GitHub attachments; external links recorded, not
fetched. Source HEAD: `73c8dc7adf64ef94d7b919e759f05823ba1765a6`. Read-only,
`gh`-authenticated (credential value and identity suppressed).

<!-- SNAPSHOT:BEGIN schema-v4 rerun; values below are aggregate counters only. -->
Rerun executed read-only from a clean checkout at source `main` HEAD
`73c8dc7adf64ef94d7b919e759f05823ba1765a6` (identical to the current target
`main` HEAD; the local traversal additionally covered this audit branch's
integration-pending commits present in the same object store). Authenticated
audit time (UTC): `2026-11-05T08:04:37Z`; gate time (UTC):
`2026-11-05T08:04:42Z`.

Reachability: 207 local refs, 199 locally reachable commits, 436 local
blob/path items, `local_shallow=false`; 50 GitHub-visible refs, 213 GitHub
reachable commits. The fast current-tree check passed
(`CHECKED_NO_FINDING`).

| Source | Total | CHECKED_NO_FINDING | FINDING | NOT_VERIFIED | OUTSIDE_VERIFIED_SCOPE | Gap reasons |
|---|---:|---:|---:|---:|---:|---|
| local_git_history | 842 | 709 | 133 | 0 | 0 | — |
| local_object_store_boundary | 38 | 0 | 0 | 0 | 38 | `dangling_object_not_traversed=38` |
| github_refs | 50 | 50 | 0 | 0 | 0 | — |
| github_history | 10666 | 7727 | 2939 | 0 | 0 | — |
| github_discussions | 124 | 118 | 6 | 0 | 0 | — |
| github_reviews | 10 | 10 | 0 | 0 | 0 | — |
| github_inline_comments | 0 | 0 | 0 | 0 | 0 | — |
| github_actions | 179 | 178 | 1 | 0 | 0 | — |
| github_action_logs | 75 | 0 | 0 | 75 | 0 | `http_415=75` |
| github_action_artifacts | 58 | 29 | 0 | 29 | 0 | `http_415=29` |
| github_releases | 0 | 0 | 0 | 0 | 0 | — |
| github_release_assets | 0 | 0 | 0 | 0 | 0 | — |
| external_references | 31 | 0 | 0 | 31 | 0 | `external_reference_not_fetched=29`, `http_404=2` |
| **Total** | **12073** | **8821** | **3079** | **135** | **38** | |

`FINDING` here counts scanner rule-category matches, not confirmed exposures;
private risk classification of every matched item is held only in the external
report. This run's finding classes are name/artifact-family signatures only
(39 distinct sanitized signatures); no credential- or key-shape content class
appeared, so no live-credential deactivation/rotation approval route was
opened by this rerun.

Gate outcome: overall **NO-GO**. In-place publicization `NO_GO`
(`findings_present`, `unverified_items_present`,
`outside_verified_scope_present`,
`maintainer_authorization_not_recorded`); clean-room scrubbed minimum-code
export `NOT_AUTHORIZED` (`maintainer_authorization_not_recorded`).
`approval_granted_by_gate=false`. Maintainer authorization: **not recorded**.

Private verification authority: the sanitized schema-v4 audit report kept
outside the repository and all linked worktrees by the repository maintainer,
identified by SHA-256
`97f5fef4fcddfb703782389a76d7d50303ab7694370f4ad30e0f0f577bad85d9` (the
machine-readable gate decision is stored alongside it). This document
intentionally records no file names, paths, raw values, account identities, or
source URLs from the audit.
<!-- SNAPSHOT:END -->

## Preserved contracts

- No source-repository visibility change; history is not rewritten; remote
  GitHub assets are not modified.
- No credential usability testing, deactivation, or rotation outside the
  separate authorized approval route above.
- No raw sensitive match values, credentials/OAuth material, account
  identities, host names, file names, paths, or full URLs in this repository,
  PRs, Issues, CI logs, gate decisions, or task handoffs.
- Audit reports, authorization records, and gate decisions stay outside the
  repository and every linked worktree; the tools refuse those paths
  otherwise.
- Publication of any separate clean-room export additionally requires the
  explicit human maintainer authorization; publication itself is never a tool
  operation.
