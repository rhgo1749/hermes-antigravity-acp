# Optional read-only exposure audit

The repository hygiene check remains the fast, credential-free current-tree check:

```sh
python3 scripts/audit_public_tree.py
```

It checks tracked and unignored files in the current worktree. Standard CI keeps
running this command and does not receive a GitHub credential. It does not prove
that historical objects, other refs, GitHub discussion, Actions artifacts, or
release attachments are clear.

## Explicit opt-in audit

Run the deeper audit from a checkout and name the GitHub repository explicitly:

```sh
python3 scripts/audit_exposure.py \
  --root /path/to/checkout \
  --github OWNER/REPO \
  --format markdown \
  --output /path/outside/checkout/sanitized-audit.md
```

If `--output` is used, its destination must be outside the selected Git
repository so the audit cannot modify repository contents.

Without `--github`, the command audits only the refs and reachable history
available in the local checkout; every remote surface is reported as
`NOT_VERIFIED` with reason `not_requested`. The local scan reads refs, commits,
trees, and blobs without lazy fetching, replacement refs, or changing the
checkout. Shallow clones, missing objects, submodules, and inaccessible
boundaries are recorded as `NOT_VERIFIED`, never as clean.

With `--github`, the command uses GitHub REST **GET** requests only. It reads
all API-visible Git refs (including heads, tags, and pull refs), traverses their
reachable commit parents, and paginates issues and pull requests, comments,
workflow runs/jobs/logs/artifacts, releases, and release assets. A credential is
optional for public resources but recommended for complete authorized visibility.
When `gh` is authenticated, the command obtains the credential in memory via
`gh auth token`; it never writes or prints it. For a private repository, use a
fine-grained/read-only credential with only the required repository permissions:
Metadata read, Contents read, Issues read, Pull requests read, and Actions read.
No write, administrative, secrets-management, or workflow-dispatch permission is
needed. The GitHub audit is an operator-run procedure, not a normal CI step.

The report records the audit time, local and GitHub ref/reachable-commit counts,
pagination requests/pages, collection completion, and for every source a
partition of `CHECKED_NO_FINDING`, `FINDING`, `NOT_VERIFIED`, and
`OUTSIDE_VERIFIED_SCOPE` items. Partition totals are checked by the command.
`NOT_VERIFIED` reasons include access or retention failures, shallow/missing Git
objects, truncated trees, and pagination failures. A successful page does not
imply that unavailable or expired assets were checked. The local object-store
boundary is a separate surface: objects present in the local store but not
reachable from any advertised ref are counted as `OUTSIDE_VERIFIED_SCOPE` and
are never inspected; if the boundary probe itself fails, the boundary is
`NOT_VERIFIED`. Neither status may ever be represented as clean, and a clean
current-tree or clean reachable-traversal result never substitutes for them.
Resource limits are also explicit gaps: JSON responses are capped at 8 MiB,
Git blobs and downloads at 32 MiB, and archive members at 8 MiB each / 64
MiB total (10,000 members maximum). Oversized or unsupported content is
`NOT_VERIFIED`, not silently skipped.

Only matched rule categories, sanitized per-item class signatures, aggregate
counts, generic API status codes, and fixed gap reasons are included in JSON or
Markdown. Every `FINDING` item contributes a fixed-vocabulary signature with a
`locator=` structural-source token (for example `git_blob_content`,
`remote_blob_path`, `github_record`, or `download_content`), zero or more `ctx=`
path-context tokens (`example_fixture_path`, `example_naming`, or `general_path`),
one or more `fam=` coarse name/content-family tokens (`env_name`,
`credential_json_name`, `runtime_state_name`, `key_material_suffix`,
`ordinary_artifact_suffix`, `deployment_dir_name`, `content_rule`, or
`unclassified`), and, when
path/name evidence exists, `assoc=` tokens that bind one context to one family
from the same matched path or name. A bare filename token found in blob text
inherits the containing source path's context; a token with path segments uses
its own path context. The association vocabulary is regex-gated to the fixed
context and family values, and reports must use these pairs rather than infer a
relationship from separately unioned `ctx=` and `fam=` tokens. This prevents an
unrelated example/artifact match from downgrading a general-context sensitive
name match. Signatures never include the path, name, or value itself. Any class
token that does not match the fixed pattern is dropped before storage. Matched
values, GitHub user identities, URLs, and raw paths are suppressed from standard
output, errors, and reports. The command scans
supported GitHub user-attachment URLs discovered in text; arbitrary external
URLs are not fetched and remain `NOT_VERIFIED` (`external_reference_not_fetched`).
Binary content that cannot be meaningfully inspected is also `NOT_VERIFIED`
rather than clean. Reports do not claim that an unverified surface is clear.

The audit only reads and reports. It does not rotate credentials, delete assets,
modify issues or Actions, rewrite history, or automatically remediate findings.
If a report contains findings, handle usable credentials only through an
independently approved private security response. Do not paste raw findings into
public issues, CI logs, or reports.

## Publication gate

The sanitized report feeds the read-only publication gate:

```sh
python3 scripts/publication_gate.py \
  --report /path/outside/checkout/exposure-audit.json \
  --root /path/to/checkout \
  --github OWNER/REPO \
  --format markdown \
  --output /path/outside/checkout/publication-gate-decision.md
```

The gate re-runs the credential-free current-tree check, aggregates the four
typed partitions across every surface, and records (never grants) an optional
explicit human maintainer authorization file. An explicit `--github` target
repository identity is required for any route to reach eligibility: when it is
omitted, the report-target and authorization-source repository equality checks
cannot be verified and every route fails closed with the
`repository_identity_unbound` blocking reason. `NOT_VERIFIED`,
`OUTSIDE_VERIFIED_SCOPE`, current-tree findings, a stale report (>7 days), or an
open live-credential review keep in-place publicization at `NO_GO`; a clean-room
scrubbed minimum-code export is at best `CONDITIONALLY_ELIGIBLE` and is
`NOT_AUTHORIZED` without an explicit maintainer authorization record bound to
the same repository and scope. Report, authorization, and decision paths must
all sit outside the repository and every linked worktree. See
[publication scope decision](publication-scope-decision.md) for the standing
decision and the credential deactivation/rotation approval route.

## Dated audit snapshot

[Sanitized read-only audit, 2026-10-21 UTC](read-only-exposure-audit-2026-10-21.md)
records the original schema-v1 and schema-v2 historical snapshots plus the
2026-10-21T22:54:55Z schema-v3 authenticated, read-only rerun at source HEAD
`67631c089099ac8cf640d525c3b7a54086c9b5e7`. The latest report uses per-match
context/family associations and replaces the prior schema-v2 classification,
which could merge unrelated contexts. It records partition counts, rule-match
categories, pagination/reachability evidence, and explicit `NOT_VERIFIED`
boundaries. These are time-specific inventories, not a guarantee that later
repository or GitHub state is unchanged.
