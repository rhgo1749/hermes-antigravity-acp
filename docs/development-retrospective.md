# Development retrospective

This repository began as a private engineering log. Before publishing we
removed internal evidence trails (issue-runner records, host deployment
notes). This page preserves what was actually learned, in publishable form.
Commit history starts from a sanitized snapshot for that reason; the work it
compresses spans roughly six weeks and 60+ merged changes.

## What went right

- **Credential-free CI from day one.** Every automated check runs without any
  vendor credential. Live authenticated behavior is verified only by an
  operator-supervised, single-prompt canary with an on-disk event journal, so
  "the tests pass" and "the real service answered" remain separate, provable
  claims.
- **A written path contract.** Where the provider looks for its binary,
  workspace, registry, state, and logs is a single explicit resolution order
  (documented in `docs/acp-path-contract.md`), with fail-closed refusal when
  two roots conflict. A duplicated, drifting home directory caused one real
  incident; the contract plus 20 pinned assertions is the response.
- **Fail-closed packaging.** The optional multi-account mux installs only on
  explicit invocation, aborts with zero writes over foreign bytes, and its
  installer/uninstaller/status/doctor surface never reads credentials. The
  default single-account path is byte-invariant under all of it.
- **Public-tree audits as code.** `scripts/audit_public_tree.py` and
  `scripts/audit_exposure.py` encode what may ship, and CI enforces them.

## What hurt, and what it taught

- **Provenance claims outran evidence.** An internal gate was once marked done
  from a console transcript that could not prove how many prompts were sent or
  that authentication and inference used the same session. The verdict was
  retracted. Since then, gate records separate *authentication*, *model
  response*, and *frame-level call counting*, and only the last makes a
  single-call claim. The one-touch probe (`spawn_count=1`,
  `prompt_attempts=1`, ordered `events.jsonl`) exists because of this failure.
- **Automation lifecycle bugs masquerade as product bugs.** A webhook delivery
  failed with a stale in-process registration after a plugin reload; a card
  sat in review although its PR had merged. Root cause was lifecycle plumbing,
  not the provider. Fresh reads of the authoritative system (GitHub state,
  event journals) became mandatory before any status claim.
- **Thinking-level mapping was guesswork.** Reasoning-effort values were
  mapped to vendor thinking levels without documented rationale; two upstream
  levels had no mapping at all. Fixed with an explicit, tested mapping and
  honest documentation of what the server actually advertises.
- **Docs that assert absolutes rot.** A blanket "we never touch accounts"
  claim became false the day an opt-in mux preview shipped. Wording now states
  what the software does and does not support, per distribution surface.

## Standing rules this produced

1. Never claim a state without a fresh read of its authoritative source.
2. Separate HTTP success from response fidelity; separate CI green from live
   verification.
3. One supervised prompt per live credential probe, with a journal.
4. Opt-in features must leave the default path byte-identical.
5. Prefer deleting a wrong absolute claim over softening it.
