# Historical exposure-audit methodology

An earlier read-only audit examined repository history and GitHub resources.
Its scope and results apply only to the snapshot examined at that time, not to
this repository's current tree or any future publication.

The initial collector reported aggregate matches only; aggregate rule counts
cannot establish whether individual findings are benign or sensitive. A later
collector retained privacy-preserving classifications per item. An intermediate
classification was withdrawn because unrelated matches within an item could be
combined incorrectly. The later association-aware collector distinguishes
individual match contexts and treats ambiguous findings conservatively.

The audit could not inspect every external reference or inaccessible Actions
log. Such gaps remain **NOT VERIFIED**, not clean results. No credential
usability or confirmed exposure is inferred from a filename or a pattern match.
The original detailed inventory is not part of the public distribution.

For the read-only tool and its limitations, see
[the exposure-audit guide](read-only-exposure-audit.md). Re-run an audit on the
actual candidate and independently inspect its reachable history and remote
resources before publication.
