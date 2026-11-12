# Provider runtime contracts

Detailed runtime behavior of `hermes-plugin/antigravity-acp/`,
moved out of the README. These behaviors are code-verified and covered by the
credential-free suites (`tests/test_standalone_client.py`,
`tests/test_native_video_blocks.py`, `tests/test_native_permission_policy.py`,
`tests/test_usage_telemetry_contract.py`, and siblings).

## ACP session flow

The provider starts the official server, sends `initialize` / `session/new`
(or `session/resume`) / `session/set_config_option` / `session/prompt`,
consumes `session/update`, and maps the response back into Hermes' provider
client shape. Tool-call/result replay, completed-action handling, no-progress
duplicate suppression, conversation affinity, and durable ACP continuation all
live inside this repository rather than in Hermes core.

## Model attribution (fail-closed)

If ACP does not offer the requested model, the provider continues only when
the session reports its active model (`models.currentModelId` or the model
config option's `currentValue`). It reports that effective model in
`completion.model` and a warning; if ACP does not identify the session
default, the provider fails explicitly rather than attributing the request to
a model it did not select. On a resumed native session the effective model
comes only from a server-reported active model or a persisted effective model
bound to the exact resumed `sessionId`; when neither is known (legacy
checkpoint with an empty effective model, or a session-id mismatch on a
metadata-less resume), the turn fails explicitly instead of claiming the
requested model or an arbitrary default.

## Durable continuation

Durable continuation is intentionally **independent of Hermes provider-client
lifetime**. The plugin keys native ACP sessions from Hermes' durable session
identity plus the turn lane (`foreground`, `background_review`,
`side_question`), keeps that mapping process-wide, and checkpoints only opaque
session/frontier hashes to `~/.hermes/cache/antigravity-acp-sessions.json`
(0600, atomic replace; override with `HERMES_ANTIGRAVITY_ACP_STATE_FILE`).
Rebuilding an `AIAgent`, interrupting a request, reloading plugins, or
recreating the transport client therefore resumes the existing native ACP
session instead of replaying the whole transcript. Checkpoints expire after 24
hours by default (`HERMES_ANTIGRAVITY_ACP_STATE_TTL_SECONDS`) and are bounded
to 512 entries (`HERMES_ANTIGRAVITY_ACP_STATE_MAX_ENTRIES`). Checkpoint I/O is
fail-soft: a write failure degrades to process-local continuity rather than
failing the model response.

## Learned native trajectory limits

Native ACP trajectory limits are learned separately from model context size.
The provider starts from a **1,000,000-token model ceiling** and rotates at 90%
by default. If ACP reports a concrete `token limit` / `max_token_limit`, that
value clamps the ceiling immediately. If a resumed session instead dies with a
confirmed context-window/trajectory-limit failure but no numeric limit, the
failed projected size can be recorded as an inferred upper bound and future
sessions rotate before it. A bare `doneCh for checkpoint` error is **not proof
of token exhaustion**, so it does not lower the inferred limit. When a
checkpoint error occurs after `session/prompt` begins, the provider fails
closed and records any partial native tool activity rather than replaying a
possibly mutating action; the caller must reconcile external state before an
explicit retry. Learned limits are stored as profile-neutral operational
metadata in `~/.hermes/cache/antigravity-acp-native-limits.json` (0600, atomic
replace, seven-day TTL by default), so all Hermes profiles on the same
installation share the observation. Override the file with
`HERMES_ANTIGRAVITY_ACP_LIMIT_STATE_FILE`, the TTL with
`HERMES_ANTIGRAVITY_ACP_LIMIT_TTL_SECONDS`, the ceiling with
`HERMES_ANTIGRAVITY_ACP_NATIVE_TOKEN_LIMIT`, or the rotation fraction with
`HERMES_ANTIGRAVITY_ACP_ROTATION_FRACTION`.

## Fabricated-artifact grounding check

Final responses also fail closed on fabricated Hermes scratch artifacts. When
a final answer positively claims that a path under the Hermes scratch/cache
area was created, saved, or produced, the provider performs a fresh filesystem
existence check. A missing artifact gets one grounded correction turn; if the
corrected final answer still claims a nonexistent path, the completion is
rejected instead of being surfaced as successful evidence. Negative
diagnostics such as "that file does not exist" are not treated as positive
artifact claims.

## Replay structure

When a full replay is actually necessary (first turn, ACP `session/resume`
miss, an optional compatible-transport failover, or an incompatible
history/tool frontier), the prompt separates authoritative
`SYSTEM_INSTRUCTIONS`, reference-only `HISTORICAL_CONTEXT`, the current
`ACTIVE_REQUEST`, and already-completed `ACTIVE_REQUEST_PROGRESS`. Older
`User:` blocks are explicitly non-active so a long replay cannot silently
resurrect a completed task.

## Native Telegram video (opt-in; trust warning)

Telegram's inbound path currently passes a video to the model client as a text
note plus a local cache path. This provider can convert that note to an ACP
`resource_link`, which the official Antigravity server resolves as native
video (including its audio track). It is **disabled by default**. Enable it
only by setting `HERMES_ANTIGRAVITY_ACP_NATIVE_VIDEO=1` in the Hermes process
environment; any other or missing value disables it.

This is not authenticated attachment provenance: `request_messages` exposes
the note as user text, and a sender who can type that text can point it at any
video in the same profile's allowed cache. Cache-path checks block arbitrary
outside paths and symlinks, but do **not** prove Hermes Core created the note.
Do not opt in for a shared Hermes home, multiple mutually-untrusted users, or
any deployment where one user must not cause another user's cached video to be
sent to the model. Even in a single-user home, enabling this allows a
user-authored message to cause processing of any allowed cached video; the
plugin cannot authenticate that it is the file Telegram attached.

The plugin rechecks the file's inode/size/timestamps immediately before
sending the ACP prompt. ACP `resource_link` carries a pathname, not a pinned
file handle, so a same-UID process can still replace it in the final
check-to-open window inside the official server. This mitigation narrows but
cannot remove that TOCTOU risk; the official server protocol is unchanged.

The allowlist is limited to regular `.mp4`, `.mov`, and `.webm` files directly
inside the current Hermes home's `cache/videos`, at most 50 MiB and 24 hours
old, and at most two per turn. Only the newest user message is scanned. A
resumed ACP session may retain media already consumed in its earlier prompt;
new continuation deltas do not reattach prior videos. If a file disappears or
changes after extraction, a retry drops it; a fresh replay with the same note
and a replacement file at the same path cannot prove it is the original
upload.

## Web research bridge (provider mode)

For provider-mode web research, the adapter bridges only function schemas
explicitly supplied by Hermes and returns their calls to Hermes' normal
policy/execution path; it does not execute a search itself or infer that the
official ACP server has a native web tool. The bridge records privacy-safe
call/result status and distinguishes unavailable, not-attempted, denied,
cancelled, and failed outcomes. A previously reported incident's exact tool
and denial stage remain **UNVERIFIED** absent a correlated protocol trace. See
[`docs/web-research-bridge.md`](web-research-bridge.md) for ownership,
troubleshooting, sanitized evidence, and rollout/rollback guidance.

## Native coding and workspace

Native coding tools are never auto-approved. Native `run_command` is disabled
at session launch (`agy.disabledTools`) and every native file-mutation or
command permission frame is answered with the server's own reject option; the
model performs shell and file work through Hermes' approval-gated terminal and
file tools. The former trusted-coding auto-approval was removed after the
Hermes plugin catalog review; `HERMES_ANTIGRAVITY_ACP_WORKSPACE` and the legacy
`HERMES_ANTIGRAVITY_ACP_EXECUTION_MODE` variable are inert. Sessions whose
stored context fingerprint predates the removal mismatch and start a fresh ACP
session.
