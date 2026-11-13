# Phase B P1: Windows lifecycle removal failure

## Executed failure and root cause

Exact candidate `a09ca50727350be16ddf003a1d1d35083404be6f` failed both native
Windows lifecycle jobs in [dispatch 43360195761](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43360195761).
The preceding installation, provider registration and unauthenticated
initialize succeeded. `CI gate` and `Release gate` correctly failed; those
partial platform successes never certify a new candidate.

Diagnostic commit `c35d542539cc726f398d9ae44908293cf1358536` adds only fixed
failure vocabulary (phase, operation, safe managed-path class, exception class,
errno/winerror), not raw paths, exceptions, credentials or session information.
The native x64 [job 131699865245](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43368911592/job/131699865245)
confirmed the following failure. ARM64
[job 131699865188](https://github.com/rhgo1749/hermes-antigravity-acp/actions/runs/43368911592/job/131699865188)
independently emitted the identical record and left five orphan official servers:

```json
{"phase":"delete","operation":"remove_official","path_type":"official_executable","error_class":"PermissionError","errno":13,"winerror":5}
```

The job cleanup also found five orphan `agy_acp_server` processes. The owning
source explains the discrepancy: `acp_probe.py` used `Popen.terminate()` and
waited only for its direct child. Windows official launchers are `.cmd`
wrappers, so this stops `cmd.exe` but not necessarily its server descendant.
A live Windows executable cannot be removed; the POSIX ability to unlink a
running image hid this gap. Installer/initialize success did not require the
server image to be deletable; the newly required lifecycle did.

The provider projection is removed first by `install_acp.delete`; the failure
is then in `install_official.uninstall` removing the pinned server tree, not
provider provenance checks or a need to grant broader NTFS permissions.
The pin and managed-launcher ownership checks are unchanged. The diagnosis is
not a runner-transient classification and no automatic retry is added.

## Smallest owning fix

`acp_probe.py` reuses the existing stdlib production
`process_teardown.py::terminate_process_tree` contract from #31. POSIX probes
start a new session so group ownership can be verified; Windows performs the
existing `taskkill /T /F` walk **while the known parent is still alive**.
No executable-name scan, foreign PID kill, ACL grant or arbitrary sleep is
introduced. The request send is also inside the cleanup `try/finally`.
Success output is emitted only after verified cleanup. False/unknown tree
cleanup fails the probe even if initialize answered.

The official installer, provider ownership classifier, deletion order and
publisher SHA-256 checks remain unchanged. Nothing suppresses PermissionError
or turns a locked/denied removal into PASS. Both Windows lanes retain all
previous actual installer, architecture, provider and restricted-environment
initialize checks; x64 retains the existing production teardown regression.

## Tests and executed evidence boundaries

`tests/test_acp_probe_cleanup.py` is discovered by pytest and can run with
stdlib unittest on each Windows native runner. It executes an isolated real
wrapper/server fixture for initialize and timeout, asserts the owned server
exits, and removes its fixture file. On Windows the server holds a genuine
no-delete-share file handle until it exits. The tests do not use vendor
accounts, production homes or process-name cleanup. A stop-file and bounded
fixture lifetime clean pre-fix failures without guessing/killing a PID.
The pre-fix source left the server alive for both paths (RED); the existing
production tree cleanup makes these same cases pass (GREEN).

`tests/test_windows_lifecycle_guards.py` exercises the existing public
removers with unknown provider ownership, unmanaged launcher, injected
permission denial (exactly one attempt) and a genuine Windows locked-file
negative. The lock case must fail and preserve the executable; only releasing
the fixture's own handle permits a subsequent explicit removal. It is skipped
on non-Windows, not reported as native-Windows PASS from Linux.

The first fixed-candidate x64 job passed all three native probe cleanup tests,
then rejected two negative fixtures as unmanaged **before** reaching deletion.
Their direct `_write_launcher` fixture used an unresolved temporary-root alias,
whereas production install and uninstall both resolve their roots. This was
reproduced with a POSIX symlink alias (RED), then corrected solely by resolving
the test root (GREEN); installer ownership checks remain byte-identical. A
regression preserves that fixture/source parity. Native Windows requires no
symlink privilege: its existing temp alias exercises the same fixture path.

`tests/test_ci_provider_lifecycle.py` checks diagnostics never echo raw paths or
error text and both native Windows lanes execute these regressions before
attesting stages. The complete fake/protocol suite and #31 regressions retain
automatic pytest discovery. Full new-HEAD PR CI, exact-SHA dispatch, all five
platform stages and the generated run/attempt/SHA-bound
`release-verification.json` must independently pass before candidate approval.
Final results and run links are maintained in Draft PR #37; older green jobs
are not reused.

No Phase C, main-push reduction, operating deployment, Gateway restart,
authenticated inference, GC enablement, tag/release creation or merge is part
of this rework.
