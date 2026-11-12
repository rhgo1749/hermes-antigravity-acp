#!/usr/bin/env python3
"""historical reference rework: hosted clean-room Hermes selection + discovery probe.

Runs ONLY under the official, unmodified upstream Hermes virtualenv (the
commit pinned by the ``acp-clean-room`` workflow job) and ONLY as the
dedicated clean-room UID, against the provider projection that
``scripts/install_acp.py`` registered into ``HERMES_HOME``.

Exercises exactly two evidence classes and no others:

1. Provider selection — real ``providers.get_provider_profile`` discovery,
   profile field equality against this repository's own constants, native
   (override-free) resolution of ``process_command`` to the clean-room
   launcher under the clean-room user's HOME.
2. Model-discovery entry — the production seam
   ``AntigravityACPClient.list_models`` -> real official server, attempted
   with zero credential state. Whatever the server answers is summarized
   through the historical reference fingerprint-only contract: the probe prints counts,
   boolean boundary flags, sha256-16 fingerprints, and credential-shape
   class names — never server-authored text, never model ids, never raw
   exception messages. Zero ``authenticate``/login/OAuth frames are sent by
   construction: this probe has no authentication code path at all.

Prints sanitized, probe-authored ``PROBE|`` lines only. Exit 0 means the
auth boundary (or an unexpected real success) was reached cleanly; exit 1
is a fail-closed divergence.
"""
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import install_acp  # noqa: E402  (stdlib-only closure: redaction contract)

DISPLAY_NAME = "Antigravity ACP"
BASE_URL = "acp://antigravity"
AUTH_TYPE = "external_process"
LAUNCHER_NAME = "antigravity-acp-official"


def _fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _summary(text: str) -> str:
    # Reuse the runtime's non-echoing summary verbatim: counts, fingerprint,
    # class names — never values.
    return install_acp._server_stderr_summary(text)


def main() -> int:
    hermes_home = os.environ.get("HERMES_HOME", "")
    if not hermes_home:
        print("PROBE|FAIL reason=hermes-home-unset")
        return 1
    if os.environ.get("HERMES_ANTIGRAVITY_ACP_COMMAND", "").strip():
        print("PROBE|FAIL reason=command-override-present")
        return 1
    expected_launcher = str(Path.home() / ".local" / "bin" / LAUNCHER_NAME)
    if os.getuid() == 0:
        print("PROBE|FAIL reason=runs-as-root")
        return 1

    import providers

    profile = providers.get_provider_profile("antigravity-acp")
    if profile is None:
        print("PROBE|selection outcome=fail reason=profile-not-discovered")
        return 1
    assert profile is not None
    module = sys.modules.get(type(profile).__module__)
    module_file = str(getattr(module, "__file__", "") or "")
    expected_module = (
        Path(hermes_home) / "plugins" / "model-providers" / "antigravity-acp" / "__init__.py"
    )
    checks = {
        "profile_class": type(profile).__name__ == "AntigravityACPProfile",
        "display_name": profile.display_name == DISPLAY_NAME,
        "base_url": profile.base_url == BASE_URL,
        "auth_type": profile.auth_type == AUTH_TYPE,
        "native_command": str(profile.process_command) == expected_launcher,
        "served_from_hermes_home": (
            Path(module_file).resolve() == expected_module.resolve()
        ),
    }
    print("PROBE|selection " + " ".join(f"{k}={v}" for k, v in sorted(checks.items())))
    if not all(checks.values()):
        print("PROBE|FAIL reason=selection-field-divergence")
        return 1

    client = profile.create_client(
        api_key="antigravity-acp",
        base_url=profile.base_url,
        command=profile.process_command,
        args=list(profile.process_args),
    )
    assert client is not None
    class_ok = client.__class__.__name__ == "AntigravityACPClient" and not any(
        base.__name__ == "CopilotACPClient" for base in client.__class__.__mro__
    )
    print(f"PROBE|client class_ok={class_ok}")
    if not class_ok:
        print("PROBE|FAIL reason=client-class-divergence")
        return 1

    listing_outcome = ""
    try:
        try:
            models = client.list_models(timeout_seconds=25.0)
        except Exception as exc:  # noqa: BLE001 — boundary probe
            message = str(exc)
            boundary = "code=-32000" in message or "Authentication required" in message
            print(
                "PROBE|model_boundary outcome=auth-boundary "
                f"code_neg32000={'code=-32000' in message} "
                f"auth_required={'Authentication required' in message} "
                f"boundary_recognized={boundary} "
                f"fp={_fingerprint(message)} bytes={len(message.encode('utf-8', 'replace'))}"
            )
            if not boundary:
                # Not the documented auth gate: fail closed with fingerprint
                # only — untrusted server-authored text is never echoed.
                print("PROBE|failclosed " + _summary(message))
                print("PROBE|FAIL reason=non-auth-listing-failure")
                return 1
            listing_outcome = "auth-boundary"
        else:
            # The server answered a real unauthenticated listing — a genuine
            # (surprising) pass, recorded by count only; ids are server data.
            print(
                "PROBE|model_boundary outcome=real-unauthenticated-success "
                f"count={len(models or [])} ids_printed=False"
            )
            listing_outcome = "real-success"
    finally:
        client.close()

    floor = profile.fetch_models(timeout=25.0)
    print(
        "PROBE|picker_floor fetch_models_none="
        f"{floor is None} count_if_list={0 if floor is None else len(floor)}"
    )
    print(
        "PROBE|frames constructed=initialize+session/new "
        "authenticate_frames=0 login_frames=0 prompt_frames=0"
    )
    print(f"PROBE|RESULT PASS listing={listing_outcome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
