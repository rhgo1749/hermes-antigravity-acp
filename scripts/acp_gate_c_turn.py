"""Gate C: one explicitly-approved live ACP turn.

Refuses to run unless HERMES_ACP_GATE_C_APPROVED=1 is set in the invoking
environment. Sends exactly one minimal prompt through the installed official
ACP session, prints only the reply text, then closes. No retries, no tools,
no credential or payload output.
"""
from __future__ import annotations

import os
import sys

APPROVAL_ENV = "HERMES_ACP_GATE_C_APPROVED"
PROMPT = (
    "This is a one-shot connection test. Reply with exactly this text and "
    "nothing else: ACP-GATE-C-OK"
)


def main() -> int:
    if os.environ.get(APPROVAL_ENV) != "1":
        print("GATE_C|REFUSED reason=approval-env-not-set")
        return 2
    os.environ.pop(APPROVAL_ENV, None)

    from providers import get_provider_profile

    profile = get_provider_profile("antigravity-acp")
    if profile is None:
        print("GATE_C|FAIL provider_not_found")
        return 1
    client = profile.create_client()
    try:
        completion = client.chat.completions.create(
            model="gemini-3.8-flash-high",
            messages=[{"role": "user", "content": PROMPT}],
            timeout=180.0,
        )
        reply = (completion.choices[0].message.content or "").strip()
        print("GATE_C|REPLY_LEN=" + str(len(reply)))
        print("GATE_C|REPLY=" + reply[:200])
    except Exception as exc:  # noqa: BLE001 - class name only, never payloads
        print("GATE_C|FAIL error_class=" + type(exc).__name__)
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
