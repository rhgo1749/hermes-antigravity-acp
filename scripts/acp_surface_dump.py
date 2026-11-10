"""Read-only dump of the RAW model surfaces of one live ACP session.

Sends only initialize + session/new against the profile's configured launch
target (mux or official launcher). No authenticate, no login, no prompt, no
inference. Prints every raw entry the server authored, including enablement
metadata that the Hermes picker filters out.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hermes-plugin" / "antigravity-acp"))

from providers import get_provider_profile  # noqa: E402


def main() -> int:
    profile = get_provider_profile("antigravity-acp")
    if profile is None:
        print("PROBE|no_profile")
        return 2
    client = profile.create_client(
        command=profile.process_command, args=list(profile.process_args)
    )
    try:
        config_entries, legacy_entries = client.session_model_surface(
            timeout_seconds=30
        )
    finally:
        client.close()
    print("PROBE|config_options " + json.dumps(config_entries, ensure_ascii=False, sort_keys=True))
    print("PROBE|legacy_available " + json.dumps(legacy_entries, ensure_ascii=False, sort_keys=True))
    print(f"PROBE|counts config={len(config_entries)} legacy={len(legacy_entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
