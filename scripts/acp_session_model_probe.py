"""Read-only ACP session-model probe for the Gate C model-mapping question.

Runs initialize + session/new only. No authenticate, no session/prompt, no
login, no credential output. Prints the server's raw session model surface:
configOptions (model-category entries), models.currentModelId, and the
enabled availableModels/options ids. Run several times to observe whether the
official server's live list varies between sessions.
"""
from __future__ import annotations

import json
import sys

from providers import get_provider_profile


def main() -> int:
    profile = get_provider_profile("antigravity-acp")
    if profile is None:
        print("PROBE|FAIL provider_not_found")
        return 1
    client = profile.create_client()
    try:
        with client._session(30.0, allow_file_requests=False) as (session, _, _):
            model_options = [
                option
                for option in (session.get("configOptions") or [])
                if isinstance(option, dict)
                and "model" in (option.get("category"), option.get("id"))
            ]
            for option in model_options:
                print(
                    "PROBE|config_option",
                    json.dumps(
                        {
                            "id": option.get("id"),
                            "category": option.get("category"),
                            "current_value": option.get("currentValue"),
                            "options": [
                                {
                                    "value": entry.get("value"),
                                    "enablement": (
                                        (entry.get("_meta") or {}).get(
                                            "copilotEnablement"
                                        )
                                    ),
                                }
                                for entry in (option.get("options") or [])
                                if isinstance(entry, dict)
                            ],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                )
            models = session.get("models")
            if isinstance(models, dict):
                print("PROBE|models_current", json.dumps(models.get("currentModelId")))
                print(
                    "PROBE|models_available",
                    json.dumps(
                        [
                            entry.get("modelId")
                            for entry in (models.get("availableModels") or [])
                            if isinstance(entry, dict)
                        ],
                        ensure_ascii=False,
                    ),
                )
                print(
                    "PROBE|model_entry_fields",
                    json.dumps(
                        sorted(
                            {
                                key
                                for entry in (models.get("availableModels") or [])
                                if isinstance(entry, dict)
                                for key in entry
                            }
                        )
                    ),
                )
            print("PROBE|session_keys", json.dumps(sorted(session.keys())))
    except Exception as exc:  # noqa: BLE001 - report class only, never payloads
        print("PROBE|FAIL error_class=" + type(exc).__name__)
        return 1
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
