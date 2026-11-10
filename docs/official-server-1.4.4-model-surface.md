# Official ACP 1.4.4 model surface (live probe, 2026-11-11)

Evidence for how the official server authors model choice, and why the adapter
routes the two axes through two different JSON-RPC methods.

Probe conditions: the official 1.4.4 server, `initialize` + `session/new` +
`session/set_model` + `session/set_config_option` only. No `session/prompt`, no
inference, no credential read or print. Container lane, single account.

## What the server authors

One `session/new` response carries **two model axes with different contents**:

```text
configOptions[0]  id=model  category=model  currentValue=gemini-3.8-flash
                  values=[gemini-3.8-flash]
configOptions[1]  id=thinking_level  category=thought_level  currentValue=high
                  values=[low, medium, high]
configOptions[2]  id=mode  category=mode  currentValue=default
                  values=[default, auto_edit, yolo]

models.currentModelId = gemini-3.8-flash-high
models.availableModels = [
  {modelId: gemini-3.8-flash-high,   name: "Gemini 3.8 Flash (High)"},
  {modelId: gemini-3.8-flash-medium, name: "Gemini 3.8 Flash (Medium)"},
  {modelId: gemini-3.8-flash-low,    name: "Gemini 3.8 Flash (Low)"}
]
```

The axes are independent: the config group's current value is
`gemini-3.8-flash` while the legacy surface's `currentModelId` is
`gemini-3.8-flash-high`. The legacy rows are a live selection axis with their
own current id, not decoration for the config group.

## What the server accepts

| Request | Result |
| --- | --- |
| `session/set_model` `modelId=gemini-3.8-flash-high` | accepted, `result: {}` |
| `session/set_model` `modelId=gemini-3.8-flash-medium` | accepted, `result: {}` |
| `session/set_model` `modelId=gemini-3.8-flash-low` | accepted, `result: {}` |
| `session/set_config_option` `configId=model value=gemini-3.8-flash` | accepted, returns updated `configOptions` |

`session/set_model` is therefore the working method for legacy ids. The probe
records acceptance without a JSON-RPC error; it does not measure the resulting
thinking tier, which would require inference and is out of scope here.

## Adapter contract

1. Every model id the adapter lists comes from one of these two surfaces. No
   curated list, no plan- or tier-conditional branch, no model name in the
   plugin source.
2. Every listed id must resolve to a real request. A `configOptions` model
   value goes through `session/set_config_option` for the group that authored
   it; a legacy `models.availableModels` id goes through `session/set_model`.
3. An id neither surface authored is refused before sending — never
   force-sent, never silently substituted.
4. All model-category `configOptions` groups are read, not just the first, so a
   server that splits a second model family into its own group still reaches
   the picker.
5. When a server authors no model surface at all there is nothing to validate
   against; the legacy method is attempted and the caller judges the answer.

## Defect this closes

Before this contract, `_model_selection_request` returned early whenever a
`configOptions` model group existed, so legacy ids were never matched against
the surface that authored them. Against the surface above, three of the four
picker rows resolved to no request at all: selecting them sent nothing and left
the server default in place, silently. `tests/test_model_surface_selection.py`
pins the invariant (every listed id resolves) plus the two-surface,
two-group, and fail-closed cases.
