# Web Paper artboard manifest

`artboards.json` is the v0.0.1 web evidence map for the approved Hermternal Paper file. It is a planning contract and review artifact, not generated application code.

## Source and scope

- Paper file: `01KZ6BB66KCWR2C4J2TSWQGDM7` (`Hermternal`)
- Authentication page: `3-0`, `Web states — Authentication`, 34 artboards
- Runtime page: `4-0`, `Web states — Runtime`, 68 artboards
- Token snapshot: `cb15f2b1`
- Platform: web
- Contract: `dashboard-v0.0.1`
- Variants, in order: `light.desktop`, `light.narrow`, `dark.desktop`, `dark.narrow`
- Runtime desktop: `1440 × 960`
- Authentication desktop: `1440 × 900`
- Narrow: `390 × 844`

All 102 artboards from the two approved pages are represented exactly once. The manifest does not infer missing Paper evidence.

## Evidence status

- `ready` means all four light/dark desktop/narrow variants are present and mapped exactly.
- `blocked` means the state is relevant to v0.0.1 but one or more required variants are absent. The missing variant IDs are listed in `missing_variants`.
- `deferred` means the UI family is retained as Paper reference evidence but excluded from v0.0.1 and targeted to v0.0.2.

Private deep-link and Session Search records are deferred. They must not be treated as shipped v0.0.1 UI. No record is a production authentication, Hermes gateway, provider, or live-data claim.

## Validation

The validator uses only the Python standard library and fails closed for:

- duplicate JSON keys, unknown keys, malformed JSON, unsafe input bounds, and non-finite numbers;
- unknown, duplicate, reordered, renamed, or dimension-shifted Paper records;
- duplicate or missing variants;
- unknown, duplicate, reordered, renamed, or value-shifted tokens;
- ready states with incomplete coverage;
- blocked states without explicit missing variants; and
- deferred states that do not target v0.0.2.

Run both interpreter modes and the focused tests from the repository root:

```sh
python3 contracts/design-tokens/web/validate.py
python3 -O contracts/design-tokens/web/validate.py
python3 contracts/design-tokens/web/test_validate.py
python3 -O contracts/design-tokens/web/test_validate.py
```

The validator is offline. It does not open Paper, call Hermes, contact a provider, perform authentication, or read live user data.
