# Web Paper artboard manifest

`artboards.json` is the v0.0.1 web evidence map for the approved Hermternal Paper file. It is a planning contract and review artifact, not generated application code.

## Source and scope

- Paper file: `01KZ6BB66KCWR2C4J2TSWQGDM7` (`Hermternal`)
- Chat workspace page: `A-0`, `Chat workspace`, 34 artboards
- Authentication page: `C-0`, `Authentication`, 48 artboards
- Runtime page: `D-0`, `Runtime and recovery`, 40 artboards
- Shared Chat–Terminal workspace page: `B-0`, 25 artboards
- Terminal desktop lifecycle page: `E-0`, 22 artboards
- Terminal narrow and mobile page: `F-0`, 28 artboards
- Accessibility page: `G-0`, 3 artboards
- Paper token snapshot: `b5b2b8c5` (84 exact name/value records)
- Platform: web
- Contract: `dashboard-v0.0.1`
- Variants, in order: `light.desktop`, `light.narrow`, `dark.desktop`, `dark.narrow`
- Runtime desktop: `1440 × 960`
- Authentication and standalone Terminal desktop: `1440 × 900`
- Narrow: `390 × 844`

The generic inventory represents 120 artboards in 30 state records. The nested Terminal evidence inventory represents 78 artboards in 15 lifecycle, selector, accessibility, and continuity records. Every registered record is matched to the approved Paper snapshot; the manifest does not infer missing Paper evidence. The legacy `3-0` (`Web states — Authentication`) and `4-0` (`Web states — Runtime`) pages are empty and are not claimed as populated evidence sources.

## Evidence status

- `ready` means all four light/dark desktop/narrow variants are present and mapped exactly.
- `blocked` means the state is relevant to v0.0.1 but one or more required variants are absent. The missing variant IDs are listed in `missing_variants`.
- `deferred` means the UI family is retained as Paper reference evidence but excluded from v0.0.1 and targeted to v0.0.2.

All 12 registered Authentication families now have complete four-variant Paper coverage. Private deep-link and Session Search records are deferred. They must not be treated as shipped v0.0.1 UI. No record is a production authentication, Hermes gateway, provider, or live-data claim.

Terminal evidence is complete for the approved static Paper snapshot:

- Lifecycle records cover fresh, open, connecting, detached, replaying, retained-output-truncated, reconnecting, superseded, ended, failed, and explicitly-closed states.
- Selector evidence covers resting, hover, focused, pressed, selected, and keyboard sheets across light/dark desktop/narrow boards.
- Accessibility evidence records keyboard focus, dark/narrow focus, zoom and text growth, reduced motion/transparency, forced colors, localization growth, touch targets, and focus order.
- Continuity evidence records the static Chat → Terminal → Chat → Terminal sequence.
- `paper_static_only` is `true`: Paper boards are static evidence and do not prove runtime keyboard behavior, authentication behavior, focus transfer, motion, continuity, or error recovery.

## Validation

The validator uses only the Python standard library and fails closed for:

- duplicate JSON keys, unknown keys, malformed JSON, unsafe input bounds, and non-finite numbers;
- unknown, duplicate, reordered, renamed, or dimension-shifted Paper records;
- duplicate or missing variants;
- unknown, duplicate, reordered, renamed, or value-shifted shipped tokens;
- stale or value-shifted Paper token snapshots;
- ready states with incomplete coverage;
- blocked states without explicit missing variants;
- deferred states that do not target v0.0.2; and
- missing, reordered, duplicated, renamed, dimension-shifted, or incomplete Terminal Paper pages, states, boards, and accessibility coverage.

Run both interpreter modes and the focused tests from the repository root:

```sh
python3 contracts/design-tokens/web/validate.py
python3 -O contracts/design-tokens/web/validate.py
python3 contracts/design-tokens/web/test_validate.py
python3 -O contracts/design-tokens/web/test_validate.py
```

The validator is offline. It does not open Paper, call Hermes, contact a provider, perform authentication, or read live user data.
