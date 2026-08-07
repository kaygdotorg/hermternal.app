# Design tokens

This directory defines semantic names for color, typography, spacing, radius, elevation, motion, and interaction states.

Paper is the visual source of truth. Define the resting, hover, pressed, focused, selected, expanded, loading, empty, success, and failure states in Paper before application code. Keep token names stable across the static Svelte web client and native SwiftUI clients, while allowing platform adaptations for browser zoom, Dynamic Type, contrast, reduced motion, and reduced transparency.

Shared compact controls use the same pill intent and full capsule radius. Preserve an effective 44 by 44 CSS-pixel target for web touch and hybrid layouts, keep icon and label groups optically centered, and retain a visible label and state for keyboard focus and assistive technology. Motion proofs must be interruptible and have a reduced-motion alternative.

Token work follows the proof order: Paper first, then accessibility and performance checks, then generated platform values. Do not claim a performance benefit before measuring the baseline.

## Web Paper evidence

[`web/artboards.json`](web/artboards.json) is the checked-in, machine-readable map from the approved Paper file to the web UI states in the `dashboard-v0.0.1` contract. It records exact Paper file and page metadata, artboard IDs and names, `1440 × 960` Runtime/workspace or `1440 × 900` Authentication/standalone Terminal desktop dimensions, `390 × 844` narrow dimensions, light/dark variant order, shipped token values, the current 84-record Paper token snapshot (`b5b2b8c5`), and evidence status.

The generic map covers 102 Paper artboards in 29 state records:

- 15 four-variant states are `ready` for v0.0.1.
- 7 Authentication groups are `blocked` because Paper is missing desktop or narrow variants.
- 7 deep-link or Session Search groups are `deferred` to v0.0.2.

The nested Terminal evidence map covers 78 Paper artboards in 15 records:

- 11 lifecycle states cover fresh through explicitly-closed Terminal sessions.
- 1 reference record retains existing light narrow references without claiming complete coverage.
- 1 selector record covers resting, hover, focused, pressed, selected, and keyboard states.
- 1 accessibility record covers focus, zoom, text growth, reduced motion/transparency, forced colors, localization growth, touch targets, and focus order.
- 1 continuity record covers the static Chat → Terminal → Chat → Terminal sequence.
- `paper_static_only` is `true`; Paper is static evidence and does not prove runtime interaction or implementation behavior.

Run the standard-library-only validator from the repository root:

```sh
python3 contracts/design-tokens/web/validate.py
python3 -O contracts/design-tokens/web/validate.py
python3 contracts/design-tokens/web/test_validate.py
python3 -O contracts/design-tokens/web/test_validate.py
```

`validate.py` is an offline contract check. It does not open Paper, call Hermes, perform authentication, contact a provider, or claim a production integration. It rejects duplicate JSON keys, unknown or reordered records, duplicate or missing variants, token drift, malformed values, and oversized or excessively deep input.

Future web and SwiftUI values must not contain credentials, live data, provider-specific behavior, or platform UI code.
