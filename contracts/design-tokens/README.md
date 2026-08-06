# Design tokens

This directory defines semantic names for color, typography, spacing, radius, elevation, motion, and interaction states.

Paper is the visual source of truth. Define the resting, hover, pressed, focused, selected, expanded, loading, empty, success, and failure states in Paper before application code. Keep token names stable across the static Svelte web client and native SwiftUI clients, while allowing platform adaptations for browser zoom, Dynamic Type, contrast, reduced motion, and reduced transparency.

Shared compact controls use the same pill intent and full capsule radius. Preserve an effective 44 by 44 CSS-pixel target for web touch and hybrid layouts, keep icon and label groups optically centered, and retain a visible label and state for keyboard focus and assistive technology. Motion proofs must be interruptible and have a reduced-motion alternative.

Token work follows the proof order: Paper first, then accessibility and performance checks, then generated platform values. Do not claim a performance benefit before measuring the baseline.

## Web Paper evidence

[`web/artboards.json`](web/artboards.json) is the checked-in, machine-readable map from the approved Paper file to the web UI states in the `dashboard-v0.0.1` contract. It records exact Paper file and page metadata, artboard IDs and names, `1440 × 960` Runtime or `1440 × 900` Authentication desktop dimensions, `390 × 844` narrow dimensions, light/dark variant order, token values, and evidence status.

The map currently covers 102 Paper artboards in 29 state records:

- 15 four-variant states are `ready` for v0.0.1.
- 7 Authentication groups are `blocked` because Paper is missing desktop or narrow variants.
- 7 deep-link or Session Search groups are `deferred` to v0.0.2.

Run the standard-library-only validator from the repository root:

```sh
python3 contracts/design-tokens/web/validate.py
python3 -O contracts/design-tokens/web/validate.py
python3 contracts/design-tokens/web/test_validate.py
python3 -O contracts/design-tokens/web/test_validate.py
```

`validate.py` is an offline contract check. It does not open Paper, call Hermes, perform authentication, contact a provider, or claim a production integration. It rejects duplicate JSON keys, unknown or reordered records, duplicate or missing variants, token drift, malformed values, and oversized or excessively deep input.

Future web and SwiftUI values must not contain credentials, live data, provider-specific behavior, or platform UI code.
