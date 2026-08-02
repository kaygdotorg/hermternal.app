# Hermternal web conversation mockup

This directory is a high-fidelity, web-only interaction prototype for Hermternal. Open `index.html` directly or serve the directory with:

```sh
python -m http.server 8000
```

Then visit `http://localhost:8000`. No build step, package install, account, or network connection is required.

## What is mocked

Every conversation, attachment, model, tool event, connectivity indicator, profile, voice recording, and send result is static or locally simulated. The prototype makes no API calls and contains no authentication, backend, persistence, analytics, live data, deployment configuration, or Hermes gateway integration. Refresh restores the default appearance and content.

## Design system and stances

The interface uses one semantic material system across the floating navigation, conversation chrome, menus, and composer: translucent surfaces, a bright edge, soft depth, and background blur. CSS custom properties keep color, material, shadow, radii, spacing, and motion coherent.

Eight themes provide different material moods, not only accent changes: Tahoe light and dark are luminous and atmospheric; graphite is neutral and low-chroma; ocean, ember, forest, and lavender tint both the environment and glass; high-contrast removes decorative shadow and uses solid black, white, and yellow.

Three selectable stances change hierarchy and rhythm:

- **Calm editorial** uses generous whitespace, serif conversation copy, and a balanced reading width.
- **Focused command** increases information density, uses sans-serif content, squares surfaces, and emphasizes tool activity.
- **Warm studio** narrows the conversation, increases conversational spacing, rounds avatars, and turns quotations into soft cards.

## Interaction and motion

Desktop navigation floats persistently. At tablet and mobile widths it moves off-canvas, opened from a 44px menu control and dismissed by its close control, backdrop, or Escape. Model, theme, stance, attachment, expanded-writing, voice-note, and send states are all interactive. Pointer-capable devices receive a restrained lift on key controls; touch devices do not. Motion uses short, interruptible transforms and opacity changes. `prefers-reduced-motion` removes transitions and animated streaming decoration.

## Accessibility

The document uses semantic landmarks, headings, navigation, articles, forms, labels, and fieldsets. Controls meet a 44px minimum target where used in the primary interface, expose state through accessible names and `aria-expanded`/`aria-pressed` where needed, and have high-visibility `:focus-visible` treatment. Escape closes layered controls. Status changes are announced through polite live regions. The layout is designed for browser zoom and reflows from desktop through tablet to 320px narrow web.

The high-contrast theme provides the strongest contrast option. Theme-specific visual contrast should still be validated with production tooling before any design is adopted. The off-canvas navigation makes background content inert while open and loops keyboard focus inside the drawer.

## Performance choices

There are no external assets, fonts, frameworks, runtime dependencies, polling loops, or network requests. Icons are inline SVG, theme changes update root custom properties, and animation is limited to compositor-friendly transforms/opacity plus tiny status indicators. Blur has an opaque fallback for unsupported browsers. The voice timer exists only while its mock recording state is active.

## Intentional limitations

This is not production UI. Data does not persist, controls do not reach services or the file system, tool progress never resolves, streaming text is prewritten, and the model choices are fictional prototype fixtures. Empty, failure, attachment, streaming, loading, and connected states are represented visually for design evaluation; they are not connected to application logic.
