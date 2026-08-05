# Design tokens

This directory will define semantic names for color, typography, spacing, radius, elevation, motion, and interaction states.

Paper is the visual source of truth. Define the resting, hover, pressed, focused, selected, expanded, loading, empty, success, and failure states in Paper before application code. Keep token names stable across the static Svelte web client and native SwiftUI clients, while allowing platform adaptations for browser zoom, Dynamic Type, contrast, reduced motion, and reduced transparency.

Shared compact controls use the same pill intent and full capsule radius. Preserve an effective 44 by 44 CSS-pixel target for web touch and hybrid layouts, keep icon and label groups optically centered, and retain a visible label and state for keyboard focus and assistive technology. Motion proofs must be interruptible and have a reduced-motion alternative.

Token work follows the proof order: Paper first, then accessibility and performance checks, then generated platform values. Do not claim a performance benefit before measuring the baseline.

No generated token output exists here yet. Future web and SwiftUI values must not contain credentials, live data, provider-specific behavior, or platform UI code.
