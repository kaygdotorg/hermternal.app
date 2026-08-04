# Architecture

Hermternal has two first-class client implementations and one shared specification layer.

- The web client is a static Svelte application.
- The Apple client is a native SwiftUI application.
- The contract layer defines compatible behavior and test evidence.

Share contracts, fixtures, state specifications, test scenarios, and design-token names. Keep UI, networking, authentication, persistence, navigation, lifecycle, gestures, motion, and accessibility code platform-native.

This boundary avoids WASM, Swift FFI, cross-language async bridges, and shared-UI compromises in v0.0.1.
