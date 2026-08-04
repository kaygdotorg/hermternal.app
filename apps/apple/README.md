# Apple clients

This directory will contain native SwiftUI clients for iOS and iPadOS. The same architecture will support macOS after the shared interaction model is proven.

The planned stack is Swift 6, SwiftUI, Observation, async/await, URLSession, URLSessionWebSocketTask, ASWebAuthenticationSession, Keychain Services, Swift Testing, and focused XCTest UI tests.

Future package boundaries should separate dashboard transport, authentication, session state, persistence, and platform UI. These implementations remain native even when they follow shared contracts and test fixtures.

No Xcode project, Swift package, signing configuration, credential, or live Hermes call exists here yet.
