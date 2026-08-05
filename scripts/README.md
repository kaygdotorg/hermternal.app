# Scripts

This directory is reserved for small, deterministic repository tools. No executable script or tool dependency exists here yet.

Future scripts may generate web and SwiftUI token values, validate the pinned Hermes revision, check contract and fixture coverage, compare web/Apple parity, and record Paper, deployment, accessibility, and performance proof results.

Scripts must not contact live Hermes services by default. They must not read or emit credentials, cookies, WebSocket tickets, live transcripts, provider data, secrets, hostnames, or user data. Missing or mismatched Hermes revision attestation, and failed behavioral probes, must fail closed and block live-operation checks.

Keep the product milestone `v0.0.1` separate from date-based git tags `vYYYY.MM.DD.<patch-num>`.
