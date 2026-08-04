# Shared contracts

This directory holds language-neutral artifacts that keep the web and Apple clients behaviorally aligned.

Shared artifacts include protocol vocabulary, compatibility records, redacted fixtures, state transitions, test scenarios, and semantic design-token names. Platform code must consume these artifacts without sharing UI, networking, authentication, persistence, or lifecycle implementations.

Contract artifacts must never contain credentials, live transcripts, provider data, or other user data.
