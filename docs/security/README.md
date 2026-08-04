# Security model

The planned web deployment places Hermternal and Hermes Dashboard behind one HTTPS origin. Hermes remains bound to loopback. Browser login uses the Dashboard OAuth or OIDC flow. Hermes creates secure server-issued session cookies. Hermternal must not store a password or reusable Hermes credential in browser storage.

The native Apple client will use system authentication sessions and Keychain Services for approved credential material.

Hermternal will use supported Hermes routes. It will not expose or directly read `~/.hermes`. It will not use SSH as a client transport. Proxy configuration must never publish Hermes state directories or secrets.

This document is a planning boundary. It is not production security configuration.
