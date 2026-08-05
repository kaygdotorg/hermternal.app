# Security model

## Status

This is a planning boundary. It is not production security configuration. All current credentials, sessions, and user data are synthetic or absent.

## Authentication

- Browser login uses server-issued HttpOnly cookies. Do not store reusable Hermes credentials in browser-readable storage.
- Native clients may use the discovered username/password provider with an isolated `URLSession` cookie store and WebSocket tickets. Browser cookies must never be shared with native code.
- Native OAuth/OIDC is supported only when the configured provider's reviewed callback transport is accepted by Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e` and proven on the target Apple platform. An unsupported or unproven transport is blocked. There is no approved upstream change, so clients must not add a hidden workaround.

## Service boundary

Hermes must use a fixed private, non-loopback bind on `:9119` protected by a firewall. It must not be published as a public service. Caddy and Traefik are equal supported front proxies and must preserve HTTPS, cookie, and WebSocket behavior.

The web client may use the full `/api/pty` Terminal. No client adds terminal-read, sudo, or secret operations. The client does not maintain a transcript mirror. Attachments are images only, and sharing is deferred to `v0.0.2`.

## Data and compatibility

Discovery remains provider-neutral. The supported Hermes revision is pinned to `f5be9236e00ddf2f2a412697f267078fc4ee068e`. The pinned Dashboard does not report its revision. Missing or mismatched out-of-band deployment attestation, or a failed behavioral probe, blocks live operation. Private deep links use `/v1/c/...`; they are not a sharing feature.

Contract fixtures must use synthetic, redacted data. Never commit passwords, username/password provider credentials, cookies, WebSocket tickets, tokens, live transcripts, hostnames, secrets, or user data.

Paper, protocol, security, deployment, and performance proofs must pass before application or live integration work. See the [Dashboard contract](../../contracts/hermes-dashboard/README.md) and [deployment plan](../deployment/README.md).
