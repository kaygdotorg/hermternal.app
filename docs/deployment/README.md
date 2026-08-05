# Deployment topology

## Status

This directory contains deployment planning and proof requirements only. It has no deployable proxy, certificate, hostname, secret, or production configuration.

## Target topology

The supported self-hosted layout uses one HTTPS origin:

- `/` serves the static Hermternal web client;
- the Dashboard routes serve chat, auth, and WebSocket traffic; and
- the web-only full `/api/pty` Terminal is routed through the same protected deployment boundary.

Caddy and Traefik are equal supported proxy choices. Either must terminate HTTPS, serve the static client, preserve WebSocket upgrades, and forward the required host, scheme, and prefix information.

Hermes uses a fixed private, non-loopback bind on `:9119`. A firewall must restrict access to the approved private path. The bind must not be public and must not move between proof runs.

## Auth and compatibility

Browser sessions use protected server-issued HttpOnly cookies. Native clients may use the discovered username/password provider with an isolated `URLSession` cookie store and WebSocket tickets; they do not reuse browser cookies. Native OAuth/OIDC is allowed only when the callback transport is accepted by the pinned Hermes native route and target-platform proof passes. It is blocked when either condition is absent or fails. No upstream change is approved.

The supported Hermes revision is `f5be9236e00ddf2f2a412697f267078fc4ee068e`. Missing or mismatched deployment attestation, or a failed behavioral probe, blocks live operation. Private deep links use `/v1/c/...`; sharing is deferred to `v0.0.2`.

## Proof matrix

Before application or live integration, prove both proxy choices for HTTPS, HttpOnly cookies, WebSocket upgrades, private `:9119` reachability, firewall behavior, and the web-only `/api/pty` path. Also prove that missing or mismatched revision attestation and failed behavioral evidence block operation. Measure the performance baseline before setting optimization claims.

See the [security model](../security/README.md), [protocol plan](../protocol/README.md), and [architecture plan](../architecture/README.md).
