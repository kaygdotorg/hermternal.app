# Hermternal

Hermternal is an open-source web and Apple client for Hermes Agent.

## Current phase

This repository is in the planning, mock, and proof phase. Paper is the visual source of truth. The proof gates must pass before application scaffolding or live Hermes integration starts:

1. Paper states and responsive layouts.
2. Protocol, security, and deployment evidence.
3. A performance baseline and agreed budgets.

No current code connects to Hermes, stores production credentials, or reads live user data.

## Product milestone

`v0.0.1` is the first planned product milestone. It is not a git release tag. Release tags use `vYYYY.MM.DD.<patch-num>` after a verified `dev` commit is promoted to `main`.

## Planned clients

- `apps/web/` will contain a static web client built with Svelte 5, SvelteKit 2, and Bun.
- `apps/apple/` will contain native SwiftUI chat clients for iOS, iPadOS, and macOS.

The web and Apple clients share protocol contracts, redacted fixtures, state definitions, test scenarios, and semantic design-token names. They do not share UI, authentication, networking, persistence, lifecycle, or accessibility implementations.

## v0.0.1 boundary

The future milestone is a focused chat client:

- one profile;
- provider-neutral discovery;
- session creation, restoration, prompts, streaming, interruption, approvals, and clarification;
- images only for attachments;
- an active model switch that applies now while idle; a normal streaming choice may defer to the next turn, while an expensive choice may require confirmation and resubmission after the turn;
- private deep links under `/v1/c/...`; and
- the full `/api/pty` Terminal on the web only.

The client does not provide a transcript mirror. It does not add terminal-read, sudo, or secret operations. Sharing starts in `v0.0.2`.

The supported Hermes revision is pinned to `f5be9236e00ddf2f2a412697f267078fc4ee068e`. The pinned Dashboard does not report its source revision. Missing or mismatched deployment attestation, or a failed behavioral probe, blocks live operation.

## Authentication and deployment boundary

- Browser authentication uses server-issued HttpOnly cookies. Reusable Hermes credentials must not enter browser storage.
- Native authentication may use the discovered username/password provider with an isolated `URLSession` cookie store and WebSocket tickets.
- Native OAuth/OIDC is supported only when the provider's reviewed callback transport is accepted by the pinned Hermes route and proven on the target Apple platform. An unsupported transport is blocked. There is no approved upstream change or hidden workaround.
- Caddy and Traefik are equal supported proxy choices.
- Hermes uses a fixed private, non-loopback bind on `:9119` and a firewall. The service must not be public.

See the focused plans for [product](docs/product/README.md), [protocol](docs/protocol/README.md), [architecture](docs/architecture/README.md), [security](docs/security/README.md), [deployment](docs/deployment/README.md), and [shared contracts](contracts/README.md).

## Repository map

| Path | Purpose |
| --- | --- |
| `apps/` | Platform-owned client implementations. |
| `contracts/` | Language-neutral Dashboard contracts, fixtures, state models, design tokens, and shared benchmark evidence. |
| `docs/` | Product, architecture, protocol, security, and deployment decisions. |
| `prototypes/` | Paper and coded prototype boundaries. |
| `scripts/` | Future deterministic contract, token, and proof checks. |

All current data and interactions are plans, specifications, or mock fixtures. Nothing in this repository currently connects to Hermes or reads live user data.

## Branches

- `dev` is the integration branch for planning and development work.
- `main` contains only verified, release-ready builds promoted from `dev`.

`CLAUDE.md` must remain a relative symlink to `AGENTS.md`. See [`AGENTS.md`](AGENTS.md) for the complete project rules.

## License

Hermternal is licensed under the [GNU General Public License v2.0](LICENSE).
