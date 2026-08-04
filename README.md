# Hermternal

Hermternal is an open-source web and Apple client for Hermes Agent.

This repository is in the planning and high-fidelity prototype phase. It does not contain a live Hermes integration, production authentication, deployment configuration, or application build scaffold. Current visual exploration happens in Paper.

## Planned clients

- `apps/web/` will contain a static TypeScript client built with Svelte 5, SvelteKit 2, Vite, Bun, and `@sveltejs/adapter-static`.
- `apps/apple/` will contain native SwiftUI clients for iOS and iPadOS. The same Apple architecture will later support macOS.

The web and Apple clients will share protocol contracts, redacted fixtures, state definitions, test scenarios, and semantic design-token names. They will not share UI, authentication, networking, persistence, lifecycle, or accessibility implementations.

## Repository map

| Path | Purpose |
| --- | --- |
| `apps/` | Platform-owned client implementations. |
| `contracts/` | Language-neutral Hermes Dashboard contracts, fixtures, state models, and design tokens. |
| `docs/` | Product, architecture, protocol, security, and deployment decisions. |
| `prototypes/` | Notes about prototype sources and their mocked boundaries. |
| `scripts/` | Future contract-generation and parity-check tools. |

## Product boundary

Hermternal v0.0.1 is planned as the first live chat client. It will use the Hermes Dashboard HTTPS, authentication, and WebSocket surfaces. SSH, PTY/TUI access, dashboard administration, terminal backend selection, and direct access to `~/.hermes` are outside the client scope.

All present data and interactions are plans, specifications, or mock fixtures. Nothing in this repository currently connects to Hermes or reads live user data.

## Branches

- `dev` is the integration branch for all planning and development work.
- `main` contains only verified, release-ready builds promoted from `dev`.

See [`AGENTS.md`](AGENTS.md) for the complete project rules.

## License

Hermternal is licensed under the [GNU General Public License v2.0](LICENSE).
