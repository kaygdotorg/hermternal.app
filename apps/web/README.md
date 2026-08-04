# Web client

This directory will contain the static Hermternal web client.

The selected stack is TypeScript, Svelte 5, SvelteKit 2, Vite, Bun, and `@sveltejs/adapter-static`. The client will use semantic CSS variables and component-scoped CSS. It will remain a static application. Caddy or nginx will provide HTTPS and route the Hermes Dashboard under the same public origin.

No package manifest, dependency, build configuration, authentication flow, or live Hermes call exists here yet.
