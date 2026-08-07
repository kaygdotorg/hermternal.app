# Integration proof fixtures

This index contains offline, synthetic integration-boundary fixtures. They
validate generated artifacts and keep live execution in an explicitly approved
VM lane.

- [`hermes-disposable/`](hermes-disposable/README.md) — R-02A's isolated
  Hermes Compose renderer, bounded validator, executor policy, and redacted
  benchmark evidence.
- [`hermes-caddy/`](hermes-caddy/README.md) — issue #156's redacted Caddy
  edge/upstream status evidence, digest bindings, and blocked-provider result.

These fixtures do not contact Hermes, providers, browsers, PTY endpoints,
proxies, identity services, or production deployments during offline
validation. The separate Caddy evidence was collected only through the
authorized disposable VM lane.
