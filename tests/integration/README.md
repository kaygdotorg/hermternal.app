# Integration proof fixtures

This index contains offline, synthetic integration-boundary fixtures. They
validate generated artifacts and keep live execution in an explicitly approved
VM lane.

- [`hermes-disposable/`](hermes-disposable/README.md) — R-02A's isolated
  Hermes Compose renderer, bounded validator, executor policy, and redacted
  benchmark evidence.

These fixtures do not contact Hermes, providers, browsers, PTY endpoints,
proxies, identity services, or production deployments.
