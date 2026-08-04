# Deployment topology

The preferred self-hosted layout uses one HTTPS origin:

- `https://agent.example.com/` serves the static Hermternal web client.
- `https://agent.example.com/hermes/` proxies to Hermes Dashboard on loopback.
- Dashboard REST, login, callback, and WebSocket routes remain under `/hermes/`.

Caddy or nginx will terminate HTTPS, serve static files, preserve WebSocket upgrades, and forward the required host, scheme, and prefix information. Hermes should remain private on `127.0.0.1:9119`.

This directory contains deployment planning only. It does not contain a deployable proxy, certificate, hostname, secret, or production configuration.
