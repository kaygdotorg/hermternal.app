# Official Hermes browser proof

This lane serves the production static build and proxies only `/api/*`, `/auth/*`, and the `/api/ws` WebSocket upgrade to a local HTTP target. The default target is `http://127.0.0.1:19131`, which is the disposable SSH tunnel to the official Hermes container. Hermes and its Dashboard stay on the VM loopback interface.

The host is test-only. It is not a deployment server and does not add authentication, retries, transcript storage, or response logging. The Playwright configuration disables traces because live password values must not enter retained artifacts. The spec records only HTTP method/path pairs and JSON-RPC method or event names. It never records the WebSocket ticket, credential value, prompt response, cookie, or raw frame payload.

Run the lane only against the authorized disposable VM. Supply the synthetic credential through `HERMES_TEST_PASSWORD` in the test process environment. Do not place it in a command argument, repository file, fixture, report, or terminal output.

The proof requires one existing disposable Hermes session and an available inference provider. It verifies provider discovery, password login, `/api/auth/me`, session and message reads, one fresh ticket, the native WebSocket upgrade, server-first `gateway.ready`, `session.resume`, one `prompt.submit`, streaming, completion, and no automatic prompt replay.

A visible logout action is not part of the current approved Paper workspace. Logout remains covered at the browser-auth boundary, but it must be added to this full UI journey only after the matching Paper state is approved.
