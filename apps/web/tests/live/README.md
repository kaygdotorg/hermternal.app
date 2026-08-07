# Official Hermes browser proof

This lane serves the production static build and proxies only `/api/*`, `/auth/*`, and the `/api/ws` WebSocket upgrade to a local HTTP target. The default target is `http://127.0.0.1:19131`, which is the disposable SSH tunnel to the official Hermes container. Hermes and its Dashboard stay on the VM loopback interface.

The host is test-only. It is not a deployment server and does not add authentication, retries, transcript storage, or response logging. The Playwright configuration disables traces because live password values must not enter retained artifacts. The spec records only HTTP method/path pairs and JSON-RPC method or event names. It never records the WebSocket ticket, credential value, prompt response, cookie, or raw frame payload.

Run the lane only against the authorized disposable VM. Supply the synthetic credential through `HERMES_TEST_PASSWORD` in the test process environment. Do not place it in a command argument, repository file, fixture, report, or terminal output.

The proof requires an available inference provider. On a fresh disposable instance, the Paper-backed **New chat** action sends one `session.create` and uses the returned ephemeral ID for the first prompt; an existing durable session instead uses `session.resume`. The lane verifies provider discovery, password login, `/api/auth/me`, session and message reads when durable history exists, one fresh ticket, the native WebSocket upgrade, server-first `gateway.ready`, one `prompt.submit`, streaming, completion, REST history reconciliation, and no automatic prompt replay. A source `error` event is recorded only by event name and fails immediately without retaining its payload.

A visible logout action is not part of the current approved Paper workspace. The live spec still verifies the reviewed same-origin logout boundary as raw `302 Location: /login`, then verifies the follow-up `/api/auth/me` `401`, without inventing an unapproved UI control. Add a visible action to this journey only after the matching Paper state is approved.
