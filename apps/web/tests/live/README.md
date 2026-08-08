# Official Hermes browser proof

This lane serves the production static build and proxies only `/api/*`, `/auth/*`, and the `/api/ws` WebSocket upgrade to a disposable local HTTP target. `HERMES_LIVE_TARGET` is accepted only as a plain HTTP loopback URL: canonical IPv4 in `127.0.0.0/8`, `[::1]`, or `localhost`, with an optional unambiguous decimal port and an optional root slash. The default target is `http://127.0.0.1:19131`, which is the disposable SSH tunnel to the official Hermes container. Hermes and its Dashboard stay on the VM loopback interface.

The host rejects HTTPS, userinfo, non-loopback names, IPv4-mapped IPv6, decimal/octal/short IPv4 encodings, percent-encoded or backslash-containing authorities, ambiguous ports, and any path, query, or fragment before creating the proxy-capable server. This validation is the disposable proof boundary; it prevents auth traffic from being sent to a target that URL parsing could reinterpret.

The host is test-only. It is not a deployment server and does not add authentication, retries, transcript storage, or response logging. The Playwright configuration disables traces because live password values must not enter retained artifacts. The spec records only HTTP method/path pairs and JSON-RPC method or event names. It never records the WebSocket ticket, credential value, prompt response, cookie, or raw frame payload.

Run the lane only against the authorized disposable VM. Use `scripts/with_live_credential.py` at the local read boundary:

```sh
python3 scripts/with_live_credential.py /path/from/credential_file -- \
  bun run test:e2e:live
```

The helper strips only trailing CR/LF, validates exactly 48 lowercase hexadecimal characters, and passes the value only as transient `HERMES_TEST_PASSWORD` child-process environment state. It never prints or writes the password, and invalid input fails before Playwright starts. Do not place it in a command argument, repository file, fixture, report, or terminal output. The default Vitest, Playwright, no-network, and static lanes do not execute this live proof; the live Playwright configuration is an explicit opt-in.

The implementation supports provider discovery, password login, `/api/auth/me`, session and message reads, one fresh ticket, the native WebSocket upgrade, server-first `gateway.ready`, `session.resume` or fresh `session.create`, one `prompt.submit`, streaming, completion, REST history reconciliation, and no automatic prompt replay. The executed authorized live proof reached authentication, ticket acquisition, `/api/ws`, `gateway.ready`, session restoration/creation, and `prompt.submit`. The disposable instance had no authenticated inference provider, so it stopped at the source `error` event before `message.delta`/`message.complete`; REST history reconciliation is therefore unproven. These live claims are not mocked, and no completion, delta, or history result is claimed. A source `error` event is recorded only by event name and never retains its payload.

A visible logout action is not part of the current approved Paper workspace. The live spec still verifies the reviewed same-origin logout boundary as raw `302 Location: /login`, then verifies the follow-up `/api/auth/me` `401`, without inventing an unapproved UI control. Add a visible action to this journey only after the matching Paper state is approved.
