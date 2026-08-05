# PTY attach source audit and fixtures

**Status:** normative planning evidence for `dashboard-v0.0.1`
**Surface:** web-only `/api/pty`
**Pinned Hermes revision:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`

## Purpose

This fixture set freezes the source-correct lifecycle split that clients must not blur:

- a missing or empty `attach` value selects the legacy one-socket/one-PTY path; a socket disconnect closes the bridge and terminates the child;
- a previously accepted, exact opaque attach handle selects the keep-alive registry; socket loss detaches only the socket, and the same handle may reattach while the session is retained;
- retained output is a bounded byte buffer, not a transcript and not an ordered replay snapshot; retained and live frames may race;
- user input, resize controls, prompt submissions, and tool actions are not retained as replayable actions and must never be replayed; prompt and tool output bytes are PTY output and may appear in the retained buffer;
- malformed or expired handles fail closed before opening `/api/pty`; they must not fall back to legacy mode or silently create a replacement PTY;
- a superseded socket receives `4409`, stops reading, and cannot detach or retry the replacement socket.

The pinned source accepts any non-empty query value as a registry key and does not expose a client-visible handle grammar or expiry rejection. The fail-closed fixture cases are therefore an Hermternal client/proof guard. They prevent an unrecognized value from becoming a new registry key, including after the source reaps an expired detached entry.

No Hermes code is vendored or executed by this repository. All fixture identifiers, handles, bytes, process references, and input references are synthetic. This artifact does not create a transcript mirror or contain credentials, cookies, tickets, token fragments, hostnames, or user data.

## Audit evidence

`source-evidence.json` records the immutable source URL, Git blob SHA, full-file SHA-256, and selected line-range hashes for the exact three-file audit set:

- `hermes_cli/web_server.py`: the legacy pump and the `attach` presence split;
- `hermes_cli/pty_session.py`: bounded output, attach/detach, supersession, and expiry reaping;
- `hermes_cli/pty_bridge.py`: direct input writes and child termination on bridge close.

The standard-library validator rejects duplicate or omitted audited files and binds every observation range to one of the recorded file/range pairs. It also rejects an observation that points at a syntactically valid but unaudited source range. The recorded observations explain the contract guard where the pinned implementation is permissive. A later Hermes revision requires a new source audit; matching only the route name is not compatibility evidence.

## Fixtures

`pty-attach-fixtures.json` is a deterministic, language-neutral set with these cases:

| Fixture | Proof |
| --- | --- |
| `missing-attach-selects-legacy` | Missing attach is not an implicit keep-alive request. |
| `legacy-disconnect-terminates` | Legacy disconnect closes the bridge, exits the PTY, and prohibits reattach. |
| `attach-detach-reattach` | One valid handle preserves the PTY identity across detach and reattach. |
| `malformed-attach-fails-closed` | Malformed input is rejected before any socket accept, upgrade, route activity, or spawn. |
| `expired-attach-fails-closed` | A reaped handle is rejected before the source can spawn a fresh PTY for its old key. |
| `superseded-socket-fails-closed` | `4409` is bound to the stale socket after the replacement attaches, without detaching the replacement. |
| `retained-output-race` | Both retained/live receive orders are allowed; the client renders receive order without a replay boundary. |
| `retained-output-truncation` | The newest 1 MiB is bounded and older output may be absent. |
| `no-input-replay` | Reattach may send retained PTY output, including prompt/tool output bytes; no prior user input, resize control, prompt submission, or tool action is replayed. |

## Narrow validation

The validator uses only Python's standard library and performs no network request and no Hermes operation.

```text
python3 contracts/fixtures/source-audit/pty-attach/validate.py
```

For a source checkout that has been independently fetched at the pinned revision, the optional audit mode verifies full-file hashes, Git blob hashes, line-range hashes, and markers:

```text
python3 contracts/fixtures/source-audit/pty-attach/validate.py \
  --source-root /path/to/hermes-agent
```

A one-run baseline records fixture artifact size and validation duration without inventing a budget threshold:

```text
python3 contracts/fixtures/source-audit/pty-attach/validate.py \
  --baseline-output contracts/fixtures/source-audit/pty-attach/validation-baseline.json
```

The validator also runs twelve in-process mutation checks: duplicate or omitted source files, an observation bound to an unaudited range, changed session identity, unsafe `payload_ref`, extra or nested input/tool-action snapshot fields, malformed-route activity, and incorrect supersession binding/order must each fail validation. The baseline measures the checked-in audit/fixture artifacts listed by `validate.py`; its duration is environment evidence, not a pass threshold. The command exits non-zero on schema drift, missing required cases, changed source fingerprints, unsafe replay expectations, or redaction violations.

## Scope notes

This is protocol and source-audit work, so Paper evidence is `N/A`: no user-facing board or runtime UI changes are made here. Later web Terminal clients must render the separate legacy `exited`, keep-alive `detached`, `reattaching`, failure, and superseded outcomes without promising reattachment for legacy sockets. Apple clients do not invoke `/api/pty`.
