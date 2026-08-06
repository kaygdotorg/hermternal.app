# DEP-07M WebSocket-ticket boundary proof

**Issue:** #208
**Operation:** deterministic ticket acquisition, upgrade-only use, rejection, expiry, reuse, error-layer distinction, and redaction
**Contract:** `dashboard-v0.0.1`
**Pinned Hermes source:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`
**Status:** synthetic fixture and offline validator only

This directory is a no-egress security proof. It does not start Hermes, open a
socket, contact a provider, contact a proxy, create credentials, or contain a
real WebSocket ticket. A passing validator proves only that the checked-in
semantic fixture and observational baseline retain this reviewed contract. It
does not prove a live deployment or compatibility.

## Contract boundary

The source-backed boundary is intentionally narrow.

1. An authenticated browser or native session may call `POST /api/auth/ws-ticket`.
   The fixture records only an ephemeral ticket class. It never stores a cookie,
   bearer value, credential, or ticket value.
2. A fresh class is used only for the gated `GET WS /api/ws` upgrade query under
   the `ticket` key. The checked-in representation is the literal semantic class
   `synthetic_placeholder_only`, not a credential.
3. The cookie or bearer credential does not authenticate the upgrade directly.
   The ticket class is not a reusable REST credential. A ticket in a REST query
   or authorization header is denied at the client boundary and is not consumed.
4. Tickets are single-use and have the exact source-backed 30-second TTL. The
   fixture records age 29 as fresh and age 30 as expired. Missing, malformed,
   expired, and already-consumed classes are denied without fallback.
5. A denied or interrupted attempt does not blindly retry. Only an explicit
   idempotent local retry may reread the fixture and start one new acquisition
   attempt; duplicate activation while that attempt is active is a no-op.

The manifest and existing source-audit references are checked locally by the
validator. The issue-owned fixture does not duplicate the broader behavioral
probe. It references the existing ticket and edge/upstream cases only to keep
this security seam aligned with the approved contract. A pinned source-anchor
record also checks the `ticket[:8]` ellipsis fragment in
`hermes_cli/dashboard_auth/ws_tickets.py:90-95` and the forwarding audit-log
surface in `hermes_cli/web_server.py:14708-14716`. The source anchor independently
pins the `except TicketInvalid as exc`, `reason=str(exc),`, and
`path=ws.url.path,` lines with the reviewed source and blob hashes; it does not
rely only on the route-audit marker list. The consumed
`contracts/fixtures/route-allowlist/source_audit.json` is also checked against
its complete pinned byte size and SHA-256 before any claim, URL, or marker
metadata can authorize the source evidence. A changed route-audit artifact
fails closed even if its selected fields still look valid.

## Fixture inventory

`ticket-fixtures.json` has 24 deterministic cases:

- `pending`, `success`, `failure`, `interrupted`, and `retry` acquisition states;
- successful upgrade-query-only use;
- REST query and header rejection;
- missing, malformed, expired, reused, and exact-boundary ticket denial;
- history, log, and DOM redaction;
- separate bounded-fragment removal cases for history, logs, and DOM;
- separate edge-origin/edge-404 and upstream-auth/upstream-handler outcomes.

Edge and upstream results remain distinct:

| Layer | Synthetic outcomes | Upstream called |
| --- | --- | --- |
| `edge` | 403 policy denial, 404 unknown route | no |
| `upstream` | 4403 authentication result, 400 handler result | yes |

The fixture preserves the layer, status or close code, and a semantic error
class. It does not relabel an edge result as an upstream Hermes result or hide an
upstream result behind a fallback.

## Redaction contract

The checked-in values are semantic markers only. History retains route/result
classes, logs retain a bounded reason class, and a future DOM may show only a
semantic error state and retry action label. None may retain or render raw
cookies, bearer values, authorization values, credentials, ticket values,
bounded `ticket[:8]` fragments, prompt text, transcript bytes, hostnames, or
user data. Retained text also rejects raw data URLs, file URLs, absolute or
punctuation-delimited paths, path-shaped filenames, embedded padded or unpadded
base64-looking values, and source-shaped `unknown ticket: Abcdefgh…` fragments.
Lowercase-only and digit-only candidates are rejected when their shape or nearby
payload context makes them credential-like, while ordinary retained copy remains
allowed. Recognized `Authorization: Basic ...`, `Authorization: Bearer ...`,
`Bearer ...`, and `Cookie: ...` forms are rejected regardless of credential
length; ordinary copy without a recognized credential/header form remains
allowed. Controlled CLI failures are one JSON object, have a
maximum length of 240 characters, do not echo input, and do not include a
traceback.

Before parsing, `validate.py` bounds raw bytes, tokens, nodes, nesting,
object keys, array items, string bytes, integer digits, and float tokens. The
baseline includes `probe-baseline.json` in its artifact manifest and binds its
samples and summaries to a fixed canonical evidence SHA; recomputing mutable
sample metadata cannot authorize a different baseline.

Accessibility is N/A for this non-UI security fixture and standard-library
validator. It creates no focus, semantic control, screen-reader, VoiceOver,
Switch Control, Dynamic Type, browser-zoom, contrast, motion, transparency, or
touch-target surface. The artifact preserves the downstream requirement that
later web and Apple clients still implement those checks.

## Reproduce offline

Run from the repository root:

```sh
python3 contracts/fixtures/deployment-security/ws-ticket/validate.py
python3 -O contracts/fixtures/deployment-security/ws-ticket/validate.py
python3 contracts/fixtures/deployment-security/ws-ticket/validate.py --unknown-flag
python3 contracts/fixtures/deployment-security/ws-ticket/test_validate.py
python3 -O contracts/fixtures/deployment-security/ws-ticket/test_validate.py
python3 -m unittest discover \
  -s contracts/fixtures/deployment-security/ws-ticket \
  -p 'test_*.py'
python3 -O -m unittest discover \
  -s contracts/fixtures/deployment-security/ws-ticket \
  -p 'test_*.py'
python3 -m py_compile \
  contracts/fixtures/deployment-security/ws-ticket/validate.py \
  contracts/fixtures/deployment-security/ws-ticket/test_validate.py
```

All commands are local and standard-library-only. They do not prove Hermes
runtime behavior, a proxy, a deployment, credentials, a real ticket, or network
security. The baseline is observational evidence, not a product budget:
`threshold` is `null`, with 30 raw normal and 30 raw optimized samples. Re-run
it on the target environment before making a performance decision.
