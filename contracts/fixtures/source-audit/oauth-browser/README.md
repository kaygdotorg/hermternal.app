# Browser OAuth source-audit fixtures

Status: deterministic synthetic proof for issue #199 (`C-02B`).

These fixtures freeze the browser OAuth state and PKCE behavior observed at Hermes revision `f5be9236e00ddf2f2a412697f267078fc4ee068e`. They do not call Hermes, an identity provider, a network service, an Apple API, or a real browser. The cases use synthetic cookie-shaped values and the audit records public commit-pinned GitHub source URLs; neither is live authentication material.

The fixtures contain no live credentials, access tokens, refresh tokens, cookie contents, deployment host data, provider data, transcripts, or user data.

## Pinned observations

The audit records typed source observations for the pinned revision:

- `hermes_cli/dashboard_auth/routes.py:auth_login` short-circuits a provider with `supports_password: true` before calling `start_login`. PKCE therefore applies to the reviewed OAuth or OIDC browser path, not to the pinned `BasicAuthProvider` password form.
- `hermes_cli/dashboard_auth/routes.py:auth_callback` rejects a missing PKCE cookie, provider cancellation/error, and missing or mismatched callback state. It passes the stored verifier to `complete_login` and issues session cookies only after the provider exchange succeeds.
- `plugins/dashboard_auth/nous/__init__.py:NousDashboardAuthProvider.start_login` builds a nested authorization parameter map containing `state`, `code_challenge`, and `code_challenge_method=S256`. Its cookie payload contains `state` and `verifier`; `complete_login` sends `code_verifier` to the token endpoint. The pinned provider maps an HTTP 400 from that auth-code exchange to `InvalidCodeError`, including code, PKCE, and redirect-URI rejection.
- The pinned Nous browser flow does not include an OAuth/OIDC `nonce` authorization parameter. This no-nonce statement is scoped to the pinned Nous flow. A separately reviewed OIDC provider MAY require and validate nonce when its compatibility record says so.
- `hermes_cli/dashboard_auth/cookies.py` calls the state value a CSRF nonce in a source comment. That label is not a provider `nonce` parameter and does not expand the pinned Nous browser contract.

The source observations are checked against the supplied immutable excerpts in [`source_excerpts/`](source_excerpts/), their commit-pinned SHA-256 values, and the pinned Hermes Git tree/blob IDs. `source_audit.json` must contain exactly one reference for each expected path, with an exact path-to-excerpt and path-to-URL mapping. URLs are parsed and must use the public `github.com` host, the pinned commit, the expected path, and no userinfo, query, fragment, or path parameters. The validator does not treat `source_audit.json` metadata alone as source evidence.

## Structured nonce policy

`source_audit.json` uses an exact recursive schema for nonce policy:

- `global_requirement.required` is `false` and `global_requirement.scope` is `null`; a global positive nonce requirement is never valid.
- `pinned Nous` has `required: false` and `exposed: false` for its pinned browser scope.
- A `reviewed OIDC provider` may have `required: true` and `exposed: true` only under the named `reviewed OIDC compatibility record` condition.

The documentation guard rejects positive nonce language with no provider scope and rejects global quantifiers such as “every provider”, “all providers”, or “each callback”. It allows a reviewed provider-scoped OIDC requirement. This prose check supplements, but does not replace, the exact structured policy validation.

## Fixture cases and exact outcome matrix

[`cases.json`](cases.json) covers exactly these callback outcomes for a reviewed OAuth browser provider:

| Case | Status | Reason | Provider exchange | Session cookie | PKCE cookie | Separate nonce |
| --- | ---: | --- | --- | --- | --- | --- |
| `success` | 302 | `login_success` | called; accepted verifier | issued | cleared | false |
| `state-mismatch` | 400 | `state_mismatch` | not called | not issued | retained until TTL | false |
| `missing-state` | 400 | `state_mismatch` | not called | not issued | retained until TTL | false |
| `pkce-failure` | 400 | `invalid_code_or_pkce` | called; verifier rejected | not issued | retained until TTL | false |
| `cancellation` | 400 | `idp_error` | not called | not issued | retained until TTL | false |
| `malformed-callback` | 400 | `invalid_code_or_pkce` | called; empty code rejected | not issued | retained until TTL | false |

The validator compares every case against an independent expected outcome matrix. It rejects status, reason, exchange, or cleanup mutations even when the mutated values remain individually well-typed. The nested authorization parameters and provider exchange verifier are cross-checked against the cookie state and verifier.

## Failure semantics and source markers

`failure_semantics` is an exact map. Every callback failure claim below is bound to ordered markers in the pinned `routes.py` excerpt; the retry instruction is explicitly unbound because it is client guidance rather than a source observation:

- missing PKCE cookie: reject callback;
- missing or mismatched state: reject before provider exchange;
- cancellation and provider error parameters: reject without a session cookie;
- code or PKCE rejection: reject without a session cookie;
- malformed callback: fail closed without a session cookie;
- `InvalidCodeError`: reject without a session cookie;
- provider unreachable during login start: return the provider-unreachable error path;
- retry: start a fresh login attempt.

Changing an outcome, source reference, marker, or marker order fails validation. The `InvalidCodeError` markers bind the empty-code malformed callback and the code/PKCE rejection path to the route's 400 response and to the pinned Nous provider's HTTP-400 mapping. The cases root names that provider observation explicitly.

## Recursive schema and redaction checks

Both JSON roots and every nested object used by the fixtures have exact key sets and type/value checks. The validator recursively walks all nested dictionaries, lists, keys, and string values in `cases.json` and `source_audit.json`. It rejects live credential-shaped values such as `ghp_live_*`, `github_pat_*`, `sk_live_*`, bearer values, cloud access-key shapes, private-key headers, token assignments, and sensitive field names. Public commit-pinned source URLs are allowed evidence; live secrets and live cookie contents are not.

Every JSON fixture or source-evidence read uses the same strict standard-library loader. It rejects duplicate object keys before redaction (including nested duplicates), `NaN`, `Infinity`, `-Infinity`, exponent overflow such as `1e9999`, integers over 4,300 digits, unsupported leaf types, and nesting beyond the fixed depth bound. Closed-schema validation also requires exact dictionary/list/string/built-in scalar types before any set, index, `.get`, regex, or membership operation; expected HTTP statuses reject booleans and floats. Duplicate-key diagnostics never echo attacker-controlled keys; normalized sensitive assignments such as `password`, `api_key`, `authorization`, and `token` are redacted; all validation diagnostics are capped at 240 characters. The loader performs a structural depth pre-scan before parsing so hostile input fails with a controlled validation error rather than a parser traceback. The CLI preflights the selected JSON through the same closed schema and accepts `--audit` and `--cases` overrides for offline temporary-fixture regressions; malformed JSON or schema exits with status `2`, a bounded `validation error` line, and no traceback. Reported artifact bytes and file names use the selected override paths plus the immutable source excerpts.

## Validation

Run the standard-library test directly from the repository root:

```text
python3 contracts/fixtures/source-audit/oauth-browser/test_oauth_browser.py
python3 -O contracts/fixtures/source-audit/oauth-browser/test_oauth_browser.py
python3 -m unittest discover -s contracts/fixtures/source-audit/oauth-browser -p 'test_oauth_browser.py'
python3 -m py_compile contracts/fixtures/source-audit/oauth-browser/test_oauth_browser.py
```

The test prints the measured fixture-validation duration and JSON artifact size as baseline evidence. These values are observations only; this issue does not define a performance threshold. The test is offline and deterministic apart from the reported wall-clock duration.

This fixture set is source-audit evidence, not production authentication code. Do not add live integration, Apple-specific behavior, `.superdesign/` output, or real provider material here.
