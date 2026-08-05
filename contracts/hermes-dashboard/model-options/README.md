# Active-model options source audit

**Contract:** `dashboard-v0.0.1`
**Pinned Hermes source:** `f5be9236e00ddf2f2a412697f267078fc4ee068e`
**Paper:** N/A. This artifact audits a protocol operation and has no user-facing UI.
**Live integration:** none. The fixtures and validator are synthetic and offline.

## Conclusion

The pinned source defines the JSON-RPC operation `model.options`. The operation is registered in [`tui_gateway/methods_complete.py`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/tui_gateway/methods_complete.py) at lines 327-347 and calls `hermes_cli.inventory.build_model_options_payload`. The shared builder returns the source-defined top-level shape `{providers, model, provider}` from [`hermes_cli/inventory.py`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/inventory.py) at lines 276-313.

The fixtures use only this proven JSON-RPC operation. They do not hard-code a provider catalog, model catalog, pricing, or fallback operation. Provider rows in the present fixture are synthetic values used to exercise the observed response shape; they are not compatibility claims.

The pinned Dashboard also exposes `GET /api/model/options` as a REST equivalent. It calls the same builder and states that its response matches `model.options` one-for-one in [`hermes_cli/web_server.py`](https://github.com/NousResearch/hermes-agent/blob/f5be9236e00ddf2f2a412697f267078fc4ee068e/hermes_cli/web_server.py) at lines 6238-6280. This issue freezes the JSON-RPC source for fixtures so the test does not silently switch transports.

## Observable contract frozen for fixtures

- **Request method:** `model.options`.
- **Request flags:** `session_id`, `explicit_only`, `include_unconfigured`, and `refresh` are the source-defined inputs used by the handler. Each case has an independently frozen request-key set in the validator; changing both request params and fixture metadata, including to an empty set, fails validation.
- **Response shape:** the result is an object with source-defined `providers`, `model`, and `provider` fields. Provider row fields remain source-defined; the fixtures assert only the list and active-selection semantics needed here. `provider_count` and `total_models` are integers when present; JSON booleans are rejected even though Python treats them as integers. Request and response JSON-RPC IDs also use strict type-aware comparison.
- **Source identity:** the validator uses strict recursive type-aware equality to bind the complete `fixture_surface` structure, negative controls, repository slug and URL, REST and registry provenance records, and four unique pinned source links to exact expected values. JSON booleans cannot satisfy integer fields. Source links contain no query strings or fragments. `validate_fixture` revalidates any audit argument before trusting it.
- **Redaction:** recursive fixture validation uses an explicit, boundary-aware sensitive-key/value policy. Compound markers such as `provider_api_key`, `x_authorization_value`, `api_key_value`, `synthetic-api-key`, and `my-secret-value` fail closed. It also rejects credential material such as PEM private keys, AWS `AKIA` keys, GitHub PATs, and bearer/basic credentials while allowing legitimate metadata such as `authenticated` and `auth_type`; ordinary synthetic provider and model identifiers remain valid.
- **Option source:** `build_model_options_payload`, which delegates to the source inventory and applies picker-specific behavior. The client must not replace it with an invented provider list or model list.
- **Empty result:** `{ "providers": [], "model": "", "provider": "" }` is valid evidence that no options are available. It is fail-closed, not permission to guess a provider or fallback model.
- **Malformed, absent, or unknown results:** fail closed and preserve the last verified source evidence. No retry or alternate method is encoded by these fixtures.

The machine-readable source record is [`source-audit.json`](source-audit.json). The synthetic cases and offline regression validator live in [`contracts/fixtures/source-audit/model-options/`](../../fixtures/source-audit/model-options/).

## Verification

Run the standard-library validator from the repository root:

```text
python3 contracts/fixtures/source-audit/model-options/test_model_options.py
```

The command validates the pinned SHA, source evidence, present/absent/empty/malformed/unknown-operation cases, fail-closed behavior, and the regression control that rejects a `model.options` dependency when the source audit says the operation is absent. It prints the measured validation duration and fixture artifact size as baseline evidence; this issue does not set a pass threshold.
