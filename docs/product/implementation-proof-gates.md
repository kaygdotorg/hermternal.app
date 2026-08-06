# Hermternal implementation proof-gate checklist

**Status:** approved fail-closed planning contract
**Roadmap key:** P0-06
**Integration branch:** dev
**Source contract:** dashboard-v0.0.1
**Pinned Hermes SHA:** f5be9236e00ddf2f2a412697f267078fc4ee068e
**Paper file:** [Paper design source of truth](https://app.paper.design/file/01KZ6BB66KCWR2C4J2TSWQGDM7/1-0)
**Validator:** scripts/validate_proof_gates.py

This is one exact checklist for the transition from approved planning to
application scaffolding and then to live-adjacent integration. A checked box
means that the required evidence is attached to the owning roadmap issue. An
unchecked, missing, malformed, mismatched, or waived item blocks the transition.
This document does not perform a runtime, deployment, production, or live
service check.

## 1. Scope and dependency policy

### Scaffolding boundary

- M0 contains only the approved planning prerequisites: `P0-01`, `P0-02`, `P0-05`, and `P0-06`.
- Application scaffolding may start only after the M0 gates and every `SCAFFOLD` gate in section 2 has checked evidence.
- Downstream client, deployment, benchmark, accessibility, and release proofs are not M0 prerequisites. They remain ordered gates for later transitions.

### Live integration boundary

- A mock-only scaffold is not a live integration. It may use synthetic fixtures and local adapters only.
- Live-adjacent integration remains blocked until the `INTEGRATION` gates pass, including compatibility, proxy, security, parity, accessibility, benchmark, and disposable integration evidence.
- Release promotion remains a separate `RELEASE` gate. This checklist does not merge branches, close issues, publish credentials, or assert a live or production result.

### Dependency direction

- A gate may depend only on its own milestone or an earlier milestone. An owner issue never depends on a downstream runtime issue.
- The approved dependency direction is `M0 → M1 → M2/M3/M4 → M5/M6 → M7`.
- The validator checks every gate owner, dependency, issue key, issue number, and canonical GitHub URL offline. It does not query GitHub.
- Deferred user-facing UI rows `D-04` and `D-04A` are not v0.0.1 proof-gate dependencies. They remain in the roadmap for traceability.
- The search and deep-link contracts `C-07A`, `C-15`, and `C-16` remain compatibility references. Non-UI chat, authentication, accessibility, performance, security, and release gates remain required.

## 2. Fail-closed gate order

The table is the complete gate order. Owners are the roadmap issues that publish
the proof. The checklist itself owns no runtime implementation.

| Gate | Phase | Requirement | Owner roadmap issue(s) | Depends on | Required evidence | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `G-01` | M0 | Approved planning reconciliation is present and names the pinned source, repository scope, and planning-only boundary. | [P0-01](https://github.com/kaygdotorg/hermternal/issues/40) | None | `E-01` | [ ] |
| `G-02` | M0 | The source-audit and compatibility policy is pinned, fail-closed, and uses synthetic or redacted evidence. | [P0-02](https://github.com/kaygdotorg/hermternal/issues/41) | [P0-01](https://github.com/kaygdotorg/hermternal/issues/40) | `E-02` | [ ] |
| `G-03` | M0 | The atomic issue-template contract is present and its required sections, evidence, and definition-of-done order are unchanged. | [P0-05](https://github.com/kaygdotorg/hermternal/issues/45) | [P0-01](https://github.com/kaygdotorg/hermternal/issues/40) | `E-03` | [ ] |
| `G-04` | M0 | This checklist is validated offline before any application scaffolding or live integration. | [P0-06](https://github.com/kaygdotorg/hermternal/issues/46) | [P0-02](https://github.com/kaygdotorg/hermternal/issues/41), [P0-05](https://github.com/kaygdotorg/hermternal/issues/45) | `E-04` | [ ] |
| `G-05` | SCAFFOLD | The approved Dashboard route and method allowlist is the only route surface available to a scaffold. | [C-01](https://github.com/kaygdotorg/hermternal/issues/47) | [P0-02](https://github.com/kaygdotorg/hermternal/issues/41) | `E-05` | [ ] |
| `G-06` | SCAFFOLD | Language-neutral synthetic fixtures, negative cases, and web/Apple parity cover the approved contract. | [C-19](https://github.com/kaygdotorg/hermternal/issues/69) | [C-02](https://github.com/kaygdotorg/hermternal/issues/48), [C-02A](https://github.com/kaygdotorg/hermternal/issues/49), [C-03](https://github.com/kaygdotorg/hermternal/issues/50), [C-05](https://github.com/kaygdotorg/hermternal/issues/53), [C-08](https://github.com/kaygdotorg/hermternal/issues/58), [C-13](https://github.com/kaygdotorg/hermternal/issues/63), [C-15](https://github.com/kaygdotorg/hermternal/issues/65), [C-17](https://github.com/kaygdotorg/hermternal/issues/67) | `E-06` | [ ] |
| `G-07` | SCAFFOLD | The Paper web manifest and semantic tokens cover the scaffold states; Apple boards remain a later shared-design dependency. | [D-15W](https://github.com/kaygdotorg/hermternal/issues/206) | [D-01](https://github.com/kaygdotorg/hermternal/issues/72), [D-02](https://github.com/kaygdotorg/hermternal/issues/73), [D-03](https://github.com/kaygdotorg/hermternal/issues/74), [D-05](https://github.com/kaygdotorg/hermternal/issues/77), [D-06](https://github.com/kaygdotorg/hermternal/issues/78), [D-07](https://github.com/kaygdotorg/hermternal/issues/79), [D-08](https://github.com/kaygdotorg/hermternal/issues/80), [D-11](https://github.com/kaygdotorg/hermternal/issues/83), [D-13](https://github.com/kaygdotorg/hermternal/issues/85), [D-14W](https://github.com/kaygdotorg/hermternal/issues/205) | `E-07` | [ ] |
| `G-08` | SCAFFOLD | Benchmark method and web or Apple harness scaffolds exist with artifact evidence and no final performance threshold. | [B-01](https://github.com/kaygdotorg/hermternal/issues/102), [B-03](https://github.com/kaygdotorg/hermternal/issues/107), [B-04](https://github.com/kaygdotorg/hermternal/issues/108) | [C-19](https://github.com/kaygdotorg/hermternal/issues/69) | `E-08` | [ ] |
| `G-09` | SCAFFOLD | Accessibility design inputs preserve keyboard, screen-reader, VoiceOver, Switch Control, zoom, contrast, motion, and touch-target requirements. | [D-11](https://github.com/kaygdotorg/hermternal/issues/83), [D-12](https://github.com/kaygdotorg/hermternal/issues/84), [D-13](https://github.com/kaygdotorg/hermternal/issues/85) | [D-01](https://github.com/kaygdotorg/hermternal/issues/72), [D-02](https://github.com/kaygdotorg/hermternal/issues/73), [D-09](https://github.com/kaygdotorg/hermternal/issues/81), [D-10](https://github.com/kaygdotorg/hermternal/issues/82) | `E-09` | [ ] |
| `G-10` | SCAFFOLD | The application scaffold uses mock-only network boundaries and cannot contact any external Hermes or deployment service. | [W-01](https://github.com/kaygdotorg/hermternal/issues/114) | [C-20](https://github.com/kaygdotorg/hermternal/issues/70), [D-14W](https://github.com/kaygdotorg/hermternal/issues/205), [B-03](https://github.com/kaygdotorg/hermternal/issues/107) | `E-10` | [ ] |
| `G-11` | SCAFFOLD | Synthetic deployment and security boundary proofs cover cookies, tickets, host/origin policy, PTY scope, and redaction before client integration. | [DEP-06M](https://github.com/kaygdotorg/hermternal/issues/207), [DEP-07M](https://github.com/kaygdotorg/hermternal/issues/208), [DEP-10M](https://github.com/kaygdotorg/hermternal/issues/209) | [C-02](https://github.com/kaygdotorg/hermternal/issues/48), [C-02A](https://github.com/kaygdotorg/hermternal/issues/49), [C-17](https://github.com/kaygdotorg/hermternal/issues/67), [C-18](https://github.com/kaygdotorg/hermternal/issues/68) | `E-11` | [ ] |
| `G-12` | INTEGRATION | Caddy and Traefik normalized deployment and security proofs match before live-adjacent integration is enabled. | [DEP-13](https://github.com/kaygdotorg/hermternal/issues/101) | [DEP-04](https://github.com/kaygdotorg/hermternal/issues/91), [DEP-05](https://github.com/kaygdotorg/hermternal/issues/92), [DEP-06](https://github.com/kaygdotorg/hermternal/issues/93), [DEP-07](https://github.com/kaygdotorg/hermternal/issues/94), [DEP-08](https://github.com/kaygdotorg/hermternal/issues/95), [DEP-09](https://github.com/kaygdotorg/hermternal/issues/96), [DEP-10](https://github.com/kaygdotorg/hermternal/issues/97), [DEP-11](https://github.com/kaygdotorg/hermternal/issues/98), [DEP-11A](https://github.com/kaygdotorg/hermternal/issues/99), [DEP-12](https://github.com/kaygdotorg/hermternal/issues/100) | `E-12` | [ ] |
| `G-13` | INTEGRATION | The pinned disposable Hermes integration proof passes only after compatibility, proxy, parity, and client gates are complete. | [R-02](https://github.com/kaygdotorg/hermternal/issues/185) | [C-04](https://github.com/kaygdotorg/hermternal/issues/51), [C-04A](https://github.com/kaygdotorg/hermternal/issues/52), [DEP-13](https://github.com/kaygdotorg/hermternal/issues/101), [R-01](https://github.com/kaygdotorg/hermternal/issues/183), [R-01A](https://github.com/kaygdotorg/hermternal/issues/184), [W-02](https://github.com/kaygdotorg/hermternal/issues/115), [W-02A](https://github.com/kaygdotorg/hermternal/issues/116), [A-07](https://github.com/kaygdotorg/hermternal/issues/156) | `E-13` | [ ] |
| `G-14` | INTEGRATION | Cross-platform accessibility, performance, and visual evidence is attached without inventing a budget before approved baseline review. | [R-05](https://github.com/kaygdotorg/hermternal/issues/188), [R-06](https://github.com/kaygdotorg/hermternal/issues/189), [R-06A](https://github.com/kaygdotorg/hermternal/issues/190) | [W-21](https://github.com/kaygdotorg/hermternal/issues/139), [W-21A](https://github.com/kaygdotorg/hermternal/issues/140), [W-21B](https://github.com/kaygdotorg/hermternal/issues/141), [W-21C](https://github.com/kaygdotorg/hermternal/issues/142), [A-21](https://github.com/kaygdotorg/hermternal/issues/177), [A-21A](https://github.com/kaygdotorg/hermternal/issues/178), [A-21B](https://github.com/kaygdotorg/hermternal/issues/179), [A-21C](https://github.com/kaygdotorg/hermternal/issues/180), [W-24](https://github.com/kaygdotorg/hermternal/issues/146), [W-25](https://github.com/kaygdotorg/hermternal/issues/147), [W-25A](https://github.com/kaygdotorg/hermternal/issues/148), [A-22](https://github.com/kaygdotorg/hermternal/issues/181), [A-22A](https://github.com/kaygdotorg/hermternal/issues/182), [R-01](https://github.com/kaygdotorg/hermternal/issues/183), [R-01A](https://github.com/kaygdotorg/hermternal/issues/184) | `E-14` | [ ] |
| `G-15` | RELEASE | Review, evidence, security audits, and one focused dev integration record are complete before any release promotion. | [R-08](https://github.com/kaygdotorg/hermternal/issues/195) | [R-03](https://github.com/kaygdotorg/hermternal/issues/186), [R-04](https://github.com/kaygdotorg/hermternal/issues/187), [R-05](https://github.com/kaygdotorg/hermternal/issues/188), [R-06](https://github.com/kaygdotorg/hermternal/issues/189), [R-06A](https://github.com/kaygdotorg/hermternal/issues/190), [R-07](https://github.com/kaygdotorg/hermternal/issues/191), [R-07A](https://github.com/kaygdotorg/hermternal/issues/192), [R-07B](https://github.com/kaygdotorg/hermternal/issues/193), [R-07C](https://github.com/kaygdotorg/hermternal/issues/194) | `E-15` | [ ] |

No gate may be marked complete from a status code, a screenshot, a copied
claim, or a best-effort fallback. The owner issue must link the raw or
reproducible evidence and its negative result where the gate has one.

## 3. Required evidence

Every gate has one evidence record. The record is complete only when the named
field is present, reproducible, and fail-closed. A missing evidence record is a
blocker, not an implicit pass.

| Evidence | Owning gate | Required field | Fail-closed requirement |
| --- | --- | --- | --- |
| `E-01` | `G-01` | Planning record | Pinned planning review, scope, and source-audit boundary are linked. |
| `E-02` | `G-02` | Source-audit and compatibility record | The full Hermes SHA, route manifest, attestation policy, behavioral-probe policy, and redacted fixture rule are linked. |
| `E-03` | `G-03` | Issue-template parity result | The exact section, field, and definition-of-done contract is checked without hidden or fenced decoys. |
| `E-04` | `G-04` | Checklist validator result | The standard-library validator returns the valid-template JSON object and rejects every required mutation. |
| `E-05` | `G-05` | Route manifest and default-deny fixture diff | Only the approved route and method allowlist is admitted; unknown, duplicate, traversal, and wrong-method cases stop at the boundary. |
| `E-06` | `G-06` | Synthetic fixture and parity result | Web and Apple use the same redacted fixture meanings, including malformed, denied, interrupted, expired, and incompatible cases. |
| `E-07` | `G-07` | Paper artboard and token manifest review | The canonical Paper file, relevant artboards, semantic tokens, responsive states, and later Apple dependency are named. |
| `E-08` | `G-08` | Benchmark method and harness evidence | The deterministic workload, environment, build-mode applicability, repetitions, distribution, and raw artifact are recorded without a final threshold. |
| `E-09` | `G-09` | Accessibility applicability and preservation result | UI gates name keyboard, focus, semantics, screen reader or VoiceOver, Switch Control, zoom, contrast, motion, transparency, and touch targets; non-UI gates preserve those fields. |
| `E-10` | `G-10` | No-network mock-scope result | The scaffold uses local synthetic boundaries and a negative proof that no external service is contacted. |
| `E-11` | `G-11` | Synthetic deployment, security, and redaction result | Cookie, bearer, ticket, host/origin, PTY host, firewall, and secret/log-redaction boundaries are proven with non-sensitive markers. |
| `E-12` | `G-12` | Caddy and Traefik normalized proof result | Both proxy variants produce equal edge/upstream/lifecycle/redaction results for the same disposable cases. |
| `E-13` | `G-13` | Pinned disposable integration trace | The exact source pin, attestation, behavioral probe, contract fixtures, proxy proof, and parity result are recorded before the gate can pass. |
| `E-14` | `G-14` | Cross-platform accessibility and performance matrix | Web, iOS, iPadOS, and macOS results identify applicable states, actual measurements, distribution, and any approved budget without invention. |
| `E-15` | `G-15` | Review, evidence, and dev-integration record | Review commands, diff, test results, security result, final issue comment, PR, commit SHA, and integration into `dev` are linked. |

## 4. Accessibility and performance

### Non-UI accessibility

- **Paper applicability:** N/A — this is a planning/tooling artifact with no direct UI; Paper states remain preserved by the linked design source and downstream Paper issues.
- **Preservation evidence:** The checklist and validator preserve keyboard/focus, semantic-name, screen-reader/VoiceOver, Switch Control, zoom/Dynamic Type, contrast, reduced-motion/transparency, and touch-target behavior requirements because they only read bytes and emit diagnostics; missing evidence stays blocked.

### Reproducible benchmark evidence

This is artifact-size and local validator evidence, not a product performance
budget. No threshold is claimed. Later web and Apple harnesses use the shared
[B-01 benchmark evidence contract](../../contracts/benchmarks/README.md). This
10-run P0-06 observation remains a separate planning-validator trace; it does
not define a product budget or replace the shared 30-sample method.

- **Deterministic fixture:** The checked-in `implementation-proof-gates.md` fixture and the standard-library validator's valid JSON result.
- **Metric:** Artifact bytes and local validator duration only; product latency, memory, bundle, render, and startup budgets are not measured here.
- **Environment:** macOS-26.5.2-arm64-arm-64bit-Mach-O, Python 3.14.6.
- **Build mode:** N/A — standard-library source scripts have no production or release build.
- **Repetitions and distribution:** 10 fresh subprocess runs; all returned valid checklist JSON; record all ten samples plus min, mean, median, p95, and max in milliseconds; p99 is not meaningful for ten samples.
- **Trace artifact:** Local command output only; no upload or service trace.
- **Raw command:** `python3 -c 'import json,platform,statistics,subprocess,sys,time; p=["scripts/validate_proof_gates.py","docs/product/implementation-proof-gates.md"]; samples=[]; [samples.append((lambda t: (subprocess.run([sys.executable,*p],check=True,capture_output=True), (time.perf_counter()-t)*1000)[1])(time.perf_counter())) for _ in range(10)]; print(json.dumps({"environment":platform.platform(),"python":sys.version.split()[0],"repetitions":10,"distribution_ms":{"min":min(samples),"mean":statistics.mean(samples),"median":statistics.median(samples),"p95":statistics.quantiles(samples,n=20,method="inclusive")[18],"max":max(samples),"samples":samples}}))'`
- **Artifact-size evidence:** Same checkout; `scripts/validate_proof_gates.py` `76,492` bytes, `scripts/test_validate_proof_gates.py` `26,828` bytes, and `docs/product/implementation-proof-gates.md` `28,835` bytes.
- **Validator-duration evidence:** Same checkout; ten samples `63.502, 66.142, 65.529, 64.241, 66.980, 64.344, 63.436, 67.437, 63.555, 63.324` ms; min `63.324` ms, mean `64.849` ms, median `64.292` ms, p95 `67.231` ms, and max `67.437` ms; p99 is not meaningful for ten samples and no threshold is inferred.
- **Threshold statement:** No threshold is claimed.

The benchmark record must include environment, repetitions, distribution, build
mode, raw command, artifact sizes, and validator durations. A duration or size
observation is evidence of reproducibility, not an approved product budget.

## 5. No-network and privacy

### Offline rule

- **No-network result:** The validator uses only the Python standard library and local bytes; it never contacts GitHub, Paper, Hermes, a proxy, a browser, or a deployment.
- **Live integration posture:** Application scaffolding is mock-only; live integration and release promotion remain blocked until the downstream checklist gates are complete.

### Redaction rule

- **Redaction result:** Fixtures and evidence use synthetic markers only; no credentials, cookies, tickets, transcripts, provider state, hostname, token, secret, or user data is retained.

The validator never shells out, imports a third-party package, follows a link,
opens a socket, or rewrites the checklist. The CLI emits one JSON object on
success and on every failure. It must not emit a traceback, argparse usage, or
an unstructured warning.

## 6. Atomic issue-template parity

This section mirrors the checked-in atomic issue-template contract. It is not a
replacement for the template. The validator checks every row, order, duplicate,
unknown item, and preservation statement. Hidden HTML comments and arbitrary
backtick or tilde fences do not count as contract content.

### Section parity

| Order | Atomic issue-template item | Checklist preservation |
| --- | --- | --- |
| `01` | `1. One operation` | The one independently verifiable operation remains explicit. |
| `02` | `2. Ownership and dependencies` | Owners, blockers, and soft sequencing remain explicit. |
| `03` | `3. Exact behavior` | Normal, pending, empty, success, failure, interruption, cancellation, retry, and recovery remain represented where applicable. |
| `04` | `4. Paper evidence` | Paper URL, artboards, static states, and justified N/A remain represented. |
| `05` | `5. Contract and tests` | Contract paths, pin, fixtures, unit, UI, integration, parity, negative, and regression evidence remain represented. |
| `06` | `6. Accessibility` | Accessibility applicability and preservation remain represented. |
| `07` | `7. Benchmark` | Fixture, metric, environment, build mode, distribution, trace, and budget fields remain represented. |
| `08` | `8. Verification commands` | Exact reproducible commands and expected artifacts remain represented. |
| `09` | `9. Evidence` | PR, commit, Paper, fixture, test, accessibility, benchmark, proxy, and security evidence remain represented. |
| `10` | `10. Definition of done` | The twelve unchecked atomic completion items remain represented. |

### Field parity

| Order | Template field | Checklist preservation |
| --- | --- | --- |
| `F-01` | `Owner` | One responsible owner remains named. |
| `F-02` | `Assigned subagent` | One assigned implementation unit remains named. |
| `F-03` | `Reviewer` | A reviewer slot remains explicit. |
| `F-04` | `Child issues` | Splitting remains visible rather than implicit. |
| `F-05` | `Hard blockers` | Blocking dependencies remain separate from soft sequence. |
| `F-06` | `Soft sequence` | Non-blocking order remains separate from blockers. |
| `F-07` | `Normal` | Normal behavior remains explicit. |
| `F-08` | `Loading or pending` | Pending behavior remains explicit. |
| `F-09` | `Empty` | Empty behavior remains explicit. |
| `F-10` | `Success` | Success behavior remains explicit without an unsupported claim. |
| `F-11` | `Failure` | Failure behavior remains fail-closed. |
| `F-12` | `Interruption or cancellation` | Safe interruption remains explicit. |
| `F-13` | `Retry and recovery` | Retry and recovery remain explicit. |
| `F-14` | `Paper file` | The canonical Paper source remains named. |
| `F-15` | `Artboards` | Exact artboards remain nameable. |
| `F-16` | `Static states` | Static state evidence remains nameable. |
| `F-17` | `Contract paths` | Contract locations remain nameable. |
| `F-18` | `Contract version or pinned Hermes SHA` | The source pin remains nameable. |
| `F-19` | `Fixture IDs` | Deterministic fixture IDs remain nameable. |
| `F-20` | `Unit tests` | Unit test evidence remains nameable. |
| `F-21` | `Component or UI tests` | UI test evidence remains nameable where applicable. |
| `F-22` | `Integration or deployment tests` | Boundary test evidence remains nameable. |
| `F-23` | `Parity tests` | Shared parity evidence remains nameable. |
| `F-24` | `Negative tests` | Negative evidence remains nameable. |
| `F-25` | `Regression tests` | Regression evidence remains nameable. |
| `F-26` | `Keyboard and focus` | Keyboard and focus evidence remains nameable. |
| `F-27` | `Semantic name` | Semantic-name evidence remains nameable. |
| `F-28` | `Screen reader or VoiceOver` | Screen-reader and VoiceOver evidence remains nameable. |
| `F-29` | `Switch Control` | Switch Control evidence remains nameable. |
| `F-30` | `Dynamic Type or browser zoom` | Dynamic Type and zoom evidence remains nameable. |
| `F-31` | `Contrast` | Contrast evidence remains nameable. |
| `F-32` | `Reduced motion and reduced transparency` | Motion and transparency evidence remains nameable. |
| `F-33` | `Touch target` | Touch-target evidence remains nameable. |
| `F-34` | `Deterministic fixture` | Deterministic workload evidence remains nameable. |
| `F-35` | `Metric` | Measured metric evidence remains nameable. |
| `F-36` | `Environment and device` | Environment and device evidence remains nameable. |
| `F-37` | `Build mode` | Build mode applicability remains nameable. |
| `F-38` | `Repetitions and distribution` | Distribution evidence remains nameable. |
| `F-39` | `Trace artifact` | Raw trace evidence remains nameable. |
| `F-40` | `Baseline or approved budget` | Baseline or approved budget remains nameable without invention. |
| `F-41` | `Pull request` | Pull-request evidence remains nameable. |
| `F-42` | `Commit SHA` | Commit evidence remains nameable. |
| `F-43` | `Paper review` | Paper review or justified N/A remains nameable. |
| `F-44` | `Fixture diff` | Fixture diff evidence remains nameable. |
| `F-45` | `Test output` | Test output evidence remains nameable. |
| `F-46` | `Accessibility result` | Accessibility result evidence remains nameable. |
| `F-47` | `Benchmark trace` | Benchmark trace evidence remains nameable. |
| `F-48` | `Proxy or integration trace` | Proxy or integration trace or justified N/A remains nameable. |
| `F-49` | `Security and redaction review` | Security and redaction evidence remains nameable. |

### Definition-of-done parity

| Order | Definition-of-done item | Checklist preservation |
| --- | --- | --- |
| `D-01` | The one operation is complete. | The checklist remains one complete operation. |
| `D-02` | Required normal and failure states pass. | Normal and failure proof remain required. |
| `D-03` | Regression tests exist and pass. | Regression proof remains required. |
| `D-04` | Matching contracts, comments, and nearby documentation are updated. | Matching documentation remains required. |
| `D-05` | Paper matches the implementation, or an approved N/A reason is recorded. | Paper parity or a reasoned N/A remains required. |
| `D-06` | Accessibility checks pass where applicable. | Accessibility applicability remains required. |
| `D-07` | Measured performance evidence is attached. | Measurement remains required without an invented threshold. |
| `D-08` | Security and privacy boundaries pass where applicable. | Security and privacy evidence remains required. |
| `D-09` | `rtk diff` was reviewed. | Diff review remains required. |
| `D-10` | `code-review-graph update --brief` and change impact review are complete. | Graph update and impact review remain required. |
| `D-11` | The assigned subagent left a final issue comment with the current state, completed work, verification results, remaining limitations, and child issues. | The final issue comment and verification results remain required. |
| `D-12` | The focused commit and pull request are reviewed and integrated into `dev`. | Focused dev integration remains required. |

## 7. Review and dev integration

### Review evidence

- **Review commands:** `rtk diff`, `code-review-graph update --brief`, `code-review-graph detect-changes`, the focused validator tests, the roadmap-template validator, and planning-docs-only checks.
- **Review result:** Review records the exact command, exit status, output artifact, and remaining limitation; a failed or unrun command is not reported as passed.
- **Pull request:** Pending until the focused branch is pushed and a PR targeting `dev` is opened.
- **Commit SHA:** Pending until the focused commit is created.
- **Paper review:** N/A — direct UI output is not owned by this planning/tooling artifact; the canonical Paper source and preservation contract are recorded above.
- **Fixture diff:** The validator mutation fixtures are synthetic local text; no aggregate or live fixture is changed.
- **Test output:** The normal, optimized, focused, discovery, compile, strict-JSON, and roadmap-template results are recorded in the final issue comment.
- **Accessibility result:** N/A — this command-line artifact has no focus order or control surface; preservation evidence is recorded in section 4.
- **Benchmark trace:** The local artifact-size and ten-run duration output is recorded in section 4 and the final issue comment.
- **Proxy or integration trace:** N/A — this checklist does not invoke live or production services; downstream local and disposable proofs own this evidence.
- **Security and redaction review:** The offline boundary, synthetic-marker rule, no-network rule, and no-live-claim rule are reviewed before publication.
- **Dev integration result:** The focused pull request targets `dev`; after review it is integrated into `dev` by the coordinator, and this task does not merge or close the issue.
- **Issue comment:** The assigned subagent posts one final comment on issue `#46` with current state, completed work, exact checks, remaining limitations, child issues, PR, and commit SHA.

### Dev integration

The only accepted integration target is `dev`. `main` is not a development
target. The branch, commit, PR, and final issue comment are evidence fields;
publication never turns an unchecked gate into a checked gate.

## 8. Definition of done

- [ ] The M0 prerequisite set contains only `P0-01`, `P0-02`, `P0-05`, and `P0-06`.
- [ ] Application scaffolding remains blocked until every earlier scaffold gate is checked with its required evidence.
- [ ] Live integration remains blocked until every integration and release gate is checked with its required evidence.
- [ ] Every exception field contains an inline reason and no performance threshold is invented.
- [ ] The validator, template validator, focused tests, and graph checks have reproducible outputs.
- [ ] The focused pull request is reviewed and integrated into `dev`; publication does not merge or close the issue.

## 9. Reproduction

- **Validator command:** `python3 scripts/validate_proof_gates.py docs/product/implementation-proof-gates.md`
- **Template validator command:** `python3 scripts/validate_roadmap_template.py .github/ISSUE_TEMPLATE/roadmap.md`
- **Focused test command:** `python3 scripts/test_validate_proof_gates.py`
- **Strict JSON check:** `python3 scripts/validate_proof_gates.py docs/product/implementation-proof-gates.md | python3 -c 'import json,sys; value=json.load(sys.stdin); assert value == {"errors": [], "ok": True, "path": "docs/product/implementation-proof-gates.md"}'`
- **Graph check:** `code-review-graph update --brief` followed by `code-review-graph detect-changes`
