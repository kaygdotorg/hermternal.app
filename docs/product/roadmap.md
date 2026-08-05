# Hermternal v0.0.1 roadmap and GitHub issue index

**Status:** approved planning index
**Release:** `v0.0.1`
**Integration branch:** `dev`
**Source contract:** [`contracts/hermes-dashboard/manifest.md`](../../contracts/hermes-dashboard/manifest.md)

## Purpose

This file is the local source of truth for the v0.0.1 GitHub roadmap. Each stable key maps to one GitHub issue. Add the GitHub issue number after publication. Do not reuse old prototype acceptance criteria without review.

Each issue owns one independently verifiable operation or artifact. Split an issue when separate parts can merge, fail, or be reviewed independently.

## Milestones

| Code | Milestone | Exit proof | Depends on |
| --- | --- | --- | --- |
| `M0` | Planning freeze | The source-correct specifications, proof gates, labels, milestones, and issue template are published. | None |
| `M1` | Shared contracts | Versioned contracts and synthetic fixtures pass language-neutral validation. | `M0` |
| `M2` | Paper and design proof | Required web, iPhone, iPad, and macOS states exist in Paper with semantic tokens. | `M1` |
| `M3` | Deployment and security proof | Caddy and Traefik pass the same disposable route, auth, WebSocket, firewall, and redaction cases. | `M1` |
| `M4` | Performance foundation | Deterministic harnesses produce reviewed baselines, then approved regression budgets. | `M1` |
| `M5` | Web client | The static web client passes contracts, Paper checks, deployment proofs, accessibility checks, and budgets. | `M1`, `M2`, `M3`, `M4` |
| `M6` | Apple clients | iOS, iPadOS, and macOS pass shared contracts with native UI, lifecycle, accessibility, and budgets. | `M1`, `M2`, `M3`, `M4` |
| `M7` | Release | Pinned disposable integration and all release audits pass on one `dev` commit. | `M5`, `M6` |

`main` is not a development target. Promote only a verified `dev` commit under the repository release policy.

## GitHub metadata

Create these labels:

- Milestone labels: `roadmap:M0` through `roadmap:M7`.
- Platform labels: `platform:shared`, `platform:web`, `platform:apple`, `platform:ios`, `platform:ipados`, `platform:macos`.
- Type labels: `type:contract`, `type:design`, `type:deployment`, `type:security`, `type:benchmark`, `type:implementation`, `type:test`, `type:release`.
- State labels: `blocked`, `needs-paper`, `needs-proof`, `deferred:v0.0.2`, `legacy-prototype`.

Create one GitHub milestone for each milestone in this file. Use the stable key in every issue title and body.

## M0 — planning freeze

| Key | GitHub # | One operation | Dependencies |
| --- | --- | --- | --- |
| `P0-01` | [#40](https://github.com/kaygdotorg/hermternal/issues/40) | Reconcile all v0.0.1 planning documents with the pinned source review. | None |
| `P0-02` | [#41](https://github.com/kaygdotorg/hermternal/issues/41) | Publish the pinned compatibility and fail-closed attestation policy. | `P0-01` |
| `P0-03` | [#42](https://github.com/kaygdotorg/hermternal/issues/42) | Triage legacy prototype issues `#1`–`#39`. | `P0-01` |
| `P0-04` | [#43](https://github.com/kaygdotorg/hermternal/issues/43) | Create roadmap labels. | `P0-01` |
| `P0-04A` | [#44](https://github.com/kaygdotorg/hermternal/issues/44) | Create roadmap milestones. | `P0-01` |
| `P0-05` | [#45](https://github.com/kaygdotorg/hermternal/issues/45) | Add the atomic GitHub issue template. | `P0-01` |
| `P0-06` | [#46](https://github.com/kaygdotorg/hermternal/issues/46) | Publish the implementation proof-gate checklist. | `P0-02`, `P0-05` |

## M1 — shared contracts

| Key | GitHub # | One operation | Dependencies |
| --- | --- | --- | --- |
| `C-01` | [#47](https://github.com/kaygdotorg/hermternal/issues/47) | Freeze the Dashboard route and method allowlist. | `P0-02` |
| `C-02` | [#48](https://github.com/kaygdotorg/hermternal/issues/48) | Freeze provider discovery behavior. | `C-01` |
| `C-02A` | [#49](https://github.com/kaygdotorg/hermternal/issues/49) | Freeze browser authentication behavior. | `C-01` |
| `C-03` | [#50](https://github.com/kaygdotorg/hermternal/issues/50) | Freeze native password-provider cookie and ticket behavior. | `C-02` |
| `C-04` | [#51](https://github.com/kaygdotorg/hermternal/issues/51) | Define out-of-band Hermes revision attestation. | `P0-02`, `C-01` |
| `C-04A` | [#52](https://github.com/kaygdotorg/hermternal/issues/52) | Define the Hermes behavioral compatibility probe. | `P0-02`, `C-01` |
| `C-05` | [#53](https://github.com/kaygdotorg/hermternal/issues/53) | Define connection and restoration state transitions. | `C-01`, `C-02`, `C-02A` |
| `C-06` | [#54](https://github.com/kaygdotorg/hermternal/issues/54) | Define uncertain prompt-delivery transitions. | `C-05` |
| `C-07` | [#55](https://github.com/kaygdotorg/hermternal/issues/55) | Define session creation and persistence behavior. | `C-01`, `C-05` |
| `C-07A` | [#56](https://github.com/kaygdotorg/hermternal/issues/56) | Define session search behavior. | `C-01`, `C-05`, `C-07` |
| `C-07B` | [#57](https://github.com/kaygdotorg/hermternal/issues/57) | Define session lineage behavior. | `C-01`, `C-05`, `C-07` |
| `C-08` | [#58](https://github.com/kaygdotorg/hermternal/issues/58) | Define chat stream and completion fixtures. | `C-05`, `C-06` |
| `C-09` | [#59](https://github.com/kaygdotorg/hermternal/issues/59) | Define tool lifecycle fixtures. | `C-08` |
| `C-10` | [#60](https://github.com/kaygdotorg/hermternal/issues/60) | Define approval and clarification fixtures. | `C-08` |
| `C-11` | [#61](https://github.com/kaygdotorg/hermternal/issues/61) | Define interruption and recovery fixtures. | `C-06`, `C-08` |
| `C-12` | [#62](https://github.com/kaygdotorg/hermternal/issues/62) | Define active-session model-switch fixtures, including deferred confirmation loss. | `C-08` |
| `C-13` | [#63](https://github.com/kaygdotorg/hermternal/issues/63) | Define the images-only attachment policy. | `C-01` |
| `C-14` | [#64](https://github.com/kaygdotorg/hermternal/issues/64) | Add image preprocessing, progress, cancellation, retry, and failure fixtures. | `C-13` |
| `C-15` | [#65](https://github.com/kaygdotorg/hermternal/issues/65) | Freeze the private deep-link grammar. | `P0-01` |
| `C-16` | [#66](https://github.com/kaygdotorg/hermternal/issues/66) | Define deep-link resolution, lineage, and message-anchor fixtures. | `C-07`, `C-07B`, `C-15` |
| `C-17` | [#67](https://github.com/kaygdotorg/hermternal/issues/67) | Freeze the PTY byte, resize, attach, and close-code contract. | `C-01` |
| `C-18` | [#68](https://github.com/kaygdotorg/hermternal/issues/68) | Add PTY detach, retained-output race, truncation, and expiry fixtures. | `C-17` |
| `C-19` | [#69](https://github.com/kaygdotorg/hermternal/issues/69) | Build the language-neutral contract fixture validator. | `C-02`, `C-02A`, `C-03`, `C-05`, `C-08`, `C-13`, `C-15`, `C-17` |
| `C-20` | [#70](https://github.com/kaygdotorg/hermternal/issues/70) | Add TypeScript contract parity tests. | `C-19` |
| `C-21` | [#71](https://github.com/kaygdotorg/hermternal/issues/71) | Add Swift contract parity tests. | `C-19` |

## M2 — Paper and design proof

| Key | GitHub # | One operation | Dependencies |
| --- | --- | --- | --- |
| `D-01` | [#72](https://github.com/kaygdotorg/hermternal/issues/72) | Add authentication and provider-selection boards. | `C-02`, `C-02A`, `C-03` |
| `D-02` | [#73](https://github.com/kaygdotorg/hermternal/issues/73) | Add loading, empty, streaming, interruption, reconnect, offline, and failure boards. | `C-05`, `C-08`, `C-11` |
| `D-03` | [#74](https://github.com/kaygdotorg/hermternal/issues/74) | Add unsupported-version and compatibility-failure boards. | `C-04`, `C-04A` |
| `D-04` | [#75](https://github.com/kaygdotorg/hermternal/issues/75) | Add session search result boards. | `C-07A` |
| `D-04A` | [#76](https://github.com/kaygdotorg/hermternal/issues/76) | Add deep-link result boards. | `C-16` |
| `D-05` | [#77](https://github.com/kaygdotorg/hermternal/issues/77) | Add image attachment lifecycle boards. | `C-14` |
| `D-06` | [#78](https://github.com/kaygdotorg/hermternal/issues/78) | Add approval and clarification outcome boards. | `C-10` |
| `D-07` | [#79](https://github.com/kaygdotorg/hermternal/issues/79) | Add web Terminal lifecycle boards. | `C-17`, `C-18` |
| `D-08` | [#80](https://github.com/kaygdotorg/hermternal/issues/80) | Add long-transcript and high-rate streaming stress boards. | `C-08` |
| `D-09` | [#81](https://github.com/kaygdotorg/hermternal/issues/81) | Add iPad portrait, landscape, split-view, and Stage Manager boards. | `D-02` |
| `D-10` | [#82](https://github.com/kaygdotorg/hermternal/issues/82) | Add macOS window, sidebar, menu, focus, and reconnect boards. | `D-02` |
| `D-11` | [#83](https://github.com/kaygdotorg/hermternal/issues/83) | Add 200% zoom, localization-growth, and visible-focus boards. | `D-01`, `D-02` |
| `D-12` | [#84](https://github.com/kaygdotorg/hermternal/issues/84) | Add Dynamic Type, VoiceOver, Switch Control, and hardware-keyboard boards. | `D-09`, `D-10` |
| `D-13` | [#85](https://github.com/kaygdotorg/hermternal/issues/85) | Add increased-contrast, reduced-transparency, and reduced-motion boards. | `D-02` |
| `D-14` | [#86](https://github.com/kaygdotorg/hermternal/issues/86) | Publish semantic state, breakpoint, typography, and motion tokens. | `D-01`, `D-02`, `D-03`, `D-04`, `D-04A`, `D-05`, `D-06`, `D-07`, `D-08`, `D-09`, `D-10`, `D-11`, `D-12`, `D-13` |
| `D-15` | [#87](https://github.com/kaygdotorg/hermternal/issues/87) | Publish the Paper artboard-to-implementation manifest. | `D-01`, `D-02`, `D-03`, `D-04`, `D-04A`, `D-05`, `D-06`, `D-07`, `D-08`, `D-09`, `D-10`, `D-11`, `D-12`, `D-13`, `D-14` |

## M3 — deployment and security proof

| Key | GitHub # | One operation | Dependencies |
| --- | --- | --- | --- |
| `DEP-01` | [#88](https://github.com/kaygdotorg/hermternal/issues/88) | Freeze the private network and firewall contract. | `C-01` |
| `DEP-02` | [#89](https://github.com/kaygdotorg/hermternal/issues/89) | Freeze the external method-and-path allowlist. | `C-01` |
| `DEP-03` | [#90](https://github.com/kaygdotorg/hermternal/issues/90) | Prove the source-compatible upstream Host and Origin mapping. | `DEP-01`, `DEP-02`, `C-04`, `C-04A` |
| `DEP-04` | [#91](https://github.com/kaygdotorg/hermternal/issues/91) | Prove the Caddy HTTPS and prefix-routing cases. | `DEP-03` |
| `DEP-05` | [#92](https://github.com/kaygdotorg/hermternal/issues/92) | Prove the Traefik HTTPS and prefix-routing cases. | `DEP-03` |
| `DEP-06` | [#93](https://github.com/kaygdotorg/hermternal/issues/93) | Prove browser provider discovery, cookies, logout, and CSRF boundaries. | `C-02`, `C-02A`, `DEP-04`, `DEP-05` |
| `DEP-07` | [#94](https://github.com/kaygdotorg/hermternal/issues/94) | Prove chat WebSocket ticket creation, query use, rejection, and redaction. | `C-02`, `C-02A`, `DEP-04`, `DEP-05` |
| `DEP-08` | [#95](https://github.com/kaygdotorg/hermternal/issues/95) | Prove native password-provider cookie isolation and ticket creation. | `C-03`, `DEP-04`, `DEP-05` |
| `DEP-09` | [#96](https://github.com/kaygdotorg/hermternal/issues/96) | Prove a source-accepted native OAuth/OIDC callback on a supported platform, and block unsupported or unproven transports. | `C-02`, `C-03` |
| `DEP-10` | [#97](https://github.com/kaygdotorg/hermternal/issues/97) | Prove PTY upgrade, byte transport, detach, reattach, and expiry. | `C-17`, `C-18`, `DEP-04`, `DEP-05` |
| `DEP-11` | [#98](https://github.com/kaygdotorg/hermternal/issues/98) | Prove direct-port denial. | `DEP-01` |
| `DEP-11A` | [#99](https://github.com/kaygdotorg/hermternal/issues/99) | Prove blocked-route no-upstream behavior. | `DEP-02`, `DEP-04`, `DEP-05` |
| `DEP-12` | [#100](https://github.com/kaygdotorg/hermternal/issues/100) | Prove access, error, and malformed-message log redaction. | `DEP-06`, `DEP-07`, `DEP-10` |
| `DEP-13` | [#101](https://github.com/kaygdotorg/hermternal/issues/101) | Compare Caddy and Traefik normalized proof results. | `DEP-04`, `DEP-05`, `DEP-06`, `DEP-07`, `DEP-08`, `DEP-09`, `DEP-10`, `DEP-11`, `DEP-11A`, `DEP-12` |

## M4 — performance foundation

The order is deliberate. Define fixtures and evidence first. Add harnesses second. Measure baselines third. Freeze budgets only after reviewed baseline distributions exist. No issue before `B-08A` invents a final threshold.

| Key | GitHub # | One operation | Dependencies |
| --- | --- | --- | --- |
| `B-01` | [#102](https://github.com/kaygdotorg/hermternal/issues/102) | Define the benchmark evidence format and statistical method. | `C-19` |
| `B-02` | [#103](https://github.com/kaygdotorg/hermternal/issues/103) | Add deterministic transcript workload. | `C-20`, `C-21`, `B-01` |
| `B-02A` | [#104](https://github.com/kaygdotorg/hermternal/issues/104) | Add deterministic stream workload. | `C-20`, `C-21`, `B-01` |
| `B-02B` | [#105](https://github.com/kaygdotorg/hermternal/issues/105) | Add deterministic reconnect workload. | `C-20`, `C-21`, `B-01` |
| `B-02C` | [#106](https://github.com/kaygdotorg/hermternal/issues/106) | Add deterministic PTY workload. | `C-20`, `B-01` |
| `B-03` | [#107](https://github.com/kaygdotorg/hermternal/issues/107) | Scaffold the web production-build benchmark harness. | `B-01` |
| `B-04` | [#108](https://github.com/kaygdotorg/hermternal/issues/108) | Scaffold the Apple release-build benchmark harness. | `B-01` |
| `B-05` | [#109](https://github.com/kaygdotorg/hermternal/issues/109) | Measure the web startup, input, stream, scroll, memory, and bundle baseline. | `B-02`, `B-02A`, `B-03` |
| `B-06` | [#110](https://github.com/kaygdotorg/hermternal/issues/110) | Measure the PTY first-byte, render, echo, resize, retained-output, and memory baseline. | `B-02C`, `B-03` |
| `B-07` | [#111](https://github.com/kaygdotorg/hermternal/issues/111) | Measure Apple launch, resume, stream, scroll, scene, and memory baselines. | `B-02`, `B-02A`, `B-02B`, `B-04` |
| `B-08` | [#112](https://github.com/kaygdotorg/hermternal/issues/112) | Review baseline distributions. | `B-05`, `B-06`, `B-07` |
| `B-08A` | [#113](https://github.com/kaygdotorg/hermternal/issues/113) | Freeze regression budgets. | `B-08` |

## M5 — web client

| Key | GitHub # | One operation | Dependencies |
| --- | --- | --- | --- |
| `W-01` | [#114](https://github.com/kaygdotorg/hermternal/issues/114) | Scaffold the static SvelteKit and Bun application with mock-only network boundaries. | `C-20`, `D-14`, `B-03` |
| `W-02` | [#115](https://github.com/kaygdotorg/hermternal/issues/115) | Implement the compatibility attestation gate. | `C-04`, `W-01` |
| `W-02A` | [#116](https://github.com/kaygdotorg/hermternal/issues/116) | Implement the behavioral-probe gate. | `C-04A`, `W-01` |
| `W-03` | [#117](https://github.com/kaygdotorg/hermternal/issues/117) | Implement provider discovery. | `C-02`, `W-01`, `D-01` |
| `W-04` | [#118](https://github.com/kaygdotorg/hermternal/issues/118) | Implement browser authentication and logout. | `C-02`, `C-02A`, `DEP-06`, `W-03` |
| `W-05` | [#119](https://github.com/kaygdotorg/hermternal/issues/119) | Implement chat WebSocket ticket acquisition. | `DEP-07`, `W-04` |
| `W-06` | [#120](https://github.com/kaygdotorg/hermternal/issues/120) | Implement typed REST transport. | `C-01`, `W-01` |
| `W-07` | [#121](https://github.com/kaygdotorg/hermternal/issues/121) | Implement typed JSON-RPC transport and handshake. | `C-05`, `W-05` |
| `W-08` | [#122](https://github.com/kaygdotorg/hermternal/issues/122) | Implement reconnect and uncertain-delivery recovery. | `C-06`, `W-07` |
| `W-09` | [#123](https://github.com/kaygdotorg/hermternal/issues/123) | Implement session list. | `C-07`, `W-06`, `W-08` |
| `W-09A` | [#124](https://github.com/kaygdotorg/hermternal/issues/124) | Implement session restoration. | `C-07`, `W-06`, `W-08` |
| `W-10` | [#125](https://github.com/kaygdotorg/hermternal/issues/125) | Implement full-text session search. | `C-07A`, `W-09`, `D-04` |
| `W-10A` | [#126](https://github.com/kaygdotorg/hermternal/issues/126) | Implement session lineage resolution. | `C-07B`, `W-09`, `D-04` |
| `W-11` | [#127](https://github.com/kaygdotorg/hermternal/issues/127) | Implement web deep-link parsing and direct-load restoration. | `C-16`, `W-09A`, `D-04A` |
| `W-12` | [#128](https://github.com/kaygdotorg/hermternal/issues/128) | Implement prompt submission. | `C-08`, `W-07`, `D-02` |
| `W-12A` | [#129](https://github.com/kaygdotorg/hermternal/issues/129) | Implement streamed message rendering. | `C-08`, `W-07`, `D-02` |
| `W-13` | [#130](https://github.com/kaygdotorg/hermternal/issues/130) | Implement tool lifecycle rendering. | `C-09`, `W-12A` |
| `W-14` | [#131](https://github.com/kaygdotorg/hermternal/issues/131) | Implement approval decisions. | `C-10`, `W-12`, `W-12A`, `D-06` |
| `W-15` | [#132](https://github.com/kaygdotorg/hermternal/issues/132) | Implement clarification responses. | `C-10`, `W-12`, `W-12A`, `D-06` |
| `W-16` | [#133](https://github.com/kaygdotorg/hermternal/issues/133) | Implement turn interruption and restored stop state. | `C-11`, `W-12`, `W-12A` |
| `W-17` | [#134](https://github.com/kaygdotorg/hermternal/issues/134) | Implement images-only attachment selection and preprocessing. | `C-14`, `D-05`, `W-01` |
| `W-18` | [#135](https://github.com/kaygdotorg/hermternal/issues/135) | Implement image upload progress, cancellation, retry, and failure handling. | `C-14`, `W-17` |
| `W-18A` | [#136](https://github.com/kaygdotorg/hermternal/issues/136) | Attach uploaded images to prompts. | `C-14`, `W-12`, `W-17`, `W-18` |
| `W-19` | [#137](https://github.com/kaygdotorg/hermternal/issues/137) | Implement active-session model selection. | `C-12`, `W-12` |
| `W-20` | [#138](https://github.com/kaygdotorg/hermternal/issues/138) | Implement the Paper-backed responsive workspace. | `D-15`, `W-09`, `W-09A`, `W-12`, `W-12A` |
| `W-21` | [#139](https://github.com/kaygdotorg/hermternal/issues/139) | Implement keyboard and focus behavior. | `D-11`, `W-20` |
| `W-21A` | [#140](https://github.com/kaygdotorg/hermternal/issues/140) | Implement browser zoom behavior. | `D-11`, `W-20` |
| `W-21B` | [#141](https://github.com/kaygdotorg/hermternal/issues/141) | Implement screen-reader behavior. | `D-11`, `W-20` |
| `W-21C` | [#142](https://github.com/kaygdotorg/hermternal/issues/142) | Implement reduced-motion behavior. | `D-13`, `W-20` |
| `W-22` | [#143](https://github.com/kaygdotorg/hermternal/issues/143) | Implement lazy-loaded xterm.js rendering. | `C-17`, `D-07`, `W-01` |
| `W-22A` | [#144](https://github.com/kaygdotorg/hermternal/issues/144) | Implement raw-byte resize transport. | `C-17`, `D-07`, `W-01` |
| `W-23` | [#145](https://github.com/kaygdotorg/hermternal/issues/145) | Implement PTY attach, detach, reattach, retained-output warning, and expiry. | `C-18`, `DEP-10`, `W-22`, `W-22A` |
| `W-24` | [#146](https://github.com/kaygdotorg/hermternal/issues/146) | Add Paper visual-regression coverage for shipped web states. | `D-15`, `W-20`, `W-23` |
| `W-25` | [#147](https://github.com/kaygdotorg/hermternal/issues/147) | Enforce web regression budgets. | `B-08`, `B-08A`, `W-20`, `W-21`, `W-21A`, `W-21B`, `W-21C` |
| `W-25A` | [#148](https://github.com/kaygdotorg/hermternal/issues/148) | Enforce PTY regression budgets. | `B-08`, `B-08A`, `W-22`, `W-22A`, `W-23` |

## M6 — Apple clients

| Key | GitHub # | One operation | Dependencies |
| --- | --- | --- | --- |
| `A-01` | [#149](https://github.com/kaygdotorg/hermternal/issues/149) | Create the shared Swift contract and fixture packages. | `C-21`, `B-04` |
| `A-02` | [#150](https://github.com/kaygdotorg/hermternal/issues/150) | Implement the shared Swift REST transport package. | `C-05`, `A-01` |
| `A-02A` | [#151](https://github.com/kaygdotorg/hermternal/issues/151) | Implement the shared Swift JSON-RPC transport package. | `C-05`, `A-01` |
| `A-03` | [#152](https://github.com/kaygdotorg/hermternal/issues/152) | Implement provider discovery. | `C-02`, `A-02`, `D-01` |
| `A-04` | [#153](https://github.com/kaygdotorg/hermternal/issues/153) | Implement native password-provider authentication and isolated cookie storage. | `C-03`, `DEP-08`, `A-03` |
| `A-05` | [#154](https://github.com/kaygdotorg/hermternal/issues/154) | Implement Keychain lifecycle and logout clearing. | `C-03`, `A-04` |
| `A-06` | [#155](https://github.com/kaygdotorg/hermternal/issues/155) | Implement chat WebSocket ticket acquisition. | `C-03`, `A-04` |
| `A-07` | [#156](https://github.com/kaygdotorg/hermternal/issues/156) | Implement native OAuth/OIDC when source-accepted and platform-proven; block unsupported or unproven transports. | `C-02`, `C-03`, `DEP-09`, `A-03`, `D-01`, `D-03` |
| `A-08` | [#157](https://github.com/kaygdotorg/hermternal/issues/157) | Implement shared reconnect and uncertain-delivery recovery. | `C-06`, `A-02`, `A-02A`, `A-06` |
| `A-09` | [#158](https://github.com/kaygdotorg/hermternal/issues/158) | Implement iOS session list and restoration. | `C-07`, `A-08`, `D-04` |
| `A-09A` | [#159](https://github.com/kaygdotorg/hermternal/issues/159) | Implement iOS deep-link routing. | `C-16`, `A-09`, `D-04A` |
| `A-10` | [#160](https://github.com/kaygdotorg/hermternal/issues/160) | Implement iOS prompt submission. | `C-08`, `A-09`, `D-02` |
| `A-10A` | [#161](https://github.com/kaygdotorg/hermternal/issues/161) | Implement iOS streamed message rendering. | `C-08`, `A-09`, `D-02` |
| `A-11` | [#162](https://github.com/kaygdotorg/hermternal/issues/162) | Implement iOS tool lifecycle rendering. | `C-09`, `A-10A` |
| `A-12` | [#163](https://github.com/kaygdotorg/hermternal/issues/163) | Implement iOS approval decisions. | `C-10`, `A-10`, `A-10A`, `D-06` |
| `A-13` | [#164](https://github.com/kaygdotorg/hermternal/issues/164) | Implement iOS clarification responses. | `C-10`, `A-10`, `A-10A`, `D-06` |
| `A-14` | [#165](https://github.com/kaygdotorg/hermternal/issues/165) | Implement iOS interruption and restored stop state. | `C-11`, `A-10`, `A-10A` |
| `A-15` | [#166](https://github.com/kaygdotorg/hermternal/issues/166) | Implement iOS images-only picker. | `C-13`, `A-10`, `D-05` |
| `A-15A` | [#167](https://github.com/kaygdotorg/hermternal/issues/167) | Implement iOS image upload lifecycle. | `C-14`, `A-10`, `A-15`, `D-05` |
| `A-16` | [#168](https://github.com/kaygdotorg/hermternal/issues/168) | Implement iOS active-session model selection. | `C-12`, `A-10` |
| `A-17` | [#169](https://github.com/kaygdotorg/hermternal/issues/169) | Implement iPad adaptive layout and Stage Manager behavior. | `D-09`, `A-09`, `A-10`, `A-10A` |
| `A-18` | [#170](https://github.com/kaygdotorg/hermternal/issues/170) | Implement iPad keyboard and pointer behavior. | `D-09`, `D-12`, `A-17` |
| `A-18A` | [#171](https://github.com/kaygdotorg/hermternal/issues/171) | Implement iPad multi-window behavior. | `D-09`, `D-12`, `A-17` |
| `A-18B` | [#172](https://github.com/kaygdotorg/hermternal/issues/172) | Implement iPad scene restoration. | `D-09`, `D-12`, `A-17` |
| `A-19` | [#173](https://github.com/kaygdotorg/hermternal/issues/173) | Implement macOS windows, sidebar, and navigation. | `D-10`, `A-09`, `A-10`, `A-10A` |
| `A-20` | [#174](https://github.com/kaygdotorg/hermternal/issues/174) | Implement macOS menus and keyboard commands. | `D-10`, `D-12`, `A-19` |
| `A-20A` | [#175](https://github.com/kaygdotorg/hermternal/issues/175) | Implement macOS focus behavior. | `D-10`, `D-12`, `A-19` |
| `A-20B` | [#176](https://github.com/kaygdotorg/hermternal/issues/176) | Implement macOS deep-link routing. | `C-16`, `D-10`, `D-12`, `A-19` |
| `A-21` | [#177](https://github.com/kaygdotorg/hermternal/issues/177) | Implement VoiceOver and Switch Control behavior. | `D-12`, `D-13`, `A-10`, `A-10A`, `A-17`, `A-18`, `A-18A`, `A-18B`, `A-19`, `A-20`, `A-20A`, `A-20B` |
| `A-21A` | [#178](https://github.com/kaygdotorg/hermternal/issues/178) | Implement Dynamic Type behavior. | `D-12`, `D-13`, `A-10`, `A-10A`, `A-17`, `A-18`, `A-18A`, `A-18B`, `A-19`, `A-20`, `A-20A`, `A-20B` |
| `A-21B` | [#179](https://github.com/kaygdotorg/hermternal/issues/179) | Implement contrast behavior. | `D-12`, `D-13`, `A-10`, `A-10A`, `A-17`, `A-18`, `A-18A`, `A-18B`, `A-19`, `A-20`, `A-20A`, `A-20B` |
| `A-21C` | [#180](https://github.com/kaygdotorg/hermternal/issues/180) | Implement reduced-motion behavior. | `D-12`, `D-13`, `A-10`, `A-10A`, `A-17`, `A-18`, `A-18A`, `A-18B`, `A-19`, `A-20`, `A-20A`, `A-20B` |
| `A-22` | [#181](https://github.com/kaygdotorg/hermternal/issues/181) | Enforce iOS and iPadOS regression budgets. | `B-08`, `B-08A`, `A-17`, `A-18`, `A-18A`, `A-18B`, `A-21`, `A-21A`, `A-21B`, `A-21C` |
| `A-22A` | [#182](https://github.com/kaygdotorg/hermternal/issues/182) | Enforce macOS regression budgets. | `B-08`, `B-08A`, `A-19`, `A-20`, `A-20A`, `A-20B`, `A-21`, `A-21A`, `A-21B`, `A-21C` |

Apple clients do not implement `/api/pty`, direct SSH, Android, Windows, profile aggregation, or an unreviewed OAuth callback. They may implement a native OAuth/OIDC callback only when `DEP-09` proves source acceptance and platform support.

## M7 — release

| Key | GitHub # | One operation | Dependencies |
| --- | --- | --- | --- |
| `R-01` | [#183](https://github.com/kaygdotorg/hermternal/issues/183) | Run TypeScript contract parity. | `C-20`, `W-25`, `W-25A` |
| `R-01A` | [#184](https://github.com/kaygdotorg/hermternal/issues/184) | Run Swift contract parity. | `C-21`, `A-22`, `A-22A` |
| `R-02` | [#185](https://github.com/kaygdotorg/hermternal/issues/185) | Run the pinned disposable Hermes integration suite. | `C-04`, `C-04A`, `DEP-13`, `R-01`, `R-01A`, `W-02`, `W-02A`, `A-07` |
| `R-03` | [#186](https://github.com/kaygdotorg/hermternal/issues/186) | Run the Caddy release deployment suite. | `DEP-13`, `W-25`, `W-25A`, `R-02` |
| `R-04` | [#187](https://github.com/kaygdotorg/hermternal/issues/187) | Run the Traefik release deployment suite. | `DEP-13`, `W-25`, `W-25A`, `R-02` |
| `R-05` | [#188](https://github.com/kaygdotorg/hermternal/issues/188) | Run the cross-platform accessibility matrix. | `W-21`, `W-21A`, `W-21B`, `W-21C`, `A-21`, `A-21A`, `A-21B`, `A-21C`, `R-01`, `R-01A` |
| `R-06` | [#189](https://github.com/kaygdotorg/hermternal/issues/189) | Run the web performance and visual matrix. | `W-24`, `W-25`, `W-25A`, `R-01` |
| `R-06A` | [#190](https://github.com/kaygdotorg/hermternal/issues/190) | Run the Apple performance and visual matrix. | `A-22`, `A-22A`, `R-01A` |
| `R-07` | [#191](https://github.com/kaygdotorg/hermternal/issues/191) | Run the security audit. | `DEP-12`, `R-02`, `R-03`, `R-04` |
| `R-07A` | [#192](https://github.com/kaygdotorg/hermternal/issues/192) | Run the dependency audit. | `R-02`, `R-03`, `R-04` |
| `R-07B` | [#193](https://github.com/kaygdotorg/hermternal/issues/193) | Run the privacy audit. | `DEP-12`, `R-02`, `R-03`, `R-04` |
| `R-07C` | [#194](https://github.com/kaygdotorg/hermternal/issues/194) | Run the redaction audit. | `DEP-12`, `R-02`, `R-03`, `R-04` |
| `R-08` | [#195](https://github.com/kaygdotorg/hermternal/issues/195) | Verify the release proof-gate checklist on one `dev` commit. | `R-03`, `R-04`, `R-05`, `R-06`, `R-06A`, `R-07`, `R-07A`, `R-07B`, `R-07C` |
| `R-09` | [#196](https://github.com/kaygdotorg/hermternal/issues/196) | Promote the verified `dev` commit to `main`. | `R-08` |
| `R-09A` | [#197](https://github.com/kaygdotorg/hermternal/issues/197) | Publish the release record. | `R-09` |
| `R-10` | [#198](https://github.com/kaygdotorg/hermternal/issues/198) | Publish the v0.0.2 deferred backlog. | `P0-03`, `R-09`, `R-09A` |

## Dependency rules

- A hard blocker stops the dependent issue. Do not add an unreviewed route or fallback.
- Shared contracts and required Paper states finish before final user-facing implementation.
- Caddy and Traefik use the same normalized proof cases.
- Baselines precede budgets. Budgets precede enforcement.
- Web and Apple work may proceed in parallel after shared dependencies pass.
- One agent owns one file at a time.
- Every implementation subagent receives one GitHub issue. It completes that issue or creates smaller child issues and delegates them. It leaves a final comment on the assigned issue with current state, completed work, verification results, remaining limitations, and child issue keys.
- Every implementation unit adds regression tests and matching documentation.
- Release issues do not waive failed proof gates.

## Atomic GitHub issue body

Every roadmap issue must contain these sections in this order.

### 1. One operation

State one independently verifiable result.

### 2. Dependencies

List hard blockers by stable key. List soft sequencing separately.

### 3. Exact behavior

Define normal, loading, empty, success, failure, interruption, cancellation, retry, and recovery behavior when applicable.

### 4. Paper evidence

Link the Paper file and exact artboard names. Use `N/A` only for protocol, security, deployment, benchmark, or tooling work, and explain why.

### 5. Contract and tests

Name repository paths, contract versions, fixture IDs, unit tests, component tests, integration tests, parity tests, negative tests, and regression tests.

### 6. Accessibility

Define keyboard, focus, semantic names, screen reader or VoiceOver, Switch Control, Dynamic Type or zoom, contrast, reduced motion, reduced transparency, and touch targets as applicable.

### 7. Benchmark

Name the deterministic fixture, metric, environment, build mode, repetitions, and trace artifact. Before `B-08A`, require baseline evidence. After `B-08A`, name the approved budget.

### 8. Verification commands

List exact reproducible commands and expected artifacts. Use production or release builds for final performance evidence.

### 9. Evidence

Link the pull request, commit SHA, Paper review, fixture diff, test output, accessibility result, benchmark trace, proxy trace, and redaction review as applicable.

### 10. Definition of done

- The one operation is complete.
- Required normal and failure states pass.
- Regression tests exist and pass.
- Matching contracts, comments, and nearby documentation are updated.
- Paper matches the implementation, or the issue records an approved `N/A`.
- Accessibility checks pass where applicable.
- Measured performance evidence is attached; no unsupported claim remains.
- Security and privacy boundaries pass where applicable.
- `rtk diff` is reviewed.
- `code-review-graph update --brief` and change impact review are complete.
- The assigned subagent leaves a final issue comment with the current state, completed work, verification results, remaining limitations, and child issues.
- The focused commit and pull request are reviewed and integrated into `dev`.

An issue is not atomic when it owns separate platform implementations, unrelated route families, or proof gates that can merge independently. Split it before implementation.

## Exclusions

Do not create v0.0.1 implementation issues for Dashboard administration, direct `~/.hermes` access, direct SSH, arbitrary file uploads, a local transcript mirror, profile aggregation, Apple Terminal, Android, Windows, production telemetry, signing, app-store submission, user-facing sharing, or an upstream Hermes callback extension.
