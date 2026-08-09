# D-12/D-13 accessibility input matrix

**Status:** normative planning input only. This document does not complete D-12, D-13,
`G-09`, or `G-14`, and it does not mark a release gate complete.

**Scope:** D-12 / [#84](https://github.com/kaygdotorg/hermternal/issues/84), D-13 /
[#85](https://github.com/kaygdotorg/hermternal/issues/85), and their D-11 / [#83](https://github.com/kaygdotorg/hermternal/issues/83)
zoom, localization-growth, and visible-focus inputs.

**Reviewed source snapshot:** `origin/dev` at
`c59b5bcdaa1978d6e5c77cccaa31770ce0a82723`.

**Paper source of truth:** [Hermternal Paper file](https://app.paper.design/file/01KZ6BB66KCWR2C4J2TSWQGDM7/1-0).
No Paper manifest, artboard, Apple implementation file, workspace component, or
accessibility test is changed by this document.

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
normative. “Mocked web evidence” means a checked-in local preview or browser test
using synthetic data. It is useful scaffold evidence, but it is not a VoiceOver,
Switch Control, device, production, or release result.

## 1. Decision and evidence boundary

Hermternal has two UI implementation families:

- **Web:** static Svelte preview and client. The web column below covers desktop
  and narrow browser layouts, including Safari when the web client is used on an
  iOS or iPadOS device.
- **Apple:** separate native SwiftUI clients for iOS, iPadOS, and macOS. The
  Apple columns do not inherit web DOM, ARIA, CSS-media, or Playwright evidence.

The current checkout contains existing mocked web evidence and no Apple runtime
implementation. [`apps/apple/README.md`](../../apps/apple/README.md) states that
Apple is still in the planning, mock, and proof phase and has no Xcode project,
Swift package, signing configuration, credential, or live Hermes call. Apple
runtime evidence is therefore **missing**, not N/A.

The checked-in web Paper manifest is also not runtime proof. Its Terminal
accessibility record is explicitly static-only, and the manifest says Paper does
not prove runtime interaction, focus transfer, motion, continuity, or error
recovery. The current web manifest validator reports `evidence_status: blocked`
on this source snapshot, so the checked-in manifest is not a validation pass.
See [`contracts/design-tokens/web/README.md`](../../contracts/design-tokens/web/README.md)
and [`contracts/design-tokens/web/artboards.json`](../../contracts/design-tokens/web/artboards.json).

`G-09` remains an unchecked scaffold gate for accessibility design inputs, and
`G-14` remains an unchecked integration gate for the cross-platform accessibility
and performance matrix. This matrix supplies the input and the evidence contract;
it is not the evidence record for either gate.

## 2. Applicability matrix

| Input | Web | iOS | iPadOS | macOS |
| --- | --- | --- | --- | --- |
| Keyboard and focus order | **Required.** Mocked Tab, focus, modal return, and focus-order evidence exists. Runtime keyboard and shipped-workflow proof remain open. | **Required.** Native focus order and focus restoration are missing. | **Required.** Native focus order plus split-view, Stage Manager, pointer, and hardware-keyboard traversal are missing. | **Required.** Native window, sidebar, menu, command, and focus behavior are missing. |
| Semantic names | **Required.** Mocked roles, names, labels, live states, and Axe checks exist. No screen-reader runtime result is claimed. | **Required.** SwiftUI accessibility labels, values, traits, and state announcements are missing. | **Required.** Same as iOS, including pointer and multi-window surfaces; missing. | **Required.** Native window, menu, command, sidebar, and control names are missing. |
| Browser zoom | **Required for the web target.** Existing tests use the 640 CSS-pixel reflow equivalent for 200% zoom. | **N/A to the native app.** Dynamic Type and system text-size evidence apply instead. Safari use of the web target remains covered by the Web column. | **N/A to the native app.** Dynamic Type, split view, and Stage Manager evidence apply instead. Safari use of the web target remains covered by the Web column. | **N/A to the native app.** Native text-size and window-resize evidence apply instead. Browser use of the web target remains covered by the Web column. |
| Touch targets | **Required in touch and hybrid layouts.** Existing mocked checks enforce an effective 44 × 44 CSS-pixel target. | **Required.** Native controls MUST preserve an effective 44 × 44 point target; missing. | **Required.** Native touch and pointer controls MUST preserve an effective 44 × 44 point target; missing. | **Not applicable to a pointer-only native surface.** If a touch or hybrid surface is introduced, the 44 × 44 target rule applies; no native surface exists today. |
| Localization growth | **Required.** A mocked long localized focus label is checked; broad locale coverage is not proven. | **Required.** Long labels, Dynamic Type, and reflow are missing. | **Required.** Long labels across portrait, landscape, split view, and Stage Manager are missing. | **Required.** Long labels across windows, sidebars, menus, and commands are missing. |
| VoiceOver / screen reader | **Required.** Axe and semantic assertions are mocked web evidence only; no VoiceOver or browser assistive-technology session is recorded. | **Required.** VoiceOver traversal, names, values, hints, focus restoration, and state announcements are missing. | **Required.** VoiceOver traversal across split view, Stage Manager, and keyboard focus changes is missing. | **Required.** VoiceOver traversal across windows, sidebar, menus, and command surfaces is missing. |
| Switch Control | **Required for the web client on supported touch devices.** Semantic and keyboard proxies exist; no Switch Control scan or activation evidence exists. | **Required.** Switch scanning, grouping, activation, and recovery are missing. | **Required.** Switch scanning with split view, Stage Manager, and hardware keyboard is missing. | **Required where the macOS assistive-control path applies.** Native switch navigation and activation are missing. |
| Dynamic Type | **Not a native web setting.** The web equivalent is browser zoom and text/localization growth. | **Required.** All relevant chat, auth, loading, empty, success, failure, and interruption states are missing at accessibility text sizes. | **Required.** The same states are missing at accessibility text sizes and in constrained layouts. | **Required.** Native text-size and window reflow evidence is missing. |
| Hardware keyboard | **Required for desktop and hybrid web use.** Tab/Space and focused activation are mocked; hardware-device and IME proof is missing. | **Required where an external keyboard is supported.** Key commands, focus traversal, text entry, repeat, and cancellation are missing. | **Required.** Keyboard commands, focus traversal, pointer/trackpad handoff, text entry, repeat, and cancellation are missing. | **Required.** Full keyboard navigation, menus, commands, focus scopes, and text entry are missing. |
| Increased contrast | **Required as the web forced-colors/high-contrast equivalent.** A mocked `forced-colors: active` focus/chrome check exists; OS/browser assistive-technology proof is missing. | **Required.** Increase Contrast rendering and focus visibility are missing. | **Required.** Increase Contrast rendering in split and Stage Manager layouts is missing. | **Required.** Increase Contrast rendering for windows, menus, sidebar, and focus rings is missing. |
| Reduced transparency | **Required.** A mocked `prefers-reduced-transparency` test checks opaque materials without blur or saturation. | **Required.** Native material fallback and hierarchy are missing. | **Required.** Native material fallback across split and Stage Manager is missing. | **Required.** Native material fallback across windows, sidebar, and menus is missing. |
| Reduced motion | **Required.** Mocked `prefers-reduced-motion` checks disable transition duration and exercise reduced-motion UI paths. Runtime frame/input and interruption evidence remain open. | **Required.** Native animation removal or reduction, immediate feedback, and interruption recovery are missing. | **Required.** The iPad gesture, split-view, and Stage Manager motion alternatives are missing. | **Required.** Window, sidebar, menu, focus, and reconnect motion alternatives are missing. |

A required row is not satisfied by a screenshot, a status code, a copied claim, or
an automated result from another platform. Each platform needs its own evidence
for the controls and states it implements.

## 3. Required state matrix

Every applicable input above MUST be checked in each state that the workflow can
reach. The shared product specification requires clear loading, empty, focused,
disabled, success, failure, reconnecting, and expired-session states; D-12 and D-13
also require pending, interruption/cancellation, and safe recovery handling. See
[`docs/product/v0.0.1.md`](v0.0.1.md).

| State | Normative requirement | Existing mocked web evidence | Apple evidence still required |
| --- | --- | --- | --- |
| Idle / resting | The first reachable control, reading order, names, state values, and available actions MUST be stable and visible. | Root and `/ui-preview` fixtures expose resting controls; Playwright checks roles, names, focus, and layout. | iOS, iPadOS, and macOS native reading order, initial focus, names, and available actions are missing. |
| Loading / pending | Pending work MUST be announced or otherwise exposed without presenting success. Controls that cannot act MUST be disabled without losing their name or focus context. | Provider and transport fixtures describe pending/loading states; `test:a11y` covers the root shell in reduced motion, light, and dark. | Native pending announcements, disabled semantics, progress treatment, and focus behavior are missing on all three Apple targets. |
| Empty | An empty fixture or no-result state MUST have a meaningful heading/status, an actionable next step where applicable, and no dead focus stop. | Axe covers root `empty`; component and preview fixtures cover empty provider/session paths. | Native empty-state names, VoiceOver/Switch Control traversal, Dynamic Type reflow, and contrast/motion variants are missing. |
| Success / ready | Success MUST expose the resulting content and the next valid actions without stealing focus unexpectedly. | Axe covers root `success`; `/ui-preview` has ready/runtime fixtures and keyboard activation checks. | Native success announcement, focus retention or transfer, and state-specific Apple evidence are missing. |
| Failure | Failure MUST expose a semantic error/status, preserve safe state, and provide a named retry or recovery action when valid. | Axe covers root `failure`; preview tests exercise compatibility failure and retry/return actions. | Native error announcement, retry focus, contrast, text growth, and assistive-control recovery are missing. |
| Interruption / cancellation | Cancellation MUST be visible, idempotent, and safe. It MUST NOT duplicate prompts, sessions, credentials, tickets, or outward-facing changes. | The web README records pending-to-cancelled-to-retry and stale-result-safe fixtures; preview tests exercise cancellation paths. | Native cancellation announcement, focus return, duplicate-prevention, and VoiceOver/Switch Control recovery are missing. |
| Reconnecting / expired session | Reconnect and expiry MUST expose current status, prevent unsafe duplicate actions, and restore focus to a valid control. | The web preview and transport README describe reconnect/failure/expired boundaries; runtime proof remains mock-only. | Native lifecycle, reconnect, expiry, focus restoration, and reduced-motion/transparency evidence are missing. |
| Focused / disabled / selected | Focus MUST remain visible and names MUST remain available when a control is focused, disabled, selected, pressed, or expanded. | Playwright checks visible focus, modal focus loops, `aria-modal`, inert underlays, `aria-expanded`, labels, and 44-pixel targets. | Native focus rings/indicators, traits, disabled/selected values, and focus-scope behavior are missing. |

## 4. Existing mocked web evidence

The following evidence exists in the current web scaffold. It MUST be reported as
mocked or static evidence, not as a release pass.

### 4.1 Exact commands

Run from `apps/web` after the pinned Bun install described in
[`apps/web/README.md`](../../apps/web/README.md):

```sh
bun run test:a11y
bun run test:e2e -- tests/e2e/prototype-shell.spec.ts --grep 'Tab and Space|200% browser zoom|reduced-motion'
bun run test:e2e -- tests/e2e/ui-preview.spec.ts --grep 'long localized|effective target|reduced-transparency|forced-colors|200% browser-zoom|axe violations'
bun run test:static
```

`bun run test:a11y` is the checked-in package command. It runs
`tests/e2e/accessibility.spec.ts`, the accessibility portions of
`tests/e2e/ui-preview.spec.ts`, and the terminal renderer lane selected by the
`axe violations` grep. The focused commands above name the existing tests without
editing them.

Run from the repository root for the static Paper contract:

```sh
python3 contracts/design-tokens/web/validate.py
python3 -O contracts/design-tokens/web/validate.py
python3 contracts/design-tokens/web/test_validate.py
python3 -O contracts/design-tokens/web/test_validate.py
```

### 4.2 Exact checked-in evidence and limits

| Evidence | What it currently demonstrates | What it does not demonstrate |
| --- | --- | --- |
| `apps/web/tests/e2e/accessibility.spec.ts` | Axe has no reported violations for root `success`, `empty`, and `failure` fixtures in light/dark with reduced motion emulated. | It is not a VoiceOver, Switch Control, hardware keyboard, Apple, production, or release test. |
| `apps/web/tests/e2e/prototype-shell.spec.ts` | Tab and Space activation, visible focus, effective target sizing, 640 CSS-pixel 200% zoom reflow, and computed reduced-motion behavior. | It is not physical keyboard/IME, screen-reader, device, or native Apple evidence. |
| `apps/web/tests/e2e/ui-preview.spec.ts` | Long localized focus labels, modal focus return and loops, `aria` state semantics, 44-pixel targets, reduced transparency, forced colors, 200% reflow, reduced motion, and preview Axe branches. | It is a local fixture preview; it does not prove a shipped workflow or an assistive-technology session. |
| `contracts/design-tokens/web/artboards.json` | The checked-in web Paper inventory records static Terminal accessibility coverage; the current validator reports `evidence_status: blocked` on this source snapshot. | `paper_static_only` remains true; static boards do not prove runtime focus transfer, motion, continuity, or recovery. |
| Playwright output | The configured `list` reporter and failure traces provide run output; `apps/web/playwright.config.ts` sets `trace: 'retain-on-failure'`. | No artifact is a release gate unless the exact run, source, environment, and raw result are retained and reviewed. |

The current web preview uses local synthetic fixtures and no external Hermes,
provider, credential, transcript, or user-data integration. The web README
explicitly calls these checks scaffold evidence and says they do not prove that a
future Runtime or Authentication screen is ready to ship.

## 5. Missing Apple and runtime evidence

No Apple runtime evidence can be collected from the current origin/dev checkout:
`apps/apple/` contains only its planning README, with no Xcode project, Swift
package, scheme, native UI, or test target. Therefore the current Apple command
for each platform is exactly **N/A — implementation and runtime harness do not
exist**. This is a missing prerequisite, not an accessibility waiver.

When the Apple implementation is approved, the owning Apple issues MUST replace
that N/A with an exact `xcodebuild test` command containing a concrete scheme,
destination, source revision, and result-bundle path. Each platform MUST retain at
least these artifacts:

- `ios-accessibility.xcresult` for iOS;
- `ipados-accessibility.xcresult` for iPadOS;
- `macos-accessibility.xcresult` for macOS;
- a reviewed manual VoiceOver and Switch Control checklist for each applicable
  state;
- Dynamic Type or native text-size screenshots for idle, loading, empty, success,
  failure, interruption, reconnecting, and expired states;
- increased-contrast, reduced-transparency, and reduced-motion screenshots or
  recordings for the same applicable states;
- hardware-keyboard/focus-order evidence for iPadOS and macOS, plus iOS external
  keyboard coverage where supported; and
- an approved performance record in the shared B-01 shape, including raw samples,
  environment, build mode, distribution, and trace/artifact hashes.

The artifact names above are required names for the evidence record, not files that
exist today. A future command or artifact MUST NOT be described as passed until it
is produced from the real Apple target and reviewed.

## 6. Evidence contract by input

The following is the minimum evidence package for a future cross-platform review.
The web entries identify existing mocked commands; the Apple entries are explicit
open work.

| Input | Web evidence command and artifact | iOS / iPadOS / macOS evidence required |
| --- | --- | --- |
| Keyboard and focus order | `bun run test:e2e -- tests/e2e/prototype-shell.spec.ts --grep 'Tab and Space'` and the focused `ui-preview.spec.ts` run; retain Playwright output and any failure trace under `apps/web/test-results/`. | Native focus traversal and restoration in each `.xcresult`; manual keyboard/VoiceOver/Switch Control checklist; iPadOS split/Stage Manager and macOS window/menu focus cases. |
| Semantic names | `bun run test:a11y`; retain Axe output for success, empty, and failure plus the preview test output. | Accessibility Inspector/VoiceOver review recorded in each `.xcresult` and checklist, covering names, roles/traits, values, hints, state changes, and live announcements. |
| Browser zoom / Dynamic Type | Web focused `prototype-shell.spec.ts` and `ui-preview.spec.ts` zoom/reflow commands; retain viewport and overflow assertions plus Paper manifest validation. | Native Dynamic Type/text-size run in each `.xcresult`, with screenshots and no-clipping/reflow observations. Native Apple apps do not substitute browser zoom. |
| Touch targets | Focused `ui-preview.spec.ts` target command; retain the assertion output and any failure trace. | 44 × 44 point measurement evidence in iOS/iPadOS `.xcresult` and screenshots. macOS is N/A unless a touch/hybrid surface is introduced. |
| Localization growth | Focused `ui-preview.spec.ts` `long localized` command; retain the run output and long-label screenshot if a review attaches one. | Long-locale fixture and screenshots in each native result bundle, including constrained iPadOS and macOS window/sidebar/menu layouts. |
| VoiceOver / Switch Control | Existing web Axe/semantic commands are only proxies; no current runtime artifact is claimed. | Manual VoiceOver and Switch Control checklist plus native result bundle for every applicable state and recovery path. |
| Hardware keyboard | Focused `prototype-shell.spec.ts` Tab/Space command and preview keyboard tests; retain output. | iOS external-keyboard evidence where supported, required iPadOS hardware-keyboard/pointer evidence, and macOS full keyboard/menu/command evidence. |
| Increased contrast | Focused `ui-preview.spec.ts` `forced-colors` command; retain computed style/focus assertions. | Native Increase Contrast result bundle and screenshots for all applicable states. |
| Reduced transparency | Focused `ui-preview.spec.ts` `reduced-transparency` command; retain computed opaque-material assertions. | Native reduced-transparency result bundle and screenshots for all applicable states. |
| Reduced motion | Focused `prototype-shell.spec.ts` and preview `200% browser-zoom`/reduced-motion command; retain media-query and transition assertions. | Native reduced-motion result bundle, interruption/recovery checklist, and evidence that no background animation remains. |

A passing web command does not populate the Apple column. A future cross-platform
record MUST preserve this distinction.

## 7. Performance risks and required measurements

Accessibility behavior can change input latency, layout cost, paint cost, memory,
and announcement volume. The following risks MUST be reviewed with measured
synthetic or local evidence; no threshold is invented here.

| Risk | Relevant inputs and states | Required observation |
| --- | --- | --- |
| Focus and layout thrash | Keyboard/focus, zoom, localization, Dynamic Type; idle, loading, failure, interruption | Measure key-to-focus/action latency and layout/reflow cost after text-size or viewport changes. Check long transcripts and rapid state changes. |
| Accessibility-tree churn | Semantic names, VoiceOver, Switch Control; streaming, reconnecting, failure | Coalesce status changes without hiding state. Measure render work, memory, and announcement/event volume during high-rate streaming and recovery. |
| Oversized hit regions and overlap | Touch targets, pointer/hybrid controls; idle, focused, expanded, modal | Measure pointer/gesture latency and scroll performance. Ensure larger targets do not steal adjacent control events or change focus order. |
| Contrast and material fallback | Increased contrast, forced colors, reduced transparency; all visible states | Check paint/frame behavior when blur, saturation, shadows, or material layers are removed. Verify focus remains visible without relying on color alone. |
| Motion cancellation and residual work | Reduced motion; loading, reconnect, interruption, modal open/close | Verify animation timers, gesture loops, and delayed focus work stop or settle immediately. Measure CPU/frame work after a cancellation or preference change. |
| Keyboard and IME handling | Hardware keyboard, text entry, repeat, localization; composer and title editor | Measure key-to-edit/action latency and repeated-key behavior. Ensure keyboard input cannot duplicate submissions or bypass pending ownership. |
| Native accessibility and window complexity | VoiceOver, Switch Control, Dynamic Type, contrast, transparency; iPadOS split/Stage Manager and macOS windows/menus | Record release-build UI-test and Instruments evidence per platform. Do not infer native performance from web Playwright timing. |

The shared [B-01 benchmark contract](../../contracts/benchmarks/README.md) requires
raw samples, a reviewed environment, source and fixture identity, build mode,
artifact hashes, and at least 30 samples per run. Web final evidence uses
`build_mode: "production"`; iOS, iPadOS, and macOS use `build_mode: "release"`.
`threshold` and `budget` remain `null` until a later review approves a budget.
The existing checked-in benchmark fixtures are synthetic and do not prove these
product measurements.

## 8. Review checklist and non-claims

Before this input matrix can become a gate evidence record, the owning issue MUST
link:

1. the reviewed Paper board set for each applicable platform and state;
2. the exact web run output and retained artifacts, clearly labelled mocked;
3. one native Apple result bundle and manual assistive-technology record per
   supported platform;
4. the shared B-01 performance record and raw traces, without inventing a budget;
5. negative evidence for missing, malformed, denied, interrupted, expired, and
   incompatible states where the workflow can reach them; and
6. the review SHA, environment, commands, artifact hashes, and remaining limits.

Until those records exist, the following claims are prohibited:

- D-12 or D-13 is complete;
- `G-09` or `G-14` is complete;
- web mock or Paper evidence proves VoiceOver, Switch Control, Dynamic Type,
  hardware keyboard, or native Apple behavior;
- Apple runtime behavior exists in this checkout; or
- a performance observation is an approved product budget.

This document is intentionally standalone so it can be reviewed without editing
active Paper manifests, artboards, tests, workspace components, live files, or
Apple implementation files.
