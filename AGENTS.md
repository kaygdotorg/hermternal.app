# hermternal.app agent guide

## current phase

this repository is the monorepo for the eventual hermternal product, but the current phase is planning and high-fidelity UI prototyping only.

allowed now:

- product briefs, user journeys, information architecture, and architecture decision records
- static and interactive UI mockups
- design tokens, prototype-only components, animation experiments, and mock data
- accessibility and performance experiments that support mockups
- prototype tests and visual regression checks

not allowed now unless explicitly approved:

- Hermes gateway integration or production API calls
- production authentication, secrets, provider credentials, or deployment configuration
- app-store release work, signing, telemetry, or live user data
- irreversible infrastructure changes

## supported platforms

build for web, iOS, iPadOS, and macOS.

do not spend design, implementation, test, or CI effort on Android or Windows unless the user explicitly changes scope.

web is a first-class product, not a fallback client. iOS and iPadOS are native SwiftUI products. macOS follows the same Apple-platform architecture once the shared interaction model is proven.

## product principles

### speed is a product requirement

make the application feel immediate. measure and protect interaction latency, startup cost, render cost, animation smoothness, memory use, network round trips, and bundle size.

prefer a simpler architecture when it makes the product materially faster. do not add polling, large dependencies, unnecessary client state, blocking transitions, or speculative abstraction.

use budgets and real measurements before optimizing. avoid performance claims without a reproducible measurement or profiling result.

### polish is also a product requirement

visual finesse is not optional. interactions must communicate state through typography, spacing, motion, feedback, and hierarchy.

micro-interactions and animations must have intent, clear timing, interruption behavior, loading states, error states, and reduced-motion behavior. motion must not block input, delay useful content, or create jank.

never trade visual quality for raw performance without documenting the user-visible cost and getting approval. never trade responsiveness for decorative effects. find an implementation that preserves both whenever feasible.

### native Apple capabilities matter

make first-class use of Apple platform features where they improve the product:

- Spotlight indexing and deep links
- Siri and App Intents
- accessibility, including VoiceOver, Dynamic Type, Switch Control, contrast, and reduced motion
- keyboard shortcuts, focus behavior, menus, and multi-window workflows on iPadOS and macOS
- haptics, notifications, share sheets, drag and drop, camera, and image pickers when relevant
- offline-friendly drafts and predictable background refresh behavior

native features belong in the product design from the beginning. do not postpone accessibility or platform integration as cleanup work.

## engineering workflow

### orchestrate through subagents

The main agent is the orchestrator. It owns planning, prioritization, task decomposition, scheduling, coordination, review of returned work, handling completed or blocked agents, and user communication.

Delegate execution work to subagents whenever an agent slot is available. Execution work includes implementation, design editing, documentation editing, tests, benchmarks, repository inspection for a delegated task, and other artifact-producing operations. Give each subagent a focused task, explicit file or surface ownership, applicable issue context, required checks, and a clear handoff format.

Do not let completed subagents wait while the main agent performs execution work. Review their results promptly, resolve blockers, and assign the next independent work item. Keep independent lanes active in parallel without violating one-agent-per-file ownership.

The main agent may perform execution work directly only when delegation is unavailable, rejected by the harness, or would materially block urgent progress. State the reason, keep the direct change narrow, and return to orchestration as soon as capacity is available. Independent review requirements still apply; direct work must not be self-approved or self-merged.

### read and index efficiently

always use `rtk` for repository navigation, file reading, search, git inspection, diffs, dependency inspection, builds, linting, and tests when an rtk command exists.

always use `code-review-graph` for code understanding and change analysis:

1. run `code-review-graph build` before working in an unindexed repository.
2. use graph search, architecture, flow, query, or impact commands before changing unfamiliar code.
3. run `code-review-graph update --brief` after edits.
4. use `code-review-graph detect-changes` or `impact` before review and handoff.

keep graph data local and do not enable cloud embeddings without explicit approval. source-derived code must not be sent to an embedding provider by default.

### document with every change

no code change is complete without an inline documentation update in the same change set.

- add or update comments where a decision, invariant, performance constraint, platform limitation, or non-obvious tradeoff needs explanation.
- document why, not a line-by-line restatement of what the code does.
- update nearby README, architecture notes, component documentation, protocol documentation, or code examples when behavior or design intent changes.
- keep comments and docs accurate as code evolves. remove stale commentary.
- prototypes must state clearly which data, interactions, and integrations are mocked.

### quality gates

before reporting a change complete:

1. inspect the diff with `rtk diff`.
2. update the code-review graph and review change impact.
3. run the narrowest relevant formatter, typecheck, tests, and visual or accessibility checks.
4. verify keyboard use, screen-reader semantics, Dynamic Type or browser zoom, color contrast, loading, empty, and error states for any user-facing change.
5. report actual command results and remaining limitations. do not claim unrun checks passed.

## UI prototype standards

prototype interfaces must be responsive across desktop web, narrow web, iPhone, and iPad form factors. use mock data that represents realistic long sessions, streaming states, tools, approvals, attachments, errors, and empty states.

create reusable semantic design tokens before duplicating visual values. share design intent, token names, interaction specifications, and fixtures between web and Apple prototypes. do not attempt to share UI implementation across Svelte and SwiftUI.

for every non-trivial screen or interaction, define:

- purpose and primary user action
- information hierarchy
- idle, hover, pressed, focused, disabled, loading, empty, success, and failure states where applicable
- animation intent, duration range, interruption behavior, and reduced-motion alternative
- accessibility labels, focus order, and keyboard behavior
- performance risks and how the prototype avoids them

### shared pill interaction contract

use one semantic, reusable pill primitive for title controls, workspace modes, selected sessions, approvals, artifact actions, and other compact controls. variants may be icon-only, icon-first with a revealed label, compound, or selected. controls that only look similar must also share input, motion, accessibility, and sizing behavior.

- use a full capsule radius for pills. use the shared radius token instead of a local literal.
- keep the combined icon and label group optically centered. reserve a fixed-width icon slot so labels do not shift the icon.
- use a minimum 44×44 css px effective target on web touch and hybrid layouts. a visible shell may be 32–40px inside that target. size text controls to their content plus padding; do not force a 44px width.
- on fine pointers, support Calternal-style magnetic movement. cap drift, update only compositor-friendly `translate`, and reset cleanly on pointer leave or cancel.
- on repeated press, restart the Dynamic-Island-style scale pulse from the current rendered state. compose scale feedback with magnetic translation so one effect does not replace the other.
- respond on pointer down. do not block input while motion settles. every transition must be immediate, interruptible, and reversible.
- touch activation must not depend on hover. do not leave a pill expanded after touch input.
- keyboard focus must expose the same label and state information as pointer hover. support Enter and Space where the control role requires them.
- give icon-only controls an accessible name and tooltip. do not rely on icon shape, color, tick count, or motion alone.
- reduced motion disables magnetic drift and bounce. retain immediate static press, focus, and selected feedback.
- when text grows, preserve target size and legibility. widen, reflow, stack, or move secondary actions to overflow. do not shrink text or targets to solve clipping.
- test narrow widths, 200% browser zoom, larger text, localization, pointer cancel, rapid repeat presses, and focus transfer.

Paper mockups must show the relevant resting, hover, focused, pressed, expanded, selected, and open states as separate static states. Paper does not prove runtime interaction behavior. implement and verify motion only in a later local prototype with mocked data and no production integration.

use selected pill material only for persistent state, such as the active conversation or workspace mode. `New chat` is an action and must never appear selected. the conversation title pill enters editing immediately; on mobile, center the editor above a dimmed, blurred background and show the keyboard state.

### Paper design source of truth

Paper file [`01KZ6BB66KCWR2C4J2TSWQGDM7`](https://app.paper.design/file/01KZ6BB66KCWR2C4J2TSWQGDM7/1-0) is the visual source of truth for Hermternal screens and component states.

- inspect the relevant Paper artboard with Paper MCP before implementing or changing a user-facing screen.
- use Paper MCP structure, computed styles, tokens, and image assets for exact implementation values. do not estimate values from screenshots.
- implement each designed resting and interaction state represented by the relevant artboards. verify responsive behavior against the desktop and narrow artboards and their light and dark variants.
- if a visual or interaction design must change, update the Paper design first. review the changed artboard, then implement the approved Paper state in code.
- do not introduce an intentional visual deviation only in code. document necessary platform adaptations in Paper and in the nearby implementation documentation.
- runtime behavior that Paper cannot prove, including motion, focus transfer, keyboard behavior, loading, error recovery, and reduced motion, must follow the interaction contracts in this guide and be verified in the local prototype.

## collaboration and git discipline

### branch model and releases

this repository has exactly two permanent branches:

- `dev` is the integration branch. all planning, mockup, feature, fix, and documentation work lands here first.
- `main` contains only release-ready, working builds promoted from `dev`. do not develop directly on `main`.

use short-lived focused branches or worktrees from `dev` for concurrent work. merge or fast-forward completed atomic work into `dev`. promote only a verified, releasable `dev` commit to `main`.

release versions use `vYYYY.MM.DD.<patch-num>`, for example `v2026.08.01.1`. increment `patch-num` for every additional release on the same calendar date. create a matching annotated git tag only when a release is promoted to `main`.

### agent instruction and skill links

`CLAUDE.md` must always be a relative symlink to the root `AGENTS.md` file. maintain one source of truth for project instructions.

if project-specific agent skills are ever added under `.agents/`, `.claude/` must be a relative symlink to `.agents/`. do not create either directory until project-specific skills are actually needed.

work in focused branches or worktrees. one agent owns a file at a time. do not overwrite another agent's uncommitted work.

keep commits small and coherent. use conventional commits in the form `type(scope): description`. every completed atomic work unit must be committed and pushed. a commit must include its matching code comments and documentation updates. do not commit secrets, generated credentials, live transcripts, API keys, signing assets, or user data.

when instructions conflict, preserve the current planning-only scope and ask for clarification before introducing live integrations or infrastructure changes.
