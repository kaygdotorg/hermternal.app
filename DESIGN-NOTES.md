# Redesign working notes

## Command / inspect plan

Hermternal is a thinking instrument for people shaping work with an assistant. The primary action is to issue or refine a command; the primary reading task is to inspect the assistant's reasoning trail, tool state, and draft without losing the conversation.

```text
desktop / tablet
┌ compact floating history ┐   ┌──────── one chrome-rimmed conversation instrument ────────┐
│ current work             │   │ title + session state                                      │
│ recent threads           │   │  ┃ prompt                                                   │
│                          │   │  ┣ response                                                  │
│ appearance + profile     │   │  ┣ tool / approval / streaming states                       │
└──────────────────────────┘   │  ┗ material composer: context ← prompt → model / voice / send│
                               └─────────────────────────────────────────────────────────────┘

mobile
┌ top bar ┐  →  sidebar moves behind a dim scrim
┌ one edge-conscious conversation instrument ┐
│ signal rail + transcript                    │
│ composer follows normal content flow        │
└─────────────────────────────────────────────┘
```

- **Palette:** Night Ink `#0b0e13`, Moon Graphite `#151a22`, Frost `#eef2f7`, Lunar Blue `#72a7ff`, Quiet Slate `#8f99a8`, and positive Mint `#79c6a3`.
- **Type:** the Apple/system UI stack for controls and prose; a restrained New York-like `ui-serif` treatment only for the assistant's key editorial statement.
- **Layout:** the sidebar is a small physical object; the conversation is one continuous shell with a narrow signal rail and no nested dashboard.
- **Signature:** a luminous vertical signal rail makes the transcript read like an inspectable execution trace while preserving conversational warmth.
- **Motion:** frequent controls only press or shift by a pixel; occasional menus and the mobile drawer use short origin-aware transform/opacity transitions. Pointer-only magnetic movement is computed from cursor position and returns with a critically damped CSS curve.

Self-critique before build: a dark surface with blue could become a familiar developer-tool trope. The rail therefore encodes actual conversation state, the assistant prose gets editorial contrast, and the shell uses asymmetric chrome detailing instead of neon glow or gradient decoration.
