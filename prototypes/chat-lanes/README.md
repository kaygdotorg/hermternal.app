# Hermternal chat lanes

This directory is an isolated, web-only design exploration. It compares three complete conversation compositions while holding geometry, typography, materials, content, interactions, and responsive behavior constant:

- **Canvas** keeps assistant prose open and reserves surfaces for authored input and operational states.
- **Stacks** groups each prompt, response, tool event, and approval into one turn boundary.
- **Focus** narrows the reading measure and quiets secondary metadata on fine pointers.

Use the bottom picker, number keys `1`–`3`, or left/right arrow keys to switch instantly. The picker selection is stored in the `?v=` URL parameter.

## Run

From the repository root:

```sh
python3 -m http.server 33918 --bind 0.0.0.0 --directory prototypes/chat-lanes
```

The prototype has no build step and no runtime dependency. It loads no remote fonts, images, scripts, or data.

## Shared design constraints

The three surfaces use one derived radius scale (`12px`, `18px`, `26px`), the platform system typeface at weights 400/500/600, and one material recipe shared by the sidebar and composer. Ten popular color fixtures change semantic tokens only: System, Nord, Dracula, Gruvbox, Solarized, Catppuccin, Tokyo Night, Rosé Pine, One Dark, and Monokai.

Controls meet a 44 CSS-pixel target. The navigation becomes a left drawer below 820px. Focus visibility, reduced motion, reduced transparency, increased contrast, and 320px-wide layouts are represented in the prototype CSS.

## Mocked boundaries

Conversations, models, attachments, context, tool details, approvals, voice timing, streaming, and send results are browser-only fixtures or simulations. Nothing is uploaded, persisted, generated, authenticated, or sent to a Hermes gateway. Refresh restores the initial state.

The rejected root prototype remains untouched so the comparison is reversible. The selected lane can be promoted later; this exploration does not define production architecture.
