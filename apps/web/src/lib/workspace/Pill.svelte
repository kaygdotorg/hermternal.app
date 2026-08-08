<script lang="ts">
  import Icon from './Icon.svelte';
  import type { IconName } from './icon-types';
  import type { PillVariant } from './pill-types';

  export let label: string;
  export let description: string | undefined = undefined;
  export let icon: IconName | undefined = undefined;
  export let trailingIcon: IconName | undefined = undefined;
  export let monogram: string | undefined = undefined;
  export let shortcut: string | undefined = undefined;
  export let ariaLabel = label;
  export let title: string | undefined = undefined;
  export let disabledReason = 'Deferred in this preview';
  export let variant: PillVariant = 'neutral';
  export let fullWidth = false;
  export let iconOnly = false;
  /** Reveal the label on fine-pointer hover or keyboard focus without moving the icon slot. */
  export let revealLabel = false;
  export let selected = false;
  export let toggleable = false;
  export let expanded = false;
  export let expandable = false;
  export let ariaControls: string | undefined = undefined;
  export let ariaHasPopup: boolean | 'menu' | 'listbox' | 'tree' | 'grid' | 'dialog' = false;
  export let ariaCurrent: 'page' | 'step' | 'location' | 'date' | 'time' | 'true' | 'false' | undefined = undefined;
  export let disabled = false;
  export let buttonType: 'button' | 'submit' | 'reset' = 'button';
  export let role: string | undefined = undefined;
  export let onActivate: (() => void) | undefined = undefined;
  export let element: HTMLButtonElement | undefined = undefined;

  let driftX = 0;
  let driftY = 0;
  let pressed = false;
  let pressPulse = 0;
  let pointerActivationHandled = false;

  function reducedMotion(): boolean {
    return typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function handlePointerMove(event: PointerEvent): void {
    if (disabled || reducedMotion() || event.pointerType === 'touch') return;

    const target = event.currentTarget as HTMLElement;
    const bounds = target.getBoundingClientRect();
    const x = ((event.clientX - bounds.left) / bounds.width - 0.5) * 2;
    const y = ((event.clientY - bounds.top) / bounds.height - 0.5) * 2;
    driftX = Math.max(-5, Math.min(5, x * 5));
    driftY = Math.max(-3, Math.min(3, y * 3));
  }

  function resetMotion(): void {
    driftX = 0;
    driftY = 0;
    pressed = false;
  }

  function handlePointerDown(event: PointerEvent): void {
    if (disabled || !onActivate || event.button !== 0) return;
    pressed = true;
    pointerActivationHandled = true;
    pressPulse = 0;
    requestAnimationFrame(() => {
      pressPulse = 1;
    });
    // Pointer activation is immediate. The following click is suppressed so
    // mouse and touch cannot emit the same presentation action twice.
    onActivate();
  }

  function handlePointerUp(): void {
    pressed = false;
    // Suppression stays armed until the compatibility click is observed. A
    // leave/re-entry sequence may deliver that click after a later task.
  }

  function handlePointerCancel(): void {
    resetMotion();
    // Keep suppression armed in case a host synthesizes a compatibility click
    // after cancellation. Keyboard and assistive clicks are distinguished below.
  }

  function handlePointerLeave(): void {
    // Motion resets on leave, but the pointer gesture remains consumed. If the
    // pointer re-enters and produces its compatibility click, it must not emit a
    // second action after the immediate pointer-down activation.
    resetMotion();
  }

  function handleClick(event: MouseEvent): void {
    if (disabled || !onActivate) return;
    if (pointerActivationHandled && event.detail > 0) {
      pointerActivationHandled = false;
      return;
    }
    // Keyboard and assistive activation use an untrusted/detail-zero click and
    // remain available even after a pointer leaves or is cancelled.
    pointerActivationHandled = false;
    onActivate();
  }
</script>

<button
  bind:this={element}
  aria-controls={expandable ? ariaControls : undefined}
  aria-current={ariaCurrent}
  aria-expanded={expandable ? expanded : undefined}
  aria-haspopup={ariaHasPopup || undefined}
  aria-label={ariaLabel}
  role={role}
  aria-pressed={toggleable ? selected : undefined}
  class:full-width={fullWidth}
  class:icon-only={iconOnly}
  class:reveal-label={revealLabel}
  class:pulsing={pressPulse === 1}
  class:pressed
  class:selected
  class="pill {variant}"
  disabled={disabled || (buttonType === 'button' && !onActivate)}
  title={title ?? (buttonType === 'button' && !onActivate ? disabledReason : ariaLabel)}
  type={buttonType}
  style={`--drift-x: ${driftX}px; --drift-y: ${driftY}px;`}
  onpointercancel={handlePointerCancel}
  onpointerdown={handlePointerDown}
  onpointerleave={handlePointerLeave}
  onpointermove={handlePointerMove}
  onpointerup={handlePointerUp}
  onclick={handleClick}
>
  {#if monogram}
    <span aria-hidden="true" class="monogram">{monogram}</span>
  {:else if icon}
    <span aria-hidden="true" class="icon-slot"><Icon name={icon} size={18} /></span>
  {:else}
    <span aria-hidden="true" class="icon-slot"></span>
  {/if}

  <span class="pill-copy" class:hidden-copy={iconOnly && !revealLabel}>
    <span class="pill-label">{label}</span>
    {#if description}
      <span class="pill-description">{description}</span>
    {/if}
  </span>

  {#if shortcut}
    <span aria-hidden="true" class="shortcut">{shortcut}</span>
  {/if}

  {#if trailingIcon}
    <span aria-hidden="true" class="trailing-slot"><Icon name={trailingIcon} size={18} /></span>
  {/if}
</button>

<style>
  .pill {
    --pill-surface: var(--surface, rgba(255, 255, 255, 0.62));
    --pill-ink: var(--ink, #16181d);
    --pill-muted: var(--muted, #667080);
    --pill-line: var(--line, #d8dde5);
    --pill-action: var(--signal, #4c6fff);
    --pill-overlay-surface: var(--pill-surface);
    --pill-overlay-line: var(--pill-line);
    --pill-overlay-ink: var(--pill-ink);
    --pill-overlay-shadow: none;
    box-sizing: border-box;
    display: inline-flex;
    min-height: 44px;
    min-width: 44px;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 8px 12px;
    border: 1px solid var(--pill-line);
    border-radius: var(--radius-pill, 999px);
    background: var(--pill-surface);
    color: var(--pill-ink);
    font: inherit;
    text-align: center;
    cursor: pointer;
    transform: translate3d(var(--drift-x), var(--drift-y), 0) scale(1);
    transition:
      transform 150ms cubic-bezier(0.22, 1, 0.36, 1),
      background-color 150ms ease,
      border-color 150ms ease,
      color 150ms ease,
      box-shadow 150ms ease;
  }

  .pill:hover:not(:disabled) {
    border-color: color-mix(in srgb, var(--pill-action) 35%, var(--pill-line));
    background: color-mix(in srgb, var(--pill-action) 7%, var(--pill-surface));
  }

  .pill:focus-visible {
    outline: 3px solid var(--focus, #2348c7);
    outline-offset: 2px;
  }

  .pill:active:not(:disabled),
  .pill.pressed {
    transform: translate3d(var(--drift-x), var(--drift-y), 0) scale(0.97);
  }

  .pill.pulsing:not(:disabled) {
    animation: pill-pulse 190ms cubic-bezier(0.22, 1, 0.36, 1);
  }

  .pill.selected {
    --pill-overlay-surface: color-mix(in srgb, var(--pill-action) 12%, var(--pill-surface));
    --pill-overlay-line: color-mix(in srgb, var(--pill-action) 36%, var(--pill-line));
    border-color: var(--pill-overlay-line);
    background: var(--pill-overlay-surface);
    color: var(--pill-ink);
  }

  .pill.selected .pill-description {
    color: color-mix(in srgb, var(--pill-ink) 70%, var(--pill-surface));
  }

  .pill.action {
    --pill-overlay-surface: var(--pill-action);
    --pill-overlay-line: var(--pill-action);
    --pill-overlay-ink: var(--action-ink, #fff);
    --pill-overlay-shadow: 0 6px 18px color-mix(in srgb, var(--pill-action) 22%, transparent);
    border-color: var(--pill-action);
    background: var(--pill-action);
    color: var(--action-ink, #fff);
    box-shadow: var(--pill-overlay-shadow);
  }

  .pill.action:hover:not(:disabled) {
    --pill-overlay-surface: color-mix(in srgb, var(--pill-action) 88%, #000);
    background: var(--pill-overlay-surface);
  }

  .pill.danger {
    --pill-overlay-surface: var(--danger-surface, rgba(217, 74, 74, 0.1));
    --pill-overlay-line: var(--danger, #d94a4a);
    --pill-overlay-ink: var(--danger-ink, var(--danger, #d94a4a));
    border-color: var(--pill-overlay-line);
    background: var(--pill-overlay-surface);
    color: var(--pill-overlay-ink);
  }

  .pill.ghost {
    --pill-overlay-surface: transparent;
    --pill-overlay-line: transparent;
    --pill-overlay-ink: var(--pill-muted);
    border-color: transparent;
    background: transparent;
    color: var(--pill-muted);
  }

  .pill:disabled {
    --pill-overlay-surface: color-mix(in srgb, var(--pill-line) 48%, var(--pill-surface));
    --pill-overlay-line: color-mix(in srgb, var(--pill-line) 70%, transparent);
    --pill-overlay-ink: color-mix(in srgb, var(--pill-muted) 48%, transparent);
    --pill-overlay-shadow: none;
    border-color: var(--pill-overlay-line);
    background: var(--pill-overlay-surface);
    color: var(--pill-overlay-ink);
    cursor: not-allowed;
    box-shadow: none;
  }

  .pill.full-width {
    width: 100%;
    justify-content: flex-start;
    text-align: left;
  }

  .pill.icon-only {
    padding-inline: 8px;
  }

  /* Paper keeps compact action islands icon-only at rest, then reveals the
     label on hover or keyboard focus. The label is a visual overlay rather
     than a layout item: the 44px button and its icon anchor never move while
     a stationary pointer is over the control or its siblings. */
  .pill.reveal-label {
    position: relative;
    width: 44px;
    min-width: 44px;
    flex: 0 0 44px;
    justify-content: center;
    overflow: visible;
    white-space: nowrap;
  }

  .pill.reveal-label .pill-copy {
    position: absolute;
    top: -1px;
    left: -1px;
    z-index: 1;
    box-sizing: border-box;
    display: flex;
    width: max-content;
    max-width: 0;
    min-width: 0;
    height: calc(100% + 2px);
    flex: 0 0 auto;
    align-items: center;
    justify-content: flex-start;
    overflow: hidden;
    padding: 0;
    border: 1px solid transparent;
    border-radius: inherit;
    background: var(--pill-overlay-surface);
    color: var(--pill-overlay-ink);
    box-shadow: var(--pill-overlay-shadow);
    opacity: 0;
    pointer-events: none;
    transition:
      max-width 150ms cubic-bezier(0.22, 1, 0.36, 1),
      padding 150ms cubic-bezier(0.22, 1, 0.36, 1),
      border-color 150ms ease,
      opacity 100ms ease;
  }

  .pill.reveal-label:is(:hover, :focus-visible) {
    z-index: 4;
  }

  .pill.reveal-label:is(:hover, :focus-visible) .pill-copy {
    max-width: 180px;
    padding: 8px 12px 8px 40px;
    border-color: var(--pill-overlay-line);
    opacity: 1;
  }

  .pill.reveal-label .icon-slot,
  .pill.reveal-label .monogram {
    position: relative;
    z-index: 2;
  }

  .icon-slot,
  .trailing-slot {
    display: inline-flex;
    width: 20px;
    flex: 0 0 20px;
    align-items: center;
    justify-content: center;
  }

  .trailing-slot {
    margin-left: auto;
  }

  .monogram {
    display: inline-flex;
    width: 40px;
    height: 40px;
    flex: 0 0 40px;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: var(--monogram-surface, color-mix(in srgb, var(--pill-action) 11%, var(--pill-surface)));
    color: var(--monogram-ink, var(--pill-action));
    font-size: 16px;
    font-weight: 600;
    line-height: 20px;
  }

  .pill-copy {
    min-width: 0;
    display: flex;
    flex: 1 1 auto;
    flex-direction: column;
    gap: 2px;
  }

  .pill-label {
    overflow: hidden;
    font-size: 14px;
    font-weight: 600;
    line-height: 18px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .pill-description {
    overflow: hidden;
    color: var(--pill-muted);
    font-size: 12px;
    font-weight: 400;
    line-height: 16px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .shortcut {
    flex: 0 0 auto;
    color: var(--pill-muted);
    font-size: 12px;
    line-height: 16px;
  }

  .hidden-copy {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }

  @keyframes pill-pulse {
    0% {
      transform: translate3d(var(--drift-x), var(--drift-y), 0) scale(1);
    }
    45% {
      transform: translate3d(var(--drift-x), var(--drift-y), 0) scale(0.965);
    }
    100% {
      transform: translate3d(var(--drift-x), var(--drift-y), 0) scale(1);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .pill {
      transition:
        background-color 0ms,
        border-color 0ms,
        color 0ms,
        box-shadow 0ms;
      transform: none;
    }

    .pill.reveal-label .pill-copy {
      transition: none;
    }

    .pill.pulsing:not(:disabled) {
      animation: none;
    }
  }
</style>
