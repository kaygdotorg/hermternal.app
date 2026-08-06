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
  export let selected = false;
  export let toggleable = false;
  export let expanded = false;
  export let expandable = false;
  export let ariaControls: string | undefined = undefined;
  export let ariaCurrent: 'page' | 'step' | 'location' | 'date' | 'time' | 'true' | 'false' | undefined = undefined;
  export let disabled = false;
  export let buttonType: 'button' | 'submit' | 'reset' = 'button';
  export let onActivate: (() => void) | undefined = undefined;

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
    if (pointerActivationHandled) {
      setTimeout(() => {
        pointerActivationHandled = false;
      }, 0);
    }
  }

  function handlePointerCancel(): void {
    resetMotion();
    pointerActivationHandled = false;
  }

  function handleClick(): void {
    if (disabled || !onActivate) return;
    if (pointerActivationHandled) {
      pointerActivationHandled = false;
      return;
    }
    onActivate();
  }
</script>

<button
  aria-controls={expandable ? ariaControls : undefined}
  aria-current={ariaCurrent}
  aria-expanded={expandable ? expanded : undefined}
  aria-label={ariaLabel}
  aria-pressed={toggleable ? selected : undefined}
  class:full-width={fullWidth}
  class:icon-only={iconOnly}
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
  onpointerleave={resetMotion}
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

  <span class="pill-copy" class:hidden-copy={iconOnly}>
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
    border-color: color-mix(in srgb, var(--pill-action) 36%, var(--pill-line));
    background: color-mix(in srgb, var(--pill-action) 12%, var(--pill-surface));
    color: var(--pill-ink);
  }

  .pill.selected .pill-description {
    color: color-mix(in srgb, var(--pill-ink) 70%, var(--pill-surface));
  }

  .pill.action {
    border-color: var(--pill-action);
    background: var(--pill-action);
    color: var(--action-ink, #fff);
    box-shadow: 0 6px 18px color-mix(in srgb, var(--pill-action) 22%, transparent);
  }

  .pill.action:hover:not(:disabled) {
    background: color-mix(in srgb, var(--pill-action) 88%, #000);
  }

  .pill.danger {
    border-color: var(--danger, #d94a4a);
    background: var(--danger-surface, rgba(217, 74, 74, 0.1));
    color: var(--danger-ink, var(--danger, #d94a4a));
  }

  .pill.ghost {
    border-color: transparent;
    background: transparent;
    color: var(--pill-muted);
  }

  .pill:disabled {
    border-color: color-mix(in srgb, var(--pill-line) 70%, transparent);
    background: color-mix(in srgb, var(--pill-line) 48%, var(--pill-surface));
    color: color-mix(in srgb, var(--pill-muted) 48%, transparent);
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
      transition: background-color 0ms, border-color 0ms, color 0ms, box-shadow 0ms;
      transform: none;
    }

    .pill.pulsing:not(:disabled) {
      animation: none;
    }
  }
</style>
