<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte';
  import type { FocusIntent, SessionCoordinatorState, WorkspaceMode } from '$lib/session/coordinator';
  import type {
    CurrentSessionTerminalEvent,
    CurrentSessionTerminalState
  } from '$lib/terminal/current-session-terminal';
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import type { WorkspaceActionHandler } from './types';

  type TerminalSurfaceBridge = {
    readonly state: CurrentSessionTerminalState;
    subscribe(listener: (event: CurrentSessionTerminalEvent) => void): () => void;
    sendInput(input: string | Uint8Array): void;
    resize(cols: number, rows: number): void;
    setRendererReady?(ready: boolean): void;
  };

  export let bridge: TerminalSurfaceBridge;
  export let active = false;
  export let title = 'Hermes terminal';
  export let coordinator: SessionCoordinatorState | undefined = undefined;
  export let focusIntent: FocusIntent | undefined = undefined;
  export let onAction: WorkspaceActionHandler = () => {};

  let host: HTMLDivElement | undefined;
  let renderer: import('$lib/terminal/renderer').TerminalRenderer | undefined;
  let rendererState: import('$lib/terminal/renderer').TerminalRendererState = 'idle';
  let rendererError: import('$lib/terminal/renderer').TerminalRendererError | null = null;
  let rendererLoading = false;
  let unsubscribe: (() => void) | undefined;
  let observer: ResizeObserver | undefined;
  let mountGeneration = 0;
  let lastFocusSequence = 0;
  let lastResize = '';
  let mounted = false;
  let subscribedBridge: TerminalSurfaceBridge | undefined;
  let lastCoordinatorKey = '';
  let coordinatorKey = '';
  let currentTerminal: CurrentSessionTerminalState = bridge.state;
  let outputMayBeTruncated = bridge.state.outputMayBeTruncated;

  $: coordinatorKey = `${coordinator?.activeSessionId ?? ''}:${coordinator?.sessionGeneration ?? -1}`;
  $: terminalLabel = labelForState(currentTerminal, coordinator, active);
  $: terminalStatusCopy = statusCopyForState(currentTerminal, coordinator, active);
  $: terminalState = stateForPresentation(currentTerminal, coordinator, active);
  $: if (active) void ensureRenderer();
  $: if (active && focusIntent && focusIntent.sequence !== lastFocusSequence) {
    lastFocusSequence = focusIntent.sequence;
    void focusRenderer();
  }
  $: if (mounted && subscribedBridge !== bridge) {
    resetRendererForBoundary();
    subscribeToBridge(bridge);
  }
  $: if (mounted && coordinatorKey !== lastCoordinatorKey) {
    lastCoordinatorKey = coordinatorKey;
    resetRendererForBoundary();
  }

  onMount(() => {
    mounted = true;
    lastCoordinatorKey = coordinatorKey;
    subscribeToBridge(bridge);
    bridge.setRendererReady?.(renderer !== undefined && rendererState === 'ready');
    if (host && typeof ResizeObserver !== 'undefined') {
      observer = new ResizeObserver(() => forwardResize());
      observer.observe(host);
    }
    if (active) void ensureRenderer();
  });

  onDestroy(() => {
    mounted = false;
    mountGeneration += 1;
    unsubscribe?.();
    observer?.disconnect();
    // Release a bridge waiting for the lazy renderer before the parent session
    // disposes it. No PTY bytes are buffered here; the renderer gate only
    // delays the first transport attach until a sink exists.
    bridge.setRendererReady?.(true);
    renderer?.dispose();
    renderer = undefined;
  });

  function subscribeToBridge(nextBridge: TerminalSurfaceBridge): void {
    unsubscribe?.();
    subscribedBridge = nextBridge;
    currentTerminal = nextBridge.state;
    outputMayBeTruncated = nextBridge.state.outputMayBeTruncated;
    unsubscribe = nextBridge.subscribe(handleBridgeEvent);
  }

  function resetRendererForBoundary(): void {
    mountGeneration += 1;
    renderer?.dispose();
    renderer = undefined;
    rendererState = 'idle';
    rendererError = null;
    lastResize = '';
    bridge.setRendererReady?.(false);
    currentTerminal = bridge.state;
    outputMayBeTruncated = bridge.state.outputMayBeTruncated;
    if (active) void ensureRenderer();
  }

  function handleBridgeEvent(event: CurrentSessionTerminalEvent): void {
    if (event.type === 'bytes') {
      if (event.generation !== currentTerminal.generation) return;
      // Raw bytes go directly to the renderer. This component does not decode or retain them.
      renderer?.write(event.bytes);
      outputMayBeTruncated ||= event.outputMayBeTruncated;
      return;
    }
    if (event.type === 'notice') {
      if (event.generation !== currentTerminal.generation) return;
      outputMayBeTruncated = true;
      return;
    }
    const generationChanged =
      event.state.generation !== currentTerminal.generation ||
      event.state.sessionId !== currentTerminal.sessionId;
    currentTerminal = event.state;
    outputMayBeTruncated = event.state.outputMayBeTruncated;
    if (generationChanged) resetRendererForBoundary();
    if (rendererState === 'ready') void renderer?.whenIdle();
  }

  async function ensureRenderer(): Promise<void> {
    if (!active || !host || renderer || rendererLoading) {
      if (active) forwardResize();
      return;
    }
    const generation = ++mountGeneration;
    rendererLoading = true;
    rendererState = 'loading';
    rendererError = null;
    try {
      const module = await import('$lib/terminal/renderer');
      if (!active || !host || generation !== mountGeneration) return;
      renderer = module.createTerminalRenderer({
        label: 'Terminal',
        initialSize: { cols: 80, rows: 24 },
        onInput: (data) => {
          try {
            bridge.sendInput(data);
          } catch {
            // Input stays local when PTY attach is not ready or has ended.
          }
        },
        onStateChange: (state) => {
          rendererState = state;
          rendererError = renderer?.error ?? null;
        }
      });
      await renderer.mount(host);
      if (generation !== mountGeneration) return;
      rendererState = renderer.state;
      rendererError = renderer.error;
      // Let the bridge attach only after the renderer owns a mounted sink.
      bridge.setRendererReady?.(rendererState === 'ready');
      forwardResize();
      await tick();
      if (focusIntent && focusIntent.sequence === lastFocusSequence) renderer.focus();
    } catch {
      if (generation !== mountGeneration) return;
      rendererState = 'error';
      rendererError = { code: 'wasm-initialization-failed', message: 'Terminal unavailable.' };
      // Do not leave coordinator activation pending forever when the optional
      // renderer fails. The visible error remains local and redacted.
      bridge.setRendererReady?.(true);
    } finally {
      rendererLoading = false;
      if (active && mounted && !renderer && generation !== mountGeneration && rendererState === 'idle') {
        void ensureRenderer();
      }
    }
  }

  async function focusRenderer(): Promise<void> {
    await ensureRenderer();
    if (active) renderer?.focus();
  }

  function forwardResize(): void {
    if (!host || !renderer || !active) return;
    const rect = host.getBoundingClientRect();
    const cols = Math.max(1, Math.min(2000, Math.floor(rect.width / 8)));
    const rows = Math.max(1, Math.min(1000, Math.floor(rect.height / 20)));
    const key = `${cols}x${rows}`;
    if (key === lastResize) return;
    lastResize = key;
    renderer.resize(cols, rows);
    try {
      bridge.resize(cols, rows);
    } catch {
      // A resize racing attach/detach is intentionally dropped at the transport boundary.
    }
  }

  function chooseMode(mode: WorkspaceMode): void {
    onAction({ type: 'set-mode', mode });
  }

  function handleTerminalAction(type: 'terminal-reconnect' | 'terminal-detach' | 'terminal-close'): void {
    onAction({ type });
  }

  function stateForPresentation(
    state: CurrentSessionTerminalState,
    coordinatorState: SessionCoordinatorState | undefined,
    isActive: boolean
  ): string {
    if (!isActive && state.status === 'closed') return 'fresh';
    if (state.explicitlyClosed) return 'closed';
    if (state.failure || state.closeClassification === 'host-or-origin-rejected') return 'failed';
    if (state.status === 'attached' && coordinatorState?.terminalStatus === 'attached') return 'open';
    if (state.status === 'reattaching') return 'replaying';
    if (state.status === 'detached') return 'detached';
    if (state.status === 'exited') return 'ended';
    if (state.status === 'failed' || coordinatorState?.terminalStatus === 'failed') return 'failed';
    if (state.status === 'connecting' || state.status === 'starting' || state.status === 'ticket_pending' || coordinatorState?.terminalStatus === 'attaching') return 'connecting';
    return isActive ? 'connecting' : 'fresh';
  }

  function labelForState(
    state: CurrentSessionTerminalState,
    coordinatorState: SessionCoordinatorState | undefined,
    isActive: boolean
  ): string {
    const value = stateForPresentation(state, coordinatorState, isActive);
    return value.charAt(0).toUpperCase() + value.slice(1);
  }

  function statusCopyForState(
    state: CurrentSessionTerminalState,
    coordinatorState: SessionCoordinatorState | undefined,
    isActive: boolean
  ): string {
    const value = stateForPresentation(state, coordinatorState, isActive);
    if (value === 'open') return 'Attached · input enabled';
    if (value === 'connecting') return 'Current session · input paused';
    if (value === 'replaying') return 'Replaying retained output · input paused';
    if (value === 'detached') return 'Detached · reconnect to continue';
    if (value === 'ended') return 'The PTY process ended';
    if (value === 'closed') return 'Explicitly closed · no PTY retry';
    if (state.failure === 'authentication-required') return 'Authentication required · sign in again';
    if (state.failure === 'incompatible-origin') return 'Incompatible origin · terminal blocked';
    if (value === 'failed') return 'Terminal attach failed · Chat remains available';
    return 'Fresh · attach on first Terminal activation';
  }
</script>

<section
  aria-label="Terminal workspace"
  class="terminal-surface"
  class:is-active={active}
  data-terminal-state={terminalState}
  data-testid="terminal-surface"
  aria-hidden={!active ? 'true' : undefined}
>
  <div class="terminal-state-bar" role="status" aria-live="polite">
    <div class="state-copy">
      <span class="state-dot" aria-hidden="true"></span>
      <strong>{terminalLabel}</strong>
      <span>{terminalStatusCopy}</span>
    </div>
    <div class="state-meta">
      <span>{title}</span>
      <span>{outputMayBeTruncated ? 'Replay window truncated · 1 MiB max' : 'Retained replay window · 1 MiB max'}</span>
    </div>
  </div>

  <div
    bind:this={host}
    aria-describedby="terminal-help"
    aria-label="Terminal input and output"
    class="terminal-viewport"
    data-renderer-state={rendererState}
    role="region"
    tabindex="-1"
  >
    {#if rendererState === 'loading'}
      <div class="terminal-placeholder" role="status">Loading terminal…</div>
    {:else if rendererState === 'error'}
      <div class="terminal-placeholder error" role="alert">{rendererError?.message ?? 'Terminal unavailable. Try again.'}</div>
    {/if}
  </div>

  <p id="terminal-help" class="sr-only">
    Terminal output stays in the W-Term renderer. Use native selection and copy. Input is enabled only when the current session is attached.
  </p>

  <footer class="terminal-footer">
    <div class="footer-copy">
      <Icon name="terminal" size={16} />
      <span>W-Term · current session</span>
    </div>
    <div class="footer-actions">
      {#if terminalState === 'failed' && currentTerminal.failure === 'authentication-required'}
        <Pill ariaLabel="Return to sign in" label="Sign in again" variant="action" onActivate={() => onAction({ type: 'return-to-sign-in' })} />
      {:else if terminalState === 'detached' || terminalState === 'ended' || terminalState === 'failed'}
        <Pill ariaLabel="Reconnect terminal" label="Reconnect" variant="action" onActivate={() => handleTerminalAction('terminal-reconnect')} />
      {/if}
      {#if terminalState !== 'open' && terminalState !== 'connecting' && terminalState !== 'replaying'}
        <Pill ariaLabel="Return to Chat mode" label="Return to Chat" variant="ghost" onActivate={() => chooseMode('chat')} />
      {:else}
        <Pill ariaLabel="Return to Chat mode" label="Return to Chat" variant="ghost" onActivate={() => chooseMode('chat')} />
      {/if}
      <Pill ariaLabel="Detach terminal" label="Detach" variant="ghost" onActivate={() => handleTerminalAction('terminal-detach')} />
      <Pill ariaLabel="Close terminal" label="Close" variant="danger" onActivate={() => handleTerminalAction('terminal-close')} />
    </div>
  </footer>
</section>

<style>
  .terminal-surface {
    box-sizing: border-box;
    display: flex;
    min-height: 0;
    flex: 1 1 auto;
    flex-direction: column;
    gap: 12px;
    padding: 20px 36px 132px;
    background: var(--canvas);
    color: var(--ink);
  }

  .terminal-surface:not(.is-active) {
    position: absolute;
    inset: 0;
    visibility: hidden;
    pointer-events: none;
  }

  .terminal-state-bar {
    box-sizing: border-box;
    display: flex;
    min-height: 44px;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 14px;
    border: 1px solid var(--line);
    border-radius: var(--radius-input);
    background: color-mix(in srgb, var(--surface) 72%, transparent);
    font-size: 12px;
    line-height: 16px;
  }

  .state-copy,
  .state-meta,
  .footer-copy,
  .footer-actions {
    display: flex;
    min-width: 0;
    align-items: center;
    gap: 8px;
  }

  .state-copy span:last-child,
  .state-meta {
    color: var(--muted);
  }

  .state-copy strong {
    color: var(--ink);
    font-size: 14px;
  }

  .state-dot {
    width: 8px;
    height: 8px;
    flex: 0 0 8px;
    border-radius: 50%;
    background: var(--courier);
  }

  [data-terminal-state='open'] .state-dot {
    background: var(--success);
  }

  [data-terminal-state='failed'] .state-dot,
  [data-terminal-state='ended'] .state-dot,
  [data-terminal-state='closed'] .state-dot {
    background: var(--danger);
  }

  .state-meta {
    justify-content: flex-end;
    text-align: right;
  }

  .terminal-viewport {
    box-sizing: border-box;
    min-height: 0;
    flex: 1 1 auto;
    overflow: hidden;
    padding: 20px;
    border: 1px solid #26303b;
    border-radius: var(--radius-nested, 14px);
    background: #0c1015;
    color: #e7ebf0;
    font-family: var(--font-mono, 'Geist Mono', ui-monospace, monospace);
  }

  .terminal-placeholder {
    display: flex;
    min-height: 100%;
    align-items: center;
    justify-content: center;
    color: #9aa5b3;
    font-size: 13px;
    line-height: 20px;
  }

  .terminal-placeholder.error {
    color: #f06a6a;
  }

  .terminal-footer {
    box-sizing: border-box;
    display: flex;
    min-height: 60px;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 12px 8px 16px;
    border: 1px solid color-mix(in srgb, var(--line) 75%, transparent);
    border-radius: var(--radius-structural, 22px);
    background: color-mix(in srgb, var(--surface) 91%, transparent);
    box-shadow: 0 10px 28px color-mix(in srgb, var(--ink) 10%, transparent);
  }

  .footer-copy {
    color: var(--muted);
    font-family: var(--font-mono, 'Geist Mono', ui-monospace, monospace);
    font-size: 12px;
    line-height: 16px;
  }

  .footer-copy :global(svg) {
    color: var(--courier);
  }

  .footer-actions {
    justify-content: flex-end;
    flex-wrap: wrap;
  }

  .footer-actions :global(.pill) {
    min-height: 44px;
  }

  @media (max-width: 720px) {
    .terminal-surface {
      padding: 16px 16px 108px;
    }

    .terminal-state-bar,
    .terminal-footer {
      align-items: flex-start;
      flex-direction: column;
    }

    .state-meta {
      justify-content: flex-start;
      text-align: left;
    }

    .footer-actions {
      width: 100%;
      justify-content: flex-start;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .terminal-surface * {
      scroll-behavior: auto;
    }
  }

  @media (forced-colors: active) {
    .terminal-state-bar,
    .terminal-viewport,
    .terminal-footer {
      border: 1px solid CanvasText;
    }

    .state-dot {
      background: CanvasText;
    }
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }
</style>
