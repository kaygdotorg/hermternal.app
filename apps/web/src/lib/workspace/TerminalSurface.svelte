<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte';
  import type { FocusIntent, SessionCoordinatorState, WorkspaceMode } from '$lib/session/coordinator';
  import type {
    CurrentSessionTerminalEvent,
    CurrentSessionTerminalLifecycleIdentity,
    CurrentSessionTerminalState
  } from '$lib/terminal/current-session-terminal';
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import type { WorkspaceActionHandler } from './types';

  type TerminalSurfaceBridge = {
    readonly state: CurrentSessionTerminalState;
    readonly lifecycleIdentity: CurrentSessionTerminalLifecycleIdentity;
    subscribe(listener: (event: CurrentSessionTerminalEvent) => void): () => void;
    sendInput(input: string | Uint8Array): void;
    resize(cols: number, rows: number): void;
    detach(): void;
    setRendererReady(ready: boolean): void;
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
  let mounted = false;
  let mountGeneration = 0;
  let lastFocusSequence = 0;
  let lastResize = '';
  let subscribedBridge: TerminalSurfaceBridge | undefined;
  let currentTerminal: CurrentSessionTerminalState = bridge.state;
  let outputMayBeTruncated = bridge.state.outputMayBeTruncated;

  $: terminalState = stateForPresentation(currentTerminal, coordinator, active);
  $: terminalLabel = terminalState.charAt(0).toUpperCase() + terminalState.slice(1);
  $: terminalStatusCopy = statusCopyForState(terminalState, currentTerminal);
  $: if (mounted && subscribedBridge !== bridge) resetBridgeBoundary();
  $: if (active) void ensureRenderer();
  $: if (active && focusIntent && focusIntent.sequence !== lastFocusSequence) {
    lastFocusSequence = focusIntent.sequence;
    void focusRenderer(focusIntent);
  }

  onMount(() => {
    mounted = true;
    subscribeToBridge(bridge);
    // The bridge must not attach/replay until this surface owns a live W-Term sink.
    bridge.setRendererReady(false);
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
    bridge.setRendererReady(false);
    renderer?.dispose();
    renderer = undefined;
  });

  function subscribeToBridge(nextBridge: TerminalSurfaceBridge): void {
    unsubscribe?.();
    subscribedBridge = nextBridge;
    currentTerminal = nextBridge.state;
    outputMayBeTruncated = nextBridge.state.outputMayBeTruncated;
    unsubscribe = nextBridge.subscribe((event) => handleBridgeEvent(nextBridge, event));
  }

  function resetBridgeBoundary(): void {
    // Readiness belongs to the current renderer/session sink. Close its bridge
    // before disposal whether ownership changed inside one bridge or by bridge
    // replacement; no replay may remain open across that boundary.
    const previousBridge = subscribedBridge;
    previousBridge?.setRendererReady(false);
    mountGeneration += 1;
    renderer?.dispose();
    renderer = undefined;
    rendererState = 'idle';
    rendererError = null;
    rendererLoading = false;
    lastResize = '';
    if (bridge !== previousBridge) bridge.setRendererReady(false);
    subscribeToBridge(bridge);
    if (active) void ensureRenderer();
  }

  function handleBridgeEvent(source: TerminalSurfaceBridge, event: CurrentSessionTerminalEvent): void {
    if (source !== bridge || source !== subscribedBridge) return;
    if (event.type === 'bytes') {
      if (event.generation !== currentTerminal.generation) return;
      // PTY bytes remain opaque and bypass application state on their way to W-Term.
      renderer?.write(event.bytes);
      outputMayBeTruncated ||= event.outputMayBeTruncated;
      return;
    }
    if (event.type === 'notice') {
      if (event.generation === currentTerminal.generation) outputMayBeTruncated = true;
      return;
    }
    const previousSessionId = currentTerminal.sessionId;
    const changedSession = previousSessionId !== event.state.sessionId;
    currentTerminal = event.state;
    outputMayBeTruncated = event.state.outputMayBeTruncated;
    // Readiness belongs to the renderer/session sink that was current before
    // this publication. Losing a defined owner closes that lease immediately;
    // the following undefined -> session transition claims the fresh renderer
    // without disposing it after attach has already passed the readiness gate.
    if (changedSession && previousSessionId !== undefined) resetBridgeBoundary();
  }

  function canForwardTerminalIo(): boolean {
    if (!active || currentTerminal.status !== 'attached') return false;
    return coordinator === undefined || (
      coordinator.mode === 'terminal' &&
      coordinator.terminalStatus === 'attached' &&
      coordinator.activeSessionId === currentTerminal.sessionId
    );
  }

  async function ensureRenderer(): Promise<void> {
    if (!mounted || !active || !host || renderer || rendererLoading) {
      if (mounted && active) forwardResize();
      return;
    }
    const generation = ++mountGeneration;
    const targetBridge = bridge;
    rendererLoading = true;
    rendererState = 'loading';
    rendererError = null;
    try {
      const module = await import('$lib/terminal/renderer');
      if (!isCurrentRendererMount(generation, targetBridge)) return;
      const created = module.createTerminalRenderer({
        label: 'Terminal',
        initialSize: { cols: 80, rows: 24 },
        onInput: (data) => {
          if (!canForwardTerminalIo() || targetBridge !== bridge) return;
          try { targetBridge.sendInput(data); } catch { /* attachment changed */ }
        },
        onStateChange: (state) => {
          if (targetBridge === bridge && generation === mountGeneration) {
            rendererState = state;
            rendererError = created.error;
            // A runtime renderer failure loses the byte sink just as surely as
            // a mount rejection. Fail closed before the bridge can replay or
            // write opaque PTY output into a failed renderer.
            if (state === 'error' || state === 'disposed') {
              targetBridge.setRendererReady(false);
              targetBridge.detach();
            }
          }
        }
      });
      renderer = created;
      await created.mount(host);
      if (!isCurrentRendererMount(generation, targetBridge) || renderer !== created) {
        created.dispose();
        return;
      }
      rendererState = created.state;
      rendererError = created.error;
      targetBridge.setRendererReady(rendererState === 'ready');
      forwardResize();
      // A newer intent may have arrived while this one waited for the lazy
      // mount. It did not own the in-flight renderer promise, so replay the
      // latest intent now and let the normal lease fence decide ownership.
      if (focusIntent) void focusRenderer(focusIntent);
    } catch {
      if (!isCurrentRendererMount(generation, targetBridge)) return;
      targetBridge.setRendererReady(false);
      targetBridge.detach();
      renderer?.dispose();
      renderer = undefined;
      rendererState = 'error';
      rendererError = { code: 'wasm-initialization-failed', message: 'Terminal unavailable.' };
    } finally {
      if (generation === mountGeneration) rendererLoading = false;
    }
  }

  function isCurrentRendererMount(generation: number, targetBridge: TerminalSurfaceBridge): boolean {
    return mounted && active && host !== undefined && generation === mountGeneration && targetBridge === bridge;
  }

  type FocusLease = Readonly<{
    bridge: TerminalSurfaceBridge;
    lifecycle: CurrentSessionTerminalLifecycleIdentity;
    intent: FocusIntent;
  }>;

  function captureFocusLease(intent: FocusIntent): FocusLease | undefined {
    if (!isFocusIntentCurrent(intent)) return undefined;
    return { bridge, lifecycle: bridge.lifecycleIdentity, intent };
  }

  function isFocusIntentCurrent(intent: FocusIntent): boolean {
    return mounted && active &&
      intent.mode === 'terminal' && intent.target === 'w-term-input' &&
      focusIntent?.mode === intent.mode &&
      focusIntent.target === intent.target &&
      focusIntent.sessionId === intent.sessionId &&
      focusIntent.sessionGeneration === intent.sessionGeneration &&
      focusIntent.sequence === intent.sequence &&
      currentTerminal.sessionId === intent.sessionId &&
      (coordinator === undefined || (
        coordinator.mode === 'terminal' && coordinator.activeSessionId === intent.sessionId &&
        coordinator.sessionGeneration === intent.sessionGeneration
      ));
  }

  function isFocusLeaseCurrent(lease: FocusLease): boolean {
    const identity = lease.bridge.lifecycleIdentity;
    // Focus is an async capability. Revalidate every owner, target, generation,
    // and opaque coordinator lease after every await so a stale continuation
    // cannot focus a replacement session or native W-Term instance.
    return isFocusIntentCurrent(lease.intent) && bridge === lease.bridge &&
      identity.binding === lease.lifecycle.binding &&
      identity.nativeTransportGeneration === lease.lifecycle.nativeTransportGeneration;
  }

  async function focusRenderer(intent: FocusIntent): Promise<void> {
    const lease = captureFocusLease(intent);
    if (!lease) return;
    await ensureRenderer();
    if (!isFocusLeaseCurrent(lease) || !renderer || rendererState !== 'ready') return;
    await tick();
    if (isFocusLeaseCurrent(lease) && renderer?.state === 'ready') renderer.focus();
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
    if (!canForwardTerminalIo()) return;
    try { bridge.resize(cols, rows); } catch { /* attachment changed */ }
  }

  function chooseMode(mode: WorkspaceMode): void {
    // The live workspace adds these terminal actions when it composes this
    // surface; keeping the preview action union unchanged avoids a transport
    // dependency in this focused renderer component.
    onAction({ type: 'set-mode', mode } as never);
  }
  function terminalAction(type: 'terminal-reconnect' | 'terminal-detach' | 'terminal-close'): void {
    onAction({ type } as never);
  }

  function stateForPresentation(state: CurrentSessionTerminalState, coordinatorState: SessionCoordinatorState | undefined, isActive: boolean): string {
    if (!isActive && state.status === 'closed') return 'fresh';
    if (state.explicitlyClosed) return 'closed';
    if (state.failure || state.closeClassification === 'host-or-origin-rejected') return 'failed';
    if (state.status === 'attached' && (coordinatorState === undefined || coordinatorState.terminalStatus === 'attached')) return 'open';
    if (state.status === 'reattaching') return 'replaying';
    if (state.status === 'detached') return 'detached';
    if (state.status === 'exited') return 'ended';
    if (state.status === 'failed' || coordinatorState?.terminalStatus === 'failed') return 'failed';
    if (state.status === 'connecting' || state.status === 'starting' || state.status === 'ticket_pending' || coordinatorState?.terminalStatus === 'attaching') return 'connecting';
    return isActive ? 'connecting' : 'fresh';
  }

  function statusCopyForState(value: string, state: CurrentSessionTerminalState): string {
    if (value === 'open') return 'Attached · input enabled';
    if (value === 'connecting') return 'Current session · input paused';
    if (value === 'replaying') return 'Replaying retained output · input paused';
    if (value === 'detached') return state.reconnectSupported ? 'Detached · reconnect to continue' : 'Detached · reattach unavailable';
    if (value === 'ended') return state.reconnectSupported ? 'The PTY process ended' : 'Legacy PTY ended · reattach unavailable';
    if (value === 'closed') return 'Explicitly closed · no PTY retry';
    if (state.failure === 'authentication-required') return 'Authentication required · sign in again';
    if (state.failure === 'incompatible-origin') return 'Incompatible origin · terminal blocked';
    if (value === 'failed') return 'Terminal attach failed · Chat remains available';
    return 'Fresh · attach on first Terminal activation';
  }
</script>

<section aria-label="Terminal workspace" class="terminal-surface" class:is-active={active} data-terminal-state={terminalState} data-testid="terminal-surface" aria-hidden={!active ? 'true' : undefined}>
  <div class="terminal-state-bar" role="status" aria-live="polite">
    <div class="state-copy"><span class="state-dot" aria-hidden="true"></span><strong>{terminalLabel}</strong><span>{terminalStatusCopy}</span></div>
    <div class="state-meta"><span>{title}</span><span>{outputMayBeTruncated ? 'Replay window truncated · 1 MiB max' : 'Retained replay window · 1 MiB max'}</span></div>
  </div>
  <div bind:this={host} aria-describedby="terminal-help" aria-label="Terminal input and output" class="terminal-viewport" data-renderer-state={rendererState} role="region" tabindex="-1">
    {#if rendererState === 'loading'}<div class="terminal-placeholder" role="status">Loading terminal…</div>{:else if rendererState === 'error'}<div class="terminal-placeholder error" role="alert">{rendererError?.message ?? 'Terminal unavailable. Try again.'}</div>{/if}
  </div>
  <p id="terminal-help" class="sr-only">Terminal output stays in the W-Term renderer. Use native selection and copy. Input is enabled only when the current session is attached.</p>
  <footer class="terminal-footer"><div class="footer-copy"><Icon name="terminal" size={16} /><span>W-Term · current session</span></div><div class="footer-actions">
    {#if terminalState === 'failed' && currentTerminal.failure === 'authentication-required'}<Pill ariaLabel="Return to sign in" label="Sign in again" variant="action" onActivate={() => onAction({ type: 'return-to-sign-in' })} />{:else if currentTerminal.reconnectSupported && (terminalState === 'detached' || terminalState === 'ended' || terminalState === 'failed')}<Pill ariaLabel="Reconnect terminal" label="Reconnect" variant="action" onActivate={() => terminalAction('terminal-reconnect')} />{/if}
    <Pill ariaLabel="Return to Chat mode" label="Return to Chat" variant="ghost" onActivate={() => chooseMode('chat')} />
    <Pill ariaLabel="Detach terminal" label="Detach" variant="ghost" onActivate={() => terminalAction('terminal-detach')} />
    <Pill ariaLabel="Close terminal" label="Close" variant="danger" onActivate={() => terminalAction('terminal-close')} />
  </div></footer>
</section>

<style>
  .terminal-surface { box-sizing: border-box; display: flex; min-height: 0; flex: 1 1 auto; flex-direction: column; gap: 12px; padding: 20px 36px 132px; background: var(--canvas); color: var(--ink); }
  .terminal-surface:not(.is-active) { position: absolute; inset: 0; visibility: hidden; pointer-events: none; }
  .terminal-state-bar, .terminal-footer { box-sizing: border-box; display: flex; align-items: center; justify-content: space-between; gap: 12px; border: 1px solid var(--line); background: color-mix(in srgb, var(--surface) 72%, transparent); }
  .terminal-state-bar { min-height: 44px; padding: 8px 14px; border-radius: var(--radius-input); font-size: 12px; line-height: 16px; }
  .state-copy, .state-meta, .footer-copy, .footer-actions { display: flex; min-width: 0; align-items: center; gap: 8px; }
  .state-copy span:last-child, .state-meta, .footer-copy { color: var(--muted); }
  .state-copy strong { color: var(--ink); font-size: 14px; }
  .state-dot { width: 8px; height: 8px; flex: 0 0 8px; border-radius: 50%; background: var(--courier); }
  [data-terminal-state='open'] .state-dot { background: var(--success); }
  [data-terminal-state='failed'] .state-dot, [data-terminal-state='ended'] .state-dot, [data-terminal-state='closed'] .state-dot { background: var(--danger); }
  .state-meta { justify-content: flex-end; text-align: right; }
  .terminal-viewport { box-sizing: border-box; min-height: 0; flex: 1 1 auto; overflow: hidden; padding: 20px; border: 1px solid #26303b; border-radius: var(--radius-nested, 14px); background: #0c1015; color: #e7ebf0; font-family: var(--font-mono, 'Geist Mono', ui-monospace, monospace); }
  .terminal-placeholder { display: flex; min-height: 100%; align-items: center; justify-content: center; color: #9aa5b3; font-size: 13px; line-height: 20px; }.terminal-placeholder.error { color: #f06a6a; }
  .terminal-footer { min-height: 60px; padding: 8px 12px 8px 16px; border-color: color-mix(in srgb, var(--line) 75%, transparent); border-radius: var(--radius-structural, 22px); background: color-mix(in srgb, var(--surface) 91%, transparent); box-shadow: 0 10px 28px color-mix(in srgb, var(--ink) 10%, transparent); }.footer-copy { font-family: var(--font-mono, 'Geist Mono', ui-monospace, monospace); font-size: 12px; line-height: 16px; }.footer-copy :global(svg) { color: var(--courier); }.footer-actions { justify-content: flex-end; flex-wrap: wrap; }.footer-actions :global(.pill) { min-height: 44px; }
  @media (max-width: 720px) { .terminal-surface { padding: 16px 16px 108px; }.terminal-state-bar, .terminal-footer { align-items: flex-start; flex-direction: column; }.state-meta { justify-content: flex-start; text-align: left; }.footer-actions { width: 100%; justify-content: flex-start; } }
  @media (prefers-reduced-motion: reduce) { .terminal-surface * { scroll-behavior: auto; } }
  @media (forced-colors: active) { .terminal-state-bar, .terminal-viewport, .terminal-footer { border: 1px solid CanvasText; }.state-dot { background: CanvasText; } }
  .sr-only { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; }
</style>
