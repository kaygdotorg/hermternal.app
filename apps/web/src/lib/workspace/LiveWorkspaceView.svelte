<script lang="ts">
  import { onDestroy, onMount, tick } from 'svelte';
  import Pill from './Pill.svelte';
  import TerminalSurface from './TerminalSurface.svelte';
  import WorkspacePreview from './WorkspacePreview.svelte';
  import type { LiveWorkspaceSession, LiveWorkspaceSnapshot } from './live-workspace-session';
  import type {
    CurrentSessionTerminalBridge,
    CurrentSessionTerminalLifecycleIdentity
  } from '$lib/terminal/current-session-terminal';
  import type { RootTerminalLifecycleLease } from '$lib/root-route';
  import type { Appearance, WorkspaceAction } from './types';

  export let session: LiveWorkspaceSession;
  export let appearance: Appearance = 'light';
  export let onReturnToSignIn: (lease: RootTerminalLifecycleLease | undefined) => void = () => {};
  /** Root only accepts identity stamped by a concrete bridge state callback. */
  export let registerTerminalLifecycle: ((
    terminal: CurrentSessionTerminalBridge,
    identity: CurrentSessionTerminalLifecycleIdentity
  ) => RootTerminalLifecycleLease | undefined) | undefined = undefined;
  /** Terminal 4401 must carry the registered opaque lease; chat has its own path. */
  export let onTerminalAuthenticationFailure: (lease: RootTerminalLifecycleLease | undefined) => void = () => {};

  let snapshot: Readonly<LiveWorkspaceSnapshot> = session.current;
  let unsubscribe: (() => void) | undefined;
  let unsubscribeTerminalLifecycle: (() => void) | undefined;
  let terminalAuthenticationLease: RootTerminalLifecycleLease | undefined;
  let coordinator = session.coordinator;
  let terminal = session.terminal;
  let liveWorkspaceElement: HTMLElement | undefined;
  let terminalLayerVisible = snapshot.mode === 'terminal';
  let chatFocusHandoff = false;
  let chatHandoffRequested = false;
  let chatHandoffRunning = false;
  let handoffSequence = 0;

  // A latched factory failure has no bridge or coordinator of its own. Keep an
  // unpromoted draft fail-closed instead of turning its Terminal controls into a
  // silent no-op; only a coordinator-confirmed durable session may expose it.
  $: terminalModeEnabled =
    snapshot.activeSessionId !== undefined &&
    (snapshot.coordinator?.activeSessionId ?? coordinator?.state.activeSessionId) === snapshot.activeSessionId;

  function bindTerminalLifecycle(nextTerminal: CurrentSessionTerminalBridge | undefined): void {
    unsubscribeTerminalLifecycle?.();
    unsubscribeTerminalLifecycle = undefined;
    terminalAuthenticationLease = undefined;
    if (!nextTerminal || !registerTerminalLifecycle) return;
    unsubscribeTerminalLifecycle = nextTerminal.subscribe((event) => {
      if (event.type !== 'state') return;
      // The bridge stamps this event before terminal settlement can invalidate
      // its binding. Forward that exact object identity; never infer a root ID.
      if (event.lifecycle) {
        terminalAuthenticationLease = registerTerminalLifecycle(nextTerminal, event.lifecycle);
      }
    });
  }

  onMount(() => {
    coordinator = session.coordinator;
    terminal = session.terminal;
    bindTerminalLifecycle(terminal);
    unsubscribe = session.subscribe((next) => {
      snapshot = next;
      coordinator = session.coordinator;
      const nextTerminal = session.terminal;
      if (nextTerminal !== terminal) bindTerminalLifecycle(nextTerminal);
      terminal = nextTerminal;
      if (next.mode === 'terminal') {
        handoffSequence += 1;
        terminalLayerVisible = true;
        chatFocusHandoff = false;
        chatHandoffRequested = false;
        chatHandoffRunning = false;
      } else if (next.mode === 'chat') {
        if (terminalLayerVisible && chatHandoffRequested) void completeChatFocusHandoff(handoffSequence);
        else if (!chatHandoffRequested) terminalLayerVisible = false;
      }
    });
    void session.initialize();
  });

  onDestroy(() => {
    // The route root owns final disposal. This authenticated projection only
    // releases its subscription so expiry can remount the same workspace.
    unsubscribe?.();
    unsubscribeTerminalLifecycle?.();
  });

  async function requestMode(mode: 'chat' | 'terminal'): Promise<void> {
    if (mode === 'chat' && terminalLayerVisible) {
      chatHandoffRequested = true;
      handoffSequence += 1;
    }
    try {
      await session.activateMode(mode);
      // Some session doubles resolve before publishing their snapshot. The
      // subscriber remains the authority for starting the visual handoff.
      if (mode === 'chat' && snapshot.mode === 'chat') void completeChatFocusHandoff(handoffSequence);
    } catch {
      if (mode === 'chat') {
        chatHandoffRequested = false;
        chatFocusHandoff = false;
      }
    }
  }

  async function afterActivationFrame(): Promise<void> {
    await tick();
    await new Promise<void>((resolve) => {
      let settled = false;
      const finish = (): void => {
        if (settled) return;
        settled = true;
        clearTimeout(fallback);
        resolve();
      };
      // Real browsers complete on the next paint. Layout-free test hosts can
      // expose a dormant RAF shim, so a bounded fallback keeps cleanup moving.
      const fallback = setTimeout(finish, 50);
      if (typeof requestAnimationFrame === 'function') requestAnimationFrame(finish);
    });
  }

  function focusVisibleChatTarget(): HTMLElement | undefined {
    if (!chatFocusHandoff || !liveWorkspaceElement) return undefined;
    const underlay = liveWorkspaceElement.querySelector<HTMLElement>('[data-testid="workspace-underlay"]');
    if (!underlay) return undefined;
    // Release the native focus fence synchronously as well as reactively. This
    // avoids a browser retaining the inert property through the Svelte update.
    underlay.inert = false;
    underlay.removeAttribute('inert');
    underlay.removeAttribute('aria-hidden');
    const mobileMode = liveWorkspaceElement.querySelector<HTMLButtonElement>('[data-testid="mobile-mode-selector"] button:first-child');
    const mobileModeVisible = mobileMode !== null && mobileMode.getClientRects().length > 0;
    const desktopMode = underlay.querySelector<HTMLButtonElement>('button[aria-label="Chat mode selected"]');
    const desktopModeVisible = desktopMode !== null && desktopMode.getClientRects().length > 0;
    const composer = underlay.querySelector<HTMLTextAreaElement>('[aria-label="Message Hermes"]:not([disabled])');
    // The narrow pill stays painted above Terminal. Layout-free hosts expose no
    // visible boxes, so use the released focusable underlay instead of guessing.
    const layoutFree = !mobileModeVisible && !desktopModeVisible;
    const target = layoutFree
      ? underlay
      : (mobileModeVisible ? mobileMode : desktopMode) ?? composer ?? underlay;
    target.focus();
    if (document.activeElement === target) return target;
    // jsdom cannot move focus out of a previously inert subtree. Treat only the
    // no-layout host as structural evidence; Playwright proves visible focus.
    return layoutFree ? target : undefined;
  }

  async function completeChatFocusHandoff(sequence: number): Promise<void> {
    if (chatHandoffRunning || !chatHandoffRequested || snapshot.mode !== 'chat') return;
    chatHandoffRunning = true;
    // A desktop Chat control lives in the underlay, below Terminal's stacking
    // context. Hide Terminal and flush that paint boundary before releasing and
    // focusing Chat; a client rect alone does not prove that a target is hit-test
    // visible. The narrow selector is already above Terminal, but follows this
    // shared ordering so both input paths retain the same no-hidden-focus rule.
    terminalLayerVisible = false;
    await tick();
    if (sequence !== handoffSequence || snapshot.mode !== 'chat' || !chatHandoffRequested) {
      chatHandoffRunning = false;
      if (snapshot.mode === 'chat' && chatHandoffRequested) {
        void completeChatFocusHandoff(handoffSequence);
      }
      return;
    }
    chatFocusHandoff = true;
    await tick();
    const focused = focusVisibleChatTarget();
    if (sequence !== handoffSequence || snapshot.mode !== 'chat' || !chatHandoffRequested) {
      chatHandoffRunning = false;
      // Rapid repeated Chat activation supersedes this attempt while it is
      // releasing focus. Restart for the newest sequence instead of leaving the
      // workspace with no active handoff owner.
      if (snapshot.mode === 'chat' && chatHandoffRequested) {
        void completeChatFocusHandoff(handoffSequence);
      }
      return;
    }
    if (!focused) {
      // Fail closed: keep Terminal visible rather than strand focus in a hidden
      // control when the browser cannot establish a visible Chat target.
      chatHandoffRunning = false;
      return;
    }
    terminalLayerVisible = false;
    // Renderer teardown may finish after Svelte's DOM flush. Wait through the
    // next activation frame, then reassert the established Chat target.
    await afterActivationFrame();
    focusVisibleChatTarget();
    chatFocusHandoff = false;
    chatHandoffRequested = false;
    chatHandoffRunning = false;
  }

  function handleAction(action: WorkspaceAction): void {
    if (action.type === 'return-to-sign-in') {
      if (
        snapshot.permanentFailure?.reason === 'authentication-required' ||
        snapshot.terminal?.failure === 'authentication-required'
      ) {
        if (snapshot.terminal?.failure === 'authentication-required') {
          onTerminalAuthenticationFailure(terminalAuthenticationLease);
        } else {
          onReturnToSignIn(undefined);
        }
      }
      return;
    }
    if (action.type === 'back-to-sessions' || action.type === 'dismiss') {
      // Both visible permanent-error exits lead back to sign-in only when the
      // transport proved that authentication is required. Incompatible-origin
      // failures remain on the reviewed fail-closed workspace boundary.
      if (snapshot.permanentFailure?.reason === 'authentication-required') {
        if (snapshot.terminal?.failure === 'authentication-required') {
          onTerminalAuthenticationFailure(terminalAuthenticationLease);
        } else {
          onReturnToSignIn(undefined);
        }
      }
      return;
    }
    if (action.type === 'set-mode') void requestMode(action.mode);
    if (action.type === 'terminal-reconnect') void session.reconnectTerminal();
    if (action.type === 'terminal-detach') session.detachTerminal();
    if (action.type === 'terminal-close') session.closeTerminal();
    if (action.type === 'new-session') void session.createSession();
    if (action.type === 'select-session') void session.selectSession(action.sessionId);
    if (action.type === 'send') session.sendPrompt(action.text);
    if (action.type === 'stop') void session.stop();
    if (action.type === 'retry' || action.type === 'check-connection') void session.retryConnection();
    if (action.type === 'cancel-reconnect') session.cancelReconnect();
    if (action.type === 'approve-tool') {
      // The preview carries once/session/always metadata; this live adapter is
      // intentionally limited to the existing boolean approval transport.
      void session.approve(action.itemId, true);
    }
    if (action.type === 'reject-tool') void session.approve(action.itemId, false);
    if (action.type === 'answer-clarification') {
      void session.answerClarification(action.itemId, action.answer);
    }
  }
</script>

<div bind:this={liveWorkspaceElement} class="live-workspace">
  <WorkspacePreview
    activeSessionId={snapshot.activeSessionId ?? ''}
    artifactInspectorEnabled={false}
    {appearance}
    {chatFocusHandoff}
    terminalPresentationActive={terminalLayerVisible}
    dataMode="live"
    interactionEnabled={snapshot.activeSessionId !== undefined}
    mode={snapshot.mode ?? 'chat'}
    model={snapshot.model}
    permanentFailure={snapshot.permanentFailure}
    sessions={snapshot.sessions}
    state={snapshot.state}
    {terminalModeEnabled}
    timelineEmptyLabel="No messages in this chat yet."
    timelineItems={snapshot.timeline}
    title={snapshot.title}
    onAction={handleAction}
  />
  {#if terminal || (snapshot.terminal?.status === 'failed' && terminalModeEnabled)}
    <div
      class="terminal-layer terminal-appearance-scope"
      class:active={terminalLayerVisible}
      data-appearance={appearance}
      data-testid="terminal-appearance-scope"
    >
      {#if terminal}
        <TerminalSurface
          active={terminalLayerVisible}
          bridge={terminal}
          coordinator={snapshot.coordinator ?? coordinator?.state}
          focusIntent={snapshot.coordinator?.focusIntent}
          title={snapshot.title}
          onAction={handleAction}
        />
      {:else}
        <section
          aria-labelledby="terminal-adapter-failure-title"
          class="terminal-adapter-failure"
          data-testid="terminal-adapter-failure"
          role="alert"
        >
          <p class="terminal-adapter-eyebrow">Terminal unavailable</p>
          <h1 id="terminal-adapter-failure-title">Terminal setup failed</h1>
          <p>
            Chat remains available. Return to Chat. Terminal can retry only after this workspace owner is replaced.
          </p>
          <Pill
            ariaLabel="Return to Chat"
            label="Return to Chat"
            variant="neutral"
            onActivate={() => void requestMode('chat')}
          />
        </section>
      {/if}
    </div>
  {/if}
</div>

<style>
  .live-workspace {
    position: relative;
    min-height: 100dvh;
  }

  .terminal-layer {
    position: absolute;
    inset: 0;
    z-index: 2;
    display: flex;
    visibility: hidden;
    background: var(--canvas);
    color: var(--ink);
    pointer-events: none;
  }

  /* Terminal is a sibling of the preview, so it cannot inherit the preview's
     scoped aliases. Keep the two appearance contracts equal and opaque here. */
  .terminal-appearance-scope {
    --canvas: #f3f5f8;
    --surface: #ffffff;
    --ink: #16181d;
    --muted: #667080;
    --line: #d8dde5;
    --signal: #4c6fff;
    --courier: #e88a2a;
    --success: #2da568;
    --danger: #d94a4a;
    --focus: #2348c7;
    --action-ink: #040b1e;
    --radius-pill: 999px;
    --radius-input: 12px;
    --radius-nested: 14px;
    --radius-structural: 22px;
    background: #f3f5f8;
  }

  .terminal-appearance-scope[data-appearance='dark'] {
    --canvas: #0d1117;
    --surface: #171c24;
    --ink: #f4f6fa;
    --muted: #a7b0bf;
    --line: #343c49;
    --signal: #6f88ff;
    --courier: #f0a451;
    --success: #4cc989;
    --danger: #f06a6a;
    --focus: #c2ccff;
    --action-ink: #10151e;
    background: #0d1117;
  }

  .terminal-adapter-failure {
    box-sizing: border-box;
    display: flex;
    width: min(520px, calc(100% - 32px));
    align-self: center;
    margin-inline: auto;
    flex-direction: column;
    gap: 12px;
    padding: 24px;
    border: 1px solid var(--line);
    border-radius: var(--radius-structural);
    background: var(--surface);
  }

  .terminal-adapter-failure :is(h1, p) {
    margin: 0;
  }

  .terminal-adapter-eyebrow {
    color: var(--danger);
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .terminal-adapter-failure h1 {
    font-size: 24px;
    line-height: 1.2;
  }

  .terminal-adapter-failure p:not(.terminal-adapter-eyebrow) {
    color: var(--muted);
    line-height: 1.5;
  }

  .terminal-adapter-failure :global(.pill) {
    min-height: 44px;
    align-self: flex-start;
  }

  .terminal-layer.active {
    visibility: visible;
    pointer-events: auto;
  }
</style>
