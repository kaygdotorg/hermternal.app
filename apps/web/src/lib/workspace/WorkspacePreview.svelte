<script lang="ts">
  import { tick } from 'svelte';
  import type { WorkspaceMode } from '$lib/session/coordinator';
  import ArtifactInspector from './ArtifactInspector.svelte';
  import Composer from './Composer.svelte';
  import ConversationHeader from './ConversationHeader.svelte';
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import SessionList from './SessionList.svelte';
  import StateBanner from './StateBanner.svelte';
  import Timeline from './Timeline.svelte';
  import type { LiveWorkspacePermanentFailure } from './live-workspace-session';
  import { DEFAULT_SESSIONS, timelineForState } from './fixtures';
  import type {
    Appearance,
    SessionSummary,
    TimelineItem,
    WorkspaceAction,
    WorkspaceDataSource,
    WorkspaceActionHandler,
    WorkspaceRuntimeState
  } from './types';

  export let appearance: Appearance = 'light';
  export let dataSource: WorkspaceDataSource = 'synthetic-preview';
  export let state: WorkspaceRuntimeState = 'stopped';
  export let title = 'Quarterly analysis';
  export let model = 'Atlas · balanced';
  // The coordinator owns mode state; this preview only presents it and forwards selection actions.
  export let mode: WorkspaceMode = 'chat';
  export let activeSessionId = 'quarterly-logistics';
  export let sessions: SessionSummary[] = DEFAULT_SESSIONS;
  export let timelineItems: TimelineItem[] | undefined = undefined;
  export let timelineEmptyLabel = 'No messages in this synthetic session.';
  export let permanentFailure: LiveWorkspacePermanentFailure | undefined = undefined;
  export let dataMode: 'fixture' | 'live' = 'fixture';
  export let interactionEnabled = true;
  export let artifactInspectorEnabled = true;
  // The parent owns Terminal's sibling layer. Keep Chat inert until that painted
  // layer is gone, rather than inferring safety from the mode snapshot alone.
  export let terminalPresentationActive = false;
  export let chatFocusHandoff = false;
  export let terminalModeEnabled = true;
  export let terminalModeDisabledReason = 'Terminal is available after the first message is saved.';
  export let onAction: WorkspaceActionHandler = () => {};

  let inspectorVisible = artifactInspectorEnabled;
  let mobileSidebarOpen = false;
  let mobileWorkspaceOpen = false;
  let mobileTitleEditing = false;
  let mobileTitleDraft = title;
  let mobileTitleInput: HTMLInputElement | undefined;
  let mobileTitleTrigger: HTMLButtonElement | undefined;
  let mobileSidebarTrigger: HTMLButtonElement | undefined;
  let mobileWorkspaceTrigger: HTMLButtonElement | undefined;
  let mobileSidebarDrawer: HTMLElement | undefined;
  let mobileWorkspaceDrawer: HTMLElement | undefined;
  let mobileTitleLayer: HTMLElement | undefined;
  let modalTrigger: HTMLElement | undefined;
  let localTitle = title;
  let localModel = model;

  // REST restoration and session selection can replace these durable values after
  // mount. Sync only when the authoritative prop changes so unrelated state
  // updates do not overwrite an in-progress prototype-local edit.
  $: localTitle = title;
  $: localModel = model;

  // Explicit timeline input separates live server reads from deterministic fixtures.
  // Undefined preserves the Paper preview states; an empty array is a real empty session.
  $: timeline = timelineItems ?? timelineForState(state);
  $: if (!artifactInspectorEnabled) inspectorVisible = false;
  $: composerDisabled =
    !interactionEnabled ||
    state === 'loading' ||
    state === 'offline' ||
    state === 'reconnecting' ||
    state === 'retryable-error' ||
    state === 'permanent-error' ||
    state === 'compatibility-check-failed' ||
    state === 'unsupported-version';
  $: compatibilityBlocked = state === 'compatibility-check-failed' || state === 'unsupported-version';
  // Terminal owns a separate top layer. Its Chat projection must leave both the
  // sequential focus order and accessibility tree until that painted layer is
  // removed, not merely until the logical mode snapshot flips to Chat.
  $: terminalBlocked = (terminalPresentationActive || mode === 'terminal') && !chatFocusHandoff;
  $: selectorBlocked = compatibilityBlocked || mobileTitleEditing || mobileSidebarOpen || mobileWorkspaceOpen;
  $: underlayBlocked = selectorBlocked || terminalBlocked;
  $: if (compatibilityBlocked) {
    // A fail-closed gate dismisses transient drawers and editors before the
    // underlay becomes inert, leaving only the two recovery actions available.
    mobileSidebarOpen = false;
    mobileWorkspaceOpen = false;
    mobileTitleEditing = false;
  }

  function recoveryActionAllowed(action: WorkspaceAction): boolean {
    return action.type === 'retry-compatibility-check' || action.type === 'return-to-sign-in';
  }

  async function afterActivationFrame(): Promise<void> {
    await tick();
    await new Promise<void>((resolve) => {
      if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => resolve());
      else setTimeout(resolve, 0);
    });
  }

  function activeModalRoot(): HTMLElement | undefined {
    if (mobileTitleEditing) return mobileTitleLayer;
    if (mobileSidebarOpen) return mobileSidebarDrawer;
    if (mobileWorkspaceOpen) return mobileWorkspaceDrawer;
    return undefined;
  }

  function focusables(root: HTMLElement): HTMLElement[] {
    return Array.from(
      root.querySelectorAll<HTMLElement>(
        'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
    ).filter((element) => element.getAttribute('aria-hidden') !== 'true');
  }

  async function focusModalStart(): Promise<void> {
    await afterActivationFrame();
    const root = activeModalRoot();
    const first = root ? focusables(root)[0] : undefined;
    first?.focus();
  }

  async function closeMobileDrawers(restoreFocus = true): Promise<void> {
    const trigger = modalTrigger;
    mobileSidebarOpen = false;
    mobileWorkspaceOpen = false;
    modalTrigger = undefined;
    if (!restoreFocus) return;
    await afterActivationFrame();
    trigger?.focus();
  }

  function openMobileDrawer(kind: 'sidebar' | 'workspace'): void {
    if (compatibilityBlocked) return;
    // Pointer-down runs before the browser moves focus to the button. Use the
    // bound trigger identity so Escape and scrim close always restore focus.
    modalTrigger = kind === 'sidebar' ? mobileSidebarTrigger : mobileWorkspaceTrigger;
    mobileSidebarOpen = kind === 'sidebar';
    mobileWorkspaceOpen = kind === 'workspace';
    void focusModalStart();
  }

  function handleGlobalKeydown(event: KeyboardEvent): void {
    const root = activeModalRoot();
    if (!root || compatibilityBlocked) return;

    if (event.key === 'Escape') {
      event.preventDefault();
      if (mobileTitleEditing) void closeMobileTitleEditing(false);
      else void closeMobileDrawers();
      return;
    }

    if (event.key !== 'Tab') return;
    const controls = focusables(root);
    if (controls.length === 0) {
      event.preventDefault();
      return;
    }

    const currentIndex = controls.indexOf(document.activeElement as HTMLElement);
    if (currentIndex === -1) {
      event.preventDefault();
      controls[0].focus();
      return;
    }

    const nextIndex = event.shiftKey
      ? (currentIndex - 1 + controls.length) % controls.length
      : (currentIndex + 1) % controls.length;
    if ((event.shiftKey && currentIndex === 0) || (!event.shiftKey && currentIndex === controls.length - 1)) {
      event.preventDefault();
      controls[nextIndex].focus();
    }
  }

  async function startMobileTitleEditing(): Promise<void> {
    if (compatibilityBlocked) return;
    mobileTitleDraft = localTitle;
    mobileTitleEditing = true;
    await afterActivationFrame();
    if (!mobileTitleEditing) return;
    // Defer focus until the title pill's compatibility click completes so the
    // browser cannot return focus to the control hidden behind the modal layer.
    mobileTitleInput?.focus();
    mobileTitleInput?.select();
  }

  async function closeMobileTitleEditing(commit: boolean): Promise<void> {
    if (commit) {
      const nextTitle = mobileTitleDraft.trim();
      if (nextTitle && nextTitle !== localTitle) handleAction({ type: 'edit-title', title: nextTitle });
    }
    mobileTitleEditing = false;
    await afterActivationFrame();
    mobileTitleTrigger?.focus();
  }

  function handleMobileTitleKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      void closeMobileTitleEditing(true);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      void closeMobileTitleEditing(false);
    }
  }

  function toggleMobileSidebar(): void {
    // Forced events can bypass native `inert`; guard local presentation state
    // before any drawer mutation, matching the action-emission boundary below.
    if (compatibilityBlocked) return;
    if (mobileSidebarOpen) void closeMobileDrawers();
    else openMobileDrawer('sidebar');
  }

  function toggleMobileWorkspace(): void {
    if (compatibilityBlocked) return;
    if (mobileWorkspaceOpen) void closeMobileDrawers();
    else {
      openMobileDrawer('workspace');
      handleAction({ type: 'open-workspace' });
    }
  }

  function handleAction(action: WorkspaceAction): void {
    // `inert` is the browser and accessibility boundary; this handler guard is
    // the matching programmatic boundary for synthetic or forced DOM events.
    if (compatibilityBlocked && !recoveryActionAllowed(action)) return;
    if (action.type === 'toggle-inspector' && artifactInspectorEnabled) {
      if (mobileWorkspaceOpen) void closeMobileDrawers();
      else inspectorVisible = !inspectorVisible;
    }
    if (action.type === 'select-session') {
      activeSessionId = action.sessionId;
      if (mobileSidebarOpen) void closeMobileDrawers();
    }
    if (action.type === 'edit-title') localTitle = action.title;
    if (action.type === 'set-model') localModel = action.model;
    onAction(action);
  }
</script>

<svelte:window onkeydown={handleGlobalKeydown} />

<div class="workspace-preview-container">
  <section
    aria-label="Hermternal runtime workspace preview"
    class="workspace-preview"
    data-appearance={appearance}
    data-mode-source={dataMode}
    data-state={state}
    data-testid="runtime-preview"
  >
  <div
    aria-hidden={underlayBlocked ? 'true' : undefined}
    class="workspace-underlay"
    data-testid="workspace-underlay"
    inert={underlayBlocked}
    tabindex="-1"
  >
    <div aria-hidden="true" class="workspace-mobile-status-bar">
      <span class="status-time">9:41</span>
      <span class="status-system"><span>5G</span><span class="status-battery"><span></span></span></span>
    </div>

    <div class="mobile-toolbar">
      <div class="mobile-title-island" aria-label="Navigation and conversation">
      <Pill
        ariaLabel="Open conversations"
        bind:element={mobileSidebarTrigger}
        icon="menu"
        iconOnly
        label="Conversations"
        variant="ghost"
        onActivate={toggleMobileSidebar}
      />
      <Pill
        ariaLabel="Edit conversation title"
        bind:element={mobileTitleTrigger}
        label={localTitle}
        variant="ghost"
        onActivate={startMobileTitleEditing}
      />
    </div>
    <Pill
      ariaLabel="Open workspace"
      bind:element={mobileWorkspaceTrigger}
      expandable
      expanded={mobileWorkspaceOpen}
      icon="workspace"
      iconOnly
      label="Workspace"
      variant="neutral"
      onActivate={toggleMobileWorkspace}
    />
  </div>

    <div class:inspector-hidden={!artifactInspectorEnabled || !inspectorVisible} class="workspace-grid">
      <aside class="sidebar">
        <SessionList {activeSessionId} {sessions} onAction={handleAction} />
      </aside>

      <div class="conversation-panel">
        <ConversationHeader
          model={localModel}
          {mode}
          {terminalModeDisabledReason}
          {terminalModeEnabled}
          title={localTitle}
          onAction={handleAction}
        />

        <div class="conversation-body">
          <Timeline {dataSource} emptyLabel={timelineEmptyLabel} items={timeline} runtimeState={state} onAction={handleAction} />

          <div
            class:empty-layer={state === 'empty'}
            class:visible={state !== 'ready' && !compatibilityBlocked}
            class="state-layer"
          >
            {#if !compatibilityBlocked}
              <StateBanner {dataMode} {dataSource} {permanentFailure} {state} onAction={handleAction} />
            {/if}
          </div>

          <Composer
            disabled={composerDisabled}
            isStreaming={state === 'streaming'}
            model={localModel}
            onAction={handleAction}
          />
        </div>
      </div>

      {#if artifactInspectorEnabled && inspectorVisible}
        <div class="desktop-inspector">
          <ArtifactInspector onAction={handleAction} />
        </div>
      {/if}
    </div>
  </div>

  {#if dataMode === 'live'}
    <div
      aria-hidden={selectorBlocked ? 'true' : undefined}
      aria-label="Workspace mode"
      class="mobile-mode-selector"
      data-testid="mobile-mode-selector"
      inert={selectorBlocked}
      role="group"
    >
      <Pill
        ariaLabel={mode === 'chat' ? 'Chat mode selected' : 'Open chat mode'}
        icon="conversation"
        iconOnly
        label="Chat"
        selected={mode === 'chat'}
        toggleable
        variant="ghost"
        onActivate={() => handleAction({ type: 'set-mode', mode: 'chat' })}
      />
      <Pill
        ariaLabel={!terminalModeEnabled && mode !== 'terminal'
          ? 'Terminal unavailable until the first message is saved'
          : mode === 'terminal'
            ? 'Terminal mode selected'
            : 'Open terminal mode'}
        disabled={!terminalModeEnabled && mode !== 'terminal'}
        disabledReason={terminalModeDisabledReason}
        title={!terminalModeEnabled && mode !== 'terminal' ? terminalModeDisabledReason : undefined}
        icon="terminal"
        iconOnly
        label="Terminal"
        selected={mode === 'terminal'}
        toggleable
        variant="ghost"
        onActivate={() => handleAction({ type: 'set-mode', mode: 'terminal' })}
      />
    </div>
  {/if}

  {#if mobileSidebarOpen || mobileWorkspaceOpen}
    <button
      aria-label="Close drawer"
      class="mobile-drawer-scrim"
      data-testid="mobile-drawer-scrim"
      type="button"
      onclick={() => void closeMobileDrawers()}
    ></button>
  {/if}

  {#if mobileSidebarOpen}
    <div
      aria-label="Conversations"
      aria-modal="true"
      bind:this={mobileSidebarDrawer}
      class="mobile-session-drawer"
      data-testid="mobile-session-drawer"
      role="dialog"
    >
      <SessionList {activeSessionId} {sessions} onAction={handleAction} />
    </div>
  {/if}

  {#if mobileWorkspaceOpen}
    <div
      aria-label="Workspace"
      aria-modal="true"
      bind:this={mobileWorkspaceDrawer}
      class="mobile-workspace-drawer"
      data-testid="mobile-workspace-drawer"
      role="dialog"
    >
      <ArtifactInspector onAction={handleAction} />
    </div>
  {/if}

  {#if compatibilityBlocked}
    <div class="state-layer compatibility-layer visible" data-testid="compatibility-gate-layer">
      <StateBanner {dataSource} {state} onAction={handleAction} />
    </div>
  {/if}

  {#if mobileTitleEditing && !compatibilityBlocked}
    <div
      aria-label="Edit conversation title"
      aria-modal="true"
      bind:this={mobileTitleLayer}
      class="mobile-title-edit-layer"
      data-testid="mobile-title-editor"
      role="dialog"
    >
      <button
        aria-label="Cancel title editing"
        class="title-edit-dimmer"
        type="button"
        onclick={() => closeMobileTitleEditing(false)}
      ></button>
      <div class="centered-title-editor">
        <label class="sr-only" for="mobile-conversation-title">Conversation title</label>
        <input
          id="mobile-conversation-title"
          aria-label="Conversation title"
          bind:this={mobileTitleInput}
          bind:value={mobileTitleDraft}
          maxlength="72"
          onkeydown={handleMobileTitleKeydown}
        />
      </div>
      <div aria-hidden="true" class="mobile-keyboard" data-testid="represented-mobile-keyboard">
        <div class="keyboard-suggestions"><span>Quarterly</span><span>analysis</span><span>planning</span></div>
        {#each ['QWERTYUIOP', 'ASDFGHJKL', 'ZXCVBNM'] as row}
          <div class="keyboard-row">
            {#each row.split('') as key}<span class="keyboard-key">{key}</span>{/each}
          </div>
        {/each}
        <div class="keyboard-row keyboard-actions"><span>123</span><span>space</span><span>done</span></div>
      </div>
    </div>
  {/if}
  </section>
</div>

<style>
  .workspace-preview-container {
    width: 100%;
    min-width: 0;
    container-name: workspace-preview;
    container-type: inline-size;
  }

  .workspace-preview {
    --canvas: var(--color-canvas);
    --surface: var(--color-paper);
    --ink: var(--color-ink);
    --muted: var(--color-muted);
    --line: var(--color-line);
    --line-soft: color-mix(in srgb, var(--line) 70%, transparent);
    --signal: var(--color-signal);
    --courier: var(--color-courier);
    --courier-ink: #8a4b00;
    --success: var(--color-success);
    --danger: var(--color-danger);
    --focus: #2348c7;
    --action-ink: #040b1e;
    --gate-action: var(--color-gate-light-action);
    --gate-action-ink: var(--color-gate-light-action-ink);
    --gate-state-surface: var(--color-gate-light-state-surface);
    --gate-state-ink: var(--color-gate-light-state-ink);
    --gate-focus: var(--color-gate-light-focus);
    --gate-error-surface: var(--color-gate-light-error-surface);
    --gate-error-ink: var(--color-gate-light-error-ink);
    --gate-error-border: var(--color-gate-light-error-border);
    --chrome-surface: #f8fafdd1;
    --chrome-line: #3641521a;
    --chrome-shadow: #1f263429 0 22px 60px, #1f263414 0 2px 8px;
    --composer-surface: #ffffff99;
    --composer-shadow: #1f263424 0 16px 38px, #1f263412 0 2px 7px;
    --radius-pill: 999px;
    --radius-input: 12px;
    --radius-nested-glass: 14px;
    --radius-popover: 18px;
    --radius-glass: 22px;
    position: relative;
    box-sizing: border-box;
    container-name: workspace-preview;
    container-type: inline-size;
    width: 100%;
    height: 100dvh;
    min-width: 0;
    min-height: 0;
    overflow: hidden;
    background: var(--canvas);
    color: var(--ink);
    font-family: 'Instrument Sans', system-ui, sans-serif;
    font-synthesis: none;
    text-rendering: optimizeLegibility;
  }

  .workspace-preview[data-appearance='dark'] {
    --canvas: #0d1117;
    --surface: #171c24;
    --ink: #f4f6fa;
    --muted: #a7b0bf;
    --line: #343c49;
    --signal: #6f88ff;
    --courier: #f0a451;
    --courier-ink: #f0a451;
    --success: #4cc989;
    --danger: #f06a6a;
    --focus: #c2ccff;
    --action-ink: #10151e;
    --gate-action: var(--color-gate-dark-action);
    --gate-action-ink: var(--color-gate-dark-action-ink);
    --gate-state-surface: var(--color-gate-dark-state-surface);
    --gate-state-ink: var(--color-gate-dark-state-ink);
    --gate-focus: var(--color-gate-dark-focus);
    --gate-error-surface: var(--color-gate-dark-error-surface);
    --gate-error-ink: var(--color-gate-dark-error-ink);
    --gate-error-border: var(--color-gate-dark-error-border);
    --chrome-surface: #171c24d9;
    --chrome-line: #a7b0bf26;
    --chrome-shadow: #00000059 0 22px 60px, #0000003d 0 2px 8px;
    --composer-surface: #171c24d9;
    --composer-shadow: #00000059 0 16px 38px, #0000003d 0 2px 7px;
  }

  @media (prefers-color-scheme: dark) {
    .workspace-preview:not([data-appearance='light']) {
      --canvas: #0d1117;
      --surface: #171c24;
      --ink: #f4f6fa;
      --muted: #a7b0bf;
      --line: #343c49;
      --signal: #6f88ff;
      --courier: #f0a451;
      --courier-ink: #f0a451;
      --success: #4cc989;
      --danger: #f06a6a;
      --focus: #c2ccff;
      --action-ink: #10151e;
      --gate-action: var(--color-gate-dark-action);
      --gate-action-ink: var(--color-gate-dark-action-ink);
      --gate-state-surface: var(--color-gate-dark-state-surface);
      --gate-state-ink: var(--color-gate-dark-state-ink);
      --gate-focus: var(--color-gate-dark-focus);
      --gate-error-surface: var(--color-gate-dark-error-surface);
      --gate-error-ink: var(--color-gate-dark-error-ink);
      --gate-error-border: var(--color-gate-dark-error-border);
      --chrome-surface: #171c24d9;
      --chrome-line: #a7b0bf26;
      --chrome-shadow: #00000059 0 22px 60px, #0000003d 0 2px 8px;
      --composer-surface: #171c24d9;
      --composer-shadow: #00000059 0 16px 38px, #0000003d 0 2px 7px;
    }
  }

  .workspace-underlay {
    display: block;
    height: 100%;
  }

  /* Paper fixes the 1440px reference to 276 / 720 / 380 columns. Runtime
     height follows the viewport, while the two bounded transition families
     below reuse the approved mobile toolbar and drawers instead of shrinking
     text, targets, or the conversation beyond its readable width. */
  .workspace-grid {
    box-sizing: border-box;
    display: grid;
    grid-template-columns: minmax(220px, 276px) minmax(0, 720px) minmax(260px, 380px);
    grid-template-rows: calc(100% + 32px);
    gap: 16px;
    height: calc(100% - 32px);
    min-height: 0;
    padding: 16px;
  }

  .workspace-grid.inspector-hidden {
    grid-template-columns: minmax(220px, 276px) minmax(0, 720px);
  }

  .workspace-mobile-status-bar {
    display: none;
  }

  .sidebar,
  .conversation-panel,
  .desktop-inspector {
    min-width: 0;
    min-height: 0;
    height: 100%;
  }

  .desktop-inspector {
    display: flex;
  }

  .conversation-panel {
    position: relative;
    display: flex;
    overflow: hidden;
    flex-direction: column;
    border-radius: var(--radius-glass);
    background: color-mix(in srgb, var(--surface) 22%, transparent);
  }

  .conversation-body {
    position: relative;
    display: flex;
    height: calc(100% - 72px);
    min-height: 0;
    flex: 1 1 auto;
    flex-direction: column;
  }

  .conversation-body :global(.timeline) {
    flex: 1 1 auto;
    min-height: 0;
    overflow-y: auto;
  }

  .state-layer {
    position: absolute;
    top: 0;
    right: 0;
    left: 0;
    z-index: 2;
    display: none;
    justify-content: center;
    padding: 14px 36px 0;
    pointer-events: none;
  }

  .state-layer.visible {
    display: flex;
  }

  .state-layer :global(.state-banner),
  .state-layer :global(.state-card) {
    position: static;
    pointer-events: auto;
  }

  .state-layer.empty-layer {
    top: 0;
    bottom: 0;
    align-items: center;
    padding: 112px 36px 160px;
  }

  .state-layer.empty-layer :global(.state-card) {
    max-width: 400px;
  }

  .workspace-mobile-status-bar,
  .mobile-toolbar,
  .mobile-mode-selector,
  .mobile-drawer-scrim,
  .mobile-session-drawer,
  .mobile-workspace-drawer,
  .mobile-title-edit-layer {
    display: none;
  }

  .state-layer.compatibility-layer {
    top: 0;
    bottom: 0;
    z-index: 12;
    align-items: center;
    padding: 24px;
    background: color-mix(in srgb, var(--canvas) 58%, transparent);
    backdrop-filter: blur(8px) saturate(115%);
  }

  .state-layer.compatibility-layer :global(.compatibility-gate) {
    pointer-events: auto;
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }

  @container workspace-preview (max-width: 1439px) {
    .workspace-preview {
      height: 844px;
      min-height: 844px;
      overflow: visible;
    }

    .workspace-mobile-status-bar {
      box-sizing: border-box;
      display: flex;
      width: 100%;
      height: 62px;
      align-items: center;
      justify-content: space-between;
      padding: 21px 24px 19px;
      color: var(--ink);
      font-size: 12px;
      font-weight: 600;
      line-height: 16px;
    }

    .status-system {
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }

    .status-battery {
      position: relative;
      display: inline-flex;
      width: 23px;
      height: 12px;
      align-items: center;
      padding: 2px;
      border: 1px solid currentColor;
      border-radius: 4px;
    }

    .status-battery::after {
      position: absolute;
      top: 3px;
      right: -3px;
      width: 2px;
      height: 4px;
      border-radius: 0 2px 2px 0;
      background: currentColor;
      content: '';
    }

    .status-battery span {
      display: block;
      width: 100%;
      height: 100%;
      border-radius: 2px;
      background: currentColor;
    }

    .mobile-toolbar {
      box-sizing: border-box;
      display: flex;
      width: 100%;
      min-height: 64px;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 10px 16px;
    }

    .mobile-title-island {
      box-sizing: border-box;
      display: flex;
      width: 198px;
      height: 44px;
      align-items: center;
      padding: 0;
      border: 1px solid var(--chrome-line);
      border-radius: var(--radius-pill);
      background: var(--composer-surface);
      box-shadow: 0 6px 14px color-mix(in srgb, var(--ink) 8%, transparent);
      backdrop-filter: blur(18px) saturate(150%);
    }

    .mobile-title-island :global(.pill) {
      height: 44px;
      min-height: 44px;
      border: 0;
      background: transparent;
      box-shadow: none;
    }

    .mobile-title-island :global(.pill:first-child) {
      width: 44px;
      flex: 0 0 44px;
      padding: 8px;
    }

    .mobile-title-island :global(.pill:last-child) {
      width: 154px;
      min-width: 0;
      flex: 0 0 154px;
      padding-inline: 11px;
    }

    .mobile-title-island :global(.pill:last-child .icon-slot) {
      display: none;
    }

    .mobile-title-island :global(.pill:last-child .pill-label) {
      font-size: 15px;
      line-height: 20px;
    }

    .mobile-toolbar > :global(.pill) {
      width: 44px;
      height: 44px;
      padding: 8px;
      border-color: var(--chrome-line);
      background: var(--composer-surface);
      box-shadow: 0 6px 14px color-mix(in srgb, var(--ink) 8%, transparent);
      backdrop-filter: blur(18px) saturate(150%);
    }

    .workspace-preview[data-mode-source='live'] .mobile-toolbar > :global(.pill) {
      display: none;
    }

    .mobile-mode-selector {
      position: absolute;
      top: 72px;
      right: 16px;
      z-index: 14;
      box-sizing: border-box;
      display: flex;
      width: 92px;
      height: 44px;
      align-items: center;
      gap: 4px;
      padding: 2px;
      border: 1px solid var(--chrome-line);
      border-radius: var(--radius-pill);
      background: var(--composer-surface);
      box-shadow: 0 6px 14px color-mix(in srgb, var(--ink) 8%, transparent);
      backdrop-filter: blur(18px) saturate(150%);
    }

    .mobile-mode-selector :global(.pill) {
      position: relative;
      width: 40px;
      height: 40px;
      min-width: 40px;
      min-height: 40px;
      padding: 8px;
      border: 0;
      background: transparent;
      box-shadow: none;
    }

    /* Paper's visible 40px segments sit in a 44px toolbar row. Extend each
       pointer box into the shell padding so each mode keeps a 44px target. */
    .mobile-mode-selector :global(.pill::before) {
      position: absolute;
      inset: -2px;
      content: '';
    }

    .mobile-mode-selector :global(.pill.selected) {
      background: color-mix(in srgb, var(--signal) 12%, var(--surface));
    }

    .conversation-panel :global(.conversation-header) {
      display: none;
    }

    .workspace-grid {
      display: block;
      grid-template-rows: 718px;
      height: 718px;
      min-height: 718px;
      padding: 0;
    }

    .workspace-grid > .sidebar,
    .workspace-grid > .desktop-inspector {
      display: none;
    }

    .mobile-drawer-scrim {
      position: absolute;
      top: 62px;
      right: 0;
      bottom: 0;
      left: 0;
      z-index: 10;
      display: block;
      width: 100%;
      height: auto;
      padding: 0;
      border: 0;
      background: #343b4780;
      backdrop-filter: blur(2px);
    }

    .mobile-session-drawer,
    .mobile-workspace-drawer {
      position: absolute;
      top: 74px;
      left: 12px;
      z-index: 11;
      display: block;
      box-sizing: border-box;
      height: 756px;
      max-height: calc(100% - 88px);
      overflow: hidden;
      border: 1px solid var(--chrome-line);
      border-radius: 28px;
      background: var(--chrome-surface);
      box-shadow: var(--chrome-shadow);
      contain: layout paint;
    }

    .mobile-session-drawer {
      width: min(342px, calc(100% - 24px));
    }

    .mobile-workspace-drawer {
      width: min(366px, calc(100% - 24px));
    }

    .mobile-session-drawer :global(.session-list),
    .mobile-workspace-drawer :global(.inspector) {
      box-sizing: border-box;
      display: flex;
      width: 100%;
      height: 100%;
      min-height: 0;
      border: 0;
      border-radius: 27px;
      box-shadow: none;
    }

    .mobile-title-edit-layer {
      position: absolute;
      inset: 0;
      z-index: 20;
      display: block;
      min-height: 100%;
    }

    .title-edit-dimmer {
      position: absolute;
      top: 62px;
      right: 0;
      bottom: 0;
      left: 0;
      width: 100%;
      height: auto;
      padding: 0;
      border: 0;
      background: #0d11175c;
      backdrop-filter: blur(14px) saturate(120%);
    }

    .centered-title-editor {
      position: absolute;
      top: 218px;
      right: 24px;
      left: 24px;
      display: flex;
      height: 112px;
      align-items: center;
      justify-content: center;
    }

    .centered-title-editor input {
      box-sizing: border-box;
      width: 100%;
      padding: 8px;
      border: 0;
      outline: 0;
      background: transparent;
      color: #fff;
      font: inherit;
      font-size: 28px;
      font-weight: 600;
      line-height: 34px;
      text-align: center;
      text-shadow: 0 2px 18px #0d111747;
    }

    .mobile-keyboard {
      position: absolute;
      right: 0;
      bottom: 0;
      left: 0;
      box-sizing: border-box;
      display: flex;
      height: 298px;
      flex-direction: column;
      gap: 8px;
      padding: 10px 6px 8px;
      border-top: 1px solid #ffffff94;
      background: #cdd1d8f5;
      box-shadow: 0 -12px 32px #0d11172e;
    }

    .keyboard-suggestions,
    .keyboard-row {
      display: flex;
      height: 44px;
      align-items: center;
      justify-content: center;
      gap: 6px;
    }

    .keyboard-suggestions {
      height: 36px;
      gap: 20px;
      color: #3c424c;
      font-size: 14px;
      line-height: 18px;
    }

    .keyboard-key,
    .keyboard-actions span {
      display: inline-flex;
      height: 44px;
      align-items: center;
      justify-content: center;
      border-radius: 5px;
      background: #fff;
      color: #111318;
      box-shadow: 0 1px 1px #00000038;
    }

    .keyboard-key {
      width: 32px;
      font-size: 20px;
      line-height: 24px;
    }

    .keyboard-actions {
      gap: 8px;
    }

    .keyboard-actions span:first-child,
    .keyboard-actions span:last-child {
      width: 92px;
    }

    .keyboard-actions span:nth-child(2) {
      width: 172px;
    }

    .keyboard-actions span:last-child {
      background: var(--signal);
      color: #fff;
      font-weight: 600;
    }

    .workspace-preview[data-appearance='dark'] .title-edit-dimmer {
      background: #04070b9e;
      backdrop-filter: blur(12px) saturate(110%);
    }

    .workspace-preview[data-appearance='dark'] .mobile-keyboard {
      border-top-color: #f4f6fa1a;
      background: #181d25fa;
      box-shadow: 0 -12px 34px #00000057;
    }

    .workspace-preview[data-appearance='dark'] .keyboard-suggestions {
      color: #d7dce5;
    }

    .conversation-panel {
      height: 718px;
      min-height: 718px;
      border-radius: var(--radius-nested-glass);
    }

    .conversation-body {
      height: 718px;
      min-height: 0;
      flex: 0 0 718px;
    }

    .state-layer {
      padding-inline: 16px;
    }

    .state-layer.empty-layer {
      padding: 100px 16px 152px;
    }
  }

  /* Between the exact 1440px and 390px boards, preserve the approved compact
     controls but omit the simulated phone status bar. The conversation remains
     capped at 720px, and both secondary columns move to the existing modal
     drawers instead of compressing their text or action targets. */
  @container workspace-preview (min-width: 761px) and (max-width: 1439px) {
    .workspace-preview {
      height: 100dvh;
      min-height: 0;
      overflow: hidden;
    }

    .workspace-mobile-status-bar {
      display: none;
    }

    .workspace-grid {
      width: min(720px, 100%);
      height: calc(100% - 64px);
      min-height: 0;
      margin-inline: auto;
    }

    .conversation-panel,
    .conversation-body {
      height: 100%;
      min-height: 0;
      flex-basis: auto;
    }

    .mobile-mode-selector {
      top: 10px;
    }

    .mobile-drawer-scrim,
    .title-edit-dimmer {
      top: 0;
    }

    .mobile-session-drawer,
    .mobile-workspace-drawer {
      top: 12px;
      height: calc(100% - 24px);
      max-height: none;
    }
  }

  @container workspace-preview (max-width: 420px) {
    .workspace-grid {
      padding: 0;
    }

    .conversation-panel {
      border-radius: 0;
    }

    .mobile-toolbar {
      padding-inline: 16px;
    }
  }

  @media (prefers-reduced-transparency: reduce) {
    .workspace-preview {
      --chrome-surface: var(--surface);
      --composer-surface: var(--surface);
    }

    /* Reduced transparency is a computed-material contract, not just a token
       swap: every frosted mobile surface becomes opaque and removes filtering. */
    .conversation-panel,
    .mobile-title-island,
    .mobile-mode-selector,
    .mobile-toolbar > :global(.pill),
    .title-edit-dimmer,
    .state-layer.compatibility-layer {
      background: var(--surface);
    }

    .title-edit-dimmer {
      background: var(--canvas);
    }

    .centered-title-editor input {
      color: var(--ink);
      text-shadow: none;
    }

    .workspace-preview :global(.session-list),
    .workspace-preview :global(.inspector),
    .workspace-preview :global(.composer),
    .mobile-toolbar,
    .mobile-title-island,
    .mobile-mode-selector,
    .mobile-toolbar > :global(.pill),
    .title-edit-dimmer,
    .state-layer.compatibility-layer {
      backdrop-filter: none;
    }
  }

  @media (forced-colors: active) {
    .workspace-preview {
      --line: CanvasText;
      --line-soft: CanvasText;
      --chrome-line: CanvasText;
      --focus: Highlight;
      --signal: Highlight;
      --ink: CanvasText;
      --muted: CanvasText;
      --surface: Canvas;
      --canvas: Canvas;
    }

    .workspace-preview :global(.session-list),
    .workspace-preview :global(.inspector),
    .workspace-preview :global(.composer),
    .conversation-panel,
    .mobile-session-drawer,
    .mobile-workspace-drawer,
    .mobile-title-island,
    .mobile-mode-selector,
    .mobile-toolbar > :global(.pill),
    .mobile-workspace-drawer,
    .title-edit-dimmer,
    .workspace-preview :global(.artifact-card),
    .workspace-preview :global(.approval-card),
    .workspace-preview :global(.clarification-card),
    .workspace-preview :global(.image-card),
    .workspace-preview :global(.stopped-card),
    .workspace-preview :global(.loading-card),
    .workspace-preview :global(.error-card) {
      border-color: CanvasText;
      background: Canvas;
      box-shadow: none;
      forced-color-adjust: auto;
    }

    .workspace-preview :global(.pill:focus-visible),
    .workspace-preview :global(button:focus-visible),
    .workspace-preview :global(textarea:focus-visible),
    .workspace-preview :global(input:focus-visible) {
      outline: 2px solid Highlight;
      outline-offset: 2px;
    }
  }
</style>
