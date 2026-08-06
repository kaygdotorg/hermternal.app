<script lang="ts">
  import ArtifactInspector from './ArtifactInspector.svelte';
  import Composer from './Composer.svelte';
  import ConversationHeader from './ConversationHeader.svelte';
  import Pill from './Pill.svelte';
  import SessionList from './SessionList.svelte';
  import StateBanner from './StateBanner.svelte';
  import Timeline from './Timeline.svelte';
  import { DEFAULT_SESSIONS, timelineForState } from './fixtures';
  import type {
    Appearance,
    SessionSummary,
    WorkspaceAction,
    WorkspaceActionHandler,
    WorkspaceRuntimeState
  } from './types';

  export let appearance: Appearance = 'light';
  export let state: WorkspaceRuntimeState = 'stopped';
  export let title = 'Quarterly analysis';
  export let model = 'Atlas · balanced';
  export let activeSessionId = 'quarterly-logistics';
  export let sessions: SessionSummary[] = DEFAULT_SESSIONS;
  export let onAction: WorkspaceActionHandler = () => {};

  let inspectorVisible = true;
  let mobileSidebarOpen = false;
  let localTitle = title;
  let localModel = model;

  $: timeline = timelineForState(state);
  $: composerDisabled =
    state === 'loading' ||
    state === 'offline' ||
    state === 'reconnecting' ||
    state === 'retryable-error' ||
    state === 'permanent-error';

  function handleAction(action: WorkspaceAction): void {
    if (action.type === 'toggle-inspector') inspectorVisible = !inspectorVisible;
    if (action.type === 'select-session') {
      activeSessionId = action.sessionId;
      mobileSidebarOpen = false;
    }
    if (action.type === 'edit-title') localTitle = action.title;
    if (action.type === 'set-model') localModel = action.model;
    onAction(action);
  }
</script>

<section
  aria-label="Hermternal runtime workspace preview"
  class="workspace-preview"
  data-appearance={appearance}
  data-state={state}
  data-testid="runtime-preview"
>
  <div class="mobile-toolbar">
    <Pill
      ariaLabel="Open conversations"
      icon="menu"
      label="Conversations"
      variant="ghost"
      onActivate={() => (mobileSidebarOpen = !mobileSidebarOpen)}
    />
    <span class="mobile-title">{localTitle}</span>
    <Pill ariaLabel="Open workspace options" icon="menu" iconOnly label="Workspace options" variant="ghost" />
  </div>

  <div class:inspector-hidden={!inspectorVisible} class="workspace-grid">
    <aside class:open={mobileSidebarOpen} class="sidebar">
      <SessionList {activeSessionId} {sessions} onAction={handleAction} />
    </aside>

    <div class="conversation-panel">
      <ConversationHeader model={localModel} title={localTitle} onAction={handleAction} />

      <div class="conversation-body">
        <Timeline items={timeline} runtimeState={state} onAction={handleAction} />

        <div class:empty-layer={state === 'empty'} class:visible={state !== 'ready'} class="state-layer">
          <StateBanner {state} onAction={handleAction} />
        </div>

        <Composer
          disabled={composerDisabled}
          isStreaming={state === 'streaming'}
          model={localModel}
          onAction={handleAction}
        />
      </div>
    </div>

    {#if inspectorVisible}
      <ArtifactInspector onAction={handleAction} />
    {/if}
  </div>
</section>

<style>
  .workspace-preview {
    --canvas: #f3f5f8;
    --surface: #ffffff;
    --ink: #16181d;
    --muted: #667080;
    --line: #d8dde5;
    --line-soft: color-mix(in srgb, var(--line) 70%, transparent);
    --signal: #4c6fff;
    --courier: #e88a2a;
    --courier-ink: #8a4b00;
    --success: #2da568;
    --danger: #d94a4a;
    --focus: #2348c7;
    --action-ink: #040b1e;
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
    width: 100%;
    min-width: 0;
    min-height: 960px;
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
      --chrome-surface: #171c24d9;
      --chrome-line: #a7b0bf26;
      --chrome-shadow: #00000059 0 22px 60px, #0000003d 0 2px 8px;
      --composer-surface: #171c24d9;
      --composer-shadow: #00000059 0 16px 38px, #0000003d 0 2px 7px;
    }
  }

  .workspace-grid {
    box-sizing: border-box;
    display: grid;
    grid-template-columns: minmax(220px, 276px) minmax(0, 720px) minmax(260px, 380px);
    gap: 16px;
    min-height: 928px;
    padding: 16px;
  }

  .workspace-grid.inspector-hidden {
    grid-template-columns: minmax(220px, 276px) minmax(0, 1fr);
  }

  .sidebar,
  .conversation-panel {
    min-width: 0;
    min-height: 0;
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
    min-height: 0;
    flex: 1 1 auto;
    flex-direction: column;
  }

  .conversation-body :global(.timeline) {
    flex: 1 1 auto;
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

  .mobile-toolbar {
    display: none;
  }

  @media (max-width: 1320px) {
    .workspace-grid {
      grid-template-columns: minmax(210px, 248px) minmax(0, 1fr) minmax(248px, 320px);
    }
  }

  @media (max-width: 1120px) {
    .workspace-grid {
      grid-template-columns: minmax(210px, 248px) minmax(0, 1fr);
    }

    .workspace-grid :global(.inspector) {
      display: none;
    }
  }

  @media (max-width: 760px) {
    .workspace-preview {
      min-height: 0;
      overflow: visible;
    }

    .mobile-toolbar {
      display: flex;
      min-height: 56px;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 8px 12px;
      border-bottom: 1px solid var(--line-soft);
      background: color-mix(in srgb, var(--surface) 82%, transparent);
      backdrop-filter: blur(18px) saturate(150%);
    }

    .mobile-title {
      min-width: 0;
      flex: 1 1 auto;
      overflow: hidden;
      color: var(--ink);
      font-size: 14px;
      font-weight: 600;
      line-height: 18px;
      text-align: center;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .workspace-grid {
      display: block;
      min-height: calc(100dvh - 56px);
      padding: 8px;
    }

    .sidebar {
      position: absolute;
      top: 64px;
      left: 8px;
      z-index: 8;
      display: none;
      box-sizing: border-box;
      width: min(276px, calc(100% - 16px));
      max-width: calc(100% - 16px);
      height: min(720px, calc(100dvh - 80px));
      max-height: calc(100dvh - 80px);
      overflow: auto;
      contain: layout paint;
    }

    .sidebar.open {
      display: block;
    }

    .conversation-panel {
      min-height: calc(100dvh - 72px);
      border-radius: var(--radius-nested-glass);
    }

    .state-layer {
      padding-inline: 16px;
    }

    .state-layer.empty-layer {
      padding: 100px 16px 152px;
    }
  }

  @media (max-width: 420px) {
    .workspace-grid {
      padding: 0;
    }

    .conversation-panel {
      border-radius: 0;
    }

    .mobile-toolbar {
      padding-inline: 8px;
    }
  }

  @media (prefers-reduced-transparency: reduce) {
    .workspace-preview {
      --chrome-surface: var(--surface);
      --composer-surface: var(--surface);
    }

    .workspace-preview :global(.session-list),
    .workspace-preview :global(.inspector),
    .workspace-preview :global(.composer),
    .mobile-toolbar {
      backdrop-filter: none;
    }
  }
</style>
