<script lang="ts">
  import { tick } from 'svelte';
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import type { WorkspaceMode } from '$lib/session/coordinator';
  import type { WorkspaceActionHandler } from './types';

  export let title = 'Quarterly analysis';
  export let model = 'Atlas · balanced';
  export let mode: WorkspaceMode = 'chat';
  export let modeActionsEnabled = false;
  export let onAction: WorkspaceActionHandler = () => {};

  let editing = false;
  let draftTitle = title;
  let titleEditor: HTMLInputElement | undefined;
  let suppressBlurCommit = false;

  $: if (!editing) draftTitle = title;

  async function startEditing(): Promise<void> {
    suppressBlurCommit = false;
    draftTitle = title;
    editing = true;
    await tick();
    titleEditor?.focus();
    titleEditor?.select();
  }

  function finishEditing(): void {
    if (suppressBlurCommit) {
      suppressBlurCommit = false;
      return;
    }
    const nextTitle = draftTitle.trim();
    if (nextTitle) onAction({ type: 'edit-title', title: nextTitle });
    editing = false;
  }

  function cancelEditing(): void {
    suppressBlurCommit = true;
    editing = false;
    draftTitle = title;
  }

  function handleTitleKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter') {
      event.preventDefault();
      finishEditing();
    } else if (event.key === 'Escape') {
      event.preventDefault();
      cancelEditing();
    }
  }
</script>

<header class="conversation-header">
  <div class="title-region" data-live-content="conversation-title">
    {#if editing}
      <label class="title-editor-label" for="conversation-title">Conversation title</label>
      <input
        id="conversation-title"
        aria-label="Conversation title"
        class="title-editor"
        maxlength="72"
        bind:this={titleEditor}
        bind:value={draftTitle}
        onblur={finishEditing}
        onkeydown={handleTitleKeydown}
      />
    {:else}
      <Pill
        ariaLabel="Edit conversation title"
        fullWidth
        label={title}
        trailingIcon="chevron-down"
        variant="neutral"
        onActivate={startEditing}
      />
    {/if}
  </div>

  <!-- Keep the approved preview pill geometry while enabling live mode actions only when wired. -->
  <div aria-label="Workspace mode" class="mode-controls">
    <Pill
      ariaLabel={mode === 'chat' ? 'Chat mode selected' : 'Switch to Chat mode'}
      icon="conversation"
      iconOnly
      label="Chat"
      revealLabel
      selected={mode === 'chat'}
      title={modeActionsEnabled ? (mode === 'chat' ? 'Chat mode is current' : 'Switch to Chat mode') : 'Chat mode is current in this preview'}
      toggleable
      variant={mode === 'chat' ? 'selected' : 'ghost'}
      onActivate={modeActionsEnabled ? () => { if (mode !== 'chat') onAction({ type: 'set-mode', mode: 'chat' }); } : undefined}
    />
    <Pill
      ariaLabel={mode === 'terminal' ? 'Terminal mode selected' : 'Open terminal mode'}
      icon="terminal"
      iconOnly
      label="Terminal"
      revealLabel
      selected={mode === 'terminal'}
      title={modeActionsEnabled ? (mode === 'terminal' ? 'Terminal mode is current' : 'Open the current-session terminal') : 'Terminal mode is deferred in this preview'}
      toggleable
      variant={mode === 'terminal' ? 'selected' : 'ghost'}
      onActivate={modeActionsEnabled ? () => { if (mode !== 'terminal') onAction({ type: 'set-mode', mode: 'terminal' }); } : undefined}
    />
  </div>

  <Pill
    ariaLabel="Workspace options"
    icon="share"
    iconOnly
    label="Workspace options"
    title="Sharing is deferred in this preview"
    variant="ghost"
  />

  <div class="header-model" aria-label={`Current model ${model}`}>
    <Icon name="spark" size={14} />
    <span>{model}</span>
  </div>
</header>

<style>
  .conversation-header {
    box-sizing: border-box;
    display: flex;
    min-height: 72px;
    align-items: center;
    gap: 14px;
    padding: 8px 8px 8px 12px;
    border-bottom: 1px solid var(--line-soft);
  }

  .title-region {
    width: min(486px, 100%);
    min-width: 0;
    flex: 0 1 486px;
  }

  .title-region :global(.pill) {
    min-height: 44px;
  }

  .title-editor-label {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }

  .title-editor {
    box-sizing: border-box;
    width: 100%;
    min-height: 44px;
    padding: 10px 14px;
    border: 2px solid var(--focus);
    border-radius: var(--radius-pill);
    outline: none;
    background: var(--surface);
    color: var(--ink);
    font: inherit;
    font-size: 14px;
    font-weight: 600;
  }

  .mode-controls {
    position: relative;
    box-sizing: border-box;
    display: flex;
    width: 92px;
    height: 44px;
    flex: 0 0 auto;
    align-items: center;
    gap: 2px;
    padding: 0;
    overflow: visible;
  }

  /* The mode island may grow visually, but its layout slot stays 92px wide.
     Keeping the shell in a non-layout layer prevents a stationary pointer from
     losing the hovered Chat or Terminal button while the reveal settles. */
  .mode-controls::before {
    position: absolute;
    top: 0;
    left: 0;
    z-index: 0;
    box-sizing: border-box;
    width: 92px;
    height: 44px;
    border: 1px solid var(--line-soft);
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--muted) 8%, transparent);
    content: '';
    pointer-events: none;
    transition: width 150ms cubic-bezier(0.22, 1, 0.36, 1);
  }

  .mode-controls:has(:global(.pill:hover)),
  .mode-controls:has(:global(.pill:focus-visible)) {
    /* Raise the whole visual overlay above following header controls. The
       overlay itself remains pointer-transparent, so adjacent buttons keep
       their hit testing while the mode label is visibly unobscured. */
    z-index: 2;
  }

  .mode-controls:has(:global(.pill:hover))::before,
  .mode-controls:has(:global(.pill:focus-visible))::before {
    width: 220px;
  }

  .mode-controls :global(.pill) {
    position: relative;
    z-index: 1;
    width: 44px;
    min-width: 44px;
    height: 44px;
    min-height: 44px;
    padding-inline: 8px;
  }

  .mode-controls :global(.pill.ghost) {
    color: var(--ink);
  }

  .header-model {
    display: none;
  }

  @container workspace-preview (max-width: 760px) {
    .conversation-header {
      gap: 6px;
    }

    .mode-controls :global(.pill) {
      width: 44px;
      min-width: 44px;
      padding-inline: 8px;
    }
  }
</style>
