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
  <div class="title-region">
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

  <div aria-label="Workspace mode" class="mode-controls">
    <Pill
      ariaLabel={mode === 'chat' ? 'Chat mode selected' : 'Switch to Chat mode'}
      icon="conversation"
      label="Chat"
      selected={mode === 'chat'}
      title={modeActionsEnabled ? (mode === 'chat' ? 'Chat mode is current' : 'Switch to Chat mode') : 'Deferred in this preview'}
      toggleable
      variant={mode === 'chat' ? 'selected' : 'ghost'}
      onActivate={modeActionsEnabled ? () => { if (mode !== 'chat') onAction({ type: 'set-mode', mode: 'chat' }); } : undefined}
    />
    <Pill
      ariaLabel={mode === 'terminal' ? 'Terminal mode selected' : 'Open terminal mode'}
      icon="terminal"
      label="Terminal"
      selected={mode === 'terminal'}
      title={modeActionsEnabled ? (mode === 'terminal' ? 'Terminal mode is current' : 'Open the current-session terminal') : 'Deferred in this preview'}
      toggleable
      variant={mode === 'terminal' ? 'selected' : 'ghost'}
      onActivate={modeActionsEnabled ? () => { if (mode !== 'terminal') onAction({ type: 'set-mode', mode: 'terminal' }); } : undefined}
    />
  </div>

  <Pill ariaLabel="Workspace options" icon="menu" iconOnly label="Workspace options" variant="ghost" />

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
    gap: 10px;
    padding: 8px 8px 8px 12px;
    border-bottom: 1px solid var(--line-soft);
  }

  .title-region {
    min-width: 0;
    flex: 1 1 auto;
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
    display: flex;
    flex: 0 0 auto;
    gap: 2px;
    padding: 2px;
    border: 1px solid var(--line-soft);
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--muted) 8%, transparent);
  }

  .mode-controls :global(.pill) {
    min-height: 44px;
    padding-inline: 10px;
  }

  .mode-controls :global(.pill.ghost) {
    color: var(--ink);
  }

  .mode-controls :global(.pill-label) {
    font-size: 13px;
  }

  .header-model {
    display: none;
    align-items: center;
    gap: 6px;
    color: var(--muted);
    font-size: 12px;
    line-height: 16px;
    white-space: nowrap;
  }

  @media (min-width: 1280px) {
    .header-model {
      display: inline-flex;
    }
  }

  @media (max-width: 620px) {
    .conversation-header {
      gap: 6px;
    }

    .mode-controls :global(.pill-label) {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
      white-space: nowrap;
    }

    .mode-controls :global(.pill) {
      width: 44px;
      min-width: 44px;
      padding-inline: 8px;
    }
  }
</style>
