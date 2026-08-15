<script lang="ts">
  import { tick } from 'svelte';
  import type { WorkspaceMode } from '$lib/session/coordinator';
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import type { WorkspaceActionHandler } from './types';

  export let title = 'Quarterly analysis';
  export let model = 'Atlas · balanced';
  export let mode: WorkspaceMode = 'chat';
  export let terminalModeEnabled = true;
  export let terminalModeDisabledReason = 'Terminal is available after the first message is saved.';
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
        label={title}
        variant="neutral"
        onActivate={startEditing}
      />
    {/if}
  </div>

  <div aria-label="Workspace mode" class="mode-controls">
    <Pill
      ariaLabel={mode === 'chat' ? 'Chat mode selected' : 'Open chat mode'}
      icon="conversation"
      iconOnly
      label="Chat"
      revealLabel
      selected={mode === 'chat'}
      title={mode === 'chat' ? 'Chat mode is current' : 'Open chat mode'}
      toggleable
      variant={mode === 'chat' ? 'selected' : 'ghost'}
      onActivate={() => onAction({ type: 'set-mode', mode: 'chat' })}
    />
    <Pill
      ariaLabel={!terminalModeEnabled && mode !== 'terminal'
        ? 'Terminal unavailable until the first message is saved'
        : mode === 'terminal'
          ? 'Terminal mode selected'
          : 'Open terminal mode'}
      disabled={!terminalModeEnabled && mode !== 'terminal'}
      disabledReason={terminalModeDisabledReason}
      icon="terminal"
      iconOnly
      label="Terminal"
      revealLabel
      selected={mode === 'terminal'}
      title={!terminalModeEnabled && mode !== 'terminal'
        ? terminalModeDisabledReason
        : mode === 'terminal'
          ? 'Terminal mode is current'
          : 'Open terminal mode'}
      toggleable
      variant={mode === 'terminal' ? 'selected' : 'ghost'}
      onActivate={() => onAction({ type: 'set-mode', mode: 'terminal' })}
    />
  </div>

  <div class="share-control">
    <Pill
      ariaLabel="Workspace options"
      icon="share"
      iconOnly
      label="Workspace options"
      title="Sharing is deferred in this preview"
      variant="neutral"
    />
  </div>

  <div class="header-model" aria-label={`Current model ${model}`}>
    <Icon name="spark" size={14} />
    <span>{model}</span>
  </div>
</header>

<style>
  /* Paper uses an open 72px header. Each action has its own floating island;
     the header itself must not add a field background or divider. */
  .conversation-header {
    position: relative;
    box-sizing: border-box;
    display: flex;
    height: 72px;
    min-height: 72px;
    align-items: center;
    padding: 0 8px 0 12px;
    background: transparent;
  }

  .title-region {
    width: auto;
    max-width: calc(100% - 168px);
    min-width: 0;
    flex: 0 1 auto;
  }

  .title-region :global(.pill) {
    max-width: 100%;
    min-height: 44px;
    padding-inline: 16px;
  }

  /* Paper's resting desktop title is a 15px/600/20px role. The shared pill
     keeps the 44px target and its state behavior; only the title copy needs
     this larger conversation-heading treatment. */
  .title-region :global(.pill-label) {
    font-size: 15px;
    font-weight: 600;
    line-height: 20px;
  }

  .title-region :global(.pill .icon-slot:empty) {
    display: none;
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
    position: absolute;
    top: 14px;
    left: 50%;
    box-sizing: border-box;
    display: flex;
    width: 92px;
    height: 44px;
    flex: 0 0 auto;
    align-items: center;
    gap: 2px;
    padding: 0;
    overflow: visible;
    transform: translateX(-50%);
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
    box-shadow: 0 6px 14px color-mix(in srgb, var(--ink) 8%, transparent);
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

  .mode-controls :global(.pill.selected) {
    --pill-overlay-line: transparent;
    --pill-overlay-surface: color-mix(in srgb, var(--muted) 10%, var(--surface));
    border-color: transparent;
    background: var(--pill-overlay-surface);
  }

  .share-control {
    z-index: 1;
    display: flex;
    width: 44px;
    height: 44px;
    margin-left: auto;
    align-items: center;
    justify-content: center;
    flex: 0 0 44px;
  }

  .share-control :global(.pill) {
    width: 44px;
    min-width: 44px;
    height: 44px;
    min-height: 44px;
    border-color: var(--chrome-line);
    background: color-mix(in srgb, var(--surface) 88%, transparent);
    box-shadow: 0 6px 14px color-mix(in srgb, var(--ink) 8%, transparent);
    backdrop-filter: blur(18px) saturate(150%);
  }

  .header-model {
    display: none;
  }

  @media (prefers-reduced-transparency: reduce) {
    .share-control :global(.pill),
    .mode-controls::before {
      background: var(--surface);
      backdrop-filter: none;
    }
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
