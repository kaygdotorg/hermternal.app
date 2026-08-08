<script lang="ts">
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import type { WorkspaceActionHandler } from './types';

  export let model = 'Atlas · balanced';
  export let disabled = false;
  export let isStreaming = false;
  export let placeholder = 'Message Hermes…';
  export let onAction: WorkspaceActionHandler = () => {};

  let draft = '';
  let selectedModel = model;
  let lastSubmittedText = '';
  let editedSinceSubmit = true;

  function sendMessage(): void {
    const text = draft.trim();
    if (!text || disabled || isStreaming || (!editedSinceSubmit && text === lastSubmittedText)) return;

    lastSubmittedText = text;
    editedSinceSubmit = false;
    draft = '';
    onAction({ type: 'send', text });
  }

  function handleDraftInput(): void {
    editedSinceSubmit = true;
  }

  function handleSubmit(event: SubmitEvent): void {
    event.preventDefault();
    sendMessage();
  }

  function handleKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter' && (event.metaKey || event.ctrlKey) && !event.shiftKey) {
      event.preventDefault();
      const form = (event.currentTarget as HTMLElement).closest('form');
      form?.requestSubmit();
    }
  }

  function handleModelChange(): void {
    onAction({ type: 'set-model', model: selectedModel });
  }
</script>

<form aria-label="Message composer" class="composer" data-live-content="composer" onsubmit={handleSubmit}>
  <label class="message-field">
    <span class="sr-only">Message Hermes</span>
    <textarea
      aria-label="Message Hermes"
      bind:value={draft}
      {disabled}
      {placeholder}
      rows="1"
      oninput={handleDraftInput}
      onkeydown={handleKeydown}
    ></textarea>
    <span class="field-hint">⌘/Ctrl Enter to send · Shift Enter for a new line</span>
  </label>

  <div class="composer-controls">
    <div class="composer-left">
      <Pill
        ariaLabel="Add an attachment"
        icon="paperclip"
        iconOnly
        label="Add attachment"
        variant="ghost"
        {disabled}
        onActivate={() => onAction({ type: 'attach' })}
      />
      <Pill
        ariaLabel="Open security policy"
        icon="shield"
        label="Restricted"
        variant="ghost"
        {disabled}
        onActivate={() => onAction({ type: 'set-policy' })}
      />
    </div>

    <div class="composer-right">
      <Pill ariaLabel="Context usage 62 percent" icon="spark" label="62%" variant="ghost" {disabled} />
      <label class="model-control">
        <span class="sr-only">Model</span>
        <Icon name="spark" size={14} />
        <span aria-hidden="true" class="model-short">Atlas</span>
        <select aria-label="Model" bind:value={selectedModel} {disabled} onchange={handleModelChange}>
          <option>Atlas · balanced</option>
          <option>Atlas · fast</option>
          <option>Atlas · precise</option>
        </select>
      </label>
      <Pill ariaLabel="Record a voice message" icon="mic" iconOnly label="Voice message" variant="ghost" {disabled} />
      {#if isStreaming}
        <Pill
          ariaLabel="Stop response"
          icon="stop"
          label="Stop"
          variant="danger"
          onActivate={() => onAction({ type: 'stop' })}
        />
      {:else}
        <Pill
          ariaLabel="Send message"
          icon="send"
          iconOnly
          label="Send message"
          variant="action"
          disabled={disabled || !draft.trim()}
          onActivate={sendMessage}
        />
      {/if}
    </div>
  </div>
</form>

<style>
  .composer {
    position: absolute;
    right: 36px;
    bottom: 32px;
    left: 36px;
    z-index: 3;
    box-sizing: border-box;
    display: flex;
    height: 112px;
    min-height: 112px;
    flex-direction: column;
    gap: 4px;
    padding: 8px;
    border: 1px solid var(--chrome-line);
    border-radius: var(--radius-glass);
    background: var(--composer-surface);
    box-shadow: var(--composer-shadow);
    backdrop-filter: blur(18px) saturate(150%);
  }

  .message-field {
    display: flex;
    min-height: 44px;
    flex-direction: column;
    justify-content: center;
    padding-inline: 12px;
  }

  .message-field textarea {
    box-sizing: border-box;
    width: 100%;
    min-height: 23px;
    max-height: 132px;
    resize: vertical;
    border: 0;
    outline: 0;
    background: transparent;
    color: var(--ink);
    font: inherit;
    font-size: 15px;
    line-height: 23px;
  }

  .message-field textarea::placeholder {
    color: var(--muted);
    opacity: 1;
  }

  .message-field textarea:focus-visible {
    outline: 3px solid var(--focus);
    outline-offset: 3px;
    border-radius: var(--radius-input);
  }

  .field-hint {
    display: none;
    color: var(--muted);
    font-size: 11px;
    line-height: 15px;
  }

  .composer-controls {
    display: flex;
    min-height: 44px;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .composer-left,
  .composer-right {
    display: flex;
    min-width: 0;
    align-items: center;
    gap: 2px;
  }

  .composer-right {
    justify-content: flex-end;
  }

  .composer-left :global(.pill),
  .composer-right :global(.pill) {
    min-height: 44px;
  }

  .model-control {
    display: inline-flex;
    min-height: 44px;
    align-items: center;
    gap: 4px;
    padding-inline: 8px;
    border: 1px solid transparent;
    border-radius: var(--radius-pill);
    color: var(--muted);
  }

  .model-control:focus-within {
    border-color: var(--focus);
    outline: 3px solid color-mix(in srgb, var(--focus) 30%, transparent);
    outline-offset: 1px;
  }

  .model-control select {
    max-width: 90px;
    border: 0;
    outline: 0;
    background: transparent;
    color: var(--ink);
    font: inherit;
    font-size: 12px;
    line-height: 16px;
    cursor: pointer;
  }

  .model-short {
    display: none;
    color: var(--ink);
    font-size: 12px;
    font-weight: 600;
    line-height: 16px;
  }

  .model-control select:disabled {
    cursor: not-allowed;
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }

  @container workspace-preview (max-width: 760px) {
    .composer {
      right: 16px;
      bottom: 16px;
      left: 16px;
      height: 100px;
      min-height: 100px;
    }

    .composer-controls {
      align-items: flex-start;
    }

    .composer-left,
    .composer-right {
      flex-wrap: wrap;
    }

    .composer-right {
      gap: 0;
    }

    .composer-left :global(.pill-label),
    .composer-right :global(.pill-label) {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
      white-space: nowrap;
    }

    .composer-left :global(.pill),
    .composer-right :global(.pill) {
      width: 44px;
      min-width: 44px;
      padding-inline: 8px;
    }

    .model-control {
      width: 60px;
      min-width: 60px;
      justify-content: center;
      padding-inline: 6px;
    }

    .model-short {
      display: inline;
    }

    .model-control select {
      position: absolute;
      width: 1px;
      height: 1px;
      overflow: hidden;
      clip: rect(0 0 0 0);
      white-space: nowrap;
    }
  }
</style>
