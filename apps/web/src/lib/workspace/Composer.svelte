<script lang="ts">
  import Pill from './Pill.svelte';
  import type { LiveWorkspaceDraft } from './live-workspace-session';
  import type { WorkspaceAction } from './types';

  type ComposerActionHandler = (action: WorkspaceAction) => void | boolean;

  export let model = 'Atlas · balanced';
  export let disabled = false;
  export let isStreaming = false;
  export let placeholder = 'Message Hermes...';
  export let retainedDraft: Readonly<LiveWorkspaceDraft> | undefined = undefined;
  export let onDraftChange: (draft: LiveWorkspaceDraft | undefined) => void = () => {};
  export let onAction: ComposerActionHandler = () => {};

  const MAX_MOCK_ATTACHMENTS = 8;

  let draft = '';
  let attachments: LiveWorkspaceDraft['attachments'] = [];
  let observedDraft: Readonly<LiveWorkspaceDraft> | undefined;
  let selectedModel = model;
  let lastSubmittedText = '';
  let editedSinceSubmit = true;

  // The root-owned snapshot is the restore authority after the authenticated
  // view unmounts. Do not mirror it into storage or a transcript-local item.
  $: if (retainedDraft !== observedDraft) {
    observedDraft = retainedDraft;
    draft = retainedDraft?.text ?? '';
    attachments = retainedDraft?.attachments ?? [];
    lastSubmittedText = '';
    editedSinceSubmit = true;
  }

  function sendMessage(): void {
    const text = draft.trim();
    if (!text || disabled || isStreaming || (!editedSinceSubmit && text === lastSubmittedText)) return;

    // Keep local and root-owned state until the action boundary confirms that
    // the live transport adopted the request. A rejected send must be retryable.
    const accepted = onAction({ type: 'send', text });
    if (accepted === false) return;
    lastSubmittedText = text;
    editedSinceSubmit = false;
    draft = '';
    attachments = [];
    onDraftChange(undefined);
  }

  function publishDraft(): void {
    const next: LiveWorkspaceDraft | undefined =
      draft.length > 0 || attachments.length > 0
        ? { text: draft, attachments: [...attachments] }
        : undefined;
    onDraftChange(next);
  }

  function addMockAttachment(): void {
    if (disabled || attachments.length >= MAX_MOCK_ATTACHMENTS) return;
    // The prototype does not open a file picker or retain file bytes. This
    // deterministic metadata-only record proves attachment draft retention
    // without introducing paths, blobs, credentials, or transport payloads.
    const index = attachments.length + 1;
    attachments = [
      ...attachments,
      {
        id: `mock-attachment-${index}`,
        name: index === 1 ? 'brief.png' : `attachment-${index}.dat`,
        mediaType: index === 1 ? 'image/png' : 'application/octet-stream',
        sizeBytes: 12
      }
    ];
    publishDraft();
    onAction({ type: 'attach' });
  }

  function handleDraftInput(): void {
    editedSinceSubmit = true;
    publishDraft();
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

<form aria-label="Message composer" class="composer" onsubmit={handleSubmit}>
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
      <div class="composer-action-island">
        <Pill
          ariaLabel="Add an attachment"
          icon="plus"
          iconOnly
          label="Add attachment"
          variant="ghost"
          {disabled}
          onActivate={addMockAttachment}
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
    </div>

    <div class="composer-right">
      <div class="composer-context-island">
        <div class="context-meter">
          <Pill ariaLabel="Context usage 62 percent" icon="spark" iconOnly label="62%" variant="ghost" {disabled} />
        </div>
        <label class="model-control">
          <span class="sr-only">Model</span>
          <span aria-hidden="true" class="model-short">Atlas</span>
          <select aria-label="Model" bind:value={selectedModel} {disabled} onchange={handleModelChange}>
            <option>Atlas · balanced</option>
            <option>Atlas · fast</option>
            <option>Atlas · precise</option>
          </select>
        </label>
        <Pill ariaLabel="Record a voice message" icon="mic" iconOnly label="Voice message" variant="ghost" {disabled} />
      </div>
      <div class="send-control">
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
    -webkit-backdrop-filter: blur(18px) saturate(150%);
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
    gap: 0;
  }

  /* Paper groups the compact actions into two visual islands. The child
     buttons keep their 44px targets, while the islands provide the visible
     36px narrow-board shells. */
  .composer-left :global(.pill),
  .composer-right :global(.pill) {
    min-height: 44px;
  }

  .composer-action-island,
  .composer-context-island {
    display: inline-flex;
    height: 44px;
    min-height: 44px;
    align-items: center;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--muted) 8%, transparent);
  }

  .composer-action-island,
  .composer-context-island,
  .send-control {
    flex: 0 0 auto;
  }

  .composer-action-island :global(.pill),
  .composer-context-island :global(.pill) {
    border-color: transparent;
    background: transparent;
    box-shadow: none;
  }

  .composer-action-island :global(.pill + .pill) {
    margin-left: -8px;
  }

  .context-meter {
    position: relative;
    display: inline-flex;
    width: 44px;
    height: 44px;
    align-items: center;
    justify-content: center;
    flex: 0 0 44px;
  }

  .context-meter::before {
    width: 14px;
    height: 14px;
    border: 2px solid var(--signal);
    border-right-color: color-mix(in srgb, var(--signal) 20%, transparent);
    border-radius: 50%;
    content: '';
    transform: rotate(-30deg);
  }

  .context-meter :global(.pill) {
    position: absolute;
    inset: 0;
    width: 44px;
    min-width: 44px;
    height: 44px;
    min-height: 44px;
    padding: 8px;
  }

  .context-meter :global(.pill .icon-slot) {
    visibility: hidden;
  }

  .context-meter :global(.pill:disabled) {
    border-color: transparent;
    background: transparent;
    color: transparent;
  }

  .model-control {
    position: relative;
    display: inline-flex;
    box-sizing: border-box;
    width: 76px;
    min-width: 76px;
    height: 44px;
    min-height: 44px;
    align-items: center;
    justify-content: center;
    gap: 4px;
    padding-inline: 0;
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
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    border: 0;
    outline: 0;
    background: transparent;
    color: transparent;
    font: inherit;
    font-size: 12px;
    line-height: 16px;
    opacity: 0;
    cursor: pointer;
  }

  .model-short {
    display: inline;
    color: var(--ink);
    font-size: 12px;
    font-weight: 600;
    line-height: 16px;
    pointer-events: none;
  }

  .model-control select:disabled {
    cursor: not-allowed;
  }

  .send-control {
    position: relative;
    z-index: 2;
    display: inline-flex;
    margin-left: -16px;
    align-items: center;
  }

  .send-control :global(.pill.action) {
    --pill-action: var(--ink);
    --action-ink: var(--canvas);
    width: 44px;
    min-width: 44px;
    height: 44px;
    min-height: 44px;
    border-color: var(--ink);
    background: var(--ink);
    color: var(--canvas);
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
    .composer {
      right: 16px;
      bottom: 16px;
      left: 16px;
      height: 100px;
      min-height: 100px;
    }

    .composer-controls {
      align-items: center;
    }

    .composer-left,
    .composer-right {
      flex-wrap: nowrap;
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

    .message-field {
      padding-inline: 7px;
    }

    .composer-action-island,
    .composer-context-island {
      height: 36px;
      min-height: 36px;
    }

    .composer-action-island {
      width: 72px;
      justify-content: center;
    }

    .composer-action-island :global(.pill) {
      width: 44px;
      min-width: 44px;
      min-height: 44px;
    }

    .composer-action-island :global(.pill + .pill) {
      margin-left: -8px;
    }

    .composer-context-island {
      width: 160px;
      justify-content: flex-start;
    }

    .model-control {
      width: 64px;
      min-width: 64px;
      height: 44px;
      min-height: 44px;
      justify-content: center;
      padding-inline: 0;
    }

    .send-control {
      margin-left: -30px;
      transform: translateX(2px);
    }

    .send-control :global(.pill.action) {
      background: transparent;
      box-shadow: inset 0 0 0 3px var(--ink);
    }

    .message-field textarea {
      transform: translateY(-6px);
    }

    .composer-controls {
      transform: translateY(-11px);
    }
  }

  @media (prefers-reduced-transparency: reduce) {
    .composer {
      background: var(--surface);
      backdrop-filter: none;
      -webkit-backdrop-filter: none;
    }

    .composer-action-island,
    .composer-context-island {
      background: color-mix(in srgb, var(--muted) 8%, var(--surface));
    }
  }
</style>
