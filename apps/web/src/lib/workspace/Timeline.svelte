<script lang="ts">
  import Icon from './Icon.svelte';
  import type { IconName } from './icon-types';
  import Pill from './Pill.svelte';
  import type { TimelineItem, WorkspaceActionHandler } from './types';

  export let items: TimelineItem[] = [];
  export let onAction: WorkspaceActionHandler = () => {};

  function toolIcon(status: 'completed' | 'running' | 'pending' | 'failed'): IconName {
    if (status === 'completed') return 'check';
    if (status === 'failed') return 'warning';
    if (status === 'pending') return 'clock';
    return 'spark';
  }
</script>

<section aria-label="Conversation timeline" class="timeline" data-testid="conversation-timeline" role="log">
  {#if items.length === 0}
    <div class="timeline-empty">
      <Icon name="conversation" size={20} />
      <p>No messages in this synthetic session.</p>
    </div>
  {/if}

  {#each items as item (item.id)}
    {#if item.kind === 'user-message'}
      <article class="timeline-row user-row">
        <div class="user-message">
          <p>{item.text}</p>
          {#if item.attachments?.length}
            <div class="inline-attachments">
              {#each item.attachments as attachment (attachment.id)}
                <span class="attachment-chip"><Icon name="image" size={14} />{attachment.caption}</span>
              {/each}
            </div>
          {/if}
        </div>
      </article>
    {:else if item.kind === 'assistant-message'}
      <article class="timeline-row assistant-row">
        <header class="assistant-header">
          <span aria-hidden="true" class="assistant-avatar">H</span>
          <span class="assistant-name">Hermes</span>
          <span class="assistant-model">{item.model}</span>
          {#if item.status === 'draft'}<span class="draft-label">Draft</span>{/if}
        </header>
        <p class="assistant-copy">{item.text}</p>
      </article>
    {:else if item.kind === 'tool'}
      <article class="timeline-row tool-row">
        <span aria-hidden="true" class="step-icon {item.status}"><Icon name={toolIcon(item.status)} size={16} /></span>
        <div class="step-copy">
          <strong>{item.label}</strong>
          <span>{item.detail}</span>
        </div>
        <span class="step-status">{item.status}</span>
      </article>
    {:else if item.kind === 'approval'}
      <article class="timeline-row approval-card" aria-label={`Approval request: ${item.title}`}>
        <div class="approval-header">
          <span aria-hidden="true" class="step-icon approval"><Icon name="shield" size={16} /></span>
          <div>
            <strong>{item.title}</strong>
            <span>Action required before the next tool step</span>
          </div>
          {#if item.status !== 'pending'}<span class="approval-state">{item.status}</span>{/if}
        </div>
        <p>{item.description}</p>
        {#if item.status === 'pending'}
          <div class="approval-actions">
            <Pill
              label={item.confirmLabel}
              variant="action"
              onActivate={() => onAction({ type: 'approve-tool', itemId: item.id })}
            />
            <Pill
              label={item.rejectLabel}
              variant="ghost"
              onActivate={() => onAction({ type: 'reject-tool', itemId: item.id })}
            />
          </div>
        {/if}
      </article>
    {:else if item.kind === 'clarification'}
      <article class="timeline-row clarification-card" aria-label="Clarification request">
        <div class="clarification-heading">
          <span aria-hidden="true" class="step-icon clarification"><Icon name="info" size={16} /></span>
          <div>
            <strong>Clarification needed</strong>
            <span>{item.question}</span>
          </div>
        </div>
        <div class="clarification-options" role="group" aria-label="Clarification choices">
          {#each item.options as option}
            <button
              aria-pressed={item.selectedOption === option}
              class:selected={item.selectedOption === option}
              type="button"
              onclick={() => onAction({ type: 'answer-clarification', itemId: item.id, answer: option })}
            >{option}</button>
          {/each}
        </div>
      </article>
    {:else if item.kind === 'image'}
      <figure class="timeline-row image-card">
        {#if item.attachment.src}
          <img src={item.attachment.src} alt={item.attachment.alt} />
        {:else}
          <div aria-label={item.attachment.alt} class="image-placeholder" role="img">
            <Icon name="image" size={28} />
            <span>Image placeholder</span>
          </div>
        {/if}
        <figcaption>{item.attachment.caption}</figcaption>
      </figure>
    {:else if item.kind === 'streaming'}
      <article aria-live="polite" class="timeline-row streaming-card">
        <header class="assistant-header">
          <span aria-hidden="true" class="assistant-avatar">H</span>
          <span class="assistant-name">Hermes</span>
          <span class="assistant-model">{item.model}</span>
          <span class="streaming-label"><span class="streaming-dot"></span>Responding</span>
        </header>
        <p class="assistant-copy">{item.text}<span aria-hidden="true" class="streaming-caret"></span></p>
      </article>
    {:else if item.kind === 'stopped'}
      <article class="timeline-row stopped-card">
        <span aria-hidden="true" class="step-icon stopped"><Icon name="stop" size={16} /></span>
        <div>
          <strong>Response stopped</strong>
          <span>{item.text}</span>
        </div>
        <span class="step-status">Stopped by you</span>
      </article>
    {:else if item.kind === 'loading'}
      <article aria-busy="true" class="timeline-row loading-card">
        <span aria-hidden="true" class="loading-spinner"></span>
        <div>
          <strong>{item.label}</strong>
          <span>Messages load before the composer becomes available.</span>
        </div>
        <span class="step-status">Read-only while loading</span>
      </article>
    {:else if item.kind === 'error'}
      <article class="timeline-row error-card">
        <span aria-hidden="true" class="step-icon error"><Icon name="warning" size={16} /></span>
        <div>
          <strong>{item.title}</strong>
          <span>{item.detail}</span>
        </div>
      </article>
    {/if}
  {/each}
</section>

<style>
  .timeline {
    display: flex;
    min-width: 0;
    flex-direction: column;
    gap: 18px;
    padding: 28px 36px 176px;
    overflow: auto;
    scrollbar-width: thin;
    scrollbar-color: var(--line) transparent;
  }

  .timeline-row {
    min-width: 0;
  }

  .user-row {
    display: flex;
    justify-content: flex-end;
  }

  .user-message {
    max-width: min(510px, 88%);
    padding: 14px 16px;
    border-radius: 17px 17px 6px 17px;
    background: var(--signal);
    color: var(--action-ink);
    box-shadow: 0 8px 20px color-mix(in srgb, var(--signal) 18%, transparent);
  }

  .user-message p,
  .assistant-copy,
  .approval-card p {
    margin: 0;
    font-size: 15px;
    line-height: 23px;
  }

  .inline-attachments {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    padding-top: 10px;
  }

  .attachment-chip {
    display: inline-flex;
    min-height: 28px;
    align-items: center;
    gap: 5px;
    padding: 4px 8px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--action-ink) 16%, transparent);
    font-size: 12px;
    line-height: 16px;
  }

  .assistant-row,
  .streaming-card {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-inline: 8px;
  }

  .assistant-header,
  .approval-header,
  .clarification-heading,
  .stopped-card,
  .loading-card,
  .error-card,
  .tool-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .assistant-avatar {
    display: inline-flex;
    width: 28px;
    height: 28px;
    flex: 0 0 28px;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--line);
    border-radius: 50%;
    background: color-mix(in srgb, var(--signal) 12%, var(--surface));
    color: var(--signal);
    font-size: 13px;
    font-weight: 600;
    line-height: 18px;
  }

  .assistant-name,
  .assistant-model,
  .draft-label,
  .streaming-label {
    line-height: 18px;
  }

  .assistant-name {
    color: var(--ink);
    font-size: 14px;
    font-weight: 600;
  }

  .assistant-model,
  .draft-label,
  .streaming-label {
    color: var(--muted);
    font-size: 12px;
  }

  .draft-label {
    padding: 3px 7px;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--courier) 14%, transparent);
    color: var(--courier-ink, var(--courier));
  }

  .assistant-copy {
    max-width: 640px;
    color: var(--ink);
  }

  .tool-row {
    min-height: 28px;
    padding-inline: 28px;
  }

  .step-icon {
    display: inline-flex;
    width: 28px;
    height: 28px;
    flex: 0 0 28px;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: color-mix(in srgb, var(--signal) 11%, var(--surface));
    color: var(--signal);
  }

  .step-icon.completed {
    background: color-mix(in srgb, var(--success) 12%, var(--surface));
    color: var(--success);
  }

  .step-icon.pending,
  .step-icon.approval,
  .step-icon.clarification {
    background: color-mix(in srgb, var(--courier) 15%, var(--surface));
    color: var(--courier-ink, var(--courier));
  }

  .step-icon.failed,
  .step-icon.error {
    background: color-mix(in srgb, var(--danger) 12%, var(--surface));
    color: var(--danger);
  }

  .step-copy,
  .approval-header > div,
  .clarification-heading > div,
  .stopped-card > div,
  .loading-card > div,
  .error-card > div {
    min-width: 0;
    display: flex;
    flex: 1 1 auto;
    flex-direction: column;
    gap: 2px;
  }

  .step-copy strong,
  .approval-header strong,
  .clarification-heading strong,
  .stopped-card strong,
  .loading-card strong,
  .error-card strong {
    color: var(--ink);
    font-size: 14px;
    font-weight: 600;
    line-height: 18px;
  }

  .step-copy span,
  .approval-header span,
  .clarification-heading span,
  .stopped-card span,
  .loading-card span,
  .error-card span {
    color: var(--muted);
    font-size: 12px;
    line-height: 16px;
  }

  .step-status,
  .approval-state {
    flex: 0 0 auto;
    color: var(--muted);
    font-size: 11px;
    line-height: 16px;
    text-transform: uppercase;
  }

  .approval-card,
  .clarification-card,
  .image-card,
  .stopped-card,
  .loading-card,
  .error-card {
    padding: 14px 16px;
    border: 1px solid var(--line);
    border-radius: var(--radius-nested-glass);
    background: color-mix(in srgb, var(--surface) 86%, transparent);
  }

  .approval-card {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-inline: 28px;
    border-color: color-mix(in srgb, var(--courier) 35%, var(--line));
    background: color-mix(in srgb, var(--courier) 7%, var(--surface));
  }

  .approval-header {
    align-items: flex-start;
  }

  .approval-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    padding-left: 36px;
  }

  .clarification-card {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-inline: 28px;
  }

  .clarification-heading {
    align-items: flex-start;
  }

  .clarification-options {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    padding-left: 36px;
  }

  .clarification-options button {
    min-height: 44px;
    padding: 8px 12px;
    border: 1px solid var(--line);
    border-radius: var(--radius-pill);
    background: var(--surface);
    color: var(--ink);
    font: inherit;
    font-size: 13px;
    cursor: pointer;
  }

  .clarification-options button.selected {
    border-color: var(--signal);
    background: color-mix(in srgb, var(--signal) 12%, var(--surface));
  }

  .clarification-options button:focus-visible {
    outline: 3px solid var(--focus);
    outline-offset: 2px;
  }

  .image-card {
    display: flex;
    max-width: 360px;
    flex-direction: column;
    gap: 8px;
    margin: 0 28px;
  }

  .image-card img,
  .image-placeholder {
    display: flex;
    width: 100%;
    min-height: 148px;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-input);
    object-fit: cover;
    background: color-mix(in srgb, var(--signal) 8%, var(--surface));
    color: var(--signal);
  }

  .image-placeholder {
    flex-direction: column;
    gap: 8px;
    font-size: 12px;
    line-height: 16px;
  }

  .image-card figcaption {
    color: var(--muted);
    font-size: 12px;
    line-height: 16px;
  }

  .streaming-card {
    gap: 8px;
  }

  .streaming-label {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    margin-left: auto;
  }

  .streaming-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--success);
    animation: streaming-dot 1.25s ease-in-out infinite;
  }

  .streaming-caret {
    display: inline-block;
    width: 2px;
    height: 18px;
    margin-left: 3px;
    vertical-align: -3px;
    background: var(--signal);
    animation: caret-blink 1s steps(2, jump-none) infinite;
  }

  .stopped-card,
  .loading-card,
  .error-card {
    align-items: flex-start;
    margin-inline: 28px;
  }

  .stopped-card {
    border-color: color-mix(in srgb, var(--courier) 28%, var(--line));
    background: color-mix(in srgb, var(--courier) 7%, var(--surface));
  }

  .loading-card {
    border-color: color-mix(in srgb, var(--signal) 25%, var(--line));
    background: color-mix(in srgb, var(--signal) 7%, var(--surface));
  }

  .error-card {
    border-color: color-mix(in srgb, var(--danger) 35%, var(--line));
    background: color-mix(in srgb, var(--danger) 7%, var(--surface));
  }

  .loading-spinner {
    width: 20px;
    height: 20px;
    flex: 0 0 20px;
    border: 2px solid color-mix(in srgb, var(--signal) 22%, transparent);
    border-top-color: var(--signal);
    border-radius: 50%;
    animation: spinner 700ms linear infinite;
  }

  .timeline-empty {
    display: flex;
    min-height: 240px;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 10px;
    color: var(--muted);
    text-align: center;
  }

  .timeline-empty p {
    margin: 0;
    font-size: 14px;
    line-height: 20px;
  }

  @keyframes streaming-dot {
    0%, 100% { opacity: 0.35; transform: scale(0.8); }
    50% { opacity: 1; transform: scale(1); }
  }

  @keyframes caret-blink {
    50% { opacity: 0; }
  }

  @keyframes spinner {
    to { transform: rotate(360deg); }
  }

  @media (max-width: 620px) {
    .timeline {
      gap: 14px;
      padding: 20px 16px 156px;
    }

    .approval-card,
    .clarification-card,
    .image-card,
    .stopped-card,
    .loading-card,
    .error-card,
    .tool-row {
      margin-inline: 0;
    }

    .tool-row {
      padding-inline: 4px;
    }

    .approval-actions,
    .clarification-options {
      padding-left: 0;
    }

    .step-status,
    .approval-state {
      display: none;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .streaming-dot,
    .streaming-caret,
    .loading-spinner {
      animation: none;
    }
  }
</style>
