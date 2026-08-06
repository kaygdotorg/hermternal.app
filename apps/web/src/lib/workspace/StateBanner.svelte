<script lang="ts">
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import type { WorkspaceActionHandler, WorkspaceRuntimeState } from './types';

  export let state: WorkspaceRuntimeState = 'ready';
  export let dataMode: 'fixture' | 'live' = 'fixture';
  export let onAction: WorkspaceActionHandler = () => {};
</script>

{#if state === 'streaming'}
  <div aria-live="polite" class="state-banner streaming-banner" data-testid="streaming-state" role="status">
    <div class="state-copy">
      <span aria-hidden="true" class="state-dot"></span>
      <div>
        <strong>Hermes is responding</strong>
        <span>Input stays available</span>
      </div>
    </div>
    <Pill
      ariaLabel="Stop response"
      icon="stop"
      label="Stop response"
      variant="danger"
      onActivate={() => onAction({ type: 'stop' })}
    />
  </div>
{:else if state === 'stopped'}
  <div aria-live="polite" class="state-banner stopped-banner" data-testid="stopped-state" role="status">
    <div class="state-copy">
      <span aria-hidden="true" class="state-icon"><Icon name="stop" size={16} /></span>
      <div>
        <strong>Response stopped</strong>
        <span>Interrupted response · no automatic retry</span>
      </div>
    </div>
    <span class="state-meta">Stopped by you</span>
  </div>
{:else if state === 'loading'}
  <div aria-busy="true" aria-live="polite" class="state-card loading-state" data-testid="loading-state" role="status">
    <span aria-hidden="true" class="loading-spinner"></span>
    <div>
      <strong>Restoring session</strong>
      <span>Messages load before the composer becomes available.</span>
    </div>
    <span class="state-meta">Read-only while loading</span>
  </div>
{:else if state === 'empty'}
  <div class="state-card empty-state" data-testid="empty-state">
    <span aria-hidden="true" class="state-icon"><Icon name="conversation" size={20} /></span>
    <div class="empty-copy">
      <strong>Start with a question</strong>
      {#if dataMode === 'live'}
        <span>This Hermes session has no messages yet. Send a message to begin.</span>
      {:else}
        <span>This session is ready for a fresh start. Available controls remain local to this preview.</span>
      {/if}
    </div>
    {#if dataMode === 'fixture'}
      <Pill
        label="Choose an action"
        icon="spark"
        variant="action"
        onActivate={() => onAction({ type: 'new-session' })}
      />
      <p>Mocked fixture only · synthetic empty state · no live connection</p>
    {/if}
  </div>
{:else if state === 'offline'}
  <div aria-live="polite" class="state-card offline-state" data-testid="offline-state" role="status">
    <div class="state-copy">
      <span aria-hidden="true" class="state-icon"><Icon name="warning" size={16} /></span>
      <div>
        <strong>You are offline</strong>
        <span>Drafts stay on this device. Sending is paused.</span>
      </div>
    </div>
    <Pill
      label="Check connection"
      icon="refresh"
      variant="action"
      onActivate={() => onAction({ type: 'check-connection' })}
    />
  </div>
{:else if state === 'reconnecting'}
  <div aria-live="polite" class="state-card reconnect-state" data-testid="reconnect-state" role="status">
    <div class="state-copy">
      <span aria-hidden="true" class="state-icon"><Icon name="refresh" size={16} /></span>
      <div>
        <strong>Connection interrupted</strong>
        <span>Reconnecting before any new prompt can be sent.</span>
      </div>
    </div>
    <Pill label="Cancel" variant="ghost" onActivate={() => onAction({ type: 'cancel-reconnect' })} />
  </div>
{:else if state === 'retryable-error'}
  <div aria-live="assertive" class="state-card error-state" data-testid="retryable-error-state" role="alert">
    <span aria-hidden="true" class="state-icon"><Icon name="refresh" size={18} /></span>
    <div class="error-copy">
      <strong>Connection lost</strong>
      {#if dataMode === 'live'}
        <span>Reconnect and inspect Hermes history before sending again. No prompt was resent.</span>
      {:else}
        <span>Your draft is safe. Reconnect before sending it. No prompt was resent.</span>
      {/if}
      <small>Focus order: status → Retry now → Later. Copy reflows at 200% zoom.</small>
    </div>
    <div class="state-actions">
      <Pill label="Retry now" icon="refresh" variant="action" onActivate={() => onAction({ type: 'retry' })} />
      <Pill label="Later" variant="ghost" onActivate={() => onAction({ type: 'dismiss' })} />
    </div>
  </div>
{:else if state === 'permanent-error'}
  <div aria-live="assertive" class="state-card error-state" data-testid="permanent-error-state" role="alert">
    <span aria-hidden="true" class="state-icon"><Icon name="warning" size={18} /></span>
    <div class="error-copy">
      <strong>Session state rejected</strong>
      <span>Hermes rejected the session state. No prompt was resent.</span>
      <small>Focus order: status → Back to sessions → Dismiss. No automatic recovery.</small>
    </div>
    <div class="state-actions">
      <Pill
        label="Back to sessions"
        icon="arrow-left"
        variant="action"
        onActivate={() => onAction({ type: 'back-to-sessions' })}
      />
      <Pill label="Dismiss" variant="ghost" onActivate={() => onAction({ type: 'dismiss' })} />
    </div>
  </div>
{/if}

<style>
  .state-banner,
  .state-card {
    box-sizing: border-box;
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 14px 18px;
    border: 1px solid var(--line);
    border-radius: var(--radius-popover);
    background: var(--surface);
    box-shadow: 0 12px 34px color-mix(in srgb, var(--ink) 10%, transparent);
  }

  .state-banner {
    position: absolute;
    top: 102px;
    right: 80px;
    left: 80px;
    z-index: 4;
    justify-content: space-between;
  }

  .state-card {
    max-width: 560px;
  }

  .state-copy,
  .empty-copy,
  .error-copy {
    min-width: 0;
    display: flex;
    flex: 1 1 auto;
    align-items: flex-start;
    gap: 10px;
  }

  .state-copy > div,
  .empty-copy,
  .error-copy {
    display: flex;
    min-width: 0;
    flex-direction: column;
    gap: 2px;
  }

  .state-copy strong,
  .empty-copy strong,
  .error-copy strong {
    color: var(--ink);
    font-size: 14px;
    font-weight: 600;
    line-height: 18px;
  }

  .state-copy span,
  .empty-copy span,
  .error-copy span {
    color: var(--muted);
    font-size: 12px;
    line-height: 16px;
  }

  .state-meta {
    flex: 0 0 auto;
    color: var(--muted);
    font-size: 11px;
    line-height: 16px;
  }

  .state-dot {
    display: inline-block;
    width: 10px;
    height: 10px;
    flex: 0 0 10px;
    margin-top: 4px;
    border-radius: 50%;
    background: var(--success);
    animation: state-pulse 1.4s ease-in-out infinite;
  }

  .state-icon {
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

  .stopped-banner {
    border-color: color-mix(in srgb, var(--courier) 35%, var(--line));
    background: color-mix(in srgb, var(--courier) 7%, var(--surface));
  }

  .offline-state,
  .reconnect-state,
  .loading-state {
    border-color: color-mix(in srgb, var(--signal) 28%, var(--line));
    background: color-mix(in srgb, var(--signal) 6%, var(--surface));
  }

  .error-state {
    align-items: flex-start;
    border-color: color-mix(in srgb, var(--danger) 35%, var(--line));
    background: color-mix(in srgb, var(--danger) 7%, var(--surface));
  }

  .error-copy small,
  .empty-state p {
    color: var(--muted);
    font-size: 11px;
    line-height: 15px;
  }

  .error-copy small {
    padding-top: 8px;
  }

  .state-actions {
    display: flex;
    flex: 0 0 auto;
    flex-wrap: wrap;
    gap: 6px;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 12px;
    padding: 24px;
    text-align: left;
  }

  .empty-state p {
    margin: 0;
  }

  .loading-spinner {
    width: 24px;
    height: 24px;
    flex: 0 0 24px;
    border: 2px solid color-mix(in srgb, var(--signal) 22%, transparent);
    border-top-color: var(--signal);
    border-radius: 50%;
    animation: spinner 700ms linear infinite;
  }

  @keyframes state-pulse {
    0%,
    100% {
      opacity: 0.35;
      transform: scale(0.85);
    }
    50% {
      opacity: 1;
      transform: scale(1);
    }
  }

  @keyframes spinner {
    to {
      transform: rotate(360deg);
    }
  }

  @media (max-width: 620px) {
    .state-banner {
      top: 76px;
      right: 16px;
      left: 16px;
      align-items: flex-start;
      padding: 12px;
    }

    .state-meta {
      display: none;
    }

    .state-card {
      width: 100%;
      max-width: none;
    }

    .error-state,
    .loading-state,
    .empty-state {
      flex-wrap: wrap;
    }

    .state-actions {
      width: 100%;
      padding-left: 38px;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .state-dot,
    .loading-spinner {
      animation: none;
    }
  }
</style>
