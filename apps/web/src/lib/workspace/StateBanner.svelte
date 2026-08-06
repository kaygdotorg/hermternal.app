<script lang="ts">
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import type { WorkspaceActionHandler, WorkspaceRuntimeState } from './types';

  export let state: WorkspaceRuntimeState = 'ready';
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
      <span>This session is ready for a fresh start. Available controls remain local to this preview.</span>
    </div>
    <Pill label="Choose an action" icon="spark" variant="action" onActivate={() => onAction({ type: 'new-session' })} />
    <p>Mocked fixture only · synthetic empty state · no live connection</p>
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
{:else if state === 'compatibility-check-failed' || state === 'unsupported-version'}
  <section
    aria-labelledby="compatibility-gate-title"
    aria-live="assertive"
    class="compatibility-gate"
    data-testid={`${state}-state`}
    role="alert"
  >
    <header class="gate-header">
      <span aria-hidden="true" class="gate-icon"><Icon name="warning" size={18} /></span>
      <div>
        <p>Compatibility gate · blocked</p>
        <h2 id="compatibility-gate-title">
          {state === 'compatibility-check-failed' ? 'Compatibility check failed' : 'Unsupported Hermes revision'}
        </h2>
      </div>
    </header>

    <p class="gate-message">
      {state === 'compatibility-check-failed'
        ? 'The deployment did not provide the attestation or behavioral proof required for dashboard-v0.0.1.'
        : 'This deployment is running a Hermes revision that Hermternal has not reviewed for dashboard-v0.0.1.'}
    </p>

    <div class="gate-boundary">
      <strong>{state === 'compatibility-check-failed' ? 'Fail-closed recovery' : 'Safe boundary'}</strong>
      <span>
        {state === 'compatibility-check-failed'
          ? 'Hermternal will not guess routes, downgrade behavior, or resend an uncertain prompt. Nothing was sent.'
          : 'Chat is paused. No prompts, tickets, credentials, or session changes will be sent.'}
      </span>
    </div>

    <div class="gate-evidence-group">
      <p class="evidence-heading">Safe details</p>
      <dl class="gate-evidence">
        {#if state === 'compatibility-check-failed'}
          <div><dt>Deployment attestation</dt><dd class="danger-value">Missing or mismatched</dd></div>
          <div><dt>Behavioral probe</dt><dd class="danger-value">Failed</dd></div>
          <div><dt>Route manifest</dt><dd>Not verified</dd></div>
        {:else}
          <div><dt>Expected contract</dt><dd>dashboard-v0.0.1</dd></div>
          <div><dt>Pinned source</dt><dd>f5be9236…068e</dd></div>
          <div><dt>Deployment attestation</dt><dd class="danger-value">Not verified</dd></div>
        {/if}
      </dl>
    </div>

    <div class="gate-actions">
      <Pill
        fullWidth
        label="Retry compatibility check"
        variant="action"
        onActivate={() => onAction({ type: 'retry-compatibility-check' })}
      />
      <Pill
        fullWidth
        label="Return to sign-in"
        variant="ghost"
        onActivate={() => onAction({ type: 'return-to-sign-in' })}
      />
    </div>

    <p class="gate-note">Mocked fixture only · synthetic evidence · no live compatibility request</p>
  </section>
{:else if state === 'retryable-error'}
  <div aria-live="assertive" class="state-card error-state" data-testid="retryable-error-state" role="alert">
    <span aria-hidden="true" class="state-icon"><Icon name="refresh" size={18} /></span>
    <div class="error-copy">
      <strong>Connection lost</strong>
      <span>Your draft is safe. Reconnect before sending it. No prompt was resent.</span>
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

  .compatibility-gate {
    --signal: var(--gate-action);
    --action-ink: var(--gate-action-ink);
    --focus: var(--gate-focus);
    box-sizing: border-box;
    display: flex;
    width: min(660px, 100%);
    flex-direction: column;
    gap: 14px;
    padding: 24px;
    border: 1px solid color-mix(in srgb, var(--gate-error-border) 60%, var(--line));
    border-radius: var(--radius-popover);
    background: var(--surface);
    box-shadow: 0 18px 50px color-mix(in srgb, var(--ink) 16%, transparent);
  }

  .gate-header {
    display: flex;
    align-items: flex-start;
    gap: 10px;
  }

  .gate-icon {
    display: inline-flex;
    width: 36px;
    height: 36px;
    flex: 0 0 36px;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: var(--gate-error-surface);
    color: var(--gate-error-ink);
  }

  .gate-header > div {
    display: flex;
    min-width: 0;
    flex-direction: column;
    gap: 2px;
  }

  .gate-header p,
  .gate-note,
  .evidence-heading {
    margin: 0;
    color: var(--gate-error-ink);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.06em;
    line-height: 16px;
    text-transform: uppercase;
  }

  .gate-header h2 {
    margin: 0;
    color: var(--ink);
    font-size: 20px;
    font-weight: 600;
    line-height: 26px;
  }

  .gate-message {
    margin: 0;
    color: var(--ink);
    font-size: 15px;
    line-height: 22px;
  }

  .gate-boundary {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 12px 14px;
    border: 1px solid var(--gate-error-border);
    border-radius: var(--radius-input);
    background: var(--gate-error-surface);
    box-shadow: inset 3px 0 0 var(--gate-error-border);
  }

  .gate-boundary strong,
  .gate-boundary span {
    font-size: 14px;
    line-height: 20px;
  }

  .gate-boundary strong,
  .danger-value {
    color: var(--gate-error-ink);
  }

  .gate-evidence-group {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 13px;
    border: 1px solid var(--line);
    border-radius: var(--radius-input);
    background: color-mix(in srgb, var(--muted) 6%, var(--surface));
  }

  .gate-evidence {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin: 0;
  }

  .evidence-heading {
    color: var(--muted);
  }

  .gate-evidence > div:not(.evidence-heading) {
    display: flex;
    justify-content: space-between;
    gap: 16px;
  }

  .gate-evidence dt,
  .gate-evidence dd {
    margin: 0;
    font-size: 14px;
    line-height: 20px;
  }

  .gate-evidence dt {
    color: var(--muted);
  }

  .gate-evidence dd {
    color: var(--ink);
    font-weight: 600;
    text-align: right;
  }

  .gate-evidence dd.danger-value {
    color: var(--gate-error-ink);
  }

  .gate-actions {
    display: flex;
    gap: 8px;
  }

  .gate-actions :global(.pill) {
    flex: 1 1 0;
  }

  .gate-actions :global(.pill.ghost) {
    color: var(--ink);
  }

  .gate-note {
    color: var(--muted);
    font-weight: 500;
    letter-spacing: 0;
    text-transform: none;
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

    .compatibility-gate {
      width: 100%;
      gap: 12px;
      padding: 20px;
    }

    .gate-actions {
      flex-direction: column;
    }

    .gate-evidence > div:not(.evidence-heading) {
      align-items: flex-start;
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
