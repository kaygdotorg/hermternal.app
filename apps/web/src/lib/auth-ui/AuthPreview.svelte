<script lang="ts">
  import Icon from '$lib/workspace/Icon.svelte';
  import Pill from '$lib/workspace/Pill.svelte';
  import ProviderCard from './ProviderCard.svelte';
  import { DEFAULT_PROVIDERS } from './fixtures';
  import type { AuthAction, AuthActionHandler, AuthProvider, AuthViewState } from './types';
  import type { Appearance } from '$lib/workspace/types';

  export let appearance: Appearance = 'light';
  export let state: AuthViewState = 'provider-selection';
  export let providers: AuthProvider[] = DEFAULT_PROVIDERS;
  export let onAction: AuthActionHandler = () => {};

  let username = 'alex';
  // This value is a deliberately synthetic fixture; it never crosses a transport boundary.
  let password = 'fixture-value';
  let passwordVisible = false;

  $: isProviderState = state === 'provider-selection' || state === 'discovery-pending';
  $: isPasswordState = state === 'password' || state === 'password-submitting';
  $: panelClass = isProviderState ? 'provider-panel' : state === 'session-expired' ? 'session-panel' : 'narrow-panel';

  function handleAction(action: AuthAction): void {
    if (action.type === 'toggle-password-visibility') passwordVisible = !passwordVisible;
    onAction(action);
  }

  function submitPassword(): void {
    onAction({ type: 'submit-password', username, password });
  }
</script>

<section
  aria-label="Hermternal authentication preview"
  class="auth-preview"
  data-appearance={appearance}
  data-state={state}
  data-testid="auth-preview"
>
  <div aria-hidden="true" class="mobile-status-bar">
    <span>9:41</span>
    <span class="status-icons"><span class="status-signal"></span><span class="status-wifi"></span><span class="status-battery"></span></span>
  </div>

  <div class="auth-frame">
    <div class="auth-panel {panelClass}">
      {#if state === 'provider-selection'}
        <header class="panel-heading">
          <p class="eyebrow">HERMTERNAL</p>
          <h1>Connect to Hermes</h1>
          <p>Choose one available sign-in method. Hermternal does not rank providers or retain reusable credentials.</p>
        </header>

        <div class="provider-list" aria-label="Available sign-in providers">
          {#each providers as provider (provider.id)}
            <ProviderCard provider={provider} onAction={handleAction} />
          {/each}
        </div>

        <p class="provider-note"><span aria-hidden="true" class="note-dot"></span>Connected to the configured HTTPS origin. Only providers reported by Hermes are shown.</p>
      {:else if state === 'discovery-pending'}
        <header class="panel-heading">
          <p class="eyebrow">PROVIDER DISCOVERY · PENDING</p>
          <h1>Discovering sign-in methods</h1>
          <p>Waiting for the configured Hermes deployment to report providers. Controls stay unavailable until the result is complete.</p>
        </header>

        <div class="provider-list" aria-label="Provider discovery in progress" aria-busy="true">
          {#each providers as provider (provider.id)}
            <ProviderCard disabled pending provider={provider} onAction={handleAction} />
          {/each}
        </div>

        <p class="provider-note"><span aria-hidden="true" class="note-dot"></span>Mocked only · provider discovery is pending; no sign-in action is available.</p>
      {:else if isPasswordState}
        <header class="panel-heading">
          <p class="eyebrow">BASIC AUTH PROVIDER{state === 'password-submitting' ? ' · SUBMITTING' : ''}</p>
          <h1>{state === 'password-submitting' ? 'Signing in to Hermes' : 'Sign in to Hermes'}</h1>
          <p>{state === 'password-submitting' ? 'Mocked only · submitting once to the configured Hermes origin. Controls remain disabled while the request is represented.' : 'Your password is sent only to the configured Hermes origin for this session. It is not retained by this prototype.'}</p>
        </header>

        <form aria-label="Hermes password sign in" class="password-form" onsubmit={(event) => { event.preventDefault(); submitPassword(); }}>
          <label class="field-label" for="auth-username">Username</label>
          <input id="auth-username" bind:value={username} disabled={state === 'password-submitting'} autocomplete="username" />

          <div class="password-label-row">
            <label class="field-label" for="auth-password">Password</label>
            <button
              aria-label={passwordVisible ? 'Hide password' : 'Show password'}
              class="show-password"
              disabled={state === 'password-submitting'}
              type="button"
              onclick={() => handleAction({ type: 'toggle-password-visibility' })}
            >{passwordVisible ? 'Hide' : 'Show'}</button>
          </div>
          <input
            id="auth-password"
            bind:value={password}
            disabled={state === 'password-submitting'}
            autocomplete="current-password"
            type={passwordVisible ? 'text' : 'password'}
          />

          <div class="auth-action">
            <Pill
              ariaLabel={state === 'password-submitting' ? 'Signing in' : 'Sign in'}
              disabled={state === 'password-submitting'}
              label={state === 'password-submitting' ? 'Signing in…' : 'Sign in'}
              variant="action"
              onActivate={submitPassword}
            />
          </div>
          <Pill label={state === 'password-submitting' ? 'Cancel sign-in' : 'Back to providers'} variant="ghost" onActivate={() => handleAction({ type: 'back-to-providers' })} />
        </form>

        {#if state === 'password-submitting'}
          <p class="interaction-note">Static mocked state · 44px targets · focus order is fields → sign in → cancel.</p>
        {/if}
      {:else if state === 'callback'}
        <div class="callback-progress" aria-hidden="true"><span></span></div>
        <div class="callback-message">
          <h1>Completing sign-in</h1>
          <p>Checking the provider response and creating a protected browser session.</p>
        </div>
        <div class="privacy-note">
          <span aria-hidden="true" class="info-icon"><Icon name="info" size={16} /></span>
          <p>Do not close this tab. Callback parameters are checked once and are not rendered into the transcript.</p>
        </div>
        <Pill label="Cancel and return to providers" variant="ghost" onActivate={() => handleAction({ type: 'cancel-callback' })} />
      {:else if state === 'session-expired'}
        <div class="session-icon" aria-hidden="true"><Icon name="refresh" size={20} /></div>
        <div class="session-copy">
          <h1>Session expired</h1>
          <p>Sign in again to continue. Your draft stays on this device until you choose what to do.</p>
        </div>
        <div class="session-actions">
          <Pill label="Sign in again" variant="action" onActivate={() => handleAction({ type: 'sign-in-again' })} />
          <Pill label="Discard draft" variant="ghost" onActivate={() => handleAction({ type: 'discard-draft' })} />
        </div>
        <p class="provider-note"><span aria-hidden="true" class="note-dot"></span>Draft retained locally. No prompt was sent after the session expired.</p>
      {:else if state === 'failure' || state === 'discovery-retry' || state === 'provider-unavailable'}
        <div class="failure-icon" aria-hidden="true"><Icon name={state === 'discovery-retry' ? 'refresh' : 'warning'} size={20} /></div>
        <div class="failure-heading">
          <h1>{state === 'failure' ? 'Sign-in did not complete' : state === 'discovery-retry' ? 'Retry provider discovery' : 'Provider discovery stopped'}</h1>
          <p>{state === 'failure' ? 'Hermes rejected this attempt. No session was created and no credential was retained.' : state === 'discovery-retry' ? 'The previous result was unknown. A fresh user action is required before sign-in can continue.' : 'No usable provider list was returned. The client fails closed and does not invent a sign-in method.'}</p>
        </div>
        <div class="failure-detail">
          <strong>{state === 'failure' ? 'The provider rejected this request' : state === 'discovery-retry' ? 'Ready to retry' : 'provider_unavailable'}</strong>
          <p>{state === 'failure' ? 'Try again, or choose another provider. Error details do not include credentials.' : state === 'discovery-retry' ? 'Retry is idempotent; duplicate submits stay blocked until the first result settles.' : 'Empty or malformed provider data was rejected before sign-in actions were exposed.'}</p>
        </div>
        <div class="failure-actions">
          <Pill
            label={state === 'failure' ? 'Try again' : 'Retry discovery'}
            icon="refresh"
            variant="action"
            onActivate={() => handleAction({ type: state === 'failure' ? 'retry-authentication' : 'retry-discovery' })}
          />
          <Pill
            label={state === 'failure' ? 'Choose provider' : 'Back to sign-in'}
            variant="ghost"
            onActivate={() => handleAction({ type: state === 'failure' ? 'choose-provider-again' : 'back-to-sign-in' })}
          />
        </div>
        <p class="metadata">{state === 'failure' ? 'Reference: AUTH-REJECTED · Safe to retry' : state === 'discovery-retry' ? 'Mocked fixture · user initiated · safe to cancel' : 'Mocked fixture · empty + malformed · no credentials'}</p>
      {/if}
    </div>
  </div>
</section>

<style>
  .auth-preview {
    --canvas: #f3f5f8;
    --surface: #ffffff;
    --ink: #16181d;
    --muted: #667080;
    --line: #d8dde5;
    --signal: #3157c7;
    --success: #2da568;
    --danger: #ab3838;
    --danger-surface: #fff1f2;
    --focus: #2348c7;
    --action-ink: #ffffff;
    --radius-pill: 999px;
    --radius-input: 12px;
    --radius-glass: 22px;
    box-sizing: border-box;
    width: 100%;
    min-width: 0;
    min-height: 900px;
    background: var(--canvas);
    color: var(--ink);
    font-family: 'Instrument Sans', system-ui, sans-serif;
    font-synthesis: none;
    text-rendering: optimizeLegibility;
  }

  .auth-preview[data-appearance='dark'] {
    --canvas: #0d1117;
    --surface: #171c24;
    --ink: #f4f6fa;
    --muted: #a7b0bf;
    --line: #343c49;
    --signal: #6f88ff;
    --success: #4cc989;
    --danger: #f06a6a;
    --danger-surface: #351f26;
    --focus: #c2ccff;
    --action-ink: #10151e;
  }

  .auth-frame {
    box-sizing: border-box;
    display: flex;
    min-height: 900px;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }

  .auth-panel {
    box-sizing: border-box;
    display: flex;
    width: 440px;
    flex-direction: column;
    gap: 24px;
    padding: 32px;
    border: 1px solid var(--line);
    border-radius: var(--radius-glass);
    background: var(--surface);
    box-shadow: 0 18px 50px color-mix(in srgb, var(--ink) 10%, transparent);
  }

  .auth-panel.provider-panel {
    width: 480px;
  }

  .panel-heading {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .eyebrow {
    margin: 0;
    color: var(--signal);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.08em;
    line-height: 16px;
  }

  h1,
  p {
    margin: 0;
  }

  .panel-heading h1,
  .callback-message h1,
  .session-copy h1,
  .failure-heading h1 {
    color: var(--ink);
    font-size: 28px;
    font-weight: 600;
    letter-spacing: -0.025em;
    line-height: 34px;
  }

  .panel-heading > p:last-child,
  .callback-message p,
  .session-copy p,
  .failure-heading p,
  .failure-detail p,
  .privacy-note p,
  .interaction-note {
    color: var(--muted);
    font-size: 15px;
    line-height: 23px;
  }

  .provider-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .provider-note {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding-top: 2px;
    color: var(--muted);
    font-size: 12px;
    line-height: 18px;
  }

  .note-dot {
    display: inline-block;
    width: 12px;
    height: 12px;
    flex: 0 0 12px;
    margin-top: 3px;
    border-radius: 50%;
    background: var(--success);
  }

  .password-form {
    display: flex;
    flex-direction: column;
    gap: 7px;
  }

  .field-label {
    color: var(--ink);
    font-size: 14px;
    font-weight: 500;
    line-height: 18px;
  }

  .password-form input {
    box-sizing: border-box;
    width: 100%;
    min-height: 48px;
    margin: 0 0 7px;
    padding: 12px 14px;
    border: 1px solid var(--line);
    border-radius: var(--radius-input);
    outline: 0;
    background: var(--surface);
    color: var(--ink);
    font: inherit;
    font-size: 15px;
    line-height: 20px;
  }

  .password-form input:focus-visible {
    border-color: var(--focus);
    outline: 3px solid color-mix(in srgb, var(--focus) 28%, transparent);
    outline-offset: 2px;
  }

  .password-form input:disabled {
    color: var(--muted);
    opacity: 0.72;
  }

  .password-label-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .show-password {
    min-height: 44px;
    padding: 8px 10px;
    border: 0;
    border-radius: var(--radius-pill);
    background: transparent;
    color: var(--signal);
    font: inherit;
    font-size: 12px;
    cursor: pointer;
  }

  .show-password:focus-visible {
    outline: 3px solid var(--focus);
    outline-offset: 2px;
  }

  .show-password:disabled {
    color: var(--muted);
    cursor: not-allowed;
  }

  .auth-action :global(.pill),
  .session-actions :global(.pill:first-child) {
    width: 100%;
  }

  .interaction-note,
  .metadata {
    color: var(--muted);
    font-size: 12px;
    line-height: 18px;
  }

  .callback-progress {
    display: flex;
    width: 64px;
    height: 64px;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: color-mix(in srgb, var(--signal) 10%, var(--surface));
  }

  .callback-progress span {
    width: 28px;
    height: 28px;
    border: 3px solid color-mix(in srgb, var(--signal) 22%, transparent);
    border-top-color: var(--signal);
    border-radius: 50%;
    animation: spinner 700ms linear infinite;
  }

  .callback-message,
  .session-copy,
  .failure-heading,
  .failure-detail {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .callback-message h1,
  .session-copy h1,
  .failure-heading h1 {
    font-size: 28px;
  }

  .privacy-note {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px;
    border: 1px solid var(--line);
    border-radius: var(--radius-input);
    background: color-mix(in srgb, var(--signal) 6%, var(--surface));
  }

  .info-icon {
    display: inline-flex;
    width: 20px;
    height: 20px;
    flex: 0 0 20px;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: color-mix(in srgb, var(--signal) 12%, var(--surface));
    color: var(--signal);
  }

  .session-panel {
    width: 440px;
  }

  .session-icon,
  .failure-icon {
    display: inline-flex;
    width: 44px;
    height: 44px;
    align-items: center;
    justify-content: center;
    border-radius: 50%;
    background: color-mix(in srgb, var(--signal) 12%, var(--surface));
    color: var(--signal);
  }

  .session-actions,
  .failure-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .session-actions {
    flex-direction: column;
    gap: 0;
  }

  .failure-icon {
    background: color-mix(in srgb, var(--danger) 11%, var(--surface));
    color: var(--danger);
  }

  .failure-detail {
    gap: 4px;
    padding: 12px 14px;
    border: 1px solid color-mix(in srgb, var(--danger) 30%, var(--line));
    border-radius: var(--radius-input);
    background: var(--danger-surface);
  }

  .failure-detail strong {
    color: var(--danger);
    font-size: 14px;
    line-height: 18px;
  }

  .failure-detail p {
    font-size: 13px;
    line-height: 19px;
  }

  .failure-actions :global(.pill) {
    min-width: 100px;
  }

  .mobile-status-bar {
    display: none;
  }

  .status-icons {
    display: inline-flex;
    align-items: center;
    gap: 5px;
  }

  .status-signal {
    width: 18px;
    height: 10px;
    border-radius: 2px 2px 0 0;
    background: linear-gradient(to top, currentColor 25%, transparent 25% 100%);
    clip-path: polygon(0 100%, 0 75%, 25% 75%, 25% 50%, 50% 50%, 50% 25%, 75% 25%, 75% 0, 100% 0, 100% 100%);
  }

  .status-wifi {
    width: 16px;
    height: 10px;
    border: 2px solid currentColor;
    border-top-color: transparent;
    border-right-color: transparent;
    border-radius: 50%;
    transform: rotate(-45deg);
  }

  .status-battery {
    position: relative;
    display: inline-block;
    width: 20px;
    height: 9px;
    border: 1.5px solid currentColor;
    border-radius: 3px;
  }

  .status-battery::after {
    position: absolute;
    top: 2px;
    right: -4px;
    width: 2px;
    height: 4px;
    border-radius: 0 1px 1px 0;
    background: currentColor;
    content: '';
  }

  @keyframes spinner {
    to { transform: rotate(360deg); }
  }

  @media (max-width: 600px) {
    .auth-preview {
      min-height: 844px;
    }

    .auth-frame {
      min-height: 782px;
      align-items: stretch;
      justify-content: flex-start;
      padding: 0;
    }

    .mobile-status-bar {
      position: absolute;
      top: 0;
      right: 0;
      left: 0;
      z-index: 2;
      display: flex;
      height: 62px;
      align-items: center;
      justify-content: space-between;
      padding: 0 20px;
      color: var(--ink);
      font-size: 15px;
      font-weight: 600;
      line-height: 22px;
      pointer-events: none;
    }

    .auth-panel,
    .auth-panel.provider-panel,
    .auth-panel.session-panel {
      width: 100%;
      min-height: 782px;
      justify-content: flex-start;
      padding: 72px 20px 28px;
      border: 0;
      border-radius: 0;
      background: transparent;
      box-shadow: none;
    }

    .panel-heading h1,
    .callback-message h1,
    .session-copy h1,
    .failure-heading h1 {
      font-size: 28px;
      line-height: 36px;
    }

    .provider-list {
      gap: 12px;
    }

    .provider-note {
      display: none;
    }

    .password-form input {
      min-height: 52px;
      font-size: 16px;
    }

    .failure-actions {
      flex-direction: column;
    }

    .failure-actions :global(.pill) {
      width: 100%;
    }

    .session-panel {
      justify-content: center;
      padding-top: 110px;
      padding-bottom: 54px;
    }

    .session-actions {
      gap: 0;
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .callback-progress span {
      animation: none;
    }
  }

  @media (prefers-reduced-transparency: reduce) {
    .auth-panel {
      box-shadow: 0 8px 24px color-mix(in srgb, var(--ink) 10%, transparent);
    }
  }
</style>
