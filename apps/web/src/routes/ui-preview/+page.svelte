<script lang="ts">
  import { onMount } from 'svelte';
  import AuthPreview from '$lib/auth-ui/AuthPreview.svelte';
  import { discoverProviders } from '$lib/auth-ui/provider-discovery';
  import { DEFAULT_PROVIDERS } from '$lib/auth-ui/fixtures';
  import WorkspacePreview from '$lib/workspace/WorkspacePreview.svelte';
  import {
    authStateForProviderKind,
    type AuthAction,
    type AuthDiscoveryMode,
    type AuthProvider,
    type AuthViewState
  } from '$lib/auth-ui/types';
  import type { Appearance, WorkspaceAction, WorkspaceRuntimeState } from '$lib/workspace/types';

  const runtimeStates: WorkspaceRuntimeState[] = [
    'stopped',
    'ready',
    'streaming',
    'loading',
    'empty',
    'offline',
    'reconnecting',
    'retryable-error',
    'permanent-error',
    'compatibility-check-failed',
    'unsupported-version'
  ];

  const authStates: AuthViewState[] = [
    'provider-selection',
    'password',
    'callback',
    'failure',
    'session-expired',
    'discovery-pending',
    'discovery-retry',
    'discovery-empty',
    'discovery-malformed',
    'discovery-aborted',
    'provider-unavailable',
    'password-submitting'
  ];

  const liveDiscoveryConfigured = import.meta.env.VITE_HERMES_LIVE_AUTH_DISCOVERY === 'true';

  let appearance: Appearance = 'light';
  let runtimeState: WorkspaceRuntimeState = 'stopped';
  let authState: AuthViewState = 'provider-selection';
  let discoveryMode: AuthDiscoveryMode = 'fixture';
  let providers: AuthProvider[] = DEFAULT_PROVIDERS;
  let lastRuntimeAction = 'No runtime action yet';
  let lastAuthAction = 'No authentication action yet';
  let discoveryAbortController: AbortController | undefined;
  let discoveryAttempt = 0;
  let discoveryActive = false;

  function formatState(value: string): string {
    return value
      .split('-')
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ');
  }

  function isLiveDiscoveryRequested(): boolean {
    return new URLSearchParams(window.location.search).get('authDiscovery') === 'live';
  }

  function startProviderDiscovery(): void {
    discoveryAbortController?.abort();
    const controller = new AbortController();
    const attempt = discoveryAttempt + 1;
    discoveryAttempt = attempt;
    discoveryAbortController = controller;
    providers = [];
    authState = 'discovery-pending';

    void discoverProviders({ signal: controller.signal })
      .then((result) => {
        if (!discoveryActive || attempt !== discoveryAttempt || controller.signal.aborted) return;
        providers = result.providers;
        authState = result.providers.length === 0 ? 'discovery-empty' : 'provider-selection';
      })
      .catch((error: unknown) => {
        if (!discoveryActive || attempt !== discoveryAttempt || controller.signal.aborted) return;
        const code = error instanceof Error && 'code' in error ? String(error.code) : 'network';
        providers = [];
        if (code === 'aborted') authState = 'discovery-aborted';
        else if (code === 'malformed-json' || code === 'invalid-response' || code === 'body-too-large')
          authState = 'discovery-malformed';
        else authState = 'provider-unavailable';
      });
  }

  function stopProviderDiscovery(): void {
    discoveryActive = false;
    discoveryAttempt += 1;
    discoveryAbortController?.abort();
    discoveryAbortController = undefined;
  }

  function handleRuntimeAction(action: WorkspaceAction): void {
    lastRuntimeAction = action.type;
  }

  function handleAuthAction(action: AuthAction): void {
    lastAuthAction = action.type;

    if (action.type === 'retry-discovery' && discoveryMode === 'live') {
      startProviderDiscovery();
      return;
    }

    if (action.type === 'cancel-discovery' && discoveryMode === 'live') {
      discoveryAttempt += 1;
      discoveryAbortController?.abort();
      discoveryAbortController = undefined;
      providers = [];
      authState = 'discovery-aborted';
      return;
    }

    // Runtime-shaped provider data is untrusted. Only the two reviewed kinds
    // may advance; missing or future values fail closed instead of assuming OAuth.
    if (action.type === 'choose-provider') {
      authState = authStateForProviderKind(action.providerKind);
      return;
    }

    if (
      action.type === 'back-to-providers' ||
      action.type === 'cancel-callback' ||
      action.type === 'choose-provider-again' ||
      action.type === 'back-to-sign-in' ||
      action.type === 'discard-draft'
    ) {
      authState = 'provider-selection';
    }

    if (action.type === 'retry-authentication' || action.type === 'retry-discovery') {
      authState = action.type === 'retry-discovery' ? 'discovery-pending' : 'provider-selection';
    }

    if (action.type === 'submit-password-fixture') authState = 'password-submitting';
    if (action.type === 'sign-in-again') authState = 'provider-selection';
  }

  onMount(() => {
    const liveRequested = isLiveDiscoveryRequested();
    if (!liveRequested) return;

    discoveryMode = 'live';
    discoveryActive = true;
    if (!liveDiscoveryConfigured) {
      // Live mode is fail-closed when not explicitly enabled at build time.
      providers = [];
      authState = 'provider-unavailable';
      lastAuthAction = 'live-discovery-disabled';
      return stopProviderDiscovery;
    }

    startProviderDiscovery();
    return stopProviderDiscovery;
  });
</script>

<svelte:head>
  <title>Hermternal UI preview</title>
  <meta
    name="description"
    content="Static, transport-independent Runtime and Authentication UI states for Hermternal."
  />
</svelte:head>

<main aria-labelledby="preview-title" class="preview-page" data-appearance={appearance}>
  <header class="preview-header">
    <div class="heading-copy">
      <p class="eyebrow">HERMTERNAL · UI PREVIEW</p>
      <h1 id="preview-title">Runtime and authentication states</h1>
      <p class="intro">
        {discoveryMode === 'live'
          ? 'Opt-in provider discovery uses only the same-origin GET /api/auth/providers boundary. Credentials, transcripts, search, and deep links remain out of scope.'
          : 'Static presentation surfaces with synthetic fixtures only. Nothing on this page calls Hermes, stores credentials, mirrors transcripts, or exposes search and deep links.'}
      </p>
    </div>

    <div class="page-controls" aria-label="Preview controls">
      <label>
        <span>Appearance</span>
        <select bind:value={appearance} aria-label="Appearance">
          <option value="light">Light</option>
          <option value="dark">Dark</option>
        </select>
      </label>
      <a class="back-link" href="/" aria-label="Return to prototype shell">Return to shell</a>
    </div>
  </header>

  <section class="preview-section" aria-labelledby="runtime-heading">
    <div class="section-heading">
      <div>
        <p class="eyebrow">WEB STATES · RUNTIME</p>
        <h2 id="runtime-heading">Conversation workspace</h2>
      </div>
      <label class="state-control">
        <span>Runtime state</span>
        <select bind:value={runtimeState} aria-label="Runtime state">
          {#each runtimeStates as state}
            <option value={state}>{formatState(state)}</option>
          {/each}
        </select>
      </label>
    </div>
    <p class="section-note">{lastRuntimeAction}</p>
    <div class="runtime-stage">
      <WorkspacePreview {appearance} state={runtimeState} onAction={handleRuntimeAction} />
    </div>
  </section>

  <section class="preview-section" aria-labelledby="auth-heading">
    <div class="section-heading">
      <div>
        <p class="eyebrow">WEB STATES · AUTHENTICATION</p>
        <h2 id="auth-heading">Browser authentication boundary</h2>
      </div>
      <label class="state-control">
        <span>Authentication state</span>
        <select bind:value={authState} aria-label="Authentication state">
          {#each authStates as state}
            <option value={state}>{formatState(state)}</option>
          {/each}
        </select>
      </label>
    </div>
    <p class="section-note">{lastAuthAction}</p>
    <div class="auth-stage">
      <AuthPreview {appearance} {discoveryMode} {providers} state={authState} onAction={handleAuthAction} />
    </div>
  </section>

  <footer class="preview-footer">
    <span>Prototype-only fixture data</span>
    <span>Keyboard, reduced-motion, and reduced-transparency states are represented in the components.</span>
  </footer>
</main>

<style>
  .preview-page {
    --canvas: #f3f5f8;
    --surface: #ffffff;
    --ink: #16181d;
    --muted: #667080;
    --line: #d8dde5;
    --signal: #3157c7;
    box-sizing: border-box;
    display: flex;
    min-width: 0;
    min-height: 100vh;
    flex-direction: column;
    gap: 28px;
    padding: 32px;
    background: var(--canvas);
    color: var(--ink);
    font-family: 'Instrument Sans', system-ui, sans-serif;
    font-synthesis: none;
  }

  .preview-page[data-appearance='dark'] {
    --canvas: #0d1117;
    --surface: #171c24;
    --ink: #f4f6fa;
    --muted: #a7b0bf;
    --line: #343c49;
    --signal: #6f88ff;
  }

  .preview-header,
  .section-heading,
  .preview-footer {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 24px;
  }

  .heading-copy,
  .section-heading > div {
    display: flex;
    min-width: 0;
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
  h2,
  p {
    margin: 0;
  }

  h1 {
    font-size: 34px;
    font-weight: 600;
    letter-spacing: -0.03em;
    line-height: 40px;
  }

  h2 {
    font-size: 24px;
    font-weight: 600;
    letter-spacing: -0.02em;
    line-height: 30px;
  }

  .intro {
    max-width: 720px;
    color: var(--muted);
    font-size: 15px;
    line-height: 23px;
  }

  .page-controls,
  .state-control {
    display: flex;
    align-items: flex-end;
    gap: 10px;
  }

  .page-controls {
    flex-wrap: wrap;
    justify-content: flex-end;
  }

  .page-controls label,
  .state-control {
    display: flex;
    flex-direction: column;
    gap: 5px;
    color: var(--muted);
    font-size: 12px;
    line-height: 16px;
  }

  select {
    min-height: 44px;
    padding: 8px 34px 8px 12px;
    border: 1px solid var(--line);
    border-radius: 12px;
    background: var(--surface);
    color: var(--ink);
    font: inherit;
    font-size: 14px;
  }

  select:focus-visible,
  .back-link:focus-visible {
    outline: 3px solid color-mix(in srgb, var(--signal) 32%, transparent);
    outline-offset: 3px;
  }

  .back-link {
    display: inline-flex;
    min-height: 44px;
    align-items: center;
    padding: 8px 12px;
    border-radius: 999px;
    color: var(--signal);
    font-size: 14px;
    line-height: 18px;
    text-decoration: none;
  }

  .back-link:hover {
    background: color-mix(in srgb, var(--signal) 8%, transparent);
  }

  .preview-section {
    display: flex;
    min-width: 0;
    flex-direction: column;
    gap: 12px;
  }

  .section-note {
    min-height: 18px;
    color: var(--muted);
    font-size: 12px;
    line-height: 18px;
  }

  .runtime-stage,
  .auth-stage {
    min-width: 0;
    overflow: hidden;
    border: 1px solid var(--line);
    border-radius: 22px;
    background: var(--surface);
  }

  .runtime-stage :global(.workspace-preview) {
    max-height: 960px;
  }

  .auth-stage :global(.auth-preview) {
    min-height: 900px;
  }

  .preview-footer {
    flex-wrap: wrap;
    color: var(--muted);
    font-size: 12px;
    line-height: 18px;
  }

  @media (max-width: 760px) {
    .preview-page {
      gap: 22px;
      padding: 20px 12px;
    }

    .preview-header,
    .section-heading {
      flex-direction: column;
      align-items: stretch;
    }

    h1 {
      font-size: 28px;
      line-height: 34px;
    }

    .page-controls,
    .state-control {
      align-items: stretch;
      justify-content: stretch;
    }

    .page-controls label,
    .page-controls select,
    .state-control,
    .state-control select {
      width: 100%;
    }

    .back-link {
      justify-content: center;
      border: 1px solid var(--line);
      background: var(--surface);
    }

    .runtime-stage,
    .auth-stage {
      border-radius: 16px;
    }
  }

  @media (prefers-reduced-transparency: reduce) {
    .runtime-stage,
    .auth-stage {
      background: var(--surface);
    }
  }
</style>
