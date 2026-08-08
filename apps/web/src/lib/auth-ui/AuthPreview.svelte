<script lang="ts">
  import { onMount, tick } from 'svelte';
  import Icon from '$lib/workspace/Icon.svelte';
  import Pill from '$lib/workspace/Pill.svelte';
  import ProviderCard from './ProviderCard.svelte';
  import { DEFAULT_PROVIDERS, validateAuthProviders } from './fixtures';
  import type {
    AuthAction,
    AuthActionHandler,
    AuthDiscoveryMode,
    AuthProvider,
    AuthViewState,
    PasswordSubmissionHandler
  } from './types';
  import type { Appearance } from '$lib/workspace/types';

  export let appearance: Appearance = 'light';
  export let state: AuthViewState = 'provider-selection';
  export let providers: AuthProvider[] = DEFAULT_PROVIDERS;
  export let discoveryMode: AuthDiscoveryMode = 'fixture';
  export let onAction: AuthActionHandler = () => {};
  export let onPasswordSubmit: PasswordSubmissionHandler | undefined = undefined;
  export let failureMessage: string | undefined = undefined;
  export let failureCode: string | undefined = undefined;

  let passwordVisible = false;
  let previousState: AuthViewState = state;
  $: validatedProviders = validateAuthProviders(providers);
  // A selectable registry must validate before actions are exposed. Discovery
  // status screens may intentionally carry no providers while pending or failed.
  $: effectiveState = state === 'provider-selection' && !validatedProviders ? 'provider-unavailable' : state;
  $: safeProviders = validatedProviders ?? [];
  let submissionLocked = false;
  let formResetKey = 0;
  let stateHeading: HTMLElement | undefined;
  let passwordForm: HTMLFormElement | undefined;
  let usernameInput: HTMLInputElement | undefined;
  let passwordInput: HTMLInputElement | undefined;
  // A password form can be present before the browser has hydrated its event
  // handlers. Keep both controls read-only until focus ownership is explicit.
  let fieldOwnershipReady = false;
  let focusGeneration = 0;
  let componentMounted = false;

  $: if (effectiveState !== previousState) {
    resetPasswordEntry();
    previousState = effectiveState;
    void focusEnteredState();
  }
  $: isProviderState = isProviderPanelState(effectiveState);
  $: isPasswordState = effectiveState === 'password' || effectiveState === 'password-submitting';

  onMount(() => {
    componentMounted = true;
    // The password state can be the first client-rendered state, so it does not
    // pass through the state-change reactive block. Establish focus ownership
    // explicitly after hydration in that case.
    if (isPasswordState) void focusEnteredState();
    return () => {
      componentMounted = false;
      focusGeneration += 1;
    };
  });

  $: panelClass = isProviderState
    ? 'provider-panel'
    : effectiveState === 'session-expired' || effectiveState === 'logout-pending' || effectiveState === 'logout-failed'
      ? 'session-panel'
      : 'narrow-panel';
  $: politeAnnouncement =
    effectiveState === 'password-submitting'
      ? 'Signing in. The synthetic form is disabled while the local state completes.'
      : effectiveState === 'callback'
        ? 'Completing sign-in in a mocked local callback state.'
        : effectiveState === 'logout-pending'
          ? 'Signing out. Provider discovery and retry actions are unavailable until logout is verified.'
          : effectiveState === 'discovery-pending'
            ? 'Discovering sign-in methods. Provider actions are unavailable while the request is pending.'
            : effectiveState === 'discovery-retry'
              ? 'Provider discovery can be retried. Choose Retry discovery or Back to sign-in.'
              : '';
  $: assertiveAnnouncement =
    effectiveState === 'failure'
      ? 'Sign-in did not complete. Try again or choose another provider.'
      : effectiveState === 'logout-failed'
        ? 'Sign-out could not be verified. Only Retry sign out is available.'
        : effectiveState === 'session-expired'
        ? 'Session expired. Sign in again or discard the local draft fixture.'
        : effectiveState === 'discovery-empty'
          ? 'Provider discovery returned an invalid empty registry. No sign-in method is available.'
          : effectiveState === 'discovery-malformed'
            ? 'Provider discovery returned incompatible data. No sign-in method is available.'
            : effectiveState === 'discovery-aborted'
              ? 'Provider discovery was cancelled. No sign-in method is available.'
              : effectiveState === 'provider-unavailable'
                ? 'Provider discovery stopped. No sign-in method is available.'
                : '';

  function isProviderPanelState(value: AuthViewState): boolean {
    return (
      value === 'provider-selection' ||
      value === 'discovery-pending' ||
      value === 'discovery-empty' ||
      value === 'discovery-malformed' ||
      value === 'discovery-aborted' ||
      value === 'discovery-retry' ||
      value === 'provider-unavailable'
    );
  }

  function isDiscoveryFailureState(value: AuthViewState): boolean {
    return (
      value === 'failure' ||
      value === 'discovery-retry' ||
      value === 'discovery-malformed' ||
      value === 'discovery-aborted' ||
      value === 'provider-unavailable'
    );
  }

  function discoveryFailureHeading(value: AuthViewState): string {
    if (value === 'failure') return 'Sign-in did not complete';
    if (value === 'discovery-retry') return 'Retry provider discovery';
    if (value === 'discovery-malformed') return 'Provider discovery returned incompatible data';
    if (value === 'discovery-aborted') return 'Provider discovery was cancelled';
    return 'Provider discovery stopped';
  }

  function discoveryFailureCopy(value: AuthViewState): string {
    if (value === 'failure')
      return 'Synthetic failure state only. No request was made, no session was created, and no credential was retained.';
    if (value === 'discovery-retry')
      return 'A fresh same-origin provider discovery request is ready. Retry is safe because discovery is read-only.';
    if (value === 'discovery-malformed')
      return 'The provider response did not match the reviewed schema. The preview fails closed and exposes no invented sign-in method.';
    if (value === 'discovery-aborted')
      return 'The provider discovery request was cancelled before a usable registry was received. No provider action is available.';
    return 'The provider registry is unavailable. The preview fails closed and exposes no invented sign-in method.';
  }

  function discoveryFailureDetail(value: AuthViewState): string {
    if (value === 'failure') return 'Synthetic sign-in failure';
    if (value === 'discovery-retry') return 'Ready to retry provider discovery';
    if (value === 'discovery-malformed') return 'invalid_response';
    if (value === 'discovery-aborted') return 'aborted';
    return 'provider_unavailable';
  }

  function discoveryFailureDetailCopy(value: AuthViewState): string {
    if (value === 'failure') return 'Choose another local fixture state. Error details do not include credentials.';
    if (value === 'discovery-retry') return 'Retry starts only the idempotent GET /api/auth/providers boundary.';
    if (value === 'discovery-malformed')
      return 'Unknown fields, malformed data, and unsafe values are rejected after bounded strict parsing.';
    if (value === 'discovery-aborted') return 'Cancellation leaves no provider list and does not expose response data.';
    return 'The endpoint did not provide a usable provider registry. No fallback provider is invented.';
  }

  function discoveryFailureMetadata(value: AuthViewState): string {
    if (value === 'failure') return 'Synthetic fixture · safe to retry';
    if (value === 'discovery-retry') return 'Live boundary · user initiated · safe to retry';
    if (value === 'discovery-malformed') return 'Live boundary · fail closed · no credentials';
    if (value === 'discovery-aborted') return 'Live boundary · cancelled · no credentials';
    return 'Live boundary · unavailable · no credentials';
  }

  function resetPasswordEntry(): void {
    passwordVisible = false;
    submissionLocked = false;
    fieldOwnershipReady = false;
    focusGeneration += 1;
    formResetKey += 1;
  }

  async function focusEnteredState(): Promise<void> {
    const enteredState = effectiveState;
    const generation = focusGeneration;
    await tick();
    await new Promise<void>((resolve) => {
      if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => resolve());
      else setTimeout(resolve, 0);
    });
    if (!componentMounted || generation !== focusGeneration || effectiveState !== enteredState) return;
    // Focus waits until the activating click finishes. Otherwise a pointer-down
    // transition can focus the new task before the browser restores focus to
    // the provider button that was just removed. The controls stay read-only until
    // this focus transfer completes, so rapid typing cannot cross-populate them.
    if (effectiveState === 'password') {
      if (!usernameInput) return;
      usernameInput.focus();
      if (document.activeElement !== usernameInput) return;
    } else {
      stateHeading?.focus();
    }
    fieldOwnershipReady = true;
  }

  function handleAction(action: AuthAction): void {
    if (action.type === 'toggle-password-visibility') passwordVisible = !passwordVisible;
    if (
      action.type === 'back-to-providers' ||
      action.type === 'cancel-callback' ||
      action.type === 'choose-provider-again' ||
      action.type === 'back-to-sign-in' ||
      action.type === 'discard-draft'
    ) {
      resetPasswordEntry();
    }
    onAction(action);
  }

  function activatePasswordFixture(): void {
    if (
      effectiveState === 'password-submitting' ||
      submissionLocked ||
      !fieldOwnershipReady ||
      !passwordForm?.checkValidity()
    )
      return;

    submissionLocked = true;
    // Read the two owned controls directly instead of relying on FormData's
    // name lookup. Explicit refs keep a delayed hydration/focus transfer from
    // ever swapping the username and password channels.
    const username = usernameInput?.value ?? '';
    const password = passwordInput?.value ?? '';
    // Snapshot only the transient live values, then synchronously clear the DOM
    // before either the fixture action or live authentication callback can run.
    passwordForm.reset();
    formResetKey += 1;
    passwordVisible = false;

    if (discoveryMode === 'live') {
      if (onPasswordSubmit && typeof username === 'string' && typeof password === 'string') {
        // The live callback receives transient values once. Auth actions and observable
        // component state remain credential-free, and the keyed form is cleared now.
        onPasswordSubmit({ username, password });
      } else {
        submissionLocked = false;
      }
      return;
    }
    onAction({ type: 'submit-password-fixture' });
  }

  function handlePasswordSubmit(event: SubmitEvent): void {
    event.preventDefault();
    activatePasswordFixture();
  }

  function handlePasswordKeydown(event: KeyboardEvent): void {
    if (event.key !== 'Enter' || !(event.target instanceof HTMLInputElement)) return;
    event.preventDefault();
    activatePasswordFixture();
  }
</script>

<section
  aria-label="Hermternal authentication preview"
  class="auth-preview"
  data-appearance={appearance}
  data-discovery-mode={discoveryMode}
  data-state={effectiveState}
  data-testid="auth-preview"
>
  <div aria-hidden="true" class="mobile-status-bar">
    <span>9:41</span>
    <span class="status-icons"
      ><span class="status-signal"></span><span class="status-wifi"></span><span class="status-battery"></span></span
    >
  </div>

  {#if politeAnnouncement}
    <p aria-atomic="true" aria-live="polite" class="sr-only" role="status">{politeAnnouncement}</p>
  {/if}
  {#if assertiveAnnouncement}
    <p aria-atomic="true" aria-live="assertive" class="sr-only" role="alert">{assertiveAnnouncement}</p>
  {/if}

  <div class="auth-frame">
    <div class="auth-panel {panelClass}">
      {#if effectiveState === 'provider-selection'}
        <header class="panel-heading">
          <p class="eyebrow">HERMTERNAL</p>
          <h1 bind:this={stateHeading} tabindex="-1">Connect to Hermes</h1>
          <p>
            {discoveryMode === 'live'
              ? 'Choose a sign-in method reported by the same-origin Hermes boundary. This preview never stores reusable credentials or calls a provider.'
              : 'Choose one synthetic sign-in method. This preview never stores reusable credentials or calls a provider.'}
          </p>
        </header>

        <div class="provider-list" aria-label="Available sign-in providers">
          {#each safeProviders as provider (provider.id)}
            <ProviderCard {provider} onAction={handleAction} />
          {/each}
        </div>

        <p class="provider-note">
          <span aria-hidden="true" class="note-dot"></span>{discoveryMode === 'live'
            ? 'Live same-origin discovery · provider choices came from GET /api/auth/providers; no credentials are stored.'
            : 'Synthetic fixture only · provider choices are local presentation data; no discovery request is made.'}
        </p>
      {:else if effectiveState === 'discovery-pending'}
        <header class="panel-heading">
          <p class="eyebrow">PROVIDER DISCOVERY · PENDING</p>
          <h1 bind:this={stateHeading} tabindex="-1">Discovering sign-in methods</h1>
          <p>
            {discoveryMode === 'live'
              ? 'A same-origin GET /api/auth/providers request is pending. Provider actions stay unavailable until bounded data is validated.'
              : 'Static pending state only. No discovery request runs, and controls stay unavailable until the fixture state changes.'}
          </p>
        </header>

        <div class="provider-list" aria-label="Provider discovery in progress" aria-busy="true">
          {#each safeProviders as provider (provider.id)}
            <ProviderCard disabled pending {provider} onAction={handleAction} />
          {/each}
        </div>

        {#if discoveryMode === 'live'}
          <div class="failure-actions">
            <Pill
              label="Cancel discovery"
              variant="ghost"
              onActivate={() => handleAction({ type: 'cancel-discovery' })}
            />
          </div>
        {/if}
        <p class="provider-note">
          <span aria-hidden="true" class="note-dot"></span>{discoveryMode === 'live'
            ? 'Live boundary · provider actions stay disabled while discovery is pending.'
            : 'Prototype-only pending state · no sign-in action is available.'}
        </p>
      {:else if effectiveState === 'discovery-empty'}
        <div class="failure-icon" aria-hidden="true"><Icon name="warning" size={20} /></div>
        <div class="failure-heading">
          <h1 bind:this={stateHeading} tabindex="-1">No sign-in methods available</h1>
          <p>
            A successful empty provider registry is outside the pinned response contract. The preview fails closed and
            exposes no invented provider.
          </p>
        </div>
        <div class="failure-detail">
          <strong>invalid_empty_provider_registry</strong>
          <p>Retry discovery after Hermes reports the reviewed provider registry or exact unavailable response.</p>
        </div>
        <div class="failure-actions">
          <Pill
            label="Retry discovery"
            icon="refresh"
            variant="action"
            onActivate={() => handleAction({ type: 'retry-discovery' })}
          />
          <Pill label="Back to sign-in" variant="ghost" onActivate={() => handleAction({ type: 'back-to-sign-in' })} />
        </div>
        <p class="metadata">
          {discoveryMode === 'live'
            ? 'Live boundary · empty registry · no credentials'
            : 'Synthetic fixture · empty registry · no credentials'}
        </p>
      {:else if isPasswordState}
        <header class="panel-heading">
          <p class="eyebrow">BASIC AUTH PROVIDER{effectiveState === 'password-submitting' ? ' · SUBMITTING' : ''}</p>
          <h1 bind:this={stateHeading} tabindex="-1">
            {effectiveState === 'password-submitting' ? 'Signing in to Hermes' : 'Sign in to Hermes'}
          </h1>
          <p>
            {effectiveState === 'password-submitting'
              ? discoveryMode === 'live'
                ? 'Your password was cleared from the form and sent only to the configured Hermes origin for this sign-in attempt.'
                : 'Static submitting state only · the synthetic values were cleared and no request was made.'
              : discoveryMode === 'live'
                ? 'Your password is sent only to the configured Hermes origin for this sign-in attempt.'
                : 'Static fixture state. No credential values are stored or submitted.'}
          </p>
        </header>

        {#key formResetKey}
          <!-- `dialog` has no native navigation target outside a dialog. The
               reset-type primary action clears live values without script,
               while hydrated submit handling stays accessible. Synthetic
               fixtures suppress password managers; live controls intentionally
               omit those markers so username/current-password semantics remain
               discoverable while the hydration fence is still active. -->
          <form
            bind:this={passwordForm}
            aria-busy={effectiveState === 'password-submitting'}
            aria-label="Hermes password sign in"
            autocomplete={discoveryMode === 'live' ? undefined : 'off'}
            class="password-form"
            data-field-ownership={fieldOwnershipReady ? 'ready' : 'pending'}
            data-form-type={discoveryMode === 'live' ? undefined : 'other'}
            method="dialog"
            onsubmit={handlePasswordSubmit}
          >
            <label class="field-label" for="auth-username">Username</label>
            <input
              id="auth-username"
              autocomplete={discoveryMode === 'live' ? 'username' : 'off'}
              data-1p-ignore={discoveryMode === 'live' ? undefined : ''}
              data-lpignore={discoveryMode === 'live' ? undefined : 'true'}
              data-fixture-field={discoveryMode === 'live' ? undefined : 'username'}
              disabled={effectiveState === 'password-submitting'}
              placeholder={effectiveState === 'password-submitting' ? 'Cleared' : 'Enter username'}
              name={discoveryMode === 'live' ? 'username' : undefined}
              readonly={!fieldOwnershipReady}
              required
              onkeydown={handlePasswordKeydown}
              bind:this={usernameInput}
              value=""
            />

            <div class="password-label-row">
              <label class="field-label" for="auth-password">Password</label>
              <button
                aria-label={effectiveState === 'password-submitting'
                  ? 'Password hidden'
                  : passwordVisible
                    ? 'Hide password'
                    : 'Show password'}
                class="show-password"
                disabled={effectiveState === 'password-submitting'}
                type="button"
                onclick={() => handleAction({ type: 'toggle-password-visibility' })}
                >{effectiveState === 'password-submitting' ? 'Hidden' : passwordVisible ? 'Hide' : 'Show'}</button
              >
            </div>
            <input
              id="auth-password"
              autocomplete={discoveryMode === 'live' ? 'current-password' : 'off'}
              data-1p-ignore={discoveryMode === 'live' ? undefined : ''}
              data-lpignore={discoveryMode === 'live' ? undefined : 'true'}
              data-fixture-field={discoveryMode === 'live' ? undefined : 'password'}
              disabled={effectiveState === 'password-submitting'}
              name={discoveryMode === 'live' ? 'password' : undefined}
              placeholder={effectiveState === 'password-submitting' ? 'Cleared' : 'Enter password'}
              readonly={!fieldOwnershipReady}
              required
              onkeydown={handlePasswordKeydown}
              bind:this={passwordInput}
              type={passwordVisible ? 'text' : 'password'}
              value=""
            />

            <div class="auth-action">
              <Pill
                ariaLabel={effectiveState === 'password-submitting' ? 'Signing in' : 'Sign in'}
                buttonType="reset"
                disabled={effectiveState === 'password-submitting'}
                label={effectiveState === 'password-submitting' ? 'Signing in…' : 'Sign in'}
                variant="action"
                onActivate={activatePasswordFixture}
              />
            </div>
            <Pill
              label={effectiveState === 'password-submitting' ? 'Cancel sign-in' : 'Back to providers'}
              variant="ghost"
              onActivate={() => handleAction({ type: 'back-to-providers' })}
            />
          </form>
        {/key}

        {#if effectiveState === 'password-submitting'}
          <p class="interaction-note">Static mocked state · 44px targets · focus order is fields → sign in → cancel.</p>
        {/if}
      {:else if effectiveState === 'callback'}
        <div class="callback-progress" aria-hidden="true"><span></span></div>
        <div class="callback-message">
          <h1 bind:this={stateHeading} tabindex="-1">Completing sign-in</h1>
          <p>Static callback state only. No provider response is read and no browser session is created.</p>
        </div>
        <div class="privacy-note">
          <span aria-hidden="true" class="info-icon"><Icon name="info" size={16} /></span>
          <p>Prototype-only callback presentation. No callback parameters or transcript data are read.</p>
        </div>
        <Pill
          label="Cancel and return to providers"
          variant="ghost"
          onActivate={() => handleAction({ type: 'cancel-callback' })}
        />
      {:else if effectiveState === 'session-expired'}
        <div class="session-icon" aria-hidden="true"><Icon name="refresh" size={20} /></div>
        <div class="session-copy">
          <h1 bind:this={stateHeading} tabindex="-1">Session expired</h1>
          <p>
            Static expiry state only. This preview does not persist a draft; choose how to represent the next local
            state.
          </p>
        </div>
        <div class="session-actions">
          <Pill label="Sign in again" variant="action" onActivate={() => handleAction({ type: 'sign-in-again' })} />
          <Pill label="Discard draft" variant="ghost" onActivate={() => handleAction({ type: 'discard-draft' })} />
        </div>
        <p class="provider-note">
          <span aria-hidden="true" class="note-dot"></span>Prototype-only state · no draft or prompt was persisted after
          expiry.
        </p>
      {:else if effectiveState === 'logout-pending'}
        <div class="callback-progress" aria-hidden="true"><span></span></div>
        <div class="callback-message">
          <h1 bind:this={stateHeading} tabindex="-1">Signing out</h1>
          <p>Logout is being verified with the same-origin Hermes session boundary.</p>
        </div>
        <div class="privacy-note">
          <span aria-hidden="true" class="info-icon"><Icon name="info" size={16} /></span>
          <p>Retry and provider discovery stay unavailable until the server identity probe confirms logout.</p>
        </div>
      {:else if effectiveState === 'logout-failed'}
        <div class="failure-icon" aria-hidden="true"><Icon name="warning" size={20} /></div>
        <div class="failure-heading">
          <h1 bind:this={stateHeading} tabindex="-1">Sign-out could not be verified</h1>
          <p>{failureMessage ?? 'The server session could not be confirmed as signed out.'}</p>
        </div>
        <div class="failure-detail">
          <strong>{failureCode ?? 'logout-unverified'}</strong>
          <p>Retry sign out rechecks the same-origin session boundary. Provider discovery remains unavailable.</p>
        </div>
        <div class="failure-actions">
          <Pill
            label="Retry sign out"
            icon="refresh"
            variant="action"
            onActivate={() => handleAction({ type: 'retry-logout' })}
          />
        </div>
        <p class="metadata">Live boundary · logout recovery · no provider discovery</p>
      {:else if isDiscoveryFailureState(effectiveState)}
        <div class="failure-icon" aria-hidden="true">
          <Icon name={effectiveState === 'discovery-retry' ? 'refresh' : 'warning'} size={20} />
        </div>
        <div class="failure-heading">
          <h1 bind:this={stateHeading} tabindex="-1">{discoveryFailureHeading(effectiveState)}</h1>
          <p>
            {effectiveState === 'failure' && discoveryMode === 'live' && failureMessage
              ? failureMessage
              : discoveryFailureCopy(effectiveState)}
          </p>
        </div>
        <div class="failure-detail">
          <strong
            >{effectiveState === 'failure' && discoveryMode === 'live' && failureCode
              ? failureCode
              : discoveryFailureDetail(effectiveState)}</strong
          >
          <p>
            {effectiveState === 'failure' && discoveryMode === 'live'
              ? 'The fixed diagnostic contains no credential or provider response detail.'
              : discoveryFailureDetailCopy(effectiveState)}
          </p>
        </div>
        <div class="failure-actions">
          <Pill
            label={effectiveState === 'failure' ? 'Try again' : 'Retry discovery'}
            icon="refresh"
            variant="action"
            onActivate={() => handleAction({ type: effectiveState === 'failure' ? 'retry-authentication' : 'retry-discovery' })}
          />
          <Pill
            label={effectiveState === 'failure' ? 'Choose provider' : 'Back to sign-in'}
            variant="ghost"
            onActivate={() => handleAction({ type: effectiveState === 'failure' ? 'choose-provider-again' : 'back-to-sign-in' })}
          />
        </div>
        <p class="metadata">{discoveryFailureMetadata(effectiveState)}</p>
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
    --signal: var(--color-auth-signal);
    --success: #2da568;
    --danger: var(--color-auth-danger);
    --danger-surface: #fff1f2;
    --focus: #2348c7;
    --action-ink: #ffffff;
    --radius-pill: 999px;
    --radius-input: 12px;
    --radius-glass: 22px;
    position: relative;
    box-sizing: border-box;
    width: 100%;
    min-width: 0;
    min-height: 900px;
    overflow: hidden;
    background: var(--canvas);
    color: var(--ink);
    font-family: 'Instrument Sans', system-ui, sans-serif;
    font-synthesis: none;
    text-rendering: optimizeLegibility;
  }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
    white-space: nowrap;
  }

  h1[tabindex='-1']:focus {
    outline: none;
  }

  .auth-preview[data-appearance='dark'] {
    --canvas: #0d1117;
    --surface: #171c24;
    --ink: #f4f6fa;
    --muted: #a7b0bf;
    --line: #343c49;
    --signal: var(--color-auth-signal);
    --success: #4cc989;
    --danger: #f06a6a;
    --danger-surface: #351f26;
    --focus: #c2ccff;
    --action-ink: var(--color-dark-ink);
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
    to {
      transform: rotate(360deg);
    }
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
