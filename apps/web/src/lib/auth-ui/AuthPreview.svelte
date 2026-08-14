<script lang="ts">
  import { onMount, tick } from 'svelte';
  import Icon from '$lib/workspace/Icon.svelte';
  import Pill from '$lib/workspace/Pill.svelte';
  import ProviderCard from './ProviderCard.svelte';
  import { DEFAULT_PROVIDERS, validateAuthProviders } from './fixtures';
  import type {
    AuthAction,
    AuthActionHandler,
    AuthDiscoveryFailureVariant,
    AuthDiscoveryMode,
    AuthProvider,
    AuthViewState,
    PasswordSubmissionHandler
  } from './types';
  import type { Appearance } from '$lib/workspace/types';

  /**
   * Live discovery must not borrow fixture identities while the registry is
   * pending. These neutral rows keep the approved Paper rhythm without
   * presenting a provider name or capability as a live fact.
   */
  const PENDING_PROVIDERS: AuthProvider[] = [
    {
      id: 'pending-provider-manifest',
      name: 'Provider manifest',
      monogram: 'P',
      kind: 'oauth',
      description: 'Loading · no sign-in action yet',
      mobileDescription: 'Provider manifest'
    },
    {
      id: 'pending-provider-entries',
      name: 'Provider entries',
      monogram: 'P',
      kind: 'password',
      description: 'Waiting for a complete response',
      mobileDescription: 'Provider entries'
    }
  ];

  export let appearance: Appearance = 'light';
  export let state: AuthViewState = 'provider-selection';
  export let providers: AuthProvider[] = DEFAULT_PROVIDERS;
  export let discoveryMode: AuthDiscoveryMode = 'fixture';
  export let passwordSubmitting = false;
  export let onAction: AuthActionHandler = () => {};
  export let onPasswordSubmit: PasswordSubmissionHandler | undefined = undefined;
  export let failureMessage: string | undefined = undefined;
  export let failureCode: string | undefined = undefined;

  let passwordVisible = false;
  let previousState: AuthViewState = state;
  let previousPasswordSubmitting = passwordSubmitting;
  $: validatedProviders = validateAuthProviders(providers);
  // A selectable registry must validate before actions are exposed. Discovery
  // status screens may intentionally carry no providers while pending or failed.
  $: effectiveState = state === 'provider-selection' && !validatedProviders ? 'provider-unavailable' : state;
  $: safeProviders = validatedProviders ?? [];
  // A live pending state has no trusted registry yet. Never render the local
  // fixture identities there, even if a caller supplies stale provider data.
  $: pendingProviders =
    discoveryMode === 'live'
      ? PENDING_PROVIDERS
      : safeProviders.length > 0
        ? safeProviders
        : DEFAULT_PROVIDERS;
  $: isPasswordState = effectiveState === 'password' || effectiveState === 'password-submitting';
  $: isPasswordSubmitting = effectiveState === 'password-submitting' || (effectiveState === 'password' && passwordSubmitting);
  $: activeDiscoveryFailure = discoveryFailureVariantForState(effectiveState);

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

  $: if (effectiveState !== previousState || isPasswordSubmitting !== previousPasswordSubmitting) {
    const enteredState = effectiveState;
    const exitedState = previousState;
    const enteredSubmitting = isPasswordSubmitting;
    // Password submission starts on pointer down. Keep the owned form mounted
    // through the matching pointer up/click so replacing its reset button cannot
    // cancel the gesture before the credential-free action settles.
    if (exitedState === 'password' && enteredSubmitting) {
      passwordVisible = false;
      fieldOwnershipReady = false;
      focusGeneration += 1;
    } else if (enteredState !== exitedState) {
      resetPasswordEntry();
    }
    previousState = enteredState;
    previousPasswordSubmitting = enteredSubmitting;
    void focusEnteredState();
  }

  $: isProviderState =
    effectiveState === 'provider-selection' ||
    effectiveState === 'discovery-pending' ||
    isDiscoveryFailureState(effectiveState);
  $: panelClass = isProviderState
    ? 'provider-panel'
    : effectiveState === 'session-expired'
      ? 'session-panel'
      : 'narrow-panel';
  $: politeAnnouncement =
    isPasswordSubmitting
      ? 'Signing in to Hermes. The form is disabled while this mocked state completes.'
      : effectiveState === 'callback'
        ? discoveryMode === 'live'
          ? 'Completing sign-in. Checking the provider response and creating a protected browser session.'
          : 'Completing sign-in. Static callback state only; no provider response is read.'
        : effectiveState === 'discovery-pending'
          ? 'Discovering sign-in methods. Provider actions are unavailable while the result is pending.'
          : isDiscoveryFailureState(effectiveState) && activeDiscoveryFailure === 'retry'
            ? 'Provider discovery can be retried. Choose Retry discovery or Back to sign-in.'
            : '';
  $: assertiveAnnouncement =
    effectiveState === 'failure'
      ? 'Sign-in did not complete. Try again or choose another provider.'
      : effectiveState === 'session-expired'
        ? 'Session expired. Sign in again or discard the retained local draft.'
        : isDiscoveryFailureState(effectiveState) && activeDiscoveryFailure !== 'retry'
          ? `${discoveryFailureHeading(activeDiscoveryFailure)}. ${discoveryFailureCopy(activeDiscoveryFailure)}`
          : '';

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

  function isDiscoveryFailureState(value: AuthViewState): boolean {
    return (
      value === 'discovery-retry' ||
      value === 'discovery-empty' ||
      value === 'discovery-malformed' ||
      value === 'discovery-aborted' ||
      value === 'provider-unavailable'
    );
  }

  function discoveryFailureVariantForState(value: AuthViewState): AuthDiscoveryFailureVariant {
    if (value === 'discovery-retry') return 'retry';
    if (value === 'discovery-empty') return 'empty';
    if (value === 'discovery-malformed') return 'malformed';
    if (value === 'discovery-aborted') return 'aborted';
    return 'unavailable';
  }

  function discoveryFailureHeading(value: AuthDiscoveryFailureVariant): string {
    if (value === 'retry') return 'Retry provider discovery';
    if (value === 'empty') return 'No sign-in methods available';
    if (value === 'malformed') return 'Provider discovery returned incompatible data';
    // Cancellation is still the approved generic discovery-stop family. Keep
    // the Paper heading stable while the detail copy records the abort reason.
    if (value === 'aborted') return 'Provider discovery stopped';
    return 'Provider discovery stopped';
  }

  function discoveryFailureCopy(value: AuthDiscoveryFailureVariant): string {
    if (value === 'retry') {
      return 'The previous result was unknown. A fresh user action is required before another lookup.';
    }
    if (value === 'empty') {
      return 'A successful empty provider registry is outside the pinned response contract. The preview fails closed and exposes no invented provider.';
    }
    if (value === 'malformed') {
      return 'The provider response did not match the reviewed schema. The preview fails closed and exposes no invented sign-in method.';
    }
    if (value === 'aborted') {
      return 'The provider discovery request was cancelled before a usable registry was received. No provider action is available.';
    }
    return 'No usable provider list was returned. The client fails closed and does not invent a fallback.';
  }

  function discoveryFailureDetail(value: AuthDiscoveryFailureVariant): string {
    if (value === 'retry') return 'Ready to retry provider discovery';
    if (value === 'empty') return 'invalid_empty_provider_registry';
    if (value === 'malformed') return 'invalid_response';
    if (value === 'aborted') return 'aborted';
    return 'provider_unavailable';
  }

  function discoveryFailureDetailCopy(value: AuthDiscoveryFailureVariant): string {
    if (value === 'retry') {
      return 'Retry is idempotent; duplicate submits stay blocked until the result returns.';
    }
    if (value === 'empty') {
      return 'Retry discovery after Hermes reports the reviewed provider registry or exact unavailable response.';
    }
    if (value === 'malformed') {
      return 'Unknown fields are ignored only after bounded strict parsing; malformed or unsafe data is rejected.';
    }
    if (value === 'aborted') return 'Cancellation leaves no provider list and does not expose response data.';
    return 'The endpoint did not provide a usable provider registry. No fallback provider is invented.';
  }

  function discoveryFailureMetadata(value: AuthDiscoveryFailureVariant, mode: AuthDiscoveryMode): string {
    const source = mode === 'live' ? 'Live boundary' : 'Mocked fixture';
    if (value === 'retry') return `${source} · user initiated · safe to retry`;
    if (value === 'empty') return `${source} · empty registry · no credentials`;
    if (value === 'malformed') return `${source} · malformed response · no credentials`;
    if (value === 'aborted') return `${source} · cancelled · no credentials`;
    return `${source} · provider unavailable · no credentials`;
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
    if (effectiveState === 'password' && !isPasswordSubmitting) {
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
      isPasswordSubmitting ||
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
    // Do not key-replace the form inside the pointer-down gesture: reset() clears
    // the controls without detaching the button that owns the compatibility click.
    passwordForm.reset();
    passwordVisible = false;

    if (discoveryMode === 'live') {
      if (onPasswordSubmit && typeof username === 'string' && typeof password === 'string') {
        // The live callback receives transient values once. Auth actions and observable
        // component state remain credential-free, and the form is cleared now.
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
  data-discovery-failure={isDiscoveryFailureState(effectiveState) ? activeDiscoveryFailure : undefined}
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
            <span class="desktop-copy">Choose one available sign-in method. Hermternal does not rank providers or retain reusable credentials.</span>
            <span class="mobile-copy">Choose a method reported by this Hermes deployment.</span>
          </p>
        </header>

        <div class="provider-list" aria-label="Available sign-in providers">
          {#each safeProviders as provider (provider.id)}
            <ProviderCard {provider} onAction={handleAction} />
          {/each}
        </div>

        <p class="provider-note">
          <span aria-hidden="true" class="note-dot"></span>{discoveryMode === 'live'
            ? 'Connected to the configured HTTPS origin. Only providers reported by Hermes are shown.'
            : 'Synthetic fixture only · provider choices are local presentation data; no discovery request is made.'}
        </p>
      {:else if effectiveState === 'discovery-pending'}
        <header class="panel-heading">
          <p class="eyebrow">PROVIDER DISCOVERY · PENDING</p>
          <h1 bind:this={stateHeading} tabindex="-1">Discovering sign-in methods</h1>
          <p>
            <span class="desktop-copy">Waiting for the configured Hermes deployment to report provider capabilities. No fallback is guessed.</span>
            <span class="mobile-copy">{discoveryMode === 'live'
              ? 'Live discovery · no provider action until the list is valid.'
              : 'Mocked only · no provider action until the list is valid.'}</span>
          </p>
        </header>

        <div class="provider-list" aria-label="Provider discovery in progress" aria-busy="true">
          {#each pendingProviders as provider (provider.id)}
            <ProviderCard disabled pending {provider} onAction={handleAction} />
          {/each}
        </div>

        {#if discoveryMode === 'live'}
          <div class="failure-actions">
            <Pill label="Cancel discovery" variant="ghost" onActivate={() => handleAction({ type: 'cancel-discovery' })} />
          </div>
        {/if}
        <p class="provider-note">
          <span aria-hidden="true" class="note-dot"></span>{discoveryMode === 'live'
            ? 'Live discovery · provider discovery is pending; controls stay unavailable until a valid list arrives.'
            : 'Mocked only · provider discovery is pending; controls stay unavailable until a valid list arrives.'}
        </p>
      {:else if isPasswordState}
        <header class="panel-heading">
          <p class="eyebrow">BASIC AUTH PROVIDER{isPasswordSubmitting ? ' · SUBMITTING' : ''}</p>
          <h1 bind:this={stateHeading} tabindex="-1">{isPasswordSubmitting ? 'Signing in to Hermes' : 'Sign in to Hermes'}</h1>
          <p>
            {isPasswordSubmitting
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
               omit those markers while the hydration fence is active. -->
          <form
            bind:this={passwordForm}
            aria-busy={isPasswordSubmitting}
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
              disabled={isPasswordSubmitting}
              placeholder={isPasswordSubmitting ? 'Cleared' : 'Enter username'}
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
                aria-label={isPasswordSubmitting ? 'Password hidden' : passwordVisible ? 'Hide password' : 'Show password'}
                class="show-password"
                disabled={isPasswordSubmitting}
                type="button"
                onclick={() => handleAction({ type: 'toggle-password-visibility' })}
                >{isPasswordSubmitting ? 'Hidden' : passwordVisible ? 'Hide' : 'Show'}</button
              >
            </div>
            <input
              id="auth-password"
              autocomplete={discoveryMode === 'live' ? 'current-password' : 'off'}
              data-1p-ignore={discoveryMode === 'live' ? undefined : ''}
              data-lpignore={discoveryMode === 'live' ? undefined : 'true'}
              data-fixture-field={discoveryMode === 'live' ? undefined : 'password'}
              disabled={isPasswordSubmitting}
              name={discoveryMode === 'live' ? 'password' : undefined}
              placeholder={isPasswordSubmitting ? 'Cleared' : 'Enter password'}
              readonly={!fieldOwnershipReady}
              required
              onkeydown={handlePasswordKeydown}
              bind:this={passwordInput}
              type={passwordVisible ? 'text' : 'password'}
              value=""
            />

            <div class="auth-action">
              <Pill
                ariaLabel={isPasswordSubmitting ? 'Signing in' : 'Sign in'}
                buttonType="reset"
                disabled={isPasswordSubmitting}
                label={isPasswordSubmitting ? 'Signing in…' : 'Sign in'}
                variant="action"
                onActivate={activatePasswordFixture}
              />
            </div>
            <Pill
              label={isPasswordSubmitting ? 'Cancel sign-in' : 'Back to providers'}
              variant="ghost"
              onActivate={() => handleAction({ type: 'back-to-providers' })}
            />
          </form>
        {/key}

        {#if isPasswordSubmitting}
          <p class="interaction-note">{discoveryMode === 'live'
            ? 'Live request state · 44px targets · focus order is fields → sign in → cancel.'
            : 'Static mocked state · 44px targets · focus order is fields → sign in → cancel.'}</p>
        {/if}
      {:else if effectiveState === 'callback'}
        <div class="callback-progress" aria-hidden="true"><span></span></div>
        <div class="callback-message">
          <h1 bind:this={stateHeading} tabindex="-1">Completing sign-in</h1>
          <p>{discoveryMode === 'live'
            ? 'Checking the provider response and creating a protected browser session.'
            : 'Static callback state only. No provider response is read and no browser session is created.'}</p>
        </div>
        <div class="privacy-note">
          <span aria-hidden="true" class="info-icon"><Icon name="info" size={16} /></span>
          <p>{discoveryMode === 'live'
            ? 'Do not close this tab. Callback parameters are checked once and are never shown in the interface.'
            : 'Prototype-only callback presentation. No callback parameters or transcript data are read.'}</p>
        </div>
        <Pill label="Cancel and return to providers" variant="ghost" onActivate={() => handleAction({ type: 'cancel-callback' })} />
      {:else if effectiveState === 'session-expired'}
        <div class="session-icon" aria-hidden="true"><Icon name="refresh" size={20} /></div>
        <div class="session-copy">
          <h1 bind:this={stateHeading} tabindex="-1">Session expired</h1>
          <p>{discoveryMode === 'live'
            ? 'Sign in again to continue. Your bounded local draft stays in memory until authentication completes.'
            : 'Sign in again to continue. This fixture keeps a bounded local draft in memory until authentication completes.'}</p>
        </div>
        <div class="session-actions">
          <Pill label="Sign in again" variant="action" onActivate={() => handleAction({ type: 'sign-in-again' })} />
          <Pill label="Discard draft" variant="ghost" onActivate={() => handleAction({ type: 'discard-draft' })} />
        </div>
        <p class="provider-note">
          <span aria-hidden="true" class="note-dot"></span>{discoveryMode === 'live'
            ? 'Live session gate · draft retained locally. No prompt was sent after the session expired.'
            : 'Mocked session gate · draft retained locally. No prompt was sent after the session expired.'}
        </p>
      {:else if effectiveState === 'failure'}
        <div class="failure-icon" aria-hidden="true"><Icon name="warning" size={20} /></div>
        <div class="failure-heading">
          <h1 bind:this={stateHeading} tabindex="-1">Sign-in did not complete</h1>
          <p>{discoveryMode === 'live' && failureMessage
            ? failureMessage
            : 'Static failure state only. No session was created and no provider was tried automatically.'}</p>
        </div>
        <div class="failure-detail">
          <strong>{discoveryMode === 'live' && failureCode ? failureCode : 'static_fixture_failure'}</strong>
          <p>{discoveryMode === 'live' && failureCode
            ? 'The fixed diagnostic contains no credential or callback parameter detail.'
            : 'Try again, or choose another provider. This fixture reads no provider response and retains no credentials.'}</p>
        </div>
        <div class="failure-actions">
          <Pill label="Try again" icon="refresh" variant="action" onActivate={() => handleAction({ type: 'retry-authentication' })} />
          <Pill label="Choose provider" variant="ghost" onActivate={() => handleAction({ type: 'choose-provider-again' })} />
        </div>
        <p class="metadata">Reference: AUTH-REJECTED · Safe to retry</p>
      {:else if isDiscoveryFailureState(effectiveState)}
        <div class="failure-icon" aria-hidden="true">
          <Icon name={activeDiscoveryFailure === 'retry' ? 'refresh' : 'warning'} size={20} />
        </div>
        <div class="failure-heading">
          <h1 bind:this={stateHeading} tabindex="-1">{discoveryFailureHeading(activeDiscoveryFailure)}</h1>
          <p>{discoveryFailureCopy(activeDiscoveryFailure)}</p>
        </div>
        <div class="failure-detail">
          <strong>{discoveryFailureDetail(activeDiscoveryFailure)}</strong>
          <p>{discoveryFailureDetailCopy(activeDiscoveryFailure)}</p>
        </div>
        <div class="failure-actions">
          <Pill label="Retry discovery" icon="refresh" variant="action" onActivate={() => handleAction({ type: 'retry-discovery' })} />
          <Pill label="Back to sign-in" variant="ghost" onActivate={() => handleAction({ type: 'back-to-sign-in' })} />
        </div>
        <p class="metadata">{discoveryFailureMetadata(activeDiscoveryFailure, discoveryMode)}</p>
      {/if}
    </div>
  </div>
</section>

<style>
  .auth-preview {
    --canvas: var(--color-canvas);
    --surface: var(--color-paper);
    --ink: var(--color-ink);
    --muted: var(--color-muted);
    --line: var(--color-line);
    --signal: var(--color-auth-signal);
    --success: var(--color-success);
    --danger: var(--color-auth-danger);
    --danger-surface: var(--color-gate-light-error-surface);
    --focus: var(--color-gate-light-focus);
    --action-ink: var(--color-gate-light-action-ink);
    position: relative;
    box-sizing: border-box;
    width: 100%;
    min-width: 0;
    min-height: 900px;
    overflow: hidden;
    background: var(--canvas);
    color: var(--ink);
    font-family: var(--font-ui), ui-sans-serif, system-ui, sans-serif;
    font-synthesis: none;
    text-rendering: optimizeLegibility;
  }

  .auth-preview[data-appearance='dark'] {
    --canvas: var(--color-dark-canvas);
    --surface: var(--color-dark-paper);
    --ink: var(--color-dark-ink);
    --muted: var(--color-dark-muted);
    --line: var(--color-dark-line);
    --signal: var(--color-dark-signal);
    --success: var(--color-dark-success);
    --danger: var(--color-dark-danger);
    --danger-surface: var(--color-gate-dark-error-surface);
    --focus: var(--color-gate-dark-focus);
    /* Dark action surfaces use canvas ink so the Paper signal remains readable. */
    --action-ink: var(--color-dark-canvas);
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

  .auth-frame {
    box-sizing: border-box;
    display: flex;
    min-height: 900px;
    align-items: center;
    justify-content: center;
    padding: var(--space-6);
  }

  .auth-panel {
    box-sizing: border-box;
    display: flex;
    width: 440px;
    flex-direction: column;
    gap: var(--space-6);
    padding: var(--space-8);
    border: 1px solid var(--line);
    border-radius: var(--radius-structural);
    background: var(--surface);
    box-shadow: 0 18px 50px color-mix(in srgb, var(--ink) 10%, transparent);
  }

  .auth-panel.provider-panel {
    width: 480px;
  }

  .panel-heading {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
  }

  .eyebrow {
    margin: 0;
    color: var(--signal);
    font-size: var(--text-meta);
    font-weight: var(--weight-semibold);
    letter-spacing: 0.08em;
    line-height: var(--leading-meta);
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
    font-weight: var(--weight-semibold);
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
    font-size: var(--text-body);
    line-height: var(--leading-body);
  }

  .mobile-copy {
    display: none;
  }

  .provider-list {
    display: flex;
    flex-direction: column;
    gap: var(--space-3);
  }

  .provider-note {
    display: flex;
    align-items: flex-start;
    gap: var(--space-2);
    padding-top: 2px;
    color: var(--muted);
    font-size: var(--text-meta);
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
    font-size: var(--text-control);
    font-weight: var(--weight-medium);
    line-height: var(--leading-control);
  }

  .password-form input {
    box-sizing: border-box;
    width: 100%;
    min-height: 48px;
    margin: 0 0 7px;
    padding: var(--space-3) 14px;
    border: 1px solid var(--line);
    border-radius: var(--radius-input);
    outline: 0;
    background: var(--surface);
    color: var(--ink);
    font: inherit;
    font-size: var(--text-body);
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
    padding: var(--space-2) 10px;
    border: 0;
    border-radius: var(--radius-pill);
    background: transparent;
    color: var(--signal);
    font: inherit;
    font-size: var(--text-meta);
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
    font-size: var(--text-meta);
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
    gap: var(--space-2);
  }

  .privacy-note {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: var(--space-3);
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
    gap: var(--space-2);
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
    padding: var(--space-3) 14px;
    border: 1px solid color-mix(in srgb, var(--danger) 30%, var(--line));
    border-radius: var(--radius-input);
    background: var(--danger-surface);
  }

  .failure-detail strong {
    color: var(--danger);
    font-size: var(--text-control);
    line-height: var(--leading-control);
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
      font-weight: var(--weight-semibold);
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

    .desktop-copy {
      display: none;
    }

    .mobile-copy {
      display: inline;
    }

    .panel-heading h1,
    .callback-message h1,
    .session-copy h1,
    .failure-heading h1 {
      font-size: 28px;
      line-height: 36px;
    }

    .provider-list {
      gap: var(--space-3);
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

  @media (forced-colors: active) {
    .auth-panel,
    .provider-card :global(.pill),
    .password-form input,
    .privacy-note,
    .failure-detail {
      forced-color-adjust: none;
      border-color: CanvasText;
      background: Canvas;
      color: CanvasText;
      box-shadow: none;
    }

    .provider-card :global(.pill:disabled) {
      border-color: GrayText;
      color: GrayText;
    }

    .show-password,
    .provider-note,
    .metadata,
    .panel-heading > p:last-child,
    .callback-message p,
    .session-copy p,
    .failure-heading p,
    .failure-detail p,
    .privacy-note p,
    .interaction-note {
      color: CanvasText;
    }

    .password-form input:focus-visible,
    .show-password:focus-visible {
      outline: 3px solid Highlight;
    }

    .callback-progress span {
      border-color: CanvasText;
      border-top-color: Highlight;
    }
  }
</style>
