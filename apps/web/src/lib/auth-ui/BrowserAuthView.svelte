<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import type { AuthIdentity } from '$lib/transport/live-rest-types';
  import type { Appearance } from '$lib/workspace/types';
  import AuthPreview from './AuthPreview.svelte';
  import { browserAuthErrorMessage } from './browser-auth';
  import { BrowserAuthSession, type BrowserAuthSnapshot } from './browser-auth-session';
  import {
    authStateForProviderKind,
    type AuthAction,
    type AuthViewState,
    type PasswordSubmission
  } from './types';

  export let session: BrowserAuthSession;
  export let appearance: Appearance = 'light';
  export let onAuthenticated: (identity: AuthIdentity) => void = () => {};

  let snapshot: Readonly<BrowserAuthSnapshot> = session.current;
  let unsubscribe: (() => void) | undefined;
  let lastPublishedIdentity: AuthIdentity | undefined;

  $: authState = toViewState(snapshot);
  $: keepAuthenticatedProjection = snapshot.status === 'authenticated' || snapshot.status === 'logging_out';
  $: if (snapshot.status === 'authenticated' && snapshot.identity !== lastPublishedIdentity) {
    lastPublishedIdentity = snapshot.identity;
    if (snapshot.identity) onAuthenticated(snapshot.identity);
  }

  function handleAction(action: AuthAction): void {
    // The approved failure family supplies the visible retry. Keep its action
    // internal so recovery reuses the retained identity and session lifecycle.
    if (action.type === 'retry-authentication' && snapshot.status === 'logout_failed') {
      void session.logout();
      return;
    }
    // A pending logout remains an authenticated projection and cannot be
    // interrupted by generic auth controls.
    if (snapshot.status === 'logging_out') return;
    if (action.type === 'choose-provider') {
      session.chooseProvider(action.providerId);
      return;
    }
    if (
      action.type === 'back-to-providers' ||
      action.type === 'cancel-callback' ||
      action.type === 'choose-provider-again' ||
      action.type === 'back-to-sign-in' ||
      action.type === 'discard-draft'
    ) {
      session.clearSelection();
      return;
    }
    if (action.type === 'retry-discovery' || action.type === 'sign-in-again') {
      void session.retryDiscovery();
      return;
    }
    if (action.type === 'cancel-discovery') {
      session.cancel();
      return;
    }
    if (action.type === 'retry-authentication') {
      // A failure without a selected provider came from the identity barrier.
      // Retry that barrier; provider discovery is eligible only after a genuine
      // 401 has classified the browser as signed out.
      const selected = snapshot.selectedProviderId;
      if (!selected || snapshot.errorCode === 'identity-failed') {
        void session.initialize();
        return;
      }
      session.chooseProvider(selected);
    }
  }

  function handlePasswordSubmit(submission: PasswordSubmission): void {
    void session.loginWithPassword(submission);
  }

  onMount(() => {
    unsubscribe = session.subscribe((next) => {
      snapshot = next;
    });
    void session.initialize();
  });

  onDestroy(() => {
    unsubscribe?.();
    session.dispose();
  });

  function toViewState(value: Readonly<BrowserAuthSnapshot>): AuthViewState {
    if (value.status === 'refreshing' || value.status === 'redirecting' || value.status === 'native_exchanging') {
      return 'callback';
    }
    if (value.status === 'discovering') return 'discovery-pending';
    if (value.status === 'provider_unavailable') return 'provider-unavailable';
    if (value.status === 'password_submitting') return 'password-submitting';
    if (value.status === 'expired') return 'session-expired';
    if (value.status === 'logout_failed') return 'failure';
    if (value.status === 'failed') return 'failure';
    if (!value.selectedProviderId) return 'provider-selection';

    const selectedProvider = value.providers.find((provider) => provider.id === value.selectedProviderId);
    if (!selectedProvider) return 'provider-unavailable';
    // This view is the live browser boundary. OAuth has a fixture callback
    // family, but no reviewed live callback transport, so it must fail closed
    // instead of entering the password form or implying a provider window.
    if (selectedProvider.kind === 'oauth') return 'provider-unavailable';
    return authStateForProviderKind(selectedProvider.kind);
  }
</script>

{#if keepAuthenticatedProjection}
  <!-- Logout pending/recovery is deliberately not a new Authentication
       presentation state. The authenticated projection remains mounted until
       the internal lifecycle proves signed-out or a reviewed Paper state exists. -->
  <slot />
{:else}
  <AuthPreview
    {appearance}
    discoveryMode="live"
    failureCode={snapshot.errorCode}
    failureMessage={snapshot.errorCode ? browserAuthErrorMessage(snapshot.errorCode) : undefined}
    providers={snapshot.providers}
    state={authState}
    onAction={handleAction}
    onPasswordSubmit={handlePasswordSubmit}
  />
{/if}
