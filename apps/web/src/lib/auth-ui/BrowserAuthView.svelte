<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import type { AuthIdentity } from '$lib/transport/live-rest-types';
  import type { Appearance } from '$lib/workspace/types';
  import AuthPreview from './AuthPreview.svelte';
  import { browserAuthErrorMessage } from './browser-auth';
  import { BrowserAuthSession, type BrowserAuthSnapshot } from './browser-auth-session';
  import type { AuthAction, AuthViewState, PasswordSubmission } from './types';

  export let session: BrowserAuthSession;
  export let appearance: Appearance = 'light';
  export let onAuthenticated: (identity: AuthIdentity) => void = () => {};

  let snapshot: Readonly<BrowserAuthSnapshot> = session.current;
  let unsubscribe: (() => void) | undefined;
  let lastPublishedIdentity: AuthIdentity | undefined;

  $: authState = toViewState(snapshot);
  $: if (snapshot.status === 'authenticated' && snapshot.identity !== lastPublishedIdentity) {
    lastPublishedIdentity = snapshot.identity;
    if (snapshot.identity) onAuthenticated(snapshot.identity);
  }

  function handleAction(action: AuthAction): void {
    if (action.type === 'retry-logout') {
      if (snapshot.status === 'logout_failed') void session.logout();
      return;
    }
    if (snapshot.status === 'logging_out' || snapshot.status === 'logout_failed') return;
    if (action.type === 'cancel-sign-in') {
      // Cancellation owns a different boundary from returning to provider
      // selection: only the active password operation may abort the session.
      // A duplicate compatibility event after the synchronous return must not
      // clear the retained provider selection.
      if (snapshot.status === 'password_submitting') session.cancel();
      return;
    }
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
    if (value.status === 'logging_out') return 'logout-pending';
    if (value.status === 'logout_failed') return 'logout-failed';
    if (value.status === 'failed') return 'failure';
    if (value.selectedProviderId) return 'password';
    return 'provider-selection';
  }
</script>

{#if snapshot.status === 'authenticated'}
  <slot />
{:else}
  <AuthPreview
    {appearance}
    discoveryMode="live"
    failureCode={snapshot.errorCode}
    failureMessage={snapshot.errorCode ? browserAuthErrorMessage(snapshot.errorCode) : undefined}
    providers={snapshot.providers.filter((provider) => provider.kind === 'password')}
    state={authState}
    onAction={handleAction}
    onPasswordSubmit={handlePasswordSubmit}
  />
{/if}
