<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import BrowserAuthView from '$lib/auth-ui/BrowserAuthView.svelte';
  import PrototypeShell from '$lib/components/PrototypeShell.svelte';
  import { createLiveRootContext, resolveRootRoute, type LiveRootContext } from '$lib/root-route';
  import { createMockTransport, type MockTransport } from '$lib/transport';
  import LiveWorkspaceView from '$lib/workspace/LiveWorkspaceView.svelte';

  let routeMode: 'pending' | 'fixture' | 'live' = 'pending';
  let fixtureTransport: MockTransport | undefined;
  let liveContext: LiveRootContext | undefined;

  function returnLiveWorkspaceToSignIn(): void {
    // Chat has no PTY lease and retains the established auth path.
    liveContext?.auth.expire();
  }

  function returnTerminalToSignIn(lease: import('$lib/root-route').RootTerminalLifecycleLease | undefined): void {
    // A terminal 4401 without the active opaque lease is stale and must not
    // become a generic auth expiry after a later reauthentication.
    liveContext?.expireTerminalAuthentication(lease);
  }

  // Route selection waits for browser mount. The server and first client render
  // stay identical, while valid scenario queries retain the no-network lane.
  onMount(() => {
    const selection = resolveRootRoute(window.location.search);
    if (selection.mode === 'fixture') {
      fixtureTransport = createMockTransport({ scenario: selection.scenario, delayMs: selection.delayMs });
      routeMode = 'fixture';
      return;
    }

    liveContext = createLiveRootContext();
    routeMode = 'live';
  });

  onDestroy(() => {
    // The page is the final owner. Auth expiry only removes the authenticated
    // projection; route teardown permanently closes Chat, PTY, coordinator
    // subscriptions, and their sockets through the root context exactly once.
    liveContext?.dispose();
  });
</script>

{#if routeMode === 'fixture' && fixtureTransport}
  <PrototypeShell transport={fixtureTransport} />
{:else if routeMode === 'live' && liveContext}
  <BrowserAuthView session={liveContext.auth}>
    <main class="live-route-main">
      <LiveWorkspaceView
        session={liveContext.workspace}
        registerTerminalLifecycle={liveContext.registerTerminalLifecycle}
        onReturnToSignIn={returnLiveWorkspaceToSignIn}
        onTerminalAuthenticationFailure={returnTerminalToSignIn}
      />
    </main>
  </BrowserAuthView>
{:else}
  <main aria-busy="true" aria-label="Starting Hermternal"></main>
{/if}

<style>
  main {
    min-height: 100dvh;
  }

  .live-route-main {
    width: 100%;
    min-width: 0;
  }
</style>
