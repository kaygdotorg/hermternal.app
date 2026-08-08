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
    // The rendered workspace only reports the semantic authentication-required
    // boundary. It has no truthful PTY lifecycle lease, so ordinary expiry stays
    // with BrowserAuthSession until #368 supplies that Terminal bridge contract.
    liveContext?.auth.expire();
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
    <LiveWorkspaceView session={liveContext.workspace} onReturnToSignIn={returnLiveWorkspaceToSignIn} />
  </BrowserAuthView>
{:else}
  <main aria-busy="true" aria-label="Starting Hermternal"></main>
{/if}

<style>
  main {
    min-height: 100dvh;
  }
</style>
