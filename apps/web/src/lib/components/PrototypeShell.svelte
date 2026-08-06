<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { MOCK_FIXTURE_IDS } from '$lib/transport/fixtures';
  import { isMockAbortError, MockTransportError } from '$lib/transport/mock-transport';
  import type { MockCancellationReason, MockShellState, MockTransport } from '$lib/transport/types';

  export let transport: MockTransport;

  let state: MockShellState = {
    status: 'pending',
    fixtureId: MOCK_FIXTURE_IDS.pending
  };
  let requestNumber = 0;
  let activeController: AbortController | undefined;
  let mounted = false;
  let abortReason: MockCancellationReason = 'retry';

  function cancelledState(reason: MockCancellationReason): MockShellState {
    return {
      status: 'cancelled',
      fixtureId: MOCK_FIXTURE_IDS.cancelled,
      reason
    };
  }

  async function loadMockState(): Promise<void> {
    // Increment before aborting so an old transport completion cannot publish
    // after a retry has established the next request's pending state.
    const currentRequest = ++requestNumber;
    abortReason = 'retry';
    activeController?.abort();
    activeController = new AbortController();
    const controller = activeController;
    state = {
      status: 'pending',
      fixtureId: MOCK_FIXTURE_IDS.pending
    };

    try {
      const nextState = await transport.getWorkspace(controller.signal);
      if (currentRequest !== requestNumber || !mounted) {
        return;
      }
      state = nextState;
    } catch (error) {
      if (currentRequest !== requestNumber || !mounted) {
        return;
      }

      if (isMockAbortError(error)) {
        state = cancelledState(abortReason);
      } else {
        state = {
          status: 'failure',
          fixtureId: MOCK_FIXTURE_IDS.failure,
          message:
            error instanceof MockTransportError
              ? error.message
              : 'The mock boundary returned an unknown failure.'
        };
      }
    } finally {
      if (currentRequest === requestNumber) {
        activeController = undefined;
      }
    }
  }

  function cancelMockState(): void {
    if (!activeController || state.status !== 'pending') {
      return;
    }

    abortReason = 'user';
    requestNumber += 1;
    activeController.abort();
    activeController = undefined;
    state = cancelledState('user');
  }

  onMount(() => {
    mounted = true;
    void loadMockState();
  });

  onDestroy(() => {
    mounted = false;
    abortReason = 'unmount';
    requestNumber += 1;
    activeController?.abort();
    activeController = undefined;
  });
</script>

<svelte:head>
  <title>Hermternal web prototype</title>
</svelte:head>

<main class="shell" data-testid="prototype-shell">
  <header class="shell-header">
    <div>
      <p class="eyebrow">Hermternal web</p>
      <h1>Prototype shell</h1>
    </div>
    <span class="status-pill" data-testid="prototype-label">Prototype only</span>
  </header>

  <section class="card" aria-labelledby="scope-heading">
    <div class="card-heading">
      <p class="eyebrow">W-01 scaffold</p>
      <h2 id="scope-heading">A safe place for future web surfaces</h2>
    </div>
    <p>
      This client is a static SvelteKit SPA with deterministic mock transport. Runtime and
      authentication screens are intentionally withheld while their separate implementation and
      proof gates remain open.
    </p>

    <dl class="boundary-list">
      <div>
        <dt>Transport</dt>
        <dd>In-memory fixture</dd>
      </div>
      <div>
        <dt>Rendering</dt>
        <dd>Static build, client-only</dd>
      </div>
      <div>
        <dt>Data</dt>
        <dd>Synthetic, redacted values</dd>
      </div>
    </dl>
  </section>

  <section class="card" aria-labelledby="evidence-heading">
    <div class="card-heading">
      <p class="eyebrow">Evidence collection</p>
      <h2 id="evidence-heading">Mock boundary status</h2>
    </div>

    <div class="status-region" aria-live="polite" data-testid="mock-status">
      {#if state.status === 'pending'}
        <p class="status-message" data-testid="status-pending">Collecting deterministic mock evidence…</p>
        <p class="status-detail">Pending fixture: {state.fixtureId}</p>
      {:else if state.status === 'success'}
        <p class="status-message" data-testid="status-success">Mock transport ready.</p>
        <p class="status-detail">{state.workspaceLabel} · {state.detail}</p>
        <code data-testid="fixture-id">{state.fixtureId}</code>
      {:else if state.status === 'empty'}
        <p class="status-message" data-testid="status-empty">The fixture is empty.</p>
        <p class="status-detail">No synthetic workspace result is available.</p>
        <code data-testid="fixture-id">{state.fixtureId}</code>
      {:else if state.status === 'cancelled'}
        <p class="status-message" data-testid="status-cancelled">Mock request cancelled safely.</p>
        <p class="status-detail">Cancellation reason: {state.reason}.</p>
        <code data-testid="fixture-id">{state.fixtureId}</code>
      {:else}
        <p class="status-message" data-testid="status-failure">Mock evidence unavailable.</p>
        <p class="status-detail">{state.message}</p>
        <code data-testid="fixture-id">{state.fixtureId}</code>
      {/if}
    </div>

    {#if state.status === 'pending' && activeController}
      <button class="action secondary-action" type="button" onclick={cancelMockState}>
        Cancel mock check
      </button>
    {/if}
    <button class="action" type="button" onclick={loadMockState}>
      {state.status === 'cancelled' ? 'Retry mock check' : 'Re-run mock check'}
    </button>
  </section>

  <aside class="notice" aria-label="Scope limitation">
    <strong>No live integrations.</strong>
    Hermes calls, provider credentials, browser authentication, live data, and transcript mirrors
    are not part of this scaffold.
  </aside>
</main>
