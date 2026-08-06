<script lang="ts">
  import { onMount } from 'svelte';
  import { MockTransportError } from '$lib/transport';
  import type { MockTransport, MockWorkspaceState } from '$lib/transport';

  export let transport: MockTransport;

  type ShellState = MockWorkspaceState | { status: 'pending' } | { status: 'failure'; message: string };

  let state: ShellState = { status: 'pending' };
  let requestNumber = 0;

  async function loadMockState(): Promise<void> {
    const currentRequest = ++requestNumber;
    state = { status: 'pending' };

    try {
      const nextState = await transport.getWorkspace();
      if (currentRequest === requestNumber) {
        state = nextState;
      }
    } catch (error) {
      if (currentRequest !== requestNumber) {
        return;
      }

      state = {
        status: 'failure',
        message:
          error instanceof MockTransportError
            ? error.message
            : 'The mock boundary returned an unknown failure.'
      };
    }
  }

  onMount(() => {
    void loadMockState();
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
      authentication screens are intentionally withheld while the Paper and proof gates remain
      open.
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
      {:else if state.status === 'success'}
        <p class="status-message" data-testid="status-success">Mock transport ready.</p>
        <p class="status-detail">{state.workspaceLabel} · {state.detail}</p>
        <code data-testid="fixture-id">{state.fixtureId}</code>
      {:else if state.status === 'empty'}
        <p class="status-message" data-testid="status-empty">The fixture is empty.</p>
        <p class="status-detail">No synthetic workspace result is available.</p>
        <code data-testid="fixture-id">{state.fixtureId}</code>
      {:else}
        <p class="status-message" data-testid="status-failure">Mock evidence unavailable.</p>
        <p class="status-detail">{state.message}</p>
      {/if}
    </div>

    <button class="action" type="button" onclick={loadMockState}>
      Re-run mock check
    </button>
  </section>

  <aside class="notice" aria-label="Scope limitation">
    <strong>No live integrations.</strong>
    Hermes calls, provider credentials, browser authentication, live data, and transcript mirrors
    are not part of this scaffold.
  </aside>
</main>
