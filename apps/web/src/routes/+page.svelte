<script lang="ts">
  import PrototypeShell from '$lib/components/PrototypeShell.svelte';
  import { createMockTransport } from '$lib/transport';
  import type { MockScenario } from '$lib/transport';

  function createRouteTransport() {
    if (typeof window === 'undefined') {
      return createMockTransport({ scenario: 'success' });
    }

    // Query-selected fixtures keep browser regression states deterministic
    // without adding a product route or a live transport boundary.
    const params = new URLSearchParams(window.location.search);
    const candidate = params.get('scenario');
    const scenario: MockScenario =
      candidate === 'empty' || candidate === 'failure' || candidate === 'success'
        ? candidate
        : 'success';
    const delayMs = params.get('delayMs') === 'short' ? 250 : 0;

    return createMockTransport({ scenario, delayMs });
  }

  const transport = createRouteTransport();
</script>

<PrototypeShell {transport} />
