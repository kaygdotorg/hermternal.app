<script lang="ts">
  import PrototypeShell from '$lib/components/PrototypeShell.svelte';
  import { createMockTransport } from '$lib/transport';

  // Keep the route deterministic until the approved transport and visual gates exist.
  const transport = createMockTransport({ scenario: 'success' });
</script>

<PrototypeShell {transport} />
