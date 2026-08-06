<script lang="ts">
  import { browser, dev } from '$app/environment';
  import { onMount } from 'svelte';
  import { registerServiceWorker } from '$lib/service-worker-registration';

  onMount(() => {
    if (!browser || dev) {
      return;
    }
    return registerServiceWorker();
  });
</script>

<slot />
