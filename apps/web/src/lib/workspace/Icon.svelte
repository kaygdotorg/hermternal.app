<script lang="ts">
  import type { IconName } from './icon-types';

  export let name: IconName;
  export let size = 18;
  export let strokeWidth = 1.8;
</script>

<svg
  aria-hidden="true"
  class="icon"
  fill="none"
  height={size}
  stroke="currentColor"
  stroke-linecap="round"
  stroke-linejoin="round"
  stroke-width={strokeWidth}
  viewBox="0 0 24 24"
  width={size}
>
  {#if name === 'arrow-left'}
    <path d="M19 12H6" />
    <path d="m11 6-6 6 6 6" />
  {:else if name === 'arrow-right'}
    <path d="M5 12h13" />
    <path d="m13 6 6 6-6 6" />
  {:else if name === 'arrow-down'}
    <path d="M12 5v13" />
    <path d="m6 13 6 6 6-6" />
  {:else if name === 'arrow-up'}
    <path d="M12 19V6" />
    <path d="m6 11 6-6 6 6" />
  {:else if name === 'check'}
    <path d="m5 12 4 4L19 6" />
  {:else if name === 'chevron-down'}
    <path d="m6 9 6 6 6-6" />
  {:else if name === 'clock'}
    <circle cx="12" cy="12" r="8" />
    <path d="M12 8v4l3 2" />
  {:else if name === 'close' || name === 'x'}
    <path d="m6 6 12 12" />
    <path d="m18 6-12 12" />
  {:else if name === 'conversation'}
    <path d="M5 6.5h14v9H9l-4 3v-12Z" />
    <path d="M8 10h8" />
  {:else if name === 'image'}
    <rect height="14" rx="2" width="16" x="4" y="5" />
    <circle cx="9" cy="10" r="1.5" />
    <path d="m5 17 4-4 3 3 2-2 5 5" />
  {:else if name === 'info'}
    <circle cx="12" cy="12" r="8" />
    <path d="M12 11v5" />
    <path d="M12 8h.01" />
  {:else if name === 'menu'}
    <path d="M5 7h14" />
    <path d="M5 12h14" />
    <path d="M5 17h14" />
  {:else if name === 'mic'}
    <rect height="10" rx="4" width="6" x="9" y="4" />
    <path d="M6 11a6 6 0 0 0 12 0" />
    <path d="M12 17v3" />
    <path d="M9 20h6" />
  {:else if name === 'paperclip'}
    <path d="m8 12 5.5-5.5a3 3 0 0 1 4.25 4.25L11 17.5a4 4 0 0 1-5.66-5.66l7-7" />
  {:else if name === 'plus'}
    <path d="M12 5v14" />
    <path d="M5 12h14" />
  {:else if name === 'refresh'}
    <path d="M19 7v4h-4" />
    <path d="M5 17v-4h4" />
    <path d="M7.5 9A6 6 0 0 1 19 11" />
    <path d="M16.5 15A6 6 0 0 1 5 13" />
  {:else if name === 'send'}
    <path d="m4 5 16 7-16 7 3-7-3-7Z" />
    <path d="M7 12h13" />
  {:else if name === 'share'}
    <circle cx="18" cy="5" r="2.5" />
    <circle cx="6" cy="12" r="2.5" />
    <circle cx="18" cy="19" r="2.5" />
    <path d="m8.2 10.8 7.6-4.4" />
    <path d="m8.2 13.2 7.6 4.4" />
  {:else if name === 'shield'}
    <path d="M12 4 19 7v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V7l7-3Z" />
    <path d="m9 12 2 2 4-4" />
  {:else if name === 'spark'}
    <path d="m12 3 1.2 5.8L19 10l-5.8 1.2L12 17l-1.2-5.8L5 10l5.8-1.2L12 3Z" />
    <path d="m19 16 .5 2.5L22 19l-2.5.5L19 22l-.5-2.5L16 19l2.5-.5L19 16Z" />
  {:else if name === 'stop'}
    <rect height="9" rx="1.5" width="9" x="7.5" y="7.5" />
  {:else if name === 'terminal'}
    <path d="m5 7 5 5-5 5" />
    <path d="M13 17h6" />
  {:else if name === 'tool'}
    <path d="m14 6 4 4" />
    <path d="m16 4 4 4-2 2-4-4 2-2Z" />
    <path d="m13 9-8 8a2 2 0 0 0 3 3l8-8" />
  {:else if name === 'warning'}
    <path d="m12 4 8 15H4L12 4Z" />
    <path d="M12 9v4" />
    <path d="M12 16h.01" />
  {:else if name === 'workspace'}
    <rect height="14" rx="3" width="16" x="4" y="5" />
    <path d="M14 5v14" />
  {/if}
</svg>

<style>
  .icon {
    display: block;
    flex: 0 0 auto;
  }
</style>
