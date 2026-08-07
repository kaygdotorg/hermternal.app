<script lang="ts">
  import Pill from '$lib/workspace/Pill.svelte';
  import type { IconName } from '$lib/workspace/icon-types';
  import type { AuthProvider, AuthActionHandler } from './types';

  export let provider: AuthProvider;
  export let disabled = false;
  export let expanded = false;
  export let pending = false;
  export let onAction: AuthActionHandler = () => {};

  $: unavailable = provider.kind === 'unavailable';
  $: description = pending
    ? provider.kind === 'oauth'
      ? 'Checking provider manifest'
      : 'Validating provider entries'
    : expanded && provider.kind === 'oauth'
      ? `${provider.description} · No provider window opens in this preview`
      : provider.description;

  let trailingIcon: IconName = 'arrow-right';
  $: trailingIcon = pending ? 'clock' : unavailable ? 'warning' : expanded ? 'arrow-down' : 'arrow-right';
</script>

<div class:expanded class:pending class="provider-card" data-provider-id={provider.id}>
  <Pill
    ariaLabel={`${provider.name}${pending ? ', loading' : unavailable ? ', unavailable' : ''}`}
    {description}
    disabled={disabled || pending || unavailable}
    {expanded}
    fullWidth
    label={provider.name}
    monogram={provider.monogram}
    {trailingIcon}
    variant="neutral"
    onActivate={() =>
      onAction({ type: 'choose-provider', providerId: provider.id, providerKind: provider.kind })}
  />
</div>

<style>
  .provider-card {
    width: 100%;
  }

  .provider-card :global(.pill) {
    min-height: 64px;
    padding-block: 12px;
    padding-inline: 14px;
    border-radius: var(--radius-input);
    background: var(--surface);
  }

  .provider-card :global(.pill-label) {
    font-size: 15px;
    line-height: 20px;
  }

  .provider-card :global(.pill-description) {
    font-size: 12px;
    line-height: 16px;
  }

  .provider-card:hover :global(.pill:not(:disabled)),
  .provider-card.expanded :global(.pill:not(:disabled)) {
    background: color-mix(in srgb, var(--signal) 5%, var(--surface));
  }

  .provider-card.pending :global(.pill) {
    cursor: wait;
  }

  @media (max-width: 600px) {
    .provider-card :global(.pill) {
      min-height: 68px;
    }
  }
</style>
