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
  $: actionLabel = provider.kind === 'oauth' ? `Continue with ${provider.name}` : provider.name;
  $: pendingCopy =
    provider.kind === 'oauth'
      ? 'Checking provider manifest\nLoading · no sign-in action yet'
      : 'Validating provider entries\nWaiting for a complete response';
  $: description = pending
    ? pendingCopy
    : expanded && provider.kind === 'oauth'
      ? `${provider.description} · No provider window opens in this preview`
      : provider.description;
  $: mobileDescription =
    provider.mobileDescription ??
    (provider.kind === 'oauth' ? 'OAuth provider' : provider.kind === 'password' ? 'Username and password' : provider.description);

  let trailingIcon: IconName = 'arrow-right';
  $: trailingIcon = pending ? 'clock' : unavailable ? 'warning' : expanded ? 'arrow-down' : 'arrow-right';
</script>

<div class:expanded class:pending class="provider-card" data-provider-id={provider.id}>
  <Pill
    ariaLabel={`${actionLabel}${pending ? ', loading' : unavailable ? ', unavailable' : ''}`}
    {description}
    disabled={disabled || pending || unavailable}
    {expanded}
    fullWidth
    label={actionLabel}
    monogram={provider.monogram}
    {trailingIcon}
    variant="neutral"
    onActivate={() =>
      onAction({ type: 'choose-provider', providerId: provider.id, providerKind: provider.kind })}
  />
  {#if mobileDescription !== provider.description}
    <span aria-hidden="true" class="mobile-description">{mobileDescription}</span>
  {/if}
</div>

<style>
  .provider-card {
    position: relative;
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
    font-size: var(--text-body);
    line-height: 20px;
  }

  .provider-card :global(.pill-description) {
    font-size: var(--text-meta);
    line-height: var(--leading-meta);
    white-space: pre-line;
  }

  .provider-card.pending :global(.pill-description) {
    white-space: pre-line;
  }

  .provider-card:hover :global(.pill:not(:disabled)),
  .provider-card.expanded :global(.pill:not(:disabled)) {
    background: color-mix(in srgb, var(--signal) 5%, var(--surface));
  }

  .provider-card.pending :global(.pill) {
    cursor: wait;
  }

  .mobile-description {
    display: none;
  }

  @media (max-width: 600px) {
    .provider-card :global(.pill) {
      min-height: 68px;
    }

    .provider-card :global(.pill-description) {
      visibility: hidden;
    }

    .mobile-description {
      position: absolute;
      right: 48px;
      bottom: 10px;
      left: 66px;
      display: block;
      overflow: hidden;
      color: var(--muted);
      font-size: var(--text-meta);
      line-height: var(--leading-meta);
      pointer-events: none;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
  }
</style>
