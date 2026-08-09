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
  $: pendingLabel = provider.kind === 'oauth' ? 'Checking provider manifest' : 'Validating provider entries';
  $: pendingMobileLabel = provider.kind === 'oauth' ? 'Provider manifest' : 'Provider entries';
  $: pendingDescription =
    provider.kind === 'oauth' ? 'Loading · no sign-in action yet' : 'Waiting for a complete response';
  $: actionLabel = pending ? pendingLabel : provider.kind === 'oauth' ? `Continue with ${provider.name}` : provider.name;
  $: description = pending
    ? pendingDescription
    : expanded && provider.kind === 'oauth'
      ? `${provider.description} · No provider window opens in this preview`
      : provider.description;
  $: mobileDescription = pending
    ? pendingDescription
    : provider.mobileDescription ??
      (provider.kind === 'oauth' ? 'OAuth provider' : provider.kind === 'password' ? 'Username and password' : provider.description);

  let trailingIcon: IconName = 'arrow-right';
  $: trailingIcon = pending ? 'clock' : unavailable ? 'warning' : expanded ? 'arrow-down' : 'arrow-right';
</script>

<div class:expanded class:pending class:unavailable class="provider-card" data-provider-id={provider.id}>
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
  {#if pending}
    <span aria-hidden="true" class="mobile-label">{pendingMobileLabel}</span>
  {/if}
  {#if pending || (!unavailable && mobileDescription !== provider.description)}
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
    border-radius: var(--radius-pill);
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

  .mobile-label,
  .mobile-description {
    display: none;
  }

  @media (max-width: 600px) {
    .provider-card :global(.pill) {
      min-height: 68px;
    }

    /* Pending Paper rows use shorter narrow labels while preserving the
       desktop wording for assistive technology and wider layouts. */
    .provider-card.pending :global(.pill-label),
    .provider-card.pending :global(.pill-description) {
      visibility: hidden;
    }

    .mobile-label,
    .mobile-description {
      position: absolute;
      right: 48px;
      left: 66px;
      display: block;
      overflow: hidden;
      color: var(--muted);
      pointer-events: none;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    .mobile-label {
      top: 13px;
      font-size: var(--text-body);
      font-weight: var(--weight-semibold);
      line-height: 20px;
    }

    .mobile-description {
      bottom: 10px;
      font-size: var(--text-meta);
      line-height: var(--leading-meta);
    }

    /* Unavailable capability explanations are real provider data, not the
       compact mobile replacement. Keep the full explanation readable. */
    .provider-card.unavailable :global(.pill-description) {
      visibility: visible;
      overflow: visible;
      text-overflow: clip;
      white-space: normal;
    }

    .provider-card.unavailable .mobile-description {
      display: none;
    }
  }
</style>
