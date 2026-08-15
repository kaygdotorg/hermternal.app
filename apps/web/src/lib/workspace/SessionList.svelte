<script lang="ts">
  import Pill from './Pill.svelte';
  import type { SessionSummary, WorkspaceActionHandler } from './types';

  export let sessions: SessionSummary[] = [];
  export let activeSessionId = '';
  export let onAction: WorkspaceActionHandler = () => {};

  $: pinned = sessions.filter((session) => session.group === 'pinned');
  $: recent = sessions.filter((session) => session.group === 'recent');

  function selectSession(sessionId: string): void {
    onAction({ type: 'select-session', sessionId });
  }
</script>

<nav aria-label="Conversations" class="session-list">
  <div class="sidebar-heading">
    <span class="brand-mark">hermternal</span>
    <Pill ariaLabel="Collapse conversations" icon="arrow-left" iconOnly label="Collapse" variant="ghost" />
  </div>

  <div class="new-chat-row">
    <Pill
      ariaLabel="Start a new chat"
      fullWidth
      icon="plus"
      label="New chat"
      shortcut="⌘N"
      variant="ghost"
      onActivate={() => onAction({ type: 'new-session' })}
    />
  </div>

  <div class="primary-destinations" aria-label="Workspace destinations">
    <Pill fullWidth icon="spark" label="Automations" variant="ghost" />
    <Pill fullWidth icon="tool" label="Kanban" variant="ghost" />
  </div>

  <section aria-labelledby="pinned-heading" class="session-group">
    <div class="group-heading">
      <h2 id="pinned-heading">Pinned</h2>
      <span aria-hidden="true" class="group-count">{pinned.length}</span>
    </div>
    <div class="session-items">
      {#each pinned as session (session.id)}
        <div class="session-row">
          <Pill
            ariaLabel={`Open ${session.title}${session.unread ? ', unread' : ''}`}
            description={session.detail}
            fullWidth
            icon="conversation"
            ariaCurrent={session.id === activeSessionId ? 'page' : undefined}
            label={session.title}
            selected={session.id === activeSessionId}
            variant={session.id === activeSessionId ? 'selected' : 'ghost'}
            onActivate={() => selectSession(session.id)}
          />
          {#if session.unread}
            <span aria-hidden="true" class="unread-dot"></span>
          {/if}
        </div>
      {/each}
    </div>
  </section>

  <section aria-labelledby="recent-heading" class="session-group recent-group">
    <div class="group-heading">
      <h2 id="recent-heading">Recents</h2>
      <span aria-hidden="true" class="group-count">{recent.length}</span>
    </div>
    <div class="session-items">
      {#each recent as session (session.id)}
        <div class="session-row">
          <Pill
            ariaLabel={`Open ${session.title}${session.unread ? ', unread' : ''}`}
            description={session.detail}
            fullWidth
            icon="conversation"
            ariaCurrent={session.id === activeSessionId ? 'page' : undefined}
            label={session.title}
            selected={session.id === activeSessionId}
            variant={session.id === activeSessionId ? 'selected' : 'ghost'}
            onActivate={() => selectSession(session.id)}
          />
          {#if session.unread}
            <span aria-hidden="true" class="unread-dot"></span>
          {/if}
        </div>
      {/each}
    </div>
  </section>

  <div class="sidebar-spacer"></div>

  <div class="profile-row">
    <span aria-hidden="true" class="avatar">H</span>
    <span class="profile-name">Hermes</span>
    <div class="profile-actions">
      <Pill ariaLabel="Open profile" icon="conversation" iconOnly label="Profile" variant="ghost" />
      <Pill ariaLabel="Open settings" icon="shield" iconOnly label="Settings" variant="ghost" />
      <Pill ariaLabel="Open utilities" icon="menu" iconOnly label="Utilities" variant="ghost" />
    </div>
  </div>
</nav>

<style>
  .session-list {
    box-sizing: border-box;
    display: flex;
    min-width: 0;
    min-height: 100%;
    flex-direction: column;
    gap: 8px;
    padding: 16px;
    border: 1px solid var(--chrome-line);
    border-radius: var(--radius-glass);
    background: var(--chrome-surface);
    box-shadow: var(--chrome-shadow);
    backdrop-filter: blur(28px) saturate(155%);
  }

  .sidebar-heading,
  .profile-row,
  .group-heading {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .sidebar-heading {
    min-height: 56px;
    padding-inline: 10px 8px;
  }

  .brand-mark {
    flex: 1 1 auto;
    color: var(--ink);
    font-family: 'Dancing Script', system-ui, sans-serif;
    font-style: normal;
    font-size: 27px;
    font-weight: 600;
    letter-spacing: -0.02em;
    line-height: 31px;
  }

  .primary-destinations {
    display: flex;
    flex-direction: column;
    gap: 0;
    padding-block: 2px;
  }

  .new-chat-row :global(.pill),
  .primary-destinations :global(.pill) {
    border-color: transparent;
    background: transparent;
  }

  /* The preview keeps destinations inert until their product actions exist,
     but their resting Paper state is still quiet ink instead of a disabled
     button shell. The native disabled state and tooltip remain intact. */
  .primary-destinations :global(.pill:disabled) {
    color: color-mix(in srgb, var(--ink) 84%, var(--muted));
    opacity: 0.9;
  }

  .session-group {
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 12px 8px 10px;
    border: 1px solid color-mix(in srgb, var(--chrome-line) 42%, transparent);
    border-radius: var(--radius-nested-glass);
    background: color-mix(in srgb, var(--surface) 66%, transparent);
    box-shadow: 0 4px 12px color-mix(in srgb, var(--ink) 4%, transparent);
  }

  .recent-group {
    padding-top: 8px;
  }

  .group-heading {
    min-height: 30px;
    justify-content: space-between;
    padding-inline: 6px;
    color: var(--muted);
  }

  .group-heading h2 {
    margin: 0;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.06em;
    line-height: 16px;
    text-transform: uppercase;
  }

  .group-count {
    display: none;
  }

  .session-items {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .session-row {
    position: relative;
    min-width: 0;
  }

  .session-row :global(.pill) {
    min-height: 44px;
    padding-inline: 8px 10px;
    border-color: transparent;
    background: transparent;
  }

  .session-row :global(.pill-label) {
    font-size: 14px;
  }

  .session-row :global(.pill.selected) {
    border-color: transparent;
    background: color-mix(in srgb, var(--signal) 12%, var(--surface));
    box-shadow: none;
  }

  .session-row :global(.icon-slot) {
    width: 20px;
    flex-basis: 20px;
    color: color-mix(in srgb, var(--muted) 72%, var(--surface));
  }

  .session-row :global(.pill.selected .icon-slot) {
    color: var(--signal);
  }

  .unread-dot {
    position: absolute;
    top: 17px;
    right: 12px;
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--success) 16%, transparent);
    pointer-events: none;
  }

  .sidebar-spacer {
    min-height: 80px;
    flex: 1 1 auto;
  }

  .profile-row {
    min-height: 44px;
    padding: 12px 0 0;
    border-top: 1px solid var(--line-soft);
  }

  .avatar {
    display: inline-flex;
    width: 32px;
    height: 32px;
    flex: 0 0 32px;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--chrome-line);
    border-radius: 50%;
    background: color-mix(in srgb, var(--signal) 12%, var(--surface));
    color: var(--signal);
    font-size: 14px;
    font-weight: 600;
    line-height: 20px;
  }

  .profile-name {
    flex: 1 1 auto;
    min-width: 0;
    color: var(--muted);
    font-size: 14px;
    line-height: 18px;
  }

  .profile-actions {
    display: flex;
    flex: 0 0 auto;
    gap: 0;
    padding: 1px 2px;
    border: 1px solid var(--chrome-line);
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--surface) 62%, transparent);
  }

  .profile-actions :global(.pill) {
    min-width: 44px;
    min-height: 44px;
    padding-inline: 6px;
    border-color: transparent;
    background: transparent;
  }
</style>
