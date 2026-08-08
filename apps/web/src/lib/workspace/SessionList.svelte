<script lang="ts">
  import { onMount, tick } from 'svelte';
  import Pill from './Pill.svelte';
  import type { SessionSummary, WorkspaceActionHandler } from './types';

  type ScrollPosition = { element: HTMLElement; top: number; left: number };

  export let sessions: SessionSummary[] = [];
  export let activeSessionId = '';
  export let onAction: WorkspaceActionHandler = () => {};
  export let onSignOut: () => void = () => {};
  export let accountMenuId = 'account-menu';

  let accountMenuOpen = false;
  let signOutPending = false;
  let accountMenuTrigger: HTMLButtonElement | undefined;
  let accountMenu: HTMLElement | undefined;
  let accountMenuFocusGeneration = 0;

  function captureScrollPositions(element: HTMLElement | null | undefined): ScrollPosition[] {
    const scrollPositions: ScrollPosition[] = [];
    const seen = new Set<HTMLElement>();
    let ancestor = element?.parentElement as HTMLElement | null;
    while (ancestor) {
      if (!seen.has(ancestor)) {
        seen.add(ancestor);
        scrollPositions.push({ element: ancestor, top: ancestor.scrollTop, left: ancestor.scrollLeft });
      }
      ancestor = ancestor.parentElement;
    }

    const documentScroller = document.scrollingElement as HTMLElement | null;
    if (documentScroller && !seen.has(documentScroller)) {
      scrollPositions.push({ top: documentScroller.scrollTop, left: documentScroller.scrollLeft, element: documentScroller });
    }
    return scrollPositions;
  }

  $: pinned = sessions.filter((session) => session.group === 'pinned');
  $: recent = sessions.filter((session) => session.group === 'recent');

  function selectSession(sessionId: string): void {
    onAction({ type: 'select-session', sessionId });
  }

  async function afterActivationFrame(): Promise<void> {
    await tick();
    await new Promise<void>((resolve) => {
      if (typeof requestAnimationFrame === 'function') requestAnimationFrame(() => resolve());
      else setTimeout(resolve, 0);
    });
  }

  function focusWithoutScroll(element: HTMLElement | null | undefined): void {
    if (!element) return;

    const scrollPositions = captureScrollPositions(element);
    element.focus({ preventScroll: true });
    for (const position of scrollPositions) {
      position.element.scrollTop = position.top;
      position.element.scrollLeft = position.left;
    }
  }

  function focusBelongsToMenuTransition(focused: Element | null, closingMenu: HTMLElement | undefined): boolean {
    return (
      focused === accountMenuTrigger ||
      focused === document.body ||
      focused === document.documentElement ||
      focused === closingMenu ||
      Boolean(focused && closingMenu?.contains(focused))
    );
  }

  function focusBelongsToMenuOpenTransition(focused: Element | null, focusAtOpen: Element | null): boolean {
    return (
      focused === focusAtOpen ||
      focused === accountMenuTrigger ||
      focused === document.body ||
      focused === document.documentElement ||
      Boolean(focused && accountMenu?.contains(focused))
    );
  }

  async function focusAccountMenuStart(generation: number, focusAtOpen: Element | null): Promise<void> {
    await afterActivationFrame();
    if (generation !== accountMenuFocusGeneration || !accountMenuOpen) return;

    const focused = document.activeElement;
    // Do not steal focus from a control the user reached while the menu was
    // opening. The trigger and neutral document focus are expected browser
    // transitions; an already-focused menu descendant owns focus itself.
    if (!focusBelongsToMenuOpenTransition(focused, focusAtOpen) || accountMenu?.contains(focused)) return;

    // The mobile drawer is a scroll container. Preserve its current position while
    // moving focus into the newly-rendered menu. Capture at focus time so a real
    // user's later scroll is never replaced by a stale mount-time snapshot.
    focusWithoutScroll(accountMenu?.querySelector<HTMLButtonElement>('[role="menuitem"]:not([disabled])'));
  }

  function openAccountMenu(): void {
    if (signOutPending) return;
    const generation = ++accountMenuFocusGeneration;
    const focusAtOpen = document.activeElement;
    accountMenuOpen = true;
    void focusAccountMenuStart(generation, focusAtOpen);
  }

  async function closeAccountMenu(restoreFocus = true): Promise<void> {
    const generation = ++accountMenuFocusGeneration;
    const closingMenu = accountMenu;
    const focusAtClose = document.activeElement;
    const ownsFocusAtClose = focusBelongsToMenuTransition(focusAtClose, closingMenu);
    accountMenuOpen = false;
    if (!restoreFocus || !ownsFocusAtClose) return;
    await afterActivationFrame();
    if (generation !== accountMenuFocusGeneration || accountMenuOpen) return;

    // Do not steal focus from a control the user reached while the menu was
    // closing. Body focus is the browser's expected handoff after removing the
    // menu; the trigger/menu transition still owns that neutral state.
    const focusAfterClose = document.activeElement;
    if (!focusBelongsToMenuTransition(focusAfterClose, closingMenu)) return;
    focusWithoutScroll(accountMenuTrigger);
  }

  function toggleAccountMenu(): void {
    if (accountMenuOpen) void closeAccountMenu();
    else openAccountMenu();
  }

  function requestSignOut(): void {
    if (signOutPending) return;
    signOutPending = true;
    // Invalidate any delayed menu-focus continuation before removing the menu.
    // The root owns BrowserAuthSession.logout(); this narrow callback keeps the
    // shell independent from auth transport and local workspace invalidation.
    void closeAccountMenu(false);
    onSignOut();
  }

  function handleAccountMenuKeydown(event: KeyboardEvent): void {
    if (!accountMenuOpen || event.key !== 'Escape') return;
    // The trigger owns this handler while focus is still settling. Stop before
    // WorkspacePreview's window handler can close the surrounding mobile drawer.
    event.preventDefault();
    event.stopPropagation();
    void closeAccountMenu();
  }

  function handleWindowKeydown(event: KeyboardEvent): void {
    if (!accountMenuOpen || event.key !== 'Escape') return;
    // Touch pointerdown can open the menu while focus remains on another drawer
    // control. Capture Escape before WorkspacePreview's window bubble handler so
    // the nested account menu closes without dismissing the whole drawer.
    event.preventDefault();
    event.stopImmediatePropagation();
    void closeAccountMenu();
  }

  onMount(() => {
    window.addEventListener('keydown', handleWindowKeydown, true);
    return () => window.removeEventListener('keydown', handleWindowKeydown, true);
  });

  function handleAccountMenuFocusOut(event: FocusEvent): void {
    if (!accountMenuOpen) return;
    const next = event.relatedTarget as Node | null;
    if (!next || !accountMenu?.contains(next)) void closeAccountMenu(false);
  }
</script>

<nav aria-label="Conversations" class="session-list">
  <div class="sidebar-heading">
    <span class="brand-mark">hermternal</span>
    <Pill ariaLabel="Collapse conversations" icon="arrow-left" iconOnly label="Collapse" variant="ghost" />
  </div>

  <Pill
    ariaLabel="Start a new chat"
    fullWidth
    icon="plus"
    label="New chat"
    shortcut="⌘N"
    onActivate={() => onAction({ type: 'new-session' })}
  />

  <div class="primary-destinations" aria-label="Workspace destinations">
    <Pill fullWidth icon="spark" label="Automations" variant="ghost" />
    <Pill fullWidth icon="tool" label="Kanban" variant="ghost" />
  </div>

  <section aria-labelledby="pinned-heading" class="session-group">
    <div class="group-heading">
      <h2 id="pinned-heading">Pinned</h2>
      <span class="group-count">{pinned.length}</span>
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
      <span class="group-count">{recent.length}</span>
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
      <Pill
        ariaControls={accountMenuId}
        ariaHasPopup="menu"
        ariaLabel="Open account menu"
        bind:element={accountMenuTrigger}
        expandable
        expanded={accountMenuOpen}
        icon="conversation"
        iconOnly
        label="Account"
        variant="ghost"
        onActivate={toggleAccountMenu}
        onKeyDown={handleAccountMenuKeydown}
      />
      <Pill ariaLabel="Open settings" icon="shield" iconOnly label="Settings" variant="ghost" />
      <Pill ariaLabel="Open utilities" icon="menu" iconOnly label="Utilities" variant="ghost" />
    </div>
  </div>

  {#if accountMenuOpen}
    <div
      id={accountMenuId}
      aria-label="Account menu"
      bind:this={accountMenu}
      class="account-menu"
      role="menu"
      tabindex="-1"
      onfocusout={handleAccountMenuFocusOut}
      onkeydown={handleAccountMenuKeydown}
    >
      <div class="account-menu-header">
        <span aria-hidden="true" class="menu-avatar">H</span>
        <span class="menu-account-copy">
          <span class="menu-account-name">Hermes</span>
          <span class="menu-account-subtitle">Account</span>
        </span>
        <span aria-hidden="true" class="menu-account-shortcut">⌘K</span>
      </div>
      <div class="account-menu-divider" role="separator"></div>
      <Pill
        ariaLabel={signOutPending ? 'Signing out' : 'Sign out'}
        disabled={signOutPending}
        fullWidth
        icon="logout"
        label={signOutPending ? 'Signing out' : 'Sign out'}
        role="menuitem"
        variant="ghost"
        onActivate={requestSignOut}
      />
      <div class="account-menu-hint">Enter or Space activates · Escape closes</div>
    </div>
  {/if}
</nav>

<style>
  .session-list {
    position: relative;
    box-sizing: border-box;
    display: flex;
    min-width: 0;
    min-height: 100%;
    flex-direction: column;
    gap: 12px;
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
    min-height: 60px;
    padding-inline: 10px 8px;
  }

  .brand-mark {
    flex: 1 1 auto;
    color: var(--ink);
    font-family: 'Dancing Script', 'Instrument Sans', cursive;
    font-size: 27px;
    font-weight: 600;
    letter-spacing: -0.02em;
    line-height: 31px;
  }

  .primary-destinations {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding-block: 4px;
  }

  .session-group {
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 6px 10px;
    border: 1px solid var(--chrome-line);
    border-radius: var(--radius-nested-glass);
    background: color-mix(in srgb, var(--surface) 58%, transparent);
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
    font-size: 12px;
    line-height: 16px;
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
    padding-inline: 10px 12px;
  }

  .session-row :global(.pill-label) {
    font-size: 14px;
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
    padding: 8px 4px 0;
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
    gap: 2px;
  }

  .profile-actions :global(.pill) {
    min-width: 44px;
    min-height: 44px;
    padding-inline: 6px;
  }

  .account-menu {
    position: absolute;
    bottom: 146px;
    left: 11px;
    z-index: 8;
    box-sizing: border-box;
    display: flex;
    width: min(242px, calc(100% - 32px));
    max-width: calc(100% - 32px);
    min-width: 0;
    flex-direction: column;
    gap: 8px;
    padding: 8px;
    border: 1px solid var(--line, #d8dde5);
    border-radius: var(--radius-popover, 18px);
    background: var(--surface, var(--color-paper, #fff));
    color: var(--ink, #16181d);
    box-shadow: 0 18px 40px color-mix(in srgb, var(--ink, #16181d) 16%, transparent);
  }

  .account-menu-header {
    display: flex;
    min-height: 40px;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    padding-inline: 8px;
  }

  .menu-avatar {
    display: inline-flex;
    width: 28px;
    height: 28px;
    flex: 0 0 28px;
    align-items: center;
    justify-content: center;
    border: 1px solid var(--line, #d8dde5);
    border-radius: 50%;
    background: color-mix(in srgb, var(--signal, #4c6fff) 12%, var(--surface, #fff));
    color: var(--signal, #4c6fff);
    font-size: 14px;
    font-weight: 600;
    line-height: 20px;
  }

  .menu-account-copy {
    display: flex;
    min-width: 0;
    flex: 1 1 auto;
    flex-direction: column;
  }

  .menu-account-name {
    min-width: 0;
    color: var(--ink, #16181d);
    font-size: 14px;
    font-weight: 600;
    line-height: 18px;
  }

  .menu-account-subtitle,
  .menu-account-shortcut,
  .account-menu-hint {
    color: var(--muted, #667080);
    font-size: 12px;
    line-height: 16px;
  }

  .menu-account-subtitle {
    min-width: 0;
  }

  .menu-account-shortcut {
    flex: 0 0 auto;
  }

  .account-menu-divider {
    width: 100%;
    height: 1px;
    flex-shrink: 0;
    background: var(--line, #d8dde5);
  }

  .account-menu :global(.pill) {
    width: 100%;
    min-height: 44px;
    justify-content: flex-start;
    gap: 10px;
    padding-inline: 12px;
    border-color: transparent;
    color: var(--ink, #16181d);
  }

  .account-menu :global(.pill:hover:not(:disabled)) {
    border-color: var(--line, #d8dde5);
    background: var(--gate-state-surface, color-mix(in srgb, var(--signal, #4c6fff) 7%, var(--surface, #fff)));
  }

  /* Logout sheets specify a two-pixel focus treatment, narrower than the
     shared pill default while preserving the same visible target and offset. */
  .account-menu :global(.pill:focus-visible) {
    outline: 2px solid var(--gate-focus, var(--focus, var(--signal, #4c6fff)));
    outline-offset: 2px;
  }

  .account-menu :global(.pill:disabled) {
    background: color-mix(in srgb, var(--line, #d8dde5) 48%, var(--surface, #fff));
  }

  .account-menu-hint {
    min-height: 16px;
    padding-inline: 12px;
  }

  @media (max-width: 760px) {
    .account-menu {
      bottom: 158px;
      left: 15px;
      width: min(308px, calc(100% - 32px));
      max-width: calc(100% - 32px);
    }
  }
</style>
