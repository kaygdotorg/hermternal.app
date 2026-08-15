<script lang="ts">
  import { tick } from 'svelte';
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import type { WorkspaceActionHandler } from './types';

  type InspectorTab = 'artifacts' | 'sources' | 'files';

  const tabs: Array<{ id: InspectorTab; label: string; count?: string }> = [
    { id: 'artifacts', label: 'Artifacts' },
    { id: 'sources', label: 'Sources', count: '12' },
    { id: 'files', label: 'Files', count: '3' }
  ];

  export let onAction: WorkspaceActionHandler = () => {};
  let activeTab: InspectorTab = 'artifacts';
  let tabButtons: HTMLButtonElement[] = [];

  function selectTab(tab: InspectorTab): void {
    activeTab = tab;
  }

  async function handleTabKeydown(event: KeyboardEvent, index: number): Promise<void> {
    const key = event.key;
    if (key !== 'ArrowRight' && key !== 'ArrowLeft' && key !== 'Home' && key !== 'End') return;

    event.preventDefault();
    const nextIndex =
      key === 'Home'
        ? 0
        : key === 'End'
          ? tabs.length - 1
          : (index + (key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    activeTab = tabs[nextIndex].id;
    await tick();
    tabButtons[nextIndex]?.focus();
  }
</script>

<aside aria-label="Workspace inspector" class="inspector">
  <header class="inspector-header">
    <h2>Workspace</h2>
    <Pill
      ariaLabel="Close workspace inspector"
      icon="close"
      iconOnly
      label="Close inspector"
      variant="ghost"
      onActivate={() => onAction({ type: 'toggle-inspector' })}
    />
  </header>

  <div aria-label="Inspector sections" aria-orientation="horizontal" class="inspector-tabs" role="tablist">
    {#each tabs as tab, index (tab.id)}
      <button
        id={`inspector-tab-${tab.id}`}
        aria-controls={`inspector-panel-${tab.id}`}
        aria-selected={activeTab === tab.id}
        bind:this={tabButtons[index]}
        class:active={activeTab === tab.id}
        role="tab"
        tabindex={activeTab === tab.id ? 0 : -1}
        type="button"
        onclick={() => selectTab(tab.id)}
        onkeydown={(event) => handleTabKeydown(event, index)}
      >
        <span>{tab.label}</span>
        {#if tab.count}<span class="tab-count">{tab.count}</span>{/if}
      </button>
    {/each}
  </div>

  <div
    id="inspector-panel-artifacts"
    aria-labelledby="inspector-tab-artifacts"
    class="artifact-card"
    hidden={activeTab !== 'artifacts'}
    role="tabpanel"
    tabindex="0"
  >
    <header class="artifact-header">
      <span aria-hidden="true" class="artifact-icon"><Icon name="image" size={20} /></span>
      <div class="artifact-title">
        <h3 id="artifact-heading">EMEA logistics map</h3>
        <p>Generated · mock · just now</p>
      </div>
      <Pill
        ariaLabel="Undo artifact action"
        icon="refresh"
        iconOnly
        label="Undo"
        title="Undo is deferred in this preview"
        variant="ghost"
      />
    </header>

    <figure class="artifact-preview" aria-labelledby="artifact-caption">
      <figcaption id="artifact-caption">Container load by hub</figcaption>
      <div aria-hidden="true" class="thumbnail-bars">
        <div class="hub-bar"><span class="bar bar-one"></span><span>FRA</span></div>
        <div class="hub-bar"><span class="bar bar-two"></span><span>AMS</span></div>
        <div class="hub-bar"><span class="bar bar-three"></span><span>LHR</span></div>
        <div class="hub-bar"><span class="bar bar-four"></span><span>RTM</span></div>
      </div>
      <p class="thumbnail-note">Delay signal · 12% · synthetic fixture</p>
    </figure>

    <div class="artifact-actions">
      <Pill
        ariaLabel="Open artifact preview"
        disabled
        icon="arrow-up"
        iconOnly
        label="Open artifact"
        revealLabel
        title="Artifact preview is presentation-only"
        variant="action"
      />
      <Pill
        ariaLabel="Download artifact preview"
        icon="arrow-down"
        iconOnly
        label="Download"
        revealLabel
        title="Download is deferred in this preview"
        variant="ghost"
      />
    </div>
  </div>

  <div
    id="inspector-panel-sources"
    aria-labelledby="inspector-tab-sources"
    class="empty-tab"
    hidden={activeTab !== 'sources'}
    role="tabpanel"
    tabindex="0"
  >
    <Icon name="tool" size={20} />
    <h3>Synthetic sources</h3>
    <p>Source references stay local to this fixture. No remote documents are loaded.</p>
  </div>

  <div
    id="inspector-panel-files"
    aria-labelledby="inspector-tab-files"
    class="empty-tab"
    hidden={activeTab !== 'files'}
    role="tabpanel"
    tabindex="0"
  >
    <Icon name="image" size={20} />
    <h3>Fixture files</h3>
    <p>Attachments are represented as local placeholders until a later product phase.</p>
  </div>
</aside>

<style>
  .inspector {
    box-sizing: border-box;
    display: flex;
    min-width: 0;
    min-height: 100%;
    flex-direction: column;
    gap: 16px;
    padding: 24px;
    border: 1px solid var(--chrome-line);
    border-radius: var(--radius-glass);
    background: var(--chrome-surface);
    box-shadow: var(--chrome-shadow);
    backdrop-filter: blur(28px) saturate(155%);
  }

  .inspector-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }

  .inspector-header h2,
  .artifact-header h3,
  .empty-tab h3 {
    margin: 0;
    color: var(--ink);
    font-size: 16px;
    font-weight: 600;
    line-height: 20px;
  }

  .inspector-tabs {
    display: flex;
    gap: 2px;
    padding: 3px;
    border: 0;
    border-radius: var(--radius-pill);
    background: color-mix(in srgb, var(--surface) 72%, var(--line));
  }

  .inspector-tabs button {
    display: inline-flex;
    min-width: 0;
    min-height: 44px;
    flex: 1 1 0;
    align-items: center;
    justify-content: center;
    gap: 4px;
    padding: 8px 6px;
    border: 0;
    border-radius: var(--radius-pill);
    background: transparent;
    color: var(--muted);
    font: inherit;
    font-size: 13px;
    line-height: 18px;
    cursor: pointer;
  }

  .inspector-tabs button.active {
    background: color-mix(in srgb, var(--line) 34%, var(--surface));
    color: var(--ink);
    font-weight: 600;
  }

  /* A component-scoped display rule is required because the card styles are
     author CSS. Without it, the generic empty-panel display can override the
     browser's hidden attribute and leave mock source/file panels below the
     approved Paper card. */
  .artifact-card[hidden],
  .empty-tab[hidden] {
    display: none;
  }

  .inspector-tabs button:focus-visible {
    outline: 3px solid var(--focus);
    outline-offset: 2px;
  }

  .tab-count {
    color: var(--muted);
    font-size: 12px;
  }

  .artifact-card {
    box-sizing: border-box;
    display: flex;
    min-height: 326px;
    flex-direction: column;
    gap: 12px;
    padding: 16px;
    border: 1px solid var(--chrome-line);
    border-radius: var(--radius-nested-glass);
    background: color-mix(in srgb, var(--surface) 80%, transparent);
  }

  .artifact-header {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .artifact-header :global(.pill) {
    min-width: 32px;
    min-height: 32px;
    padding-inline: 4px;
    border-color: transparent;
    background: transparent;
  }

  .artifact-header :global(.pill:disabled) {
    border-color: transparent;
    background: transparent;
    color: var(--muted);
  }

  .artifact-icon {
    display: inline-flex;
    width: 40px;
    height: 40px;
    flex: 0 0 40px;
    align-items: center;
    justify-content: center;
    border-radius: var(--radius-input);
    background: color-mix(in srgb, var(--signal) 12%, var(--surface));
    color: var(--signal);
  }

  .artifact-title {
    min-width: 0;
    flex: 1 1 auto;
  }

  .artifact-title h3 {
    overflow: hidden;
    font-size: 14px;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .artifact-title p,
  .thumbnail-note,
  .empty-tab p {
    margin: 2px 0 0;
    color: var(--muted);
    font-size: 12px;
    line-height: 16px;
  }

  .artifact-preview {
    display: flex;
    min-height: 176px;
    flex-direction: column;
    gap: 10px;
    padding: 14px;
    margin: 0;
    border-radius: var(--radius-input);
    background: color-mix(in srgb, var(--line) 20%, var(--surface));
  }

  .artifact-preview figcaption {
    color: var(--ink);
    font-size: 12px;
    font-weight: 600;
    line-height: 16px;
  }

  .thumbnail-bars {
    display: flex;
    height: 92px;
    align-items: flex-end;
    gap: 8px;
    padding: 8px 10px 0;
    border-bottom: 1px solid var(--line-soft);
  }

  .hub-bar {
    display: flex;
    min-width: 0;
    height: 100%;
    flex: 1 1 0;
    flex-direction: column;
    align-items: center;
    justify-content: flex-end;
    gap: 6px;
    color: var(--muted);
    font-size: 10px;
    line-height: 14px;
  }

  .bar {
    display: block;
    width: 100%;
    min-height: 8px;
    border-radius: 4px 4px 0 0;
    background: color-mix(in srgb, var(--signal) 58%, #ffffff);
  }

  .bar-one {
    height: 48%;
    opacity: 0.55;
  }
  .bar-two {
    height: 72%;
    background: var(--signal);
    opacity: 0.9;
  }
  .bar-three {
    height: 88%;
    background: color-mix(in srgb, var(--signal) 58%, #ffffff);
    opacity: 0.72;
  }
  .bar-four {
    height: 62%;
    background: var(--courier);
    opacity: 0.9;
  }

  .thumbnail-note {
    margin: 0;
    font-size: 11px;
  }

  .artifact-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
  }

  /* Deferred prototype actions retain their accessibility and disabled
     semantics, but use the Paper resting materials so the mock does not look
     like a broken card. */
  .artifact-actions :global(.pill.action:disabled) {
    border-color: var(--signal);
    background: var(--signal);
    color: var(--action-ink);
    opacity: 1;
  }

  .artifact-actions :global(.pill.ghost:disabled) {
    border-color: var(--line);
    background: var(--surface);
    color: var(--ink);
    opacity: 1;
  }

  .empty-tab {
    display: flex;
    min-height: 180px;
    flex-direction: column;
    align-items: flex-start;
    justify-content: center;
    gap: 8px;
    padding: 16px;
    border: 1px dashed var(--line);
    border-radius: var(--radius-input);
    color: var(--muted);
  }

  .empty-tab h3 {
    color: var(--ink);
  }

  .empty-tab p {
    margin: 0;
  }
</style>
