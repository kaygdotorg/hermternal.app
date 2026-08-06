<script lang="ts">
  import Icon from './Icon.svelte';
  import Pill from './Pill.svelte';
  import type { WorkspaceActionHandler } from './types';

  export let onAction: WorkspaceActionHandler = () => {};
  let activeTab: 'artifacts' | 'sources' | 'files' = 'artifacts';
</script>

<aside aria-label="Workspace inspector" class="inspector">
  <header class="inspector-header">
    <div>
      <p class="eyebrow">Workspace</p>
      <h2>Artifact inspector</h2>
    </div>
    <Pill ariaLabel="Close workspace inspector" icon="close" iconOnly label="Close inspector" variant="ghost" onActivate={() => onAction({ type: 'toggle-inspector' })} />
  </header>

  <div class="inspector-tabs" role="tablist" aria-label="Inspector sections">
    {#each [
      { id: 'artifacts', label: 'Artifacts', count: '' },
      { id: 'sources', label: 'Sources', count: '12' },
      { id: 'files', label: 'Files', count: '3' }
    ] as tab}
      <button
        aria-selected={activeTab === tab.id}
        class:active={activeTab === tab.id}
        role="tab"
        type="button"
        onclick={() => (activeTab = tab.id as typeof activeTab)}
      >
        <span>{tab.label}</span>
        {#if tab.count}<span class="tab-count">{tab.count}</span>{/if}
      </button>
    {/each}
  </div>

  {#if activeTab === 'artifacts'}
    <section class="artifact-card" aria-labelledby="artifact-heading">
      <header class="artifact-header">
        <span aria-hidden="true" class="artifact-icon"><Icon name="image" size={20} /></span>
        <div class="artifact-title">
          <h3 id="artifact-heading">EMEA logistics map</h3>
          <p>Generated · mock · just now</p>
        </div>
        <Pill ariaLabel="Undo artifact action" icon="refresh" iconOnly label="Undo" variant="ghost" />
      </header>

      <figure class="artifact-preview" aria-labelledby="artifact-caption">
        <figcaption id="artifact-caption">Synthetic container load by hub</figcaption>
        <div aria-hidden="true" class="thumbnail-bars">
          <span class="bar bar-one"></span>
          <span class="bar bar-two"></span>
          <span class="bar bar-three"></span>
          <span class="bar bar-four"></span>
        </div>
        <p class="thumbnail-note">Presentation-only thumbnail · no live analytics</p>
      </figure>

      <div class="artifact-actions">
        <Pill ariaLabel="Open artifact preview" icon="arrow-up" label="Open" variant="selected" onActivate={() => onAction({ type: 'toggle-inspector' })} />
        <Pill ariaLabel="Download artifact preview" icon="arrow-down" iconOnly label="Download" variant="ghost" />
      </div>
    </section>
  {:else if activeTab === 'sources'}
    <div class="empty-tab" role="tabpanel">
      <Icon name="tool" size={20} />
      <h3>Synthetic sources</h3>
      <p>Source references stay local to this fixture. No remote documents are loaded.</p>
    </div>
  {:else}
    <div class="empty-tab" role="tabpanel">
      <Icon name="image" size={20} />
      <h3>Fixture files</h3>
      <p>Attachments are represented as local placeholders until a later product phase.</p>
    </div>
  {/if}
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

  .eyebrow {
    margin: 0 0 2px;
    color: var(--muted);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.08em;
    line-height: 16px;
    text-transform: uppercase;
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
    padding: 2px;
    border-bottom: 1px solid var(--line-soft);
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
    background: color-mix(in srgb, var(--signal) 10%, var(--surface));
    color: var(--ink);
    font-weight: 600;
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
    display: flex;
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
    background: color-mix(in srgb, var(--signal) 6%, var(--surface));
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
    padding: 8px 10px;
    border-bottom: 1px solid var(--line-soft);
  }

  .bar {
    display: block;
    width: 25%;
    border-radius: 4px 4px 0 0;
    background: var(--signal);
  }

  .bar-one { height: 48%; opacity: 0.55; }
  .bar-two { height: 72%; opacity: 0.72; }
  .bar-three { height: 88%; opacity: 0.9; }
  .bar-four { height: 62%; opacity: 0.66; }

  .thumbnail-note {
    margin: 0;
    font-size: 11px;
  }

  .artifact-actions {
    display: flex;
    justify-content: space-between;
    gap: 8px;
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
