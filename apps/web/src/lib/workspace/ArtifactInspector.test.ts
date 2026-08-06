import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import ArtifactInspector from './ArtifactInspector.svelte';

describe('ArtifactInspector', () => {
  it('implements tab, tabpanel, and arrow-key semantics', async () => {
    render(ArtifactInspector);

    const tabs = screen.getAllByRole('tab');
    expect(tabs).toHaveLength(3);
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true');
    expect(tabs[0]).toHaveAttribute('aria-controls', 'inspector-panel-artifacts');
    expect(screen.getByRole('tabpanel')).toHaveAttribute('aria-labelledby', 'inspector-tab-artifacts');
    expect(screen.getAllByRole('tabpanel', { hidden: true })).toHaveLength(3);

    tabs[0].focus();
    fireEvent.keyDown(tabs[0], { key: 'ArrowRight' });

    await waitFor(() => {
      expect(tabs[1]).toHaveFocus();
      expect(tabs[1]).toHaveAttribute('aria-selected', 'true');
    });
    expect(screen.getByRole('tabpanel')).toHaveAttribute('aria-labelledby', 'inspector-tab-sources');
  });

  it('native-disables deferred artifact actions instead of exposing no-op activation', () => {
    render(ArtifactInspector);

    const undo = screen.getByRole('button', { name: 'Undo artifact action' });
    const open = screen.getByRole('button', { name: 'Open artifact preview' });
    const download = screen.getByRole('button', { name: 'Download artifact preview' });
    expect(undo).toBeDisabled();
    expect(open).toBeDisabled();
    expect(download).toBeDisabled();
    expect(undo).toHaveAttribute('title', 'Undo is deferred in this preview');
    expect(download).toHaveAttribute('title', 'Download is deferred in this preview');
  });
});
