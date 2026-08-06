import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import Timeline from './Timeline.svelte';
import type { TimelineItem, WorkspaceRuntimeState } from './types';

const approval: TimelineItem = {
  kind: 'approval',
  id: 'approval-test',
  title: 'Allow fixture action?',
  description: 'Synthetic approval only.',
  confirmLabel: 'Allow once',
  rejectLabel: 'Not now',
  status: 'pending'
};

describe('Timeline', () => {
  it.each(['stopped', 'offline', 'reconnecting'] as WorkspaceRuntimeState[])(
    'gates approval actions while %s',
    (runtimeState) => {
      const onAction = vi.fn();
      render(Timeline, { items: [approval], runtimeState, onAction });

      const allow = screen.getByRole('button', { name: 'Allow once, unavailable' });
      const reject = screen.getByRole('button', { name: 'Not now, unavailable' });
      expect(allow).toBeDisabled();
      expect(reject).toBeDisabled();
      fireEvent.click(allow);
      fireEvent.click(reject);
      expect(onAction).not.toHaveBeenCalled();
      expect(screen.getByRole('status')).toHaveTextContent(/unavailable/i);
    }
  );

  it('labels fixture streaming visibly and accessibly as synthetic by default', () => {
    const item: TimelineItem = {
      kind: 'streaming',
      id: 'streaming-test',
      model: 'Atlas · balanced',
      text: 'Synthetic partial response'
    };

    render(Timeline, { items: [item], runtimeState: 'streaming' });

    expect(screen.getByText('Hermes fixture')).toBeVisible();
    expect(screen.getByText('Synthetic preview')).toBeVisible();
    expect(
      screen.getByRole('article', { name: 'Synthetic preview response from a local fixture' })
    ).toHaveAttribute('aria-live', 'polite');
    expect(screen.queryByText('Responding')).not.toBeInTheDocument();
  });

  it('requires an explicit live-runtime source before exposing live status copy', () => {
    const item: TimelineItem = {
      kind: 'streaming',
      id: 'live-streaming-test',
      model: 'Atlas · balanced',
      text: 'Live partial response'
    };

    render(Timeline, { dataSource: 'live-runtime', items: [item], runtimeState: 'streaming' });

    expect(screen.getByText('Hermes')).toBeVisible();
    expect(screen.getByText('Responding')).toBeVisible();
    expect(screen.getByRole('article', { name: 'Live Hermes response' })).toHaveAttribute('aria-live', 'polite');
  });

  it('never mounts caller-provided image sources in the local preview', () => {
    const sources = ['https://example.com/image.png', '/same-origin.png', 'data:image/png;base64,ZmFrZQ=='];

    for (const [index, source] of sources.entries()) {
      const item: TimelineItem = {
        kind: 'image',
        id: `image-${index}`,
        attachment: {
          id: `source-${index}`,
          alt: `Image source ${index}`,
          caption: 'Presentation-only image fixture',
          src: source
        }
      };
      const view = render(Timeline, { items: [item] });
      expect(view.container.querySelector('img')).not.toBeInTheDocument();
      expect(screen.getByText(/image source omitted from this local preview/i)).toBeInTheDocument();
      expect(view.container.innerHTML).not.toContain(source);
      view.unmount();
    }
  });
});
