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
