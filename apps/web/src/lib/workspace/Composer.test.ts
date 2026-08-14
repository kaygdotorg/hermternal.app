import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import Composer from './Composer.svelte';

describe('Composer', () => {
  it('sends from pointer activation and suppresses the duplicate click', async () => {
    const onAction = vi.fn();
    render(Composer, { onAction });

    const editor = screen.getByRole('textbox', { name: 'Message Hermes' });
    const send = screen.getByRole('button', { name: 'Send message' });
    fireEvent.input(editor, { target: { value: 'Send this fixture' } });
    await waitFor(() => expect(send).toBeEnabled());

    fireEvent.pointerDown(send, { button: 0, pointerType: 'mouse' });
    fireEvent.click(send);

    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction).toHaveBeenCalledWith({ type: 'send', text: 'Send this fixture' });
    await waitFor(() => expect(editor).toHaveValue(''));
  });

  it('supports the Ctrl+Enter keyboard shortcut and ignores blank submits', async () => {
    const onAction = vi.fn();
    render(Composer, { onAction });

    const editor = screen.getByRole('textbox', { name: 'Message Hermes' });
    const send = screen.getByRole('button', { name: 'Send message' });
    fireEvent.click(send);
    expect(onAction).not.toHaveBeenCalled();

    fireEvent.input(editor, { target: { value: 'Keyboard fixture' } });
    fireEvent.keyDown(editor, { key: 'Enter', ctrlKey: true });

    await waitFor(() => {
      expect(onAction).toHaveBeenCalledWith({ type: 'send', text: 'Keyboard fixture' });
    });
  });

  it('keeps a draft when recovery disables the composer before send', async () => {
    const onAction = vi.fn();
    const view = render(Composer, { onAction });
    const editor = screen.getByRole('textbox', { name: 'Message Hermes' });
    fireEvent.input(editor, { target: { value: 'Keep this draft' } });

    await view.rerender({ onAction, disabled: true });

    expect(editor).toBeDisabled();
    expect(editor).toHaveValue('Keep this draft');
    expect(screen.getByRole('button', { name: 'Send message' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    expect(onAction).not.toHaveBeenCalled();
  });

  it('restores retained text and attachment metadata and emits bounded draft updates', async () => {
    const onDraftChange = vi.fn();
    render(Composer, {
      retainedDraft: {
        text: 'Restored draft',
        attachments: [{ id: 'attachment-1', name: 'brief.png', mediaType: 'image/png', sizeBytes: 12 }]
      },
      onDraftChange
    });

    expect(screen.getByRole('textbox', { name: 'Message Hermes' })).toHaveValue('Restored draft');
    fireEvent.input(screen.getByRole('textbox', { name: 'Message Hermes' }), {
      target: { value: 'Restored draft with edit' }
    });

    await waitFor(() =>
      expect(onDraftChange).toHaveBeenLastCalledWith({
        text: 'Restored draft with edit',
        attachments: [{ id: 'attachment-1', name: 'brief.png', mediaType: 'image/png', sizeBytes: 12 }]
      })
    );
  });

  it('keeps local and root draft state when the live send boundary rejects a prompt', async () => {
    const onAction = vi.fn(() => false);
    const onDraftChange = vi.fn();
    render(Composer, { onAction, onDraftChange });
    const editor = screen.getByRole('textbox', { name: 'Message Hermes' });
    fireEvent.input(editor, { target: { value: 'Retry after recovery' } });

    fireEvent.click(screen.getByRole('button', { name: 'Send message' }));

    expect(onAction).toHaveBeenCalledWith({ type: 'send', text: 'Retry after recovery' });
    expect(editor).toHaveValue('Retry after recovery');
    expect(onDraftChange).not.toHaveBeenLastCalledWith(undefined);
  });

  it('retains bounded metadata when the mock attachment action is activated', async () => {
    const onAction = vi.fn();
    const onDraftChange = vi.fn();
    render(Composer, { onAction, onDraftChange });

    fireEvent.click(screen.getByRole('button', { name: 'Add an attachment' }));

    expect(onAction).toHaveBeenCalledWith({ type: 'attach' });
    expect(onDraftChange).toHaveBeenLastCalledWith({
      text: '',
      attachments: [
        { id: 'mock-attachment-1', name: 'brief.png', mediaType: 'image/png', sizeBytes: 12 }
      ]
    });
    expect(JSON.stringify(onDraftChange.mock.calls)).not.toContain('blob');
    expect(JSON.stringify(onDraftChange.mock.calls)).not.toContain('path');
  });
});
