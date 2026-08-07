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
});
