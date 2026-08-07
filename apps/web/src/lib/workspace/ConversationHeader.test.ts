import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import ConversationHeader from './ConversationHeader.svelte';

describe('ConversationHeader', () => {
  it('cancels title editing with Escape without emitting an edit', async () => {
    const onAction = vi.fn();
    render(ConversationHeader, { title: 'Original title', onAction });

    fireEvent.click(screen.getByRole('button', { name: 'Edit conversation title' }));
    const editor = await waitFor(() => screen.getByRole('textbox', { name: 'Conversation title' }));
    fireEvent.input(editor, { target: { value: 'Discarded title' } });
    fireEvent.keyDown(editor, { key: 'Escape' });
    fireEvent.blur(editor);

    expect(onAction).not.toHaveBeenCalled();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Edit conversation title' })).toBeInTheDocument());
  });

  it('keeps transient title editing neutral while persistent Chat mode exposes pressed state', () => {
    render(ConversationHeader);

    const titleButton = screen.getByRole('button', { name: 'Edit conversation title' });
    const chatButton = screen.getByRole('button', { name: 'Chat mode selected' });
    expect(titleButton).not.toHaveAttribute('aria-pressed');
    expect(chatButton).toHaveAttribute('aria-pressed', 'true');
  });
});
