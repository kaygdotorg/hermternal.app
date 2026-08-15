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
    expect(titleButton).not.toHaveClass('full-width');
    expect(titleButton.querySelector('.trailing-slot')).not.toBeInTheDocument();
    expect(chatButton).toHaveAttribute('aria-pressed', 'true');
  });

  it('keeps the desktop header controls as separate floating targets', () => {
    render(ConversationHeader);

    const header = document.querySelector('.conversation-header');
    expect(header).toHaveClass('conversation-header');
    expect(header?.querySelector('.title-region')).toBeInTheDocument();
    expect(header?.querySelector('.mode-controls')).toBeInTheDocument();
    expect(header?.querySelector('.share-control')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Workspace options' })).toBeDisabled();
  });

  it('native-disables Terminal until the draft has a coordinator-owned session', async () => {
    const onAction = vi.fn();
    const view = render(ConversationHeader, { terminalModeEnabled: false, onAction });

    const disabledTerminal = screen.getByRole('button', {
      name: 'Terminal unavailable until the first message is saved'
    });
    expect(disabledTerminal).toBeDisabled();
    expect(disabledTerminal).toHaveAttribute(
      'title',
      'Terminal is available after the first message is saved.'
    );
    await fireEvent.click(disabledTerminal);
    expect(onAction).not.toHaveBeenCalled();

    await view.rerender({ terminalModeEnabled: true });
    const enabledTerminal = screen.getByRole('button', { name: 'Open terminal mode' });
    expect(enabledTerminal).toBeEnabled();
    await fireEvent.click(enabledTerminal);
    expect(onAction).toHaveBeenCalledWith({ type: 'set-mode', mode: 'terminal' });
  });
});
