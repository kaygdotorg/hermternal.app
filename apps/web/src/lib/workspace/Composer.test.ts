import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import type { FocusIntent, SessionCoordinatorState } from '$lib/session/coordinator';
import Composer from './Composer.svelte';

function chatCoordinator(sessionGeneration = 1): SessionCoordinatorState {
  return {
    status: 'active',
    mode: 'chat',
    sessionGeneration,
    compatibility: 'compatible',
    chatStatus: 'ready',
    terminalStatus: 'detached',
    activeSessionId: 'session-chat'
  };
}

function composerFocus(sequence: number, sessionGeneration = 1): FocusIntent {
  return {
    mode: 'chat',
    target: 'composer',
    sessionId: 'session-chat',
    sessionGeneration,
    sequence
  };
}

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

  it('consumes only a current Chat focus intent once the composer is enabled', async () => {
    const coordinator = chatCoordinator();
    const intent = composerFocus(1);
    const view = render(Composer, { coordinator, focusIntent: intent, disabled: true });
    const editor = screen.getByRole('textbox', { name: 'Message Hermes' });

    expect(editor).not.toHaveFocus();
    await view.rerender({ coordinator, focusIntent: intent, disabled: false });
    await waitFor(() => expect(editor).toHaveFocus());

    editor.blur();
    await view.rerender({
      coordinator,
      focusIntent: { ...intent, sequence: 2, sessionId: 'other-session' }
    });
    await Promise.resolve();
    expect(editor).not.toHaveFocus();

    await view.rerender({ coordinator, focusIntent: composerFocus(3) });
    await waitFor(() => expect(editor).toHaveFocus());
  });

  it('does not steal focus during streaming or from a mismatched generation', async () => {
    const coordinator = chatCoordinator(2);
    const editorView = render(Composer, {
      coordinator,
      focusIntent: composerFocus(1, 1),
      isStreaming: true
    });
    const editor = screen.getByRole('textbox', { name: 'Message Hermes' });

    await Promise.resolve();
    expect(editor).not.toHaveFocus();
    await editorView.rerender({ coordinator, focusIntent: composerFocus(1, 1), isStreaming: false });
    await Promise.resolve();
    expect(editor).not.toHaveFocus();

    await editorView.rerender({ coordinator, focusIntent: composerFocus(2, 2), isStreaming: false });
    await waitFor(() => expect(editor).toHaveFocus());
  });
});
