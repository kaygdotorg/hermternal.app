import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import WorkspacePreview from './WorkspacePreview.svelte';

describe('WorkspacePreview', () => {
  it('renders a stopped response and keeps the composer available', () => {
    render(WorkspacePreview, { state: 'stopped' });

    expect(screen.getByRole('log', { name: 'Conversation timeline' })).toBeInTheDocument();
    expect(screen.getAllByText('Response stopped')).toHaveLength(2);
    expect(screen.getByRole('textbox', { name: 'Message Hermes' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Send message' })).toBeDisabled();
  });

  it('enters title editing immediately and commits with Enter', async () => {
    const onAction = vi.fn();
    render(WorkspacePreview, { state: 'ready', onAction });

    fireEvent.click(screen.getByRole('button', { name: 'Edit conversation title' }));
    const editor = await waitFor(() => screen.getByRole('textbox', { name: 'Conversation title' }));
    fireEvent.input(editor, { target: { value: 'Updated session' } });
    fireEvent.keyDown(editor, { key: 'Enter' });

    expect(onAction).toHaveBeenCalledWith({ type: 'edit-title', title: 'Updated session' });
  });

  it('sends a message with the command-enter keyboard contract', async () => {
    const onAction = vi.fn();
    render(WorkspacePreview, { state: 'ready', onAction });

    const composer = screen.getByRole('textbox', { name: 'Message Hermes' });
    fireEvent.input(composer, { target: { value: 'Summarize this fixture' } });
    fireEvent.keyDown(composer, { key: 'Enter', metaKey: true });

    await waitFor(() => {
      expect(onAction).toHaveBeenCalledWith({ type: 'send', text: 'Summarize this fixture' });
    });
  });
});
