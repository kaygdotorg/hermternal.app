import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import WorkspacePreview from './WorkspacePreview.svelte';

const deferredControls = [
  'Collapse conversations',
  'Automations',
  'Kanban',
  'Open profile',
  'Open settings',
  'Open utilities',
  'Context usage 62 percent',
  'Record a voice message',
  'Open terminal mode'
];

describe('WorkspacePreview', () => {
  it('renders a stopped response, gates approval, and keeps the composer available', () => {
    render(WorkspacePreview, { state: 'stopped' });

    expect(screen.getByRole('log', { name: 'Conversation timeline' })).toBeInTheDocument();
    expect(screen.getAllByText('Response stopped')).toHaveLength(2);
    expect(screen.getByRole('textbox', { name: 'Message Hermes' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Send message' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Allow once, unavailable' })).toBeDisabled();
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

  it('keeps approval and clarification actions enabled only in the ready state', async () => {
    const states = [
      'ready',
      'streaming',
      'stopped',
      'offline',
      'reconnecting',
      'loading',
      'retryable-error',
      'permanent-error',
      'compatibility-check-failed',
      'unsupported-version'
    ] as const;

    for (const state of states) {
      const onAction = vi.fn();
      const view = render(WorkspacePreview, { state, onAction });
      const approval = screen.queryByRole('button', {
        name: state === 'ready' ? 'Allow once' : /Allow once, unavailable/
      });
      const clarification = screen.queryByRole('button', {
        name: state === 'ready' ? 'Include transfers' : /Include transfers, unavailable/
      });

      if (state === 'ready') {
        expect(approval).toBeEnabled();
        expect(clarification).toBeEnabled();
        fireEvent.click(approval!);
        fireEvent.click(clarification!);
        expect(onAction).toHaveBeenCalledWith({ type: 'approve-tool', itemId: 'approval-1' });
        expect(onAction).toHaveBeenCalledWith({
          type: 'answer-clarification',
          itemId: 'clarification-1',
          answer: 'Include transfers'
        });
      } else {
        if (approval) {
          await waitFor(() => expect(approval).toBeDisabled());
          fireEvent.click(approval);
        }
        if (clarification) {
          await waitFor(() => expect(clarification).toBeDisabled());
          fireEvent.click(clarification);
        }
        expect(onAction).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'approve-tool' }));
        expect(onAction).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'answer-clarification' }));
      }

      view.unmount();
    }
  });

  it('native-disables every visible no-handler control while retaining functional controls', () => {
    const onAction = vi.fn();
    render(WorkspacePreview, { state: 'ready', onAction });

    for (const name of deferredControls) {
      const control = screen.getByRole('button', { name });
      expect(control).toBeDisabled();
      expect(control).toHaveAttribute('title', expect.stringMatching(/deferred/i));
      fireEvent.click(control);
    }

    const workspaceOptions = screen.getByRole('button', { name: 'Workspace options' });
    expect(workspaceOptions).toBeDisabled();
    fireEvent.click(workspaceOptions);

    expect(screen.getByRole('button', { name: 'Start a new chat' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Add an attachment' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Open security policy' })).toBeEnabled();
    expect(onAction).not.toHaveBeenCalled();
  });

  it('renders both fail-closed compatibility gates with recovery actions and disabled input', () => {
    for (const state of ['compatibility-check-failed', 'unsupported-version'] as const) {
      const onAction = vi.fn();
      const view = render(WorkspacePreview, { state, onAction });

      expect(
        screen.getByRole('heading', {
          name: state === 'compatibility-check-failed' ? 'Compatibility check failed' : 'Unsupported Hermes revision'
        })
      ).toBeInTheDocument();
      expect(screen.getByRole('alert')).toHaveAttribute('aria-live', 'assertive');
      expect(screen.getByRole('textbox', { name: 'Message Hermes' })).toBeDisabled();

      fireEvent.click(screen.getByRole('button', { name: 'Retry compatibility check' }));
      fireEvent.click(screen.getByRole('button', { name: 'Return to sign-in' }));
      expect(onAction).toHaveBeenCalledWith({ type: 'retry-compatibility-check' });
      expect(onAction).toHaveBeenCalledWith({ type: 'return-to-sign-in' });

      view.unmount();
    }
  });

  it('exposes the approved narrow compound island, separate workspace action, and represented title editor', async () => {
    const onAction = vi.fn();
    render(WorkspacePreview, { state: 'ready', onAction });

    const preview = screen.getByTestId('runtime-preview');
    const island = preview.querySelector('.mobile-title-island');
    const conversations = island?.querySelector<HTMLButtonElement>('[aria-label="Open conversations"]');
    const mobileTitle = island?.querySelector<HTMLButtonElement>('[aria-label="Edit conversation title"]');
    const workspace = preview.querySelector<HTMLButtonElement>('[aria-label="Open workspace"]');
    expect(conversations).toBeInTheDocument();
    expect(mobileTitle).toBeInTheDocument();
    expect(workspace).toBeInTheDocument();
    expect(island).not.toContainElement(workspace);

    await fireEvent.click(workspace!);
    expect(preview.querySelector('aside[aria-label="Workspace"]')).toBeInTheDocument();
    expect(onAction).toHaveBeenCalledWith({ type: 'open-workspace' });

    await fireEvent.click(mobileTitle!);
    const editor = await screen.findByTestId('mobile-title-editor');
    expect(editor.querySelector('.title-edit-dimmer')).toBeInTheDocument();
    expect(screen.getByTestId('represented-mobile-keyboard')).toBeInTheDocument();
    await waitFor(() => expect(editor.querySelector('[aria-label="Conversation title"]')).toHaveFocus());
  });

  it('uses a two-column grid when the inspector is hidden', async () => {
    render(WorkspacePreview, { state: 'ready' });

    const grid = screen.getByTestId('runtime-preview').querySelector('.workspace-grid');
    expect(grid).not.toHaveClass('inspector-hidden');
    fireEvent.click(screen.getByRole('button', { name: 'Close workspace inspector' }));
    await waitFor(() => expect(grid).toHaveClass('inspector-hidden'));
    expect(screen.queryByRole('complementary', { name: 'Workspace inspector' })).not.toBeInTheDocument();
  });
});
