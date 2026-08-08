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
        expect(onAction).toHaveBeenCalledWith({ type: 'approve-tool', itemId: 'approval-1', scope: 'once' });
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

  it('makes the complete workspace underlay inert and emits only compatibility recovery actions', async () => {
    for (const state of ['compatibility-check-failed', 'unsupported-version'] as const) {
      const onAction = vi.fn();
      const view = render(WorkspacePreview, { state, onAction });
      const preview = screen.getByTestId('runtime-preview');
      const underlay = screen.getByTestId('workspace-underlay');
      const retry = screen.getByRole('button', { name: 'Retry compatibility check' });
      const returnToSignIn = screen.getByRole('button', { name: 'Return to sign-in' });
      const sidebar = underlay.querySelector('.sidebar');

      expect(sidebar).not.toHaveClass('open');
      expect(
        screen.getByRole('heading', {
          name: state === 'compatibility-check-failed' ? 'Compatibility check failed' : 'Unsupported Hermes revision'
        })
      ).toBeInTheDocument();
      expect(screen.getByRole('alert')).toHaveAttribute('aria-live', 'assertive');
      expect((underlay as HTMLElement & { inert: boolean }).inert).toBe(true);
      expect(underlay).toHaveAttribute('aria-hidden', 'true');
      expect(preview.querySelector<HTMLTextAreaElement>('[aria-label="Message Hermes"]')).toBeDisabled();
      await waitFor(() => expect(retry).toHaveFocus());

      const blockedControls = [
        '[aria-label="Start a new chat"]',
        '[aria-label="Open Product roadmap, unread"]',
        '[aria-label="Edit conversation title"]',
        '[aria-label="Open conversations"]',
        '[aria-label="Open workspace"]',
        '[aria-label="Close workspace inspector"]',
        '[aria-label="Add an attachment"]'
      ];
      for (const selector of blockedControls) {
        const control = underlay.querySelector<HTMLElement>(selector);
        expect(control).toBeInTheDocument();
        fireEvent.pointerDown(control!, { button: 0, pointerType: 'mouse' });
        fireEvent.click(control!, { detail: 1 });
      }
      expect(sidebar).not.toHaveClass('open');
      const composer = underlay.querySelector<HTMLTextAreaElement>('[aria-label="Message Hermes"]');
      fireEvent.input(composer!, { target: { value: 'Blocked fixture input' } });
      fireEvent.keyDown(composer!, { key: 'Enter', metaKey: true });

      expect(screen.queryByRole('textbox', { name: 'Conversation title' })).not.toBeInTheDocument();
      expect(onAction).not.toHaveBeenCalled();

      fireEvent.pointerDown(retry, { button: 0, pointerType: 'mouse' });
      fireEvent.click(retry, { detail: 1 });
      fireEvent.keyDown(returnToSignIn, { key: 'Enter' });
      fireEvent.click(returnToSignIn);
      expect(onAction).toHaveBeenCalledTimes(2);
      expect(onAction).toHaveBeenNthCalledWith(1, { type: 'retry-compatibility-check' });
      expect(onAction).toHaveBeenNthCalledWith(2, { type: 'return-to-sign-in' });

      view.unmount();
    }
  });

  it('marks fixture streaming as synthetic in visible status and live-region copy', () => {
    render(WorkspacePreview, { state: 'streaming' });

    const status = screen.getByTestId('streaming-state');
    expect(status).toHaveTextContent('Synthetic preview response');
    expect(status).toHaveTextContent('no live Hermes connection');
    expect(screen.getByText('Hermes fixture')).toBeVisible();
    expect(screen.getByText('Synthetic preview')).toBeVisible();
    expect(screen.queryByText('Hermes is responding')).not.toBeInTheDocument();
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
    // jsdom does not evaluate the named container query, so the mobile-only
    // surface is CSS-hidden in this unit test; the browser suite verifies its
    // visible Paper geometry at the narrow viewport.
    const workspaceDrawer = screen.getByTestId('mobile-workspace-drawer');
    expect(workspaceDrawer).toHaveAttribute('role', 'dialog');
    expect(workspaceDrawer).toHaveAttribute('aria-label', 'Workspace');
    expect(onAction).toHaveBeenCalledWith({ type: 'open-workspace' });

    await fireEvent.click(mobileTitle!);
    const editor = await screen.findByTestId('mobile-title-editor');
    expect(editor.querySelector('.title-edit-dimmer')).toBeInTheDocument();
    expect(screen.getByTestId('represented-mobile-keyboard')).toBeInTheDocument();
    await waitFor(() => expect(editor.querySelector('[aria-label="Conversation title"]')).toHaveFocus());
  });

  it('treats mobile drawers as modal surfaces and restores focus after Escape', async () => {
    render(WorkspacePreview, { state: 'ready' });

    // jsdom does not evaluate the named container query, so use the hidden
    // mobile-only trigger while the browser suite checks the visible surface.
    const conversations = screen.getByRole('button', { name: 'Open conversations', hidden: true });
    conversations.focus();
    await fireEvent.click(conversations);
    const dialog = screen.getByTestId('mobile-session-drawer');
    expect(dialog).toHaveAttribute('role', 'dialog');
    expect(dialog).toHaveAttribute('aria-label', 'Conversations');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByTestId('mobile-drawer-scrim')).toBeInTheDocument();
    expect(screen.getByTestId('workspace-underlay')).toHaveAttribute('aria-hidden', 'true');
    expect((screen.getByTestId('workspace-underlay') as HTMLElement & { inert: boolean }).inert).toBe(true);
    await waitFor(() => expect(dialog.querySelector('button:not([disabled])')).toHaveFocus());

    fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByTestId('mobile-session-drawer')).not.toBeInTheDocument());
    // Focus restoration is asserted in the real narrow browser surface; the
    // unit environment intentionally keeps the mobile toolbar CSS-hidden.
    expect(screen.getByRole('button', { name: 'Open conversations', hidden: true })).toBe(conversations);
  });

  it('uses a two-column grid when the inspector is hidden', async () => {
    render(WorkspacePreview, { state: 'ready' });

    const grid = screen.getByTestId('runtime-preview').querySelector('.workspace-grid');
    expect(grid).not.toHaveClass('inspector-hidden');
    fireEvent.click(screen.getByRole('button', { name: 'Close workspace inspector' }));
    await waitFor(() => expect(grid).toHaveClass('inspector-hidden'));
    expect(screen.queryByRole('complementary', { name: 'Workspace inspector' })).not.toBeInTheDocument();
  });

  it('renders explicit live timeline data without synthetic artifacts', () => {
    render(WorkspacePreview, {
      state: 'ready',
      artifactInspectorEnabled: false,
      timelineEmptyLabel: 'No messages in this chat yet.',
      timelineItems: [{ kind: 'user-message', id: 'live-1', text: 'Live server message' }]
    });

    expect(screen.getByText('Live server message')).toBeInTheDocument();
    expect(screen.queryByText('Quarterly inventory movement')).not.toBeInTheDocument();
    expect(screen.queryByRole('complementary', { name: 'Workspace inspector' })).not.toBeInTheDocument();
    expect(screen.getByTestId('runtime-preview').querySelector('.workspace-grid')).toHaveClass('inspector-hidden');
  });

  it('distinguishes a real empty live session from fixture timelines and copy', () => {
    render(WorkspacePreview, {
      state: 'empty',
      dataMode: 'live',
      artifactInspectorEnabled: false,
      timelineEmptyLabel: 'No messages in this chat yet.',
      timelineItems: []
    });

    expect(screen.getByText('No messages in this chat yet.')).toBeInTheDocument();
    expect(screen.getByText('This Hermes session has no messages yet. Send a message to begin.')).toBeInTheDocument();
    expect(screen.queryByText('No messages in this synthetic session.')).not.toBeInTheDocument();
    expect(screen.queryByText(/Mocked fixture only/)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Choose an action' })).not.toBeInTheDocument();
  });

  it('uses live recovery copy without claiming an unretained draft is safe', () => {
    render(WorkspacePreview, {
      state: 'retryable-error',
      dataMode: 'live',
      artifactInspectorEnabled: false,
      timelineItems: []
    });

    expect(
      screen.getByText('Reconnect and inspect Hermes history before sending again. No prompt was resent.')
    ).toBeInTheDocument();
    expect(screen.queryByText(/Your draft is safe/)).not.toBeInTheDocument();
  });
});
