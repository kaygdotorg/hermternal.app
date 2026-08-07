import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import type { LiveWorkspaceSession, LiveWorkspaceSnapshot } from './live-workspace-session';
import LiveWorkspaceView from './LiveWorkspaceView.svelte';

function createSession(snapshot: LiveWorkspaceSnapshot) {
  const session = {
    current: snapshot,
    subscribe: vi.fn((subscriber: (next: Readonly<LiveWorkspaceSnapshot>) => void) => {
      subscriber(snapshot);
      return vi.fn();
    }),
    initialize: vi.fn().mockResolvedValue(undefined),
    selectSession: vi.fn().mockResolvedValue(undefined),
    sendPrompt: vi.fn(),
    stop: vi.fn().mockResolvedValue(undefined),
    retryConnection: vi.fn().mockResolvedValue(undefined),
    approve: vi.fn().mockResolvedValue(undefined),
    answerClarification: vi.fn().mockResolvedValue(undefined),
    dispose: vi.fn()
  };
  return session as unknown as LiveWorkspaceSession & typeof session;
}

describe('LiveWorkspaceView', () => {
  it('initializes the controller, sends user input, and disposes local state', async () => {
    const session = createSession({
      state: 'ready',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: []
    });
    const view = render(LiveWorkspaceView, { session });

    await waitFor(() => expect(session.initialize).toHaveBeenCalledTimes(1));
    const composer = screen.getByRole('textbox', { name: 'Message Hermes' });
    fireEvent.input(composer, { target: { value: 'Send once' } });
    fireEvent.keyDown(composer, { key: 'Enter', metaKey: true });
    await waitFor(() => expect(session.sendPrompt).toHaveBeenCalledWith('Send once'));

    view.unmount();
    expect(session.dispose).toHaveBeenCalledTimes(1);
  });

  it('renders truthful live empty state and disables input without a server session', async () => {
    const session = createSession({
      state: 'empty',
      sessions: [],
      title: 'Hermes',
      model: 'Hermes',
      timeline: []
    });
    render(LiveWorkspaceView, { session });

    expect(screen.getByText('This Hermes session has no messages yet. Send a message to begin.')).toBeInTheDocument();
    expect(screen.queryByText(/Mocked fixture only/)).not.toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Message Hermes' })).toBeDisabled();
  });

  it('returns authentication-required permanent errors to the root auth boundary', async () => {
    const onReturnToSignIn = vi.fn();
    const session = createSession({
      state: 'permanent-error',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: [],
      permanentFailure: {
        reason: 'authentication-required',
        closeCode: 4401,
        closeClassification: 'authentication-rejected'
      }
    });
    render(LiveWorkspaceView, { session, onReturnToSignIn });

    expect(screen.getByText('Sign in again before sending another prompt.')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Back to sessions' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));

    expect(onReturnToSignIn).toHaveBeenCalledTimes(2);
  });

  it('does not route incompatible permanent errors through authentication recovery', async () => {
    const onReturnToSignIn = vi.fn();
    const session = createSession({
      state: 'permanent-error',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: [],
      permanentFailure: {
        reason: 'incompatible',
        closeCode: 4403,
        closeClassification: 'host-or-origin-rejected'
      }
    });
    render(LiveWorkspaceView, { session, onReturnToSignIn });

    expect(screen.getByText('Hermes rejected this origin for chat. Use a reviewed origin before sending another prompt.')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: 'Back to sessions' }));
    await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));

    expect(onReturnToSignIn).not.toHaveBeenCalled();
  });
});
