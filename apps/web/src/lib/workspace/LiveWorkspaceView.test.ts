import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import type { LiveWorkspaceSession, LiveWorkspaceSnapshot } from './live-workspace-session';
import LiveWorkspaceView from './LiveWorkspaceView.svelte';

const terminalRenderer = vi.hoisted(() => ({
  create: vi.fn(() => ({
    state: 'ready' as const,
    error: null,
    mount: vi.fn().mockResolvedValue(undefined),
    write: vi.fn(),
    resize: vi.fn(),
    focus: vi.fn(),
    dispose: vi.fn()
  }))
}));
vi.mock('$lib/terminal/renderer', () => ({ createTerminalRenderer: terminalRenderer.create }));

function createSession(snapshot: LiveWorkspaceSnapshot, extras: Record<string, unknown> = {}) {
  const unsubscribe = vi.fn();
  let current = snapshot;
  let listener: ((next: Readonly<LiveWorkspaceSnapshot>) => void) | undefined;
  const session = {
    get current() { return current; },
    subscribe: vi.fn((subscriber: (next: Readonly<LiveWorkspaceSnapshot>) => void) => {
      listener = subscriber;
      subscriber(current);
      return unsubscribe;
    }),
    initialize: vi.fn().mockResolvedValue(undefined),
    activateMode: vi.fn().mockResolvedValue(undefined),
    reconnectTerminal: vi.fn().mockResolvedValue(undefined),
    detachTerminal: vi.fn(),
    closeTerminal: vi.fn(),
    createSession: vi.fn().mockResolvedValue(undefined),
    selectSession: vi.fn().mockResolvedValue(undefined),
    sendPrompt: vi.fn(),
    setComposerDraft: vi.fn((draft) => {
      current = { ...current, ...(draft === undefined ? { draft: undefined } : { draft }) };
      listener?.(current);
    }),
    clearComposerDraft: vi.fn(() => {
      current = { ...current, draft: undefined };
      listener?.(current);
    }),
    stop: vi.fn().mockResolvedValue(undefined),
    retryConnection: vi.fn().mockResolvedValue(undefined),
    cancelReconnect: vi.fn(),
    approve: vi.fn().mockResolvedValue(undefined),
    answerClarification: vi.fn().mockResolvedValue(undefined),
    dispose: vi.fn(),
    unsubscribe,
    emitSnapshot(next: LiveWorkspaceSnapshot) {
      current = next;
      listener?.(next);
    },
    ...extras
  };
  return session as unknown as LiveWorkspaceSession & typeof session;
}

function createTerminalBridge() {
  const state = {
    status: 'closed' as const,
    generation: 1,
    outputMayBeTruncated: false,
    explicitlyClosed: false
  };
  const listeners = new Set<(event: { type: 'state'; state: typeof state; lifecycle: object }) => void>();
  let lifecycle = {};
  return {
    state,
    lifecycleIdentity: { binding: undefined, nativeTransportGeneration: 1 },
    subscribe: vi.fn((listener: (event: { type: 'state'; state: typeof state; lifecycle: object }) => void) => {
      listeners.add(listener);
      listener({ type: 'state', state, lifecycle });
      return () => listeners.delete(listener);
    }),
    emitLifecycle(_binding: object, _generation: number) {
      lifecycle = {};
      for (const listener of listeners) listener({ type: 'state', state, lifecycle });
      return lifecycle;
    },
    sendInput: vi.fn(),
    resize: vi.fn(),
    detach: vi.fn(),
    setRendererReady: vi.fn()
  };
}

describe('LiveWorkspaceView', () => {
  it('initializes the controller, sends user input, and releases only its subscription', async () => {
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
    expect(session.unsubscribe).toHaveBeenCalledTimes(1);
    expect(session.dispose).not.toHaveBeenCalled();
  });

  it('restores the root-owned draft after the authenticated view remounts', async () => {
    const session = createSession({
      state: 'ready',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: []
    });
    const first = render(LiveWorkspaceView, { session });
    const editor = screen.getByRole('textbox', { name: 'Message Hermes' });
    fireEvent.input(editor, { target: { value: 'Keep this across auth recovery' } });
    await waitFor(() =>
      expect(session.setComposerDraft).toHaveBeenCalledWith({
        text: 'Keep this across auth recovery',
        attachments: []
      })
    );

    first.unmount();
    render(LiveWorkspaceView, { session });

    expect(screen.getByRole('textbox', { name: 'Message Hermes' })).toHaveValue(
      'Keep this across auth recovery'
    );
  });

  it('clears the root-owned draft when Terminal is explicitly closed or detached', async () => {
    const terminal = createTerminalBridge();
    const session = createSession({
      state: 'ready',
      mode: 'terminal',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: [],
      draft: { text: 'discard on terminal teardown', attachments: [] }
    }, { terminal });
    render(LiveWorkspaceView, { session });

    await fireEvent.click(screen.getByRole('button', { name: 'Close terminal' }));

    expect(session.closeTerminal).toHaveBeenCalledTimes(1);
    expect(session.clearComposerDraft).toHaveBeenCalledTimes(1);
  });

  it('forwards the bridge-stamped active lifecycle through the rendered 4401 action', async () => {
    const terminal = createTerminalBridge();
    const binding = {};
    const lease = {};
    const registerTerminalLifecycle = vi.fn(() => lease);
    const onReturnToSignIn = vi.fn();
    const session = createSession({
      state: 'permanent-error',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: [],
      terminal: { status: 'failed', generation: 7, outputMayBeTruncated: false, explicitlyClosed: false, failure: 'authentication-required' },
      permanentFailure: { reason: 'authentication-required', closeCode: 4401, closeClassification: 'authentication-rejected' }
    }, { terminal });
    render(LiveWorkspaceView, {
      session,
      registerTerminalLifecycle,
      onReturnToSignIn,
      onTerminalAuthenticationFailure: onReturnToSignIn
    });
    const stamp = terminal.emitLifecycle(binding, 7);

    await fireEvent.click(screen.getByRole('button', { name: 'Back to sessions' }));
    expect(registerTerminalLifecycle).toHaveBeenLastCalledWith(terminal, stamp);
    expect(onReturnToSignIn).toHaveBeenCalledWith(lease);
  });

  it('routes the Terminal mode action without creating or replacing the current session', async () => {
    const session = createSession({
      state: 'ready',
      mode: 'chat',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: []
    }, {
      coordinator: { state: { activeSessionId: 'session-1' } }
    });
    render(LiveWorkspaceView, { session });

    await fireEvent.click(screen.getByRole('button', { name: 'Open terminal mode' }));

    expect(session.activateMode).toHaveBeenCalledWith('terminal');
    expect(session.createSession).not.toHaveBeenCalled();
    expect(session.selectSession).not.toHaveBeenCalled();
  });

  it('keeps both Terminal controls natively disabled after a factory failure on an unpromoted draft', async () => {
    const session = createSession({
      state: 'empty',
      mode: 'chat',
      sessions: [{ id: 'stored-draft', title: 'New chat', group: 'recent' }],
      activeSessionId: 'stored-draft',
      title: 'New chat',
      model: 'Hermes 4',
      timeline: [],
      terminal: {
        status: 'failed',
        generation: 0,
        outputMayBeTruncated: false,
        explicitlyClosed: false,
        reconnectSupported: false
      }
    });
    render(LiveWorkspaceView, { session });

    const terminalControls = document.querySelectorAll<HTMLButtonElement>(
      'button[aria-label="Terminal unavailable until the first message is saved"]'
    );
    // WorkspacePreview mounts distinct desktop and narrow/mobile controls. Both
    // must use native disabled semantics rather than accepting a silent request.
    expect(terminalControls).toHaveLength(2);
    expect(screen.queryByTestId('terminal-adapter-failure')).not.toBeInTheDocument();
    for (const control of terminalControls) {
      expect(control).toBeDisabled();
      expect(control).toHaveAttribute(
        'title',
        'Terminal is available after the first message is saved.'
      );
      await fireEvent.click(control);
    }
    expect(session.activateMode).not.toHaveBeenCalled();
  });

  it('removes the complete Chat underlay from focus and accessibility while Terminal is active', () => {
    const terminal = createTerminalBridge();
    const session = createSession({
      state: 'ready',
      mode: 'terminal',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: []
    }, { terminal });
    render(LiveWorkspaceView, { session });

    const underlay = screen.getByTestId('workspace-underlay');
    expect((underlay as HTMLElement & { inert: boolean }).inert).toBe(true);
    expect(underlay).toHaveAttribute('aria-hidden', 'true');
    expect(underlay.querySelector('[aria-label="Message Hermes"]')).toBeInTheDocument();
    expect(underlay).not.toContainElement(screen.getByTestId('mobile-mode-selector'));
    expect(screen.getByTestId('mobile-mode-selector').querySelector('button:first-child')).toHaveAttribute('aria-pressed', 'false');
  });

  it('presents a sanitized PTY setup failure with an accessible Chat escape', async () => {
    const failedSnapshot: LiveWorkspaceSnapshot = {
      state: 'ready',
      mode: 'terminal',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: [],
      terminal: {
        status: 'failed',
        generation: 0,
        outputMayBeTruncated: false,
        explicitlyClosed: false,
        reconnectSupported: false
      }
    };
    const session = createSession(failedSnapshot, {
      coordinator: { state: { activeSessionId: 'session-1' } }
    });
    render(LiveWorkspaceView, { session });
    await waitFor(() => expect(session.subscribe).toHaveBeenCalledTimes(1));
    session.activateMode.mockImplementation(async (mode) => {
      session.emitSnapshot({ ...failedSnapshot, mode });
    });

    const failure = screen.getByTestId('terminal-adapter-failure');
    expect(failure).toHaveAttribute('role', 'alert');
    expect(failure).toHaveTextContent('Terminal setup failed');
    expect(failure).not.toHaveTextContent('ticket=');
    expect(failure).not.toHaveTextContent('credential=');

    await fireEvent.click(screen.getByRole('button', { name: 'Return to Chat' }));
    await waitFor(() => expect(session.activateMode).toHaveBeenCalledWith('chat'));
    await waitFor(() => expect(screen.getByTestId('terminal-appearance-scope')).not.toHaveClass('active'));
    expect(document.activeElement).toBe(screen.getByTestId('workspace-underlay'));
  });

  it('hides Terminal before releasing and focusing the Chat handoff target', async () => {
    const terminal = createTerminalBridge();
    const terminalSnapshot: LiveWorkspaceSnapshot = {
      state: 'ready',
      mode: 'terminal',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: []
    };
    const session = createSession(terminalSnapshot, { terminal });
    render(LiveWorkspaceView, { session });
    await waitFor(() => expect(session.subscribe).toHaveBeenCalledTimes(1));
    const layer = screen.getByTestId('terminal-appearance-scope');
    const underlay = screen.getByTestId('workspace-underlay');
    const originalGetClientRects = HTMLElement.prototype.getClientRects;
    const getClientRects = vi
      .spyOn(HTMLElement.prototype, 'getClientRects')
      .mockImplementation(function (this: HTMLElement) {
        if (this.matches('[data-testid="mobile-mode-selector"] button:first-child')) {
          const rect = new DOMRect(0, 0, 44, 44);
          return {
            0: rect,
            length: 1,
            item: () => rect,
            [Symbol.iterator]: () => [rect][Symbol.iterator]()
          } as unknown as DOMRectList;
        }
        return originalGetClientRects.call(this);
      });
    const originalFocus = HTMLElement.prototype.focus;
    const focusedChatModes: HTMLElement[] = [];
    const focus = vi.spyOn(HTMLElement.prototype, 'focus').mockImplementation(function (
      this: HTMLElement,
      options?: FocusOptions
    ) {
      if (this.matches('[data-testid="mobile-mode-selector"] button:first-child')) {
        // A focusable layout box may still be covered by Terminal. The handoff
        // must hide the layer before focus so desktop and narrow paths agree.
        expect(layer).not.toHaveClass('active');
        focusedChatModes.push(this);
      }
      originalFocus.call(this, options);
    });
    session.activateMode.mockImplementation(async (mode) => {
      session.emitSnapshot({ ...terminalSnapshot, mode });
    });

    try {
      await fireEvent.click(screen.getByRole('button', { name: 'Return to Chat mode' }));
      await waitFor(() => expect(underlay).not.toHaveAttribute('aria-hidden'));

      // The visible narrow selector is outside the inert Chat underlay. Prove the
      // handoff focuses it while Terminal is still painted, then hides Terminal.
      await waitFor(() => expect(focusedChatModes).toHaveLength(1));
      expect(document.activeElement).toBe(focusedChatModes[0]);
      await waitFor(() => expect(layer).not.toHaveClass('active'));
      expect(underlay).not.toHaveAttribute('aria-hidden');
    } finally {
      focus.mockRestore();
      getClientRects.mockRestore();
    }
  });

  it.each([
    ['light', 'rgb(243, 245, 248)'],
    ['dark', 'rgb(13, 17, 23)']
  ] as const)('gives Terminal the opaque %s appearance aliases used by Chat', (appearance, expectedCanvas) => {
    const terminal = createTerminalBridge();
    const session = createSession({
      state: 'ready',
      mode: 'terminal',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: []
    }, { terminal });
    render(LiveWorkspaceView, { session, appearance });

    const scope = screen.getByTestId('terminal-appearance-scope');
    expect(scope).toHaveAttribute('data-appearance', appearance);
    expect(getComputedStyle(scope).backgroundColor).toBe(expectedCanvas);
    expect(getComputedStyle(scope).getPropertyValue('--canvas').trim()).toBe(appearance === 'dark' ? '#0d1117' : '#f3f5f8');
    expect(getComputedStyle(scope).backgroundColor).not.toBe('rgba(0, 0, 0, 0)');
  });

  it('reacts to explicit appearance changes after mount', async () => {
    const terminal = createTerminalBridge();
    const session = createSession({
      state: 'ready',
      mode: 'terminal',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: []
    }, { terminal });
    const view = render(LiveWorkspaceView, { session, appearance: 'light' });
    const scope = screen.getByTestId('terminal-appearance-scope');

    expect(scope).toHaveAttribute('data-appearance', 'light');
    await view.rerender({ appearance: 'dark' });
    await waitFor(() => expect(scope).toHaveAttribute('data-appearance', 'dark'));
    expect(getComputedStyle(scope).getPropertyValue('--canvas').trim()).toBe('#0d1117');
  });

  it('uses the initial dark system preference before the first client render', () => {
    const addEventListener = vi.fn();
    const removeEventListener = vi.fn();
    vi.stubGlobal('matchMedia', vi.fn(() => ({
      matches: true,
      media: '(prefers-color-scheme: dark)',
      onchange: null,
      addEventListener,
      removeEventListener,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn()
    })));
    const session = createSession({
      state: 'ready',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: []
    });

    try {
      render(LiveWorkspaceView, { session });
      expect(screen.getByTestId('runtime-preview')).toHaveAttribute('data-appearance', 'dark');
      expect(addEventListener).toHaveBeenCalledWith('change', expect.any(Function));
    } finally {
      vi.unstubAllGlobals();
    }
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

  it('wires live reconnect recovery controls to retry and cancellation', async () => {
    const session = createSession({
      state: 'reconnecting',
      sessions: [{ id: 'session-1', title: 'Live session', group: 'recent' }],
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4',
      timeline: []
    });
    render(LiveWorkspaceView, { session });

    await fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(session.cancelReconnect).toHaveBeenCalledTimes(1);
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
