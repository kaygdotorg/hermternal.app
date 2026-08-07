import { describe, expect, it, vi } from 'vitest';
import type { BrowserChatOptions } from '$lib/chat/browser-chat';
import type {
  JsonRpcChatTransport,
  JsonRpcConnectionState
} from '$lib/chat/json-rpc-chat';
import {
  PtyTransportError,
  type PtyConnectionState,
  type PtyTransport,
  type PtyTransportEvent
} from '$lib/terminal/pty-transport';
import type {
  CurrentSessionTerminalEvent,
  CurrentSessionTerminalState
} from '$lib/terminal/current-session-terminal';
import type { LiveMessage, LiveRestTransport, LiveSession, SessionMessages } from '$lib/transport';
import { LiveWorkspaceSession } from './live-workspace-session';

const SESSION: LiveSession = {
  id: 'session-1',
  source: 'web',
  model: 'Hermes 4',
  title: 'Live session',
  startedAt: 1,
  endedAt: null,
  lastActive: 2,
  isActive: true,
  messageCount: 0,
  toolCallCount: 0,
  inputTokens: 0,
  outputTokens: 0,
  preview: null
};

const SESSION_2: LiveSession = {
  ...SESSION,
  id: 'session-2',
  title: 'Second session',
  isActive: false
};

const SESSION_3: LiveSession = {
  ...SESSION,
  id: 'session-3',
  title: 'Third session',
  isActive: false
};

function sessionMessages(messages: LiveMessage[] = [], sessionId = SESSION.id): SessionMessages {
  return {
    sessionId,
    messages,
    pagination: { limit: 500, offset: 0, returned: messages.length }
  };
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(reason: unknown): void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, resolve, reject };
}

function createRest(): LiveRestTransport {
  return {
    getProviders: vi.fn(),
    getAuthState: vi.fn(),
    listSessions: vi.fn().mockResolvedValue({ sessions: [SESSION], total: 1, limit: 100, offset: 0 }),
    getSessions: vi.fn(),
    getSession: vi.fn().mockResolvedValue(SESSION),
    getSessionMessages: vi.fn().mockResolvedValue(sessionMessages())
  };
}

function createChatHarness(): {
  readonly createChat: ReturnType<typeof vi.fn<(options: BrowserChatOptions) => JsonRpcChatTransport>>;
  readonly transport: JsonRpcChatTransport;
  readonly optionsHistory: BrowserChatOptions[];
} {
  const state: JsonRpcConnectionState = { status: 'ready', generation: 1 };
  const optionsHistory: BrowserChatOptions[] = [];
  const transport: JsonRpcChatTransport = {
    get state() {
      return state;
    },
    selectedSessionId: SESSION.id,
    connect: vi.fn().mockResolvedValue(undefined),
    reconnect: vi.fn().mockResolvedValue(undefined),
    createSession: vi.fn().mockResolvedValue({
      sessionId: 'draft-session',
      storedSessionId: 'stored-draft',
      model: 'Hermes 4'
    }),
    restore: vi.fn().mockResolvedValue(undefined),
    close: vi.fn(),
    sendPrompt: vi.fn(),
    interrupt: vi.fn().mockResolvedValue(undefined),
    respondToApproval: vi.fn().mockResolvedValue(undefined),
    answerClarification: vi.fn().mockResolvedValue(undefined),
    abort: vi.fn(),
    subscribe: vi.fn(() => () => {})
  };
  const createChat = vi.fn((options: BrowserChatOptions) => {
    optionsHistory.push(options);
    return transport;
  });
  return { createChat, transport, optionsHistory };
}

function createPtyHarness(): {
  readonly pty: PtyTransport;
  readonly connect: ReturnType<typeof vi.fn>;
  readonly close: ReturnType<typeof vi.fn>;
  readonly detach: ReturnType<typeof vi.fn>;
  readonly events: string[];
  emit(event: PtyTransportEvent): void;
} {
  const listeners = new Set<(event: PtyTransportEvent) => void>();
  const events: string[] = [];
  let state: PtyConnectionState = {
    status: 'closed',
    generation: 0,
    mode: 'legacy',
    outputMayBeTruncated: false
  };
  const emit = (event: PtyTransportEvent): void => {
    if (event.type === 'state') state = event.state;
    for (const listener of [...listeners]) listener(event);
  };
  const connect = vi.fn(async (input: { readonly sessionId: string }) => {
    events.push(`connect:${input.sessionId}`);
    state = {
      status: 'attached',
      generation: state.generation + 1,
      mode: 'legacy',
      sessionId: input.sessionId,
      outputMayBeTruncated: false
    };
    emit({ type: 'state', state });
  });
  const detach = vi.fn(() => {
    events.push('detach');
    state = { ...state, status: 'detached' };
    emit({ type: 'state', state });
  });
  const close = vi.fn(() => {
    events.push('close');
    state = { ...state, status: 'exited' };
    emit({ type: 'state', state });
  });
  const reconnect = vi.fn(async () => {
    if (state.mode !== 'attach') {
      throw new PtyTransportError('legacy-reattach-prohibited', state.generation);
    }
  });
  const pty: PtyTransport = {
    get state() {
      return state;
    },
    connect,
    reconnect,
    sendInput: vi.fn(),
    resize: vi.fn(),
    detach,
    close,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    }
  };
  return { pty, connect, close, detach, events, emit };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 10; index += 1) await Promise.resolve();
}

async function createInitializedWorkspace(
  rest = createRest(),
  chat = createChatHarness(),
  pty = createPtyHarness()
) {
  const session = new LiveWorkspaceSession({
    rest,
    createChat: chat.createChat,
    createTerminal: () => pty.pty
  });

  // The live route creates these shared resources before REST initialization.
  const coordinator = session.coordinator;
  const terminal = session.terminal;
  await session.initialize();
  return { session, coordinator: coordinator!, terminal: terminal!, chat, pty };
}

describe('LiveWorkspaceSession current-session Terminal integration', () => {
  it('keeps Chat, the selected session, and one PTY owner continuous across mode switches', async () => {
    const { session, coordinator, terminal, chat, pty } = await createInitializedWorkspace();
    const createSession = vi.spyOn(session, 'createSession');

    await coordinator.activate('terminal');
    await coordinator.activate('chat');
    await coordinator.activate('terminal');

    expect(createSession).not.toHaveBeenCalled();
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transport.connect).toHaveBeenCalledTimes(1);
    expect(chat.transport.restore).not.toHaveBeenCalled();
    expect(pty.connect).toHaveBeenCalledTimes(1);
    expect(coordinator.activeSessionId).toBe(SESSION.id);
    expect(coordinator.state.terminalSessionId).toBe(SESSION.id);
    expect(session.current.activeSessionId).toBe(SESSION.id);
    expect(session.current.mode).toBe('terminal');
    expect(terminal.state.sessionId).toBe(SESSION.id);
  });

  it('detaches the old PTY before publishing a replacement session snapshot', async () => {
    const rest = createRest();
    vi.mocked(rest.getSession).mockResolvedValue(SESSION_2);
    vi.mocked(rest.getSessionMessages).mockImplementation(async (sessionId) => sessionMessages([], sessionId));
    const { session, coordinator, pty } = await createInitializedWorkspace(rest);
    await coordinator.activate('terminal');
    pty.events.length = 0;

    const unsubscribe = session.subscribe((snapshot) => {
      if (snapshot.activeSessionId === SESSION_2.id) pty.events.push('snapshot:session-2');
    });
    await session.selectSession(SESSION_2.id);
    unsubscribe();

    expect(pty.events.indexOf('detach')).toBeGreaterThanOrEqual(0);
    expect(pty.events.indexOf('snapshot:session-2')).toBeGreaterThanOrEqual(0);
    expect(pty.events.indexOf('detach')).toBeLessThan(pty.events.indexOf('snapshot:session-2'));
    expect(session.current).toMatchObject({
      activeSessionId: SESSION_2.id,
      state: 'empty',
      coordinator: { activeSessionId: SESSION_2.id, terminalStatus: 'attached' }
    });
  });

  it('does not let an old Chat callback poison the coordinator fallback during replacement', async () => {
    const rest = createRest();
    const sessionLookup = deferred<LiveSession>();
    vi.mocked(rest.getSession).mockImplementationOnce(() => sessionLookup.promise);
    const chat = createChatHarness();
    const { session } = await createInitializedWorkspace(rest, chat);
    const oldChatOptions = chat.optionsHistory[0];
    if (!oldChatOptions) throw new Error('initial Chat options are missing');

    const replacement = session.selectSession(SESSION_2.id);
    await flush();
    oldChatOptions.onStateChange?.({ status: 'ready', generation: 99 });

    expect(session.coordinator?.state.chatStatus).toBe('offline');

    sessionLookup.resolve(SESSION_2);
    await replacement;
  });

  it('reconciles a PTY failure into coordinator state before the next Terminal action', async () => {
    const { session, coordinator, pty } = await createInitializedWorkspace();
    await coordinator.activate('terminal');

    pty.emit({
      type: 'state',
      state: {
        status: 'failed',
        generation: 2,
        mode: 'legacy',
        sessionId: SESSION.id,
        closeCode: 1011,
        closeClassification: 'backend-failure',
        outputMayBeTruncated: false
      }
    });

    expect(session.current.coordinator).toMatchObject({
      status: 'terminal-attach-failed',
      terminalStatus: 'failed',
      lastError: 'terminal-attach-failed'
    });
    expect(session.current.coordinator).not.toHaveProperty('terminalSessionId');
    expect(session.current.terminal).toMatchObject({ status: 'failed', sessionId: SESSION.id });

    await coordinator.activate('terminal');
    expect(session.current.coordinator).toMatchObject({
      status: 'active',
      terminalStatus: 'attached',
      terminalSessionId: SESSION.id
    });
  });

  it('reconciles an unexpected PTY exit into a failed coordinator lease', async () => {
    const { session, coordinator, pty } = await createInitializedWorkspace();
    await coordinator.activate('terminal');

    pty.emit({
      type: 'state',
      state: {
        status: 'exited',
        generation: 2,
        mode: 'legacy',
        sessionId: SESSION.id,
        outputMayBeTruncated: false
      }
    });

    expect(session.current.coordinator).toMatchObject({
      status: 'terminal-attach-failed',
      terminalStatus: 'failed',
      lastError: 'terminal-attach-failed'
    });
    expect(session.current.coordinator).not.toHaveProperty('terminalSessionId');
  });

  it('rejects late deferred Terminal state from session B after session C owns the coordinator', async () => {
    const rest = createRest();
    vi.mocked(rest.getSession).mockImplementation(async (sessionId) =>
      sessionId === SESSION_2.id ? SESSION_2 : SESSION_3
    );
    vi.mocked(rest.getSessionMessages).mockImplementation(async (sessionId) => sessionMessages([], sessionId));
    const { session, coordinator, pty } = await createInitializedWorkspace(rest);
    await coordinator.activate('terminal');

    const deferredConnect = deferred<void>();
    const originalConnect = pty.connect.getMockImplementation() as
      | ((input: { readonly sessionId: string }) => Promise<void>)
      | undefined;
    if (!originalConnect) throw new Error('PTY connect implementation is missing');
    pty.connect.mockImplementation(async (input) => {
      if (input.sessionId === SESSION_2.id) await deferredConnect.promise;
      return originalConnect(input);
    });

    const staleStates: string[] = [];
    let sessionCVisible = false;
    const unsubscribe = session.subscribe((snapshot) => {
      if (snapshot.activeSessionId === SESSION_3.id) sessionCVisible = true;
      if (sessionCVisible && snapshot.coordinator?.activeSessionId === SESSION_2.id) {
        staleStates.push('session-2');
      }
    });

    const sessionB = session.selectSession(SESSION_2.id);
    await flush();
    expect(pty.connect).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId: SESSION_2.id }),
      expect.any(AbortSignal)
    );

    await session.selectSession(SESSION_3.id);
    expect(session.current.activeSessionId).toBe(SESSION_3.id);
    expect(session.current.coordinator?.activeSessionId).toBe(SESSION_3.id);

    deferredConnect.resolve();
    await sessionB;
    unsubscribe();

    expect(staleStates).toEqual([]);
    expect(session.current.activeSessionId).toBe(SESSION_3.id);
    expect(session.current.coordinator?.activeSessionId).toBe(SESSION_3.id);
  });

  it('forwards one raw PTY byte view without adding bytes to workspace state', async () => {
    const { session, coordinator, terminal, pty } = await createInitializedWorkspace();
    await coordinator.activate('terminal');
    const events: CurrentSessionTerminalEvent[] = [];
    const unsubscribe = terminal.subscribe((event) => events.push(event));

    const bytes = new Uint8Array([0xff, 0x00, 0x80]);
    pty.emit({
      type: 'bytes',
      generation: 1,
      bytes,
      outputMayBeTruncated: false
    });

    const byteEvent = events.find(
      (event): event is Extract<CurrentSessionTerminalEvent, { type: 'bytes' }> => event.type === 'bytes'
    );
    expect(byteEvent?.bytes).toBe(bytes);
    expect(JSON.stringify(session.current)).not.toContain('255');
    expect(JSON.stringify(session.current)).not.toContain('128');
    unsubscribe();
  });

  it('keeps Terminal auth and origin failures sanitized in the live snapshot', async () => {
    const { session, coordinator, pty } = await createInitializedWorkspace();
    await coordinator.activate('terminal');

    const authState: CurrentSessionTerminalState = {
      status: 'failed',
      generation: 2,
      sessionId: SESSION.id,
      closeCode: 4401,
      closeClassification: 'authentication-rejected',
      outputMayBeTruncated: false,
      explicitlyClosed: false,
      reconnectSupported: false,
      failure: 'authentication-required'
    };
    pty.emit({
      type: 'state',
      state: {
        status: 'failed',
        generation: 2,
        mode: 'legacy',
        sessionId: SESSION.id,
        closeCode: 4401,
        closeClassification: 'authentication-rejected',
        outputMayBeTruncated: false
      }
    });
    expect(session.current.terminal).toEqual(authState);
    expect(JSON.stringify(session.current)).not.toContain('ticket');

    pty.emit({
      type: 'state',
      state: {
        status: 'failed',
        generation: 3,
        mode: 'legacy',
        sessionId: SESSION.id,
        closeCode: 4403,
        closeClassification: 'host-or-origin-rejected',
        outputMayBeTruncated: false
      }
    });
    expect(session.current.terminal).toMatchObject({
      closeCode: 4403,
      closeClassification: 'host-or-origin-rejected',
      failure: 'incompatible-origin'
    });
  });

  it('reattaches after an explicit Terminal close without replacing Chat', async () => {
    const { session, coordinator, chat, pty } = await createInitializedWorkspace();
    await coordinator.activate('terminal');

    session.closeTerminal();
    expect(pty.close).toHaveBeenCalledTimes(1);
    expect(coordinator.state.terminalStatus).toBe('detached');
    expect(coordinator.state).not.toHaveProperty('terminalSessionId');
    await coordinator.activate('terminal');

    expect(pty.connect).toHaveBeenCalledTimes(2);
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transport.close).not.toHaveBeenCalled();
    expect(session.current.terminal).toMatchObject({
      status: 'attached',
      sessionId: SESSION.id,
      explicitlyClosed: false
    });
  });

  it('disposes Chat and the PTY exactly once', async () => {
    const { session, coordinator, chat, pty } = await createInitializedWorkspace();
    await coordinator.activate('terminal');

    session.dispose();
    session.dispose();

    expect(chat.transport.close).toHaveBeenCalledTimes(1);
    expect(pty.detach).toHaveBeenCalledTimes(1);
    expect(pty.close).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('loading');
  });
});
