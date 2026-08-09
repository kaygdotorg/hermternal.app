import { describe, expect, it, vi } from 'vitest';
import type { BrowserChatOptions } from '$lib/chat/browser-chat';
import type {
  JsonRpcChatRequest,
  JsonRpcChatTransport,
  JsonRpcCompletionEvent,
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
    promoteSession: vi.fn(),
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

  it('keeps a fresh draft Chat-only until its first durable promotion', async () => {
    const rest = createRest();
    vi.mocked(rest.listSessions).mockResolvedValue({ sessions: [], total: 0, limit: 100, offset: 0 });
    const chat = createChatHarness();
    const pty = createPtyHarness();
    const completion = deferred<JsonRpcCompletionEvent>();
    const request: JsonRpcChatRequest = {
      id: 'request-1',
      completion: completion.promise,
      state: { id: 'request-1', status: 'streaming' },
      abort: vi.fn()
    };
    vi.mocked(chat.transport.sendPrompt).mockReturnValue(request);
    const session = new LiveWorkspaceSession({
      rest,
      createChat: chat.createChat,
      createTerminal: () => pty.pty
    });
    const coordinator = session.coordinator;
    if (!coordinator) throw new Error('coordinator composition is missing');

    await session.initialize();
    await session.createSession();
    await session.activateMode('terminal');

    expect(session.current.activeSessionId).toBe('stored-draft');
    expect(coordinator.activeSessionId).toBeUndefined();
    expect(chat.transport.restore).not.toHaveBeenCalled();
    expect(pty.connect).not.toHaveBeenCalled();

    session.sendPrompt('first persisted turn');
    expect(chat.transport.sendPrompt).toHaveBeenCalledWith('first persisted turn');
    const completeEvent: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: request.id,
      payload: { status: 'ok' }
    };
    chat.optionsHistory[0]?.onEvent?.(completeEvent);
    completion.resolve(completeEvent);
    await flush();

    expect(chat.transport.promoteSession).toHaveBeenCalledWith('stored-draft');
    expect(coordinator.activeSessionId).toBe('stored-draft');
    expect(session.current.coordinator?.activeSessionId).toBe('stored-draft');
  });

  it('waits for renderer readiness before mounting the current-session PTY', async () => {
    const rest = createRest();
    const chat = createChatHarness();
    const pty = createPtyHarness();
    const session = new LiveWorkspaceSession({
      rest,
      createChat: chat.createChat,
      createTerminal: () => pty.pty
    });
    const terminal = session.terminal;
    const coordinator = session.coordinator;
    if (!terminal || !coordinator) throw new Error('terminal composition is missing');
    terminal.setRendererReady(false);
    await session.initialize();

    const activation = coordinator.activate('terminal');
    await flush();

    expect(pty.connect).not.toHaveBeenCalled();
    expect(session.current.mode).toBe('terminal');

    terminal.setRendererReady(true);
    await activation;

    expect(pty.connect).toHaveBeenCalledTimes(1);
    expect(session.current.terminal).toMatchObject({ status: 'attached', sessionId: SESSION.id });
  });

  it('fails closed when the terminal adapter cannot be constructed', async () => {
    const rest = createRest();
    const chat = createChatHarness();
    const createTerminal = vi.fn((): PtyTransport => {
      throw new Error('ticket=secret credential=secret');
    });
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat, createTerminal });

    await session.initialize();
    await session.activateMode('terminal');

    expect(createTerminal).toHaveBeenCalledTimes(1);
    expect(session.current.coordinator).toBeUndefined();
    expect(session.current.terminal).toEqual({
      status: 'failed',
      generation: 0,
      outputMayBeTruncated: false,
      explicitlyClosed: false,
      reconnectSupported: false
    });
    expect(session.coordinator).toBeUndefined();
    expect(session.terminal).toBeUndefined();
    expect(createTerminal).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(session.current)).not.toContain('ticket=secret');
    expect(JSON.stringify(session.current)).not.toContain('credential=secret');

    // Auth projection invalidation remounts the same root owner. Preserve the
    // bounded failure and never retry adapter setup inside that owner lifecycle.
    session.invalidate();
    expect(session.current.terminal).toMatchObject({ status: 'failed', generation: 0 });
    expect(session.terminal).toBeUndefined();
    expect(createTerminal).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(session.current)).not.toContain('ticket=secret');
    expect(JSON.stringify(session.current)).not.toContain('credential=secret');
  });

  it('preserves a getter-latched sanitized PTY factory failure through initialize', async () => {
    const rest = createRest();
    const chat = createChatHarness();
    const createTerminal = vi.fn((): PtyTransport => {
      throw new Error('ticket=secret credential=secret');
    });
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat, createTerminal });

    expect(session.coordinator).toBeUndefined();
    expect(session.current.terminal).toMatchObject({ status: 'failed', generation: 0 });

    await session.initialize();

    expect(createTerminal).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('empty');
    expect(session.current.terminal).toEqual({
      status: 'failed',
      generation: 0,
      outputMayBeTruncated: false,
      explicitlyClosed: false,
      reconnectSupported: false
    });
    expect(session.coordinator).toBeUndefined();
    expect(session.terminal).toBeUndefined();
    expect(createTerminal).toHaveBeenCalledTimes(1);

    await session.activateMode('terminal');
    expect(session.current).toMatchObject({
      mode: 'terminal',
      terminal: { status: 'failed', generation: 0 }
    });
    await session.activateMode('chat');
    expect(session.current.mode).toBe('chat');

    expect(JSON.stringify(session.current)).not.toContain('ticket=secret');
    expect(JSON.stringify(session.current)).not.toContain('credential=secret');
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

  it('reconciles a PTY failure through the current coordinator settlement', async () => {
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
      status: 'idle',
      mode: 'terminal',
      terminalStatus: 'detached'
    });
    expect(session.current.coordinator).not.toHaveProperty('terminalSessionId');
    expect(session.current.terminal).toMatchObject({ status: 'failed', sessionId: SESSION.id });
  });

  it('reconciles an unexpected PTY exit through the current coordinator settlement', async () => {
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
      status: 'idle',
      mode: 'terminal',
      terminalStatus: 'detached'
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
    const staleTerminalStates: string[] = [];
    let sessionCVisible = false;
    const unsubscribe = session.subscribe((snapshot) => {
      if (snapshot.activeSessionId === SESSION_3.id) sessionCVisible = true;
      if (sessionCVisible && snapshot.coordinator?.activeSessionId === SESSION_2.id) {
        staleStates.push('session-2');
      }
      if (sessionCVisible && snapshot.terminal?.sessionId === SESSION_2.id) {
        staleTerminalStates.push('session-2');
      }
    });

    const sessionB = session.selectSession(SESSION_2.id);
    await flush();
    expect(pty.connect).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId: SESSION_2.id }),
      expect.any(AbortSignal)
    );

    const sessionC = session.selectSession(SESSION_3.id);
    await flush();
    expect(session.current.activeSessionId).toBe(SESSION_3.id);

    // The shared adapter serializes C behind the quarantined B call. Releasing B
    // must not let its late state publish after the replacement becomes visible.
    deferredConnect.resolve();
    await Promise.all([sessionB, sessionC]);
    unsubscribe();

    expect(staleStates).toEqual([]);
    expect(staleTerminalStates).toEqual([]);
    expect(session.current.activeSessionId).toBe(SESSION_3.id);
    expect(session.current.coordinator?.activeSessionId).toBe(SESSION_3.id);
  });

  it('rejects a late B Terminal publication after Chat mode and C visibility, and closes B', async () => {
    const rest = createRest();
    vi.mocked(rest.getSession).mockImplementation(async (sessionId) =>
      sessionId === SESSION_2.id ? SESSION_2 : SESSION_3
    );
    vi.mocked(rest.getSessionMessages).mockImplementation(async (sessionId) => sessionMessages([], sessionId));
    const { session, coordinator, pty } = await createInitializedWorkspace(rest);
    await coordinator.activate('terminal');
    await coordinator.activate('chat');

    const deferredConnect = deferred<void>();
    const originalConnect = pty.connect.getMockImplementation() as
      | ((input: { readonly sessionId: string }) => Promise<void>)
      | undefined;
    if (!originalConnect) throw new Error('PTY connect implementation is missing');
    pty.connect.mockImplementation(async (input) => {
      if (input.sessionId === SESSION_2.id) await deferredConnect.promise;
      return originalConnect(input);
    });

    const staleTerminalStates: string[] = [];
    let sessionCVisible = false;
    const unsubscribe = session.subscribe((snapshot) => {
      if (snapshot.activeSessionId === SESSION_3.id) sessionCVisible = true;
      if (sessionCVisible && snapshot.terminal?.sessionId === SESSION_2.id) {
        staleTerminalStates.push('session-2');
      }
    });

    await session.selectSession(SESSION_2.id);
    const staleTerminalAttach = coordinator.activate('terminal');
    await flush();
    expect(pty.connect).toHaveBeenCalledWith(
      expect.objectContaining({ sessionId: SESSION_2.id }),
      expect.any(AbortSignal)
    );

    await coordinator.activate('chat');
    pty.events.length = 0;
    await session.selectSession(SESSION_3.id);
    expect(sessionCVisible).toBe(true);
    expect(session.current.activeSessionId).toBe(SESSION_3.id);
    expect(session.current.coordinator?.activeSessionId).toBe(SESSION_3.id);

    deferredConnect.resolve();
    await staleTerminalAttach;
    unsubscribe();

    expect(staleTerminalStates).toEqual([]);
    expect(session.current.activeSessionId).toBe(SESSION_3.id);
    expect(session.current.coordinator?.activeSessionId).toBe(SESSION_3.id);
    expect(session.current.terminal?.sessionId).not.toBe(SESSION_2.id);
    expect(session.terminal?.state.status).toBe('detached');
    expect(session.terminal?.state.sessionId).toBeUndefined();
    // The bridge quarantines the late adapter completion behind one owned cleanup.
    expect(pty.events.filter((event) => event === 'detach')).toEqual(['detach']);
    expect(pty.pty.state.status).toBe('detached');
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

  it('publishes explicit detach without closing or replacing Chat', async () => {
    const { session, coordinator, chat, pty } = await createInitializedWorkspace();
    await coordinator.activate('terminal');

    session.detachTerminal();

    expect(pty.detach).toHaveBeenCalledTimes(1);
    expect(pty.close).not.toHaveBeenCalled();
    expect(chat.transport.close).not.toHaveBeenCalled();
    expect(session.current.terminal).toMatchObject({
      status: 'exited',
      sessionId: SESSION.id,
      explicitlyClosed: false
    });
    expect(session.current.coordinator).toMatchObject({ terminalStatus: 'detached' });
    expect(session.current.coordinator).not.toHaveProperty('terminalSessionId');
  });

  it('publishes explicit close without replacing Chat or starting another PTY', async () => {
    const { session, coordinator, chat, pty } = await createInitializedWorkspace();
    await coordinator.activate('terminal');

    session.closeTerminal();

    expect(pty.close).toHaveBeenCalledTimes(1);
    expect(pty.connect).toHaveBeenCalledTimes(1);
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transport.close).not.toHaveBeenCalled();
    expect(session.current.terminal).toMatchObject({
      status: 'closed',
      explicitlyClosed: true
    });
  });

  it('revokes publication and resource ownership before synchronous invalidation callbacks', async () => {
    const rest = createRest();
    const chat = createChatHarness();
    const pty = createPtyHarness();
    const createTerminal = vi.fn(() => pty.pty);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat, createTerminal });
    expect(session.coordinator).toBeDefined();
    await session.initialize();
    const oldChatOptions = chat.optionsHistory[0];
    if (!oldChatOptions) throw new Error('initial Chat options are missing');
    const publishedStates: string[] = [];
    const unsubscribe = session.subscribe((snapshot) => publishedStates.push(snapshot.state));
    publishedStates.length = 0;
    let reentrantCoordinator = session.coordinator;
    let reentrantTerminal = session.terminal;
    chat.transport.close = vi.fn(() => {
      oldChatOptions.onStateChange?.({ status: 'failed', generation: 99 });
      reentrantCoordinator = session.coordinator;
      reentrantTerminal = session.terminal;
    });

    session.invalidate();
    unsubscribe();

    expect(chat.transport.close).toHaveBeenCalledTimes(1);
    expect(createTerminal).toHaveBeenCalledTimes(1);
    expect(reentrantCoordinator).toBeUndefined();
    expect(reentrantTerminal).toBeUndefined();
    expect(publishedStates).toEqual(['loading']);
    expect(session.current).toEqual({
      state: 'loading',
      sessions: [],
      title: 'Hermes',
      model: 'Hermes',
      timeline: []
    });
  });

  it('disposes Chat and the PTY exactly once', async () => {
    const { session, coordinator, chat, pty } = await createInitializedWorkspace();
    await coordinator.activate('terminal');

    session.dispose();
    session.dispose();

    expect(chat.transport.close).toHaveBeenCalledTimes(1);
    expect(pty.events.filter((event) => event === 'detach' || event === 'close')).toEqual(['detach']);
    expect(session.current.state).toBe('loading');
  });
});
