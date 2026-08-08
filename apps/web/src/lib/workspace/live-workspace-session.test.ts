import { describe, expect, it, vi } from 'vitest';
import { createBrowserChatTransport, type BrowserChatOptions } from '$lib/chat/browser-chat';
import {
  JsonRpcChatError,
  type JsonRpcChatEvent,
  type JsonRpcChatRequest,
  type JsonRpcCompletionEvent,
  type JsonRpcChatTransport,
  type JsonRpcConnectionState,
  type JsonRpcWebSocket
} from '$lib/chat/json-rpc-chat';
import {
  createLiveRestTransport,
  LiveRestError,
  type LiveMessage,
  type LiveRestTransport,
  type LiveSession,
  type SessionMessages
} from '$lib/transport';
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
  messageCount: 1,
  toolCallCount: 0,
  inputTokens: 1,
  outputTokens: 1,
  preview: 'must not enter presentation state'
};

function sessionMessagesFor(sessionId: string, messages: LiveMessage[]): SessionMessages {
  return {
    sessionId,
    messages,
    pagination: { limit: 500, offset: 0, returned: messages.length }
  };
}

function sessionMessages(messages: LiveMessage[]): SessionMessages {
  return sessionMessagesFor(SESSION.id, messages);
}

function rawSessionDetail(session: LiveSession): string {
  return JSON.stringify({
    id: session.id,
    source: session.source,
    model: session.model,
    title: session.title,
    started_at: session.startedAt,
    ended_at: session.endedAt,
    message_count: session.messageCount,
    tool_call_count: session.toolCallCount,
    input_tokens: session.inputTokens,
    output_tokens: session.outputTokens
  });
}

class BrowserChatSocket implements JsonRpcWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number; readonly reason?: string }) => void) | null = null;
  readonly sent: string[] = [];
  onSend: ((data: string) => void) | undefined;

  send(data: string): void {
    this.sent.push(data);
    this.onSend?.(data);
  }

  close(code?: number, reason?: string): void {
    this.onclose?.({ code, reason });
  }

  emitOpen(): void {
    this.onopen?.();
  }

  emitGatewayReady(): void {
    this.onmessage?.({
      data: JSON.stringify({
        jsonrpc: '2.0',
        method: 'event',
        params: {
          type: 'gateway.ready',
          payload: { skin: 'official', change_events: true }
        }
      })
    });
  }

  emitResponse(id: string): void {
    this.onmessage?.({ data: JSON.stringify({ jsonrpc: '2.0', id, result: { restored: true } }) });
  }

  emitEvent(type: string, requestId: string | undefined, payload: Record<string, unknown> = {}): void {
    this.onmessage?.({
      data: JSON.stringify({
        jsonrpc: '2.0',
        method: 'event',
        params: {
          type,
          ...(requestId ? { request_id: requestId } : {}),
          payload
        }
      })
    });
  }

  emitClose(code = 1006, reason = ''): void {
    this.onclose?.({ code, reason });
  }
}

async function waitForSocket(sockets: readonly BrowserChatSocket[]): Promise<BrowserChatSocket> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const socket = sockets[0];
    if (socket?.onopen) return socket;
    await flush();
  }
  throw new Error('browser chat socket was not created');
}

async function createConnectedSocketWorkspace(rest: LiveRestTransport = createRest()) {
  const socket = new BrowserChatSocket();
  let transport: JsonRpcChatTransport | undefined;
  const createChat = vi.fn((options: BrowserChatOptions) => {
    transport = createBrowserChatTransport({
      ...options,
      fetch: async () =>
        new Response('{"ticket":"fresh-ticket-1","ttl_seconds":30}', {
          headers: { 'content-type': 'application/json' }
        }),
      createSocket: () => socket
    });
    return transport;
  });
  const session = new LiveWorkspaceSession({ rest, createChat });
  const initialization = session.initialize();
  const attached = await waitForSocket([socket]);
  attached.emitOpen();
  attached.emitGatewayReady();
  await flush();
  const resumeFrame = JSON.parse(attached.sent[0] ?? '{}') as { id?: string };
  if (!resumeFrame.id) throw new Error('session resume frame was not sent');
  attached.emitResponse(resumeFrame.id);
  await initialization;
  return { session, socket: attached, transport, createChat };
}

function createRest(messages: LiveMessage[] = []): LiveRestTransport {
  return {
    getProviders: vi.fn(),
    getAuthState: vi.fn(),
    listSessions: vi.fn().mockResolvedValue({ sessions: [SESSION], total: 1, limit: 100, offset: 0 }),
    getSessions: vi.fn(),
    getSession: vi.fn().mockResolvedValue(SESSION),
    getSessionMessages: vi.fn().mockResolvedValue(sessionMessages(messages))
  };
}

function createDeferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, resolve, reject };
}

function latestPromptId(socket: BrowserChatSocket): string {
  for (const frame of [...socket.sent].reverse()) {
    const parsed = JSON.parse(frame) as { id?: string; method?: string };
    if (parsed.method === 'prompt.submit' && parsed.id) return parsed.id;
  }
  throw new Error('prompt frame was not sent');
}

async function waitForSocketMethod(
  socket: BrowserChatSocket,
  method: string
): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    for (const frame of socket.sent) {
      const parsed = JSON.parse(frame) as Record<string, unknown>;
      if (parsed.method === method) return parsed;
    }
    await flush();
  }
  throw new Error(`socket method was not sent: ${method}`);
}

function createUnauthorizedChatFactory() {
  const transports: JsonRpcChatTransport[] = [];
  const createChat = vi.fn((options: BrowserChatOptions) => {
    const transport = createBrowserChatTransport({
      ...options,
      fetch: async () => new Response(null, { status: 401 }),
      createSocket: () => {
        throw new Error('unauthorized ticket must not start a WebSocket upgrade');
      }
    });
    transports.push(transport);
    return transport;
  });
  return { createChat, transports };
}

function createReconnectUnauthorizedChatFactory() {
  const sockets: BrowserChatSocket[] = [];
  const transports: JsonRpcChatTransport[] = [];
  let ticketRequests = 0;
  const createChat = vi.fn((options: BrowserChatOptions) => {
    const transport = createBrowserChatTransport({
      ...options,
      fetch: async () => {
        ticketRequests += 1;
        return ticketRequests === 1
          ? new Response('{"ticket":"fresh-ticket-1","ttl_seconds":30}', {
              status: 200,
              headers: { 'content-type': 'application/json' }
            })
          : new Response(null, { status: 401 });
      },
      createSocket: () => {
        const socket = new BrowserChatSocket();
        sockets.push(socket);
        return socket;
      }
    });
    transports.push(transport);
    return transport;
  });
  return { createChat, sockets, transports };
}

function createChatHarness(options: {
  readonly onSendPrompt?: () => void;
  readonly sendPromptError?: unknown;
} = {}) {
  let chatOptions: BrowserChatOptions | undefined;
  let requestNumber = 0;
  let activeRequest:
    | { readonly id: string; readonly deferred: ReturnType<typeof createDeferred<JsonRpcCompletionEvent>> }
    | undefined;
  const pendingRequests = new Map<
    string,
    ReturnType<typeof createDeferred<JsonRpcCompletionEvent>>
  >();
  const sendPrompt = vi.fn((prompt: string): JsonRpcChatRequest => {
    const id = `request-${++requestNumber}`;
    const deferred = createDeferred<JsonRpcCompletionEvent>();
    activeRequest = { id, deferred };
    pendingRequests.set(id, deferred);
    const request: JsonRpcChatRequest = {
      id,
      completion: deferred.promise,
      state: { id, status: 'submitting' },
      abort: vi.fn()
    };
    options.onSendPrompt?.();
    if (options.sendPromptError !== undefined) throw options.sendPromptError;
    return request;
  });
  const transport: JsonRpcChatTransport = {
    state: { status: 'offline', generation: 0 },
    selectedSessionId: SESSION.id,
    connect: vi.fn().mockResolvedValue(undefined),
    reconnect: vi.fn().mockResolvedValue(undefined),
    createSession: vi.fn().mockResolvedValue({
      sessionId: 'live-draft',
      storedSessionId: 'stored-draft',
      model: 'Hermes 4'
    }),
    promoteSession: vi.fn(),
    restore: vi.fn().mockResolvedValue(undefined),
    close: vi.fn(),
    sendPrompt,
    interrupt: vi.fn().mockResolvedValue(undefined),
    respondToApproval: vi.fn().mockResolvedValue(undefined),
    answerClarification: vi.fn().mockResolvedValue(undefined),
    abort: vi.fn(),
    subscribe: vi.fn(() => () => {})
  };
  const createChat = vi.fn((nextOptions: BrowserChatOptions) => {
    chatOptions = nextOptions;
    return transport;
  });

  return {
    createChat,
    transport,
    sendPrompt,
    emit(event: JsonRpcChatEvent) {
      chatOptions?.onEvent?.(event);
    },
    changeState(state: JsonRpcConnectionState) {
      chatOptions?.onStateChange?.(state);
    },
    complete(event: JsonRpcCompletionEvent, requestId?: string) {
      const id = requestId ?? activeRequest?.id;
      if (!id) return;
      pendingRequests.get(id)?.resolve(event);
    },
    reject(error: unknown, requestId?: string) {
      const id = requestId ?? activeRequest?.id;
      if (!id) return;
      pendingRequests.get(id)?.reject(error);
    },
    completeRequest(requestId: string, event: JsonRpcCompletionEvent) {
      pendingRequests.get(requestId)?.resolve(event);
    },
    rejectRequest(requestId: string, error: unknown) {
      pendingRequests.get(requestId)?.reject(error);
    }
  };
}

async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('LiveWorkspaceSession', () => {
  it('creates an official empty draft before enabling its first prompt', async () => {
    const rest = createRest();
    vi.mocked(rest.listSessions).mockResolvedValue({ sessions: [], total: 0, limit: 100, offset: 0 });
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();
    expect(session.current.state).toBe('empty');

    await session.createSession();

    expect(chat.createChat).toHaveBeenCalledWith(expect.not.objectContaining({ selectedSessionId: expect.anything() }));
    expect(chat.transport.connect).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(chat.transport.createSession).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(session.current).toMatchObject({
      state: 'empty',
      activeSessionId: 'stored-draft',
      title: 'Untitled chat',
      model: 'Hermes 4'
    });
    expect(session.current.sessions).toEqual([
      expect.objectContaining({ id: 'stored-draft', title: 'Untitled chat', group: 'recent' })
    ]);
  });

  it('reconnects an unpersisted draft without loading or resuming its future REST identity', async () => {
    const rest = createRest();
    vi.mocked(rest.listSessions).mockResolvedValue({ sessions: [], total: 0, limit: 100, offset: 0 });
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();
    await session.createSession();
    await session.retryConnection();

    expect(chat.transport.reconnect).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(rest.getSessionMessages).not.toHaveBeenCalled();
    expect(chat.transport.promoteSession).not.toHaveBeenCalled();
    expect(session.current.state).toBe('retryable-error');
    session.sendPrompt('must not send a stale live draft');
    expect(chat.sendPrompt).not.toHaveBeenCalled();
  });

  it('promotes a created draft only after its first completion commits server history', async () => {
    const rest = createRest();
    vi.mocked(rest.listSessions).mockResolvedValue({ sessions: [], total: 0, limit: 100, offset: 0 });
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();
    await session.createSession();
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce({
      ...sessionMessages([]),
      sessionId: 'stored-draft'
    });
    session.sendPrompt('first persisted turn');
    chat.emit({ type: 'message.complete', requestId: 'request-1', payload: { status: 'ok' } });
    chat.complete({ type: 'message.complete', requestId: 'request-1', payload: { status: 'ok' } });
    await flush();

    expect(rest.getSessionMessages).toHaveBeenCalledWith(
      'stored-draft',
      { limit: 500, offset: 0 },
      expect.any(AbortSignal)
    );
    expect(chat.transport.promoteSession).toHaveBeenCalledWith('stored-draft');
  });

  it('does not let a replaced draft promote from a stale completion callback', async () => {
    const rest = createRest();
    vi.mocked(rest.listSessions).mockResolvedValue({ sessions: [], total: 0, limit: 100, offset: 0 });
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();
    await session.createSession();
    session.sendPrompt('old draft prompt');
    await session.createSession();
    chat.emit({ type: 'message.complete', requestId: 'request-1', payload: { status: 'ok' } });
    chat.complete({ type: 'message.complete', requestId: 'request-1', payload: { status: 'ok' } });
    await flush();

    expect(chat.transport.promoteSession).not.toHaveBeenCalled();
  });

  it('restores the active server session before enabling chat', async () => {
    const rest = createRest([{ role: 'user', content: 'Server-owned history' }]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();

    expect(rest.listSessions).toHaveBeenCalledWith({ limit: 100, offset: 0 }, expect.any(AbortSignal));
    expect(rest.getSessionMessages).toHaveBeenCalledWith(
      'session-1',
      { limit: 500, offset: 0 },
      expect.any(AbortSignal)
    );
    expect(chat.createChat).toHaveBeenCalledWith(expect.objectContaining({ selectedSessionId: 'session-1' }));
    expect(chat.transport.connect).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(session.current).toMatchObject({
      state: 'ready',
      activeSessionId: 'session-1',
      title: 'Live session',
      model: 'Hermes 4'
    });
    expect(session.current.timeline).toEqual([
      { kind: 'user-message', id: 'session-1:message:0', text: 'Server-owned history' }
    ]);
    expect(JSON.stringify(session.current)).not.toContain('must not enter presentation state');
  });

  it('rejects foreign history before initial restore publishes or creates chat', async () => {
    const rest = createRest([]);
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce(
      sessionMessagesFor('foreign-session', [
        { role: 'user', content: 'Foreign initial prompt' },
        { role: 'assistant', content: 'Foreign initial answer' }
      ])
    );
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    const published: string[] = [];
    session.subscribe((snapshot) => published.push(JSON.stringify(snapshot)));

    await session.initialize();

    expect(session.current).toMatchObject({ state: 'retryable-error' });
    expect(session.current.activeSessionId).toBeUndefined();
    expect(session.current.timeline).toEqual([]);
    expect(chat.createChat).not.toHaveBeenCalled();
    expect(published.every((snapshot) => !snapshot.includes('Foreign initial'))).toBe(true);
  });

  it('retries a pre-identity persisted restore without creating a new session', async () => {
    const rest = createRest([]);
    vi.mocked(rest.getSessionMessages).mockRejectedValueOnce(new Error('synthetic history parse failure'));
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();

    expect(session.current).toMatchObject({ state: 'retryable-error' });
    expect(session.current.activeSessionId).toBeUndefined();
    expect(chat.createChat).not.toHaveBeenCalled();
    expect(JSON.stringify(session.current)).not.toContain('session-1');

    await session.retryConnection();

    expect(rest.getSession).toHaveBeenCalledWith('session-1', expect.any(AbortSignal));
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transport.createSession).not.toHaveBeenCalled();
    expect(session.current).toMatchObject({ state: 'empty', activeSessionId: 'session-1' });
  });

  it('rejects foreign history on pre-identity restore retry before creating chat', async () => {
    const rest = createRest([]);
    vi.mocked(rest.getSessionMessages)
      .mockRejectedValueOnce(new Error('synthetic history parse failure'))
      .mockResolvedValueOnce(
        sessionMessagesFor('foreign-session', [
          { role: 'user', content: 'Foreign retry prompt' },
          { role: 'assistant', content: 'Foreign retry answer' }
        ])
      );
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();
    await session.retryConnection();

    expect(session.current).toMatchObject({ state: 'retryable-error' });
    expect(session.current.activeSessionId).toBeUndefined();
    expect(session.current.timeline).toEqual([]);
    expect(chat.createChat).not.toHaveBeenCalled();
    expect(JSON.stringify(session.current)).not.toContain('Foreign retry');
  });

  it('retries a pre-identity restore through history and session.resume in order', async () => {
    const events: string[] = [];
    const detailSessionIds: string[] = [];
    const historySessionIds: string[] = [];
    const selectedSessionIds: Array<string | undefined> = [];
    const resumedSessionIds: string[] = [];
    const retryHistory = createDeferred<SessionMessages>();
    let historyCall = 0;
    const rest = createRest([]);
    vi.mocked(rest.getSession).mockImplementation(async (sessionId, signal) => {
      expect(signal).toBeInstanceOf(AbortSignal);
      detailSessionIds.push(sessionId);
      events.push('detail');
      return SESSION;
    });
    vi.mocked(rest.getSessionMessages).mockImplementation((sessionId, _options, signal) => {
      expect(signal).toBeInstanceOf(AbortSignal);
      historyCall += 1;
      historySessionIds.push(sessionId);
      events.push(`history-${historyCall}`);
      if (historyCall === 1) return Promise.reject(new Error('synthetic history parse failure'));
      return retryHistory.promise;
    });

    const sockets: BrowserChatSocket[] = [];
    let restoredTransport: JsonRpcChatTransport | undefined;
    const createChat = vi.fn((options: BrowserChatOptions) => {
      events.push('createChat');
      selectedSessionIds.push(options.selectedSessionId);
      const transport = createBrowserChatTransport({
        ...options,
        fetch: async () => {
          events.push('ticket');
          return new Response('{"ticket":"fresh-ticket-1","ttl_seconds":30}', {
            headers: { 'content-type': 'application/json' }
          });
        },
        createSocket: () => {
          events.push('socket');
          const socket = new BrowserChatSocket();
          socket.onSend = (data) => {
            const frame = JSON.parse(data) as {
              method?: string;
              params?: { session_id?: unknown };
            };
            if (frame.method === 'session.resume') {
              events.push('session.resume');
              if (typeof frame.params?.session_id === 'string') {
                resumedSessionIds.push(frame.params.session_id);
              }
            }
          };
          sockets.push(socket);
          return socket;
        }
      });
      restoredTransport = transport;
      const connect = transport.connect.bind(transport);
      vi.spyOn(transport, 'connect').mockImplementation((signal) => {
        events.push('connect');
        return connect(signal);
      });
      vi.spyOn(transport, 'createSession');
      return transport;
    });
    const session = new LiveWorkspaceSession({ rest, createChat });

    await session.initialize();

    expect(session.current).toMatchObject({ state: 'retryable-error' });
    expect(session.current.activeSessionId).toBeUndefined();
    events.length = 0;

    type RetryOperation = { readonly generation: number; readonly signal: AbortSignal };
    type WorkspaceInternals = {
      readonly generation: number;
      readonly factoryRetryGeneration: number | undefined;
      readonly controller: AbortController | undefined;
      readonly disposed: boolean;
      ownsOperation(operation: RetryOperation): boolean;
      ownsFactoryRetry(operation: RetryOperation): boolean;
    };
    const internals = session as unknown as WorkspaceInternals;
    const ownershipTrace: Array<{
      readonly stage: 'ownsOperation' | 'ownsFactoryRetry';
      readonly generation: number;
      readonly currentGeneration: number;
      readonly factoryRetryGeneration: number | undefined;
      readonly controllerOwns: boolean;
      readonly signalAborted: boolean;
      readonly disposed: boolean;
      readonly owns: boolean;
    }> = [];
    const recordOwnership = (
      stage: 'ownsOperation' | 'ownsFactoryRetry',
      operation: RetryOperation,
      owns: boolean
    ): void => {
      ownershipTrace.push({
        stage,
        generation: operation.generation,
        currentGeneration: internals.generation,
        factoryRetryGeneration: internals.factoryRetryGeneration,
        controllerOwns: internals.controller?.signal === operation.signal,
        signalAborted: operation.signal.aborted,
        disposed: internals.disposed,
        owns
      });
    };
    const originalOwnsOperation = internals.ownsOperation.bind(session);
    const originalOwnsFactoryRetry = internals.ownsFactoryRetry.bind(session);
    vi.spyOn(internals, 'ownsOperation').mockImplementation((operation) => {
      const owns = originalOwnsOperation(operation);
      recordOwnership('ownsOperation', operation, owns);
      return owns;
    });
    vi.spyOn(internals, 'ownsFactoryRetry').mockImplementation((operation) => {
      const owns = originalOwnsFactoryRetry(operation);
      recordOwnership('ownsFactoryRetry', operation, owns);
      return owns;
    });

    const retry = session.retryConnection();
    await flush();

    expect(events).toEqual(['detail', 'history-2']);
    expect(historySessionIds).toEqual([SESSION.id, SESSION.id]);
    expect(session.current.activeSessionId).toBeUndefined();
    expect(
      ownershipTrace.some(
        (entry) => entry.stage === 'ownsFactoryRetry' && entry.owns && entry.signalAborted === false
      )
    ).toBe(true);
    expect(ownershipTrace.every((entry) => entry.owns)).toBe(true);

    retryHistory.resolve(sessionMessages([{ role: 'user', content: 'Retry server history' }]));
    const socket = await waitForSocket(sockets);

    expect(events).toEqual(['detail', 'history-2', 'createChat', 'connect', 'ticket', 'socket']);
    expect(selectedSessionIds).toEqual([SESSION.id]);
    expect(restoredTransport?.selectedSessionId).toBe(SESSION.id);

    socket.emitOpen();
    events.push('gateway.ready');
    socket.emitGatewayReady();
    const resumeFrame = await waitForSocketMethod(socket, 'session.resume');
    const resumeId = typeof resumeFrame.id === 'string' ? resumeFrame.id : undefined;
    if (!resumeId) throw new Error('session resume request did not have an id');
    socket.emitResponse(resumeId);
    await retry;

    expect(events).toEqual([
      'detail',
      'history-2',
      'createChat',
      'connect',
      'ticket',
      'socket',
      'gateway.ready',
      'session.resume'
    ]);
    expect(detailSessionIds).toEqual([SESSION.id]);
    expect(historySessionIds).toEqual([SESSION.id, SESSION.id]);
    expect(selectedSessionIds).toEqual([SESSION.id]);
    expect(resumedSessionIds).toEqual([SESSION.id]);
    expect(rest.getSessionMessages).toHaveBeenCalledTimes(2);
    expect(rest.getSessionMessages).toHaveBeenNthCalledWith(
      2,
      SESSION.id,
      { limit: 500, offset: 0 },
      expect.any(AbortSignal)
    );
    expect(restoredTransport?.connect).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(restoredTransport?.createSession).not.toHaveBeenCalled();
    expect(socket.sent.map((frame) => (JSON.parse(frame) as { method?: string }).method)).toEqual([
      'session.resume'
    ]);
    expect(session.current).toMatchObject({ state: 'ready', activeSessionId: SESSION.id });
    expect(session.current.timeline).toEqual([
      { kind: 'user-message', id: 'session-1:message:0', text: 'Retry server history' }
    ]);
  });

  it('suppresses a stale session read after a newer selection starts', async () => {
    const rest = createRest();
    const first = createDeferred<LiveSession>();
    const second = { ...SESSION, id: 'session-2', title: 'Second session', isActive: false };
    vi.mocked(rest.getSession)
      .mockImplementationOnce(() => first.promise)
      .mockResolvedValueOnce(second);
    vi.mocked(rest.getSessionMessages).mockResolvedValue({
      ...sessionMessages([]),
      sessionId: 'session-2'
    });
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    const stale = session.selectSession('session-1');
    const current = session.selectSession('session-2');
    first.resolve(SESSION);
    await Promise.all([stale, current]);

    expect(session.current.activeSessionId).toBe('session-2');
    expect(session.current.title).toBe('Second session');
    expect(chat.createChat).toHaveBeenCalledTimes(1);
  });

  it('rejects foreign history during session replacement without publishing or committing it', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Owned session answer' }]);
    const replacement = { ...SESSION, id: 'session-2', title: 'Replacement', isActive: false };
    vi.mocked(rest.getSession)
      .mockResolvedValueOnce(SESSION)
      .mockResolvedValueOnce(replacement);
    vi.mocked(rest.getSessionMessages)
      .mockResolvedValueOnce(sessionMessages([{ role: 'assistant', content: 'Owned session answer' }]))
      .mockResolvedValueOnce(
        sessionMessagesFor('foreign-session', [
          { role: 'user', content: 'Foreign replacement prompt' },
          { role: 'assistant', content: 'Foreign replacement answer' }
        ])
      );
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    const published: string[] = [];
    session.subscribe((snapshot) => published.push(JSON.stringify(snapshot)));

    await session.initialize();
    await session.selectSession(replacement.id);

    expect(session.current).toMatchObject({ state: 'retryable-error', activeSessionId: replacement.id });
    expect(session.current.timeline).toEqual([]);
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transport.promoteSession).not.toHaveBeenCalled();
    expect(published.every((snapshot) => !snapshot.includes('Foreign replacement'))).toBe(true);
  });

  it('rejects an untrusted A-to-B detail before reading history or replacing Chat ownership', async () => {
    const rest = createRest([]);
    const requestedSession = { ...SESSION, id: 'session-2', title: 'Requested replacement', isActive: false };
    const foreignDetail = { ...requestedSession, id: 'foreign-session', title: 'Foreign detail' };
    vi.mocked(rest.getSession).mockResolvedValueOnce(foreignDetail);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    const published: string[] = [];
    session.subscribe((snapshot) => published.push(JSON.stringify(snapshot)));

    await session.initialize();
    await session.selectSession(requestedSession.id);

    expect(rest.getSession).toHaveBeenLastCalledWith(requestedSession.id, expect.any(AbortSignal));
    expect(rest.getSessionMessages).toHaveBeenCalledTimes(1);
    expect(session.current).toMatchObject({
      state: 'retryable-error',
      activeSessionId: requestedSession.id
    });
    expect(session.current.timeline).toEqual([]);
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transport.connect).toHaveBeenCalledTimes(1);
    expect(published.every((snapshot) => !snapshot.includes('Foreign detail'))).toBe(true);
  });

  it('adopts a trusted REST canonical alias only after valid history and Chat setup', async () => {
    const requestedSessionId = 'alias-session';
    const canonicalSession = {
      ...SESSION,
      id: 'canonical-session',
      title: 'Canonical session',
      isActive: false
    };
    const rawHistory = (sessionId: string, content?: string): string =>
      JSON.stringify({
        session_id: sessionId,
        messages: content === undefined ? [] : [{ role: 'assistant', content }],
        pagination: { limit: 500, offset: 0, returned: content === undefined ? 0 : 1 }
      });
    const responses = [
      new Response(
        JSON.stringify({
          sessions: [JSON.parse(rawSessionDetail(SESSION))],
          total: 1,
          limit: 100,
          offset: 0
        }),
        { headers: { 'content-type': 'application/json' } }
      ),
      new Response(rawHistory(SESSION.id), { headers: { 'content-type': 'application/json' } }),
      new Response(rawSessionDetail(canonicalSession), {
        headers: { 'content-type': 'application/json' }
      }),
      new Response(rawHistory(canonicalSession.id, 'Canonical history'), {
        headers: { 'content-type': 'application/json' }
      })
    ];
    const requests: string[] = [];
    const liveRest = createLiveRestTransport({
      fetch: async (input) => {
        requests.push(String(input));
        const next = responses.shift();
        if (!next) throw new Error('missing synthetic REST response');
        return next;
      }
    });
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest: liveRest, createChat: chat.createChat });

    await session.initialize();
    await session.selectSession(requestedSessionId);

    expect(requests).toEqual([
      '/api/sessions?limit=100&offset=0',
      `/api/sessions/${SESSION.id}/messages?limit=500&offset=0`,
      `/api/sessions/${requestedSessionId}`,
      `/api/sessions/${canonicalSession.id}/messages?limit=500&offset=0`
    ]);
    expect(chat.createChat).toHaveBeenCalledTimes(2);
    expect(chat.createChat.mock.calls[1]?.[0]).toEqual(
      expect.objectContaining({ selectedSessionId: canonicalSession.id })
    );
    expect(session.current).toMatchObject({
      state: 'ready',
      activeSessionId: canonicalSession.id,
      title: canonicalSession.title
    });
    expect(session.current.timeline).toEqual([
      {
        kind: 'assistant-message',
        id: `${canonicalSession.id}:message:0`,
        text: 'Canonical history',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);
  });

  it('rejects a wrapper that relays a real REST canonical detail before history or Chat ownership', async () => {
    const requestedSessionId = 'alias-session';
    const canonicalSession = { ...SESSION, id: 'canonical-session', isActive: false };
    const realRest = createLiveRestTransport({
      fetch: async () =>
        new Response(rawSessionDetail(canonicalSession), {
          headers: { 'content-type': 'application/json' }
        })
    });
    const wrapper = createRest([]);
    vi.mocked(wrapper.getSession).mockImplementation((sessionId, signal) =>
      realRest.getSession(sessionId, signal)
    );
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest: wrapper, createChat: chat.createChat });

    await session.initialize();
    await session.selectSession(requestedSessionId);

    expect(wrapper.getSession).toHaveBeenCalledWith(requestedSessionId, expect.any(AbortSignal));
    expect(wrapper.getSessionMessages).toHaveBeenCalledTimes(1);
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(session.current).toMatchObject({
      state: 'retryable-error',
      activeSessionId: requestedSessionId
    });
    expect(session.current.timeline).toEqual([]);
  });

  it('shows bounded streaming text and then replaces it from server history', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce(
      sessionMessages([
        { role: 'user', content: 'Hello' },
        { role: 'assistant', content: 'Complete answer' }
      ])
    );

    session.sendPrompt('Hello');
    chat.emit({
      type: 'message.delta',
      requestId: 'request-1',
      payload: { text: 'Partial' }
    });

    expect(chat.sendPrompt).toHaveBeenCalledWith('Hello');
    expect(session.current.state).toBe('streaming');
    expect(session.current.timeline).toContainEqual({
      kind: 'streaming',
      id: 'request-1:stream',
      text: 'Partial',
      model: 'Hermes 4'
    });

    const completeEvent: JsonRpcChatEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'Complete answer' }
    };
    chat.emit(completeEvent);
    chat.complete(completeEvent);
    await flush();

    expect(session.current.state).toBe('ready');
    expect(session.current.timeline).toEqual([
      { kind: 'user-message', id: 'session-1:message:0', text: 'Hello' },
      {
        kind: 'assistant-message',
        id: 'session-1:message:1',
        text: 'Complete answer',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);
  });

  it('renders request-ID-free Hermes events and reconciles completion from REST', async () => {
    const rest = createRest([]);
    const { session, socket } = await createConnectedSocketWorkspace(rest);
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce(
      sessionMessages([
        { role: 'user', content: 'Hello without an event request ID' },
        { role: 'assistant', content: 'Complete server history' }
      ])
    );

    session.sendPrompt('Hello without an event request ID');
    const requestId = latestPromptId(socket);
    socket.emitEvent('message.delta', undefined, { text: 'Partial live answer' });

    expect(session.current).toMatchObject({ state: 'streaming' });
    expect(session.current.timeline).toContainEqual({
      kind: 'streaming',
      id: `${requestId}:stream`,
      text: 'Partial live answer',
      model: 'Hermes 4'
    });

    socket.emitEvent('message.complete', undefined, {
      text: 'Complete live answer',
      status: 'ok'
    });
    await flush();
    await flush();

    expect(rest.getSessionMessages).toHaveBeenLastCalledWith(
      'session-1',
      { limit: 500, offset: 0 },
      expect.any(AbortSignal)
    );
    expect(session.current).toMatchObject({ state: 'ready' });
    expect(session.current.timeline).toEqual([
      {
        kind: 'user-message',
        id: 'session-1:message:0',
        text: 'Hello without an event request ID'
      },
      {
        kind: 'assistant-message',
        id: 'session-1:message:1',
        text: 'Complete server history',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);

    // The completion was correlated without a wire request ID. A later generic
    // transport failure is stale after the successful REST commit and must not
    // regress the ready workspace or replay the prompt.
    socket.emitClose(1011, 'redacted');

    expect(session.current.state).toBe('ready');
    expect(socket.sent.filter((frame) => JSON.parse(frame).method === 'prompt.submit')).toHaveLength(1);
    expect(JSON.stringify(session.current)).not.toContain('redacted');
  });

  it('rejects foreign REST history after a correlated completion without replacing the owned timeline', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce({
      sessionId: 'foreign-session',
      messages: [
        { role: 'user', content: 'Foreign prompt' },
        { role: 'assistant', content: 'Foreign answer' }
      ],
      pagination: { limit: 500, offset: 0, returned: 2 }
    });

    session.sendPrompt('Owned prompt');
    const completion: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      sessionId: SESSION.id,
      payload: { text: 'Owned answer', status: 'ok' }
    };
    chat.emit(completion);
    chat.complete(completion);
    await flush();
    await flush();

    expect(rest.getSessionMessages).toHaveBeenLastCalledWith(
      SESSION.id,
      { limit: 500, offset: 0 },
      expect.any(AbortSignal)
    );
    expect(session.current).toMatchObject({
      state: 'retryable-error',
      activeSessionId: SESSION.id
    });
    expect(session.current.timeline).toEqual([
      { kind: 'user-message', id: 'request-1:user', text: 'Owned prompt' },
      {
        kind: 'assistant-message',
        id: 'request-1:stream',
        text: 'Owned answer',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);
    expect(JSON.stringify(session.current.timeline)).not.toContain('Foreign prompt');
    expect(JSON.stringify(session.current.timeline)).not.toContain('Foreign answer');
  });

  it('does not let an earlier completion refresh erase a newer prompt', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    const refresh = createDeferred<SessionMessages>();
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);

    session.sendPrompt('First prompt');
    const firstComplete: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'First answer' }
    };
    chat.emit(firstComplete);
    chat.complete(firstComplete);
    await flush();
    await flush();

    session.sendPrompt('Second prompt');
    expect(session.current.state).toBe('streaming');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'streaming', id: 'request-2:stream' })
    );

    refresh.resolve(
      sessionMessages([
        { role: 'user', content: 'First prompt' },
        { role: 'assistant', content: 'Late first history' }
      ])
    );
    await flush();

    expect(session.current.state).toBe('streaming');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'user-message', id: 'request-2:user', text: 'Second prompt' })
    );
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'streaming', id: 'request-2:stream' })
    );
    expect(JSON.stringify(session.current.timeline)).not.toContain('Late first history');
    expect(chat.sendPrompt).toHaveBeenCalledTimes(2);
  });

  it('interrupts without replay and permits a later user-led prompt', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    session.sendPrompt('First prompt');
    await session.stop();
    session.sendPrompt('Second prompt');

    expect(chat.transport.interrupt).toHaveBeenCalledWith('request-1');
    expect(session.current.state).toBe('streaming');
    expect(chat.sendPrompt).toHaveBeenNthCalledWith(1, 'First prompt');
    expect(chat.sendPrompt).toHaveBeenNthCalledWith(2, 'Second prompt');
  });

  it('aborts completion history refresh and drops a late authenticated response after invalidation', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    const refresh = createDeferred<SessionMessages>();
    let refreshSignal: AbortSignal | undefined;
    vi.mocked(rest.getSessionMessages).mockImplementationOnce((_sessionId, _options, signal) => {
      refreshSignal = signal;
      return refresh.promise;
    });

    session.sendPrompt('Complete once');
    const completeEvent: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'Server answer' }
    };
    chat.emit(completeEvent);
    chat.complete(completeEvent);
    await flush();
    await flush();

    expect(refreshSignal).toBeInstanceOf(AbortSignal);
    chat.changeState({ status: 'failed', generation: 1 });
    expect(session.current.state).toBe('ready');
    session.invalidate();
    expect(refreshSignal?.aborted).toBe(true);

    refresh.resolve(
      sessionMessages([
        { role: 'assistant', content: 'Late authenticated response must not be retained' }
      ])
    );
    await flush();

    expect(session.current.state).toBe('loading');
    expect(session.current.timeline).toEqual([]);
  });

  it('aborts completion history refresh and drops a late authenticated response after disposal', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    const refresh = createDeferred<SessionMessages>();
    let refreshSignal: AbortSignal | undefined;
    vi.mocked(rest.getSessionMessages).mockImplementationOnce((_sessionId, _options, signal) => {
      refreshSignal = signal;
      return refresh.promise;
    });

    session.sendPrompt('Complete once');
    const completeEvent: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'Server answer' }
    };
    chat.complete(completeEvent);
    await flush();
    await flush();

    expect(refreshSignal).toBeInstanceOf(AbortSignal);
    session.dispose();
    expect(refreshSignal?.aborted).toBe(true);

    refresh.resolve(
      sessionMessages([
        { role: 'assistant', content: 'Late authenticated response must not be retained' }
      ])
    );
    await flush();

    expect(session.current.state).toBe('loading');
    expect(session.current.timeline).toEqual([]);
  });

  it('keeps close 4401 permanent when completion history is still pending', async () => {
    const rest = createRest([]);
    const refresh = createDeferred<SessionMessages>();
    const { session, socket } = await createConnectedSocketWorkspace(rest);
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);

    session.sendPrompt('Complete before authentication closes');
    const requestId = latestPromptId(socket);
    socket.emitEvent('message.complete', requestId, { text: 'Server answer' });
    await flush();
    await flush();

    socket.emitClose(4401, 'redacted');
    expect(session.current).toMatchObject({
      state: 'permanent-error',
      permanentFailure: {
        reason: 'authentication-required',
        closeCode: 4401,
        closeClassification: 'authentication-rejected'
      }
    });
    const sentBeforeBlockedPrompt = socket.sent.length;
    session.sendPrompt('must remain blocked');
    expect(socket.sent).toHaveLength(sentBeforeBlockedPrompt);

    refresh.resolve(sessionMessages([{ role: 'assistant', content: 'late history' }]));
    await flush();

    expect(session.current.state).toBe('permanent-error');
    expect(session.current.permanentFailure?.reason).toBe('authentication-required');
    expect(session.current.timeline).not.toContainEqual(
      expect.objectContaining({ text: 'late history' })
    );
  });

  it('keeps close 4403 incompatible when completion history is still pending', async () => {
    const rest = createRest([]);
    const refresh = createDeferred<SessionMessages>();
    const { session, socket } = await createConnectedSocketWorkspace(rest);
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);

    session.sendPrompt('Complete before origin rejection');
    const requestId = latestPromptId(socket);
    socket.emitEvent('message.complete', requestId, { text: 'Server answer' });
    await flush();
    await flush();

    socket.emitClose(4403, 'redacted');
    expect(session.current).toMatchObject({
      state: 'permanent-error',
      permanentFailure: {
        reason: 'incompatible',
        closeCode: 4403,
        closeClassification: 'host-or-origin-rejected'
      }
    });
    const sentBeforeBlockedPrompt = socket.sent.length;
    session.sendPrompt('must remain blocked');
    expect(socket.sent).toHaveLength(sentBeforeBlockedPrompt);

    refresh.resolve(sessionMessages([{ role: 'assistant', content: 'late history' }]));
    await flush();

    expect(session.current.state).toBe('permanent-error');
    expect(session.current.permanentFailure?.reason).toBe('incompatible');
    expect(session.current.timeline).not.toContainEqual(
      expect.objectContaining({ text: 'late history' })
    );
  });

  it('lets only the newer reconnect refresh publish when it resolves after the old completion refresh', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    const completionRefresh = createDeferred<SessionMessages>();
    const reconnectRefresh = createDeferred<SessionMessages>();
    vi.mocked(rest.getSessionMessages)
      .mockImplementationOnce(() => completionRefresh.promise)
      .mockImplementationOnce(() => reconnectRefresh.promise);

    session.sendPrompt('First prompt');
    const completeEvent: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'First answer' }
    };
    chat.emit(completeEvent);
    chat.complete(completeEvent);
    await flush();
    await flush();

    const reconnect = session.retryConnection();
    await flush();
    await flush();
    expect(rest.getSessionMessages).toHaveBeenCalledTimes(3);
    expect(session.current.state).toBe('reconnecting');

    completionRefresh.resolve(sessionMessages([{ role: 'assistant', content: 'old completion history' }]));
    await flush();
    expect(session.current.state).toBe('reconnecting');
    expect(JSON.stringify(session.current.timeline)).not.toContain('old completion history');

    reconnectRefresh.resolve(sessionMessages([{ role: 'assistant', content: 'new reconnect history' }]));
    await reconnect;

    expect(session.current.state).toBe('ready');
    expect(JSON.stringify(session.current.timeline)).toContain('new reconnect history');
  });

  it('keeps the newer reconnect history when it resolves before the old completion refresh', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    const completionRefresh = createDeferred<SessionMessages>();
    const reconnectRefresh = createDeferred<SessionMessages>();
    vi.mocked(rest.getSessionMessages)
      .mockImplementationOnce(() => completionRefresh.promise)
      .mockImplementationOnce(() => reconnectRefresh.promise);

    session.sendPrompt('First prompt');
    const completeEvent: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'First answer' }
    };
    chat.emit(completeEvent);
    chat.complete(completeEvent);
    await flush();
    await flush();

    const reconnect = session.retryConnection();
    await flush();
    await flush();

    reconnectRefresh.resolve(sessionMessages([{ role: 'assistant', content: 'new reconnect history' }]));
    await flush();
    expect(session.current.state).toBe('ready');
    expect(JSON.stringify(session.current.timeline)).toContain('new reconnect history');

    completionRefresh.resolve(sessionMessages([{ role: 'assistant', content: 'old completion history' }]));
    await reconnect;

    expect(session.current.state).toBe('ready');
    expect(JSON.stringify(session.current.timeline)).not.toContain('old completion history');
    expect(JSON.stringify(session.current.timeline)).toContain('new reconnect history');
  });

  it('does not publish an abort rejection from a completion refresh after session replacement', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    const refresh = createDeferred<SessionMessages>();
    vi.mocked(rest.getSession).mockResolvedValueOnce({ ...SESSION, id: 'session-2', title: 'Replacement' });
    vi.mocked(rest.getSessionMessages)
      .mockImplementationOnce(() => refresh.promise)
      .mockResolvedValueOnce({ ...sessionMessages([]), sessionId: 'session-2' });

    session.sendPrompt('First prompt');
    const completeEvent: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'First answer' }
    };
    chat.complete(completeEvent);
    await flush();
    await flush();

    const replacement = session.selectSession('session-2');
    refresh.reject(new DOMException('aborted', 'AbortError'));
    await replacement;
    await flush();

    expect(session.current).toMatchObject({ activeSessionId: 'session-2', state: 'empty' });
    expect(session.current.state).not.toBe('retryable-error');
    expect(session.current.timeline).toEqual([]);
  });

  it('does not publish a non-abort completion refresh rejection after session replacement', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    const refresh = createDeferred<SessionMessages>();
    vi.mocked(rest.getSession).mockResolvedValueOnce({ ...SESSION, id: 'session-2', title: 'Replacement' });
    vi.mocked(rest.getSessionMessages)
      .mockImplementationOnce(() => refresh.promise)
      .mockResolvedValueOnce({ ...sessionMessages([]), sessionId: 'session-2' });

    session.sendPrompt('First prompt');
    const completeEvent: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'First answer' }
    };
    chat.complete(completeEvent);
    await flush();
    await flush();

    const replacement = session.selectSession('session-2');
    refresh.reject(new Error('late history failure'));
    await replacement;
    await flush();

    expect(session.current).toMatchObject({ activeSessionId: 'session-2', state: 'empty' });
    expect(session.current.state).not.toBe('retryable-error');
    expect(session.current.timeline).toEqual([]);
  });

  it('blocks a completion subscriber from sending a second prompt before transport delivery', async () => {
    const rest = createRest([]);
    const refresh = createDeferred<SessionMessages>();
    const { session, socket } = await createConnectedSocketWorkspace(rest);
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);
    let reentrantSendAttempts = 0;
    let reentrantSendHandled = false;

    session.subscribe((snapshot) => {
      const completedOriginalPrompt = snapshot.timeline.some(
        (item) => item.kind === 'assistant-message' && item.text === 'Server answer'
      );
      if (reentrantSendHandled || snapshot.state !== 'ready' || !completedOriginalPrompt) return;
      reentrantSendHandled = true;
      reentrantSendAttempts += 1;
      session.sendPrompt('must not cross the transport boundary');
    });

    session.sendPrompt('Original prompt');
    const requestId = latestPromptId(socket);
    socket.emitEvent('message.complete', requestId, { text: 'Server answer' });

    // The ready publication reentered sendPrompt synchronously, but the original
    // request stays the sole transport operation and owns the pending REST read.
    expect(reentrantSendAttempts).toBe(1);
    expect(socket.sent.filter((frame) => JSON.parse(frame).method === 'prompt.submit')).toHaveLength(1);
    await flush();
    await flush();
    expect(rest.getSessionMessages).toHaveBeenCalledTimes(2);

    refresh.resolve(
      sessionMessages([
        { role: 'user', content: 'Original prompt' },
        { role: 'assistant', content: 'Server answer' }
      ])
    );
    await flush();

    expect(session.current.state).toBe('ready');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'assistant-message', text: 'Server answer' })
    );
    expect(socket.sent.filter((frame) => JSON.parse(frame).method === 'prompt.submit')).toHaveLength(1);

    // A late generic close is stale after the exact completion refresh commits;
    // it cannot replay the prompt or revoke the server-owned completed history.
    socket.emitClose(1011, 'redacted');
    expect(session.current.state).toBe('ready');
    expect(socket.sent.filter((frame) => JSON.parse(frame).method === 'prompt.submit')).toHaveLength(1);
  });

  it('defers a generic terminal close until completion history commits', async () => {
    const rest = createRest([]);
    const refresh = createDeferred<SessionMessages>();
    const { session, socket } = await createConnectedSocketWorkspace(rest);
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);

    session.sendPrompt('Complete before generic close');
    const requestId = latestPromptId(socket);
    socket.emitEvent('message.complete', requestId, { text: 'Server answer' });
    await flush();
    await flush();

    socket.emitClose(1011, 'redacted');
    // The matching generic failure is owned by the exact completion refresh;
    // it must not become actionable recovery before REST settles.
    expect(session.current.state).toBe('ready');
    expect(socket.sent.filter((frame) => JSON.parse(frame).method === 'prompt.submit')).toHaveLength(1);

    refresh.resolve(sessionMessages([{ role: 'assistant', content: 'late history' }]));
    await flush();

    expect(session.current.state).toBe('ready');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'assistant-message', text: 'late history' })
    );
    expect(socket.sent.filter((frame) => JSON.parse(frame).method === 'prompt.submit')).toHaveLength(1);
  });

  it('publishes REST failure after deferring a matching generic terminal close', async () => {
    const rest = createRest([]);
    const refresh = createDeferred<SessionMessages>();
    const { session, socket } = await createConnectedSocketWorkspace(rest);
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);

    session.sendPrompt('Complete before history failure');
    const requestId = latestPromptId(socket);
    socket.emitEvent('message.complete', requestId, { text: 'Server answer' });
    await flush();
    await flush();

    socket.emitClose(1011, 'redacted');
    expect(session.current.state).toBe('ready');

    refresh.reject(new Error('history read failed'));
    await flush();

    expect(session.current.state).toBe('retryable-error');
    expect(socket.sent.filter((frame) => JSON.parse(frame).method === 'prompt.submit')).toHaveLength(1);
  });

  it('invalidates deferred completion history on delivery uncertainty', async () => {
    const rest = createRest([]);
    const refresh = createDeferred<SessionMessages>();
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);

    session.sendPrompt('Complete before uncertain delivery');
    const completion: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'Server answer' }
    };
    chat.emit(completion);
    chat.complete(completion);
    await flush();
    await flush();

    chat.changeState({ status: 'delivery_uncertain', generation: 1 });
    expect(session.current.state).toBe('retryable-error');

    refresh.resolve(sessionMessages([{ role: 'assistant', content: 'must not commit' }]));
    await flush();

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.timeline).not.toContainEqual(
      expect.objectContaining({ text: 'must not commit' })
    );
    expect(chat.sendPrompt).toHaveBeenCalledTimes(1);
  });

  it('keeps a generic failure deferred until a replacement owns the session', async () => {
    const rest = createRest([]);
    const refresh = createDeferred<SessionMessages>();
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);
    vi.mocked(rest.getSession).mockResolvedValueOnce({ ...SESSION, id: 'session-2', title: 'Replacement' });
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce({ ...sessionMessages([]), sessionId: 'session-2' });

    session.sendPrompt('Complete before replacement');
    const completion: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'Server answer' }
    };
    chat.emit(completion);
    chat.complete(completion);
    await flush();
    await flush();
    chat.changeState({ status: 'failed', generation: 1 });
    expect(session.current.state).toBe('ready');

    const replacement = session.selectSession('session-2');
    refresh.resolve(sessionMessages([{ role: 'assistant', content: 'stale history' }]));
    await replacement;

    expect(session.current).toMatchObject({ activeSessionId: 'session-2', title: 'Replacement', state: 'empty' });
    expect(session.current.timeline).not.toContainEqual(
      expect.objectContaining({ text: 'stale history' })
    );
  });

  it('keeps committed completion history ready after a late generic terminal callback', async () => {
    const rest = createRest([]);
    const { session, socket } = await createConnectedSocketWorkspace(rest);
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce(
      sessionMessages([
        { role: 'user', content: 'Completed prompt' },
        { role: 'assistant', content: 'Completed answer' }
      ])
    );

    session.sendPrompt('Completed prompt');
    const requestId = latestPromptId(socket);
    socket.emitEvent('message.complete', requestId, { text: 'Completed answer' });
    await flush();
    await flush();

    expect(session.current.state).toBe('ready');
    expect(session.current.timeline.filter((item) => item.kind === 'assistant-message')).toEqual([
      expect.objectContaining({ text: 'Completed answer' })
    ]);

    // Official Hermes may report a generic close after the REST replacement has
    // committed. It must not downgrade or duplicate the committed history.
    socket.emitClose(1011, 'redacted');

    expect(session.current.state).toBe('ready');
    expect(session.current.timeline.filter((item) => item.kind === 'assistant-message')).toEqual([
      expect.objectContaining({ text: 'Completed answer' })
    ]);
    expect(JSON.stringify(session.current)).not.toContain('redacted');

    // No prompt is replayed by the late callback. An explicit send against the
    // closed transport fails locally and then exposes normal recovery.
    const sentBeforeBlockedPrompt = socket.sent.length;
    session.sendPrompt('must reconnect');
    expect(socket.sent).toHaveLength(sentBeforeBlockedPrompt);
    expect(session.current.state).toBe('retryable-error');
  });

  it('retains one completed assistant marker after a reload-like session replacement', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    vi.mocked(rest.getSessionMessages)
      .mockResolvedValueOnce(sessionMessages([]))
      .mockResolvedValue(
        sessionMessages([
          { role: 'user', content: 'Completed prompt' },
          { role: 'assistant', content: 'Completed answer' }
        ])
      );
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    session.sendPrompt('Completed prompt');
    const completion: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'Completed answer' }
    };
    chat.emit(completion);
    chat.complete(completion);
    await flush();
    await flush();

    const countAssistantMarkers = (): number =>
      session.current.timeline.filter(
        (item) => item.kind === 'assistant-message' && item.text === 'Completed answer'
      ).length;
    expect(countAssistantMarkers()).toBe(1);

    // A reload starts a new workspace generation and re-reads the server; it
    // must replace rather than append the already-completed marker.
    session.invalidate();
    await session.initialize();

    expect(session.current.state).toBe('ready');
    expect(countAssistantMarkers()).toBe(1);
  });

  it('keeps initial restore history retryable after a generic terminal callback', async () => {
    const rest = createRest([
      { role: 'user', content: 'Persisted prompt' },
      { role: 'assistant', content: 'Persisted answer' }
    ]);
    const { session, socket } = await createConnectedSocketWorkspace(rest);

    expect(JSON.parse(socket.sent[0] ?? '{}')).toMatchObject({ method: 'session.resume' });
    expect(session.current.state).toBe('ready');
    expect(session.current.timeline).toEqual([
      { kind: 'user-message', id: 'session-1:message:0', text: 'Persisted prompt' },
      {
        kind: 'assistant-message',
        id: 'session-1:message:1',
        text: 'Persisted answer',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);

    // Restore history is not evidence that a prompt completed on this chat.
    // A later generic close must therefore remain actionable recovery.
    socket.emitClose(1011, 'redacted');

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.timeline).toEqual([
      { kind: 'user-message', id: 'session-1:message:0', text: 'Persisted prompt' },
      {
        kind: 'assistant-message',
        id: 'session-1:message:1',
        text: 'Persisted answer',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);
  });

  it('rejects foreign history during reconnect without replacing committed history', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Initial answer' }]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce(
      sessionMessagesFor('foreign-session', [
        { role: 'user', content: 'Foreign reconnect prompt' },
        { role: 'assistant', content: 'Foreign reconnect answer' }
      ])
    );

    await session.retryConnection();

    expect(chat.transport.reconnect).toHaveBeenCalledWith(expect.any(AbortSignal));
    expect(session.current).toMatchObject({ state: 'retryable-error', activeSessionId: SESSION.id });
    expect(session.current.timeline).toEqual([
      {
        kind: 'assistant-message',
        id: 'session-1:message:0',
        text: 'Initial answer',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);
    expect(chat.transport.promoteSession).not.toHaveBeenCalled();
    expect(JSON.stringify(session.current.timeline)).not.toContain('Foreign reconnect');
  });

  it('keeps reconnect history retryable after a generic terminal callback', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Initial answer' }]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce(
      sessionMessages([{ role: 'assistant', content: 'Reconnected answer' }])
    );
    await session.retryConnection();

    expect(session.current.state).toBe('ready');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'assistant-message', text: 'Reconnected answer' })
    );

    // Reconnect history is not evidence that a new prompt completed. A later
    // generic transport failure must not inherit completion suppression.
    chat.changeState({ status: 'failed', generation: 1 });

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'assistant-message', text: 'Reconnected answer' })
    );
  });

  it('does not let committed history suppress permanent authentication or origin closes', async () => {
    for (const [closeCode, reason, expectedFailure] of [
      [4401, 'authentication-rejected', 'authentication-required'],
      [4403, 'host-or-origin-rejected', 'incompatible']
    ] as const) {
      const rest = createRest([{ role: 'assistant', content: 'Persisted answer' }]);
      const { session, socket } = await createConnectedSocketWorkspace(rest);

      socket.emitClose(closeCode, 'redacted');

      expect(session.current.state).toBe('permanent-error');
      expect(session.current.permanentFailure).toMatchObject({
        reason: expectedFailure,
        closeCode,
        closeClassification: reason
      });
      expect(session.current.timeline).toEqual([
        {
          kind: 'assistant-message',
          id: 'session-1:message:0',
          text: 'Persisted answer',
          model: 'Hermes 4',
          status: 'complete'
        }
      ]);
    }
  });

  it('keeps committed history visible but non-sendable after a late uncertain-delivery callback', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce(
      sessionMessages([
        { role: 'user', content: 'Completed prompt' },
        { role: 'assistant', content: 'Completed answer' }
      ])
    );

    session.sendPrompt('Completed prompt');
    const completion: JsonRpcCompletionEvent = {
      type: 'message.complete',
      requestId: 'request-1',
      payload: { text: 'Completed answer' }
    };
    chat.emit(completion);
    chat.complete(completion);
    await flush();
    await flush();

    expect(session.current.state).toBe('ready');
    chat.changeState({ status: 'delivery_uncertain', generation: 1 });

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.timeline.filter((item) => item.kind === 'assistant-message')).toEqual([
      expect.objectContaining({ text: 'Completed answer' })
    ]);
  });

  it('does not commit REST history before a pre-ticket connection failure', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Persisted answer' }]);
    const chat = createChatHarness();
    vi.mocked(chat.transport.connect).mockRejectedValue(new JsonRpcChatError('connection-failed'));
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.timeline).toEqual([
      {
        kind: 'assistant-message',
        id: 'session-1:message:0',
        text: 'Persisted answer',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);
  });

  it('maps authentication-required chat state to a permanent workspace error', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    chat.changeState({ status: 'auth_required', generation: 1 });

    expect(session.current.state).toBe('permanent-error');
  });

  it('preserves a real HTTP 401 connect rejection during initialize', async () => {
    const rest = createRest();
    const chat = createUnauthorizedChatFactory();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();

    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transports[0]?.state.status).toBe('auth_required');
    expect(session.current.state).toBe('permanent-error');
  });

  it('preserves a real HTTP 401 connect rejection during session selection', async () => {
    const rest = createRest();
    const chat = createUnauthorizedChatFactory();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.selectSession('session-1');

    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transports[0]?.state.status).toBe('auth_required');
    expect(session.current.state).toBe('permanent-error');
  });

  it('preserves a real HTTP 401 connect rejection during empty-session creation', async () => {
    const rest = createRest([]);
    vi.mocked(rest.listSessions).mockResolvedValue({ sessions: [], total: 0, limit: 100, offset: 0 });
    const chat = createUnauthorizedChatFactory();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();
    await session.createSession();

    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transports[0]?.state.status).toBe('auth_required');
    expect(session.current.state).toBe('permanent-error');
  });

  it('keeps a genuine generic connect rejection retryable', async () => {
    const rest = createRest([]);
    vi.mocked(rest.listSessions).mockResolvedValue({ sessions: [], total: 0, limit: 100, offset: 0 });
    const chat = createChatHarness();
    vi.mocked(chat.transport.connect).mockRejectedValue(new JsonRpcChatError('connection-failed'));
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();
    await session.createSession();

    expect(session.current.state).toBe('retryable-error');
  });

  it('preserves a real HTTP 401 reconnect rejection as permanent workspace state', async () => {
    const rest = createRest();
    const chat = createReconnectUnauthorizedChatFactory();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    const initialization = session.initialize();
    const socket = await waitForSocket(chat.sockets);
    socket.emitOpen();
    socket.emitGatewayReady();
    await flush();
    const resumeFrame = JSON.parse(socket.sent[0] ?? '{}') as { id?: string };
    if (!resumeFrame.id) throw new Error('session resume frame was not sent');
    socket.emitResponse(resumeFrame.id);
    await initialization;

    await session.retryConnection();

    expect(chat.transports[0]?.state.status).toBe('auth_required');
    expect(session.current.state).toBe('permanent-error');
  });

  it('keeps auth_required permanent when an active prompt is interrupted by close 4401', async () => {
    const rest = createRest([]);
    const socket = new BrowserChatSocket();
    let transport: JsonRpcChatTransport | undefined;
    const createChat = vi.fn((options: BrowserChatOptions) => {
      transport = createBrowserChatTransport({
        ...options,
        fetch: async () =>
          new Response('{"ticket":"fresh-ticket-1","ttl_seconds":30}', {
            headers: { 'content-type': 'application/json' }
          }),
        createSocket: () => socket
      });
      return transport;
    });
    const session = new LiveWorkspaceSession({ rest, createChat });

    const initialization = session.initialize();
    const attached = await waitForSocket([socket]);
    attached.emitOpen();
    attached.emitGatewayReady();
    await flush();
    const resumeFrame = JSON.parse(attached.sent[0] ?? '{}') as { id?: string };
    if (!resumeFrame.id) throw new Error('session resume frame was not sent');
    attached.emitResponse(resumeFrame.id);
    await initialization;

    session.sendPrompt('requires authentication');
    attached.emitClose(4401, 'redacted');
    await flush();

    expect(transport?.state.status).toBe('auth_required');
    expect(session.current.state).toBe('permanent-error');
    expect(session.current.permanentFailure).toEqual({
      reason: 'authentication-required',
      closeCode: 4401,
      closeClassification: 'authentication-rejected'
    });
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'error', title: 'Authentication required' })
    );
  });

  it('keeps an active prompt origin rejection permanently incompatible after close 4403', async () => {
    const rest = createRest([]);
    const socket = new BrowserChatSocket();
    let transport: JsonRpcChatTransport | undefined;
    const createChat = vi.fn((options: BrowserChatOptions) => {
      transport = createBrowserChatTransport({
        ...options,
        fetch: async () =>
          new Response('{"ticket":"fresh-ticket-1","ttl_seconds":30}', {
            headers: { 'content-type': 'application/json' }
          }),
        createSocket: () => socket
      });
      return transport;
    });
    const session = new LiveWorkspaceSession({ rest, createChat });

    const initialization = session.initialize();
    const attached = await waitForSocket([socket]);
    attached.emitOpen();
    attached.emitGatewayReady();
    await flush();
    const resumeFrame = JSON.parse(attached.sent[0] ?? '{}') as { id?: string };
    if (!resumeFrame.id) throw new Error('session resume frame was not sent');
    attached.emitResponse(resumeFrame.id);
    await initialization;

    session.sendPrompt('origin rejection');
    attached.emitClose(4403, 'redacted');
    await flush();

    expect(transport?.state.status).toBe('incompatible');
    expect(transport?.state.closeCode).toBe(4403);
    expect(transport?.state.closeClassification).toBe('host-or-origin-rejected');
    expect(session.current.state).toBe('permanent-error');
    expect(session.current.permanentFailure).toEqual({
      reason: 'incompatible',
      closeCode: 4403,
      closeClassification: 'host-or-origin-rejected'
    });
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({
        kind: 'error',
        title: 'Incompatible origin',
        detail: expect.stringContaining('origin')
      })
    );
  });

  it('marks uncertain delivery without reconnecting or replaying the prompt', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    session.sendPrompt('Do this once');
    chat.reject(new JsonRpcChatError('uncertain-delivery'));
    await flush();

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'error', title: 'Delivery is uncertain' })
    );
    expect(chat.sendPrompt).toHaveBeenCalledTimes(1);
    expect(chat.transport.reconnect).not.toHaveBeenCalled();
  });

  it('ignores a late reconnect completion after workspace invalidation', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const reconnect = createDeferred<void>();
    vi.mocked(chat.transport.reconnect).mockImplementation(() => reconnect.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockClear();

    const retry = session.retryConnection();
    expect(session.current.state).toBe('reconnecting');
    session.invalidate();
    reconnect.resolve();
    await retry;

    expect(rest.getSessionMessages).not.toHaveBeenCalled();
    expect(session.current.state).toBe('loading');
  });

  it('ignores a late reconnect completion after workspace disposal', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const reconnect = createDeferred<void>();
    vi.mocked(chat.transport.reconnect).mockImplementation(() => reconnect.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockClear();

    const retry = session.retryConnection();
    session.dispose();
    reconnect.reject(new Error('late reconnect failure'));
    await retry;

    expect(rest.getSessionMessages).not.toHaveBeenCalled();
    expect(session.current.state).toBe('loading');
  });

  it('ignores a late reconnect completion after the chat is replaced', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const reconnect = createDeferred<void>();
    vi.mocked(chat.transport.reconnect).mockImplementation(() => reconnect.promise);
    const replacement: JsonRpcChatTransport = {
      ...chat.transport,
      connect: vi.fn().mockResolvedValue(undefined),
      close: vi.fn(),
      reconnect: vi.fn().mockResolvedValue(undefined)
    };
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSession).mockResolvedValueOnce({ ...SESSION, id: 'session-2', title: 'Replacement' });
    vi.mocked(chat.createChat).mockImplementationOnce(() => replacement);
    vi.mocked(rest.getSessionMessages).mockClear();
    vi.mocked(rest.getSessionMessages).mockResolvedValueOnce(sessionMessagesFor('session-2', []));

    const retry = session.retryConnection();
    await session.selectSession('session-2');
    reconnect.resolve();
    await retry;

    expect(rest.getSessionMessages).toHaveBeenCalledTimes(1);
    expect(session.current).toMatchObject({ activeSessionId: 'session-2', title: 'Replacement' });
    expect(session.current.state).toBe('empty');
  });

  it('does not reconnect after a subscriber reentrantly invalidates the workspace', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const reconnect = createDeferred<void>();
    vi.mocked(chat.transport.reconnect).mockImplementation(() => reconnect.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockClear();
    let invalidated = false;
    const unsubscribe = session.subscribe((snapshot) => {
      if (snapshot.state === 'reconnecting' && !invalidated) {
        invalidated = true;
        session.invalidate();
      }
    });

    const retry = session.retryConnection();
    reconnect.resolve();
    await retry;
    unsubscribe();

    expect(invalidated).toBe(true);
    expect(rest.getSessionMessages).not.toHaveBeenCalled();
    expect(session.current.state).toBe('loading');
  });

  it('ignores a late approval completion after the chat generation is invalidated', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const pending = createDeferred<void>();
    vi.mocked(chat.transport.respondToApproval).mockImplementation(() => pending.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    chat.emit({
      type: 'approval.request',
      requestId: 'approval-request',
      approvalId: 'approval-1',
      payload: { title: 'Permission', description: 'Confirm once' }
    });

    const approval = session.approve('approval:approval-1', true);
    session.invalidate();
    pending.resolve();
    await approval;

    expect(session.current.state).toBe('loading');
    expect(session.current.timeline).toEqual([]);
  });

  it('ignores a late clarification failure after disposal and reentrant chat close', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const pending = createDeferred<void>();
    vi.mocked(chat.transport.answerClarification).mockImplementation(() => pending.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    chat.emit({
      type: 'clarify.request',
      requestId: 'clarify-request',
      clarificationId: 'clarification-1',
      payload: { question: 'Choose one', options: ['one', 'two'] }
    });
    chat.transport.close = vi.fn(() => session.dispose());

    const clarification = session.answerClarification('clarification:clarification-1', 'one');
    session.dispose();
    pending.reject(new Error('late clarification failure'));
    await clarification;

    expect(chat.transport.close).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('loading');
    expect(session.current.timeline).toEqual([]);
  });

  it('rejects an approval completion from a replaced chat identity', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const pending = createDeferred<void>();
    vi.mocked(chat.transport.respondToApproval).mockImplementation(() => pending.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    chat.emit({
      type: 'approval.request',
      requestId: 'approval-request',
      approvalId: 'approval-2',
      payload: { title: 'Permission', description: 'Confirm once' }
    });
    const approval = session.approve('approval:approval-2', true);
    const replacement: JsonRpcChatTransport = {
      ...chat.transport,
      connect: vi.fn().mockResolvedValue(undefined),
      close: vi.fn()
    };
    vi.mocked(chat.createChat).mockImplementationOnce(() => replacement);
    await session.selectSession('session-1');
    pending.resolve();
    await approval;

    expect(session.current.state).toBe('empty');
    expect(session.current.timeline).toEqual([]);
  });

  it('maps a genuine REST 401 history failure to permanent authentication state', async () => {
    const rest = createRest([]);
    vi.mocked(rest.getSessionMessages).mockRejectedValue(new LiveRestError('unauthenticated', 401));
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });

    await session.initialize();

    expect(session.current.state).toBe('permanent-error');
    expect(session.current.permanentFailure).toEqual({ reason: 'authentication-required' });
    expect(chat.transport.connect).not.toHaveBeenCalled();
  });

  it('cancels an in-flight reconnect without allowing its late history result', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const reconnect = createDeferred<void>();
    vi.mocked(chat.transport.reconnect).mockImplementation(() => reconnect.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockClear();

    const retry = session.retryConnection();
    session.cancelReconnect();
    reconnect.resolve();
    await retry;

    expect(session.current.state).toBe('offline');
    expect(rest.getSessionMessages).not.toHaveBeenCalled();
  });

  it('closes chat and drops local session references before invalidation is published', async () => {
    const rest = createRest([{ role: 'user', content: 'Temporary local view' }]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    const observed: string[] = [];
    session.subscribe((snapshot) => observed.push(JSON.stringify(snapshot)));

    session.invalidate();

    expect(chat.transport.close).toHaveBeenCalledTimes(1);
    expect(session.current.activeSessionId).toBeUndefined();
    expect(session.current.sessions).toEqual([]);
    expect(session.current.timeline).toEqual([]);
    expect(observed.at(-1)).not.toContain('Temporary local view');
  });

  it('drops a request returned after a synchronous prompt invalidation', async () => {
    let session!: LiveWorkspaceSession;
    const rest = createRest([]);
    const chat = createChatHarness({ onSendPrompt: () => session.invalidate() });
    session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    session.sendPrompt('prompt invalidated during send');
    const request = chat.sendPrompt.mock.results[0]?.value as JsonRpcChatRequest;

    expect(request.abort).toHaveBeenCalledTimes(1);
    expect(chat.transport.close).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('loading');
    expect(session.current.timeline).toEqual([]);
  });

  it('does not publish a synchronous prompt error after disposal reentry', async () => {
    let session!: LiveWorkspaceSession;
    const rest = createRest([]);
    const chat = createChatHarness({
      onSendPrompt: () => session.dispose(),
      sendPromptError: new JsonRpcChatError('connection-failed')
    });
    session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    session.sendPrompt('prompt failed during disposal');

    expect(chat.transport.close).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('loading');
    expect(session.current.timeline).toEqual([]);
  });

  it('closes a stale open-session factory result exactly once after reentrant invalidation', async () => {
    const rest = createRest([]);
    const staleChat = createChatHarness();
    let session!: LiveWorkspaceSession;
    const createChat = vi.fn(() => {
      session.invalidate();
      return staleChat.transport;
    });
    session = new LiveWorkspaceSession({ rest, createChat });

    await session.initialize();

    expect(staleChat.transport.close).toHaveBeenCalledTimes(1);
    expect(staleChat.transport.connect).not.toHaveBeenCalled();
    expect(session.current.state).toBe('loading');
  });

  it('closes a stale empty-session factory result exactly once after reentrant disposal', async () => {
    const rest = createRest([]);
    vi.mocked(rest.listSessions).mockResolvedValue({ sessions: [], total: 0, limit: 100, offset: 0 });
    const staleChat = createChatHarness();
    let session!: LiveWorkspaceSession;
    const createChat = vi.fn(() => {
      session.dispose();
      return staleChat.transport;
    });
    session = new LiveWorkspaceSession({ rest, createChat });

    await session.initialize();
    await session.createSession();

    expect(staleChat.transport.close).toHaveBeenCalledTimes(1);
    expect(staleChat.transport.connect).not.toHaveBeenCalled();
    expect(session.current.state).toBe('loading');
  });

  it('retains parsed REST history when chat factory fails before ticket acquisition', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Persisted answer' }]);
    const failure = new Error('synthetic factory failure');
    const createChat = vi.fn(() => {
      throw failure;
    });
    const session = new LiveWorkspaceSession({ rest, createChat });

    await session.initialize();

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.timeline).toEqual([
      {
        kind: 'assistant-message',
        id: 'session-1:message:0',
        text: 'Persisted answer',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);
    expect(JSON.stringify(session.current)).not.toContain('synthetic factory failure');
  });

  it('publishes a bounded retryable state for a current synchronous chat factory failure', async () => {
    const rest = createRest([]);
    const failure = new Error('synthetic factory failure');
    const createChat = vi.fn(() => {
      throw failure;
    });
    const session = new LiveWorkspaceSession({ rest, createChat });

    await session.initialize();

    expect(session.current.state).toBe('retryable-error');
    expect(JSON.stringify(session.current)).not.toContain('synthetic factory failure');
  });

  it('retries a new-session factory failure by rebuilding chat and creating the session', async () => {
    const rest = createRest();
    vi.mocked(rest.listSessions).mockResolvedValue({ sessions: [], total: 0, limit: 100, offset: 0 });
    const chat = createChatHarness();
    let attempts = 0;
    const createChat = vi.fn((options: BrowserChatOptions) => {
      attempts += 1;
      if (attempts === 1) throw new Error('first factory failure');
      return chat.createChat(options);
    });
    const session = new LiveWorkspaceSession({ rest, createChat });

    await session.initialize();
    await session.createSession();

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.activeSessionId).toBeUndefined();

    const retry = session.retryConnection();
    await retry;

    expect(attempts).toBe(2);
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(chat.transport.connect).toHaveBeenCalledTimes(1);
    expect(chat.transport.createSession).toHaveBeenCalledTimes(1);
    expect(session.current).toMatchObject({
      state: 'empty',
      activeSessionId: 'stored-draft',
      title: 'Untitled chat',
      model: 'Hermes 4'
    });
  });

  it('retries a factory failure by rebuilding the active session chat and restoring history', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Recovered answer' }]);
    const chat = createChatHarness();
    let attempts = 0;
    const createChat = vi.fn((options: BrowserChatOptions) => {
      attempts += 1;
      if (attempts === 1) throw new Error('first factory failure');
      return chat.createChat(options);
    });
    const session = new LiveWorkspaceSession({ rest, createChat });

    await session.initialize();

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'assistant-message', text: 'Recovered answer' })
    );

    const retry = session.retryConnection();
    expect(session.current.state).toBe('reconnecting');
    await retry;

    expect(attempts).toBe(2);
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(rest.getSession).toHaveBeenCalledWith('session-1', expect.any(AbortSignal));
    expect(chat.transport.connect).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('ready');
    expect(session.current.timeline).toEqual([
      {
        kind: 'assistant-message',
        id: 'session-1:message:0',
        text: 'Recovered answer',
        model: 'Hermes 4',
        status: 'complete'
      }
    ]);
  });

  it('coalesces a reentrant factory retry so stale restore cannot create a second chat', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Recovered answer' }]);
    const chat = createChatHarness();
    let attempts = 0;
    const createChat = vi.fn((options: BrowserChatOptions) => {
      attempts += 1;
      if (attempts === 1) throw new Error('first factory failure');
      return chat.createChat(options);
    });
    const session = new LiveWorkspaceSession({ rest, createChat });
    await session.initialize();

    let nested: Promise<void> | undefined;
    let reentered = false;
    const unsubscribe = session.subscribe((snapshot) => {
      if (snapshot.state === 'reconnecting' && !reentered) {
        reentered = true;
        nested = session.retryConnection();
        void nested.catch(() => undefined);
      }
    });

    const first = session.retryConnection();
    await first;
    await nested;
    unsubscribe();

    expect(reentered).toBe(true);
    expect(attempts).toBe(2);
    expect(chat.createChat).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('ready');
  });

  it('cancels a factory retry without adopting a late active-session result', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Existing history' }]);
    const chat = createChatHarness();
    let attempts = 0;
    const createChat = vi.fn((options: BrowserChatOptions) => {
      attempts += 1;
      if (attempts === 1) throw new Error('first factory failure');
      return chat.createChat(options);
    });
    const sessionLookup = createDeferred<LiveSession>();
    vi.mocked(rest.getSession).mockImplementationOnce(() => sessionLookup.promise);
    const session = new LiveWorkspaceSession({ rest, createChat });
    await session.initialize();

    const retry = session.retryConnection();
    expect(session.current.state).toBe('reconnecting');
    session.cancelReconnect();
    sessionLookup.resolve(SESSION);
    await retry;

    expect(session.current.state).toBe('offline');
    expect(attempts).toBe(1);
    expect(chat.createChat).not.toHaveBeenCalled();
  });

  it('keeps factory retry offline when history resolves after cancellation', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Existing history' }]);
    const chat = createChatHarness();
    let attempts = 0;
    const createChat = vi.fn((options: BrowserChatOptions) => {
      attempts += 1;
      if (attempts === 1) throw new Error('first factory failure');
      return chat.createChat(options);
    });
    const lateHistory = createDeferred<SessionMessages>();
    vi.mocked(rest.getSessionMessages)
      .mockResolvedValueOnce(sessionMessages([{ role: 'assistant', content: 'Existing history' }]))
      .mockImplementationOnce(() => lateHistory.promise);
    const session = new LiveWorkspaceSession({ rest, createChat });
    await session.initialize();

    const retry = session.retryConnection();
    await flush();
    expect(rest.getSessionMessages).toHaveBeenCalledTimes(2);
    expect(session.current.state).toBe('reconnecting');

    session.cancelReconnect();
    lateHistory.resolve(sessionMessages([{ role: 'assistant', content: 'Late history' }]));
    await retry;

    expect(session.current.state).toBe('offline');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'assistant-message', text: 'Existing history' })
    );
    expect(session.current.timeline).not.toContainEqual(
      expect.objectContaining({ text: 'Late history' })
    );
    expect(attempts).toBe(1);
    expect(chat.createChat).not.toHaveBeenCalled();
  });

  it('closes a connect result once when invalidation races an abort-ignoring connector', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const connect = createDeferred<void>();
    vi.mocked(chat.transport.connect).mockImplementation(() => connect.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    const initialization = session.initialize();
    await flush();

    session.invalidate();
    connect.resolve();
    await initialization;

    expect(chat.transport.close).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('loading');
  });

  it('supersedes an older retry when a second retry starts', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Existing history' }]);
    const chat = createChatHarness();
    const firstReconnect = createDeferred<void>();
    const secondReconnect = createDeferred<void>();
    vi.mocked(chat.transport.reconnect)
      .mockImplementationOnce(() => firstReconnect.promise)
      .mockImplementationOnce(() => secondReconnect.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockClear();

    const first = session.retryConnection();
    await flush();
    const second = session.retryConnection();
    firstReconnect.resolve();
    await first;
    expect(session.current.state).toBe('reconnecting');

    secondReconnect.resolve();
    await second;
    expect(chat.transport.reconnect).toHaveBeenCalledTimes(2);
    expect(session.current.state).toBe('ready');
  });

  it('lets a reentrant retry subscriber own one effective reconnect', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Existing history' }]);
    const chat = createChatHarness();
    const reconnect = createDeferred<void>();
    vi.mocked(chat.transport.reconnect).mockImplementation(() => reconnect.promise);
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    let nested: Promise<void> | undefined;
    let reentered = false;
    const unsubscribe = session.subscribe((snapshot) => {
      if (snapshot.state === 'reconnecting' && !reentered) {
        reentered = true;
        nested = session.retryConnection();
        void nested.catch(() => undefined);
      }
    });

    const first = session.retryConnection();
    reconnect.resolve();
    await first;
    await nested;
    unsubscribe();

    expect(reentered).toBe(true);
    expect(chat.transport.reconnect).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('ready');
  });

  it('ignores an old prompt failure after reconnect owns a newer prompt', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    session.sendPrompt('old prompt');
    const oldRequest = chat.sendPrompt.mock.results[0]?.value as JsonRpcChatRequest;
    await session.retryConnection();
    session.sendPrompt('new prompt');
    chat.reject(new Error('late old prompt failure'), oldRequest.id);
    await flush();

    expect(session.current.state).toBe('streaming');
    expect(JSON.stringify(session.current.timeline)).not.toContain('late old prompt failure');
  });

  it('ignores an old prompt failure while reconnect history is pending', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const refresh = createDeferred<SessionMessages>();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockClear();
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);

    session.sendPrompt('old prompt');
    const oldRequest = chat.sendPrompt.mock.results[0]?.value as JsonRpcChatRequest;
    const retry = session.retryConnection();
    await flush();
    chat.reject(new Error('late history prompt failure'), oldRequest.id);
    await flush();
    expect(session.current.state).toBe('reconnecting');

    refresh.resolve(sessionMessages([{ role: 'assistant', content: 'reconnect history' }]));
    await retry;
    expect(session.current.state).toBe('ready');
    expect(JSON.stringify(session.current.timeline)).toContain('reconnect history');
    expect(JSON.stringify(session.current.timeline)).not.toContain('late history prompt failure');
  });

  it('keeps same-turn classified closes from starting completion history', async () => {
    for (const closeCode of [4401, 4403] as const) {
      const rest = createRest([]);
      const { session, socket } = await createConnectedSocketWorkspace(rest);
      vi.mocked(rest.getSessionMessages).mockClear();

      session.sendPrompt(`same-turn close ${closeCode}`);
      const requestId = latestPromptId(socket);
      socket.emitEvent('message.complete', requestId, { text: 'completed before close' });
      socket.emitClose(closeCode, 'redacted');
      await flush();

      expect(rest.getSessionMessages).not.toHaveBeenCalled();
      expect(session.current.state).toBe('permanent-error');
    }
  });

  it('starts completion history after a same-turn generic close', async () => {
    const rest = createRest([]);
    const refresh = createDeferred<SessionMessages>();
    const { session, socket } = await createConnectedSocketWorkspace(rest);
    vi.mocked(rest.getSessionMessages).mockClear();
    vi.mocked(rest.getSessionMessages).mockImplementationOnce(() => refresh.promise);

    session.sendPrompt('same-turn generic close');
    const requestId = latestPromptId(socket);
    socket.emitEvent('message.complete', requestId, { text: 'completed before close' });
    socket.emitClose(1011, 'redacted');
    await flush();

    expect(rest.getSessionMessages).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('ready');

    refresh.resolve(sessionMessages([{ role: 'assistant', content: 'same-turn history' }]));
    await flush();

    expect(session.current.state).toBe('ready');
    expect(session.current.timeline).toContainEqual(
      expect.objectContaining({ kind: 'assistant-message', text: 'same-turn history' })
    );
  });

  it('lets an explicit retry own the same-turn completion before history refresh starts', async () => {
    const rest = createRest([]);
    const { session, socket } = await createConnectedSocketWorkspace(rest);
    vi.mocked(rest.getSessionMessages).mockClear();

    session.sendPrompt('same-turn retry');
    const requestId = latestPromptId(socket);
    socket.emitEvent('message.complete', requestId, { text: 'completed before retry' });
    const retry = session.retryConnection();
    await flush();
    socket.emitOpen();
    socket.emitGatewayReady();
    await flush();
    const resume = [...socket.sent]
      .reverse()
      .map((raw) => JSON.parse(raw) as { id?: string; method?: string })
      .find((frame) => frame.method === 'session.resume');
    if (!resume?.id) throw new Error('reconnect resume frame was not sent');
    socket.emitResponse(resume.id);
    await retry;

    expect(rest.getSessionMessages).toHaveBeenCalledTimes(1);
    expect(session.current.state).toBe('empty');
  });

  it('aborts pending reconnect history on invalidation and suppresses late success', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Existing history' }]);
    const chat = createChatHarness();
    const history = createDeferred<SessionMessages>();
    let historySignal: AbortSignal | undefined;
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockClear();
    vi.mocked(rest.getSessionMessages).mockImplementationOnce((_id, _options, signal) => {
      historySignal = signal;
      return history.promise;
    });

    const retry = session.retryConnection();
    await flush();
    expect(historySignal).toBeInstanceOf(AbortSignal);
    session.invalidate();
    expect(historySignal?.aborted).toBe(true);
    history.resolve(sessionMessages([{ role: 'assistant', content: 'late reconnect success' }]));
    await retry;

    expect(session.current.state).toBe('loading');
    expect(JSON.stringify(session.current.timeline)).not.toContain('late reconnect success');
  });

  it('aborts pending reconnect history on disposal and suppresses late failure', async () => {
    const rest = createRest([{ role: 'assistant', content: 'Existing history' }]);
    const chat = createChatHarness();
    const history = createDeferred<SessionMessages>();
    let historySignal: AbortSignal | undefined;
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();
    vi.mocked(rest.getSessionMessages).mockClear();
    vi.mocked(rest.getSessionMessages).mockImplementationOnce((_id, _options, signal) => {
      historySignal = signal;
      return history.promise;
    });

    const retry = session.retryConnection();
    await flush();
    expect(historySignal).toBeInstanceOf(AbortSignal);
    session.dispose();
    expect(historySignal?.aborted).toBe(true);
    history.reject(new Error('late reconnect failure'));
    await retry;

    expect(session.current.state).toBe('loading');
    expect(session.current.timeline).toEqual([]);
  });
});
