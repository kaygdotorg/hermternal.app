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
import { LiveRestError, type LiveMessage, type LiveRestTransport, type LiveSession, type SessionMessages } from '$lib/transport';
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

function sessionMessages(messages: LiveMessage[]): SessionMessages {
  return {
    sessionId: SESSION.id,
    messages,
    pagination: { limit: 500, offset: 0, returned: messages.length }
  };
}

class BrowserChatSocket implements JsonRpcWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number; readonly reason?: string }) => void) | null = null;
  readonly sent: string[] = [];

  send(data: string): void {
    this.sent.push(data);
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

  emitEvent(type: string, requestId: string, payload: Record<string, unknown> = {}): void {
    this.onmessage?.({
      data: JSON.stringify({
        jsonrpc: '2.0',
        method: 'event',
        params: { type, request_id: requestId, payload }
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
    chat.complete(completeEvent);
    await flush();
    await flush();

    expect(refreshSignal).toBeInstanceOf(AbortSignal);
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

  it('keeps a generic terminal close retryable when completion history is still pending', async () => {
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
    expect(session.current.state).toBe('retryable-error');

    refresh.resolve(sessionMessages([{ role: 'assistant', content: 'late history' }]));
    await flush();

    expect(session.current.state).toBe('retryable-error');
    expect(JSON.stringify(session.current.timeline)).not.toContain('late history');
  });

  it('keeps committed completion history visible but non-sendable after a late generic terminal callback', async () => {
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

    expect(session.current.state).toBe('retryable-error');
    expect(session.current.timeline.filter((item) => item.kind === 'assistant-message')).toEqual([
      expect.objectContaining({ text: 'Completed answer' })
    ]);
    expect(JSON.stringify(session.current)).not.toContain('redacted');

    // The committed view remains readable, but a dead transport cannot accept
    // another prompt. The next user action must surface recovery, not replay.
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

  it('keeps committed persisted history visible but non-sendable after a late generic terminal callback', async () => {
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

  it('keeps same-turn completion events from starting stale history after a terminal close', async () => {
    const cases = [
      [4401, 'permanent-error'],
      [4403, 'permanent-error'],
      [1011, 'retryable-error']
    ] as const;

    for (const [closeCode, expectedState] of cases) {
      const rest = createRest([]);
      const { session, socket } = await createConnectedSocketWorkspace(rest);
      vi.mocked(rest.getSessionMessages).mockClear();

      session.sendPrompt(`same-turn close ${closeCode}`);
      const requestId = latestPromptId(socket);
      socket.emitEvent('message.complete', requestId, { text: 'completed before close' });
      socket.emitClose(closeCode, 'redacted');
      await flush();

      expect(rest.getSessionMessages).not.toHaveBeenCalled();
      expect(session.current.state).toBe(expectedState);
    }
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
