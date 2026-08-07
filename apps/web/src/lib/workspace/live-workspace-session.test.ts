import { describe, expect, it, vi } from 'vitest';
import type { BrowserChatOptions } from '$lib/chat/browser-chat';
import {
  JsonRpcChatError,
  type JsonRpcChatEvent,
  type JsonRpcChatRequest,
  type JsonRpcCompletionEvent,
  type JsonRpcChatTransport,
  type JsonRpcConnectionState
} from '$lib/chat/json-rpc-chat';
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

function createChatHarness() {
  let options: BrowserChatOptions | undefined;
  let activeRequest: ReturnType<typeof createDeferred<JsonRpcCompletionEvent>> | undefined;
  const sendPrompt = vi.fn((prompt: string): JsonRpcChatRequest => {
    const deferred = createDeferred<JsonRpcCompletionEvent>();
    activeRequest = deferred;
    return {
      id: 'request-1',
      completion: deferred.promise,
      state: { id: 'request-1', status: 'submitting' },
      abort: vi.fn()
    };
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
    options = nextOptions;
    return transport;
  });

  return {
    createChat,
    transport,
    sendPrompt,
    emit(event: JsonRpcChatEvent) {
      options?.onEvent?.(event);
    },
    changeState(state: JsonRpcConnectionState) {
      options?.onStateChange?.(state);
    },
    complete(event: JsonRpcCompletionEvent) {
      activeRequest?.resolve(event);
    },
    reject(error: unknown) {
      activeRequest?.reject(error);
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

  it('maps authentication-required chat state to a permanent workspace error', async () => {
    const rest = createRest([]);
    const chat = createChatHarness();
    const session = new LiveWorkspaceSession({ rest, createChat: chat.createChat });
    await session.initialize();

    chat.changeState({ status: 'auth_required', generation: 1 });

    expect(session.current.state).toBe('permanent-error');
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
});
