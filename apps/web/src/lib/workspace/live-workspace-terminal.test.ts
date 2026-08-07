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

function sessionMessages(messages: LiveMessage[] = []): SessionMessages {
  return {
    sessionId: SESSION.id,
    messages,
    pagination: { limit: 500, offset: 0, returned: messages.length }
  };
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
} {
  const state: JsonRpcConnectionState = { status: 'ready', generation: 1 };
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
  const createChat = vi.fn((_: BrowserChatOptions) => transport);
  return { createChat, transport };
}

function createPtyHarness(): {
  readonly pty: PtyTransport;
  readonly connect: ReturnType<typeof vi.fn>;
  readonly close: ReturnType<typeof vi.fn>;
  readonly detach: ReturnType<typeof vi.fn>;
  emit(event: PtyTransportEvent): void;
} {
  const listeners = new Set<(event: PtyTransportEvent) => void>();
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
    state = { ...state, status: 'detached' };
    emit({ type: 'state', state });
  });
  const close = vi.fn(() => {
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
  return { pty, connect, close, detach, emit };
}

async function createInitializedWorkspace() {
  const rest = createRest();
  const chat = createChatHarness();
  const pty = createPtyHarness();
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
