import { describe, expect, it, vi } from 'vitest';
import {
  PINNED_DASHBOARD_CONTRACT,
  PINNED_HERMES_SOURCE_SHA,
  SessionCoordinatorError,
  createSessionCoordinator,
  type ChatSessionPort,
  type TerminalBinding,
  type TerminalSessionPort
} from './coordinator';
import type { JsonRpcConnectionStatus } from '../chat/json-rpc-chat';

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

async function flush(): Promise<void> {
  for (let index = 0; index < 20; index += 1) await Promise.resolve();
}

interface FakeChatHarness {
  chat: ChatSessionPort;
  connect: ReturnType<typeof vi.fn>;
  reconnect: ReturnType<typeof vi.fn>;
  restore: ReturnType<typeof vi.fn>;
  close: ReturnType<typeof vi.fn>;
  get status(): JsonRpcConnectionStatus;
  set status(value: JsonRpcConnectionStatus);
  get selectedSessionId(): string | undefined;
}

function createFakeChat(
  initialSessionId = 'session-old',
  initialStatus: JsonRpcConnectionStatus = 'ready'
): FakeChatHarness {
  let status = initialStatus;
  let selectedSessionId: string | undefined = initialSessionId;
  let generation = 1;
  const connect = vi.fn(async (signal: AbortSignal) => {
    if (signal.aborted) throw new SessionCoordinatorError('aborted');
    status = 'ready';
    generation += 1;
  });
  const reconnect = vi.fn(async (signal: AbortSignal) => {
    if (signal.aborted) throw new SessionCoordinatorError('aborted');
    status = 'ready';
    generation += 1;
  });
  const restore = vi.fn(async (sessionId: string, signal: AbortSignal) => {
    if (signal.aborted) throw new SessionCoordinatorError('aborted');
    selectedSessionId = sessionId;
    status = 'ready';
  });
  const close = vi.fn(() => {
    status = 'offline';
  });
  return {
    chat: {
      get state() {
        return { status, generation };
      },
      get selectedSessionId() {
        return selectedSessionId;
      },
      connect,
      reconnect,
      restore,
      close
    },
    connect,
    reconnect,
    restore,
    close,
    get status() {
      return status;
    },
    set status(value: JsonRpcConnectionStatus) {
      status = value;
    },
    get selectedSessionId() {
      return selectedSessionId;
    }
  };
}

interface FakeTerminalHarness {
  terminal: TerminalSessionPort;
  attach: ReturnType<typeof vi.fn>;
  release: ReturnType<typeof vi.fn>;
  deferNext(sessionId: string): { deferred: Deferred<TerminalBinding>; binding: TerminalBinding };
  rejectNext(sessionId: string): Deferred<TerminalBinding>;
}

type AttachPlan =
  | { kind: 'deferred'; deferred: Deferred<TerminalBinding>; binding: TerminalBinding }
  | { kind: 'rejected'; deferred: Deferred<TerminalBinding> };

function createFakeTerminal(): FakeTerminalHarness {
  const plans = new Map<string, AttachPlan[]>();
  const release = vi.fn();
  const enqueue = (sessionId: string, plan: AttachPlan): void => {
    const queue = plans.get(sessionId) ?? [];
    queue.push(plan);
    plans.set(sessionId, queue);
  };
  const makeBinding = (sessionId: string): TerminalBinding => ({
    sessionId,
    invalidate: vi.fn()
  });
  const attach = vi.fn(async (sessionId: string, signal: AbortSignal): Promise<TerminalBinding> => {
    const [plan, ...remaining] = plans.get(sessionId) ?? [];
    if (remaining.length > 0) plans.set(sessionId, remaining);
    else plans.delete(sessionId);
    if (signal.aborted) throw new SessionCoordinatorError('aborted');
    if (plan?.kind === 'rejected') return plan.deferred.promise;
    if (plan?.kind === 'deferred') return plan.deferred.promise;
    return makeBinding(sessionId);
  });
  return {
    terminal: { attach, release },
    attach,
    release,
    deferNext(sessionId) {
      const binding = makeBinding(sessionId);
      const pending = deferred<TerminalBinding>();
      enqueue(sessionId, { kind: 'deferred', deferred: pending, binding });
      return { deferred: pending, binding };
    },
    rejectNext(sessionId) {
      const pending = deferred<TerminalBinding>();
      enqueue(sessionId, { kind: 'rejected', deferred: pending });
      return pending;
    }
  };
}

function compatibleDeployment() {
  return {
    status: 'compatible' as const,
    contract: PINNED_DASHBOARD_CONTRACT,
    hermesSourceSha: PINNED_HERMES_SOURCE_SHA
  };
}

function createCoordinator(
  chat: FakeChatHarness = createFakeChat(),
  terminal: FakeTerminalHarness = createFakeTerminal(),
  extra: Partial<Parameters<typeof createSessionCoordinator>[0]> = {}
) {
  return {
    coordinator: createSessionCoordinator({
      chat: chat.chat,
      terminal: terminal.terminal,
      deployment: compatibleDeployment(),
      initialSessionId: 'session-old',
      ...extra
    }),
    chat,
    terminal
  };
}

describe('createSessionCoordinator', () => {
  it('switches Chat to Terminal without changing the selected session', async () => {
    const focus: string[] = [];
    const harness = createCoordinator(undefined, undefined, {
      onFocusIntent: (intent) => focus.push(intent.target)
    });

    await harness.coordinator.activate('chat');
    await harness.coordinator.activate('terminal');

    expect(harness.coordinator.activeSessionId).toBe('session-old');
    expect(harness.terminal.attach).toHaveBeenCalledTimes(1);
    expect(harness.terminal.attach).toHaveBeenCalledWith('session-old', expect.any(AbortSignal));
    expect(focus).toEqual(['composer', 'w-term-input']);
  });

  it('switches Terminal to Chat with the same binding and session', async () => {
    const harness = createCoordinator();

    await harness.coordinator.activate('terminal');
    await harness.coordinator.activate('chat');

    expect(harness.coordinator.activeSessionId).toBe('session-old');
    expect(harness.chat.connect).not.toHaveBeenCalled();
    expect(harness.chat.restore).not.toHaveBeenCalled();
    expect(harness.terminal.attach).toHaveBeenCalledTimes(1);
    expect(harness.coordinator.state.focusIntent).toMatchObject({
      mode: 'chat',
      target: 'composer',
      sessionId: 'session-old'
    });
  });

  it('coalesces rapid repeated switching and does not duplicate a Terminal attach', async () => {
    const harness = createCoordinator();
    const pending = harness.terminal.deferNext('session-old');

    const first = harness.coordinator.activate('terminal');
    await flush();
    const second = harness.coordinator.activate('terminal');
    const throughChat = harness.coordinator.activate('chat');
    const backToTerminal = harness.coordinator.activate('terminal');

    expect(harness.terminal.attach).toHaveBeenCalledTimes(1);
    pending.deferred.resolve(pending.binding);
    await Promise.all([first, second, throughChat, backToTerminal]);

    expect(harness.terminal.attach).toHaveBeenCalledTimes(1);
    expect(harness.coordinator.state.terminalSessionId).toBe('session-old');
  });

  it('replaces the session while Chat is active and restores only the server session', async () => {
    const harness = createCoordinator();
    await harness.coordinator.activate('chat');

    await harness.coordinator.setSession('session-new');

    expect(harness.chat.restore).toHaveBeenCalledTimes(1);
    expect(harness.chat.restore).toHaveBeenCalledWith('session-new', expect.any(AbortSignal));
    expect(harness.coordinator.state.activeSessionId).toBe('session-new');
    expect(harness.terminal.attach).not.toHaveBeenCalled();
    expect('transcript' in harness.coordinator.state).toBe(false);
    expect('messages' in harness.coordinator.state).toBe(false);
  });

  it('replaces the session while Terminal is active and invalidates the old binding', async () => {
    const harness = createCoordinator();
    await harness.coordinator.activate('terminal');
    const oldBinding = harness.terminal.attach.mock.results[0]?.value as Promise<TerminalBinding>;
    expect(oldBinding).toBeInstanceOf(Promise);
    const oldInvalidation = harness.coordinator.state.terminalSessionId;

    await harness.coordinator.setSession('session-new');

    expect(harness.terminal.attach).toHaveBeenCalledTimes(2);
    expect(harness.coordinator.state.activeSessionId).toBe('session-new');
    expect(harness.coordinator.state.terminalSessionId).toBe('session-new');
    expect(oldInvalidation).toBe('session-old');
    const firstBinding = await oldBinding;
    expect(firstBinding.invalidate).toHaveBeenCalledTimes(1);
  });

  it('contains Terminal attach failure without closing or poisoning Chat', async () => {
    const chat = createFakeChat();
    const terminal = createFakeTerminal();
    const failed = terminal.rejectNext('session-old');
    const { coordinator } = createCoordinator(chat, terminal);

    failed.reject(new Error('untrusted terminal adapter detail'));
    await expect(coordinator.activate('terminal')).rejects.toMatchObject({
      code: 'terminal-attach-failed'
    });
    expect(chat.status).toBe('ready');
    expect(chat.close).not.toHaveBeenCalled();
    expect(coordinator.state.status).toBe('terminal-attach-failed');

    await coordinator.activate('chat');
    expect(coordinator.state.focusIntent?.target).toBe('composer');
    expect(chat.status).toBe('ready');
  });

  it('coalesces Chat reconnect and keeps an attached Terminal binding', async () => {
    const harness = createCoordinator();
    await harness.coordinator.activate('terminal');
    const pending = deferred<void>();
    harness.chat.reconnect.mockImplementationOnce(async (signal: AbortSignal) => {
      if (signal.aborted) throw new SessionCoordinatorError('aborted');
      await pending.promise;
      harness.chat.status = 'ready';
    });

    const first = harness.coordinator.reconnect();
    const second = harness.coordinator.reconnect();
    await flush();
    expect(harness.chat.reconnect).toHaveBeenCalledTimes(1);
    pending.resolve();
    await Promise.all([first, second]);

    expect(harness.terminal.attach).toHaveBeenCalledTimes(1);
    expect(harness.coordinator.state.terminalSessionId).toBe('session-old');
  });

  it('invalidates a stale Terminal completion from the previous session', async () => {
    const harness = createCoordinator();
    const oldAttach = harness.terminal.deferNext('session-old');
    const oldActivation = harness.coordinator.activate('terminal');
    await flush();

    const newAttach = harness.terminal.deferNext('session-new');
    const replacement = harness.coordinator.setSession('session-new');
    await flush();
    oldAttach.deferred.resolve(oldAttach.binding);
    await flush();
    expect(oldAttach.binding.invalidate).toHaveBeenCalledTimes(1);
    expect(harness.coordinator.state.terminalSessionId).not.toBe('session-old');

    newAttach.deferred.resolve(newAttach.binding);
    await Promise.all([oldActivation, replacement]);
    expect(harness.coordinator.state.terminalSessionId).toBe('session-new');
    expect(newAttach.binding.invalidate).not.toHaveBeenCalled();
  });

  it('restores a selected server session after refresh without creating a transcript mirror', async () => {
    const harness = createCoordinator();

    await harness.coordinator.restore('session-old');

    expect(harness.chat.restore).toHaveBeenCalledTimes(1);
    expect(harness.terminal.attach).not.toHaveBeenCalled();
    expect(Object.keys(harness.coordinator.state)).not.toContain('transcript');
    expect(Object.keys(harness.coordinator.state)).not.toContain('messages');
  });

  it('invalidates Terminal and closes Chat on logout and disposal', async () => {
    const logoutHarness = createCoordinator();
    await logoutHarness.coordinator.activate('terminal');
    const logoutBinding = await logoutHarness.terminal.attach.mock.results[0]!.value;
    logoutHarness.coordinator.logout();
    expect(logoutBinding.invalidate).toHaveBeenCalledTimes(1);
    expect(logoutHarness.chat.close).toHaveBeenCalledTimes(1);
    expect(logoutHarness.coordinator.state.status).toBe('logged-out');
    await expect(logoutHarness.coordinator.activate('chat')).rejects.toMatchObject({ code: 'logged-out' });

    const disposeHarness = createCoordinator();
    await disposeHarness.coordinator.activate('terminal');
    const disposeBinding = await disposeHarness.terminal.attach.mock.results[0]!.value;
    disposeHarness.coordinator.dispose();
    disposeHarness.coordinator.dispose();
    expect(disposeBinding.invalidate).toHaveBeenCalledTimes(1);
    expect(disposeHarness.chat.close).toHaveBeenCalledTimes(1);
    expect(disposeHarness.coordinator.state.status).toBe('disposed');
  });

  it('fails closed for unknown, incompatible, and mismatched deployments', async () => {
    const deployments = [
      { status: 'unknown' as const },
      { status: 'incompatible' as const },
      {
        status: 'compatible' as const,
        contract: 'dashboard-future',
        hermesSourceSha: PINNED_HERMES_SOURCE_SHA
      }
    ];

    for (const deployment of deployments) {
      const harness = createCoordinator(undefined, undefined, { deployment });
      expect(harness.coordinator.state.status).toBe('blocked');
      expect(harness.coordinator.activeSessionId).toBeUndefined();
      await expect(harness.coordinator.activate('chat')).rejects.toMatchObject({
        code: deployment.status === 'unknown' ? 'unknown-deployment' : 'incompatible-deployment'
      });
      expect(harness.chat.connect).not.toHaveBeenCalled();
      expect(harness.terminal.attach).not.toHaveBeenCalled();
    }
  });

  it('keeps focus semantics unchanged when reduced motion is requested', async () => {
    const normal = createCoordinator(undefined, undefined, { reducedMotion: false });
    const reduced = createCoordinator(undefined, undefined, { reducedMotion: true });

    await normal.coordinator.activate('chat');
    await reduced.coordinator.activate('chat');

    expect(normal.coordinator.state.focusIntent?.target).toBe('composer');
    expect(reduced.coordinator.state.focusIntent?.target).toBe('composer');
    expect(normal.coordinator.state.mode).toBe(reduced.coordinator.state.mode);
    expect(normal.coordinator.state.activeSessionId).toBe(reduced.coordinator.state.activeSessionId);
  });
});
