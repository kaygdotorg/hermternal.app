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
  events: string[];
  deferNext(
    sessionId: string,
    binding?: TerminalBinding
  ): { deferred: Deferred<TerminalBinding>; binding: TerminalBinding };
  rejectNext(sessionId: string): Deferred<TerminalBinding>;
}

type AttachPlan =
  | { kind: 'deferred'; deferred: Deferred<TerminalBinding>; binding: TerminalBinding }
  | { kind: 'rejected'; deferred: Deferred<TerminalBinding> };

function createFakeTerminal(): FakeTerminalHarness {
  const plans = new Map<string, AttachPlan[]>();
  const events: string[] = [];
  const release = vi.fn((binding: TerminalBinding) => {
    events.push(`release:${binding.sessionId}`);
  });
  const enqueue = (sessionId: string, plan: AttachPlan): void => {
    const queue = plans.get(sessionId) ?? [];
    queue.push(plan);
    plans.set(sessionId, queue);
  };
  const makeBinding = (sessionId: string): TerminalBinding => {
    const binding = {
      sessionId,
      invalidate: vi.fn(() => {
        events.push(`invalidate:${binding.sessionId}`);
      })
    };
    return binding;
  };
  const attach = vi.fn(async (sessionId: string, signal: AbortSignal): Promise<TerminalBinding> => {
    const [plan, ...remaining] = plans.get(sessionId) ?? [];
    if (remaining.length > 0) plans.set(sessionId, remaining);
    else plans.delete(sessionId);
    if (signal.aborted) throw new SessionCoordinatorError('aborted');
    if (plan?.kind === 'rejected') return plan.deferred.promise;
    if (plan?.kind === 'deferred') {
      (plan.binding as TerminalBinding & { sessionId: string }).sessionId = sessionId;
      return plan.deferred.promise;
    }
    return makeBinding(sessionId);
  });
  return {
    terminal: { attach, release },
    attach,
    release,
    events,
    deferNext(sessionId, binding = makeBinding(sessionId)) {
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

function expectInvalidatedThenReleased(terminal: FakeTerminalHarness, binding: TerminalBinding): void {
  expect(binding.invalidate).toHaveBeenCalledTimes(1);
  expect(terminal.release).toHaveBeenCalledTimes(1);
  expect(terminal.release).toHaveBeenCalledWith(binding);
  expect(terminal.events).toEqual([
    `invalidate:${binding.sessionId}`,
    `release:${binding.sessionId}`
  ]);
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

  it('keeps a deferred Terminal binding attached without a late W-Term focus after switching to Chat', async () => {
    const focus: Array<{ mode: string; target: string }> = [];
    const harness = createCoordinator(undefined, undefined, {
      onFocusIntent: (intent) => focus.push(intent)
    });
    const pending = harness.terminal.deferNext('session-old');

    const terminalActivation = harness.coordinator.activate('terminal');
    await flush();
    const chatActivation = harness.coordinator.activate('chat');
    await chatActivation;

    expect(focus).toEqual([expect.objectContaining({ mode: 'chat', target: 'composer' })]);
    pending.deferred.resolve(pending.binding);
    await terminalActivation;

    expect(focus).toEqual([expect.objectContaining({ mode: 'chat', target: 'composer' })]);
    expect(harness.coordinator.state.mode).toBe('chat');
    expect(harness.coordinator.state.terminalStatus).toBe('attached');
    expect(harness.coordinator.state.terminalSessionId).toBe('session-old');
    expect(pending.binding.invalidate).not.toHaveBeenCalled();
    expect(harness.terminal.release).not.toHaveBeenCalled();
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

  it('gives one focus intent to the latest request during a pending Terminal attach', async () => {
    const focus: Array<{ mode: string; target: string; sequence: number }> = [];
    const harness = createCoordinator(undefined, undefined, {
      onFocusIntent: (intent) => focus.push(intent)
    });
    const pending = harness.terminal.deferNext('session-old');

    const firstTerminal = harness.coordinator.activate('terminal');
    await flush();
    const throughChat = harness.coordinator.activate('chat');
    const backToTerminal = harness.coordinator.activate('terminal');

    expect(harness.terminal.attach).toHaveBeenCalledTimes(1);
    pending.deferred.resolve(pending.binding);
    await Promise.all([firstTerminal, throughChat, backToTerminal]);

    expect(focus).toEqual([
      expect.objectContaining({
        mode: 'chat',
        target: 'composer',
        sessionId: 'session-old',
        sessionGeneration: 1,
        sequence: 1
      }),
      expect.objectContaining({
        mode: 'terminal',
        target: 'w-term-input',
        sessionId: 'session-old',
        sessionGeneration: 1,
        sequence: 2
      })
    ]);
    expect(harness.coordinator.state.focusIntent?.target).toBe('w-term-input');
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

  it('synchronously revokes the selected session and Terminal lease before asynchronous replacement', async () => {
    const harness = createCoordinator();
    await harness.coordinator.activate('terminal');
    const binding = await harness.terminal.attach.mock.results[0]!.value;
    const previousGeneration = harness.coordinator.state.sessionGeneration;

    harness.coordinator.invalidateSession();

    expectInvalidatedThenReleased(harness.terminal, binding);
    expect(harness.coordinator.state).toMatchObject({
      status: 'empty',
      terminalStatus: 'detached',
      sessionGeneration: previousGeneration + 1
    });
    expect(harness.coordinator.activeSessionId).toBeUndefined();
    expect(harness.chat.restore).not.toHaveBeenCalled();
    expect(harness.chat.connect).not.toHaveBeenCalled();
  });

  it('fences same-ID replacement settlement by both session identity and generation', async () => {
    const harness = createCoordinator();
    await harness.coordinator.activate('terminal');
    const oldBinding = await harness.terminal.attach.mock.results[0]!.value;
    const oldSettlement = {
      sessionId: 'session-old',
      sessionGeneration: harness.coordinator.state.sessionGeneration
    };

    harness.coordinator.invalidateSession();
    await harness.coordinator.setSession('session-old');
    const replacementBinding = await harness.terminal.attach.mock.results[1]!.value;

    expect(harness.coordinator.invalidateTerminalBinding(oldSettlement)).toBe(false);
    expect(harness.coordinator.state).toMatchObject({
      activeSessionId: 'session-old',
      terminalSessionId: 'session-old',
      terminalStatus: 'attached',
      sessionGeneration: oldSettlement.sessionGeneration + 2
    });
    expect(oldBinding.invalidate).toHaveBeenCalledTimes(1);
    expect(replacementBinding.invalidate).not.toHaveBeenCalled();
  });

  it('clears only stale Terminal focus when a detached lease settles after Chat focus', async () => {
    const focus: string[] = [];
    const harness = createCoordinator(undefined, undefined, {
      onFocusIntent: (intent) => focus.push(intent.target)
    });
    await harness.coordinator.activate('terminal');
    const settlement = {
      sessionId: 'session-old',
      sessionGeneration: harness.coordinator.state.sessionGeneration
    };
    await harness.coordinator.activate('chat');

    expect(harness.coordinator.invalidateTerminalBinding(settlement)).toBe(true);

    expect(focus).toEqual(['w-term-input', 'composer']);
    expect(harness.coordinator.state).toMatchObject({
      mode: 'chat',
      terminalStatus: 'detached',
      focusIntent: { target: 'composer' }
    });
  });

  it('reacquires Terminal without asynchronous Chat selection and focuses the recovered lease', async () => {
    const focus: Array<{ target: string; sessionGeneration: number }> = [];
    const harness = createCoordinator(undefined, undefined, {
      onFocusIntent: (intent) => focus.push(intent)
    });
    await harness.coordinator.activate('terminal');
    const settlement = {
      sessionId: 'session-old',
      sessionGeneration: harness.coordinator.state.sessionGeneration
    };
    const restoreCalls = harness.chat.restore.mock.calls.length;
    const reconnectCalls = harness.chat.reconnect.mock.calls.length;

    expect(harness.coordinator.invalidateTerminalBinding(settlement)).toBe(true);
    await harness.coordinator.reconnectTerminal();

    expect(harness.chat.restore).toHaveBeenCalledTimes(restoreCalls);
    expect(harness.chat.reconnect).toHaveBeenCalledTimes(reconnectCalls);
    expect(harness.terminal.attach).toHaveBeenCalledTimes(2);
    expect(focus.map((intent) => intent.target)).toEqual(['w-term-input', 'w-term-input']);
    expect(focus.at(-1)).toMatchObject({ sessionGeneration: settlement.sessionGeneration });
  });

  it('fences a settled Terminal lease from its same-generation reconnect replacement', async () => {
    const harness = createCoordinator();
    await harness.coordinator.activate('terminal');
    const settlementA = {
      sessionId: 'session-old',
      sessionGeneration: harness.coordinator.state.sessionGeneration,
      terminalLeaseSequence: harness.coordinator.state.terminalLeaseSequence
    };

    expect(harness.coordinator.invalidateTerminalBinding(settlementA)).toBe(true);
    await harness.coordinator.reconnectTerminal();
    const bindingB = await harness.terminal.attach.mock.results[1]!.value;
    const settlementB = {
      sessionId: 'session-old',
      sessionGeneration: harness.coordinator.state.sessionGeneration,
      terminalLeaseSequence: harness.coordinator.state.terminalLeaseSequence
    };

    expect(settlementB.sessionGeneration).toBe(settlementA.sessionGeneration);
    expect(settlementB.terminalLeaseSequence).not.toBe(settlementA.terminalLeaseSequence);
    expect(
      harness.coordinator.invalidateTerminalBinding({
        sessionId: settlementA.sessionId,
        sessionGeneration: settlementA.sessionGeneration
      })
    ).toBe(false);
    expect(harness.coordinator.invalidateTerminalBinding(settlementA)).toBe(false);
    expect(bindingB.invalidate).not.toHaveBeenCalled();
    expect(harness.terminal.release).toHaveBeenCalledTimes(1);
    expect(harness.coordinator.invalidateTerminalBinding(settlementB)).toBe(true);
    expect(harness.coordinator.invalidateTerminalBinding(settlementB)).toBe(false);
    expect(bindingB.invalidate).toHaveBeenCalledTimes(1);
    expect(harness.terminal.release).toHaveBeenCalledTimes(2);
    expect(harness.terminal.release).toHaveBeenLastCalledWith(bindingB);
  });

  it('does not let a stale settlement cancel a same-generation reconnect attachment', async () => {
    const harness = createCoordinator();
    await harness.coordinator.activate('terminal');
    const settlementA = {
      sessionId: 'session-old',
      sessionGeneration: harness.coordinator.state.sessionGeneration,
      terminalLeaseSequence: harness.coordinator.state.terminalLeaseSequence
    };
    expect(harness.coordinator.invalidateTerminalBinding(settlementA)).toBe(true);

    const pendingB = harness.terminal.deferNext('session-old');
    const reconnectB = harness.coordinator.reconnectTerminal();
    await flush();

    expect(harness.coordinator.state.terminalLeaseSequence).not.toBe(settlementA.terminalLeaseSequence);
    expect(harness.coordinator.invalidateTerminalBinding(settlementA)).toBe(false);
    pendingB.deferred.resolve(pendingB.binding);
    await reconnectB;

    expect(harness.coordinator.state).toMatchObject({
      terminalStatus: 'attached',
      terminalLeaseSequence: expect.any(Number)
    });
    expect(pendingB.binding.invalidate).not.toHaveBeenCalled();
    expect(harness.terminal.release).toHaveBeenCalledTimes(1);
  });

  it('does not let an old recovery settlement revoke a rapid same-ID reselect lease', async () => {
    const harness = createCoordinator();
    await harness.coordinator.activate('terminal');
    const oldSettlement = {
      sessionId: 'session-old',
      sessionGeneration: harness.coordinator.state.sessionGeneration
    };
    expect(harness.coordinator.invalidateTerminalBinding(oldSettlement)).toBe(true);

    const recovering = harness.terminal.deferNext('session-old');
    const recovery = harness.coordinator.reconnectTerminal();
    await flush();
    harness.coordinator.invalidateSession();

    const replacement = harness.coordinator.setSession('session-old');
    await flush();
    const replacementBinding = await harness.terminal.attach.mock.results[2]!.value;
    await replacement;

    expect(harness.coordinator.invalidateTerminalBinding(oldSettlement)).toBe(false);
    recovering.deferred.resolve(recovering.binding);
    await recovery;

    expect(harness.coordinator.state).toMatchObject({
      activeSessionId: 'session-old',
      terminalSessionId: 'session-old',
      terminalStatus: 'attached',
      sessionGeneration: oldSettlement.sessionGeneration + 2
    });
    expect(replacementBinding.invalidate).not.toHaveBeenCalled();
    expect(recovering.binding.invalidate).toHaveBeenCalledTimes(1);
    expect(harness.terminal.release.mock.calls.filter(([binding]) => binding === recovering.binding)).toHaveLength(1);
  });

  it('accepts a synchronous observer settlement for the published attaching lease', async () => {
    const chat = createFakeChat();
    const terminal = createFakeTerminal();
    const pending = terminal.deferNext('session-old');
    let coordinator!: ReturnType<typeof createSessionCoordinator>;
    let settlementAccepted: boolean | undefined;

    coordinator = createSessionCoordinator({
      chat: chat.chat,
      terminal: terminal.terminal,
      deployment: compatibleDeployment(),
      initialSessionId: 'session-old',
      onStateChange: (nextState) => {
        if (settlementAccepted !== undefined || nextState.terminalStatus !== 'attaching') return;
        settlementAccepted = coordinator.invalidateTerminalBinding({
          sessionId: nextState.activeSessionId!,
          sessionGeneration: nextState.sessionGeneration,
          terminalLeaseSequence: nextState.terminalLeaseSequence!
        });
      }
    });

    const activation = coordinator.activate('terminal');
    await flush();

    expect(settlementAccepted).toBe(true);
    expect(terminal.attach).toHaveBeenCalledTimes(1);
    expect(coordinator.state).toMatchObject({
      activeSessionId: 'session-old',
      terminalStatus: 'detached'
    });
    expect(coordinator.state).not.toHaveProperty('terminalSessionId');
    expect(coordinator.state).not.toHaveProperty('terminalLeaseSequence');

    // The adapter had already begun attaching; its late completion must clean up
    // rather than restoring the lease the synchronous observer revoked.
    pending.deferred.resolve(pending.binding);
    await activation;

    expectInvalidatedThenReleased(terminal, pending.binding);
    expect(coordinator.state).toMatchObject({ terminalStatus: 'detached' });
    expect(coordinator.state).not.toHaveProperty('terminalSessionId');
  });

  it.each(['invalidate', 'release'] as const)(
    'preserves nested session invalidation when Terminal %s cleanup reenters',
    async (cleanupPoint) => {
      const harness = createCoordinator();
      await harness.coordinator.activate('terminal');
      const binding = await harness.terminal.attach.mock.results[0]!.value;
      const settlement = {
        sessionId: 'session-old',
        sessionGeneration: harness.coordinator.state.sessionGeneration,
        terminalLeaseSequence: harness.coordinator.state.terminalLeaseSequence
      };
      const generation = harness.coordinator.state.sessionGeneration;

      if (cleanupPoint === 'invalidate') {
        vi.spyOn(binding, 'invalidate').mockImplementation(() => harness.coordinator.invalidateSession());
      } else {
        harness.terminal.release.mockImplementationOnce(() => harness.coordinator.invalidateSession());
      }

      expect(harness.coordinator.invalidateTerminalBinding(settlement)).toBe(false);

      expect(binding.invalidate).toHaveBeenCalledTimes(1);
      expect(harness.terminal.release).toHaveBeenCalledTimes(1);
      expect(harness.coordinator.state).toMatchObject({
        status: 'empty',
        mode: 'terminal',
        terminalStatus: 'detached',
        sessionGeneration: generation + 1
      });
      expect(harness.coordinator.activeSessionId).toBeUndefined();
      expect(harness.coordinator.state).not.toHaveProperty('activeSessionId');
      expect(harness.coordinator.state).not.toHaveProperty('terminalSessionId');
      expect(harness.coordinator.state).not.toHaveProperty('terminalLeaseSequence');
      expect(harness.coordinator.state).not.toHaveProperty('focusIntent');
    }
  );

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

  it('invalidates and releases a stale Terminal completion from the previous session', async () => {
    const harness = createCoordinator();
    const oldAttach = harness.terminal.deferNext('session-old');
    const oldActivation = harness.coordinator.activate('terminal');
    await flush();

    const newAttach = harness.terminal.deferNext('session-new');
    const replacement = harness.coordinator.setSession('session-new');
    await flush();
    oldAttach.deferred.resolve(oldAttach.binding);
    await flush();
    expectInvalidatedThenReleased(harness.terminal, oldAttach.binding);
    expect(harness.coordinator.state.terminalSessionId).not.toBe('session-old');

    newAttach.deferred.resolve(newAttach.binding);
    await Promise.all([oldActivation, replacement]);
    expect(harness.coordinator.state.terminalSessionId).toBe('session-new');
    expect(newAttach.binding.invalidate).not.toHaveBeenCalled();
  });

  it.each(['logout', 'dispose'] as const)(
    'does not clean a current shared raw binding from a stale completion before %s',
    async (finalize) => {
      const harness = createCoordinator();
      const oldAttach = harness.terminal.deferNext('session-old');
      const replacementAttach = harness.terminal.deferNext('session-new', oldAttach.binding);
      const oldActivation = harness.coordinator.activate('terminal');
      await flush();

      const replacement = harness.coordinator.setSession('session-new');
      await flush();
      expect(harness.terminal.attach).toHaveBeenCalledTimes(2);
      replacementAttach.deferred.resolve(oldAttach.binding);
      await replacement;

      expect(harness.coordinator.state.terminalSessionId).toBe('session-new');
      expect(oldAttach.binding.invalidate).not.toHaveBeenCalled();
      expect(harness.terminal.release).not.toHaveBeenCalled();

      oldAttach.deferred.resolve(oldAttach.binding);
      await oldActivation;

      expect(oldAttach.binding.invalidate).not.toHaveBeenCalled();
      expect(harness.terminal.release).not.toHaveBeenCalled();
      const attachedGeneration = harness.coordinator.state.sessionGeneration;
      if (finalize === 'logout') harness.coordinator.logout();
      else harness.coordinator.dispose();

      expectInvalidatedThenReleased(harness.terminal, oldAttach.binding);
      expect(harness.coordinator.state.sessionGeneration).toBe(attachedGeneration + 1);
      expect(harness.coordinator.state.terminalStatus).toBe('detached');
      expect(harness.coordinator.state.activeSessionId).toBeUndefined();
      expect(harness.coordinator.state.status).toBe(finalize === 'logout' ? 'logged-out' : 'disposed');

      if (finalize === 'logout') harness.coordinator.logout();
      else harness.coordinator.dispose();
      expect(oldAttach.binding.invalidate).toHaveBeenCalledTimes(1);
      expect(harness.terminal.release).toHaveBeenCalledTimes(1);
      expect(harness.coordinator.state.sessionGeneration).toBe(attachedGeneration + 1);
    }
  );

  it('cleans each attachment lease when the adapter reuses one raw binding', async () => {
    const harness = createCoordinator();
    const staleAttach = harness.terminal.deferNext('session-old');
    const replacementAttach = harness.terminal.deferNext('session-new');
    const oldActivation = harness.coordinator.activate('terminal');
    await flush();

    const replacement = harness.coordinator.setSession('session-new');
    await flush();
    staleAttach.deferred.resolve(staleAttach.binding);
    await flush();
    replacementAttach.deferred.resolve(replacementAttach.binding);
    await Promise.all([oldActivation, replacement]);

    const thirdAttach = harness.terminal.deferNext('session-third', staleAttach.binding);
    const third = harness.coordinator.setSession('session-third');
    await flush();
    thirdAttach.deferred.resolve(thirdAttach.binding);
    await third;
    const fourthAttach = harness.terminal.deferNext('session-fourth', staleAttach.binding);
    const fourth = harness.coordinator.setSession('session-fourth');
    await flush();
    fourthAttach.deferred.resolve(fourthAttach.binding);
    await fourth;
    harness.coordinator.logout();

    expect(staleAttach.binding.invalidate).toHaveBeenCalledTimes(3);
    expect(harness.terminal.release).toHaveBeenCalledTimes(4);
    expect(harness.terminal.release.mock.calls.filter(([binding]) => binding === staleAttach.binding)).toHaveLength(3);
    expect(harness.terminal.events).toEqual([
      'invalidate:session-old',
      'release:session-old',
      'invalidate:session-new',
      'release:session-new',
      'invalidate:session-third',
      'release:session-third',
      'invalidate:session-fourth',
      'release:session-fourth'
    ]);
    expect(harness.coordinator.state.status).toBe('logged-out');
  });

  it('invalidates and releases a stale Terminal completion after logout', async () => {
    const harness = createCoordinator();
    const pending = harness.terminal.deferNext('session-old');
    const activation = harness.coordinator.activate('terminal');
    await flush();
    expect(harness.terminal.attach).toHaveBeenCalledTimes(1);

    harness.coordinator.logout();
    pending.deferred.resolve(pending.binding);
    await activation;

    expectInvalidatedThenReleased(harness.terminal, pending.binding);
    expect(harness.coordinator.state.status).toBe('logged-out');
  });

  it('invalidates and releases a stale Terminal completion after disposal', async () => {
    const harness = createCoordinator();
    const pending = harness.terminal.deferNext('session-old');
    const activation = harness.coordinator.activate('terminal');
    await flush();
    expect(harness.terminal.attach).toHaveBeenCalledTimes(1);

    harness.coordinator.dispose();
    pending.deferred.resolve(pending.binding);
    await activation;

    expectInvalidatedThenReleased(harness.terminal, pending.binding);
    expect(harness.coordinator.state.status).toBe('disposed');
  });

  it.each([
    ['invalidate', 'logout', 'logged-out'],
    ['release', 'logout', 'logged-out'],
    ['invalidate', 'dispose', 'disposed'],
    ['release', 'dispose', 'disposed']
  ] as const)(
    'does not resume setSession when %s cleanup reentrantly calls %s',
    async (cleanupPoint, action, expectedStatus) => {
      const harness = createCoordinator();
      await harness.coordinator.activate('terminal');
      const binding = await harness.terminal.attach.mock.results[0]!.value;

      if (cleanupPoint === 'invalidate') {
        vi.spyOn(binding, 'invalidate').mockImplementation(() => {
          if (action === 'logout') harness.coordinator.logout();
          else harness.coordinator.dispose();
        });
      } else {
        harness.terminal.release.mockImplementationOnce(() => {
          if (action === 'logout') harness.coordinator.logout();
          else harness.coordinator.dispose();
        });
      }

      await harness.coordinator.setSession('session-new');

      expect(binding.invalidate).toHaveBeenCalledTimes(1);
      expect(harness.terminal.release).toHaveBeenCalledWith(binding);
      expect(harness.chat.restore).not.toHaveBeenCalled();
      expect(harness.chat.connect).not.toHaveBeenCalled();
      expect(harness.coordinator.activeSessionId).toBeUndefined();
      expect(harness.coordinator.state).toMatchObject({
        status: expectedStatus,
        mode: 'chat',
        terminalStatus: 'detached',
        sessionGeneration: 2
      });
      expect(harness.coordinator.state).not.toHaveProperty('activeSessionId');
    }
  );

  it.each(['logout', 'dispose'] as const)(
    'does not resume setSession after activating publication reenters %s',
    async (action) => {
      let reentered = false;
      const harness = createCoordinator(undefined, undefined, {
        onStateChange: (nextState) => {
          if (reentered || nextState.status !== 'activating' || nextState.activeSessionId !== 'session-new') {
            return;
          }
          reentered = true;
          if (action === 'logout') harness.coordinator.logout();
          else harness.coordinator.dispose();
        }
      });

      const result = await harness.coordinator.setSession('session-new');

      expect(reentered).toBe(true);
      expect(result.status).toBe(action === 'logout' ? 'logged-out' : 'disposed');
      expect(harness.chat.connect).not.toHaveBeenCalled();
      expect(harness.chat.restore).not.toHaveBeenCalled();
      expect(harness.terminal.attach).not.toHaveBeenCalled();
      expect(harness.chat.close).toHaveBeenCalledTimes(1);
      expect(harness.coordinator.activeSessionId).toBeUndefined();
      expect(harness.coordinator.state.sessionGeneration).toBe(3);
      expect(harness.coordinator.state.terminalStatus).toBe('detached');
      expect(harness.coordinator.state).not.toHaveProperty('focusIntent');
    }
  );

  it.each([
    ['logout', 'invalidate', 'logout', 'logged-out'],
    ['logout', 'invalidate', 'dispose', 'disposed'],
    ['logout', 'release', 'logout', 'logged-out'],
    ['logout', 'release', 'dispose', 'disposed'],
    ['dispose', 'invalidate', 'dispose', 'disposed'],
    ['dispose', 'invalidate', 'logout', 'disposed'],
    ['dispose', 'release', 'dispose', 'disposed'],
    ['dispose', 'release', 'logout', 'disposed']
  ] as const)(
    'keeps outer %s cleanup exactly once when %s reenters %s',
    async (outerAction, cleanupPoint, nestedAction, expectedStatus) => {
      const harness = createCoordinator();
      await harness.coordinator.activate('terminal');
      const binding = await harness.terminal.attach.mock.results[0]!.value;
      const initialGeneration = harness.coordinator.state.sessionGeneration;
      const invoke = (action: 'logout' | 'dispose'): void => {
        if (action === 'logout') harness.coordinator.logout();
        else harness.coordinator.dispose();
      };
      const reenter = (): void => invoke(nestedAction);

      if (cleanupPoint === 'invalidate') {
        vi.spyOn(binding, 'invalidate').mockImplementation(reenter);
      } else {
        harness.terminal.release.mockImplementationOnce(reenter);
      }

      invoke(outerAction);

      expect(binding.invalidate).toHaveBeenCalledTimes(1);
      expect(harness.terminal.release).toHaveBeenCalledTimes(1);
      expect(harness.chat.close).toHaveBeenCalledTimes(1);
      expect(harness.coordinator.state).toMatchObject({
        status: expectedStatus,
        mode: 'chat',
        sessionGeneration: initialGeneration + 1,
        terminalStatus: 'detached'
      });
      expect(harness.coordinator.state).not.toHaveProperty('activeSessionId');
      expect(harness.coordinator.state).not.toHaveProperty('terminalSessionId');
      expect(harness.coordinator.state).not.toHaveProperty('focusIntent');

      invoke(expectedStatus === 'logged-out' ? 'logout' : 'dispose');
      expect(binding.invalidate).toHaveBeenCalledTimes(1);
      expect(harness.terminal.release).toHaveBeenCalledTimes(1);
      expect(harness.chat.close).toHaveBeenCalledTimes(1);
      expect(harness.coordinator.state.sessionGeneration).toBe(initialGeneration + 1);
      expect(harness.coordinator.state.status).toBe(expectedStatus);
    }
  );

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
    expectInvalidatedThenReleased(logoutHarness.terminal, logoutBinding);
    expect(logoutHarness.chat.close).toHaveBeenCalledTimes(1);
    expect(logoutHarness.coordinator.state.status).toBe('logged-out');
    await expect(logoutHarness.coordinator.activate('chat')).rejects.toMatchObject({ code: 'logged-out' });

    const disposeHarness = createCoordinator();
    await disposeHarness.coordinator.activate('terminal');
    const disposeBinding = await disposeHarness.terminal.attach.mock.results[0]!.value;
    disposeHarness.coordinator.dispose();
    disposeHarness.coordinator.dispose();
    expectInvalidatedThenReleased(disposeHarness.terminal, disposeBinding);
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
