import {
  DASHBOARD_CONTRACT,
  HERMES_SOURCE_SHA,
  JsonRpcChatError,
  type JsonRpcChatTransport,
  type JsonRpcConnectionStatus
} from '../chat/json-rpc-chat';
import { validateSessionId } from '../transport/live-rest-transport';

/** The only Hermes revision accepted by this planning-only browser seam. */
export const PINNED_DASHBOARD_CONTRACT = DASHBOARD_CONTRACT;
export const PINNED_HERMES_SOURCE_SHA = HERMES_SOURCE_SHA;

export type WorkspaceMode = 'chat' | 'terminal';
export type FocusTarget = 'composer' | 'w-term-input';
export type DeploymentCompatibilityStatus = 'compatible' | 'unknown' | 'incompatible';
export type TerminalBindingStatus = 'detached' | 'attaching' | 'attached' | 'failed';

export type SessionCoordinatorStatus =
  | 'empty'
  | 'idle'
  | 'activating'
  | 'active'
  | 'reconnecting'
  | 'terminal-attach-failed'
  | 'chat-error'
  | 'blocked'
  | 'logged-out'
  | 'disposed';

export type SessionCoordinatorErrorCode =
  | 'aborted'
  | 'chat-operation-failed'
  | 'disposed'
  | 'incompatible-deployment'
  | 'invalid-session'
  | 'logged-out'
  | 'no-session'
  | 'stale-operation'
  | 'terminal-attach-failed'
  | 'unknown-deployment';

const ERROR_MESSAGES: Record<SessionCoordinatorErrorCode, string> = {
  aborted: 'The session coordinator operation was cancelled.',
  'chat-operation-failed': 'The Chat session operation failed.',
  disposed: 'The session coordinator has been disposed.',
  'incompatible-deployment': 'The Hermes deployment is outside the pinned contract.',
  'invalid-session': 'The Hermes session identity is invalid.',
  'logged-out': 'The session coordinator is logged out.',
  'no-session': 'A Hermes session must be selected before activation.',
  'stale-operation': 'The session coordinator operation is no longer current.',
  'terminal-attach-failed': 'The W-Term session binding could not be attached.',
  'unknown-deployment': 'The Hermes deployment compatibility is unknown.'
};

/** Errors intentionally contain only a closed, redacted code and message set. */
export class SessionCoordinatorError extends Error {
  readonly code: SessionCoordinatorErrorCode;

  constructor(code: SessionCoordinatorErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = 'SessionCoordinatorError';
    this.code = code;
  }
}

/**
 * The coordinator accepts the existing W-07 Chat transport without importing
 * Chat rendering. A compatible transport remains the owner of WebSocket,
 * ticket, prompt, and server-owned transcript behavior.
 */
export type ChatSessionPort = Pick<
  JsonRpcChatTransport,
  'state' | 'selectedSessionId' | 'connect' | 'reconnect' | 'restore' | 'close'
>;

/**
 * W-Term owns the concrete PTY/renderer binding. The coordinator only receives
 * an opaque invalidatable handle and never stores terminal bytes or transcript
 * content. Each attachment receives its own coordinator-owned lease, so the
 * same raw handle may be reused by an adapter after an earlier lease settles.
 */
export interface TerminalBinding {
  readonly sessionId: string;
  invalidate(): void;
}

export interface TerminalSessionPort {
  attach(sessionId: string, signal: AbortSignal): TerminalBinding | Promise<TerminalBinding>;
  /** Optional renderer/transport cleanup after invalidation; called once per lease. */
  release?(binding: TerminalBinding): void;
}

/**
 * Compatibility evidence is deliberately smaller than the attestation record.
 * It is still fail-closed: `compatible` is accepted only with both pinned
 * values, while omitted or unknown evidence cannot activate either workspace.
 */
export interface HermesDeploymentCompatibility {
  readonly status: DeploymentCompatibilityStatus;
  readonly contract?: string;
  readonly hermesSourceSha?: string;
}

export interface FocusIntent {
  readonly mode: WorkspaceMode;
  readonly target: FocusTarget;
  readonly sessionId: string;
  readonly sessionGeneration: number;
  readonly sequence: number;
}

/**
 * Identifies the coordinator generation that owned a Terminal callback when it
 * was created. Session IDs can be selected again, so either field alone is not
 * a sufficient stale-callback fence.
 */
export interface TerminalSettlement {
  readonly sessionId: string;
  readonly sessionGeneration: number;
  /**
   * Coordinator-issued ownership token from the state observed when the Terminal
   * operation started. Optional only for legacy callers; after a retry in the
   * same session generation, a tokenless settlement is rejected conservatively.
   */
  readonly terminalLeaseSequence?: number;
}

export interface SessionCoordinatorState {
  readonly status: SessionCoordinatorStatus;
  readonly mode: WorkspaceMode;
  readonly activeSessionId?: string;
  readonly sessionGeneration: number;
  readonly compatibility: DeploymentCompatibilityStatus;
  readonly chatStatus: JsonRpcConnectionStatus;
  readonly terminalStatus: TerminalBindingStatus;
  readonly terminalSessionId?: string;
  /** Coordinator-issued ownership token for the attached or attaching Terminal lease. */
  readonly terminalLeaseSequence?: number;
  readonly focusIntent?: FocusIntent;
  readonly lastError?: SessionCoordinatorErrorCode;
}

export interface SessionCoordinatorOptions {
  readonly chat: ChatSessionPort;
  readonly terminal: TerminalSessionPort;
  /** Omitted evidence is treated as unknown and cannot activate the runtime. */
  readonly deployment?: HermesDeploymentCompatibility;
  readonly initialSessionId?: string;
  readonly initialMode?: WorkspaceMode;
  /** Motion is a renderer concern; this flag never changes coordinator semantics. */
  readonly reducedMotion?: boolean;
  readonly onStateChange?: (state: SessionCoordinatorState) => void;
  readonly onFocusIntent?: (intent: FocusIntent) => void;
}

export interface SessionCoordinator {
  readonly state: SessionCoordinatorState;
  readonly activeSessionId: string | undefined;
  readonly mode: WorkspaceMode;
  activate(mode: WorkspaceMode, signal?: AbortSignal): Promise<SessionCoordinatorState>;
  switchMode(mode: WorkspaceMode, signal?: AbortSignal): Promise<SessionCoordinatorState>;
  /**
   * Synchronously revoke the selected session and its Terminal lease. Callers
   * use this before exposing a replacement live-workspace snapshot; it never
   * selects or restores Chat.
   */
  invalidateSession(): void;
  /**
   * Reconcile an unsolicited Terminal settlement without selecting Chat. The
   * callback must carry the session ID and generation it captured at start.
   * Returns false when that ownership is already stale.
   */
  invalidateTerminalBinding(settlement: TerminalSettlement): boolean;
  setSession(sessionId: string, signal?: AbortSignal): Promise<SessionCoordinatorState>;
  /** Restore server-owned state after a browser refresh without transcript mirroring. */
  restore(sessionId: string, signal?: AbortSignal): Promise<SessionCoordinatorState>;
  reconnect(signal?: AbortSignal): Promise<SessionCoordinatorState>;
  /** Reacquire Terminal and issue the normal generation-owned focus intent. */
  reconnectTerminal(signal?: AbortSignal): Promise<SessionCoordinatorState>;
  logout(): void;
  dispose(): void;
  subscribe(listener: (state: SessionCoordinatorState) => void): () => void;
}

interface PendingSessionOperation {
  readonly generation: number;
  readonly sessionId: string;
  readonly controller: AbortController;
  readonly promise: Promise<void>;
  cancelled: boolean;
}

interface TerminalBindingLease {
  readonly binding: TerminalBinding;
  /** Unique coordinator ownership, independent of an adapter's raw binding object. */
  readonly terminalLeaseSequence: number;
  cleaned: boolean;
}

interface PendingTerminalAttach {
  readonly generation: number;
  readonly sessionId: string;
  readonly terminalLeaseSequence: number;
  readonly controller: AbortController;
  readonly promise: Promise<TerminalBinding>;
  focusOwnerSequence: number | undefined;
  cancelled: boolean;
}

interface PendingReconnect {
  readonly generation: number;
  readonly sessionId: string;
  readonly controller: AbortController;
  readonly promise: Promise<void>;
  cancelled: boolean;
}

/** Captures the requested focus target and per-mode completion ownership. */
interface ModeActivation {
  readonly mode: WorkspaceMode;
  readonly generation: number;
  readonly sessionId: string;
  readonly sequence: number;
}

function safeCall<T extends unknown[]>(callback: ((...args: T) => void) | undefined, ...args: T): void {
  if (!callback) return;
  try {
    callback(...args);
  } catch {
    // Observers cannot alter coordinator state or interrupt cleanup.
  }
}

function normalizeDeployment(
  deployment: HermesDeploymentCompatibility | undefined
): DeploymentCompatibilityStatus {
  if (!deployment) return 'unknown';
  if (deployment.status === 'unknown' || deployment.status === 'incompatible') {
    return deployment.status;
  }
  if (
    deployment.status === 'compatible' &&
    deployment.contract === PINNED_DASHBOARD_CONTRACT &&
    deployment.hermesSourceSha === PINNED_HERMES_SOURCE_SHA
  ) {
    return 'compatible';
  }
  return 'incompatible';
}

function normalizeSessionId(sessionId: string): string {
  try {
    return validateSessionId(sessionId);
  } catch {
    throw new SessionCoordinatorError('invalid-session');
  }
}

function errorForDeployment(status: DeploymentCompatibilityStatus): SessionCoordinatorError {
  return new SessionCoordinatorError(
    status === 'unknown' ? 'unknown-deployment' : 'incompatible-deployment'
  );
}

function isAbortLike(error: unknown): boolean {
  return error instanceof SessionCoordinatorError && error.code === 'aborted';
}

function isStale(error: unknown): boolean {
  return error instanceof SessionCoordinatorError && error.code === 'stale-operation';
}

function safeAbort(controller: AbortController): void {
  try {
    controller.abort();
  } catch {
    // AbortController is platform-owned; cleanup remains best effort.
  }
}

function awaitWithAbort<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new SessionCoordinatorError('aborted'));

  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      signal.removeEventListener('abort', onAbort);
      reject(new SessionCoordinatorError('aborted'));
    };
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      }
    );
  });
}

function isConnectionIncompatible(chat: ChatSessionPort): boolean {
  try {
    return chat.state.status === 'incompatible';
  } catch {
    return false;
  }
}

function normalizeChatError(error: unknown, chat: ChatSessionPort): SessionCoordinatorError {
  if (error instanceof SessionCoordinatorError) return error;
  if (error instanceof JsonRpcChatError && error.code === 'incompatible') {
    return new SessionCoordinatorError('incompatible-deployment');
  }
  if (isConnectionIncompatible(chat)) {
    return new SessionCoordinatorError('incompatible-deployment');
  }
  if (error instanceof JsonRpcChatError && error.code === 'aborted') {
    return new SessionCoordinatorError('aborted');
  }
  return new SessionCoordinatorError('chat-operation-failed');
}

function normalizeTerminalError(): SessionCoordinatorError {
  return new SessionCoordinatorError('terminal-attach-failed');
}

function isMode(value: WorkspaceMode): boolean {
  return value === 'chat' || value === 'terminal';
}

/**
 * Coordinates one selected server session across the Chat and W-Term modes.
 * This object deliberately has no create-session method: switching modes and
 * reconnecting reuse the selected opaque identity, while `setSession` is the
 * only operation that replaces it.
 */
export function createSessionCoordinator(options: SessionCoordinatorOptions): SessionCoordinator {
  const chat = options.chat;
  const terminal = options.terminal;
  let compatibility = normalizeDeployment(options.deployment);
  const listeners = new Set<(state: SessionCoordinatorState) => void>();
  let activeSessionId: string | undefined;
  let mode: WorkspaceMode = options.initialMode ?? 'chat';
  let sessionGeneration = 0;
  let terminalStatus: TerminalBindingStatus = 'detached';
  let terminalBinding: TerminalBindingLease | undefined;
  let terminalBindingFocusOwnerSequence: number | undefined;
  // This token fences retries within one session generation; raw adapter binding
  // identity cannot do so because adapters may intentionally reuse an object.
  let terminalLeaseSequence: number | undefined;
  let nextTerminalLeaseSequence = 0;
  let terminalLeaseCountForSession = 0;
  let lastError: SessionCoordinatorErrorCode | undefined;
  let lastFocusIntent: FocusIntent | undefined;
  let nextFocusSequence = 0;
  // Nested observer transitions synchronously publish a newer state. This
  // monotonic fence prevents an outer publish from delivering its stale snapshot.
  let publicationRevision = 0;
  let nextModeActivationSequence = 0;
  const latestModeActivationSequence: Record<WorkspaceMode, number> = { chat: 0, terminal: 0 };
  let disposed = false;
  let loggedOut = false;
  let chatClosed = false;
  let lifecycleCleanupInProgress = false;
  let lifecycle: SessionCoordinatorStatus;
  let pendingSession: PendingSessionOperation | undefined;
  let pendingTerminal: PendingTerminalAttach | undefined;
  let pendingReconnect: PendingReconnect | undefined;

  if (!isMode(mode)) {
    throw new SessionCoordinatorError('chat-operation-failed');
  }

  if (compatibility === 'compatible' && options.initialSessionId !== undefined) {
    activeSessionId = normalizeSessionId(options.initialSessionId);
    sessionGeneration = 1;
  }

  lifecycle =
    compatibility === 'compatible'
      ? activeSessionId === undefined
        ? 'empty'
        : 'idle'
      : 'blocked';

  // Reduced motion intentionally is not read into state. Focus targets and
  // lifecycle semantics remain identical; the renderer decides how to animate.
  void options.reducedMotion;

  const state = (): SessionCoordinatorState => {
    let chatStatus: JsonRpcConnectionStatus;
    try {
      chatStatus = chat.state.status;
    } catch {
      chatStatus = 'failed';
    }

    const snapshot: SessionCoordinatorState = {
      status: lifecycle,
      mode,
      sessionGeneration,
      compatibility,
      chatStatus,
      terminalStatus,
      ...(activeSessionId === undefined ? {} : { activeSessionId }),
      ...(terminalBinding === undefined ? {} : { terminalSessionId: terminalBinding.binding.sessionId }),
      ...(terminalLeaseSequence === undefined ? {} : { terminalLeaseSequence }),
      ...(lastFocusIntent === undefined ? {} : { focusIntent: lastFocusIntent }),
      ...(lastError === undefined ? {} : { lastError })
    };
    return Object.freeze(snapshot);
  };

  const publish = (): void => {
    const revision = ++publicationRevision;
    const snapshot = state();
    safeCall(options.onStateChange, snapshot);
    // `onStateChange` and subscribers are synchronous extension points. If one
    // reenters the lifecycle it publishes a newer revision, whose state must win.
    if (revision !== publicationRevision) return;
    for (const listener of [...listeners]) {
      if (revision !== publicationRevision) return;
      safeCall(listener, snapshot);
    }
  };

  const current = (generation: number, sessionId: string): boolean =>
    !disposed && !loggedOut && generation === sessionGeneration && activeSessionId === sessionId;

  // Chat focus is emitted as soon as Chat is ready; deferred Terminal focus must
  // still be owned by the active Terminal mode to avoid a late W-Term focus.
  const isCurrentModeActivation = (activation: ModeActivation): boolean =>
    current(activation.generation, activation.sessionId) &&
    latestModeActivationSequence[activation.mode] === activation.sequence &&
    (activation.mode === 'chat' ||
      (mode === activation.mode && terminalBindingFocusOwnerSequence === activation.sequence));

  const publishFocus = (activation: ModeActivation): void => {
    if (!isCurrentModeActivation(activation)) return;
    const intent = Object.freeze({
      mode: activation.mode,
      target: activation.mode === 'chat' ? 'composer' : 'w-term-input',
      sessionId: activation.sessionId,
      sessionGeneration: activation.generation,
      sequence: ++nextFocusSequence
    });
    lastFocusIntent = intent;
    safeCall(options.onFocusIntent, intent);
    publish();
  };

  const clearFocus = (): void => {
    if (lastFocusIntent === undefined) return;
    lastFocusIntent = undefined;
    publish();
  };

  // A Terminal settlement must not erase a newer Chat composer intent after a
  // mode switch. It only owns focus that was issued for its Terminal lease.
  const clearTerminalFocus = (): void => {
    if (lastFocusIntent?.mode !== 'terminal') return;
    lastFocusIntent = undefined;
  };

  const cancelSession = (): void => {
    const pending = pendingSession;
    if (!pending) return;
    pending.cancelled = true;
    safeAbort(pending.controller);
    pendingSession = undefined;
    void pending.promise.catch(() => undefined);
  };

  const cancelTerminal = (): void => {
    const pending = pendingTerminal;
    if (!pending) return;
    pending.cancelled = true;
    safeAbort(pending.controller);
    pendingTerminal = undefined;
    if (terminalLeaseSequence === pending.terminalLeaseSequence) terminalLeaseSequence = undefined;
    void pending.promise.catch(() => undefined);
  };

  const cancelReconnect = (): void => {
    const pending = pendingReconnect;
    if (!pending) return;
    pending.cancelled = true;
    safeAbort(pending.controller);
    pendingReconnect = undefined;
    void pending.promise.catch(() => undefined);
  };

  /** Cleanup is lease-based so a reused raw binding gets fresh ownership. */
  const cleanupBinding = (lease: TerminalBindingLease): void => {
    if (lease.cleaned) return;
    lease.cleaned = true;
    try {
      lease.binding.invalidate();
    } catch {
      // Invalidation is best effort; the binding is no longer exposed.
    }
    try {
      terminal.release?.(lease.binding);
    } catch {
      // Renderer cleanup cannot keep Chat or session replacement from settling.
    }
  };

  const ownsActiveTerminalLease = (value: unknown): boolean =>
    terminalBinding !== undefined &&
    !terminalBinding.cleaned &&
    terminalBinding.binding === value;

  const cleanupUnknownBinding = (value: unknown): void => {
    if (!value || typeof value !== 'object') return;
    if (ownsActiveTerminalLease(value)) return;
    const invalidate = (value as { invalidate?: unknown }).invalidate;
    if (typeof invalidate !== 'function') return;
    cleanupBinding({ binding: value as TerminalBinding, terminalLeaseSequence: -1, cleaned: false });
  };

  const invalidateBinding = (): void => {
    const lease = terminalBinding;
    terminalBinding = undefined;
    terminalBindingFocusOwnerSequence = undefined;
    // Every caller has already cancelled any pending attach, so this is the
    // terminal lifecycle's destructive boundary even when cleanup reentered
    // after the binding reference was cleared.
    terminalLeaseSequence = undefined;
    terminalStatus = 'detached';
    if (lease) cleanupBinding(lease);
  };

  /**
   * This is deliberately synchronous: a live-workspace owner can make the old
   * identity unobservable before it publishes its replacement snapshot. Chat
   * selection is asynchronous and therefore belongs to a later `setSession`.
   */
  const invalidateSession = (): void => {
    if (disposed || loggedOut || activeSessionId === undefined) return;

    cancelSession();
    cancelTerminal();
    cancelReconnect();
    activeSessionId = undefined;
    sessionGeneration += 1;
    terminalLeaseCountForSession = 0;
    terminalStatus = 'detached';
    lastError = undefined;
    lastFocusIntent = undefined;
    lifecycle = 'empty';
    invalidateBinding();
    terminalLeaseSequence = undefined;

    // Binding cleanup may reenter logout or disposal; its final lifecycle wins.
    if (!disposed && !loggedOut) publish();
  };

  /**
   * Terminal adapters may report detach/failure after an async operation. The
   * lease token fences recoveries in the same session generation; tokenless
   * legacy settlements are accepted only before that generation has retried.
   */
  const invalidateTerminalBinding = (settlement: TerminalSettlement): boolean => {
    if (!current(settlement.sessionGeneration, settlement.sessionId)) return false;
    const activeLeaseSequence =
      terminalBinding?.terminalLeaseSequence ?? pendingTerminal?.terminalLeaseSequence;
    if (activeLeaseSequence === undefined) return false;
    if (
      (settlement.terminalLeaseSequence !== undefined &&
        settlement.terminalLeaseSequence !== activeLeaseSequence) ||
      (settlement.terminalLeaseSequence === undefined && terminalLeaseCountForSession > 1)
    ) {
      return false;
    }

    // Retain this token through adapter cleanup. Either callback may synchronously
    // start another lifecycle transition, so the original settlement may finish
    // only if it still owns this exact, otherwise-unobservable lease transition.
    const lifecycleBeforeCleanup = lifecycle;
    const pending = pendingTerminal;
    if (pending?.terminalLeaseSequence === activeLeaseSequence) {
      pending.cancelled = true;
      safeAbort(pending.controller);
      pendingTerminal = undefined;
      void pending.promise.catch(() => undefined);
    }
    const lease = terminalBinding;
    terminalBinding = undefined;
    terminalBindingFocusOwnerSequence = undefined;
    terminalStatus = 'detached';
    if (lease) cleanupBinding(lease);

    if (
      !current(settlement.sessionGeneration, settlement.sessionId) ||
      terminalLeaseSequence !== activeLeaseSequence ||
      lifecycle !== lifecycleBeforeCleanup ||
      terminalBinding !== undefined ||
      pendingTerminal !== undefined
    ) {
      return false;
    }
    terminalLeaseSequence = undefined;
    clearTerminalFocus();
    if (mode === 'terminal') lifecycle = 'idle';
    publish();
    return true;
  };

  const assertCurrent = (generation: number, sessionId: string): void => {
    if (!current(generation, sessionId)) {
      throw new SessionCoordinatorError('stale-operation');
    }
  };

  const assertUsable = (): void => {
    if (disposed) throw new SessionCoordinatorError('disposed');
    if (loggedOut) throw new SessionCoordinatorError('logged-out');
    if (compatibility !== 'compatible') throw errorForDeployment(compatibility);
    if (isConnectionIncompatible(chat)) {
      markBlocked('incompatible-deployment');
      throw new SessionCoordinatorError('incompatible-deployment');
    }
  };

  const assertSession = (): string => {
    if (!activeSessionId) throw new SessionCoordinatorError('no-session');
    return activeSessionId;
  };

  const markBlocked = (code: 'incompatible-deployment'): void => {
    if (disposed || loggedOut) return;
    compatibility = 'incompatible';
    cancelSession();
    cancelTerminal();
    cancelReconnect();
    invalidateBinding();
    activeSessionId = undefined;
    sessionGeneration += 1;
    terminalLeaseCountForSession = 0;
    terminalStatus = 'detached';
    lastError = code;
    lifecycle = 'blocked';
    clearFocus();
    publish();
  };

  const ensureChatForCurrentSession = (
    forceRestore: boolean,
    signal?: AbortSignal
  ): Promise<void> => {
    const sessionId = assertSession();
    const generation = sessionGeneration;
    const existing = pendingSession;
    if (
      existing &&
      !existing.cancelled &&
      existing.generation === generation &&
      existing.sessionId === sessionId
    ) {
      return awaitWithAbort(existing.promise, signal);
    }
    if (existing) cancelSession();

    lifecycle = 'activating';
    lastError = undefined;
    publish();
    if (!current(generation, sessionId)) {
      return Promise.reject(new SessionCoordinatorError('stale-operation'));
    }

    const controller = new AbortController();
    const pending = {
      generation,
      sessionId,
      controller,
      cancelled: false,
      promise: undefined as unknown as Promise<void>
    } satisfies Omit<PendingSessionOperation, 'promise'> & { promise: Promise<void> };

    const promise = (async (): Promise<void> => {
      let wasReady = false;
      try {
        assertCurrent(generation, sessionId);
        if (isConnectionIncompatible(chat)) {
          throw new SessionCoordinatorError('incompatible-deployment');
        }
        wasReady = chat.state.status === 'ready';
        if (!wasReady) {
          await chat.connect(controller.signal);
        }
        assertCurrent(generation, sessionId);
        if (isConnectionIncompatible(chat)) {
          throw new SessionCoordinatorError('incompatible-deployment');
        }
        const selectedSessionId = chat.selectedSessionId;
        if (selectedSessionId !== sessionId && (chat.state.status === 'ready' || !wasReady)) {
          await chat.restore(sessionId, controller.signal);
        } else if (forceRestore && wasReady) {
          await chat.restore(sessionId, controller.signal);
        }
        assertCurrent(generation, sessionId);
        if (isConnectionIncompatible(chat)) {
          throw new SessionCoordinatorError('incompatible-deployment');
        }
        if (chat.state.status !== 'ready') {
          throw new SessionCoordinatorError('chat-operation-failed');
        }
      } catch (error) {
        if (pending.cancelled) {
          throw new SessionCoordinatorError('stale-operation');
        }
        if (isStale(error)) throw error;
        const normalized = normalizeChatError(error, chat);
        if (normalized.code === 'incompatible-deployment') {
          markBlocked('incompatible-deployment');
        } else if (current(generation, sessionId)) {
          lastError = normalized.code;
          lifecycle = 'chat-error';
          publish();
        }
        throw normalized;
      }
    })().finally(() => {
      if (pendingSession === pending) pendingSession = undefined;
    });
    pending.promise = promise;
    pendingSession = pending;
    void promise.catch(() => undefined);
    return awaitWithAbort(promise, signal);
  };

  const normalizeBinding = (value: TerminalBinding, sessionId: string): TerminalBinding => {
    if (!value || typeof value !== 'object' || value.sessionId !== sessionId) {
      cleanupUnknownBinding(value);
      throw normalizeTerminalError();
    }
    const invalidate = (value as { invalidate?: unknown }).invalidate;
    if (typeof invalidate !== 'function') {
      cleanupUnknownBinding(value);
      throw normalizeTerminalError();
    }
    return value;
  };

  const ensureTerminalForCurrentSession = (
    signal?: AbortSignal,
    focusOwnerSequence?: number
  ): Promise<TerminalBinding> => {
    const sessionId = assertSession();
    const generation = sessionGeneration;
    if (terminalBinding?.binding.sessionId === sessionId) {
      terminalStatus = 'attached';
      if (focusOwnerSequence !== undefined) terminalBindingFocusOwnerSequence = focusOwnerSequence;
      return Promise.resolve(terminalBinding.binding);
    }

    const existing = pendingTerminal;
    if (
      existing &&
      !existing.cancelled &&
      existing.generation === generation &&
      existing.sessionId === sessionId
    ) {
      // Coalescing keeps one attach; the latest Terminal waiter owns its focus.
      if (focusOwnerSequence !== undefined) existing.focusOwnerSequence = focusOwnerSequence;
      return awaitWithAbort(existing.promise, signal);
    }
    if (existing) cancelTerminal();

    // Install an owned operation, not merely its token, before starting the
    // adapter or publishing `attaching`. A synchronous observer may settle the
    // published token while the adapter is still pending.
    const leaseSequence = ++nextTerminalLeaseSequence;
    const controller = new AbortController();
    let startAttach!: () => void;
    let pending!: PendingTerminalAttach;
    const operation = new Promise<TerminalBinding>((resolve, reject) => {
      startAttach = () => {
        void (async (): Promise<TerminalBinding> => {
          try {
            const value = await terminal.attach(sessionId, controller.signal);
            if (!current(generation, sessionId) || pending.cancelled) {
              cleanupUnknownBinding(value);
              throw new SessionCoordinatorError('stale-operation');
            }
            const binding = normalizeBinding(value, sessionId);
            const lease: TerminalBindingLease = {
              binding,
              terminalLeaseSequence: pending.terminalLeaseSequence,
              cleaned: false
            };
            if (!current(generation, sessionId) || pending.cancelled) {
              cleanupBinding(lease);
              throw new SessionCoordinatorError('stale-operation');
            }
            terminalBinding = lease;
            terminalBindingFocusOwnerSequence = pending.focusOwnerSequence;
            terminalStatus = 'attached';
            lastError = undefined;
            lifecycle = 'active';
            publish();
            return binding;
          } catch (error) {
            if (isStale(error) || pending.cancelled) throw new SessionCoordinatorError('stale-operation');
            const normalized = normalizeTerminalError();
            if (current(generation, sessionId)) {
              if (terminalLeaseSequence === pending.terminalLeaseSequence) {
                terminalLeaseSequence = undefined;
              }
              terminalStatus = 'failed';
              lastError = normalized.code;
              lifecycle = mode === 'terminal' ? 'terminal-attach-failed' : 'active';
              publish();
            }
            throw normalized;
          }
        })().then(resolve, reject);
      };
    });
    const promise = operation.finally(() => {
      if (pendingTerminal === pending) pendingTerminal = undefined;
    });
    pending = {
      generation,
      sessionId,
      terminalLeaseSequence: leaseSequence,
      controller,
      focusOwnerSequence,
      cancelled: false,
      promise
    };
    terminalLeaseSequence = leaseSequence;
    terminalLeaseCountForSession += 1;
    terminalStatus = 'attaching';
    lastError = undefined;
    pendingTerminal = pending;
    void promise.catch(() => undefined);
    // Start the adapter only after its cancellation ownership is installed; the
    // following publish may synchronously settle this still-pending lease.
    startAttach();
    publish();
    return awaitWithAbort(promise, signal);
  };

  const beginModeActivation = (
    nextMode: WorkspaceMode,
    generation: number,
    sessionId: string
  ): ModeActivation => {
    if (!isMode(nextMode)) throw new SessionCoordinatorError('chat-operation-failed');
    mode = nextMode;
    const activation = Object.freeze({
      mode: nextMode,
      generation,
      sessionId,
      sequence: ++nextModeActivationSequence
    });
    latestModeActivationSequence[nextMode] = activation.sequence;
    lastError = undefined;
    clearFocus();
    if (!current(generation, sessionId)) return activation;
    lifecycle = 'activating';
    publish();
    return activation;
  };

  const captureModeActivation = (generation: number, sessionId: string): ModeActivation =>
    Object.freeze({
      mode,
      generation,
      sessionId,
      sequence: latestModeActivationSequence[mode]
    });

  const activate = async (
    nextMode: WorkspaceMode,
    signal?: AbortSignal
  ): Promise<SessionCoordinatorState> => {
    assertUsable();
    const sessionId = assertSession();
    const generation = sessionGeneration;
    const activation = beginModeActivation(nextMode, generation, sessionId);

    try {
      if (!current(generation, sessionId)) return state();
      await ensureChatForCurrentSession(false, signal);
      assertCurrent(generation, sessionId);
      if (activation.mode === 'terminal') {
        await ensureTerminalForCurrentSession(signal, activation.sequence);
        assertCurrent(generation, sessionId);
      }
      if (!isCurrentModeActivation(activation)) return state();
      lifecycle = 'active';
      publish();
      publishFocus(activation);
      return state();
    } catch (error) {
      if (isStale(error)) return state();
      throw error;
    }
  };

  const setSession = async (
    nextSessionId: string,
    signal?: AbortSignal
  ): Promise<SessionCoordinatorState> => {
    assertUsable();
    const sessionId = normalizeSessionId(nextSessionId);
    if (sessionId === activeSessionId) {
      return activate(mode, signal);
    }

    cancelSession();
    cancelTerminal();
    cancelReconnect();
    const cleanupGeneration = sessionGeneration;
    const cleanupSessionId = activeSessionId;
    const cleanupLifecycle = lifecycle;
    invalidateBinding();
    // Binding cleanup is adapter-owned and may synchronously log out or dispose.
    // Recheck lifecycle, generation, and identity before installing the replacement.
    if (
      disposed ||
      loggedOut ||
      sessionGeneration !== cleanupGeneration ||
      activeSessionId !== cleanupSessionId ||
      lifecycle !== cleanupLifecycle
    ) {
      return state();
    }
    activeSessionId = sessionId;
    sessionGeneration += 1;
    terminalLeaseCountForSession = 0;
    terminalStatus = 'detached';
    lastError = undefined;
    const generation = sessionGeneration;
    clearFocus();
    if (!current(generation, sessionId)) return state();
    lifecycle = 'activating';
    const activation = captureModeActivation(generation, sessionId);
    publish();

    try {
      if (!current(generation, sessionId)) return state();
      await ensureChatForCurrentSession(false, signal);
      assertCurrent(generation, sessionId);
      if (activation.mode === 'terminal') {
        await ensureTerminalForCurrentSession(signal, activation.sequence);
        assertCurrent(generation, sessionId);
      }
      lifecycle = 'active';
      publish();
      publishFocus(activation);
      return state();
    } catch (error) {
      if (isStale(error)) return state();
      throw error;
    }
  };

  const restore = async (
    requestedSessionId: string,
    signal?: AbortSignal
  ): Promise<SessionCoordinatorState> => {
    assertUsable();
    const sessionId = normalizeSessionId(requestedSessionId);
    if (sessionId !== activeSessionId) return setSession(sessionId, signal);

    const generation = sessionGeneration;
    const activation = captureModeActivation(generation, sessionId);
    clearFocus();
    if (!current(generation, sessionId)) return state();
    lastError = undefined;
    lifecycle = 'activating';
    publish();
    try {
      if (!current(generation, sessionId)) return state();
      await ensureChatForCurrentSession(true, signal);
      assertCurrent(generation, sessionId);
      lifecycle = 'active';
      publish();
      publishFocus(activation);
      return state();
    } catch (error) {
      if (isStale(error)) return state();
      throw error;
    }
  };

  const reconnect = async (signal?: AbortSignal): Promise<SessionCoordinatorState> => {
    assertUsable();
    const sessionId = assertSession();
    const generation = sessionGeneration;
    const existing = pendingReconnect;
    if (
      existing &&
      !existing.cancelled &&
      existing.generation === generation &&
      existing.sessionId === sessionId
    ) {
      await awaitWithAbort(existing.promise, signal);
      return state();
    }
    if (existing) cancelReconnect();
    cancelSession();
    lifecycle = 'reconnecting';
    lastError = undefined;
    clearFocus();
    if (!current(generation, sessionId)) return state();
    publish();
    if (!current(generation, sessionId)) return state();
    const controller = new AbortController();
    const pending = {
      generation,
      sessionId,
      controller,
      cancelled: false,
      promise: undefined as unknown as Promise<void>
    } satisfies Omit<PendingReconnect, 'promise'> & { promise: Promise<void> };

    const promise = (async (): Promise<void> => {
      try {
        await chat.reconnect(controller.signal);
        assertCurrent(generation, sessionId);
        if (isConnectionIncompatible(chat)) {
          throw new SessionCoordinatorError('incompatible-deployment');
        }
        if (chat.selectedSessionId !== sessionId) {
          await chat.restore(sessionId, controller.signal);
        }
        assertCurrent(generation, sessionId);
        if (chat.state.status !== 'ready') {
          throw new SessionCoordinatorError('chat-operation-failed');
        }
        lifecycle = 'active';
        publish();
      } catch (error) {
        if (pending.cancelled) throw new SessionCoordinatorError('stale-operation');
        if (isStale(error)) throw error;
        const normalized = normalizeChatError(error, chat);
        if (normalized.code === 'incompatible-deployment') {
          markBlocked('incompatible-deployment');
        } else if (current(generation, sessionId)) {
          lastError = normalized.code;
          lifecycle = 'chat-error';
          publish();
        }
        throw normalized;
      }
    })().finally(() => {
      if (pendingReconnect === pending) pendingReconnect = undefined;
    });
    pending.promise = promise;
    pendingReconnect = pending;
    void promise.catch(() => undefined);

    try {
      await awaitWithAbort(promise, signal);
      return state();
    } catch (error) {
      if (isStale(error)) return state();
      throw error;
    }
  };

  const reconnectTerminal = async (signal?: AbortSignal): Promise<SessionCoordinatorState> => {
    assertUsable();
    const sessionId = assertSession();
    const generation = sessionGeneration;
    // Recovery uses the same activation and focus ownership as an explicit
    // Terminal selection, but never calls Chat connect, restore, or reconnect.
    const activation = beginModeActivation('terminal', generation, sessionId);

    try {
      if (!current(generation, sessionId)) return state();
      await ensureTerminalForCurrentSession(signal, activation.sequence);
      assertCurrent(generation, sessionId);
      if (!isCurrentModeActivation(activation)) return state();
      lifecycle = 'active';
      publish();
      publishFocus(activation);
      return state();
    } catch (error) {
      if (isStale(error)) return state();
      throw error;
    }
  };

  const closeChatOnce = (): void => {
    if (chatClosed) return;
    chatClosed = true;
    try {
      chat.close();
    } catch {
      // Terminal cleanup remains deterministic even if Chat cleanup throws.
    }
  };

  const logout = (): void => {
    if (disposed || loggedOut) return;

    // Claim the terminal lifecycle before adapter cleanup can reenter logout or
    // dispose. A nested dispose may promote this transition, but never repeats
    // its generation increment, binding cleanup, or Chat close.
    loggedOut = true;
    activeSessionId = undefined;
    sessionGeneration += 1;
    terminalLeaseCountForSession = 0;
    terminalStatus = 'detached';
    lastError = undefined;
    lastFocusIntent = undefined;
    mode = 'chat';
    lifecycle = 'logged-out';
    lifecycleCleanupInProgress = true;

    cancelSession();
    cancelTerminal();
    cancelReconnect();
    invalidateBinding();
    closeChatOnce();

    lifecycleCleanupInProgress = false;
    if (disposed) {
      lifecycle = 'disposed';
      publish();
      listeners.clear();
      return;
    }
    lifecycle = 'logged-out';
    publish();
  };

  const dispose = (): void => {
    if (disposed) return;
    if (loggedOut) {
      // Disposal has precedence over a completed or in-flight logout. The
      // logout owner already claimed cleanup and incremented the generation.
      disposed = true;
      lifecycle = 'disposed';
      if (!lifecycleCleanupInProgress) {
        publish();
        listeners.clear();
      }
      return;
    }

    // Claim disposal before adapter cleanup so nested logout/dispose calls are
    // idempotent and cannot overwrite the final disposed lifecycle.
    disposed = true;
    activeSessionId = undefined;
    sessionGeneration += 1;
    terminalLeaseCountForSession = 0;
    terminalStatus = 'detached';
    lastError = undefined;
    lastFocusIntent = undefined;
    mode = 'chat';
    lifecycle = 'disposed';
    lifecycleCleanupInProgress = true;

    cancelSession();
    cancelTerminal();
    cancelReconnect();
    invalidateBinding();
    closeChatOnce();

    lifecycleCleanupInProgress = false;
    lifecycle = 'disposed';
    publish();
    listeners.clear();
  };

  const subscribe = (listener: (nextState: SessionCoordinatorState) => void): (() => void) => {
    listeners.add(listener);
    return () => listeners.delete(listener);
  };

  return {
    get state(): SessionCoordinatorState {
      return state();
    },
    get activeSessionId(): string | undefined {
      return activeSessionId;
    },
    get mode(): WorkspaceMode {
      return mode;
    },
    activate,
    switchMode: activate,
    invalidateSession,
    invalidateTerminalBinding,
    setSession,
    restore,
    reconnect,
    reconnectTerminal,
    logout,
    dispose,
    subscribe
  };
}
