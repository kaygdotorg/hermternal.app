import {
  PtyTransportError,
  createFreshPtyTicketProvider,
  createPtyTransport,
  type PtyCloseClassification,
  type PtyConnectionState,
  type PtyMessageEvent,
  type PtyTicketRequestInput,
  type PtyTransport,
  type PtyTransportEvent,
  type PtyWebSocket,
  type PtyWebSocketFactory
} from './pty-transport';
import type { LiveRestFetch } from '$lib/transport';
import type { TerminalBinding, TerminalSessionPort } from '$lib/session/coordinator';

/**
 * The workspace-facing state deliberately omits attach/process identities. They
 * remain transport-owned opaque values and never become presentation state.
 */
export type CurrentSessionTerminalState = Readonly<{
  status: PtyConnectionState['status'];
  generation: number;
  sessionId?: string;
  closeCode?: number;
  closeClassification?: PtyCloseClassification;
  outputMayBeTruncated: boolean;
  explicitlyClosed: boolean;
  /** True only when the transport owns an opaque attach identity. */
  reconnectSupported?: boolean;
  failure?: 'authentication-required' | 'incompatible-origin';
}>;

export type CurrentSessionTerminalEvent =
  | Readonly<{ type: 'bytes'; generation: number; bytes: Uint8Array; outputMayBeTruncated: boolean }>
  | Readonly<{ type: 'state'; state: CurrentSessionTerminalState }>
  | Readonly<{
      type: 'notice';
      generation: number;
      notice: 'output-may-be-truncated';
      replayCapacityBytes: number;
    }>;

export type CurrentSessionTerminalListener = (event: CurrentSessionTerminalEvent) => void;

export type BrowserPtyWebSocketFactory = (
  url: string,
  signal: AbortSignal
) => PtyWebSocket;

export type BrowserPtyTransportOptions = Readonly<{
  fetch?: LiveRestFetch;
  createSocket?: BrowserPtyWebSocketFactory;
}>;

export type CurrentSessionTerminalAttachment = Readonly<{
  /** Opaque values remain inside the transport and are never projected to UI state. */
  attach: string;
  processIdentity: string;
  detachedAtMs?: number;
}>;

export type CurrentSessionTerminalAttachmentProvider = (
  sessionId: string,
  signal: AbortSignal
) => CurrentSessionTerminalAttachment | Promise<CurrentSessionTerminalAttachment>;

export type CurrentSessionTerminalBridgeOptions = Readonly<{
  createTransport: () => PtyTransport;
  /** Optional reviewed attach issuance seam. Omitted normal-route PTYs stay legacy and cannot reconnect. */
  createAttachment?: CurrentSessionTerminalAttachmentProvider;
}>;

interface ActiveBinding extends TerminalBinding {
  readonly token: object;
  valid: boolean;
}

type TransportCleanup = 'detach' | 'close';

/**
 * Tracks one adapter call that can still claim the bridge's sole PTY owner.
 * AbortSignal cancellation is only an optimization: an adapter may ignore it
 * and resolve after its binding was invalidated. The bridge therefore keeps the
 * operation quarantined until its promise settles, suppresses its events, and
 * performs a final adapter cleanup before another operation can start.
 */
interface PendingTransportOperation {
  readonly token: object;
  readonly sessionId: string;
  transportStarted: boolean;
  transportSettled: boolean;
  invalidated: boolean;
  initialCleanupIssued: boolean;
  initialCleanupMode?: TransportCleanup;
  finalCleanupIssued: boolean;
  cleanup: TransportCleanup;
}

/**
 * Adapts one current-session PTY transport to the shared coordinator. The
 * bridge forwards byte views directly to listeners and does not decode, log,
 * queue, or retain them. A mode switch leaves a valid binding attached; a
 * session replacement or explicit terminal action invalidates that binding.
 * Every invalidated adapter call remains quarantined until it settles, so late
 * completion cannot revive presentation state or leave raw PTY ownership
 * attached.
 */
export class CurrentSessionTerminalBridge implements TerminalSessionPort {
  private readonly transport: PtyTransport;
  private readonly createAttachment: CurrentSessionTerminalAttachmentProvider | undefined;
  private readonly listeners = new Set<CurrentSessionTerminalListener>();
  private readonly unsubscribeTransport: () => void;
  private currentState: CurrentSessionTerminalState;
  private activeBinding: ActiveBinding | undefined;
  private pendingTransportOperation: PendingTransportOperation | undefined;
  private disposed = false;
  private explicitlyClosed = false;
  private rendererReadyGateEnabled = false;
  private rendererReady = false;
  /** A workspace rejection marks this session until a later attach/reconnect owns it. */
  private invalidatedSessionId: string | undefined;
  /** Explicit reconnect owns a recovery attempt even before a binding is returned. */
  private reconnectingSessionId: string | undefined;
  private rendererReadyWaiters = new Set<{
    resolve: () => void;
    reject: (error: PtyTransportError) => void;
    signal?: AbortSignal;
    onAbort?: () => void;
  }>();

  constructor(options: CurrentSessionTerminalBridgeOptions) {
    this.transport = options.createTransport();
    this.createAttachment = options.createAttachment;
    this.currentState = projectState(this.transport.state, false);
    this.unsubscribeTransport = this.transport.subscribe((event) => this.handleTransportEvent(event));
  }

  get state(): CurrentSessionTerminalState {
    if (
      this.currentState.sessionId !== undefined &&
      this.currentState.sessionId === this.invalidatedSessionId &&
      this.activeBinding === undefined
    ) {
      // Do not let a renderer read the last stale session through the state
      // getter after the workspace has rejected it. Keep the transport-owned
      // session identity private for a later explicit reconnect/attach.
      return Object.freeze({
        status: 'detached',
        generation: this.currentState.generation,
        outputMayBeTruncated: this.currentState.outputMayBeTruncated,
        explicitlyClosed: this.explicitlyClosed
      });
    }
    return this.currentState;
  }

  /**
   * TerminalSurface enables this gate before first attach so PTY replay cannot
   * outrun the lazy renderer. Headless coordinator consumers leave it disabled.
   */
  setRendererReady(ready: boolean): void {
    if (this.disposed) return;
    this.rendererReadyGateEnabled = true;
    this.rendererReady = ready;
    if (!ready) return;
    for (const waiter of [...this.rendererReadyWaiters]) {
      this.rendererReadyWaiters.delete(waiter);
      if (waiter.signal && waiter.onAbort) waiter.signal.removeEventListener('abort', waiter.onAbort);
      waiter.resolve();
    }
  }

  subscribe(listener: CurrentSessionTerminalListener): () => void {
    if (this.disposed) return () => {};
    this.listeners.add(listener);
    // A workspace rejection may leave the transport's last state tagged with
    // the stale session while its detach callback is still settling. Do not
    // replay that stale presentation state to a later renderer subscriber;
    // only a new binding state may clear the rejection marker.
    if (
      this.currentState.sessionId === undefined ||
      this.currentState.sessionId !== this.invalidatedSessionId ||
      this.activeBinding !== undefined
    ) {
      try {
        listener({ type: 'state', state: this.currentState });
      } catch {
        // A presentation observer cannot interrupt bridge setup or transport flow.
      }
    }
    return () => this.listeners.delete(listener);
  }

  async attach(sessionId: string, signal: AbortSignal): Promise<TerminalBinding> {
    if (this.disposed) throw new PtyTransportError('closed');
    if (signal.aborted) throw new PtyTransportError('aborted');
    if (this.activeBinding?.valid && this.activeBinding.sessionId === sessionId) {
      return this.activeBinding;
    }
    this.invalidateActiveBinding();
    if (this.pendingTransportOperation !== undefined) throw new PtyTransportError('aborted');
    await this.waitForRendererReady(signal);
    if (this.disposed) throw new PtyTransportError('closed');
    if (signal.aborted) throw new PtyTransportError('aborted');

    this.explicitlyClosed = false;
    const token = {};
    const binding: ActiveBinding = {
      token,
      sessionId,
      valid: true,
      invalidate: () => {
        if (!binding.valid) return;
        binding.valid = false;
        if (this.activeBinding?.token !== token) return;
        this.activeBinding = undefined;
        this.reconnectingSessionId =
          this.reconnectingSessionId === sessionId ? undefined : this.reconnectingSessionId;
        this.invalidatedSessionId = sessionId;
        if (!this.invalidatePendingTransportOperation(token, 'detach')) {
          this.cleanupTransport('detach');
        }
      },
      isValid: () => binding.valid
    };
    this.reconnectingSessionId = undefined;
    this.activeBinding = binding;

    try {
      const attachment = this.createAttachment
        ? await this.createAttachment(sessionId, signal)
        : undefined;
      if (this.disposed || !binding.valid || this.activeBinding?.token !== token) {
        binding.valid = false;
        throw new PtyTransportError('aborted');
      }
      const operation = this.beginTransportOperation(token, sessionId);
      try {
        operation.transportStarted = true;
        await this.transport.connect(
          attachment === undefined ? { sessionId } : { sessionId, ...attachment },
          signal
        );
        operation.transportSettled = true;
        if (
          this.disposed ||
          operation.invalidated ||
          !binding.valid ||
          this.activeBinding?.token !== token
        ) {
          binding.valid = false;
          throw new PtyTransportError('aborted');
        }
        return binding;
      } catch (error) {
        operation.transportSettled = true;
        if (!operation.invalidated) {
          this.invalidateTransportOperation(operation, this.disposed ? 'close' : 'detach');
        }
        throw error;
      } finally {
        this.completeTransportOperation(operation);
      }
    } catch (error) {
      binding.valid = false;
      if (this.activeBinding?.token === token) {
        this.activeBinding = undefined;
        this.reconnectingSessionId =
          this.reconnectingSessionId === sessionId ? undefined : this.reconnectingSessionId;
        this.invalidatedSessionId = sessionId;
      }
      if (error instanceof PtyTransportError && error.code === 'authentication-required') {
        this.publishState({ ...this.currentState, status: 'failed', failure: 'authentication-required' });
      }
      throw error;
    }
  }

  release(_binding: TerminalBinding): void {
    // `invalidate()` owns transport detachment. Release is intentionally a
    // no-op so coordinator lease cleanup cannot close a newer binding.
  }

  /**
   * Closes a binding whose event crossed a workspace/session ownership fence.
   * This is separate from a user detach so a stale publication cannot merely be
   * hidden while the PTY remains active. A later attach clears the marker when
   * its own transport state is observed.
   */
  invalidateBindingForSession(sessionId: string): void {
    const binding = this.activeBinding;
    const pending = this.pendingTransportOperation;
    const reconnecting = this.reconnectingSessionId === sessionId;
    const pendingMatches = pending?.sessionId === sessionId;
    // A newer binding owns the transport and must never be detached by an old
    // session event. With no binding left, a matching pending adapter call is
    // still an owned transport attempt and must also be closed; otherwise retain
    // only the rejection marker so reentrant listeners cannot receive stale state.
    if (binding && binding.sessionId !== sessionId) return;
    if (pending && !pendingMatches && !binding) return;
    this.invalidatedSessionId = sessionId;
    if (binding) {
      this.invalidateActiveBinding();
    } else if (pendingMatches) {
      this.reconnectingSessionId = undefined;
      this.invalidateTransportOperation(pending, 'detach');
    } else if (reconnecting) {
      this.reconnectingSessionId = undefined;
      this.cleanupTransport('detach');
    }
  }

  sendInput(input: string | Uint8Array): void {
    if (this.disposed) throw new PtyTransportError('closed');
    this.transport.sendInput(input);
  }

  resize(cols: number, rows: number): void {
    if (this.disposed) throw new PtyTransportError('closed');
    this.transport.resize(cols, rows);
  }

  async reconnect(signal?: AbortSignal): Promise<void> {
    if (this.disposed) throw new PtyTransportError('closed');
    if (!this.currentState.reconnectSupported) {
      // The pinned server source has no client-visible attach-token issuance
      // route. Never relabel a legacy PTY as reattachable or silently spawn a
      // replacement process behind a Reconnect action.
      throw new PtyTransportError('legacy-reattach-prohibited', this.currentState.generation);
    }
    this.invalidatePendingTransportOperation(undefined, 'detach');
    if (this.pendingTransportOperation !== undefined) throw new PtyTransportError('aborted');
    await this.waitForRendererReady(signal);
    if (this.disposed) throw new PtyTransportError('closed');
    if (signal?.aborted) throw new PtyTransportError('aborted');
    this.explicitlyClosed = false;
    const reconnectingSessionId = this.currentState.sessionId;
    if (reconnectingSessionId === undefined) throw new PtyTransportError('aborted');
    this.reconnectingSessionId = reconnectingSessionId;
    const operation = this.beginTransportOperation({}, reconnectingSessionId);
    try {
      operation.transportStarted = true;
      await this.transport.reconnect(signal);
      operation.transportSettled = true;
      if (this.disposed || operation.invalidated) throw new PtyTransportError('aborted');
    } catch (error) {
      operation.transportSettled = true;
      if (!operation.invalidated) {
        this.invalidateTransportOperation(operation, this.disposed ? 'close' : 'detach');
      }
      if (this.reconnectingSessionId === reconnectingSessionId) {
        this.reconnectingSessionId = undefined;
      }
      if (
        !operation.invalidated &&
        error instanceof PtyTransportError &&
        error.code === 'authentication-required'
      ) {
        this.publishState({ ...this.currentState, status: 'failed', failure: 'authentication-required' });
      }
      throw error;
    } finally {
      this.completeTransportOperation(operation);
    }
  }

  /**
   * Reacquires a coordinator-owned binding before an attach-mode reconnect is
   * exposed as attached. Direct transport reconnect remains available only for
   * the bridge's transport seam; workspace actions must use this lease path.
   */
  async reconnectBinding(
    sessionId: string,
    signal?: AbortSignal,
    onBindingReady?: (binding: TerminalBinding) => void
  ): Promise<TerminalBinding> {
    if (this.disposed) throw new PtyTransportError('closed');
    if (signal?.aborted) throw new PtyTransportError('aborted');
    if (this.currentState.sessionId !== sessionId) throw new PtyTransportError('aborted');
    if (!this.currentState.reconnectSupported) {
      throw new PtyTransportError('legacy-reattach-prohibited', this.currentState.generation);
    }

    this.invalidateActiveBinding();
    if (this.pendingTransportOperation !== undefined) throw new PtyTransportError('aborted');
    await this.waitForRendererReady(signal);
    if (this.disposed) throw new PtyTransportError('closed');
    if (signal?.aborted) throw new PtyTransportError('aborted');

    this.explicitlyClosed = false;
    const token = {};
    const binding: ActiveBinding = {
      token,
      sessionId,
      valid: true,
      invalidate: () => {
        if (!binding.valid) return;
        binding.valid = false;
        if (this.activeBinding?.token !== token) return;
        this.activeBinding = undefined;
        this.reconnectingSessionId =
          this.reconnectingSessionId === sessionId ? undefined : this.reconnectingSessionId;
        this.invalidatedSessionId = sessionId;
        if (!this.invalidatePendingTransportOperation(token, 'detach')) {
          this.cleanupTransport('detach');
        }
      },
      isValid: () => binding.valid
    };
    this.activeBinding = binding;
    this.reconnectingSessionId = sessionId;
    const operation = this.beginTransportOperation(token, sessionId);

    try {
      // The coordinator adopts this fresh lease before reconnect can publish a
      // synchronous attached transition. Direct bridge callers may omit the
      // callback and retain the transport-only reconnect behavior.
      onBindingReady?.(binding);
      if (this.disposed || operation.invalidated || !binding.valid || this.activeBinding?.token !== token) {
        binding.valid = false;
        throw new PtyTransportError('aborted');
      }
      operation.transportStarted = true;
      await this.transport.reconnect(signal);
      operation.transportSettled = true;
      if (this.disposed || operation.invalidated || !binding.valid || this.activeBinding?.token !== token) {
        binding.valid = false;
        throw new PtyTransportError('aborted');
      }
      return binding;
    } catch (error) {
      operation.transportSettled = true;
      if (!operation.invalidated && operation.transportStarted) {
        this.invalidateTransportOperation(operation, this.disposed ? 'close' : 'detach');
      }
      binding.valid = false;
      if (this.activeBinding?.token === token) this.activeBinding = undefined;
      if (this.reconnectingSessionId === sessionId) this.reconnectingSessionId = undefined;
      if (
        !operation.invalidated &&
        error instanceof PtyTransportError &&
        error.code === 'authentication-required'
      ) {
        this.publishState({ ...this.currentState, status: 'failed', failure: 'authentication-required' });
      }
      throw error;
    } finally {
      this.completeTransportOperation(operation);
    }
  }

  detach(): void {
    if (this.disposed) return;
    this.explicitlyClosed = false;
    this.reconnectingSessionId = undefined;
    this.cancelRendererReadyWaiters(new PtyTransportError('aborted'));
    this.invalidateActiveBinding('detach');
  }

  close(): void {
    if (this.disposed) return;
    this.explicitlyClosed = true;
    this.reconnectingSessionId = undefined;
    this.cancelRendererReadyWaiters(new PtyTransportError('closed'));
    if (!this.invalidateActiveBinding('close')) this.cleanupTransport('close');
    this.publishState(projectState(this.transport.state, true));
  }

  dispose(): void {
    if (this.disposed) return;
    // Unsubscribe and clear observers before closing the adapter. Some test and
    // browser WebSocket shims emit synchronously from close(); a disposed bridge
    // must not publish a final state into a torn-down workspace. A pending
    // adapter call stays quarantined and receives a second close after its late
    // completion, because the first close cannot be assumed to cancel it.
    this.disposed = true;
    this.reconnectingSessionId = undefined;
    this.unsubscribeTransport();
    this.listeners.clear();
    this.cancelRendererReadyWaiters(new PtyTransportError('closed'));
    if (!this.invalidateActiveBinding('close')) this.cleanupTransport('close');
  }

  private cancelRendererReadyWaiters(error: PtyTransportError): void {
    for (const waiter of [...this.rendererReadyWaiters]) {
      this.rendererReadyWaiters.delete(waiter);
      if (waiter.signal && waiter.onAbort) waiter.signal.removeEventListener('abort', waiter.onAbort);
      waiter.reject(error);
    }
  }

  private beginTransportOperation(token: object, sessionId: string): PendingTransportOperation {
    if (this.pendingTransportOperation !== undefined) {
      throw new PtyTransportError('aborted');
    }
    const operation: PendingTransportOperation = {
      token,
      sessionId,
      transportStarted: false,
      transportSettled: false,
      invalidated: false,
      initialCleanupIssued: false,
      finalCleanupIssued: false,
      cleanup: 'detach'
    };
    this.pendingTransportOperation = operation;
    return operation;
  }

  private invalidatePendingTransportOperation(
    token: object | undefined,
    cleanup: TransportCleanup
  ): boolean {
    const operation = this.pendingTransportOperation;
    if (operation === undefined || (token !== undefined && operation.token !== token)) return false;
    this.invalidateTransportOperation(operation, cleanup);
    return true;
  }

  private invalidateTransportOperation(
    operation: PendingTransportOperation,
    cleanup: TransportCleanup
  ): void {
    if (!operation.invalidated) {
      operation.invalidated = true;
      operation.cleanup = cleanup;
      this.invalidatedSessionId = operation.sessionId;
    } else if (cleanup === 'close') {
      // Explicit close/disposal is stronger than a prior lease detach. Keep the
      // late-completion cleanup closed even if detachment was already requested.
      operation.cleanup = 'close';
    }

    if (
      operation.transportStarted &&
      !operation.initialCleanupIssued &&
      !operation.transportSettled
    ) {
      operation.initialCleanupIssued = true;
      operation.initialCleanupMode = operation.cleanup;
      this.cleanupTransport(operation.cleanup);
    } else if (
      operation.transportStarted &&
      operation.cleanup === 'close' &&
      operation.initialCleanupMode !== 'close' &&
      !operation.transportSettled
    ) {
      operation.initialCleanupMode = 'close';
      this.cleanupTransport('close');
    }

    if (operation.transportSettled) this.finalizeTransportOperation(operation);
  }

  private finalizeTransportOperation(operation: PendingTransportOperation): void {
    if (!operation.invalidated || !operation.transportStarted || operation.finalCleanupIssued) return;
    operation.finalCleanupIssued = true;
    this.cleanupTransport(operation.cleanup);
  }

  private completeTransportOperation(operation: PendingTransportOperation): void {
    operation.transportSettled = true;
    this.finalizeTransportOperation(operation);
    if (this.pendingTransportOperation === operation) this.pendingTransportOperation = undefined;
  }

  private cleanupTransport(cleanup: TransportCleanup): void {
    try {
      if (cleanup === 'close') this.transport.close();
      else this.transport.detach();
    } catch {
      // A stale adapter must not escape the bridge's cleanup boundary. If a
      // detach implementation throws, close is the fail-closed fallback that
      // prevents an adapter from retaining raw PTY ownership indefinitely.
      if (cleanup === 'detach') {
        try {
          this.transport.close();
        } catch {
          // The adapter remains responsible for its own last-resort failure.
        }
      }
    }
  }

  private waitForRendererReady(signal?: AbortSignal): Promise<void> {
    if (!this.rendererReadyGateEnabled || this.rendererReady) return Promise.resolve();
    if (signal?.aborted) return Promise.reject(new PtyTransportError('aborted'));
    return new Promise<void>((resolve, reject) => {
      const waiter: {
        resolve: () => void;
        reject: (error: PtyTransportError) => void;
        signal?: AbortSignal;
        onAbort?: () => void;
      } = {
        resolve,
        reject,
        signal,
        onAbort: undefined
      };
      if (signal) {
        waiter.onAbort = () => {
          this.rendererReadyWaiters.delete(waiter);
          reject(new PtyTransportError('aborted'));
        };
        signal.addEventListener('abort', waiter.onAbort, { once: true });
      }
      this.rendererReadyWaiters.add(waiter);
    });
  }

  private invalidateActiveBinding(cleanup: TransportCleanup = 'detach'): boolean {
    const binding = this.activeBinding;
    this.activeBinding = undefined;
    if (binding) {
      binding.valid = false;
      this.invalidatedSessionId = binding.sessionId;
    }

    const pending = this.pendingTransportOperation;
    if (pending !== undefined && (binding === undefined || pending.sessionId === binding.sessionId)) {
      this.invalidateTransportOperation(pending, cleanup);
      return true;
    }
    if (binding !== undefined) {
      this.cleanupTransport(cleanup);
      return true;
    }
    return false;
  }

  private handleTransportEvent(event: PtyTransportEvent): void {
    if (this.disposed) return;
    const pending = this.pendingTransportOperation;
    const eventSessionId = event.type === 'state' ? event.state.sessionId : this.currentState.sessionId;
    if (
      pending?.invalidated &&
      (eventSessionId === pending.sessionId || this.currentState.sessionId === pending.sessionId)
    ) {
      // Quarantine every callback from an invalidated adapter call until its
      // promise settles. The adapter may emit attached or bytes synchronously
      // after ignoring AbortSignal; those events cannot establish ownership.
      if (event.type === 'state' && event.state.generation >= this.currentState.generation) {
        this.currentState = projectState(event.state, this.explicitlyClosed);
      }
      return;
    }
    if (event.type === 'bytes') {
      // Generation is checked before forwarding, while the payload remains an
      // opaque view. The renderer owns its bounded queue; this bridge never
      // copies, decodes, inspects, or retains terminal bytes. A session rejected
      // by the workspace fence stays closed until a later attach owns it again.
      if (event.generation !== this.currentState.generation) return;
      if (this.invalidatedSessionId === this.currentState.sessionId) return;
      this.emit({
        type: 'bytes',
        generation: event.generation,
        bytes: event.bytes,
        outputMayBeTruncated: event.outputMayBeTruncated
      });
      return;
    }
    if (event.type === 'notice') {
      if (event.generation !== this.currentState.generation) return;
      if (this.invalidatedSessionId === this.currentState.sessionId) return;
      this.emit({
        type: 'notice',
        generation: event.generation,
        notice: event.notice,
        replayCapacityBytes: event.replayCapacityBytes
      });
      return;
    }
    if (event.state.generation < this.currentState.generation) return;
    if (
      this.activeBinding &&
      event.state.sessionId !== undefined &&
      event.state.sessionId !== this.activeBinding.sessionId
    ) {
      // The transport normally suppresses stale generations itself. Keep this
      // second boundary fail-closed so a late state cannot revive an old lease.
      return;
    }
    const reconnecting =
      this.reconnectingSessionId !== undefined &&
      this.reconnectingSessionId === event.state.sessionId &&
      event.state.generation >= this.currentState.generation;
    if (event.state.sessionId !== undefined && this.activeBinding?.sessionId === event.state.sessionId) {
      // A new binding owns the transport again. It may clear a prior workspace
      // rejection only after its own state, not an old callback, is observed.
      this.invalidatedSessionId = undefined;
      this.reconnectingSessionId = undefined;
    } else if (reconnecting) {
      // Explicit reconnect owns a transport attempt before it can return a
      // binding. Its generation-tagged lifecycle states are the only no-binding
      // events allowed to clear the stale marker.
      this.invalidatedSessionId = undefined;
      if (
        event.state.status === 'attached' ||
        event.state.status === 'detached' ||
        event.state.status === 'failed' ||
        event.state.status === 'exited'
      ) {
        this.reconnectingSessionId = undefined;
      }
    }
    if (
      event.state.sessionId !== undefined &&
      event.state.sessionId === this.invalidatedSessionId &&
      !this.activeBinding
    ) {
      // Keep the bridge state current for later recovery, but do not publish a
      // nested detach/close transition from the stale transport to renderers.
      this.currentState = projectState(event.state, this.explicitlyClosed);
      return;
    }
    if (event.state.status === 'detached' || event.state.status === 'failed' || event.state.status === 'exited') {
      // An unsolicited terminal failure makes the coordinator lease stale. The
      // next Terminal activation must be allowed to attach again. If the state
      // belongs to a still-pending adapter call, quarantine that call too; its
      // promise may otherwise resolve into a second attached transition.
      if (pending !== undefined && pending.sessionId === event.state.sessionId) {
        this.invalidateTransportOperation(pending, 'detach');
      }
      if (this.activeBinding) this.activeBinding.valid = false;
      this.activeBinding = undefined;
    }
    this.publishState(projectState(event.state, this.explicitlyClosed));
  }

  private publishState(state: CurrentSessionTerminalState): void {
    this.currentState = state;
    this.emit({ type: 'state', state });
  }

  private emit(event: CurrentSessionTerminalEvent): void {
    for (const listener of [...this.listeners]) {
      if (
        event.type !== 'state' &&
        this.invalidatedSessionId === this.currentState.sessionId
      ) {
        return;
      }
      if (
        event.type === 'state' &&
        event.state.sessionId !== undefined &&
        event.state.sessionId === this.invalidatedSessionId &&
        !this.activeBinding
      ) {
        return;
      }
      try {
        listener(event);
      } catch {
        // Presentation observers cannot interrupt transport cleanup or byte flow.
      }
    }
  }
}

function projectState(state: PtyConnectionState, explicitlyClosed: boolean): CurrentSessionTerminalState {
  const failure =
    state.closeClassification === 'authentication-rejected'
      ? 'authentication-required'
      : state.closeClassification === 'host-or-origin-rejected'
        ? 'incompatible-origin'
        : undefined;
  return Object.freeze({
    status: state.status,
    generation: state.generation,
    ...(state.sessionId === undefined ? {} : { sessionId: state.sessionId }),
    ...(state.closeCode === undefined ? {} : { closeCode: state.closeCode }),
    ...(state.closeClassification === undefined ? {} : { closeClassification: state.closeClassification }),
    outputMayBeTruncated: state.outputMayBeTruncated,
    explicitlyClosed,
    reconnectSupported: state.reconnectSupported ?? state.mode === 'attach',
    ...(failure === undefined ? {} : { failure })
  });
}

/**
 * Browser-only transport composition. The ticket response is handed straight
 * to the PTY parser; no ticket, URL, or socket diagnostic enters bridge state.
 */
export function createBrowserPtyTransport(options: BrowserPtyTransportOptions = {}): PtyTransport {
  const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (!fetcher) throw new PtyTransportError('invalid-options');
  const createSocket = options.createSocket ?? defaultBrowserPtySocket;
  const ticketProvider = createFreshPtyTicketProvider(async (input: PtyTicketRequestInput) => {
    let response: Response;
    try {
      response = await fetcher('/api/auth/ws-ticket', {
        method: input.method,
        credentials: input.credentials,
        signal: input.signal
      });
    } catch (error) {
      if (input.signal.aborted) throw new PtyTransportError('aborted');
      throw error;
    }
    if (response.status === 401) throw new PtyTransportError('authentication-required');
    if (!response.ok) throw new PtyTransportError('connection-failed');
    try {
      return await response.json();
    } catch {
      throw new PtyTransportError('invalid-ticket');
    }
  });

  return createPtyTransport({
    ticketProvider,
    createWebSocket: (upgrade, signal) => {
      const url = new URL(upgrade.path, globalThis.location?.origin ?? 'http://localhost');
      url.searchParams.set('ticket', upgrade.query.ticket);
      url.searchParams.set('resume', upgrade.query.resume);
      if (upgrade.query.attach !== undefined) url.searchParams.set('attach', upgrade.query.attach);
      return createSocket(url.toString(), signal);
    }
  });
}

function defaultBrowserPtySocket(url: string, signal: AbortSignal): PtyWebSocket {
  if (typeof WebSocket === 'undefined') throw new PtyTransportError('invalid-options');
  const nativeSocket = new WebSocket(url);
  nativeSocket.binaryType = 'arraybuffer';
  const adapter: PtyWebSocket = {
    onopen: null,
    onmessage: null,
    onerror: null,
    onclose: null,
    send: (data) => nativeSocket.send(data as unknown as ArrayBuffer),
    close: (code, reason) => nativeSocket.close(code, reason),
    get readyState() {
      return nativeSocket.readyState;
    }
  };
  const closeOnAbort = (): void => adapter.close(1000, 'cancelled');
  signal.addEventListener('abort', closeOnAbort, { once: true });
  nativeSocket.onopen = (event) => adapter.onopen?.(event);
  nativeSocket.onmessage = (event: MessageEvent) => adapter.onmessage?.({ data: event.data } as PtyMessageEvent);
  nativeSocket.onerror = (event) => adapter.onerror?.(event);
  nativeSocket.onclose = (event) => {
    signal.removeEventListener('abort', closeOnAbort);
    adapter.onclose?.({ code: event.code });
  };
  return adapter;
}
