import {
  createWsTicketRequestBoundary,
  type WsTicketFetch,
} from "$lib/chat/ws-ticket";
import {
  PtyTransportError,
  createFreshPtyTicketProvider,
  createPtyTransport,
  type PtyCloseClassification,
  type PtyErrorCode,
  type PtyAttachmentValidator,
  type PtyConnectionState,
  type PtyMessageEvent,
  type PtyTransport,
  type PtyTransportEvent,
  type PtyWebSocket,
  type PtyWebSocketFactory,
} from "./pty-transport";
import type { LiveRestFetch } from "$lib/transport";
import type {
  TerminalBinding,
  TerminalSessionPort,
} from "$lib/session/coordinator";

/**
 * The workspace-facing state deliberately omits attach/process identities. They
 * remain transport-owned opaque values and never become presentation state.
 */
export type CurrentSessionTerminalState = Readonly<{
  status: PtyConnectionState["status"];
  generation: number;
  sessionId?: string;
  closeCode?: number;
  closeClassification?: PtyCloseClassification;
  outputMayBeTruncated: boolean;
  explicitlyClosed: boolean;
  /** True only when the transport owns an opaque attach identity. */
  reconnectSupported?: boolean;
  failure?: "authentication-required" | "incompatible-origin";
}>;

export type CurrentSessionTerminalEvent =
  | Readonly<{
      type: "bytes";
      generation: number;
      bytes: Uint8Array;
      outputMayBeTruncated: boolean;
    }>
  | Readonly<{
      type: "state";
      state: CurrentSessionTerminalState;
      /** Producer-issued proof captured before terminal settlement can retire its lease. */
      lifecycle?: CurrentSessionTerminalLifecycleStamp;
    }>
  | Readonly<{
      type: "notice";
      generation: number;
      notice: "output-may-be-truncated";
      replayCapacityBytes: number;
    }>;

/**
 * This is the sole lifecycle fence exported by the bridge. `binding` is an
 * opaque coordinator lease (not an attach/process identity); consumers compare
 * it by reference and pair it with the transport's native generation. Root
 * callers must not invent a second lifecycle counter for this bridge.
 */
export type CurrentSessionTerminalLifecycleIdentity = Readonly<{
  binding: TerminalBinding | undefined;
  nativeTransportGeneration: number;
}>;

/**
 * A state callback receives this opaque producer capability instead of a
 * structural identity. The backing map is module-private, so callers cannot
 * forge root registration with a lookalike binding or generation object.
 */
export type CurrentSessionTerminalLifecycleStamp = object;

const lifecycleStamps = new WeakMap<object, CurrentSessionTerminalLifecycleIdentity>();

function createLifecycleStamp(
  identity: CurrentSessionTerminalLifecycleIdentity,
): CurrentSessionTerminalLifecycleStamp {
  const stamp = {};
  lifecycleStamps.set(stamp, identity);
  return stamp;
}

/** Returns bridge-captured truth only for a producer-issued callback stamp. */
export function getCurrentSessionTerminalLifecycleIdentity(
  stamp: CurrentSessionTerminalLifecycleStamp,
): CurrentSessionTerminalLifecycleIdentity | undefined {
  return lifecycleStamps.get(stamp);
}

export type CurrentSessionTerminalListener = (
  event: CurrentSessionTerminalEvent,
) => void;

export type BrowserPtyWebSocketFactory = (
  url: string,
  signal: AbortSignal,
) => PtyWebSocket;

export type BrowserPtyTransportOptions = Readonly<{
  fetch?: LiveRestFetch;
  createSocket?: BrowserPtyWebSocketFactory;
  /** Attach mode requires this issuance-owned validator; omitted stays legacy-only. */
  validateAttachment?: PtyAttachmentValidator;
}>;

export type CurrentSessionTerminalAttachment = Readonly<{
  /** Opaque values remain inside the transport and are never projected to UI state. */
  attach: string;
  processIdentity: string;
  detachedAtMs?: number;
}>;

export type CurrentSessionTerminalAttachmentProvider = (
  sessionId: string,
  signal: AbortSignal,
) =>
  CurrentSessionTerminalAttachment | Promise<CurrentSessionTerminalAttachment>;

export type CurrentSessionTerminalBridgeOptions = Readonly<{
  /**
   * The bridge serializes replacement until an invalidated operation settles.
   * This keeps the merged PtyTransport's native generation as the sole late
   * settlement owner; arbitrary adapters need no undocumented cleanup hook.
   */
  createTransport: () => PtyTransport;
  /** Optional reviewed attach issuance seam. Omitted normal-route PTYs stay legacy and cannot reconnect. */
  createAttachment?: CurrentSessionTerminalAttachmentProvider;
}>;

interface ActiveBinding extends TerminalBinding {
  readonly token: object;
  valid: boolean;
  /** Internal/test-only lease inspection; TerminalSessionPort exposes no validity API. */
  isValid(): boolean;
}

type TransportCleanup = "detach" | "close";

/**
 * Tracks one adapter call that can still claim the bridge's sole PTY owner.
 * AbortSignal cancellation is only an optimization: an adapter may ignore it
 * and resolve after its binding was invalidated. The bridge therefore keeps the
 * operation quarantined until its promise settles, suppresses its events, and
 * performs a final adapter cleanup before another operation can start.
 */
interface PendingAttach {
  readonly token: object;
  readonly sessionId: string;
  readonly completion: Promise<void>;
  resolveCompletion: () => void;
}

interface PendingTransportOperation {
  readonly token: object;
  readonly sessionId: string;
  /** Native generation immediately before this operation claims the transport. */
  readonly nativeGeneration: number;
  transportStarted: boolean;
  transportSettled: boolean;
  invalidated: boolean;
  terminalObserved: boolean;
  initialCleanupIssued: boolean;
  initialCleanupMode?: TransportCleanup;
  cleanupIssued: boolean;
  /** Close may escalate a prior detach while this operation remains quarantined. */
  closeCleanupIssued: boolean;
  cleanup: TransportCleanup;
  /** Resolves only after this call's one deferred cleanup has completed. */
  readonly completion: Promise<void>;
  resolveCompletion: () => void;
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
  private readonly createAttachment:
    CurrentSessionTerminalAttachmentProvider | undefined;
  private readonly listeners = new Set<CurrentSessionTerminalListener>();
  private readonly unsubscribeTransport: () => void;
  private currentState: CurrentSessionTerminalState;
  private activeBinding: ActiveBinding | undefined;
  /** Same-session callers share the original attach outcome, never a provisional lease. */
  private pendingAttach: PendingAttach | undefined;
  /** The active call is replaceable; invalidated calls remain here only for late cleanup. */
  private pendingTransportOperation: PendingTransportOperation | undefined;
  private readonly quarantinedTransportOperations =
    new Set<PendingTransportOperation>();
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
    this.unsubscribeTransport = this.transport.subscribe((event) =>
      this.handleTransportEvent(event),
    );
  }

  get lifecycleIdentity(): CurrentSessionTerminalLifecycleIdentity {
    // `generation` is native PTY state, and the binding is the coordinator's
    // actual lease. This deliberately exposes no bridge/root-created counter.
    return Object.freeze({
      binding: this.activeBinding?.valid ? this.activeBinding : undefined,
      nativeTransportGeneration: this.currentState.generation,
    });
  }

  get state(): CurrentSessionTerminalState {
    if (
      this.currentState.sessionId !== undefined &&
      this.currentState.sessionId === this.invalidatedSessionId &&
      this.activeBinding === undefined
    ) {
      // Keep the transport-owned session identity private after workspace
      // invalidation, but preserve the classified terminal outcome. User
      // detach/close and initial 4401/4403 failures must not be relabeled as a
      // generic detached snapshot merely because no binding remains.
      const terminalStatus =
        this.currentState.status === "detached" ||
        this.currentState.status === "failed" ||
        this.currentState.status === "exited" ||
        this.currentState.status === "closed";
      const {
        sessionId: _sessionId,
        reconnectSupported: _reconnectSupported,
        ...safeState
      } = this.currentState;
      return Object.freeze({
        ...safeState,
        status: terminalStatus ? this.currentState.status : "detached",
        reconnectSupported: false,
      });
    }
    return this.currentState;
  }

  /**
   * TerminalSurface enables this gate before first attach so PTY replay cannot
   * outrun the lazy renderer. Readiness belongs to one renderer/session sink and
   * closes before that sink loses ownership; headless consumers leave it disabled.
   */
  setRendererReady(ready: boolean): void {
    if (this.disposed) return;
    this.rendererReadyGateEnabled = true;
    this.rendererReady = ready;
    if (!ready) return;
    for (const waiter of [...this.rendererReadyWaiters]) {
      this.rendererReadyWaiters.delete(waiter);
      if (waiter.signal && waiter.onAbort)
        waiter.signal.removeEventListener("abort", waiter.onAbort);
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
        listener({
          type: "state",
          state: this.currentState,
          lifecycle: createLifecycleStamp(this.lifecycleIdentity),
        });
      } catch {
        // A presentation observer cannot interrupt bridge setup or transport flow.
      }
    }
    return () => this.listeners.delete(listener);
  }

  async attach(
    sessionId: string,
    signal: AbortSignal,
  ): Promise<TerminalBinding> {
    if (this.disposed) throw new PtyTransportError("closed");
    if (signal.aborted) throw new PtyTransportError("aborted");
    const pendingAttach = this.pendingAttach;
    if (pendingAttach !== undefined) {
      // Attachment issuance is also an ownership attempt. Serialize every caller
      // behind it, so a same-session caller cannot receive a provisional lease.
      await pendingAttach.completion;
      return this.attach(sessionId, signal);
    }
    if (
      this.activeBinding?.valid &&
      this.activeBinding.sessionId === sessionId
    ) {
      return this.activeBinding;
    }

    // An arbitrary adapter can ignore cancellation and claim raw PTY ownership
    // after its caller leaves. Invalidate A, then wait for its one cleanup before
    // allowing this attachment to touch the shared adapter.
    if (
      this.pendingTransportOperation !== undefined ||
      this.quarantinedTransportOperations.size > 0
    ) {
      this.invalidateActiveBinding();
      await this.waitForQuarantinedTransportOperations(signal);
      return this.attach(sessionId, signal);
    }

    const token = {};
    const attachAttempt = this.beginAttachAttempt(token, sessionId);
    let binding: ActiveBinding | undefined;
    try {
      this.invalidateActiveBinding();
      await this.waitForRendererReady(signal);
      if (this.disposed) throw new PtyTransportError("closed");
      if (signal.aborted) throw new PtyTransportError("aborted");

      this.explicitlyClosed = false;
      binding = {
        token,
        sessionId,
        valid: true,
        invalidate: () => {
          if (!binding?.valid) return;
          binding.valid = false;
          if (this.activeBinding?.token !== token) return;
          this.activeBinding = undefined;
          this.reconnectingSessionId =
            this.reconnectingSessionId === sessionId
              ? undefined
              : this.reconnectingSessionId;
          this.invalidatedSessionId = sessionId;
          if (!this.invalidatePendingTransportOperation(token, "detach")) {
            this.cleanupTransport("detach");
          }
        },
        isValid: () => binding?.valid ?? false,
      };
      this.reconnectingSessionId = undefined;
      this.activeBinding = binding;

      let attachment: CurrentSessionTerminalAttachment | undefined;
      try {
        attachment = this.createAttachment
          ? await this.createAttachment(sessionId, signal)
          : undefined;
      } catch (error) {
        throw normalizeBridgeError(error, "invalid-attachment");
      }
      if (
        this.disposed ||
        !binding.valid ||
        this.activeBinding?.token !== token
      ) {
        binding.valid = false;
        throw new PtyTransportError("aborted");
      }
      const operation = this.beginTransportOperation(token, sessionId);
      try {
        operation.transportStarted = true;
        await this.transport.connect(
          attachment === undefined
            ? { sessionId }
            : { sessionId, ...attachment },
          signal,
        );
        operation.transportSettled = true;
        if (
          this.disposed ||
          operation.invalidated ||
          !binding.valid ||
          this.activeBinding?.token !== token
        ) {
          binding.valid = false;
          throw new PtyTransportError("aborted");
        }
        return binding;
      } catch (error) {
        operation.transportSettled = true;
        if (!operation.invalidated) {
          this.invalidateTransportOperation(
            operation,
            this.disposed ? "close" : "detach",
          );
        }
        throw error;
      } finally {
        this.completeTransportOperation(operation);
      }
    } catch (error) {
      if (binding) binding.valid = false;
      if (this.activeBinding?.token === token) {
        this.activeBinding = undefined;
        this.reconnectingSessionId =
          this.reconnectingSessionId === sessionId
            ? undefined
            : this.reconnectingSessionId;
        this.invalidatedSessionId = sessionId;
      }
      throw normalizeBridgeError(error, "connection-failed");
    } finally {
      this.completeAttachAttempt(attachAttempt);
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
  invalidateBindingForSession(
    sessionId: string,
    expected: CurrentSessionTerminalLifecycleIdentity,
  ): void {
    const binding = this.activeBinding;
    // A workspace callback must carry the binding plus the real native
    // generation it observed. A stale A callback cannot detach same-session B.
    if (
      expected.binding === undefined ||
      binding !== expected.binding ||
      expected.nativeTransportGeneration !== this.currentState.generation ||
      binding.sessionId !== sessionId
    )
      return;
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
      this.invalidateTransportOperation(pending, "detach");
    } else if (reconnecting) {
      this.reconnectingSessionId = undefined;
      this.cleanupTransport("detach");
    }
  }

  sendInput(input: string | Uint8Array): void {
    if (this.disposed) throw new PtyTransportError("closed");
    if (!this.activeBinding?.valid) throw new PtyTransportError("not-attached");
    this.transport.sendInput(input);
  }

  resize(cols: number, rows: number): void {
    if (this.disposed) throw new PtyTransportError("closed");
    if (!this.activeBinding?.valid) throw new PtyTransportError("not-attached");
    this.transport.resize(cols, rows);
  }

  async reconnect(signal?: AbortSignal): Promise<void> {
    if (this.disposed) throw new PtyTransportError("closed");
    if (!this.currentState.reconnectSupported) {
      // The pinned server source has no client-visible attach-token issuance
      // route. Never relabel a legacy PTY as reattachable or silently spawn a
      // replacement process behind a Reconnect action.
      throw new PtyTransportError(
        "legacy-reattach-prohibited",
        this.currentState.generation,
      );
    }
    if (
      this.pendingTransportOperation !== undefined ||
      this.quarantinedTransportOperations.size > 0
    ) {
      this.invalidatePendingTransportOperation(undefined, "detach");
      await this.waitForQuarantinedTransportOperations(signal);
      return this.reconnect(signal);
    }
    await this.waitForRendererReady(signal);
    if (this.disposed) throw new PtyTransportError("closed");
    if (signal?.aborted) throw new PtyTransportError("aborted");
    this.explicitlyClosed = false;
    const reconnectingSessionId = this.currentState.sessionId;
    if (reconnectingSessionId === undefined)
      throw new PtyTransportError("aborted");

    // Reconnect must not replace the coordinator's existing lease with a
    // private binding. Retain and invalidate that lease truthfully; a reconnect
    // started without one remains input-ineligible until the coordinator attaches.
    const binding = this.activeBinding;
    const token = binding?.token ?? {};
    this.reconnectingSessionId = reconnectingSessionId;
    const operation = this.beginTransportOperation(
      token,
      reconnectingSessionId,
    );
    try {
      operation.transportStarted = true;
      await this.transport.reconnect(signal);
      operation.transportSettled = true;
      if (
        this.disposed ||
        operation.invalidated ||
        (binding !== undefined &&
          (!binding.valid || this.activeBinding?.token !== token))
      ) {
        if (binding) binding.valid = false;
        throw new PtyTransportError("aborted");
      }
    } catch (error) {
      operation.transportSettled = true;
      if (!operation.invalidated) {
        this.invalidateTransportOperation(
          operation,
          this.disposed ? "close" : "detach",
        );
      }
      if (binding) binding.valid = false;
      if (this.activeBinding?.token === token) this.activeBinding = undefined;
      if (this.reconnectingSessionId === reconnectingSessionId) {
        this.reconnectingSessionId = undefined;
      }
      throw normalizeBridgeError(error, "connection-failed");
    } finally {
      this.completeTransportOperation(operation);
    }
  }

  detach(): void {
    if (this.disposed) return;
    this.explicitlyClosed = false;
    this.reconnectingSessionId = undefined;
    this.cancelRendererReadyWaiters(new PtyTransportError("aborted"));
    this.invalidateActiveBinding("detach");
    // A generic adapter may not emit a state transition from detach(). Publish a
    // truthful detached/exited projection rather than leaving an attached
    // snapshot visible; never overwrite a reentrant replacement binding.
    if (this.activeBinding !== undefined) return;
    const transportState = this.transport.state;
    const status = transportState.mode === "attach" ? "detached" : "exited";
    this.publishState(projectState({ ...transportState, status }, false), true);
  }

  close(): void {
    if (this.disposed) return;
    this.explicitlyClosed = true;
    this.reconnectingSessionId = undefined;
    this.cancelRendererReadyWaiters(new PtyTransportError("closed"));
    this.invalidateActiveBinding("close");
    this.escalateQuarantinedCleanupToClose();
    if (this.activeBinding !== undefined) return;
    // Close is an explicit user terminal state even if the adapter keeps its
    // last attached snapshot or does not synchronously report its own close.
    this.publishState(
      projectState({ ...this.transport.state, status: "closed" }, true),
      true,
    );
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
    this.cancelRendererReadyWaiters(new PtyTransportError("closed"));
    this.invalidateActiveBinding("close");
    this.escalateQuarantinedCleanupToClose();
  }

  private cancelRendererReadyWaiters(error: PtyTransportError): void {
    for (const waiter of [...this.rendererReadyWaiters]) {
      this.rendererReadyWaiters.delete(waiter);
      if (waiter.signal && waiter.onAbort)
        waiter.signal.removeEventListener("abort", waiter.onAbort);
      waiter.reject(error);
    }
  }

  private beginAttachAttempt(token: object, sessionId: string): PendingAttach {
    let resolveCompletion = (): void => {};
    const completion = new Promise<void>((resolve) => {
      resolveCompletion = resolve;
    });
    const attempt = { token, sessionId, completion, resolveCompletion };
    this.pendingAttach = attempt;
    return attempt;
  }

  private completeAttachAttempt(attempt: PendingAttach): void {
    if (this.pendingAttach === attempt) this.pendingAttach = undefined;
    attempt.resolveCompletion();
  }

  private beginTransportOperation(
    token: object,
    sessionId: string,
  ): PendingTransportOperation {
    if (this.pendingTransportOperation !== undefined) {
      throw new PtyTransportError("aborted");
    }
    let resolveCompletion = (): void => {};
    const completion = new Promise<void>((resolve) => {
      resolveCompletion = resolve;
    });
    const operation: PendingTransportOperation = {
      token,
      sessionId,
      nativeGeneration: this.currentState.generation,
      transportStarted: false,
      transportSettled: false,
      invalidated: false,
      terminalObserved: false,
      initialCleanupIssued: false,
      cleanupIssued: false,
      closeCleanupIssued: false,
      cleanup: "detach",
      completion,
      resolveCompletion,
    };
    this.pendingTransportOperation = operation;
    return operation;
  }

  private invalidatePendingTransportOperation(
    token: object | undefined,
    cleanup: TransportCleanup,
  ): boolean {
    const operation = this.pendingTransportOperation;
    if (
      operation === undefined ||
      (token !== undefined && operation.token !== token)
    )
      return false;
    this.invalidateTransportOperation(operation, cleanup);
    return true;
  }

  private invalidateTransportOperation(
    operation: PendingTransportOperation,
    cleanup: TransportCleanup,
  ): void {
    if (!operation.invalidated) {
      operation.invalidated = true;
      operation.cleanup = cleanup;
      this.invalidatedSessionId = operation.sessionId;
      // Abort is advisory for generic adapters. Release the bridge's active
      // operation slot immediately, while retaining the old operation for
      // identity-scoped late completion cleanup and event quarantine.
      if (this.pendingTransportOperation === operation) {
        this.pendingTransportOperation = undefined;
        this.quarantinedTransportOperations.add(operation);
      }
    } else if (cleanup === "close") {
      // Explicit close/disposal is stronger than a prior lease detach. Keep the
      // late-completion cleanup closed even if detachment was already requested.
      operation.cleanup = "close";
    }

    if (
      operation.transportStarted &&
      operation.transportSettled &&
      !operation.cleanupIssued
    ) {
      // An ignored abort can attach only after its promise settles. Defer this
      // operation's single cleanup until then, while replacement is serialized,
      // so the cleanup still targets A and can never detach B.
      operation.cleanupIssued = true;
      operation.initialCleanupIssued = true;
      operation.initialCleanupMode = operation.cleanup;
      if (operation.cleanup === "close") operation.closeCleanupIssued = true;
      this.cleanupTransport(operation.cleanup);
    }

    if (operation.transportSettled) this.finalizeTransportOperation(operation);
  }

  private finalizeTransportOperation(
    operation: PendingTransportOperation,
  ): void {
    if (
      !operation.invalidated ||
      !operation.transportStarted ||
      operation.terminalObserved
    )
      return;
    // Settlement only releases quarantine. Calling the adapter again here would
    // duplicate the cleanup decision or tear down a replacement generation.
    // PtyTransport's native generation guard owns late adapter settlement.
  }

  private completeTransportOperation(
    operation: PendingTransportOperation,
  ): void {
    operation.transportSettled = true;
    if (
      operation.invalidated &&
      operation.transportStarted &&
      !operation.terminalObserved &&
      !operation.cleanupIssued
    ) {
      // This is the late-settlement ownership fence. It runs before completion
      // releases the quarantine, so a queued replacement cannot share cleanup.
      operation.cleanupIssued = true;
      operation.initialCleanupIssued = true;
      operation.initialCleanupMode = operation.cleanup;
      if (operation.cleanup === "close") operation.closeCleanupIssued = true;
      this.cleanupTransport(operation.cleanup);
    }
    this.finalizeTransportOperation(operation);
    if (this.pendingTransportOperation === operation)
      this.pendingTransportOperation = undefined;
    this.quarantinedTransportOperations.delete(operation);
    operation.resolveCompletion();
  }

  private waitForQuarantinedTransportOperations(
    signal?: AbortSignal,
  ): Promise<void> {
    const operations = [
      ...(this.pendingTransportOperation === undefined
        ? []
        : [this.pendingTransportOperation]),
      ...this.quarantinedTransportOperations,
    ];
    if (operations.length === 0) return Promise.resolve();
    if (signal?.aborted)
      return Promise.reject(new PtyTransportError("aborted"));
    if (!signal)
      return Promise.all(
        operations.map((operation) => operation.completion),
      ).then(() => {});
    return new Promise<void>((resolve, reject) => {
      const onAbort = (): void => reject(new PtyTransportError("aborted"));
      signal.addEventListener("abort", onAbort, { once: true });
      void Promise.all(
        operations.map((operation) => operation.completion),
      ).then(
        () => {
          signal.removeEventListener("abort", onAbort);
          resolve();
        },
        () => {
          signal.removeEventListener("abort", onAbort);
          reject(new PtyTransportError("aborted"));
        },
      );
    });
  }

  private escalateQuarantinedCleanupToClose(): void {
    for (const operation of this.quarantinedTransportOperations) {
      if (operation.terminalObserved || operation.closeCleanupIssued) continue;
      operation.cleanup = "close";
      operation.closeCleanupIssued = true;
      // A close/dispose request outranks a prior advisory detach. This extra
      // close is scoped to the quarantined operation before any replacement can run.
      this.cleanupTransport("close");
    }
  }

  private cleanupTransport(cleanup: TransportCleanup): void {
    try {
      if (cleanup === "close") this.transport.close();
      else this.transport.detach();
    } catch {
      // A stale adapter must not escape the bridge's cleanup boundary. If a
      // detach implementation throws, close is the fail-closed fallback that
      // prevents an adapter from retaining raw PTY ownership indefinitely.
      if (cleanup === "detach") {
        try {
          this.transport.close();
        } catch {
          // The adapter remains responsible for its own last-resort failure.
        }
      }
    }
  }

  private waitForRendererReady(signal?: AbortSignal): Promise<void> {
    if (!this.rendererReadyGateEnabled || this.rendererReady)
      return Promise.resolve();
    if (signal?.aborted)
      return Promise.reject(new PtyTransportError("aborted"));
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
        onAbort: undefined,
      };
      if (signal) {
        waiter.onAbort = () => {
          this.rendererReadyWaiters.delete(waiter);
          reject(new PtyTransportError("aborted"));
        };
        signal.addEventListener("abort", waiter.onAbort, { once: true });
      }
      this.rendererReadyWaiters.add(waiter);
    });
  }

  private invalidateActiveBinding(
    cleanup: TransportCleanup = "detach",
  ): boolean {
    const binding = this.activeBinding;
    this.activeBinding = undefined;
    if (binding) {
      binding.valid = false;
      this.invalidatedSessionId = binding.sessionId;
    }

    const pending = this.pendingTransportOperation;
    if (
      pending !== undefined &&
      (binding === undefined || pending.sessionId === binding.sessionId)
    ) {
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
    // Reject stale native work before it can invalidate a lease or update
    // bridge state. Session identity alone cannot distinguish A from a later
    // same-session B replacement.
    if (
      event.type === "state" &&
      event.state.generation < this.currentState.generation
    )
      return;
    const pending = this.pendingTransportOperation;
    const eventGeneration =
      event.type === "state" ? event.state.generation : event.generation;
    // A pending B has not established ownership until it advances the native
    // generation it observed at start. Admit neither terminal nor streaming A
    // events at or below that floor, even when A and B share a session id.
    if (
      !pending?.invalidated &&
      pending !== undefined &&
      eventGeneration <= pending.nativeGeneration
    )
      return;
    const eventSessionId =
      event.type === "state"
        ? event.state.sessionId
        : this.currentState.sessionId;
    const observedLifecycle = this.lifecycleIdentity;
    if (
      pending !== undefined &&
      !pending.invalidated &&
      event.type === "state" &&
      pending.sessionId === event.state.sessionId &&
      // A terminal result belongs only to this operation after the transport
      // has advanced past its captured native generation. Otherwise an old A
      // callback for the same session could invalidate B's active lease.
      event.state.generation > pending.nativeGeneration &&
      (event.state.status === "detached" ||
        event.state.status === "failed" ||
        event.state.status === "exited" ||
        event.state.status === "closed")
    ) {
      // PTY close classification is the authoritative result of this attach.
      // Do not call detach/close again: a reentrant cleanup would overwrite a
      // meaningful 4401/4403 failure with a generic detached snapshot.
      pending.terminalObserved = true;
      pending.invalidated = true;
      pending.initialCleanupIssued = true;
      pending.initialCleanupMode = "detach";
      this.pendingTransportOperation = undefined;
      this.quarantinedTransportOperations.add(pending);
      if (this.activeBinding?.sessionId === pending.sessionId) {
        this.activeBinding.valid = false;
        this.activeBinding = undefined;
      }
      this.invalidatedSessionId = pending.sessionId;
      this.publishState(
        projectState(event.state, this.explicitlyClosed),
        true,
        observedLifecycle,
      );
      return;
    }
    const quarantined = [...this.quarantinedTransportOperations].find(
      (operation) =>
        operation.invalidated &&
        (eventSessionId === operation.sessionId ||
          this.currentState.sessionId === operation.sessionId),
    );
    if (
      (pending?.invalidated || quarantined !== undefined) &&
      (eventSessionId === pending?.sessionId ||
        eventSessionId === quarantined?.sessionId ||
        this.currentState.sessionId === pending?.sessionId ||
        this.currentState.sessionId === quarantined?.sessionId) &&
      this.activeBinding === undefined
    ) {
      // Quarantine every callback from an invalidated adapter call until its
      // promise settles. The adapter may emit attached or bytes synchronously
      // after ignoring AbortSignal; those events cannot establish ownership.
      if (
        event.type === "state" &&
        event.state.generation >= this.currentState.generation
      ) {
        this.currentState = projectState(event.state, this.explicitlyClosed);
      }
      return;
    }
    if (event.type === "bytes") {
      // Generation is checked before forwarding, while the payload remains an
      // opaque view. The renderer owns its bounded queue; this bridge never
      // copies, decodes, inspects, or retains terminal bytes. A session rejected
      // by the workspace fence stays closed until a later attach owns it again.
      if (event.generation !== this.currentState.generation) return;
      if (this.invalidatedSessionId === this.currentState.sessionId) return;
      this.emit({
        type: "bytes",
        generation: event.generation,
        bytes: event.bytes,
        outputMayBeTruncated: event.outputMayBeTruncated,
      });
      return;
    }
    if (event.type === "notice") {
      if (event.generation !== this.currentState.generation) return;
      if (this.invalidatedSessionId === this.currentState.sessionId) return;
      this.emit({
        type: "notice",
        generation: event.generation,
        notice: event.notice,
        replayCapacityBytes: event.replayCapacityBytes,
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
    if (
      event.state.sessionId !== undefined &&
      this.activeBinding?.sessionId === event.state.sessionId
    ) {
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
        event.state.status === "attached" ||
        event.state.status === "detached" ||
        event.state.status === "failed" ||
        event.state.status === "exited" ||
        event.state.status === "closed"
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
    if (
      event.state.status === "detached" ||
      event.state.status === "failed" ||
      event.state.status === "exited" ||
      // A native close is terminal even without an explicit user Close action.
      // Keep no coordinator lease that a later same-session activation could reuse.
      event.state.status === "closed"
    ) {
      if (
        pending !== undefined &&
        pending.sessionId === event.state.sessionId &&
        event.state.generation <= pending.nativeGeneration
      ) {
        // This is an old same-session A terminal result. Do not let it mutate
        // state or invalidate the newer B operation that is still pending.
        return;
      }
      // An unsolicited terminal failure makes the coordinator lease stale. The
      // next Terminal activation must be allowed to attach again. If the state
      // belongs to a still-pending adapter call, quarantine that call too; its
      // promise may otherwise resolve into a second attached transition.
      if (
        pending !== undefined &&
        pending.sessionId === event.state.sessionId
      ) {
        this.invalidateTransportOperation(pending, "detach");
      }
      if (this.activeBinding) this.activeBinding.valid = false;
      this.activeBinding = undefined;
    }
    this.publishState(
      projectState(event.state, this.explicitlyClosed),
      false,
      observedLifecycle,
    );
  }

  private publishState(
    state: CurrentSessionTerminalState,
    allowInvalidated = false,
    lifecycle: CurrentSessionTerminalLifecycleIdentity = this.lifecycleIdentity,
  ): void {
    this.currentState = state;
    // State callbacks can synchronously cause coordinator cleanup. Stamp the
    // producer's real lease before that reentrancy can retire it; no presentation
    // layer must reconstruct identity from session or generation values.
    this.emit({ type: "state", state, lifecycle: createLifecycleStamp(lifecycle) }, allowInvalidated);
  }

  private emit(
    event: CurrentSessionTerminalEvent,
    allowInvalidated = false,
  ): void {
    for (const listener of [...this.listeners]) {
      if (
        !allowInvalidated &&
        event.type !== "state" &&
        this.invalidatedSessionId === this.currentState.sessionId
      ) {
        return;
      }
      if (
        !allowInvalidated &&
        event.type === "state" &&
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

const BRIDGE_ERROR_CODES = new Set<PtyErrorCode>([
  "aborted",
  "closed",
  "attachment-superseded",
  "connection-failed",
  "expired-attachment",
  "invalid-attachment",
  "invalid-frame",
  "invalid-input",
  "invalid-options",
  "invalid-ticket",
  "legacy-reattach-prohibited",
  "not-attached",
  "send-failed",
]);

function normalizeBridgeError(
  error: unknown,
  fallback: "invalid-attachment" | "connection-failed",
): PtyTransportError {
  // Adapter errors are an untrusted boundary, including objects branded as a
  // PtyTransportError. Reconstruct only reviewed code and bounded generation;
  // this drops foreign messages, causes, stack decorations, and own properties.
  if (
    error instanceof PtyTransportError &&
    BRIDGE_ERROR_CODES.has(error.code)
  ) {
    const generation =
      typeof error.generation === "number" &&
      Number.isSafeInteger(error.generation) &&
      error.generation >= 0
        ? error.generation
        : undefined;
    return new PtyTransportError(error.code, generation);
  }
  return new PtyTransportError(fallback);
}

function projectState(
  state: PtyConnectionState,
  explicitlyClosed: boolean,
): CurrentSessionTerminalState {
  const failure =
    state.closeClassification === "authentication-rejected"
      ? "authentication-required"
      : state.closeClassification === "host-or-origin-rejected"
        ? "incompatible-origin"
        : undefined;
  return Object.freeze({
    status: state.status,
    generation: state.generation,
    ...(state.sessionId === undefined ? {} : { sessionId: state.sessionId }),
    ...(state.closeCode === undefined ? {} : { closeCode: state.closeCode }),
    ...(state.closeClassification === undefined
      ? {}
      : { closeClassification: state.closeClassification }),
    outputMayBeTruncated: state.outputMayBeTruncated,
    explicitlyClosed,
    // Current PtyTransport deliberately keeps attach/process values opaque.
    // Its reviewed attach mode and terminal classification are the only public
    // reconnect evidence; no adapter-specific state flag is trusted here.
    reconnectSupported:
      state.mode === "attach" &&
      state.status !== "failed" &&
      state.status !== "exited" &&
      state.status !== "closed",
    ...(failure === undefined ? {} : { failure }),
  });
}

/**
 * Browser-only transport composition. The ticket response is handed straight
 * to the PTY parser; no ticket, URL, or socket diagnostic enters bridge state.
 */
export function createBrowserPtyTransport(
  options: BrowserPtyTransportOptions = {},
): PtyTransport {
  // Capture and validate browser authority before ticket minting. SSR, opaque,
  // or malformed location evidence must not route a fresh ticket elsewhere.
  const origin = currentBrowserOrigin();
  const fetcher = options.fetch ?? globalThis.fetch?.bind(globalThis);
  if (!fetcher) throw new PtyTransportError("invalid-options");
  const createSocket = options.createSocket ?? defaultBrowserPtySocket;
  // Keep PTY ticket acquisition on the shared bounded HTTP boundary. It owns
  // the exact `{ ticket, ttl_seconds: 30 }` response check; this adapter only
  // consumes its normalized `{ ticket }` value for one upgrade.
  const request = createWsTicketRequestBoundary(fetcher as WsTicketFetch);
  const ticketProvider = createFreshPtyTicketProvider(request);

  return createPtyTransport({
    ticketProvider,
    validateAttachment: options.validateAttachment,
    createWebSocket: (upgrade, signal) => {
      const url = new URL(upgrade.path, origin);
      url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
      url.searchParams.set("ticket", upgrade.query.ticket);
      url.searchParams.set("resume", upgrade.query.resume);
      if (upgrade.query.attach !== undefined)
        url.searchParams.set("attach", upgrade.query.attach);
      return createSocket(url.toString(), signal);
    },
  });
}

function currentBrowserOrigin(): string {
  const value = globalThis.location?.origin;
  if (typeof value !== "string" || value.length === 0)
    throw new PtyTransportError("invalid-options");
  try {
    const origin = new URL(value);
    if (
      (origin.protocol !== "http:" && origin.protocol !== "https:") ||
      origin.origin !== value
    ) {
      throw new PtyTransportError("invalid-options");
    }
    return origin.toString();
  } catch (error) {
    if (error instanceof PtyTransportError) throw error;
    throw new PtyTransportError("invalid-options");
  }
}

function defaultBrowserPtySocket(
  url: string,
  signal: AbortSignal,
): PtyWebSocket {
  if (typeof WebSocket === "undefined")
    throw new PtyTransportError("invalid-options");
  const nativeSocket = new WebSocket(url);
  nativeSocket.binaryType = "arraybuffer";
  let closeIssued = false;
  const closeOnce = (code?: number, reason?: string): void => {
    if (closeIssued) return;
    closeIssued = true;
    try {
      nativeSocket.close(code, reason);
    } catch {
      // The adapter has already claimed cleanup; PTY transport owns state.
    }
  };
  const adapter: PtyWebSocket = {
    onopen: null,
    onmessage: null,
    onerror: null,
    onclose: null,
    send: (data) => nativeSocket.send(data as unknown as ArrayBuffer),
    close: closeOnce,
    get readyState() {
      return nativeSocket.readyState;
    },
  };
  const closeOnAbort = (): void => adapter.close(1000, "cancelled");
  signal.addEventListener("abort", closeOnAbort, { once: true });
  nativeSocket.onopen = (event) => adapter.onopen?.(event);
  nativeSocket.onmessage = (event: MessageEvent) =>
    adapter.onmessage?.({ data: event.data } as PtyMessageEvent);
  nativeSocket.onerror = (event) => adapter.onerror?.(event);
  nativeSocket.onclose = (event) => {
    signal.removeEventListener("abort", closeOnAbort);
    adapter.onclose?.({ code: event.code });
  };
  return adapter;
}
