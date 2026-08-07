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

export type CurrentSessionTerminalBridgeOptions = Readonly<{
  createTransport: () => PtyTransport;
}>;

interface ActiveBinding extends TerminalBinding {
  readonly token: object;
  valid: boolean;
}

/**
 * Adapts one current-session PTY transport to the shared coordinator. The
 * bridge forwards byte views directly to listeners and does not decode, log,
 * queue, or retain them. A mode switch leaves a valid binding attached; a
 * session replacement or explicit terminal action invalidates that binding.
 */
export class CurrentSessionTerminalBridge implements TerminalSessionPort {
  private readonly transport: PtyTransport;
  private readonly listeners = new Set<CurrentSessionTerminalListener>();
  private readonly unsubscribeTransport: () => void;
  private currentState: CurrentSessionTerminalState;
  private activeBinding: ActiveBinding | undefined;
  private disposed = false;
  private explicitlyClosed = false;
  private rendererReadyGateEnabled = false;
  private rendererReady = false;
  private rendererReadyWaiters = new Set<{
    resolve: () => void;
    reject: (error: PtyTransportError) => void;
    signal: AbortSignal;
    onAbort: () => void;
  }>();

  constructor(options: CurrentSessionTerminalBridgeOptions) {
    this.transport = options.createTransport();
    this.currentState = projectState(this.transport.state, false);
    this.unsubscribeTransport = this.transport.subscribe((event) => this.handleTransportEvent(event));
  }

  get state(): CurrentSessionTerminalState {
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
      waiter.signal.removeEventListener('abort', waiter.onAbort);
      waiter.resolve();
    }
  }

  get pty(): PtyTransport {
    return this.transport;
  }

  subscribe(listener: CurrentSessionTerminalListener): () => void {
    if (this.disposed) return () => {};
    this.listeners.add(listener);
    try {
      listener({ type: 'state', state: this.currentState });
    } catch {
      // A presentation observer cannot interrupt bridge setup or transport flow.
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
        this.transport.detach();
      },
      isValid: () => binding.valid
    };
    this.activeBinding = binding;

    try {
      await this.transport.connect({ sessionId }, signal);
      if (this.disposed || !binding.valid || this.activeBinding?.token !== token) {
        binding.valid = false;
        throw new PtyTransportError('aborted');
      }
      return binding;
    } catch (error) {
      binding.valid = false;
      if (this.activeBinding?.token === token) this.activeBinding = undefined;
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

  sendInput(input: string | Uint8Array): void {
    this.transport.sendInput(input);
  }

  resize(cols: number, rows: number): void {
    this.transport.resize(cols, rows);
  }

  reconnect(signal?: AbortSignal): Promise<void> {
    this.explicitlyClosed = false;
    return this.transport.reconnect(signal);
  }

  detach(): void {
    this.explicitlyClosed = false;
    this.invalidateActiveBinding();
  }

  close(): void {
    this.explicitlyClosed = true;
    this.invalidateActiveBinding(false);
    this.transport.close();
    this.publishState(projectState(this.transport.state, true));
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.invalidateActiveBinding(false);
    this.transport.close();
    this.unsubscribeTransport();
    for (const waiter of [...this.rendererReadyWaiters]) {
      this.rendererReadyWaiters.delete(waiter);
      waiter.signal.removeEventListener('abort', waiter.onAbort);
      waiter.reject(new PtyTransportError('closed'));
    }
    this.listeners.clear();
  }

  private waitForRendererReady(signal: AbortSignal): Promise<void> {
    if (!this.rendererReadyGateEnabled || this.rendererReady) return Promise.resolve();
    if (signal.aborted) return Promise.reject(new PtyTransportError('aborted'));
    return new Promise<void>((resolve, reject) => {
      const waiter = {
        resolve,
        reject,
        signal,
        onAbort: () => {
          this.rendererReadyWaiters.delete(waiter);
          reject(new PtyTransportError('aborted'));
        }
      };
      this.rendererReadyWaiters.add(waiter);
      signal.addEventListener('abort', waiter.onAbort, { once: true });
    });
  }

  private invalidateActiveBinding(detach = true): void {
    const binding = this.activeBinding;
    this.activeBinding = undefined;
    if (binding) binding.valid = false;
    if (detach && binding) this.transport.detach();
  }

  private handleTransportEvent(event: PtyTransportEvent): void {
    if (event.type === 'bytes') {
      // Generation is checked before forwarding, while the payload remains an
      // opaque view. The renderer owns its bounded queue; this bridge never
      // copies, decodes, inspects, or retains terminal bytes.
      if (event.generation !== this.currentState.generation) return;
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
    if (event.state.status === 'detached' || event.state.status === 'failed' || event.state.status === 'exited') {
      // An unsolicited terminal failure makes the coordinator lease stale. The
      // next Terminal activation must be allowed to attach again.
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
