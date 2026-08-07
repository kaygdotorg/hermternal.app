import type { WTerm, WTermOptions } from '@wterm/dom';

export const DEFAULT_TERMINAL_COLS = 80;
export const DEFAULT_TERMINAL_ROWS = 24;
/** Ghostty's scrollback is measured in bytes, not lines. Keep this bound small. */
export const DEFAULT_SCROLLBACK_LIMIT_BYTES = 64 * 1024;
export const MAX_SCROLLBACK_LIMIT_BYTES = 1024 * 1024;
export const DEFAULT_PENDING_WRITE_LIMIT_BYTES = 256 * 1024;
export const MAX_PENDING_OPERATION_COUNT = 4096;

export type TerminalRendererState = 'idle' | 'loading' | 'ready' | 'error' | 'disposed';

export type TerminalRendererErrorCode = 'wasm-initialization-failed' | 'pending-output-limit';

export type TerminalRendererError = Readonly<{
  code: TerminalRendererErrorCode;
  message: string;
}>;

export type TerminalSize = Readonly<{
  cols: number;
  rows: number;
}>;

export type PasteRequest = Readonly<{
  text: string;
  multiline: boolean;
  hasControlCharacters: boolean;
}>;

export type TerminalRendererOptions = Readonly<{
  adapter?: TerminalRendererAdapter;
  initialSize?: TerminalSize;
  scrollbackLimitBytes?: number;
  maxPendingWriteBytes?: number;
  label?: string;
  onInput?: (data: string) => void;
  confirmPaste?: (request: PasteRequest) => boolean | Promise<boolean>;
  onStateChange?: (state: TerminalRendererState) => void;
}>;

export type TerminalAdapterOptions = Readonly<{
  initialSize: TerminalSize;
  scrollbackLimitBytes: number;
  onInput: (data: string) => void;
  /** Lets a lazy adapter stop before constructing into a released host. */
  isCurrent?: () => boolean;
}>;

export type MountedTerminalDisposeOptions = Readonly<{
  /** Preserve the host because a stale async mount no longer owns it. */
  preserveHost?: boolean;
}>;

export type MountedTerminal = Readonly<{
  write(data: Uint8Array): void;
  resize(cols: number, rows: number): void;
  focus(): void;
  paste(data: string): void;
  dispose(options?: MountedTerminalDisposeOptions): void;
}>;

/**
 * The renderer owns browser lifecycle and safety policy; adapters own the
 * concrete terminal implementation. Tests inject a deterministic adapter so
 * they never need a Hermes process or a network transport.
 */
export interface TerminalRendererAdapter {
  mount(host: HTMLElement, options: TerminalAdapterOptions): Promise<MountedTerminal>;
}

export interface TerminalRenderer {
  readonly state: TerminalRendererState;
  readonly error: TerminalRendererError | null;
  mount(host: HTMLElement): Promise<void>;
  write(data: Uint8Array): void;
  resize(cols: number, rows: number): void;
  focus(): void;
  dispose(): void;
}

type PendingOperation =
  | Readonly<{ type: 'write'; data: Uint8Array }>
  | Readonly<{ type: 'resize'; size: TerminalSize }>;

type HostSnapshot = Readonly<{
  className: string | null;
  terminalState: string | null;
  terminalLoading: string | null;
  terminalError: string | null;
  role: string | null;
  ariaLabel: string | null;
  height: string;
  rowHeight: string;
  tabIndex: string | null;
}>;

type WTermModules = Readonly<{
  WTerm: typeof WTerm;
  GhosttyCore: (typeof import('@wterm/ghostty'))['GhosttyCore'];
  wasmPath: string;
}>;

let wTermModulesPromise: Promise<WTermModules> | null = null;
const wTermHostTokens = new WeakMap<HTMLElement, symbol>();

function loadWTermModules(): Promise<WTermModules> {
  if (wTermModulesPromise) return wTermModulesPromise;

  const loading = Promise.all([
    import('@wterm/dom'),
    import('@wterm/ghostty'),
    // Keep the W-Term stylesheet and explicit WASM asset URL in the same lazy
    // chunk boundary as the renderer. These imports must not move to scope.
    import('@wterm/dom/css'),
    import('./terminal.css'),
    import('@wterm/ghostty/ghostty-vt.wasm?url')
  ]).then(([dom, ghostty, _wtermCss, _rendererCss, wasm]) => ({
    WTerm: dom.WTerm,
    GhosttyCore: ghostty.GhosttyCore,
    wasmPath: wasm.default
  }));

  wTermModulesPromise = loading.catch((error: unknown) => {
    wTermModulesPromise = null;
    throw error;
  });
  return wTermModulesPromise;
}

function clampByteLimit(value: number | undefined, fallback: number, maximum: number): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.min(maximum, Math.max(0, Math.floor(value as number)));
}

function normalizeSize(size: TerminalSize | undefined): TerminalSize {
  const cols = size?.cols ?? DEFAULT_TERMINAL_COLS;
  const rows = size?.rows ?? DEFAULT_TERMINAL_ROWS;
  if (!Number.isInteger(cols) || !Number.isInteger(rows) || cols < 1 || rows < 1) {
    throw new RangeError('terminal size must use positive integer columns and rows');
  }
  return { cols, rows };
}

function isMultiline(text: string): boolean {
  return /[\r\n]/u.test(text);
}

function hasControlCharacters(text: string): boolean {
  return /[\x00-\x1f\x7f\x80-\x9f]/u.test(text);
}

function isDangerousPaste(text: string): boolean {
  return isMultiline(text) || hasControlCharacters(text);
}

function sanitizePaste(text: string): string {
  // Match W-Term's bracketed-paste safety rule. Clipboard payloads cannot
  // inject an escape sequence that exits bracketed paste mode.
  return text.replace(/\x1b/gu, '');
}

function isUint8Array(data: Uint8Array): boolean {
  // Vitest, embedded webviews, and iframes can provide a Uint8Array from a
  // different realm. Brand-check the view instead of rejecting valid bytes
  // merely because its constructor is not this realm's constructor.
  return Object.prototype.toString.call(data) === '[object Uint8Array]';
}

function renderLoading(host: HTMLElement): void {
  host.replaceChildren();
  const status = document.createElement('div');
  status.dataset.terminalLoading = 'true';
  status.setAttribute('role', 'status');
  status.textContent = 'Loading terminal…';
  host.appendChild(status);
}

function renderError(host: HTMLElement): void {
  host.replaceChildren();
  const status = document.createElement('div');
  status.dataset.terminalError = 'true';
  status.setAttribute('role', 'alert');
  status.tabIndex = -1;
  status.textContent = 'Terminal unavailable. Try again.';
  host.appendChild(status);
  status.focus({ preventScroll: true });
}

function captureHostSnapshot(host: HTMLElement): HostSnapshot {
  return {
    className: host.getAttribute('class'),
    terminalState: host.getAttribute('data-terminal-state'),
    terminalLoading: host.getAttribute('data-terminal-loading'),
    terminalError: host.getAttribute('data-terminal-error'),
    role: host.getAttribute('role'),
    ariaLabel: host.getAttribute('aria-label'),
    height: host.style.height,
    rowHeight: host.style.getPropertyValue('--term-row-height'),
    tabIndex: host.getAttribute('tabindex')
  };
}

function restoreAttribute(host: HTMLElement, name: string, value: string | null): void {
  if (value === null) host.removeAttribute(name);
  else host.setAttribute(name, value);
}

function restoreHostSnapshot(host: HTMLElement, snapshot: HostSnapshot): void {
  restoreAttribute(host, 'class', snapshot.className);
  restoreAttribute(host, 'data-terminal-state', snapshot.terminalState);
  restoreAttribute(host, 'data-terminal-loading', snapshot.terminalLoading);
  restoreAttribute(host, 'data-terminal-error', snapshot.terminalError);
  restoreAttribute(host, 'role', snapshot.role);
  restoreAttribute(host, 'aria-label', snapshot.ariaLabel);
  restoreAttribute(host, 'tabindex', snapshot.tabIndex);
  if (snapshot.height) host.style.height = snapshot.height;
  else host.style.removeProperty('height');
  if (snapshot.rowHeight) host.style.setProperty('--term-row-height', snapshot.rowHeight);
  else host.style.removeProperty('--term-row-height');
}

function applyHostState(host: HTMLElement, state: 'loading' | 'ready' | 'error', label: string): void {
  host.classList.add('terminal-renderer');
  host.dataset.terminalState = state;
  host.setAttribute('role', 'region');
  host.setAttribute('aria-label', label);
}

function removeLoadingStatus(host: HTMLElement): void {
  host.querySelector('[data-terminal-loading="true"]')?.remove();
}

/**
 * W-Term 0.3.2 marks its keyboard textarea aria-hidden while leaving it
 * tabbable. That violates aria-hidden-focus, so the renderer owns the small
 * compatibility adaptation until the upstream input contract is corrected.
 */
export function normalizeWTermInputAccessibility(host: HTMLElement): void {
  const input = host.querySelector<HTMLTextAreaElement>('textarea[aria-hidden="true"][tabindex="0"]');
  if (!input) return;
  input.removeAttribute('aria-hidden');
  input.setAttribute('aria-label', 'Terminal input');
}

function relockWTermHeight(host: HTMLElement, rows: number): void {
  const row = host.querySelector<HTMLElement>('.term-row');
  if (!row) return;
  const rowStyles = getComputedStyle(row);
  const hostStyles = getComputedStyle(host);
  const rowHeight = [rowStyles.height, rowStyles.lineHeight, hostStyles.getPropertyValue('--term-row-height')]
    .map((value) => Number.parseFloat(value))
    .find((value) => Number.isFinite(value) && value > 0);
  if (!rowHeight) return;
  let extra = (Number.parseFloat(hostStyles.paddingTop) || 0) + (Number.parseFloat(hostStyles.paddingBottom) || 0);
  if (hostStyles.boxSizing === 'border-box') {
    extra += (Number.parseFloat(hostStyles.borderTopWidth) || 0) + (Number.parseFloat(hostStyles.borderBottomWidth) || 0);
  }
  host.style.height = `${rows * rowHeight + extra}px`;
}

type WTermInputRuntime = {
  textarea?: HTMLTextAreaElement;
  _onKeyDown?: EventListener;
  _onPaste?: EventListener;
  _onCompositionStart?: EventListener;
  _onCompositionEnd?: EventListener;
  _onInput?: EventListener;
  _onFocus?: EventListener;
  _onBlur?: EventListener;
};

type WTermRuntime = {
  input?: WTermInputRuntime | null;
  resizeObserver?: ResizeObserver | null;
  _renderTimer?: number | null;
  rafId?: number | null;
  _container?: HTMLElement | null;
  _onClickFocus?: EventListener;
  _destroyed?: boolean;
  _coreOption?: unknown;
  renderer?: unknown;
  debug?: unknown;
};

/**
 * Dispose a stale W-Term instance without allowing its upstream `destroy()`
 * method to clear a host that a later mount or another owner may have reused.
 * The renderer has already removed its owned children when it released the
 * host; this path only removes the stale instance's own node/listeners.
 */
function disposeWTermPreservingHost(term: WTerm, host: HTMLElement, hostToken: symbol): void {
  const runtime = term as unknown as WTermRuntime;
  runtime._destroyed = true;
  if (runtime._renderTimer != null) clearTimeout(runtime._renderTimer);
  if (runtime.rafId != null) cancelAnimationFrame(runtime.rafId);
  runtime._renderTimer = null;
  runtime.rafId = null;
  runtime.resizeObserver?.disconnect();
  runtime.resizeObserver = null;

  const input = runtime.input;
  const textarea = input?.textarea;
  if (textarea) {
    const listeners: ReadonlyArray<readonly [string, EventListener | undefined]> = [
      ['keydown', input?._onKeyDown],
      ['paste', input?._onPaste],
      ['compositionstart', input?._onCompositionStart],
      ['compositionend', input?._onCompositionEnd],
      ['input', input?._onInput],
      ['focus', input?._onFocus],
      ['blur', input?._onBlur]
    ];
    for (const [type, listener] of listeners) {
      if (listener) textarea.removeEventListener(type, listener);
    }
    textarea.remove();
  }
  runtime.input = null;
  if (runtime._onClickFocus) host.removeEventListener('click', runtime._onClickFocus);
  runtime._onClickFocus = undefined;
  runtime._container?.remove();
  runtime._container = null;
  runtime.renderer = null;
  runtime.debug = null;
  runtime._coreOption = undefined;
  if (wTermHostTokens.get(host) === hostToken) {
    wTermHostTokens.delete(host);
    host.classList.remove('wterm', 'cursor-blink', 'has-scrollback', 'focused');
    host.style.removeProperty('height');
    host.style.removeProperty('--term-row-height');
  }
  term.bridge = null;
}

function safeStateChange(
  callback: ((state: TerminalRendererState) => void) | undefined,
  state: TerminalRendererState
): void {
  try {
    callback?.(state);
  } catch {
    // A consumer callback must not turn a controlled renderer state into an
    // unhandled exception or cause terminal data to be logged.
  }
}

function safeDispose(backend: MountedTerminal | null, preserveHost = false): void {
  try {
    backend?.dispose(preserveHost ? { preserveHost: true } : undefined);
  } catch {
    // Disposal is best effort and remains idempotent even after a failed WASM
    // initialization or a DOM teardown race.
  }
}

export function createWTermGhosttyAdapter(): TerminalRendererAdapter {
  return {
    async mount(host, options): Promise<MountedTerminal> {
      const { WTerm, GhosttyCore, wasmPath } = await loadWTermModules();
      const core = await GhosttyCore.load({
        wasmPath,
        scrollbackLimit: options.scrollbackLimitBytes
      });
      if (options.isCurrent && !options.isCurrent()) {
        // Avoid constructing W-Term into a host released while WASM loaded.
        // The core API has no deterministic release hook; dropping this local
        // reference is the safest available behavior for the stale operation.
        throw new Error('terminal mount became stale');
      }
      const termOptions: WTermOptions = {
        core,
        cols: options.initialSize.cols,
        rows: options.initialSize.rows,
        autoResize: false,
        cursorBlink: true,
        onData: options.onInput
      };
      const hostToken = Symbol('wterm-host');
      wTermHostTokens.set(host, hostToken);
      const term = new WTerm(host, termOptions);
      await term.init();
      if (options.isCurrent && !options.isCurrent()) {
        disposeWTermPreservingHost(term, host, hostToken);
        throw new Error('terminal mount became stale');
      }
      normalizeWTermInputAccessibility(host);
      relockWTermHeight(host, options.initialSize.rows);

      return {
        write(data) {
          term.write(data);
        },
        resize(cols, rows) {
          term.resize(cols, rows);
          // W-Term locks the initial height when autoResize is false. Re-lock
          // after every explicit resize so a larger row count is not clipped.
          relockWTermHeight(host, rows);
        },
        focus() {
          term.focus();
        },
        paste(data) {
          const safe = sanitizePaste(data);
          const bracketed = term.bridge?.bracketedPaste() ?? false;
          const payload = bracketed ? `\x1b[200~${safe}\x1b[201~` : safe;
          options.onInput(payload);
        },
        dispose(disposeOptions) {
          if (disposeOptions?.preserveHost) {
            disposeWTermPreservingHost(term, host, hostToken);
            return;
          }
          try {
            term.destroy();
          } finally {
            // @wterm/ghostty@0.3.2 has no core disposal API. Drop the active
            // bridge reference after DOM cleanup; deterministic WASM release
            // remains an upstream limitation documented by this boundary.
            if (wTermHostTokens.get(host) === hostToken) wTermHostTokens.delete(host);
            term.bridge = null;
          }
        }
      };
    }
  };
}

class ManagedTerminalRenderer implements TerminalRenderer {
  state: TerminalRendererState = 'idle';
  error: TerminalRendererError | null = null;

  private readonly adapter: TerminalRendererAdapter;
  private readonly initialSize: TerminalSize;
  private readonly scrollbackLimitBytes: number;
  private readonly maxPendingWriteBytes: number;
  private readonly label: string;
  private readonly onInput: (data: string) => void;
  private readonly confirmPaste: ((request: PasteRequest) => boolean | Promise<boolean>) | undefined;
  private readonly onStateChange: ((state: TerminalRendererState) => void) | undefined;
  private pendingOperations: PendingOperation[] = [];
  private pendingWriteBytes = 0;
  private pendingMount: Promise<void> | null = null;
  private backend: MountedTerminal | null = null;
  private host: HTMLElement | null = null;
  private hostSnapshot: HostSnapshot | null = null;
  private mountGeneration = 0;
  private restoreFocusOnMount = false;
  private focusRequested = false;
  private readonly onPasteCapture = (event: Event): void => {
    const clipboardEvent = event as ClipboardEvent;
    const text = clipboardEvent.clipboardData?.getData('text/plain') ?? '';
    if (!text || !isDangerousPaste(text)) return;

    clipboardEvent.preventDefault();
    clipboardEvent.stopPropagation();
    const request: PasteRequest = {
      text,
      multiline: isMultiline(text),
      hasControlCharacters: hasControlCharacters(text)
    };
    void this.confirmAndPaste(request);
  };

  constructor(options: TerminalRendererOptions = {}) {
    this.adapter = options.adapter ?? createWTermGhosttyAdapter();
    this.initialSize = normalizeSize(options.initialSize);
    this.scrollbackLimitBytes = clampByteLimit(
      options.scrollbackLimitBytes,
      DEFAULT_SCROLLBACK_LIMIT_BYTES,
      MAX_SCROLLBACK_LIMIT_BYTES
    );
    this.maxPendingWriteBytes = clampByteLimit(
      options.maxPendingWriteBytes,
      DEFAULT_PENDING_WRITE_LIMIT_BYTES,
      MAX_SCROLLBACK_LIMIT_BYTES
    );
    this.label = options.label ?? 'Terminal';
    this.onInput = options.onInput ?? (() => undefined);
    this.confirmPaste = options.confirmPaste;
    this.onStateChange = options.onStateChange;
  }

  async mount(host: HTMLElement): Promise<void> {
    if (this.state === 'ready' && this.host === host && this.backend) {
      if (this.restoreFocusOnMount || this.focusRequested) this.backend.focus();
      this.restoreFocusOnMount = false;
      this.focusRequested = false;
      return;
    }
    if (this.pendingMount) {
      await this.pendingMount;
      if (this.state === 'ready' && this.host === host) return;
    }

    const wasFocused = this.host?.contains(document.activeElement) ?? false;
    if (this.backend || this.host) {
      this.restoreFocusOnMount ||= wasFocused;
      this.teardownCurrentHost();
    }

    const generation = ++this.mountGeneration;
    this.host = host;
    this.hostSnapshot = captureHostSnapshot(host);
    applyHostState(host, 'loading', this.label);
    renderLoading(host);
    this.error = null;
    this.setState('loading');

    const load = this.mountAdapter(host, generation);
    this.pendingMount = load;
    try {
      await load;
    } finally {
      if (this.pendingMount === load) this.pendingMount = null;
    }
  }

  write(data: Uint8Array): void {
    if (!isUint8Array(data)) {
      throw new TypeError('terminal writes require Uint8Array data');
    }
    if (data.byteLength === 0) return;
    if (this.state === 'ready' && this.backend) {
      try {
        this.backend.write(data);
      } catch {
        this.fail('wasm-initialization-failed');
      }
      return;
    }
    if (this.state === 'error' || this.state === 'disposed') return;
    if (this.pendingWriteBytes + data.byteLength > this.maxPendingWriteBytes) {
      this.fail('pending-output-limit');
      return;
    }
    if (this.pendingOperations.length >= MAX_PENDING_OPERATION_COUNT) {
      this.fail('pending-output-limit');
      return;
    }
    const copy = new Uint8Array(data.byteLength);
    copy.set(data);
    this.pendingOperations.push({ type: 'write', data: copy });
    this.pendingWriteBytes += copy.byteLength;
  }

  resize(cols: number, rows: number): void {
    const size = normalizeSize({ cols, rows });
    if (this.state === 'ready' && this.backend) {
      try {
        this.backend.resize(size.cols, size.rows);
      } catch {
        this.fail('wasm-initialization-failed');
      }
      return;
    }
    if (this.state === 'error' || this.state === 'disposed') return;
    const last = this.pendingOperations.at(-1);
    if (last?.type === 'resize') {
      this.pendingOperations[this.pendingOperations.length - 1] = { type: 'resize', size };
      return;
    }
    if (this.pendingOperations.length >= MAX_PENDING_OPERATION_COUNT) {
      this.fail('pending-output-limit');
      return;
    }
    this.pendingOperations.push({ type: 'resize', size });
  }

  focus(): void {
    if (this.state === 'ready' && this.backend) {
      this.backend.focus();
      return;
    }
    if (this.state === 'loading' || this.state === 'idle') this.focusRequested = true;
  }

  dispose(): void {
    const host = this.host;
    if (host) this.restoreFocusOnMount = host.contains(document.activeElement);
    this.mountGeneration += 1;
    this.teardownCurrentHost();
    this.pendingOperations = [];
    this.pendingWriteBytes = 0;
    this.focusRequested = false;
    this.error = null;
    this.setState('disposed');
  }

  private async mountAdapter(host: HTMLElement, generation: number): Promise<void> {
    try {
      const backend = await this.adapter.mount(host, {
        initialSize: this.initialSize,
        scrollbackLimitBytes: this.scrollbackLimitBytes,
        onInput: this.onInput,
        isCurrent: () => generation === this.mountGeneration && this.host === host && this.state !== 'disposed'
      });
      if (generation !== this.mountGeneration || this.state === 'disposed' || this.host !== host) {
        // The async adapter may have constructed W-Term after this renderer
        // released the host. Never let the upstream destructor clear reused
        // content; production W-Term uses its host-preserving cleanup path.
        safeDispose(backend, true);
        this.restoreErrorIfOwned(host);
        return;
      }
      this.backend = backend;
      try {
        this.flushPendingOperations(backend);
      } catch {
        this.fail('wasm-initialization-failed');
        return;
      }
      removeLoadingStatus(host);
      host.addEventListener('paste', this.onPasteCapture, true);
      applyHostState(host, 'ready', this.label);
      this.setState('ready');
      if (this.restoreFocusOnMount || this.focusRequested) backend.focus();
      this.restoreFocusOnMount = false;
      this.focusRequested = false;
    } catch {
      if (generation !== this.mountGeneration || this.state === 'disposed') {
        this.restoreErrorIfOwned(host);
        return;
      }
      this.fail('wasm-initialization-failed');
    }
  }

  private flushPendingOperations(backend: MountedTerminal): void {
    const operations = this.pendingOperations;
    this.pendingOperations = [];
    this.pendingWriteBytes = 0;
    for (const operation of operations) {
      if (operation.type === 'write') backend.write(operation.data);
      else backend.resize(operation.size.cols, operation.size.rows);
    }
  }

  private restoreErrorIfOwned(host: HTMLElement): void {
    if (this.state !== 'error' || !this.error || this.host !== host) return;
    applyHostState(host, 'error', this.label);
    renderError(host);
  }

  private async confirmAndPaste(request: PasteRequest): Promise<void> {
    const generation = this.mountGeneration;
    const host = this.host;
    const backend = this.backend;
    if (this.state !== 'ready' || !host || !backend || !this.confirmPaste) return;
    let confirmed = false;
    try {
      confirmed = await this.confirmPaste(request);
    } catch {
      return;
    }
    if (
      !confirmed ||
      this.state !== 'ready' ||
      this.mountGeneration !== generation ||
      this.host !== host ||
      this.backend !== backend
    ) {
      return;
    }
    backend.paste(request.text);
    backend.focus();
  }

  private fail(code: TerminalRendererErrorCode): void {
    if (this.state === 'error') return;
    this.mountGeneration += 1;
    this.teardownCurrentHost(true);
    this.pendingOperations = [];
    this.pendingWriteBytes = 0;
    this.error = {
      code,
      message: code === 'pending-output-limit' ? 'Terminal output was not ready in time.' : 'Terminal could not start.'
    };
    if (this.host) {
      applyHostState(this.host, 'error', this.label);
      renderError(this.host);
    }
    this.setState('error');
  }

  private teardownCurrentHost(keepHost = false): void {
    const host = this.host;
    const snapshot = this.hostSnapshot;
    if (host) host.removeEventListener('paste', this.onPasteCapture, true);
    safeDispose(this.backend);
    this.backend = null;
    if (host) {
      host.replaceChildren();
      if (snapshot) restoreHostSnapshot(host, snapshot);
    }
    if (!keepHost) {
      this.host = null;
      this.hostSnapshot = null;
    }
  }

  private setState(state: TerminalRendererState): void {
    this.state = state;
    safeStateChange(this.onStateChange, state);
  }
}

export function createTerminalRenderer(options: TerminalRendererOptions = {}): TerminalRenderer {
  return new ManagedTerminalRenderer(options);
}
