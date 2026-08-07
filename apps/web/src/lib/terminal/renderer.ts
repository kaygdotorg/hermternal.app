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
}>;

export type MountedTerminal = Readonly<{
  write(data: Uint8Array): void;
  resize(cols: number, rows: number): void;
  focus(): void;
  paste(data: string): void;
  dispose(): void;
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

type WTermModules = Readonly<{
  WTerm: typeof WTerm;
  GhosttyCore: (typeof import('@wterm/ghostty'))['GhosttyCore'];
  wasmPath: string;
}>;

let wTermModulesPromise: Promise<WTermModules> | null = null;

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

function safeDispose(backend: MountedTerminal | null): void {
  try {
    backend?.dispose();
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
      const termOptions: WTermOptions = {
        core,
        cols: options.initialSize.cols,
        rows: options.initialSize.rows,
        autoResize: false,
        cursorBlink: true,
        onData: options.onInput
      };
      const term = new WTerm(host, termOptions);
      await term.init();

      return {
        write(data) {
          term.write(data);
        },
        resize(cols, rows) {
          term.resize(cols, rows);
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
        dispose() {
          term.destroy();
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
    if (this.state === 'error') {
      this.host = host;
      host.classList.add('terminal-renderer');
      host.dataset.terminalState = 'error';
      host.setAttribute('role', 'region');
      host.setAttribute('aria-label', this.label);
      renderError(host);
      return;
    }
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
    host.classList.add('terminal-renderer');
    host.dataset.terminalState = 'loading';
    host.setAttribute('role', 'region');
    host.setAttribute('aria-label', this.label);
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
      host.replaceChildren();
      const backend = await this.adapter.mount(host, {
        initialSize: this.initialSize,
        scrollbackLimitBytes: this.scrollbackLimitBytes,
        onInput: this.onInput
      });
      if (generation !== this.mountGeneration || this.state === 'disposed' || this.host !== host) {
        safeDispose(backend);
        // A bounded pre-mount buffer can fail while the adapter promise is
        // resolving. W-Term cleanup clears the host, so restore the single
        // controlled error state after disposing that stale backend.
        if (this.state === 'error' && this.error) {
          host.classList.add('terminal-renderer');
          host.dataset.terminalState = 'error';
          renderError(host);
        }
        return;
      }
      this.backend = backend;
      this.flushPendingOperations(backend);
      host.addEventListener('paste', this.onPasteCapture, true);
      host.dataset.terminalState = 'ready';
      this.setState('ready');
      if (this.restoreFocusOnMount || this.focusRequested) backend.focus();
      this.restoreFocusOnMount = false;
      this.focusRequested = false;
    } catch {
      if (generation !== this.mountGeneration || this.state === 'disposed') return;
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

  private async confirmAndPaste(request: PasteRequest): Promise<void> {
    if (this.state !== 'ready' || !this.backend || !this.confirmPaste) return;
    let confirmed = false;
    try {
      confirmed = await this.confirmPaste(request);
    } catch {
      return;
    }
    if (!confirmed || this.state !== 'ready' || !this.backend) return;
    this.backend.paste(request.text);
    this.backend.focus();
  }

  private fail(code: TerminalRendererErrorCode): void {
    if (this.state === 'error') return;
    const host = this.host;
    this.mountGeneration += 1;
    this.teardownCurrentHost();
    this.pendingOperations = [];
    this.pendingWriteBytes = 0;
    this.error = {
      code,
      message: code === 'pending-output-limit' ? 'Terminal output was not ready in time.' : 'Terminal could not start.'
    };
    if (host) {
      host.dataset.terminalState = 'error';
      renderError(host);
    }
    this.setState('error');
  }

  private teardownCurrentHost(): void {
    const host = this.host;
    if (host) {
      host.removeEventListener('paste', this.onPasteCapture, true);
      host.classList.remove('terminal-renderer');
      delete host.dataset.terminalState;
      host.replaceChildren();
    }
    safeDispose(this.backend);
    this.backend = null;
    this.host = null;
  }

  private setState(state: TerminalRendererState): void {
    this.state = state;
    safeStateChange(this.onStateChange, state);
  }
}

export function createTerminalRenderer(options: TerminalRendererOptions = {}): TerminalRenderer {
  return new ManagedTerminalRenderer(options);
}
