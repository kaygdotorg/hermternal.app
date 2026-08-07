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
const WTERM_HOST_CLASSES = ['wterm', 'cursor-blink', 'has-scrollback', 'focused'] as const;
const wTermHostRecords = new WeakMap<HTMLElement, WTermHostRecord>();
// One renderer generation owns host-level loading/error/restore mutations at a
// time. This prevents an older renderer instance from clearing a newer owner's
// content when both instances are pointed at the same host.
const rendererHostOwners = new WeakMap<HTMLElement, object>();

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

function isUint8Array(data: unknown): data is Uint8Array {
  // Vitest, embedded webviews, and iframes can provide a Uint8Array from a
  // different realm. ArrayBuffer.isView rejects Symbol.toStringTag spoofing,
  // while the tag distinguishes Uint8Array from other typed-array views.
  return ArrayBuffer.isView(data) && Object.prototype.toString.call(data) === '[object Uint8Array]';
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
export function normalizeWTermInputAccessibility(
  host: HTMLElement,
  ownedInput?: HTMLTextAreaElement
): void {
  const input = ownedInput ?? host.querySelector<HTMLTextAreaElement>('textarea[aria-hidden="true"][tabindex="0"]');
  if (!input || !host.contains(input)) return;
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

type WTermHostRecord = {
  readonly beforeClasses: ReadonlySet<string>;
  readonly ownedClasses: Set<string>;
  readonly beforeHeight: string;
  readonly beforeRowHeight: string;
  ownedHeight: string | null;
  ownedRowHeight: string | null;
  observedHeight: string;
  observedRowHeight: string;
  readonly observedClasses: Map<string, boolean>;
  readonly observedOtherClasses: Set<string>;
  otherClassesCaptured: boolean;
  classObserver: MutationObserver | null;
  disposed: boolean;
};

function recordWTermClasses(host: HTMLElement, record: WTermHostRecord): void {
  for (const className of WTERM_HOST_CLASSES) {
    const present = host.classList.contains(className);
    if (!record.beforeClasses.has(className) && present) record.ownedClasses.add(className);
    if (record.ownedClasses.has(className)) record.observedClasses.set(className, present);
  }
  if (record.otherClassesCaptured) return;
  for (const className of host.classList) {
    if (!WTERM_HOST_CLASSES.includes(className as (typeof WTERM_HOST_CLASSES)[number])) {
      record.observedOtherClasses.add(className);
    }
  }
  record.otherClassesCaptured = true;
}

/**
 * Record the host values changed by this adapter generation. The last observed
 * value is used as an ownership check at cleanup time: if another owner has
 * restored or changed a value, cleanup leaves it untouched.
 */
function recordWTermHostState(host: HTMLElement, record: WTermHostRecord, includeStyles = true): void {
  recordWTermClasses(host, record);
  if (!includeStyles) return;
  const height = host.style.height;
  record.ownedHeight = height !== record.beforeHeight ? height : null;
  record.observedHeight = height;
  const rowHeight = host.style.getPropertyValue('--term-row-height');
  record.ownedRowHeight = rowHeight !== record.beforeRowHeight ? rowHeight : null;
  record.observedRowHeight = rowHeight;
}

function sameClassSet(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  if (left.size !== right.size) return false;
  for (const className of left) {
    if (!right.has(className)) return false;
  }
  return true;
}

function restoreOwnedStyle(
  host: HTMLElement,
  property: 'height' | '--term-row-height',
  before: string,
  owned: string | null,
  observed: string
): void {
  const current = property === 'height' ? host.style.height : host.style.getPropertyValue(property);
  if (owned === null || current !== observed) return;
  if (before) host.style.setProperty(property, before);
  else host.style.removeProperty(property);
}

function restoreWTermHostRecord(host: HTMLElement, record: WTermHostRecord): void {
  if (wTermHostRecords.get(host) !== record) return;

  const currentOtherClasses = new Set(
    [...host.classList].filter(
      (className) => !WTERM_HOST_CLASSES.includes(className as (typeof WTERM_HOST_CLASSES)[number])
    )
  );
  // A foreign class change means host class ownership is no longer provable.
  // Leave every host class untouched rather than stripping a later owner's
  // state while still removing the adapter's private nodes below.
  if (sameClassSet(currentOtherClasses, record.observedOtherClasses)) {
    for (const className of record.ownedClasses) {
      // A class can be removed or replaced by a later owner while the async
      // adapter is settling. Only remove the exact state this generation saw.
      if (record.observedClasses.get(className) === true && host.classList.contains(className)) {
        host.classList.remove(className);
      }
    }
    restoreOwnedStyle(host, 'height', record.beforeHeight, record.ownedHeight, record.observedHeight);
    restoreOwnedStyle(
      host,
      '--term-row-height',
      record.beforeRowHeight,
      record.ownedRowHeight,
      record.observedRowHeight
    );
  }
  wTermHostRecords.delete(host);
}

/**
 * Dispose a W-Term instance without allowing its upstream `destroy()` method
 * to clear a host that a later mount or another owner may have reused. The
 * pinned package keeps its internal fields private, so this compatibility
 * path removes only the instance's known nodes/listeners and conditionally
 * restores host values that this exact adapter mount changed.
 */
function disposeWTermPreservingHost(
  term: WTerm,
  host: HTMLElement,
  record: WTermHostRecord,
  preserveHost = false
): void {
  if (record.disposed) return;
  record.disposed = true;
  record.classObserver?.disconnect();
  record.classObserver = null;

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
  if ((globalThis as typeof globalThis & { __wterm?: WTerm }).__wterm === term) {
    delete (globalThis as typeof globalThis & { __wterm?: WTerm }).__wterm;
  }
  if (preserveHost) {
    if (wTermHostRecords.get(host) === record) wTermHostRecords.delete(host);
  } else {
    restoreWTermHostRecord(host, record);
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

      const record: WTermHostRecord = {
        beforeClasses: new Set(host.classList),
        ownedClasses: new Set(),
        beforeHeight: host.style.height,
        beforeRowHeight: host.style.getPropertyValue('--term-row-height'),
        ownedHeight: null,
        ownedRowHeight: null,
        observedHeight: host.style.height,
        observedRowHeight: host.style.getPropertyValue('--term-row-height'),
        observedClasses: new Map(),
        observedOtherClasses: new Set(),
        otherClassesCaptured: false,
        classObserver: null,
        disposed: false
      };
      wTermHostRecords.set(host, record);

      const termOptions: WTermOptions = {
        core,
        cols: options.initialSize.cols,
        rows: options.initialSize.rows,
        autoResize: false,
        cursorBlink: true,
        onData: options.onInput
      };
      let term: WTerm | null = null;
      try {
        term = new WTerm(host, termOptions);
        await term.init();
        const ownedInput = (term as unknown as WTermRuntime).input?.textarea;
        normalizeWTermInputAccessibility(host, ownedInput);
        relockWTermHeight(host, options.initialSize.rows);
        // Capture W-Term's final initial host state before consulting the
        // renderer generation guard. No user callback runs between these
        // statements, so a stale cleanup cannot learn a later owner's values.
        recordWTermHostState(host, record);
        if (typeof MutationObserver === 'function') {
          record.classObserver = new MutationObserver(() => {
            if (!record.disposed) recordWTermClasses(host, record);
          });
          record.classObserver.observe(host, { attributes: true, attributeFilter: ['class'] });
        }
        if (options.isCurrent && !options.isCurrent()) {
          disposeWTermPreservingHost(term, host, record, true);
          throw new Error('terminal mount became stale');
        }

        const mountedTerm = term;
        let disposed = false;
        return {
          write(data) {
            if (disposed) return;
            mountedTerm.write(data);
          },
          resize(cols, rows) {
            if (disposed) return;
            mountedTerm.resize(cols, rows);
            // W-Term locks the initial height when autoResize is false. Re-lock
            // after every explicit resize so a larger row count is not clipped.
            relockWTermHeight(host, rows);
            recordWTermHostState(host, record);
          },
          focus() {
            if (disposed) return;
            mountedTerm.focus();
            recordWTermHostState(host, record, false);
          },
          paste(data) {
            if (disposed) return;
            const safe = sanitizePaste(data);
            const bracketed = mountedTerm.bridge?.bracketedPaste() ?? false;
            const payload = bracketed ? `\x1b[200~${safe}\x1b[201~` : safe;
            options.onInput(payload);
          },
          dispose(disposeOptions) {
            if (disposed) return;
            disposed = true;
            // A stale dispose must not learn values restored or written by a
            // later host owner. A direct dispose can capture the final known
            // class state synchronously; the observer covers async W-Term
            // render/focus mutations while the adapter is mounted.
            if (!disposeOptions?.preserveHost) recordWTermClasses(host, record);
            disposeWTermPreservingHost(mountedTerm, host, record, disposeOptions?.preserveHost === true);
          }
        };
      } catch (error) {
        const preserveHost = options.isCurrent?.() === false;
        if (term && !record.disposed) {
          recordWTermHostState(host, record);
          disposeWTermPreservingHost(term, host, record, preserveHost);
        } else if (!term && !record.disposed) {
          if (preserveHost) {
            if (wTermHostRecords.get(host) === record) wTermHostRecords.delete(host);
          } else {
            restoreWTermHostRecord(host, record);
          }
        }
        throw error;
      }
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
    if (
      this.state === 'ready' &&
      this.host === host &&
      this.backend &&
      rendererHostOwners.get(host) === this
    ) {
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
    rendererHostOwners.set(host, this);
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
    if (this.state === 'ready' && this.host && rendererHostOwners.get(this.host) !== this) return;
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
    if (this.state === 'ready' && this.host && rendererHostOwners.get(this.host) !== this) return;
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
    if (this.state === 'ready' && this.host && rendererHostOwners.get(this.host) !== this) return;
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
        isCurrent: () =>
          generation === this.mountGeneration &&
          this.host === host &&
          rendererHostOwners.get(host) === this &&
          this.state !== 'disposed'
      });
      if (
        generation !== this.mountGeneration ||
        this.state === 'disposed' ||
        this.host !== host ||
        rendererHostOwners.get(host) !== this
      ) {
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
      if (
        generation !== this.mountGeneration ||
        this.state === 'disposed' ||
        rendererHostOwners.get(host) !== this
      ) {
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
    if (
      this.state !== 'error' ||
      !this.error ||
      this.host !== host ||
      rendererHostOwners.get(host) !== this
    ) return;
    applyHostState(host, 'error', this.label);
    renderError(host);
  }

  private async confirmAndPaste(request: PasteRequest): Promise<void> {
    const generation = this.mountGeneration;
    const host = this.host;
    const backend = this.backend;
    if (
      this.state !== 'ready' ||
      !host ||
      !backend ||
      rendererHostOwners.get(host) !== this ||
      !this.confirmPaste
    ) return;
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
      rendererHostOwners.get(host) !== this ||
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
    if (this.host && rendererHostOwners.get(this.host) === this) {
      applyHostState(this.host, 'error', this.label);
      renderError(this.host);
    }
    this.setState('error');
  }

  private teardownCurrentHost(keepHost = false): void {
    const host = this.host;
    const snapshot = this.hostSnapshot;
    const ownsHost = host !== null && rendererHostOwners.get(host) === this;
    if (host) host.removeEventListener('paste', this.onPasteCapture, true);
    safeDispose(this.backend, !ownsHost);
    this.backend = null;
    if (host && ownsHost) {
      host.replaceChildren();
      if (snapshot) restoreHostSnapshot(host, snapshot);
    }
    if (!keepHost) {
      if (host && ownsHost) rendererHostOwners.delete(host);
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
