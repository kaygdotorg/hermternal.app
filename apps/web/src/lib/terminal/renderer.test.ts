import { describe, expect, it, vi } from 'vitest';
import {
  createTerminalRenderer,
  createWTermGhosttyAdapter,
  type MountedTerminal,
  type TerminalRendererAdapter,
  type TerminalSize
} from './renderer';
import {
  assertBenchmarkSampleCounts,
  assertCleanExecutionInputs,
  assertCommitMatchesHead,
  BENCHMARK_REPETITIONS,
  validateFullCommit
} from '../../../tests/bench/terminal-renderer.provenance';

const moduleMocks = vi.hoisted(() => {
  class MockGhosttyCore {
    static load = vi.fn(async () => new MockGhosttyCore());
    bracketedPaste(): boolean {
      return false;
    }
  }

  class MockWTerm {
    static instances: MockWTerm[] = [];
    readonly host: HTMLElement;
    readonly onData: (data: string) => void;
    readonly _container: HTMLElement;
    readonly _onClickFocus: EventListener;
    bridge: MockGhosttyCore;
    input: {
      textarea: HTMLTextAreaElement;
      _onKeyDown: EventListener;
      _onPaste: EventListener;
      _onCompositionStart: EventListener;
      _onCompositionEnd: EventListener;
      _onInput: EventListener;
      _onFocus: EventListener;
      _onBlur: EventListener;
    } | null = null;
    resizeObserver: ResizeObserver | null = null;
    _renderTimer: number | null = null;
    rafId: number | null = null;
    renderer: unknown = {};
    debug: unknown = {};
    _coreOption: unknown;
    readonly writes: Uint8Array[] = [];
    readonly resizes: TerminalSize[] = [];
    destroyed = false;

    constructor(host: HTMLElement, options: { core: MockGhosttyCore; onData: (data: string) => void }) {
      this.host = host;
      this.bridge = options.core;
      this._coreOption = options.core;
      this.onData = options.onData;
      this._container = document.createElement('div');
      this._container.className = 'term-grid';
      host.appendChild(this._container);
      this._onClickFocus = vi.fn();
      host.addEventListener('click', this._onClickFocus);
      MockWTerm.instances.push(this);
    }

    async init(): Promise<this> {
      this.host.dataset.mockWterm = 'ready';
      this.host.classList.add('wterm', 'cursor-blink');
      this.host.style.setProperty('--term-row-height', '17px');
      const row = document.createElement('div');
      row.className = 'term-row';
      row.style.height = '17px';
      row.style.lineHeight = '17px';
      this._container.appendChild(row);
      const input = document.createElement('textarea');
      input.setAttribute('tabindex', '0');
      input.setAttribute('aria-hidden', 'true');
      const onKeyDown: EventListener = () => undefined;
      const onPaste: EventListener = () => undefined;
      const onCompositionStart: EventListener = () => undefined;
      const onCompositionEnd: EventListener = () => undefined;
      const onInput: EventListener = () => undefined;
      const onFocus: EventListener = () => this.host.classList.add('focused');
      const onBlur: EventListener = () => this.host.classList.remove('focused');
      const listeners: ReadonlyArray<readonly [string, EventListener]> = [
        ['keydown', onKeyDown],
        ['paste', onPaste],
        ['compositionstart', onCompositionStart],
        ['compositionend', onCompositionEnd],
        ['input', onInput],
        ['focus', onFocus],
        ['blur', onBlur]
      ];
      for (const [type, listener] of listeners) input.addEventListener(type, listener);
      this.input = {
        textarea: input,
        _onKeyDown: onKeyDown,
        _onPaste: onPaste,
        _onCompositionStart: onCompositionStart,
        _onCompositionEnd: onCompositionEnd,
        _onInput: onInput,
        _onFocus: onFocus,
        _onBlur: onBlur
      };
      this._container.appendChild(input);
      return this;
    }

    write(data: Uint8Array): void {
      this.writes.push(data);
      queueMicrotask(() => {
        if (!this.destroyed) this.host.classList.add('has-scrollback');
      });
    }

    resize(cols: number, rows: number): void {
      this.resizes.push({ cols, rows });
    }

    focus(): void {
      this.host.tabIndex = 0;
      this.input?.textarea.focus();
    }

    destroy(): void {
      this.destroyed = true;
      this.host.replaceChildren();
    }
  }

  return { MockGhosttyCore, MockWTerm };
});

vi.mock('@wterm/ghostty', () => ({ GhosttyCore: moduleMocks.MockGhosttyCore }));
vi.mock('@wterm/dom', () => ({ WTerm: moduleMocks.MockWTerm }));
vi.mock('@wterm/dom/css', () => ({}));

type ScreenSnapshot = Readonly<{
  text: string;
  graphemes: string[];
  cursor: Readonly<{ row: number; col: number; visible: boolean }>;
  foreground: number;
  alternateScreen: boolean;
}>;

type TestTerminal = MountedTerminal & {
  readonly operations: Array<
    | Readonly<{ type: 'write'; bytes: Uint8Array }>
    | Readonly<{ type: 'resize'; size: TerminalSize }>
    | Readonly<{ type: 'paste'; text: string }>
  >;
  readonly snapshot: () => ScreenSnapshot;
};

function displayWidth(grapheme: string): number {
  if (/^\p{Mark}+$/u.test(grapheme)) return 0;
  if (/[\u{1100}-\u{115f}\u{2e80}-\u{a4cf}\u{ac00}-\u{d7a3}\u{f900}-\u{faff}\u{ff00}-\u{ff60}\u{ffe0}-\u{ffe6}]/u.test(grapheme)) {
    return 2;
  }
  return 1;
}

function createDeterministicAdapter(options: { fail?: boolean } = {}): {
  adapter: TerminalRendererAdapter;
  terminals: TestTerminal[];
} {
  const terminals: TestTerminal[] = [];
  const adapter: TerminalRendererAdapter = {
    async mount(host): Promise<MountedTerminal> {
      if (options.fail) throw new Error('synthetic WASM failure that must not reach the UI');

      const output = document.createElement('pre');
      output.dataset.testTerminalScreen = 'true';
      output.setAttribute('aria-label', 'Terminal output');
      host.appendChild(output);

      const decoder = new TextDecoder();
      let text = '';
      let parserBuffer = '';
      let cursorRow = 0;
      let cursorCol = 0;
      let cursorVisible = true;
      let foreground = 256;
      let alternateScreen = false;
      const operations: TestTerminal['operations'] = [];

      const render = (): void => {
        output.textContent = text;
      };

      const parse = (chunk: string): void => {
        parserBuffer += chunk;
        let index = 0;
        while (index < parserBuffer.length) {
          if (parserBuffer[index] !== '\x1b') {
            const nextEscape = parserBuffer.indexOf('\x1b', index);
            const printableEnd = nextEscape < 0 ? parserBuffer.length : nextEscape;
            const printable = parserBuffer.slice(index, printableEnd);
            for (const grapheme of Array.from(new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(printable), (entry) => entry.segment)) {
              if (grapheme === '\n') {
                cursorRow += 1;
                cursorCol = 0;
              } else if (grapheme === '\r') {
                cursorCol = 0;
              } else {
                text += grapheme;
                cursorCol += displayWidth(grapheme);
              }
            }
            parserBuffer = parserBuffer.slice(printableEnd);
            index = 0;
            continue;
          }

          // The test adapter only needs the CSI sequences used by the fixture
          // workload; keep incomplete escape bytes buffered for the next write.
          const match = parserBuffer.slice(index).match(/^\x1b\[([?0-9;]*)([A-Za-z~])/u);
          if (!match) {
            if (parserBuffer.slice(index).length < 8) break;
            index += 1;
            continue;
          }
          const [sequence, parameters, final] = match;
          const privateMode = parameters.startsWith('?');
          const numeric = parameters.replace(/^\?/, '').split(';').filter(Boolean).map(Number);
          if (privateMode && numeric[0] === 25 && final === 'l') cursorVisible = false;
          if (privateMode && numeric[0] === 25 && final === 'h') cursorVisible = true;
          if (privateMode && numeric[0] === 1049 && final === 'h') alternateScreen = true;
          if (privateMode && numeric[0] === 1049 && final === 'l') alternateScreen = false;
          if (!privateMode && final === 'm') foreground = numeric[0] ?? 0;
          if (!privateMode && final === 'H') {
            cursorRow = Math.max(0, (numeric[0] ?? 1) - 1);
            cursorCol = Math.max(0, (numeric[1] ?? 1) - 1);
          }
          parserBuffer = parserBuffer.slice(index + sequence.length);
          index = 0;
        }
        render();
      };

      const terminal: TestTerminal = {
        operations,
        write(data) {
          const bytes = new Uint8Array(data);
          operations.push({ type: 'write', bytes });
          parse(decoder.decode(bytes, { stream: true }));
        },
        resize(cols, rows) {
          operations.push({ type: 'resize', size: { cols, rows } });
        },
        focus() {
          host.tabIndex = 0;
          host.focus();
        },
        paste(data) {
          operations.push({ type: 'paste', text: data });
        },
        dispose(disposeOptions) {
          if (!disposeOptions?.preserveHost) host.replaceChildren();
        },
        snapshot() {
          const graphemes = Array.from(new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(text), (entry) => entry.segment);
          return {
            text,
            graphemes,
            cursor: { row: cursorRow, col: cursorCol, visible: cursorVisible },
            foreground,
            alternateScreen
          };
        }
      };
      terminals.push(terminal);
      return terminal;
    }
  };
  return { adapter, terminals };
}

function clipboardPaste(host: HTMLElement, text: string): Event {
  const event = new Event('paste', { bubbles: true, cancelable: true });
  Object.defineProperty(event, 'clipboardData', {
    value: { getData: () => text }
  });
  host.dispatchEvent(event);
  return event;
}

describe('TerminalRenderer', () => {
  it('does not initialize the Ghostty backend until mount is requested', async () => {
    moduleMocks.MockGhosttyCore.load.mockClear();
    moduleMocks.MockWTerm.instances.length = 0;
    const renderer = createTerminalRenderer();
    expect(moduleMocks.MockGhosttyCore.load).not.toHaveBeenCalled();

    const host = document.createElement('div');
    await renderer.mount(host);

    expect(moduleMocks.MockGhosttyCore.load).toHaveBeenCalledTimes(1);
    expect(moduleMocks.MockWTerm.instances).toHaveLength(1);
    expect(renderer.state).toBe('ready');
  });

  it('preserves raw byte ordering and terminal workload semantics across split writes', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter });
    const host = document.createElement('div');
    const encoder = new TextEncoder();

    renderer.write(encoder.encode('\x1b[31mred\x1b[0m '));
    renderer.write(encoder.encode('e'));
    const combining = encoder.encode('́');
    renderer.write(combining.slice(0, 1));
    renderer.write(combining.slice(1));
    const wide = encoder.encode(' 界');
    renderer.write(wide.slice(0, 2));
    renderer.write(wide.slice(2));
    const emoji = encoder.encode(' 🙂');
    renderer.write(emoji.slice(0, 2));
    renderer.write(emoji.slice(2));
    renderer.write(encoder.encode('\x1b[?25l\x1b[?1049hALT\x1b[?25h'));
    await renderer.mount(host);

    const terminal = terminals[0]!;
    const snapshot = terminal.snapshot();
    expect(snapshot.text).toBe('red é 界 🙂ALT');
    expect(snapshot.graphemes).toContain('é');
    expect(snapshot.graphemes).toContain('界');
    expect(snapshot.graphemes).toContain('🙂');
    expect(snapshot.foreground).toBe(0);
    expect(snapshot.cursor.visible).toBe(true);
    expect(snapshot.alternateScreen).toBe(true);

    const writeOperations = terminal.operations.filter((operation) => operation.type === 'write');
    const received = writeOperations.reduce((all, operation) => {
      const next = new Uint8Array(all.byteLength + operation.bytes.byteLength);
      next.set(all);
      next.set(operation.bytes, all.byteLength);
      return next;
    }, new Uint8Array());
    const expected = encoder.encode(
      '\x1b[31mred\x1b[0m é 界 🙂\x1b[?25l\x1b[?1049hALT\x1b[?25h'
    );
    expect([...received]).toEqual([...expected]);
  });

  it('keeps resize operations ordered with pending output and forwards later resizes', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter });
    const host = document.createElement('div');
    renderer.write(new Uint8Array([0x41]));
    renderer.resize(100, 30);
    renderer.write(new Uint8Array([0x42]));
    await renderer.mount(host);
    renderer.resize(120, 40);

    expect(terminals[0]?.operations.map((operation) => operation.type)).toEqual(['write', 'resize', 'write', 'resize']);
    expect(terminals[0]?.operations.at(-1)).toEqual({ type: 'resize', size: { cols: 120, rows: 40 } });
  });

  it('keeps the loading status visible until the adapter is ready', async () => {
    let resolveMount!: (terminal: MountedTerminal) => void;
    const backend: MountedTerminal = {
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      paste: vi.fn(),
      dispose: vi.fn()
    };
    const adapter: TerminalRendererAdapter = {
      mount: vi.fn(() => new Promise<MountedTerminal>((resolve) => {
        resolveMount = resolve;
      }))
    };
    const renderer = createTerminalRenderer({ adapter });
    const host = document.createElement('div');
    const mounting = renderer.mount(host);

    await vi.waitFor(() => expect(adapter.mount).toHaveBeenCalledTimes(1));
    expect(host.querySelector('[role="status"]')).toHaveTextContent('Loading terminal…');
    expect(renderer.state).toBe('loading');

    resolveMount(backend);
    await mounting;
    expect(host.querySelector('[role="status"]')).not.toBeInTheDocument();
    expect(renderer.state).toBe('ready');
  });

  it('does not let stale async teardown erase a reused host or its newer owner state', async () => {
    let resolveMount!: (terminal: MountedTerminal) => void;
    const host = document.createElement('div');
    host.className = 'shell-host';
    host.setAttribute('role', 'group');
    host.setAttribute('aria-label', 'Original host');
    host.style.height = '91px';
    host.style.setProperty('--term-row-height', '19px');
    const ownedNode = document.createElement('pre');
    ownedNode.textContent = 'stale backend output';
    const ownedListener = vi.fn();
    const dispose = vi.fn((disposeOptions?: { preserveHost?: boolean }) => {
      if (disposeOptions?.preserveHost) {
        ownedNode.remove();
        host.removeEventListener('click', ownedListener);
      } else {
        host.replaceChildren();
      }
    });
    const backend: MountedTerminal = {
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      paste: vi.fn(),
      dispose
    };
    const adapter: TerminalRendererAdapter = {
      mount: vi.fn(() => {
        // The backend has already inserted its own node and listener before
        // the renderer can release the host, matching a stale constructed
        // W-Term instance rather than a stale pre-construction promise.
        host.appendChild(ownedNode);
        host.addEventListener('click', ownedListener);
        return new Promise<MountedTerminal>((resolve) => {
          resolveMount = resolve;
        });
      })
    };
    const renderer = createTerminalRenderer({ adapter });
    const mounting = renderer.mount(host);

    await vi.waitFor(() => expect(adapter.mount).toHaveBeenCalledTimes(1));
    expect(host).toContainElement(ownedNode);
    renderer.dispose();

    const replacement = document.createElement('p');
    replacement.textContent = 'owned by the next host owner';
    const newerOwnerListener = vi.fn();
    host.classList.add('next-owner');
    host.setAttribute('role', 'article');
    host.setAttribute('aria-label', 'Next owner');
    host.style.height = '777px';
    host.style.setProperty('--term-row-height', '33px');
    host.appendChild(replacement);
    host.addEventListener('click', newerOwnerListener);

    resolveMount(backend);
    await mounting;

    host.dispatchEvent(new Event('click', { bubbles: true }));
    expect(renderer.state).toBe('disposed');
    expect(host).toContainElement(replacement);
    expect(host).not.toContainElement(ownedNode);
    expect(host).toHaveClass('shell-host', 'next-owner');
    expect(host).toHaveAttribute('role', 'article');
    expect(host).toHaveAttribute('aria-label', 'Next owner');
    expect(host.style.height).toBe('777px');
    expect(host.style.getPropertyValue('--term-row-height')).toBe('33px');
    expect(ownedListener).not.toHaveBeenCalled();
    expect(newerOwnerListener).toHaveBeenCalledTimes(1);
    expect(dispose).toHaveBeenCalledWith({ preserveHost: true });
  });

  it('does not paste into a remounted backend after an old confirmation resolves', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    let resolveConfirmation!: (accepted: boolean) => void;
    const confirmation = new Promise<boolean>((resolve) => {
      resolveConfirmation = resolve;
    });
    const confirmPaste = vi.fn(() => confirmation);
    const renderer = createTerminalRenderer({ adapter, confirmPaste });
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    document.body.append(firstHost, secondHost);

    await renderer.mount(firstHost);
    clipboardPaste(firstHost, 'printf one\nprintf two');
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(1));

    await renderer.mount(secondHost);
    resolveConfirmation(true);
    await vi.waitFor(() => expect(renderer.state).toBe('ready'));

    expect(terminals[0]?.operations.filter((operation) => operation.type === 'paste')).toHaveLength(0);
    expect(terminals[1]?.operations.filter((operation) => operation.type === 'paste')).toHaveLength(0);
  });

  it('keeps controlled error ownership through retry, remount, and dispose', async () => {
    let attempts = 0;
    const disposed = vi.fn();
    const backend: MountedTerminal = {
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      paste: vi.fn(),
      dispose: disposed
    };
    const adapter: TerminalRendererAdapter = {
      mount: vi.fn(async () => {
        attempts += 1;
        if (attempts === 1) throw new Error('synthetic initialization failure');
        return backend;
      })
    };
    const renderer = createTerminalRenderer({ adapter, label: 'Session terminal' });
    const firstHost = document.createElement('div');
    firstHost.className = 'shell-host';
    firstHost.setAttribute('role', 'group');
    firstHost.setAttribute('aria-label', 'Original host');
    firstHost.style.height = '99px';
    document.body.append(firstHost);

    await renderer.mount(firstHost);
    expect(renderer.state).toBe('error');
    expect(firstHost).toHaveClass('shell-host', 'terminal-renderer');
    expect(firstHost).toHaveAttribute('role', 'region');
    expect(firstHost).toHaveAttribute('aria-label', 'Session terminal');
    expect(firstHost.querySelector('[role="alert"]')).toBeInTheDocument();

    const secondHost = document.createElement('div');
    document.body.append(secondHost);
    await renderer.mount(secondHost);
    expect(renderer.state).toBe('ready');
    expect(firstHost).not.toHaveClass('terminal-renderer');
    expect(firstHost.querySelector('[role="alert"]')).not.toBeInTheDocument();
    expect(firstHost).toHaveClass('shell-host');
    expect(firstHost).toHaveAttribute('role', 'group');
    expect(firstHost).toHaveAttribute('aria-label', 'Original host');
    expect(firstHost.style.height).toBe('99px');

    renderer.dispose();
    expect(disposed).toHaveBeenCalledTimes(1);
    expect(secondHost.querySelector('[role="alert"], [role="status"]')).not.toBeInTheDocument();
    expect(secondHost).not.toHaveClass('terminal-renderer');
  });

  it('keeps native selection and keyboard copy available without intercepting copy', async () => {
    const { adapter } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter });
    const host = document.createElement('div');
    document.body.append(host);
    await renderer.mount(host);

    expect(host).toHaveAttribute('role', 'region');
    expect(host).toHaveAttribute('aria-label', 'Terminal');
    const screen = host.querySelector('[data-test-terminal-screen]')!;
    const textNode = document.createTextNode('selectable output');
    screen.appendChild(textNode);
    const selection = window.getSelection()!;
    const range = document.createRange();
    range.selectNodeContents(textNode);
    selection.removeAllRanges();
    selection.addRange(range);

    const copy = new Event('copy', { bubbles: true, cancelable: true });
    expect(host.dispatchEvent(copy)).toBe(true);
    expect(copy.defaultPrevented).toBe(false);
    expect(selection.rangeCount).toBe(1);
    expect(selection.getRangeAt(0).toString()).toBe('selectable output');
  });

  it('requires confirmation for multiline and control-character paste, then forwards accepted paste', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    const confirmPaste = vi.fn().mockResolvedValue(true);
    const renderer = createTerminalRenderer({ adapter, confirmPaste });
    const host = document.createElement('div');
    await renderer.mount(host);

    const multilineEvent = clipboardPaste(host, 'printf one\nprintf two');
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(1));
    expect(multilineEvent.defaultPrevented).toBe(true);
    expect(confirmPaste).toHaveBeenCalledWith({
      text: 'printf one\nprintf two',
      multiline: true,
      hasControlCharacters: true
    });
    await vi.waitFor(() => expect(terminals[0]?.operations).toContainEqual({ type: 'paste', text: 'printf one\nprintf two' }));

    confirmPaste.mockClear();
    const controlEvent = clipboardPaste(host, 'safe\x03');
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(1));
    expect(controlEvent.defaultPrevented).toBe(true);
    expect(confirmPaste.mock.calls[0]?.[0]).toMatchObject({
      multiline: false,
      hasControlCharacters: true
    });

    confirmPaste.mockClear();
    confirmPaste.mockResolvedValue(false);
    clipboardPaste(host, 'not accepted\n');
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(1));
    expect(terminals[0]?.operations.filter((operation) => operation.type === 'paste')).toHaveLength(2);
  });

  it('lets safe single-line paste use W-Term input without confirmation', async () => {
    const { adapter } = createDeterministicAdapter();
    const confirmPaste = vi.fn();
    const renderer = createTerminalRenderer({ adapter, confirmPaste });
    const host = document.createElement('div');
    await renderer.mount(host);

    const event = clipboardPaste(host, 'ls -la');
    expect(event.defaultPrevented).toBe(false);
    expect(confirmPaste).not.toHaveBeenCalled();
  });

  it('preserves focus across a safe remount and makes dispose idempotent', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter });
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    document.body.append(firstHost, secondHost);
    await renderer.mount(firstHost);
    renderer.focus();
    expect(firstHost).toHaveFocus();

    await renderer.mount(secondHost);
    expect(secondHost).toHaveFocus();
    renderer.dispose();
    renderer.dispose();
    expect(renderer.state).toBe('disposed');
    expect(terminals).toHaveLength(2);

    await renderer.mount(firstHost);
    expect(renderer.state).toBe('ready');
    expect(firstHost).toHaveFocus();
  });

  it('renders one controlled error state when initialization fails', async () => {
    const { adapter } = createDeterministicAdapter({ fail: true });
    const stateChanges: string[] = [];
    const renderer = createTerminalRenderer({ adapter, onStateChange: (state) => stateChanges.push(state) });
    const host = document.createElement('div');
    await expect(renderer.mount(host)).resolves.toBeUndefined();

    expect(renderer.state).toBe('error');
    expect(renderer.error).toEqual({
      code: 'wasm-initialization-failed',
      message: 'Terminal could not start.'
    });
    expect(host.querySelector('[role="alert"]')).toHaveTextContent('Terminal unavailable. Try again.');
    expect(host.textContent).not.toContain('synthetic WASM failure');
    expect(stateChanges).toEqual(['loading', 'error']);
  });

  it('fails closed when pending output exceeds the bounded runtime buffer', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter, maxPendingWriteBytes: 4 });
    const host = document.createElement('div');
    document.body.append(host);
    const mount = renderer.mount(host);
    renderer.write(new Uint8Array([1, 2, 3, 4, 5]));
    await mount;

    expect(renderer.state).toBe('error');
    expect(renderer.error?.code).toBe('pending-output-limit');
    expect(terminals).toHaveLength(1);
    expect(terminals[0]?.operations).toHaveLength(0);
    expect(host.querySelector('[role="alert"]')).toBeInTheDocument();
  });

  it('does not log terminal bytes', async () => {
    const { adapter } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter });
    const host = document.createElement('div');
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      await renderer.mount(host);
      renderer.write(new Uint8Array([0x1b, 0x5b, 0x33, 0x31, 0x6d, 0xff, 0x00]));
      expect(log).not.toHaveBeenCalled();
      expect(warn).not.toHaveBeenCalled();
      expect(error).not.toHaveBeenCalled();
    } finally {
      log.mockRestore();
      warn.mockRestore();
      error.mockRestore();
    }
  });

  it('does not construct W-Term into a released host after core loading', async () => {
    moduleMocks.MockGhosttyCore.load.mockResolvedValue(new moduleMocks.MockGhosttyCore());
    const adapter = createWTermGhosttyAdapter();
    const host = document.createElement('div');
    const before = moduleMocks.MockWTerm.instances.length;

    await expect(adapter.mount(host, {
      initialSize: { cols: 80, rows: 24 },
      scrollbackLimitBytes: 64 * 1024,
      onInput: vi.fn(),
      isCurrent: () => false
    })).rejects.toThrow('terminal mount became stale');

    expect(moduleMocks.MockWTerm.instances).toHaveLength(before);
    expect(host).toBeEmptyDOMElement();
  });

  it('frames accepted bracketed paste and strips escape bytes in the W-Term adapter', async () => {
    const core = { bracketedPaste: vi.fn(() => true) };
    moduleMocks.MockGhosttyCore.load.mockResolvedValue(core as never);
    const input = vi.fn();
    const adapter = createWTermGhosttyAdapter();
    const host = document.createElement('div');
    const mounted = await adapter.mount(host, {
      initialSize: { cols: 80, rows: 24 },
      scrollbackLimitBytes: 64 * 1024,
      onInput: input
    });

    mounted.paste('echo \x1b[31munsafe');

    expect(input).toHaveBeenCalledWith('\x1b[200~echo [31munsafe\x1b[201~');
    const inputElement = host.querySelector('textarea');
    expect(inputElement).not.toHaveAttribute('aria-hidden');
    expect(inputElement).toHaveAttribute('aria-label', 'Terminal input');
    expect(host.style.height).toBe('408px');

    mounted.resize(80, 30);
    expect(host.style.height).toBe('510px');
    const reusedContent = document.createElement('p');
    reusedContent.textContent = 'reused host content';
    host.appendChild(reusedContent);
    mounted.dispose({ preserveHost: true });
    expect(host).toContainElement(reusedContent);
    mounted.dispose();
  });

  it('direct adapter disposal preserves host values and cleans only its own nodes once', async () => {
    moduleMocks.MockGhosttyCore.load.mockResolvedValue(new moduleMocks.MockGhosttyCore());
    const host = document.createElement('div');
    host.className = 'shell-host wterm';
    host.setAttribute('role', 'group');
    host.setAttribute('aria-label', 'Existing terminal host');
    host.style.height = '91px';
    host.style.setProperty('--term-row-height', '19px');
    const existingInput = document.createElement('textarea');
    existingInput.setAttribute('aria-hidden', 'true');
    existingInput.setAttribute('tabindex', '0');
    const existingContent = document.createElement('p');
    existingContent.textContent = 'preexisting content';
    host.append(existingInput, existingContent);
    document.body.appendChild(host);

    const mounted = await createWTermGhosttyAdapter().mount(host, {
      initialSize: { cols: 80, rows: 24 },
      scrollbackLimitBytes: 64 * 1024,
      onInput: vi.fn()
    });
    const instance = moduleMocks.MockWTerm.instances.at(-1)!;
    const clickFocus = instance._onClickFocus;
    mounted.write(new Uint8Array([0x41]));
    await Promise.resolve();
    expect(host).toHaveClass('has-scrollback');
    expect(existingInput).toHaveAttribute('aria-hidden', 'true');
    expect(instance.input?.textarea).toHaveAttribute('aria-label', 'Terminal input');
    instance.input?.textarea.dispatchEvent(new Event('focus'));
    const click = new Event('click', { bubbles: true });
    host.dispatchEvent(click);
    expect(clickFocus).toHaveBeenCalledTimes(1);

    mounted.dispose();

    expect(host).toContainElement(existingContent);
    expect(host).toContainElement(existingInput);
    expect(host.querySelector('.term-grid')).not.toBeInTheDocument();
    expect(host.querySelectorAll('textarea')).toHaveLength(1);
    expect(host.querySelector('textarea')).toBe(existingInput);
    expect(host).toHaveClass('shell-host', 'wterm');
    expect(host).not.toHaveClass('cursor-blink', 'focused', 'has-scrollback');
    expect(host).toHaveAttribute('role', 'group');
    expect(host).toHaveAttribute('aria-label', 'Existing terminal host');
    expect(host.style.height).toBe('91px');
    expect(host.style.getPropertyValue('--term-row-height')).toBe('19px');

    host.dispatchEvent(new Event('click', { bubbles: true }));
    expect(clickFocus).toHaveBeenCalledTimes(1);
    mounted.dispose();
    expect(host).toContainElement(existingContent);
    expect(host.style.height).toBe('91px');
  });

  it('rejects missing or malformed benchmark commit provenance', () => {
    expect(() => validateFullCommit(undefined)).toThrow('explicit 40-character commit SHA');
    expect(() => validateFullCommit('not-a-commit')).toThrow('explicit 40-character commit SHA');
    expect(() => validateFullCommit('a'.repeat(39))).toThrow('explicit 40-character commit SHA');
    expect(() => validateFullCommit('g'.repeat(40))).toThrow('explicit 40-character commit SHA');
  });

  it('rejects mismatched revisions and dirty benchmark inputs', () => {
    const commit = 'a'.repeat(40);
    expect(() => assertCommitMatchesHead(commit, 'b'.repeat(40))).toThrow('does not match checkout HEAD');
    expect(() => assertCommitMatchesHead(commit, commit.toUpperCase())).not.toThrow();
    expect(() => assertCleanExecutionInputs(' M apps/web/src/lib/terminal/renderer.ts')).toThrow(
      'execution-critical benchmark inputs are dirty'
    );
    expect(() => assertCleanExecutionInputs('?? apps/web/tests/bench/terminal-renderer.bench.ts')).toThrow(
      'execution-critical benchmark inputs are dirty'
    );
    expect(() => assertCleanExecutionInputs('')).not.toThrow();
  });

  it('validates per-workload benchmark sample counts', () => {
    const samples = Object.fromEntries(
      Object.entries(BENCHMARK_REPETITIONS).map(([name, count]) => [name, { raw_samples: Array(count).fill(1) }])
    );
    expect(() => assertBenchmarkSampleCounts(samples, BENCHMARK_REPETITIONS)).not.toThrow();
    const invalid = { ...samples, sustained_output: { raw_samples: [1] } };
    expect(() => assertBenchmarkSampleCounts(invalid, BENCHMARK_REPETITIONS)).toThrow(
      'sample count for sustained_output was 1; expected 10'
    );
  });
});
