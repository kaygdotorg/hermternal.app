import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  createTerminalRenderer,
  createWTermGhosttyAdapter,
  MAX_DANGEROUS_PASTE_BYTES,
  MAX_PENDING_PASTE_BYTES,
  MAX_PENDING_PASTE_COUNT,
  MAX_READY_WRITE_CHUNK_BYTES,
  MAX_READY_WRITE_BUFFER_BYTES,
  type MountedTerminal,
  type PasteRequest,
  type TerminalRendererAdapter,
  type TerminalSize
} from './renderer';
import {
  assertBenchmarkSampleCounts,
  assertBenchmarkTrace,
  assertCleanExecutionInputs,
  assertCommitMatchesHead,
  assertNoDisallowedNetworkRequests,
  BENCHMARK_EXECUTION_INPUT_PATHS,
  BENCHMARK_REPETITIONS,
  isAllowedBenchmarkRequest,
  type BenchmarkBuild,
  type BenchmarkCheckout,
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
        dispose: vi.fn((disposeOptions?: Readonly<{ preserveHost?: boolean }>) => {
          if (!disposeOptions?.preserveHost) host.replaceChildren();
        }),
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

function benchmarkFiles(root: string, relativePath = ''): string[] {
  const directory = join(root, relativePath);
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const child = join(relativePath, entry.name);
    if (entry.isDirectory()) files.push(...benchmarkFiles(root, child));
    else files.push(child);
  }
  return files;
}

async function recomputeBenchmarkBuild(repoRoot: string): Promise<BenchmarkBuild> {
  const webRoot = resolve(repoRoot, 'apps/web');
  const outputDirectory = resolve(repoRoot, '.terminal-renderer-test-build');
  rmSync(outputDirectory, { recursive: true, force: true });
  try {
    const buildScript = `
      import { build } from 'vite';
      import { resolve } from 'node:path';
      await build({
        root: process.cwd(),
        configFile: false,
        logLevel: 'error',
        build: {
          outDir: ${JSON.stringify(outputDirectory)},
          emptyOutDir: true,
          assetsInlineLimit: 0,
          cssCodeSplit: true,
          minify: true,
          rollupOptions: {
            input: resolve(process.cwd(), 'tests/bench/terminal-renderer.browser.ts'),
            output: {
              entryFileNames: 'entry.js',
              chunkFileNames: 'chunks/[name]-[hash].js',
              assetFileNames: 'assets/[name]-[hash][extname]'
            }
          }
        }
      });
    `;
    const buildEnv = { ...process.env };
    delete buildEnv.NODE_ENV;
    delete buildEnv.VITEST;
    execFileSync('bun', ['-e', buildScript], {
      cwd: webRoot,
      env: buildEnv,
      maxBuffer: 64 * 1024 * 1024
    });
    const files = benchmarkFiles(outputDirectory).map((path) => {
      const bytes = readFileSync(join(outputDirectory, path));
      return { path, bytes: bytes.byteLength, sha256: createHash('sha256').update(bytes).digest('hex') };
    }).sort((left, right) => left.path.localeCompare(right.path));
    const sumFiles = (predicate: (path: string) => boolean): number =>
      files.reduce((total, file) => total + (predicate(file.path) ? file.bytes : 0), 0);
    return {
      command: 'vite build --configFile false --minify',
      files,
      entry_bytes: sumFiles((path) => path === 'entry.js'),
      lazy_chunk_bytes: sumFiles((path) => path.startsWith('chunks/')),
      wasm_bytes: sumFiles((path) => path.endsWith('.wasm')),
      css_bytes: sumFiles((path) => path.endsWith('.css'))
    };
  } finally {
    rmSync(outputDirectory, { recursive: true, force: true });
  }
}

async function recomputeBenchmarkCheckout(commit: string): Promise<BenchmarkCheckout> {
  const repoRoot = resolve(process.cwd(), '../..');
  const executionInputs = BENCHMARK_EXECUTION_INPUT_PATHS.map((path) => {
    const bytes = execFileSync('git', ['-C', repoRoot, 'show', `${commit}:${path}`]);
    return {
      path,
      bytes: bytes.byteLength,
      sha256: createHash('sha256').update(bytes).digest('hex')
    };
  });
  const evidenceHead = execFileSync('git', ['-C', repoRoot, 'rev-parse', 'HEAD']).toString().trim();
  try {
    execFileSync('git', ['-C', repoRoot, 'merge-base', '--is-ancestor', commit, evidenceHead]);
  } catch {
    throw new Error('benchmark evidence source commit was not an ancestor of the evidence head');
  }
  const evidenceChangedPaths = execFileSync('git', ['-C', repoRoot, 'diff', '--name-only', `${commit}..${evidenceHead}`])
    .toString()
    .split('\n')
    .map((path) => path.trim())
    .filter(Boolean);
  const status = execFileSync(
    'git',
    ['-C', repoRoot, 'status', '--porcelain=v1', '--untracked-files=all', '--', ...BENCHMARK_EXECUTION_INPUT_PATHS],
    { encoding: 'utf8' }
  );
  if (status.trim()) throw new Error('benchmark execution inputs were dirty during evidence recomputation');
  return {
    head: commit,
    // The Git commit tree is the reviewed clean checkout; current working-tree
    // dirtiness is covered independently by assertCleanExecutionInputs tests.
    clean: true,
    execution_inputs: executionInputs,
    build: await recomputeBenchmarkBuild(repoRoot),
    evidence_head: evidenceHead,
    evidence_changed_paths: evidenceChangedPaths
  };
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

  it('awaits cooperative ready-state output drain before reporting idle', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter });
    await renderer.mount(document.createElement('div'));
    renderer.write(new Uint8Array(MAX_READY_WRITE_CHUNK_BYTES * 2 + 1));

    expect(terminals[0]?.operations).toHaveLength(0);
    await renderer.whenIdle();

    expect(renderer.state).toBe('ready');
    expect(terminals[0]?.operations.filter((operation) => operation.type === 'write')).toHaveLength(3);
  });

  it('fails ready-state output closed when its bounded drain buffer is exceeded', async () => {
    const { adapter } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter });
    const host = document.createElement('div');
    document.body.append(host);
    await renderer.mount(host);
    renderer.write(new Uint8Array(MAX_READY_WRITE_BUFFER_BYTES));
    renderer.write(new Uint8Array([0x41]));

    await renderer.whenIdle();
    expect(renderer.state).toBe('error');
    expect(renderer.error?.code).toBe('pending-output-limit');
    expect(host.querySelector('[role="alert"]')).toBeInTheDocument();
  });

  it('checks intrinsic write sizes before copying and accepts exact pending limits', async () => {
    const copySet = vi.spyOn(Uint8Array.prototype, 'set');
    try {
      const oversizedRenderer = createTerminalRenderer({
        adapter: createDeterministicAdapter().adapter,
        maxPendingWriteBytes: 128
      });
      oversizedRenderer.write(new Uint8Array(129));
      expect(oversizedRenderer.state).toBe('error');
      expect(oversizedRenderer.error?.code).toBe('pending-output-limit');
      expect(copySet).not.toHaveBeenCalled();

      const exactRenderer = createTerminalRenderer({
        adapter: createDeterministicAdapter().adapter,
        maxPendingWriteBytes: 128
      });
      exactRenderer.write(new Uint8Array(128));
      expect(exactRenderer.state).toBe('idle');
      expect(copySet).toHaveBeenCalledTimes(1);

      const readyRenderer = createTerminalRenderer({ adapter: createDeterministicAdapter().adapter });
      await readyRenderer.mount(document.createElement('div'));
      const callsBeforeOversizedReadyWrite = copySet.mock.calls.length;
      readyRenderer.write(new Uint8Array(MAX_READY_WRITE_BUFFER_BYTES + 1));
      expect(readyRenderer.state).toBe('error');
      expect(readyRenderer.error?.code).toBe('pending-output-limit');
      expect(copySet.mock.calls.length).toBe(callsBeforeOversizedReadyWrite);
    } finally {
      copySet.mockRestore();
    }
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

  it('does not let an unresolved mount block dispose and remount', async () => {
    const backend: MountedTerminal = {
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      paste: vi.fn(),
      dispose: vi.fn()
    };
    let calls = 0;
    const adapter: TerminalRendererAdapter = {
      mount: vi.fn(() => {
        calls += 1;
        if (calls === 1) return new Promise<MountedTerminal>(() => undefined);
        return Promise.resolve(backend);
      })
    };
    const renderer = createTerminalRenderer({ adapter });
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    const firstMount = renderer.mount(firstHost);
    await vi.waitFor(() => expect(adapter.mount).toHaveBeenCalledTimes(1));

    renderer.dispose();
    await renderer.mount(secondHost);

    expect(calls).toBe(2);
    expect(renderer.state).toBe('ready');
    expect(firstMount).toBeInstanceOf(Promise);
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

  it('does not let an older renderer clear a newer owner on a shared host', async () => {
    const host = document.createElement('div');
    document.body.appendChild(host);
    const firstDispose = vi.fn();
    const secondDispose = vi.fn();
    const makeBackend = (dispose: ReturnType<typeof vi.fn>): MountedTerminal => ({
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      paste: vi.fn(),
      dispose: dispose as MountedTerminal['dispose']
    });
    const firstAdapter: TerminalRendererAdapter = {
      mount: vi.fn(async (mountHost) => {
        const output = document.createElement('p');
        output.textContent = 'first renderer';
        mountHost.appendChild(output);
        return makeBackend(firstDispose);
      })
    };
    const secondAdapter: TerminalRendererAdapter = {
      mount: vi.fn(async (mountHost) => {
        const output = document.createElement('p');
        output.textContent = 'second renderer';
        mountHost.appendChild(output);
        return makeBackend(secondDispose);
      })
    };
    const first = createTerminalRenderer({ adapter: firstAdapter });
    const second = createTerminalRenderer({ adapter: secondAdapter });

    await first.mount(host);
    await second.mount(host);

    expect(host).toHaveTextContent('second renderer');
    expect(first.state).toBe('disposed');
    expect(second.state).toBe('ready');
    expect(firstDispose).toHaveBeenCalledTimes(1);
    expect(firstDispose).toHaveBeenCalledWith();
    expect(secondDispose).not.toHaveBeenCalled();
  });

  it('does not let a stale shared-host paste listener cancel the current owner', async () => {
    const host = document.createElement('div');
    document.body.appendChild(host);
    const firstConfirm = vi.fn().mockResolvedValue(true);
    const secondConfirm = vi.fn().mockResolvedValue(true);
    const first = createTerminalRenderer({
      adapter: createDeterministicAdapter().adapter,
      confirmPaste: firstConfirm
    });
    let resolveSecondMount!: (backend: MountedTerminal) => void;
    const secondBackend: MountedTerminal = {
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      paste: vi.fn(),
      dispose: vi.fn()
    };
    const secondAdapter: TerminalRendererAdapter = {
      mount: vi.fn(() => new Promise<MountedTerminal>((resolve) => {
        resolveSecondMount = resolve;
      }))
    };
    const second = createTerminalRenderer({ adapter: secondAdapter, confirmPaste: secondConfirm });

    await first.mount(host);
    const mounting = second.mount(host);
    await vi.waitFor(() => expect(secondAdapter.mount).toHaveBeenCalledTimes(1));

    const duringHandoff = clipboardPaste(host, 'printf one\nprintf two');
    expect(duringHandoff.defaultPrevented).toBe(false);
    expect(firstConfirm).not.toHaveBeenCalled();

    resolveSecondMount(secondBackend);
    await mounting;
    const currentPaste = clipboardPaste(host, 'printf three\nprintf four');
    await vi.waitFor(() => expect(secondConfirm).toHaveBeenCalledTimes(1));
    expect(currentPaste.defaultPrevented).toBe(true);
    expect(firstConfirm).not.toHaveBeenCalled();
  });

  it('rejects spoofed typed-array inputs while accepting a real Uint8Array subclass', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter });
    const spoofedUint16 = new Uint16Array([0x1234]);
    Object.defineProperty(spoofedUint16, Symbol.toStringTag, { value: 'Uint8Array' });
    const spoofedDataView = new DataView(new ArrayBuffer(2));
    Object.defineProperty(spoofedDataView, Symbol.toStringTag, { value: 'Uint8Array' });
    const proxiedUint8 = new Proxy(new Uint8Array([0x41]), {});

    expect(() => renderer.write(spoofedUint16 as unknown as Uint8Array)).toThrow(
      'terminal writes require Uint8Array data'
    );
    expect(() => renderer.write(spoofedDataView as unknown as Uint8Array)).toThrow(
      'terminal writes require Uint8Array data'
    );
    expect(() => renderer.write(proxiedUint8)).toThrow('terminal writes require Uint8Array data');

    const frame = document.createElement('iframe');
    document.body.appendChild(frame);
    const foreignWindow = frame.contentWindow as (Window & { Uint8Array?: typeof Uint8Array }) | null;
    const ForeignUint8Array = foreignWindow?.Uint8Array;
    expect(ForeignUint8Array).toBeDefined();
    if (!ForeignUint8Array) return;
    renderer.write(new ForeignUint8Array([0x43, 0x44]) as unknown as Uint8Array);

    class ExtendedUint8Array extends Uint8Array {
      get byteLength(): number {
        return Number.MAX_SAFE_INTEGER;
      }
      get length(): number {
        return Number.MAX_SAFE_INTEGER;
      }
    }
    const host = document.createElement('div');
    await renderer.mount(host);
    renderer.write(new ExtendedUint8Array([0x41, 0x42]));

    expect(terminals[0]?.operations).toContainEqual({
      type: 'write',
      bytes: new Uint8Array([0x43, 0x44])
    });
    expect(terminals[0]?.operations).toContainEqual({
      type: 'write',
      bytes: new Uint8Array([0x41, 0x42])
    });
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

  it('serializes dangerous paste confirmations and preserves input order', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    let resolveFirst!: (accepted: boolean) => void;
    const firstConfirmation = new Promise<boolean>((resolve) => {
      resolveFirst = resolve;
    });
    const confirmPaste = vi.fn()
      .mockImplementationOnce(() => firstConfirmation)
      .mockResolvedValueOnce(true);
    const renderer = createTerminalRenderer({ adapter, confirmPaste });
    const host = document.createElement('div');
    await renderer.mount(host);

    clipboardPaste(host, 'first\ncommand');
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(1));
    clipboardPaste(host, 'second\ncommand');
    await Promise.resolve();
    expect(confirmPaste).toHaveBeenCalledTimes(1);

    resolveFirst(true);
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(terminals[0]?.operations.filter((operation) => operation.type === 'paste')).toHaveLength(2));
    expect(terminals[0]?.operations.filter((operation) => operation.type === 'paste')).toEqual([
      { type: 'paste', text: 'first\ncommand' },
      { type: 'paste', text: 'second\ncommand' }
    ]);
  });

  it('cancels stalled paste confirmation and releases queued requests on dispose/remount', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    let resolveFirst!: (accepted: boolean) => void;
    const stalledConfirmation = new Promise<boolean>((resolve) => {
      resolveFirst = resolve;
    });
    const confirmPaste = vi.fn()
      .mockImplementationOnce(() => stalledConfirmation)
      .mockResolvedValue(true);
    const renderer = createTerminalRenderer({ adapter, confirmPaste });
    const host = document.createElement('div');
    await renderer.mount(host);

    const firstText = `${'x'.repeat(120 * 1024)}\n`;
    const secondText = `${'y'.repeat(120 * 1024)}\n`;
    clipboardPaste(host, firstText);
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(1));
    clipboardPaste(host, secondText);
    await Promise.resolve();
    expect(confirmPaste).toHaveBeenCalledTimes(1);

    renderer.dispose();
    await renderer.mount(host);
    resolveFirst(true);
    await Promise.resolve();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(confirmPaste).toHaveBeenCalledTimes(1);
    expect(terminals[0]?.operations.filter((operation) => operation.type === 'paste')).toHaveLength(0);

    clipboardPaste(host, 'fresh command\n');
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(terminals[1]?.operations).toContainEqual({ type: 'paste', text: 'fresh command\n' }));
  });

  it('releases stalled paste state before a direct ready-host remount', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    let resolveStalled!: (accepted: boolean) => void;
    const stalledConfirmation = new Promise<boolean>((resolve) => {
      resolveStalled = resolve;
    });
    const confirmPaste = vi.fn()
      .mockImplementationOnce(() => stalledConfirmation)
      .mockResolvedValue(true);
    const renderer = createTerminalRenderer({ adapter, confirmPaste });
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    document.body.append(firstHost, secondHost);
    await renderer.mount(firstHost);

    const maximumPayload = `${'x'.repeat(MAX_DANGEROUS_PASTE_BYTES - 1)}\n`;
    clipboardPaste(firstHost, maximumPayload);
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(1));

    const runtime = renderer as unknown as {
      pasteQueue: unknown[];
      pasteQueueBytes: number;
      activePasteBytes: number;
      activePaste: { request: PasteRequest | null } | null;
    };
    expect(confirmPaste).toHaveBeenCalledWith(expect.objectContaining({ text: maximumPayload }));
    expect(runtime.activePaste).not.toBeNull();
    expect(runtime.pasteQueue).toHaveLength(0);
    expect(runtime.pasteQueueBytes).toBe(0);
    expect(runtime.activePasteBytes).toBe(new TextEncoder().encode(maximumPayload).byteLength);

    await renderer.mount(secondHost);
    expect(runtime.activePaste).toBeNull();
    expect(runtime.pasteQueue).toHaveLength(0);
    expect(runtime.pasteQueueBytes).toBe(0);
    expect(runtime.activePasteBytes).toBe(0);

    resolveStalled(true);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(terminals[0]?.operations.filter((operation) => operation.type === 'paste')).toHaveLength(0);

    const staleEvent = clipboardPaste(firstHost, 'stale\ncommand');
    expect(staleEvent.defaultPrevented).toBe(false);
    expect(confirmPaste).toHaveBeenCalledTimes(1);

    clipboardPaste(secondHost, 'fresh\ncommand');
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(terminals[1]?.operations).toContainEqual({ type: 'paste', text: 'fresh\ncommand' }));
  });

  it('enforces dangerous paste count, aggregate-byte, and single-payload boundaries', async () => {
    const { adapter } = createDeterministicAdapter();
    let resolveFirst!: (accepted: boolean) => void;
    const stalledConfirmation = new Promise<boolean>((resolve) => {
      resolveFirst = resolve;
    });
    const confirmPaste = vi.fn().mockImplementation(() => stalledConfirmation);
    const renderer = createTerminalRenderer({ adapter, confirmPaste });
    const host = document.createElement('div');
    await renderer.mount(host);

    const oneByteUnderLimit = `${'a'.repeat(MAX_DANGEROUS_PASTE_BYTES - 2)}\n`;
    const atLimit = `${'b'.repeat(MAX_DANGEROUS_PASTE_BYTES - 1)}\n`;
    const oversized = `${'c'.repeat(MAX_DANGEROUS_PASTE_BYTES)}\n`;
    expect(new TextEncoder().encode(atLimit).byteLength).toBe(MAX_DANGEROUS_PASTE_BYTES);
    expect(new TextEncoder().encode(oversized).byteLength).toBeGreaterThan(MAX_DANGEROUS_PASTE_BYTES);

    for (let index = 0; index < MAX_PENDING_PASTE_COUNT; index += 1) {
      clipboardPaste(host, `${String(index)}\n`);
    }
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(1));
    const runtime = renderer as unknown as {
      pasteQueue: unknown[];
      pasteQueueBytes: number;
      activePasteBytes: number;
      activePaste: unknown;
    };
    expect(runtime.pasteQueue).toHaveLength(MAX_PENDING_PASTE_COUNT - 1);
    expect(runtime.pasteQueueBytes).toBeGreaterThan(0);
    expect(runtime.activePasteBytes).toBeGreaterThan(0);
    expect(runtime.activePasteBytes + runtime.pasteQueueBytes).toBeLessThanOrEqual(MAX_PENDING_PASTE_BYTES);

    clipboardPaste(host, `${MAX_PENDING_PASTE_COUNT}\n`);
    await Promise.resolve();
    expect(runtime.pasteQueue).toHaveLength(MAX_PENDING_PASTE_COUNT - 1);
    expect(confirmPaste).toHaveBeenCalledTimes(1);

    renderer.dispose();
    await renderer.mount(host);
    expect(runtime.activePaste).toBeNull();
    expect(runtime.pasteQueue).toHaveLength(0);
    expect(runtime.pasteQueueBytes).toBe(0);

    const exactLimitEvent = clipboardPaste(host, atLimit);
    expect(exactLimitEvent.defaultPrevented).toBe(true);
    await vi.waitFor(() => expect(confirmPaste).toHaveBeenCalledTimes(2));
    renderer.dispose();
    await renderer.mount(host);
    expect(runtime.pasteQueueBytes).toBe(0);

    const oversizedEvent = clipboardPaste(host, oversized);
    expect(oversizedEvent.defaultPrevented).toBe(true);
    expect(confirmPaste).toHaveBeenCalledTimes(2);

    // Aggregate bytes at the limit are admitted, while one additional byte is
    // rejected without retaining a second payload. Use two stalled entries so
    // the active confirmation remains visible to the bounded accounting.
    const aggregateRenderer = createTerminalRenderer({
      adapter: createDeterministicAdapter().adapter,
      confirmPaste: vi.fn(() => stalledConfirmation)
    });
    const aggregateHost = document.createElement('div');
    await aggregateRenderer.mount(aggregateHost);
    clipboardPaste(aggregateHost, oneByteUnderLimit);
    clipboardPaste(aggregateHost, '\n');
    const aggregateRuntime = aggregateRenderer as unknown as {
      pasteQueueBytes: number;
      activePasteBytes: number;
    };
    await vi.waitFor(() => expect(
      aggregateRuntime.activePasteBytes + aggregateRuntime.pasteQueueBytes
    ).toBe(MAX_PENDING_PASTE_BYTES));
    expect(aggregateRuntime.activePasteBytes).toBeGreaterThan(0);
    expect(aggregateRuntime.pasteQueueBytes).toBe(1);
    clipboardPaste(aggregateHost, 'x\n');
    expect(aggregateRuntime.activePasteBytes + aggregateRuntime.pasteQueueBytes).toBe(MAX_PENDING_PASTE_BYTES);
    resolveFirst(false);
    await vi.waitFor(() => expect(
      aggregateRuntime.activePasteBytes + aggregateRuntime.pasteQueueBytes
    ).toBe(0));

    // A rejected confirmation releases its retained bytes before the next
    // exact-limit payload is admitted.
    const rejectConfirmation = vi.fn()
      .mockRejectedValueOnce(new Error('synthetic denial'))
      .mockResolvedValue(true);
    const rejectionRenderer = createTerminalRenderer({
      adapter: createDeterministicAdapter().adapter,
      confirmPaste: rejectConfirmation
    });
    const rejectionHost = document.createElement('div');
    await rejectionRenderer.mount(rejectionHost);
    clipboardPaste(rejectionHost, atLimit);
    const rejectionRuntime = rejectionRenderer as unknown as {
      pasteQueueBytes: number;
      activePasteBytes: number;
    };
    await vi.waitFor(() => expect(rejectConfirmation).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(
      rejectionRuntime.activePasteBytes + rejectionRuntime.pasteQueueBytes
    ).toBe(0));
    clipboardPaste(rejectionHost, atLimit);
    await vi.waitFor(() => expect(rejectConfirmation).toHaveBeenCalledTimes(2));
    rejectionRenderer.dispose();
    aggregateRenderer.dispose();
  });

  it('catches backend paste failures without an unhandled rejection', async () => {
    const backend: MountedTerminal = {
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      paste: vi.fn(() => { throw new Error('synthetic paste failure'); }),
      dispose: vi.fn()
    };
    const renderer = createTerminalRenderer({
      adapter: { mount: vi.fn(async () => backend) },
      confirmPaste: vi.fn().mockResolvedValue(true)
    });
    const host = document.createElement('div');
    document.body.append(host);
    await renderer.mount(host);
    clipboardPaste(host, 'first\ncommand');
    await vi.waitFor(() => expect(renderer.state).toBe('error'));
    expect(host.querySelector('[role="alert"]')).toBeInTheDocument();
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

  it('keeps a loading callback remount from overwriting the pending mount', async () => {
    const firstBackend: MountedTerminal = {
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      paste: vi.fn(),
      dispose: vi.fn()
    };
    const secondBackend: MountedTerminal = {
      write: vi.fn(),
      resize: vi.fn(),
      focus: vi.fn(),
      paste: vi.fn(),
      dispose: vi.fn()
    };
    let resolveFirst!: (backend: MountedTerminal) => void;
    let calls = 0;
    const adapter: TerminalRendererAdapter = {
      mount: vi.fn(() => {
        calls += 1;
        if (calls === 1) return new Promise<MountedTerminal>((resolve) => { resolveFirst = resolve; });
        return Promise.resolve(secondBackend);
      })
    };
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    document.body.append(firstHost, secondHost);
    let remounted = false;
    let renderer!: ReturnType<typeof createTerminalRenderer>;
    renderer = createTerminalRenderer({
      adapter,
      onStateChange: (state) => {
        if (state === 'loading' && !remounted) {
          remounted = true;
          queueMicrotask(() => { void renderer.mount(secondHost); });
        }
      }
    });

    const firstMount = renderer.mount(firstHost);
    await vi.waitFor(() => expect(adapter.mount).toHaveBeenCalledTimes(1));
    await vi.waitFor(() => expect(adapter.mount).toHaveBeenCalledTimes(2));
    resolveFirst(firstBackend);
    await firstMount;
    await vi.waitFor(() => expect(renderer.state).toBe('ready'));

    expect(firstBackend.dispose).toHaveBeenCalledTimes(1);
    expect(secondBackend.dispose).not.toHaveBeenCalled();
    expect(renderer.state).toBe('ready');
    expect(firstHost).toBeEmptyDOMElement();
    expect(secondHost).toHaveAttribute('data-terminal-state', 'ready');
  });

  it('restores focus once when a ready callback remounts after focusing the old host', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    document.body.append(firstHost, secondHost);
    let remounted = false;
    let renderer!: ReturnType<typeof createTerminalRenderer>;
    renderer = createTerminalRenderer({
      adapter,
      onStateChange: (state) => {
        if (state === 'ready' && !remounted) {
          remounted = true;
          renderer.focus();
          void renderer.mount(secondHost);
        }
      }
    });

    await renderer.mount(firstHost);
    await vi.waitFor(() => expect(terminals).toHaveLength(2));
    await vi.waitFor(() => expect(renderer.state).toBe('ready'));

    expect(firstHost).not.toHaveFocus();
    expect(secondHost).toHaveFocus();
    expect(terminals[0]?.operations.filter((operation) => operation.type === 'write')).toHaveLength(0);
  });

  it('rechecks ownership after onStateChange synchronously disposes at ready', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    let renderer!: ReturnType<typeof createTerminalRenderer>;
    renderer = createTerminalRenderer({
      adapter,
      onStateChange: (state) => {
        if (state === 'ready') renderer.dispose();
      }
    });
    const host = document.createElement('div');

    await renderer.mount(host);

    expect(renderer.state).toBe('disposed');
    expect(terminals[0]?.dispose).toHaveBeenCalledTimes(1);
    expect(host).toBeEmptyDOMElement();
  });

  it('does not let onStateChange synchronously remount clobber the old continuation', async () => {
    const { adapter, terminals } = createDeterministicAdapter();
    const firstHost = document.createElement('div');
    const secondHost = document.createElement('div');
    document.body.append(firstHost, secondHost);
    let remounted = false;
    let renderer!: ReturnType<typeof createTerminalRenderer>;
    renderer = createTerminalRenderer({
      adapter,
      onStateChange: (state) => {
        if (state === 'ready' && !remounted) {
          remounted = true;
          void renderer.mount(secondHost);
        }
      }
    });

    await renderer.mount(firstHost);
    await vi.waitFor(() => expect(terminals).toHaveLength(2));
    await vi.waitFor(() => expect(renderer.state).toBe('ready'));

    expect(firstHost).toBeEmptyDOMElement();
    expect(secondHost.querySelector('[data-test-terminal-screen]')).toBeInTheDocument();
    expect(terminals[0]?.dispose).toHaveBeenCalledTimes(1);
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

  it('validates direct adapter write and resize boundaries', async () => {
    const adapter = createWTermGhosttyAdapter();
    const host = document.createElement('div');
    const mounted = await adapter.mount(host, {
      initialSize: { cols: 80, rows: 24 },
      scrollbackLimitBytes: 64 * 1024,
      onInput: vi.fn()
    });
    const spoofed = new Uint8Array([0x41, 0x42]) as Uint8Array & {
      readonly byteLength: number;
      readonly length: number;
    };
    Object.defineProperties(spoofed, {
      byteLength: { get: () => Number.MAX_SAFE_INTEGER },
      length: { get: () => Number.MAX_SAFE_INTEGER }
    });
    expect(() => mounted.write(spoofed)).not.toThrow();
    expect(moduleMocks.MockWTerm.instances.at(-1)?.writes.at(-1)).toEqual(new Uint8Array([0x41, 0x42]));
    expect(() => mounted.write(new Uint16Array([0x1234]) as unknown as Uint8Array)).toThrow(
      'terminal writes require Uint8Array data'
    );
    expect(() => mounted.resize(2001, 24)).toThrow('terminal size must use integer columns 1-2000');
    expect(() => mounted.resize(80, 1001)).toThrow('terminal size must use integer columns 1-2000');
    mounted.dispose();
  });

  it('direct adapter mounts arbitrate shared-host ownership before returning', async () => {
    moduleMocks.MockGhosttyCore.load.mockResolvedValue(new moduleMocks.MockGhosttyCore());
    const host = document.createElement('div');
    host.className = 'shell-host';
    const adapter = createWTermGhosttyAdapter();
    const first = await adapter.mount(host, {
      initialSize: { cols: 80, rows: 24 },
      scrollbackLimitBytes: 64 * 1024,
      onInput: vi.fn()
    });
    const firstInstance = moduleMocks.MockWTerm.instances.at(-1)!;
    const second = await adapter.mount(host, {
      initialSize: { cols: 80, rows: 24 },
      scrollbackLimitBytes: 64 * 1024,
      onInput: vi.fn()
    });
    const secondInstance = moduleMocks.MockWTerm.instances.at(-1)!;

    expect(firstInstance).not.toBe(secondInstance);
    expect(firstInstance.input).toBeNull();
    expect(host.querySelectorAll('.term-grid')).toHaveLength(1);
    first.dispose();
    expect(host.querySelector('.term-grid')).toBe(secondInstance._container);
    second.dispose();
    expect(host).toHaveClass('shell-host');
  });

  it('makes a prior renderer inert when a direct adapter takes over its host', async () => {
    moduleMocks.MockGhosttyCore.load.mockResolvedValue(new moduleMocks.MockGhosttyCore());
    const host = document.createElement('div');
    host.className = 'shell-host';
    host.setAttribute('role', 'group');
    host.setAttribute('aria-label', 'Original host');
    document.body.appendChild(host);
    const confirmPaste = vi.fn().mockResolvedValue(true);
    const { adapter, terminals } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter, confirmPaste });
    await renderer.mount(host);
    renderer.write(new Uint8Array([0x41]));
    renderer.resize(90, 30);
    renderer.focus();
    const rendererTerminal = terminals[0]!;
    const writeCount = rendererTerminal.operations.filter((operation) => operation.type === 'write').length;
    const resizeCount = rendererTerminal.operations.filter((operation) => operation.type === 'resize').length;

    const direct = await createWTermGhosttyAdapter().mount(host, {
      initialSize: { cols: 80, rows: 24 },
      scrollbackLimitBytes: 64 * 1024,
      onInput: vi.fn()
    });
    const directInstance = moduleMocks.MockWTerm.instances.at(-1)!;
    expect(renderer.state).toBe('disposed');
    expect(host).toContainElement(directInstance._container);

    renderer.write(new Uint8Array([0x42]));
    renderer.resize(91, 31);
    renderer.focus();
    clipboardPaste(host, 'stale\nrenderer paste');
    expect(confirmPaste).toHaveBeenCalledTimes(0);
    expect(rendererTerminal.operations.filter((operation) => operation.type === 'write')).toHaveLength(writeCount);
    expect(rendererTerminal.operations.filter((operation) => operation.type === 'resize')).toHaveLength(resizeCount);

    renderer.dispose();
    expect(host).toContainElement(directInstance._container);
    direct.dispose();
    expect(host).toHaveClass('shell-host');
    expect(host).toHaveAttribute('role', 'group');
    expect(host).toHaveAttribute('aria-label', 'Original host');
  });

  it('makes a prior direct adapter inert when a renderer takes over its host', async () => {
    moduleMocks.MockGhosttyCore.load.mockResolvedValue(new moduleMocks.MockGhosttyCore());
    const host = document.createElement('div');
    host.className = 'shell-host';
    host.setAttribute('role', 'group');
    host.setAttribute('aria-label', 'Original host');
    document.body.appendChild(host);
    const direct = await createWTermGhosttyAdapter().mount(host, {
      initialSize: { cols: 80, rows: 24 },
      scrollbackLimitBytes: 64 * 1024,
      onInput: vi.fn()
    });
    const directInstance = moduleMocks.MockWTerm.instances.at(-1)!;
    direct.write(new Uint8Array([0x41]));
    direct.resize(90, 30);
    direct.focus();

    const { adapter, terminals } = createDeterministicAdapter();
    const renderer = createTerminalRenderer({ adapter });
    await renderer.mount(host);
    // The pinned adapter uses host-preserving cleanup instead of W-Term's
    // upstream innerHTML teardown. Its owned listeners, input, bridge, and
    // container are released before the renderer mutates the shared host.
    expect(directInstance.input).toBeNull();
    expect(directInstance.bridge).toBeNull();
    expect(host.querySelector('[data-test-terminal-screen]')).toBeInTheDocument();

    const directWritesBefore = directInstance.writes.length;
    const directResizesBefore = directInstance.resizes.length;
    direct.write(new Uint8Array([0x42]));
    direct.resize(91, 31);
    direct.focus();
    direct.paste('stale direct paste');
    expect(directInstance.writes).toHaveLength(directWritesBefore);
    expect(directInstance.resizes).toHaveLength(directResizesBefore);

    renderer.write(new Uint8Array([0x43]));
    await renderer.whenIdle();
    expect(terminals[0]?.operations).toContainEqual({ type: 'write', bytes: new Uint8Array([0x43]) });
    direct.dispose();
    expect(host.querySelector('[data-test-terminal-screen]')).toBeInTheDocument();
    renderer.dispose();
    expect(host).toHaveClass('shell-host');
    expect(host).toHaveAttribute('role', 'group');
    expect(host).toHaveAttribute('aria-label', 'Original host');
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

  it('restores preexisting W-Term classes after direct disposal toggles them', async () => {
    moduleMocks.MockGhosttyCore.load.mockResolvedValue(new moduleMocks.MockGhosttyCore());
    const host = document.createElement('div');
    host.className = 'shell-host wterm cursor-blink focused has-scrollback';
    document.body.appendChild(host);

    const mounted = await createWTermGhosttyAdapter().mount(host, {
      initialSize: { cols: 80, rows: 24 },
      scrollbackLimitBytes: 64 * 1024,
      onInput: vi.fn()
    });
    host.classList.remove('wterm', 'cursor-blink', 'focused', 'has-scrollback');
    mounted.dispose();

    expect(host).toHaveClass('shell-host', 'wterm', 'cursor-blink', 'focused', 'has-scrollback');
  });

  it('restores preexisting W-Term classes through renderer remount disposal', async () => {
    moduleMocks.MockGhosttyCore.load.mockResolvedValue(new moduleMocks.MockGhosttyCore());
    const host = document.createElement('div');
    host.className = 'shell-host wterm cursor-blink focused has-scrollback';
    document.body.appendChild(host);

    const renderer = createTerminalRenderer();
    await renderer.mount(host);
    host.classList.remove('wterm', 'cursor-blink', 'focused', 'has-scrollback');
    renderer.dispose();

    expect(host).toHaveClass('shell-host', 'wterm', 'cursor-blink', 'focused', 'has-scrollback');
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
      Object.entries(BENCHMARK_REPETITIONS).map(([name, count]) => [name, {
        raw_samples: Array(count).fill(1),
        distribution: { min: 1, p50: 1, p95: 1, p99: 1, max: 1, mean: 1 }
      }])
    );
    expect(() => assertBenchmarkSampleCounts(samples, BENCHMARK_REPETITIONS)).not.toThrow();
    const invalid = { ...samples, sustained_output: { raw_samples: [1] } };
    expect(() => assertBenchmarkSampleCounts(invalid, BENCHMARK_REPETITIONS)).toThrow(
      'sample count for sustained_output was 1; expected 10'
    );
    const nonFinite = {
      ...samples,
      replay_1_mib: {
        raw_samples: Array(BENCHMARK_REPETITIONS.replay_1_mib).fill(Number.NaN),
        distribution: { min: 1, p50: 1, p95: 1, p99: 1, max: 1, mean: 1 }
      }
    };
    expect(() => assertBenchmarkSampleCounts(nonFinite, BENCHMARK_REPETITIONS)).toThrow(
      'benchmark sample for replay_1_mib was not a finite non-negative number'
    );
    const missingDistribution = {
      ...samples,
      cold_initialization: {
        raw_samples: Array(BENCHMARK_REPETITIONS.cold_initialization).fill(1)
      }
    };
    expect(() => assertBenchmarkSampleCounts(missingDistribution, BENCHMARK_REPETITIONS)).toThrow(
      'benchmark distribution for cold_initialization was missing'
    );

    const incompleteDistribution = {
      ...samples,
      resize_settling: {
        raw_samples: Array(BENCHMARK_REPETITIONS.resize_settling).fill(1),
        distribution: { min: 1, p50: 1, p95: 1, p99: 1, max: 1 }
      }
    };
    expect(() => assertBenchmarkSampleCounts(incompleteDistribution, BENCHMARK_REPETITIONS)).toThrow(
      'benchmark distribution for resize_settling was incomplete; missing mean'
    );

    const invalidDistribution = {
      ...samples,
      repeated_mount_dispose: {
        raw_samples: Array(BENCHMARK_REPETITIONS.repeated_mount_dispose).fill(1),
        distribution: { min: 1, p50: 1, p95: 1, p99: 1, max: 1, mean: '1' } as unknown as Record<string, number>
      }
    };
    expect(() => assertBenchmarkSampleCounts(invalidDistribution, BENCHMARK_REPETITIONS)).toThrow(
      'benchmark distribution for repeated_mount_dispose was not finite and non-negative'
    );

    const mismatchedDistribution = {
      ...samples,
      cold_initialization: {
        raw_samples: Array(BENCHMARK_REPETITIONS.cold_initialization).fill(1),
        distribution: { min: 0, p50: 0, p95: 0, p99: 0, max: 0, mean: 0 }
      }
    };
    expect(() => assertBenchmarkSampleCounts(mismatchedDistribution, BENCHMARK_REPETITIONS)).toThrow(
      'benchmark distribution for cold_initialization did not match recomputed min'
    );
  });

  it('independently validates and binds the checked-in benchmark evidence trace', async () => {
    const evidencePath = resolve(process.cwd(), 'tests/bench/terminal-renderer.evidence.json');
    const evidence = JSON.parse(readFileSync(evidencePath, 'utf8')) as {
      revision: { source_commit: string };
      build: BenchmarkBuild;
    };
    const checkout = await recomputeBenchmarkCheckout(evidence.revision.source_commit);
    expect(() => assertBenchmarkTrace(evidence, checkout)).not.toThrow();
    expect(() => assertBenchmarkTrace(evidence, undefined as never)).toThrow(
      'checked-in benchmark evidence checkout was not a clean full-commit source'
    );

    // A valid but older renderer commit must not self-authorize evidence. The
    // helper must reject it when any non-evidence path changed before the
    // checked-in trace, rather than rebuilding current sources under that SHA.
    const arbitrarySource = execFileSync(
      'git',
      ['-C', resolve(process.cwd(), '../..'), 'rev-parse', 'HEAD~2'],
      { encoding: 'utf8' }
    ).trim();
    const arbitraryCheckout = await recomputeBenchmarkCheckout(arbitrarySource);
    const arbitraryEvidence = JSON.parse(JSON.stringify(evidence)) as {
      revision: { source_commit: string };
    };
    arbitraryEvidence.revision.source_commit = arbitrarySource;
    expect(() => assertBenchmarkTrace(arbitraryEvidence, arbitraryCheckout)).toThrow('evidence-only');

    const tamperedInput = JSON.parse(JSON.stringify(evidence)) as {
      revision: { execution_inputs: Array<{ sha256: string }> };
    };
    tamperedInput.revision.execution_inputs[0]!.sha256 = '0'.repeat(64);
    expect(() => assertBenchmarkTrace(tamperedInput, checkout)).toThrow(
      'did not match the recomputed checkout'
    );

    const tamperedSource = JSON.parse(JSON.stringify(evidence)) as {
      revision: { source_commit: string };
    };
    tamperedSource.revision.source_commit = 'a'.repeat(40);
    expect(() => assertBenchmarkTrace(tamperedSource, checkout)).toThrow(
      'did not match the reviewed checkout HEAD'
    );

    type MutableBuildEvidence = {
      build: {
        files: Array<{ path: string; bytes: number; sha256: string }>;
        entry_bytes: number;
        lazy_chunk_bytes: number;
        wasm_bytes: number;
        css_bytes: number;
      };
    };
    const cloneBuildEvidence = (): MutableBuildEvidence => JSON.parse(JSON.stringify(evidence)) as MutableBuildEvidence;

    const tamperedPath = cloneBuildEvidence();
    tamperedPath.build.files[0]!.path = 'assets/tampered.wasm';
    expect(() => assertBenchmarkTrace(tamperedPath, checkout)).toThrow(/build/);

    const tamperedSize = cloneBuildEvidence();
    tamperedSize.build.files[0]!.bytes += 1;
    expect(() => assertBenchmarkTrace(tamperedSize, checkout)).toThrow(/build/);

    const tamperedHash = cloneBuildEvidence();
    tamperedHash.build.files[0]!.sha256 = '0'.repeat(64);
    expect(() => assertBenchmarkTrace(tamperedHash, checkout)).toThrow(/build/);

    for (const key of ['entry_bytes', 'lazy_chunk_bytes', 'wasm_bytes', 'css_bytes'] as const) {
      const tamperedTotals = cloneBuildEvidence();
      tamperedTotals.build[key] += 1;
      expect(() => assertBenchmarkTrace(tamperedTotals, checkout)).toThrow(/recomputed artifacts|recomputed checkout/);
    }

    type MutablePerformanceEvidence = {
      browser: {
        environment: Record<string, string>;
        render_fence: string;
        long_tasks_ms: number[];
        memory: {
          supported: boolean;
          before_replay_bytes: number | null;
          after_replay_bytes: number | null;
          after_dispose_bytes: number | null;
          reason: string | null;
        };
        workload: {
          replay_bytes: number;
          replay_chunks: number;
          mount_dispose_repetitions: number;
          initial_size: { cols: number; rows: number };
          scrollback_limit_bytes: number;
        };
      };
    };
    const clonePerformanceEvidence = (): MutablePerformanceEvidence => JSON.parse(JSON.stringify(evidence)) as MutablePerformanceEvidence;

    const tamperedFence = clonePerformanceEvidence();
    tamperedFence.browser.render_fence = 'renderer-call-drain';
    expect(() => assertBenchmarkTrace(tamperedFence, checkout)).toThrow(/browser metadata/);

    const tamperedLongTask = clonePerformanceEvidence();
    tamperedLongTask.browser.long_tasks_ms[0] = -1;
    expect(() => assertBenchmarkTrace(tamperedLongTask, checkout)).toThrow(/long-task/);

    const tamperedMemory = clonePerformanceEvidence();
    tamperedMemory.browser.memory.supported = false;
    expect(() => assertBenchmarkTrace(tamperedMemory, checkout)).toThrow(/memory support/);

    const tamperedWorkload = clonePerformanceEvidence();
    tamperedWorkload.browser.workload.replay_chunks -= 1;
    expect(() => assertBenchmarkTrace(tamperedWorkload, checkout)).toThrow(/workload metadata/);

    const tamperedNetwork = clonePerformanceEvidence();
    tamperedNetwork.browser.environment.disallowed_network_requests = '1';
    expect(() => assertBenchmarkTrace(tamperedNetwork, checkout)).toThrow(/network policy/);

    const nonEvidenceDescendant = {
      ...checkout,
      evidence_changed_paths: ['apps/web/src/lib/terminal/renderer.ts']
    };
    expect(() => assertBenchmarkTrace(evidence, nonEvidenceDescendant)).toThrow(/evidence-only/);
  });

  it('fails closed for outbound benchmark requests', () => {
    expect(isAllowedBenchmarkRequest('http://127.0.0.1:4173/assets/entry.js', 'http://127.0.0.1:4173')).toBe(true);
    expect(isAllowedBenchmarkRequest('data:text/javascript,export default 1', 'http://127.0.0.1:4173')).toBe(true);
    expect(isAllowedBenchmarkRequest('blob:http://127.0.0.1:4173/id', 'http://127.0.0.1:4173')).toBe(true);
    expect(isAllowedBenchmarkRequest('https://example.com/collect', 'http://127.0.0.1:4173')).toBe(false);
    expect(isAllowedBenchmarkRequest('http://127.0.0.2:4173/other-loopback', 'http://127.0.0.1:4173')).toBe(false);
    expect(() => assertNoDisallowedNetworkRequests(0)).not.toThrow();
    expect(() => assertNoDisallowedNetworkRequests(1)).toThrow('disallowed network request');
  });
});
