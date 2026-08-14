import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import { accessSync, chmodSync, constants as fsConstants, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
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
  assertLiveBenchmarkTrace,
  assertRetainedBenchmarkTrace,
  assertCommitMatchesHead,
  assertNoDisallowedNetworkRequests,
  BENCHMARK_EXECUTION_INPUT_PATHS,
  BENCHMARK_HARNESS_DIAGNOSTIC_SUCCESS_MS,
  BENCHMARK_HARNESS_TIMEOUT_MS,
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

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function recomputeBenchmarkBuild(
  repoRoot: string,
  environment: NodeJS.ProcessEnv,
  options: Readonly<{
    bunExecutable?: string;
    cacheDirectory?: string;
    timeoutMs?: number;
  }> = {}
): Promise<BenchmarkBuild> {
  const webRoot = resolve(repoRoot, 'apps/web');
  const outputDirectory = resolve(repoRoot, '.terminal-renderer-test-build');
  const bunExecutable = options.bunExecutable ?? 'bun';
  const timeoutMs = options.timeoutMs ?? BENCHMARK_HARNESS_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error('benchmark recomputation timeout was invalid');
  }
  const homeDirectory = environment.HOME;
  const tempDirectory = environment.TMPDIR;
  if (!homeDirectory || !tempDirectory) {
    throw new Error('benchmark recomputation private directories were unavailable');
  }
  requireDirectory(homeDirectory, 'benchmark recomputation private home was unavailable');
  requireDirectory(tempDirectory, 'benchmark recomputation private temp directory was unavailable');
  if (options.cacheDirectory) {
    requireDirectory(options.cacheDirectory, 'benchmark recomputation private cache was unavailable');
  }
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
    const buildEnvironment = createSanitizedDependencyEnvironment(homeDirectory, tempDirectory, environment);
    buildEnvironment.BUN_CONFIG_NO_INSTALL = '1';
    buildEnvironment.BUN_CONFIG_REGISTRY = BUN_REGISTRY_BLACKHOLE;
    buildEnvironment.NPM_CONFIG_OFFLINE = 'true';
    buildEnvironment.npm_config_offline = 'true';
    buildEnvironment.NPM_CONFIG_REGISTRY = BUN_REGISTRY_BLACKHOLE;
    buildEnvironment.npm_config_registry = BUN_REGISTRY_BLACKHOLE;
    if (options.cacheDirectory) buildEnvironment.BUN_INSTALL_CACHE_DIR = options.cacheDirectory;
    await runOwnedProcess({
      command: bunExecutable,
      argumentsList: ['--no-install', '-e', buildScript],
      cwd: webRoot,
      environment: buildEnvironment,
      timeoutMs,
      failureMessage: 'benchmark recomputation build failed',
      timeoutMessage: 'benchmark recomputation build timed out',
      outputLimitBytes: BENCHMARK_BUILD_OUTPUT_LIMIT_BYTES,
      outputLimitMessage: 'benchmark recomputation output exceeded its bounded capture limit'
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

const DEPENDENCY_INSTALL_TIMEOUT_MS = 20_000;
const DEPENDENCY_CACHE_CLONE_TIMEOUT_MS = 90_000;
// Escalate promptly after SIGTERM; the larger grace remains the one total
// cleanup deadline that allows macOS to reap sandbox descendants under load.
const DEPENDENCY_ESCALATION_DELAY_MS = 250;
const DEPENDENCY_KILL_GRACE_MS = 5_000;
const BENCHMARK_BUILD_OUTPUT_LIMIT_BYTES = 64 * 1024;
const BUN_REGISTRY_BLACKHOLE = 'http://127.0.0.1:1';
const OWNED_PROCESS_SUPERVISOR_SCRIPT = String.raw`
const { spawn } = require("node:child_process");
const { writeSync } = require("node:fs");
const command = process.argv[1];
const argumentsList = process.argv.slice(2);
let reported = false;
const report = (status) => {
  if (reported) return;
  reported = true;
  try { writeSync(3, JSON.stringify(status) + "\n"); } catch {}
};
process.on("SIGTERM", () => undefined);
process.on("SIGINT", () => undefined);
const child = spawn(command, argumentsList, { stdio: ["ignore", "pipe", "pipe"] });
child.stdout.on("data", (chunk) => process.stdout.write(chunk));
child.stderr.on("data", (chunk) => process.stderr.write(chunk));
child.once("error", () => report({ code: null, signal: "spawn-error" }));
child.once("exit", (code, signal) => {
  report({ code, signal });
  process.stdin.resume();
});
process.stdin.setEncoding("utf8");
process.stdin.on("data", (value) => {
  if (value.includes("release")) process.exit(0);
});
`;
const GENERATED_SVELTEKIT_TSCONFIG = `{
  "compilerOptions": {
    "paths": {
      "$lib": ["../src/lib"],
      "$lib/*": ["../src/lib/*"],
      "$app/types": ["./types/index.d.ts"]
    },
    "rootDirs": ["..", "./types"],
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "lib": ["esnext", "DOM", "DOM.Iterable"],
    "moduleResolution": "bundler",
    "module": "esnext",
    "noEmit": true,
    "target": "esnext"
  },
  "include": [
    "ambient.d.ts",
    "env.d.ts",
    "non-ambient.d.ts",
    "./types/**/$types.d.ts",
    "../vite.config.js",
    "../vite.config.ts",
    "../src/**/*.js",
    "../src/**/*.ts",
    "../src/**/*.svelte",
    "../test/**/*.js",
    "../test/**/*.ts",
    "../test/**/*.svelte",
    "../tests/**/*.js",
    "../tests/**/*.ts",
    "../tests/**/*.svelte"
  ],
  "exclude": [
    "../node_modules/**",
    "../src/service-worker.js",
    "../src/service-worker/**/*.js",
    "../src/service-worker.ts",
    "../src/service-worker/**/*.ts",
    "../src/service-worker.d.ts",
    "../src/service-worker/**/*.d.ts"
  ]
}\n`;
const MACOS_SANDBOX_EXEC = '/usr/bin/sandbox-exec';
const MACOS_NO_NETWORK_PROFILE = '(version 1) (allow default) (deny network*)';
const BENCHMARK_EVIDENCE_PATH = 'apps/web/tests/bench/terminal-renderer.evidence.json';

function hasMacNetworkSandbox(): boolean {
  if (process.platform !== 'darwin') return false;
  try {
    accessSync(MACOS_SANDBOX_EXEC, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function requireDirectory(path: string, diagnostic: string): void {
  try {
    const identity = lstatSync(path);
    if (!identity.isDirectory() || identity.isSymbolicLink()) throw new Error(diagnostic);
  } catch {
    throw new Error(diagnostic);
  }
}

function createSanitizedDependencyEnvironment(
  homeDirectory: string,
  tempDirectory: string,
  sourceEnvironment: NodeJS.ProcessEnv = process.env
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {
    PATH: sourceEnvironment.PATH ?? '/usr/bin:/bin',
    HOME: homeDirectory,
    TMPDIR: tempDirectory
  };
  for (const key of ['LANG', 'LC_ALL', 'TZ', 'TERM', 'CI'] as const) {
    const value = sourceEnvironment[key];
    if (value !== undefined) environment[key] = value;
  }
  return environment;
}

function isProcessGroupAlive(groupId: number): boolean {
  try {
    process.kill(-groupId, 0);
    return true;
  } catch {
    return false;
  }
}

function isOwnedProcessLeaderAlive(supervisor: ChildProcess, groupId: number): boolean {
  // The ChildProcess handle is the identity anchor for this invocation. Once
  // Node observes its exit, a recycled PID must never make the old group look
  // signalable again.
  if (supervisor.pid !== groupId || supervisor.exitCode !== null || supervisor.signalCode !== null) {
    return false;
  }
  try {
    process.kill(groupId, 0);
    return true;
  } catch {
    return false;
  }
}

function signalOwnedProcessGroup(
  supervisor: ChildProcess,
  groupId: number,
  signal: NodeJS.Signals
): boolean {
  // The supervisor is the group leader and ignores SIGTERM until the parent
  // escalates. Requiring the still-live invocation handle on every signal
  // prevents a recycled group id from turning cleanup into an unrelated kill.
  if (!isOwnedProcessLeaderAlive(supervisor, groupId)) return false;
  try {
    process.kill(-groupId, signal);
    return true;
  } catch {
    return false;
  }
}

async function waitForProcessGroupGone(groupId: number, deadline: number): Promise<boolean> {
  while (isProcessGroupAlive(groupId)) {
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      // Recheck at the deadline boundary so a group that exited between the
      // poll and the clock read is not reported as an uncleared owned group.
      return !isProcessGroupAlive(groupId);
    }
    await new Promise((resolve) => setTimeout(resolve, Math.min(10, remaining)));
  }
  return true;
}

type OwnedProcessOptions = Readonly<{
  command: string;
  argumentsList: readonly string[];
  cwd: string;
  environment: NodeJS.ProcessEnv;
  timeoutMs: number;
  failureMessage: string;
  timeoutMessage: string;
  outputLimitBytes: number;
  outputLimitMessage: string;
}>;

function byteLengthOfChunk(chunk: unknown): number {
  if (typeof chunk === 'string') return Buffer.byteLength(chunk);
  if (chunk instanceof Uint8Array) return chunk.byteLength;
  return Buffer.byteLength(String(chunk));
}

function runOwnedProcess(options: OwnedProcessOptions): Promise<void> {
  const totalDeadline = Date.now() + options.timeoutMs + DEPENDENCY_KILL_GRACE_MS;
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    let cleanupStarted = false;
    let statusReceived = false;
    let processTimeoutHandle: ReturnType<typeof setTimeout> | undefined;
    let escalationHandle: ReturnType<typeof setTimeout> | undefined;
    let groupId: number | undefined;
    let statusBuffer = '';
    let outputBytes = 0;

    const finish = (error?: Error): void => {
      if (settled) return;
      settled = true;
      if (processTimeoutHandle) clearTimeout(processTimeoutHandle);
      if (escalationHandle) clearTimeout(escalationHandle);
      if (error) reject(error);
      else resolve();
    };

    let beginCleanup: (error?: Error) => void = () => undefined;
    const observeOutput = (stream: NodeJS.ReadableStream | null): void => {
      stream?.on('data', (chunk: unknown) => {
        if (settled) return;
        outputBytes = Math.min(options.outputLimitBytes + 1, outputBytes + byteLengthOfChunk(chunk));
        if (outputBytes > options.outputLimitBytes) {
          beginCleanup(new Error(options.outputLimitMessage));
        }
      });
    };

    // The supervisor is the detached group leader. Install callers may pass
    // sandbox-exec as the supervised command; build callers rely on
    // --no-install and offline environment flags rather than claiming an OS
    // network boundary for Vite.
    const child = spawn(process.execPath, [
      '-e',
      OWNED_PROCESS_SUPERVISOR_SCRIPT,
      '--',
      options.command,
      ...options.argumentsList
    ], {
      cwd: options.cwd,
      detached: true,
      env: options.environment,
      stdio: ['pipe', 'pipe', 'pipe', 'pipe']
    });
    groupId = child.pid ?? undefined;
    observeOutput(child.stdout);
    observeOutput(child.stderr);

    const statusStream = child.stdio[3] as NodeJS.ReadableStream | null;
    statusStream?.on('data', (chunk: unknown) => {
      statusBuffer += Buffer.isBuffer(chunk)
        ? chunk.toString('utf8')
        : chunk instanceof Uint8Array
          ? Buffer.from(chunk).toString('utf8')
          : String(chunk);
      let newlineIndex = statusBuffer.indexOf('\n');
      while (newlineIndex >= 0) {
        const line = statusBuffer.slice(0, newlineIndex);
        statusBuffer = statusBuffer.slice(newlineIndex + 1);
        newlineIndex = statusBuffer.indexOf('\n');
        try {
          const parsed = JSON.parse(line) as { code?: unknown; signal?: unknown };
          if (
            (typeof parsed.code === 'number' || parsed.code === null) &&
            (typeof parsed.signal === 'string' || parsed.signal === null)
          ) {
            statusReceived = true;
            const successful = parsed.code === 0 && parsed.signal === null;
            beginCleanup(successful ? undefined : new Error(options.failureMessage));
          }
        } catch {
          beginCleanup(new Error(options.failureMessage));
        }
      }
    });

    beginCleanup = (error?: Error): void => {
      if (cleanupStarted) return;
      cleanupStarted = true;
      if (processTimeoutHandle) clearTimeout(processTimeoutHandle);
      const ownedGroupId = groupId;
      if (ownedGroupId === undefined) {
        finish(error ?? new Error(options.failureMessage));
        return;
      }
      if (!isOwnedProcessLeaderAlive(child, ownedGroupId)) {
        finish(isProcessGroupAlive(ownedGroupId)
          ? new Error('benchmark subprocess process-group ownership was lost')
          : error);
        return;
      }
      if (!signalOwnedProcessGroup(child, ownedGroupId, 'SIGTERM')) {
        finish(new Error('benchmark subprocess process-group ownership was lost'));
        return;
      }
      const remaining = Math.max(0, totalDeadline - Date.now());
      escalationHandle = setTimeout(() => {
        escalationHandle = undefined;
        if (!isOwnedProcessLeaderAlive(child, ownedGroupId)) {
          finish(isProcessGroupAlive(ownedGroupId)
            ? new Error('benchmark subprocess process-group ownership was lost')
            : error);
          return;
        }
        if (!signalOwnedProcessGroup(child, ownedGroupId, 'SIGKILL')) {
          finish(new Error('benchmark subprocess process-group ownership was lost'));
          return;
        }
        void waitForProcessGroupGone(ownedGroupId, totalDeadline).then((cleaned) => {
          finish(cleaned ? error : new Error('benchmark subprocess process-group cleanup timed out'));
        });
      }, Math.min(DEPENDENCY_ESCALATION_DELAY_MS, remaining));
    };

    child.once('error', () => beginCleanup(new Error('benchmark subprocess could not start')));
    child.once('exit', () => {
      if (!cleanupStarted && !statusReceived) {
        beginCleanup(new Error(options.failureMessage));
      }
    });
    processTimeoutHandle = setTimeout(() => {
      beginCleanup(new Error(options.timeoutMessage));
    }, options.timeoutMs);
  });
}

async function runOfflineBunInstall(
  cwd: string,
  options: Readonly<{
    cacheDirectory: string;
    homeDirectory: string;
    tempDirectory: string;
    timeoutMs?: number;
    bunExecutable?: string;
  }>
): Promise<NodeJS.ProcessEnv> {
  requireDirectory(options.cacheDirectory, 'benchmark dependency cache was unavailable');
  requireDirectory(options.homeDirectory, 'benchmark dependency home was unavailable');
  requireDirectory(options.tempDirectory, 'benchmark dependency temp directory was unavailable');
  const timeoutMs = options.timeoutMs ?? DEPENDENCY_INSTALL_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error('benchmark dependency preparation timeout was invalid');
  }
  const bunExecutable = options.bunExecutable ?? 'bun';
  const installArguments = [
    'install',
    '--frozen-lockfile',
    '--ignore-scripts',
    '--prefer-offline',
    `--cache-dir=${options.cacheDirectory}`,
    `--registry=${BUN_REGISTRY_BLACKHOLE}`,
    '--no-progress',
    '--no-summary'
  ];
  const environment = createSanitizedDependencyEnvironment(options.homeDirectory, options.tempDirectory);
  const sandboxed = hasMacNetworkSandbox();
  const command = sandboxed ? MACOS_SANDBOX_EXEC : bunExecutable;
  const argumentsList = sandboxed
    ? ['-p', MACOS_NO_NETWORK_PROFILE, bunExecutable, ...installArguments]
    : installArguments;

  await runOwnedProcess({
    command,
    argumentsList,
    cwd,
    environment,
    timeoutMs,
    failureMessage: 'benchmark dependency preparation failed',
    timeoutMessage: 'benchmark dependency preparation timed out',
    outputLimitBytes: BENCHMARK_BUILD_OUTPUT_LIMIT_BYTES,
    outputLimitMessage: 'benchmark dependency preparation output exceeded its bounded capture limit'
  });
  return environment;
}

function resolveBunCacheSource(): string {
  const bootstrapEnvironment: NodeJS.ProcessEnv = {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    HOME: process.env.HOME ?? tmpdir(),
    NPM_CONFIG_USERCONFIG: '/dev/null',
    npm_config_userconfig: '/dev/null'
  };
  let cachePath: string;
  try {
    cachePath = execFileSync('bun', ['pm', 'cache'], {
      encoding: 'utf8',
      env: bootstrapEnvironment,
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 2_000
    }).trim();
  } catch {
    throw new Error('benchmark dependency cache was unavailable');
  }
  requireDirectory(cachePath, 'benchmark dependency cache was unavailable');
  return cachePath;
}

function cloneBunCache(source: string, destination: string): void {
  requireDirectory(source, 'benchmark dependency cache was unavailable');
  try {
    if (process.platform === 'darwin') {
      execFileSync('ditto', ['--clone', source, destination], {
        stdio: 'ignore',
        timeout: DEPENDENCY_CACHE_CLONE_TIMEOUT_MS
      });
    } else {
      execFileSync('cp', ['-R', source, destination], {
        stdio: 'ignore',
        timeout: DEPENDENCY_CACHE_CLONE_TIMEOUT_MS
      });
    }
  } catch {
    throw new Error('benchmark dependency cache could not be isolated');
  }
  requireDirectory(destination, 'benchmark dependency cache could not be isolated');
}

/**
 * `--ignore-scripts` skips SvelteKit's package `prepare`; write only the
 * reviewed generated config needed by the isolated Vite build instead of
 * executing an unbounded lifecycle hook from the archived source.
 */
function writeGeneratedSvelteKitConfig(webRoot: string): void {
  const generatedRoot = join(webRoot, '.svelte-kit');
  mkdirSync(generatedRoot, { recursive: true });
  writeFileSync(join(generatedRoot, 'tsconfig.json'), GENERATED_SVELTEKIT_TSCONFIG);
}

function createPrivateDependencyWorkspace(): Readonly<{
  root: string;
  homeDirectory: string;
  tempDirectory: string;
  cacheDirectory: string;
}> {
  const root = mkdtempSync(join(tmpdir(), 'hermternal-renderer-dependencies-'));
  try {
    const homeDirectory = mkdtempSync(join(root, 'home-'));
    const tempDirectory = mkdtempSync(join(root, 'tmp-'));
    const cacheDirectory = join(root, 'cache');
    cloneBunCache(resolveBunCacheSource(), cacheDirectory);
    return { root, homeDirectory, tempDirectory, cacheDirectory };
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    if (error instanceof Error && error.message.startsWith('benchmark dependency')) throw error;
    throw new Error('benchmark dependency preparation workspace was unavailable');
  }
}

type EvidenceHistory = Readonly<{
  evidenceHead: string;
  evidenceChangedPaths: readonly string[];
  evidenceSourceIsStrictAncestor: boolean;
  evidenceBlobMatches: boolean;
  evidenceAnchorCount: number;
}>;

/**
 * Inspect the immutable evidence commit one commit at a time. Endpoint tree
 * diffs are insufficient because a source mutation can be reverted before the
 * evidence commit, leaving only the evidence path in the final tree diff.
 */
function inspectEvidenceHistory(
  repoRoot: string,
  sourceCommit: string,
  evidenceBytes: Buffer,
  head = 'HEAD'
): EvidenceHistory {
  const matchingAnchors = execFileSync(
    'git',
    ['-C', repoRoot, 'log', '--format=%H', head, '--', BENCHMARK_EVIDENCE_PATH],
    { encoding: 'utf8' }
  )
    .split('\n')
    .map((candidate) => candidate.trim())
    .filter(Boolean)
    .filter((candidate) => {
      try {
        return execFileSync('git', ['-C', repoRoot, 'show', `${candidate}:${BENCHMARK_EVIDENCE_PATH}`]).equals(evidenceBytes);
      } catch {
        return false;
      }
    });
  if (matchingAnchors.length === 0) throw new Error('checked-in benchmark evidence immutable anchor was missing');
  if (matchingAnchors.length !== 1) throw new Error('checked-in benchmark evidence immutable anchor was ambiguous');
  const evidenceHead = matchingAnchors[0]!;

  let historyLines: string[];
  try {
    historyLines = execFileSync(
      'git',
      ['-C', repoRoot, 'rev-list', '--parents', '--topo-order', '--reverse', `${sourceCommit}..${evidenceHead}`],
      { encoding: 'utf8' }
    )
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
  } catch {
    throw new Error('benchmark evidence source-to-anchor history was not an evidence-only immediate child');
  }

  if (historyLines.length === 0) {
    throw new Error('benchmark evidence source-to-anchor history was not an evidence-only immediate child');
  }
  const history = historyLines.map((line) => {
    const [commit, ...parents] = line.split(/\s+/u);
    return { commit: commit ?? '', parents };
  });
  if (history.some((record) => record.parents.length !== 1)) {
    throw new Error('benchmark evidence source-to-anchor history was not an evidence-only immediate child');
  }

  const changedPaths = history.flatMap((record) => {
    const parent = record.parents[0];
    if (!parent || !record.commit) return [];
    return execFileSync(
      'git',
      ['-C', repoRoot, 'diff-tree', '--no-commit-id', '--name-only', '-r', parent, record.commit],
      { encoding: 'utf8' }
    )
      .split('\n')
      .map((path) => path.trim())
      .filter(Boolean);
  });
  if (
    changedPaths.length === 0 ||
    changedPaths.some((path) => path !== BENCHMARK_EVIDENCE_PATH) ||
    history.length !== 1 ||
    history[0]?.parents[0]?.toLowerCase() !== sourceCommit.toLowerCase()
  ) {
    throw new Error('benchmark evidence source-to-anchor history was not an evidence-only immediate child');
  }

  return {
    evidenceHead,
    evidenceChangedPaths: changedPaths,
    evidenceSourceIsStrictAncestor: true,
    evidenceBlobMatches: true,
    evidenceAnchorCount: matchingAnchors.length
  };
}

async function recomputeBenchmarkCheckout(commit: string, evidenceBytes: Buffer): Promise<BenchmarkCheckout> {
  const repoRoot = resolve(process.cwd(), '../..');
  const executionInputs = BENCHMARK_EXECUTION_INPUT_PATHS.map((path) => {
    const bytes = execFileSync('git', ['-C', repoRoot, 'show', `${commit}:${path}`]);
    return {
      path,
      bytes: bytes.byteLength,
      sha256: createHash('sha256').update(bytes).digest('hex')
    };
  });
  const evidenceHistory = inspectEvidenceHistory(repoRoot, commit, evidenceBytes);
  // Build the source tree, not the verifier's checkout. This keeps input and
  // artifact hashes tied to the declared immutable source while the validator
  // itself evolves after the evidence anchor.
  const sourceRoot = mkdtempSync(join(tmpdir(), 'hermternal-renderer-source-'));
  let dependencyWorkspace: ReturnType<typeof createPrivateDependencyWorkspace> | undefined;
  let build: BenchmarkBuild;
  try {
    const archive = execFileSync('git', ['-C', repoRoot, 'archive', commit], { maxBuffer: 64 * 1024 * 1024 });
    execFileSync('tar', ['-x', '-C', sourceRoot], { input: archive });
    const sourceWebRoot = join(sourceRoot, 'apps/web');
    dependencyWorkspace = createPrivateDependencyWorkspace();
    const buildEnvironment = await runOfflineBunInstall(sourceWebRoot, dependencyWorkspace);
    writeGeneratedSvelteKitConfig(sourceWebRoot);
    build = await recomputeBenchmarkBuild(sourceRoot, buildEnvironment, {
      cacheDirectory: dependencyWorkspace.cacheDirectory
    });
  } finally {
    rmSync(sourceRoot, { recursive: true, force: true });
    if (dependencyWorkspace) rmSync(dependencyWorkspace.root, { recursive: true, force: true });
  }
  return {
    head: commit,
    // The Git commit tree is the reviewed clean checkout; current working-tree
    // dirtiness is covered independently by assertCleanExecutionInputs tests.
    clean: true,
    execution_inputs: executionInputs,
    build,
    evidence_head: evidenceHistory.evidenceHead,
    evidence_changed_paths: evidenceHistory.evidenceChangedPaths,
    evidence_source_is_strict_ancestor: evidenceHistory.evidenceSourceIsStrictAncestor,
    evidence_blob_matches: evidenceHistory.evidenceBlobMatches,
    evidence_anchor_count: evidenceHistory.evidenceAnchorCount
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

  it('rejects an intermediate source mutation and revert hidden by endpoint diff', () => {
    const fixtureRoot = mkdtempSync(join(tmpdir(), 'hermternal-evidence-history-'));
    const rendererPath = join(fixtureRoot, 'apps/web/src/lib/terminal/renderer.ts');
    const evidencePath = join(fixtureRoot, BENCHMARK_EVIDENCE_PATH);
    const commitFixture = (message: string): string => {
      execFileSync('git', ['-C', fixtureRoot, 'add', '--all'], { stdio: 'ignore' });
      execFileSync(
        'git',
        [
          '-C', fixtureRoot,
          '-c', 'user.name=Hermternal fixture',
          '-c', 'user.email=fixture@example.invalid',
          'commit', '--quiet', '--no-gpg-sign', '-m', message
        ],
        { stdio: 'ignore' }
      );
      return execFileSync('git', ['-C', fixtureRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    };

    try {
      execFileSync('git', ['-C', fixtureRoot, 'init', '--quiet', '--initial-branch=main'], { stdio: 'ignore' });
      mkdirSync(dirname(rendererPath), { recursive: true });
      mkdirSync(dirname(evidencePath), { recursive: true });
      writeFileSync(rendererPath, 'original renderer source\n');
      writeFileSync(evidencePath, 'old evidence blob\n');
      const sourceCommit = commitFixture('measured source');

      writeFileSync(rendererPath, 'mutated renderer source\n');
      commitFixture('intermediate source mutation');
      writeFileSync(rendererPath, 'original renderer source\n');
      commitFixture('intermediate source revert');

      const evidenceBytes = Buffer.from('new evidence blob\n');
      writeFileSync(evidencePath, evidenceBytes);
      const evidenceHead = commitFixture('evidence child');

      const endpointPaths = execFileSync(
        'git',
        ['-C', fixtureRoot, 'diff', '--name-only', `${sourceCommit}..${evidenceHead}`],
        { encoding: 'utf8' }
      )
        .split('\n')
        .map((path) => path.trim())
        .filter(Boolean);
      // The rejected endpoint-only implementation sees only this final tree
      // difference and would accept the reverted source mutation.
      expect(endpointPaths).toEqual([BENCHMARK_EVIDENCE_PATH]);
      expect(() => inspectEvidenceHistory(fixtureRoot, sourceCommit, evidenceBytes, evidenceHead)).toThrow(
        'evidence-only immediate child'
      );
    } finally {
      rmSync(fixtureRoot, { recursive: true, force: true });
    }
  });

  it('keeps parent live benchmark compatibility while retaining strict evidence validation', () => {
    const evidencePath = resolve(process.cwd(), 'tests/bench/terminal-renderer.evidence.json');
    const evidence = JSON.parse(readFileSync(evidencePath, 'utf8')) as {
      revision: {
        source_commit: string;
        execution_inputs: BenchmarkCheckout['execution_inputs'];
      };
      build: BenchmarkBuild;
    };
    const benchmarkStyleCheckout: BenchmarkCheckout = {
      head: evidence.revision.source_commit,
      clean: true,
      execution_inputs: evidence.revision.execution_inputs,
      build: evidence.build
    };

    // 48739cde and origin/dev 729f2613 accepted this live benchmark shape:
    // a newly generated trace has no retained evidence child yet. The strict
    // 013ea2ef entry point rejected it at the new evidence-only assertion.
    expect(() => assertLiveBenchmarkTrace(evidence, benchmarkStyleCheckout)).not.toThrow();
    expect(() => assertBenchmarkTrace(evidence, benchmarkStyleCheckout)).toThrow(
      'checked-in benchmark evidence source relationship was not evidence-only'
    );

    // The corrected benchmark callsite uses the explicit live entry point, not
    // retained artifact fields, while retained callers cannot omit the proof.
    expect(() => assertRetainedBenchmarkTrace(evidence, benchmarkStyleCheckout)).toThrow(
      'checked-in benchmark evidence source relationship was not evidence-only'
    );
    const forgedRelationship = {
      ...benchmarkStyleCheckout,
      evidence_head: benchmarkStyleCheckout.head,
      evidence_changed_paths: [BENCHMARK_EVIDENCE_PATH],
      evidence_source_is_strict_ancestor: true,
      evidence_blob_matches: true,
      evidence_anchor_count: 1
    };
    expect(() => assertRetainedBenchmarkTrace(evidence, forgedRelationship)).toThrow(
      'checked-in benchmark evidence source relationship was not evidence-only'
    );
  });

  it('prepares benchmark dependencies offline with a private environment and bounded Bun process', async () => {
    const root = mkdtempSync(join(tmpdir(), 'hermternal-offline-bun-'));
    const bin = join(root, 'bin');
    const workspace = join(root, 'workspace');
    const cacheDirectory = join(root, 'cache');
    const homeDirectory = join(root, 'home');
    const tempDirectory = join(root, 'tmp');
    const argsPath = join(root, 'args');
    const environmentPath = join(root, 'environment');
    const scriptMarkerPath = join(root, 'script-invoked');
    const timeoutMarkerPath = join(root, 'timeout-completed');
    const fakeBunPath = join(bin, 'bun');
    const originalEnvironment = new Map(
      ['PATH', 'AWS_SECRET_ACCESS_KEY', 'GITHUB_TOKEN', 'NPM_TOKEN', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY']
        .map((key) => [key, process.env[key]])
    );
    try {
      mkdirSync(bin, { recursive: true });
      mkdirSync(workspace, { recursive: true });
      mkdirSync(cacheDirectory, { recursive: true });
      mkdirSync(homeDirectory, { recursive: true });
      mkdirSync(tempDirectory, { recursive: true });
      writeFileSync(join(cacheDirectory, 'cached-package'), 'cache present');
      const inheritedPath = process.env.PATH ?? '/usr/bin:/bin';
      process.env.PATH = `${bin}:${inheritedPath}`;
      process.env.AWS_SECRET_ACCESS_KEY = 'must-not-cross-boundary';
      process.env.GITHUB_TOKEN = 'must-not-cross-boundary';
      process.env.NPM_TOKEN = 'must-not-cross-boundary';
      process.env.HTTP_PROXY = 'http://proxy.invalid:8080';
      process.env.HTTPS_PROXY = 'https://proxy.invalid:8443';
      process.env.ALL_PROXY = 'socks5://proxy.invalid:1080';
      process.env.NO_PROXY = 'proxy.invalid';

      writeFileSync(
        fakeBunPath,
        `#!/bin/sh
set -eu
printf '%s\\n' "$@" > ${JSON.stringify(argsPath)}
env > ${JSON.stringify(environmentPath)}
found=0
for argument in "$@"; do
  if [ "$argument" = "--ignore-scripts" ]; then found=1; fi
done
if [ "$found" -ne 1 ]; then touch ${JSON.stringify(scriptMarkerPath)}; fi
`
      );
      chmodSync(fakeBunPath, 0o755);

      await expect(runOfflineBunInstall(workspace, {
        cacheDirectory: join(root, 'missing-cache'),
        homeDirectory,
        tempDirectory,
        timeoutMs: 1_000
      })).rejects.toThrow('benchmark dependency cache was unavailable');

      const environment = await runOfflineBunInstall(workspace, {
        cacheDirectory,
        homeDirectory,
        tempDirectory,
        timeoutMs: 1_000
      });
      const argumentsText = readFileSync(argsPath, 'utf8');
      const childEnvironment = readFileSync(environmentPath, 'utf8');
      expect(argumentsText).toContain('install\n');
      expect(argumentsText).toContain('--frozen-lockfile\n');
      expect(argumentsText).toContain('--ignore-scripts\n');
      expect(argumentsText).toContain('--prefer-offline\n');
      expect(argumentsText).toContain(`--cache-dir=${cacheDirectory}\n`);
      expect(argumentsText).toContain(`--registry=${BUN_REGISTRY_BLACKHOLE}\n`);
      expect(environment.HOME).toBe(homeDirectory);
      expect(environment.TMPDIR).toBe(tempDirectory);
      expect(childEnvironment).not.toContain('AWS_SECRET_ACCESS_KEY=');
      expect(childEnvironment).not.toContain('GITHUB_TOKEN=');
      expect(childEnvironment).not.toContain('NPM_TOKEN=');
      expect(childEnvironment).not.toContain('HTTP_PROXY=');
      expect(childEnvironment).not.toContain('HTTPS_PROXY=');
      expect(childEnvironment).not.toContain('ALL_PROXY=');
      expect(childEnvironment).not.toContain('NO_PROXY=');
      expect(childEnvironment).not.toContain('npm_config_userconfig=');
      expect(childEnvironment).not.toContain('NPM_CONFIG_USERCONFIG=');
      expect(existsSync(scriptMarkerPath)).toBe(false);

      writeFileSync(
        fakeBunPath,
        `#!/bin/sh
set -eu
sleep 10
touch ${JSON.stringify(timeoutMarkerPath)}
`
      );
      chmodSync(fakeBunPath, 0o755);
      await expect(runOfflineBunInstall(workspace, {
        cacheDirectory,
        homeDirectory,
        tempDirectory,
        timeoutMs: 50
      })).rejects.toThrow('benchmark dependency preparation timed out');
      await new Promise((resolve) => setTimeout(resolve, DEPENDENCY_KILL_GRACE_MS + 100));
      expect(existsSync(timeoutMarkerPath)).toBe(false);
    } finally {
      for (const [key, value] of originalEnvironment) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('waits for a detached dependency descendant that ignores SIGTERM before rejecting', async () => {
    const root = mkdtempSync(join(tmpdir(), 'hermternal-offline-bun-descendant-'));
    const bin = join(root, 'bin');
    const workspace = join(root, 'workspace');
    const cacheDirectory = join(root, 'cache');
    const homeDirectory = join(root, 'home');
    const tempDirectory = join(root, 'tmp');
    const descendantPidPath = join(root, 'descendant-pid');
    const fakeBunPath = join(bin, 'bun');
    let descendantPid: number | undefined;
    try {
      for (const directory of [bin, workspace, cacheDirectory, homeDirectory, tempDirectory]) {
        mkdirSync(directory, { recursive: true });
      }
      writeFileSync(
        fakeBunPath,
        `#!/opt/homebrew/bin/bun
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const descendant = spawn(
  process.execPath,
  ['-e', 'process.on("SIGTERM", () => undefined); setInterval(() => undefined, 1_000);'],
  { stdio: 'ignore' }
);
writeFileSync(${JSON.stringify(descendantPidPath)}, String(descendant.pid));
setInterval(() => undefined, 1_000);
`
      );
      chmodSync(fakeBunPath, 0o755);

      const installing = runOfflineBunInstall(workspace, {
        cacheDirectory,
        homeDirectory,
        tempDirectory,
        timeoutMs: 2_000,
        bunExecutable: fakeBunPath
      });
      await vi.waitFor(() => expect(existsSync(descendantPidPath)).toBe(true), { timeout: 3_000 });
      descendantPid = Number.parseInt(readFileSync(descendantPidPath, 'utf8').trim(), 10);
      expect(Number.isSafeInteger(descendantPid)).toBe(true);
      await expect(installing).rejects.toThrow('benchmark dependency preparation timed out');
      await new Promise((resolve) => setTimeout(resolve, DEPENDENCY_KILL_GRACE_MS + 100));

      // The exact 4b2ca9df parent clears its escalation timer from the leader's
      // exit handler, so this assertion observes the surviving hostile child.
      expect(isProcessAlive(descendantPid!)).toBe(false);
    } finally {
      if (descendantPid !== undefined && isProcessAlive(descendantPid)) {
        try {
          process.kill(descendantPid, 'SIGKILL');
        } catch {
          // The regression cleanup is best effort after the assertion.
        }
      }
      rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('bounds hostile benchmark recomputation and cleans its detached descendants', async () => {
    const root = mkdtempSync(join(tmpdir(), 'hermternal-renderer-build-descendant-'));
    const bin = join(root, 'bin');
    const descendantPidPath = join(root, 'descendant-pid');
    const fakeBunPath = join(bin, 'bun');
    let descendantPid: number | undefined;
    try {
      mkdirSync(bin, { recursive: true });
      writeFileSync(
        fakeBunPath,
        `#!/opt/homebrew/bin/bun
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const descendant = spawn(
  process.execPath,
  ['-e', 'process.on("SIGTERM", () => undefined); setInterval(() => undefined, 1_000);'],
  { stdio: 'ignore' }
);
writeFileSync(${JSON.stringify(descendantPidPath)}, String(descendant.pid));
setInterval(() => undefined, 1_000);
`
      );
      chmodSync(fakeBunPath, 0o755);
      const buildPromise = recomputeBenchmarkBuild(
        resolve(process.cwd(), '../..'),
        {
          PATH: `${bin}:${process.env.PATH ?? '/usr/bin:/bin'}`,
          HOME: root,
          TMPDIR: root,
          npm_config_offline: 'true',
          NPM_CONFIG_OFFLINE: 'true'
        },
        { bunExecutable: fakeBunPath, timeoutMs: 2_000 }
      );
      await vi.waitFor(() => expect(existsSync(descendantPidPath)).toBe(true), { timeout: 3_000 });
      descendantPid = Number.parseInt(readFileSync(descendantPidPath, 'utf8').trim(), 10);
      expect(Number.isSafeInteger(descendantPid)).toBe(true);
      const error = await buildPromise.then(() => undefined, (failure: unknown) => failure);
      expect(error).toBeInstanceOf(Error);
      await new Promise((resolve) => setTimeout(resolve, DEPENDENCY_KILL_GRACE_MS + 100));

      // Synchronous execFileSync on the exact parent kills only its leader; the
      // assertion is intentionally about the descendant, not just elapsed time.
      expect(isProcessAlive(descendantPid!)).toBe(false);
    } finally {
      if (descendantPid !== undefined && isProcessAlive(descendantPid)) {
        try {
          process.kill(descendantPid, 'SIGKILL');
        } catch {
          // The regression cleanup is best effort after the assertion.
        }
      }
      rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('keeps the benchmark harness deadline above the observed diagnostic completion', () => {
    expect(BENCHMARK_HARNESS_TIMEOUT_MS).toBeGreaterThan(BENCHMARK_HARNESS_DIAGNOSTIC_SUCCESS_MS);
    expect(BENCHMARK_HARNESS_TIMEOUT_MS).toBeLessThanOrEqual(
      BENCHMARK_HARNESS_DIAGNOSTIC_SUCCESS_MS + 60_000
    );
  });

  it('independently validates and binds the checked-in benchmark evidence trace', async () => {
    const evidencePath = resolve(process.cwd(), 'tests/bench/terminal-renderer.evidence.json');
    const evidenceBytes = readFileSync(evidencePath);
    const evidence = JSON.parse(evidenceBytes.toString('utf8')) as {
      revision: { source_commit: string };
      build: BenchmarkBuild;
    };
    const checkout = await recomputeBenchmarkCheckout(evidence.revision.source_commit, evidenceBytes);
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
    const arbitraryCheckout = {
      ...checkout,
      head: arbitrarySource,
      evidence_source_is_strict_ancestor: false
    };
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

    const missingNetworkCount = clonePerformanceEvidence();
    delete missingNetworkCount.browser.environment.disallowed_network_requests;
    expect(() => assertBenchmarkTrace(missingNetworkCount, checkout)).toThrow(/network policy/);

    const cloneRedactionEvidence = (): { redaction: Record<string, boolean> } =>
      JSON.parse(JSON.stringify(evidence)) as { redaction: Record<string, boolean> };
    const falseLoopbackClaim = cloneRedactionEvidence();
    falseLoopbackClaim.redaction.loopback_http_access = false;
    expect(() => assertBenchmarkTrace(falseLoopbackClaim, checkout)).toThrow(/redaction metadata/);

    const oldContradictoryRedaction = cloneRedactionEvidence();
    delete oldContradictoryRedaction.redaction.loopback_http_access;
    delete oldContradictoryRedaction.redaction.external_network_access;
    oldContradictoryRedaction.redaction.network_access = false;
    expect(() => assertBenchmarkTrace(oldContradictoryRedaction, checkout)).toThrow(/redaction metadata/);

    const nonEvidenceDescendant = {
      ...checkout,
      evidence_changed_paths: ['apps/web/src/lib/terminal/renderer.ts']
    };
    expect(() => assertBenchmarkTrace(evidence, nonEvidenceDescendant)).toThrow(/evidence-only/);

    // An evidence artifact cannot authorize itself: an empty source-to-evidence
    // range is circular even though it contains no unrelated paths.
    const selfAttestingCheckout = {
      ...checkout,
      evidence_head: checkout.head,
      evidence_changed_paths: ['apps/web/tests/bench/terminal-renderer.evidence.json']
    };
    expect(() => assertBenchmarkTrace(evidence, selfAttestingCheckout)).toThrow(/evidence-only/);

    const missingAnchor = { ...checkout, evidence_head: undefined };
    expect(() => assertBenchmarkTrace(evidence, missingAnchor)).toThrow(/evidence-only/);
    const ambiguousAnchor = { ...checkout, evidence_anchor_count: 2 };
    expect(() => assertBenchmarkTrace(evidence, ambiguousAnchor)).toThrow(/evidence-only/);
    const blobMismatch = { ...checkout, evidence_blob_matches: false };
    expect(() => assertBenchmarkTrace(evidence, blobMismatch)).toThrow(/evidence-only/);

    // Current HEAD contains unrelated later merges. The immutable evidence
    // anchor still validates, proving those merges do not require new samples.
    const currentHead = execFileSync('git', ['-C', resolve(process.cwd(), '../..'), 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    expect(checkout.evidence_head).not.toBe(currentHead);
    expect(() => assertBenchmarkTrace(evidence, checkout)).not.toThrow();
  }, 180_000);

  it('allows only the exact benchmark origin and browser-internal resources', () => {
    const benchmarkOrigin = 'http://127.0.0.1:4173';
    expect(isAllowedBenchmarkRequest(`${benchmarkOrigin}/assets/entry.js`, benchmarkOrigin)).toBe(true);
    expect(isAllowedBenchmarkRequest('data:text/javascript,export default 1', benchmarkOrigin)).toBe(true);
    expect(isAllowedBenchmarkRequest('blob:http://127.0.0.1:4173/id', benchmarkOrigin)).toBe(true);
    expect(isAllowedBenchmarkRequest('http://127.0.0.2:4173/other-loopback', benchmarkOrigin)).toBe(false);
    expect(isAllowedBenchmarkRequest('http://localhost:4173/other-loopback', benchmarkOrigin)).toBe(false);
    expect(isAllowedBenchmarkRequest('http://example.com/collect', benchmarkOrigin)).toBe(false);
    expect(isAllowedBenchmarkRequest('https://example.com/collect', benchmarkOrigin)).toBe(false);
    expect(isAllowedBenchmarkRequest('http://user:pass@127.0.0.1:4173/collect', benchmarkOrigin)).toBe(false);
    expect(isAllowedBenchmarkRequest('https://user:pass@example.com/collect', benchmarkOrigin)).toBe(false);
    expect(() => assertNoDisallowedNetworkRequests(0)).not.toThrow();
    expect(() => assertNoDisallowedNetworkRequests(1)).toThrow('disallowed network request');
  });
});
