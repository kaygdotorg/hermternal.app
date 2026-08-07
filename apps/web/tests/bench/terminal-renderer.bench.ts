import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, promises as fs } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { dirname, extname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from '@playwright/test';
import { build } from 'vite';
import {
  assertCleanExecutionInputs,
  assertCommitMatchesHead,
  validateFullCommit
} from './terminal-renderer.provenance';

type Distribution = Readonly<{
  min: number;
  p50: number;
  p95: number;
  p99: number;
  max: number;
  mean: number;
}>;

type Samples = Readonly<{
  raw_samples: number[];
  distribution: Distribution;
}>;

type BrowserBenchmarkResult = Readonly<{
  schema: string;
  environment: Readonly<Record<string, string>>;
  samples: Readonly<Record<string, Samples>>;
  long_tasks_ms: number[];
  memory: Readonly<{
    supported: boolean;
    before_replay_bytes: number | null;
    after_replay_bytes: number | null;
    after_dispose_bytes: number | null;
    reason: string | null;
  }>;
  workload: Readonly<Record<string, number | Readonly<Record<string, number>>>>;
}>;

type Trace = Readonly<{
  schema: 'hermternal.web-terminal-renderer-benchmark.v1';
  revision: Readonly<{
    source_commit: string;
    browser_entry: string;
    renderer_module: string;
    execution_inputs: ReadonlyArray<Readonly<{ path: string; bytes: number; sha256: string }>>;
  }>;
  build: Readonly<{
    command: string;
    files: ReadonlyArray<Readonly<{ path: string; bytes: number; sha256: string }>>;
    entry_bytes: number;
    lazy_chunk_bytes: number;
    wasm_bytes: number;
    css_bytes: number;
  }>;
  browser: BrowserBenchmarkResult;
  method: Readonly<{
    browser: string;
    warmups: number;
    repetitions: number;
    percentile: 'inclusive-linear-r7';
    quantiles: [0.5, 0.95, 0.99];
    rounding: 'decimal-half-even-to-three-places';
  }>;
  redaction: Readonly<Record<string, boolean>>;
  threshold: null;
  budget: null;
}>;

const sourceDirectory = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(sourceDirectory, '../..');
const repoRoot = resolve(webRoot, '../..');
const browserEntry = resolve(sourceDirectory, 'terminal-renderer.browser.ts');
const rendererModule = resolve(webRoot, 'src/lib/terminal/renderer.ts');
const terminalStyles = resolve(webRoot, 'src/lib/terminal/terminal.css');
const provenanceModule = resolve(sourceDirectory, 'terminal-renderer.provenance.ts');
const outputDirectory = resolve(webRoot, '../../.terminal-renderer-benchmark-build');
const executionCriticalPaths = [
  'apps/web/src/lib/terminal/renderer.ts',
  'apps/web/src/lib/terminal/terminal.css',
  'apps/web/tests/bench/terminal-renderer.browser.ts',
  'apps/web/tests/bench/terminal-renderer.bench.ts',
  'apps/web/tests/bench/terminal-renderer.provenance.ts'
] as const;
const repetitions = 5;
const warmups = 0;

const CONTENT_TYPES: Record<string, string> = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm'
};

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function gitText(...args: string[]): string {
  return execFileSync('git', ['-C', repoRoot, ...args], { encoding: 'utf8' }).trim();
}

async function executionInputs(): Promise<ReadonlyArray<Readonly<{ path: string; bytes: number; sha256: string }>>> {
  const absolutePaths = [rendererModule, terminalStyles, browserEntry, fileURLToPath(import.meta.url), provenanceModule];
  const inputs = [];
  for (const absolutePath of absolutePaths) {
    const bytes = await fs.readFile(absolutePath);
    inputs.push({ path: relative(repoRoot, absolutePath), bytes: bytes.byteLength, sha256: sha256(bytes) });
  }
  return inputs;
}

function html(entryFile: string): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hermternal terminal benchmark</title></head><body><main id="benchmark" aria-label="Terminal benchmark"></main><script type="module" src="/${entryFile}"></script></body></html>`;
}

function pathnameOf(request: IncomingMessage): string {
  const raw = request.url ?? '/';
  try {
    return decodeURIComponent(new URL(raw, 'http://127.0.0.1').pathname);
  } catch {
    return '/__invalid__';
  }
}

async function serveFile(
  request: IncomingMessage,
  response: ServerResponse,
  root: string,
  entryFile: string
): Promise<void> {
  const pathname = pathnameOf(request);
  if (pathname === '/') {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    response.end(html(entryFile));
    return;
  }
  const relative = pathname.replace(/^\/+/, '');
  const file = resolve(root, relative);
  if (!file.startsWith(`${root}/`)) {
    response.writeHead(404);
    response.end();
    return;
  }
  try {
    const stat = await fs.stat(file);
    if (!stat.isFile()) throw new Error('not a file');
    response.writeHead(200, {
      'content-type': CONTENT_TYPES[extname(file)] ?? 'application/octet-stream',
      'cache-control': 'no-store',
      'content-length': String(stat.size)
    });
    createReadStream(file).pipe(response);
  } catch {
    response.writeHead(404);
    response.end();
  }
}

async function listen(root: string, entryFile: string): Promise<{
  origin: string;
  close: () => Promise<void>;
}> {
  const server = createServer((request, response) => {
    void serveFile(request, response, root, entryFile);
  });
  await new Promise<void>((resolveListen, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolveListen());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('benchmark server did not expose a port');
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()))
  };
}

async function filesIn(root: string, relative = ''): Promise<string[]> {
  const directory = join(root, relative);
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const child = join(relative, entry.name);
    if (entry.isDirectory()) files.push(...await filesIn(root, child));
    else files.push(child);
  }
  return files;
}

async function buildRenderer(): Promise<Readonly<{
  entryFile: string;
  files: ReadonlyArray<Readonly<{ path: string; bytes: number; sha256: string }>>;
}>> {
  await fs.rm(outputDirectory, { recursive: true, force: true });
  await build({
    root: webRoot,
    configFile: false,
    logLevel: 'error',
    build: {
      outDir: outputDirectory,
      emptyOutDir: true,
      assetsInlineLimit: 0,
      cssCodeSplit: true,
      minify: true,
      rollupOptions: {
        input: browserEntry,
        output: {
          entryFileNames: 'entry.js',
          chunkFileNames: 'chunks/[name]-[hash].js',
          assetFileNames: 'assets/[name]-[hash][extname]'
        }
      }
    }
  });
  const filePaths = await filesIn(outputDirectory);
  const files = [];
  for (const relative of filePaths) {
    const bytes = await fs.readFile(join(outputDirectory, relative));
    files.push({ path: relative, bytes: bytes.byteLength, sha256: sha256(bytes) });
  }
  files.sort((left, right) => left.path.localeCompare(right.path));
  return {
    entryFile: 'entry.js',
    files
  };
}

function sumFiles(files: ReadonlyArray<Readonly<{ path: string; bytes: number }>>, predicate: (path: string) => boolean): number {
  return files.reduce((total, file) => total + (predicate(file.path) ? file.bytes : 0), 0);
}

async function run(): Promise<Trace> {
  const sourceCommit = validateFullCommit(process.env.GIT_COMMIT);
  assertCommitMatchesHead(sourceCommit, gitText('rev-parse', 'HEAD'));
  const status = execFileSync(
    'git',
    ['-C', repoRoot, 'status', '--porcelain=v1', '--untracked-files=all', '--', ...executionCriticalPaths],
    { encoding: 'utf8' }
  );
  assertCleanExecutionInputs(status);
  const inputs = await executionInputs();
  const buildResult = await buildRenderer();
  const server = await listen(outputDirectory, buildResult.entryFile);
  const browser = await chromium.launch({
    headless: true,
    args: ['--enable-precise-memory-info']
  });
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  try {
    await page.goto(server.origin, { waitUntil: 'networkidle' });
    await page.waitForFunction(() => {
      const value = (window as Window & { __hermternalTerminalRendererBenchmark?: BrowserBenchmarkResult })
        .__hermternalTerminalRendererBenchmark;
      return Boolean(value?.samples && Object.keys(value.samples).length > 0);
    }, undefined, { timeout: 120_000 });
    const browserResult = await page.evaluate(() => {
      const value = (window as Window & { __hermternalTerminalRendererBenchmark?: BrowserBenchmarkResult })
        .__hermternalTerminalRendererBenchmark;
      if (!value) throw new Error('browser benchmark did not publish a result');
      return value;
    });
    const files = buildResult.files;
    return {
      schema: 'hermternal.web-terminal-renderer-benchmark.v1',
      revision: {
        source_commit: sourceCommit,
        browser_entry: 'apps/web/tests/bench/terminal-renderer.browser.ts',
        renderer_module: 'apps/web/src/lib/terminal/renderer.ts',
        execution_inputs: inputs
      },
      build: {
        command: 'vite build --configFile false --minify',
        files,
        entry_bytes: sumFiles(files, (path) => path === buildResult.entryFile),
        lazy_chunk_bytes: sumFiles(files, (path) => path.startsWith('chunks/')),
        wasm_bytes: sumFiles(files, (path) => path.endsWith('.wasm')),
        css_bytes: sumFiles(files, (path) => path.endsWith('.css'))
      },
      browser: browserResult,
      method: {
        browser: 'Playwright Chromium headless',
        warmups,
        repetitions,
        percentile: 'inclusive-linear-r7',
        quantiles: [0.5, 0.95, 0.99],
        rounding: 'decimal-half-even-to-three-places'
      },
      redaction: {
        synthetic_only: true,
        network_access: false,
        provider_access: false,
        credentials: false,
        cookies: false,
        terminal_bytes_logged: false,
        hostnames: false,
        user_data: false
      },
      threshold: null,
      budget: null
    };
  } finally {
    await page.close();
    await browser.close();
    await server.close();
    await fs.rm(outputDirectory, { recursive: true, force: true });
  }
}

run()
  .then((trace) => {
    process.stdout.write(`${JSON.stringify(trace, null, 2)}\n`);
  })
  .catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
