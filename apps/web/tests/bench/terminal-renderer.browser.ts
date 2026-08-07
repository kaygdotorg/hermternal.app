import { createTerminalRenderer } from '../../src/lib/terminal/renderer';
import {
  roundBenchmarkValue,
  summarizeBenchmarkSamples,
  type BenchmarkDistribution
} from './terminal-renderer.provenance';

const encoder = new TextEncoder();
const resultKey = '__hermternalTerminalRendererBenchmark';

type Distribution = BenchmarkDistribution;

type Samples = Readonly<{
  raw_samples: number[];
  distribution: Distribution;
}>;

type BrowserBenchmarkResult = Readonly<{
  schema: 'hermternal.web-terminal-renderer-browser-benchmark.v1';
  environment: Readonly<Record<string, string>>;
  /** A visible text mutation plus observer/paint fence proves glyph completion. */
  render_fence: 'visible-text-sentinel';
  samples: Readonly<Record<string, Samples>>;
  long_tasks_ms: number[];
  memory: Readonly<{
    supported: boolean;
    before_replay_bytes: number | null;
    after_replay_bytes: number | null;
    after_dispose_bytes: number | null;
    reason: string | null;
  }>;
  workload: Readonly<{
    replay_bytes: number;
    replay_chunks: number;
    mount_dispose_repetitions: number;
    initial_size: Readonly<{ cols: number; rows: number }>;
    scrollback_limit_bytes: number;
  }>;
}>;

type BenchmarkWindow = Window & {
  [resultKey]?: BrowserBenchmarkResult;
};

const browserWindow = window as BenchmarkWindow;


function waitForPaint(): Promise<void> {
  return new Promise((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  });
}

function memoryBytes(): number | null {
  const memory = (performance as Performance & {
    memory?: { usedJSHeapSize?: number };
  }).memory;
  return typeof memory?.usedJSHeapSize === 'number' ? memory.usedJSHeapSize : null;
}

function makeReplay(size: number): Uint8Array {
  // Keep the long-run stress fixture ASCII plus ANSI. Pinned Ghostty 0.3.2
  // has a grapheme-page integrity trap under repeated large Unicode replay;
  // renderer.test.ts covers Unicode, combining, and wide-grapheme behavior.
  const pattern = encoder.encode('\x1b[38;5;45mHermes renderer fixture\x1b[0m\r\n');
  const replay = new Uint8Array(size);
  for (let offset = 0; offset < replay.byteLength; offset += pattern.byteLength) {
    replay.set(pattern.subarray(0, Math.min(pattern.byteLength, replay.byteLength - offset)), offset);
  }
  return replay;
}

function waitForText(host: HTMLElement, text: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      observer.disconnect();
      reject(new Error(`terminal glyph did not appear: ${text}`));
    }, 5_000);
    const observer = new MutationObserver(() => {
      if (host.textContent?.includes(text)) {
        window.clearTimeout(timeout);
        observer.disconnect();
        resolve();
      }
    });
    observer.observe(host, { subtree: true, childList: true, characterData: true });
    if (host.textContent?.includes(text)) {
      window.clearTimeout(timeout);
      observer.disconnect();
      resolve();
    }
  });
}

async function waitForRendererIdle(renderer: ReturnType<typeof createTerminalRenderer>): Promise<void> {
  // whenIdle() is a call-drain fence only; production W-Term schedules its
  // actual DOM render on a timer/rAF. Callers must add a visible sentinel when
  // measuring glyph completion.
  await renderer.whenIdle();
  if (renderer.state !== 'ready' || renderer.error !== null) {
    throw new Error(`terminal renderer was not ready after workload: ${renderer.error?.code ?? renderer.state}`);
  }
}

async function waitForVisibleSentinel(
  host: HTMLElement,
  renderer: ReturnType<typeof createTerminalRenderer>,
  sentinel: string
): Promise<void> {
  // A full 1 MiB replay can fill the bounded cooperative queue before its
  // timer runs. Drain that reviewed buffer before admitting the fence marker so
  // the sentinel cannot turn valid replay into a false overflow failure.
  await waitForRendererIdle(renderer);
  renderer.write(encoder.encode(`\n${sentinel}`));
  await waitForRendererIdle(renderer);
  await waitForText(host, sentinel);
  await waitForPaint();
  await waitForRendererIdle(renderer);
}

async function run(): Promise<BrowserBenchmarkResult> {
  const host = document.createElement('div');
  host.style.cssText = 'position: fixed; left: -10000px; top: 0; width: 960px; height: 480px;';
  document.body.appendChild(host);
  const browserErrorKinds: string[] = [];
  const recordBrowserError = (event: ErrorEvent | PromiseRejectionEvent): void => {
    const error = event instanceof ErrorEvent ? event.error : event.reason;
    browserErrorKinds.push(error instanceof Error ? error.name : 'unhandled-browser-error');
  };
  window.addEventListener('error', recordBrowserError);
  window.addEventListener('unhandledrejection', recordBrowserError);
  const replay = makeReplay(1024 * 1024);
  const longTasks: number[] = [];
  const longTaskObserver = typeof PerformanceObserver === 'function'
    ? new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) longTasks.push(roundBenchmarkValue(entry.duration));
      })
    : null;
  try {
    longTaskObserver?.observe({ type: 'longtask', buffered: true });
  } catch {
    // Long-task entries are optional in Firefox/WebKit and test browsers.
  }

  const renderer = createTerminalRenderer({
    initialSize: { cols: 80, rows: 24 },
    scrollbackLimitBytes: 64 * 1024,
    confirmPaste: () => true
  });
  const samples: Record<string, Samples> = {};
  let workloadPhase = 'initialization';

  try {
    const coldMountSamples: number[] = [];
  const firstGlyphSamples: number[] = [];
  const sustainedOutputSamples: number[] = [];
  const resizeSettlingSamples: number[] = [];
  const replaySamples: number[] = [];
  const mountDisposeSamples: number[] = [];

  for (let index = 0; index < 5; index += 1) {
    workloadPhase = `cold-initialization-${index}`;
    renderer.dispose();
    const started = performance.now();
    await renderer.mount(host);
    await waitForRendererIdle(renderer);
    coldMountSamples.push(performance.now() - started);
    const firstGlyphStarted = performance.now();
    renderer.write(encoder.encode(`cold-glyph-${index}`));
    await waitForText(host, `cold-glyph-${index}`);
    await waitForRendererIdle(renderer);
    firstGlyphSamples.push(performance.now() - firstGlyphStarted);
  }

  for (let index = 0; index < 10; index += 1) {
    workloadPhase = `sustained-output-${index}`;
    const started = performance.now();
    renderer.write(replay.subarray(0, 64 * 1024));
    await waitForVisibleSentinel(host, renderer, `sustained-fence-${index}`);
    sustainedOutputSamples.push(performance.now() - started);
  }

  const beforeReplay = memoryBytes();
  for (let index = 0; index < 5; index += 1) {
    workloadPhase = `replay-1-mib-${index}`;
    const started = performance.now();
    for (let offset = 0; offset < replay.byteLength; offset += 64 * 1024) {
      renderer.write(replay.subarray(offset, Math.min(replay.byteLength, offset + 64 * 1024)));
    }
    await waitForVisibleSentinel(host, renderer, `replay-fence-${index}`);
    replaySamples.push(performance.now() - started);
  }
  const afterReplay = memoryBytes();

  for (let index = 0; index < 10; index += 1) {
    workloadPhase = `resize-settling-${index}`;
    const started = performance.now();
    renderer.resize(100 + (index % 3), 28 + (index % 2));
    await waitForRendererIdle(renderer);
    await waitForPaint();
    await waitForRendererIdle(renderer);
    resizeSettlingSamples.push(performance.now() - started);
  }

  for (let index = 0; index < 10; index += 1) {
    workloadPhase = `repeated-mount-dispose-${index}`;
    const started = performance.now();
    renderer.dispose();
    await renderer.mount(host);
    await waitForRendererIdle(renderer);
    mountDisposeSamples.push(performance.now() - started);
  }
  renderer.dispose();
  await waitForPaint();
  const afterDispose = memoryBytes();

  samples.cold_initialization = summarizeBenchmarkSamples(coldMountSamples);
  samples.first_byte_to_first_glyph = summarizeBenchmarkSamples(firstGlyphSamples);
  samples.sustained_output = summarizeBenchmarkSamples(sustainedOutputSamples);
  samples.resize_settling = summarizeBenchmarkSamples(resizeSettlingSamples);
  samples.replay_1_mib = summarizeBenchmarkSamples(replaySamples);
  samples.repeated_mount_dispose = summarizeBenchmarkSamples(mountDisposeSamples);

  const result: BrowserBenchmarkResult = {
    schema: 'hermternal.web-terminal-renderer-browser-benchmark.v1',
    environment: {
      user_agent: navigator.userAgent,
      platform: navigator.platform,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      device_pixel_ratio: String(window.devicePixelRatio),
      cross_origin_isolated: String(window.crossOriginIsolated)
    },
    render_fence: 'visible-text-sentinel',
    samples,
    long_tasks_ms: longTasks,
    memory: {
      supported: beforeReplay !== null || afterReplay !== null || afterDispose !== null,
      before_replay_bytes: beforeReplay,
      after_replay_bytes: afterReplay,
      after_dispose_bytes: afterDispose,
      reason: beforeReplay === null && afterReplay === null && afterDispose === null
        ? 'performance.memory is unavailable in this browser'
        : null
    },
    workload: {
      replay_bytes: replay.byteLength,
      replay_chunks: replay.byteLength / (64 * 1024),
      mount_dispose_repetitions: mountDisposeSamples.length,
      initial_size: { cols: 80, rows: 24 },
      scrollback_limit_bytes: 64 * 1024
    }
  };
    browserWindow[resultKey] = result;
    return result;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    const browserErrors = browserErrorKinds.length > 0
      ? `; browser errors: ${browserErrorKinds.join(',')}`
      : '';
    throw new Error(`terminal renderer workload failed during ${workloadPhase}: ${message}${browserErrors}`);
  } finally {
    longTaskObserver?.disconnect();
    window.removeEventListener('error', recordBrowserError);
    window.removeEventListener('unhandledrejection', recordBrowserError);
    renderer.dispose();
    host.remove();
  }
}

void run().catch((error: unknown) => {
  browserWindow[resultKey] = {
    schema: 'hermternal.web-terminal-renderer-browser-benchmark.v1',
    environment: { error: error instanceof Error ? error.message : 'benchmark failed' },
    render_fence: 'visible-text-sentinel',
    samples: {},
    long_tasks_ms: [],
    memory: {
      supported: false,
      before_replay_bytes: null,
      after_replay_bytes: null,
      after_dispose_bytes: null,
      reason: 'benchmark failed'
    },
    workload: {
      replay_bytes: 1024 * 1024,
      replay_chunks: 16,
      mount_dispose_repetitions: 10,
      initial_size: { cols: 80, rows: 24 },
      scrollback_limit_bytes: 64 * 1024
    }
  };
});
