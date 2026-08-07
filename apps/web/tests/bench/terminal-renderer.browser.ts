import { createTerminalRenderer } from '../../src/lib/terminal/renderer';

const encoder = new TextEncoder();
const resultKey = '__hermternalTerminalRendererBenchmark';

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
  schema: 'hermternal.web-terminal-renderer-browser-benchmark.v1';
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

function percentile(sorted: readonly number[], quantile: number): number {
  const position = (sorted.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower] ?? 0;
  const low = sorted[lower] ?? 0;
  const high = sorted[upper] ?? low;
  return low + (high - low) * (position - lower);
}

function round(value: number): number {
  const scale = 1000;
  const scaled = value * scale;
  const sign = scaled < 0 ? -1 : 1;
  const magnitude = Math.abs(scaled);
  const lower = Math.floor(magnitude);
  const fraction = magnitude - lower;
  const epsilon = Number.EPSILON * Math.max(1, magnitude) * 8;
  const roundedInteger = fraction > 0.5 + epsilon
    ? lower + 1
    : fraction < 0.5 - epsilon
      ? lower
      : lower % 2 === 0 ? lower : lower + 1;
  return sign * roundedInteger / scale;
}

function summarize(rawSamples: number[]): Samples {
  const publishedSamples = rawSamples.map(round);
  const sorted = [...publishedSamples].sort((left, right) => left - right);
  const mean = publishedSamples.reduce((total, value) => total + value, 0) / Math.max(1, publishedSamples.length);
  return {
    raw_samples: publishedSamples,
    distribution: {
      min: sorted[0] ?? 0,
      p50: round(percentile(sorted, 0.5)),
      p95: round(percentile(sorted, 0.95)),
      p99: round(percentile(sorted, 0.99)),
      max: sorted.at(-1) ?? 0,
      mean: round(mean)
    }
  };
}

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
  const pattern = encoder.encode('\x1b[38;5;45mHermes renderer fixture\x1b[0m — 界🙂 é\r\n');
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

async function run(): Promise<BrowserBenchmarkResult> {
  const host = document.createElement('div');
  host.style.cssText = 'position: fixed; left: -10000px; top: 0; width: 960px; height: 480px;';
  document.body.appendChild(host);
  const replay = makeReplay(1024 * 1024);
  const longTasks: number[] = [];
  const longTaskObserver = typeof PerformanceObserver === 'function'
    ? new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) longTasks.push(round(entry.duration));
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

  try {
    const coldMountSamples: number[] = [];
  const firstGlyphSamples: number[] = [];
  const sustainedOutputSamples: number[] = [];
  const resizeSettlingSamples: number[] = [];
  const replaySamples: number[] = [];
  const mountDisposeSamples: number[] = [];

  for (let index = 0; index < 5; index += 1) {
    renderer.dispose();
    const started = performance.now();
    await renderer.mount(host);
    coldMountSamples.push(performance.now() - started);
    const firstGlyphStarted = performance.now();
    renderer.write(encoder.encode(`cold-glyph-${index}`));
    await waitForText(host, `cold-glyph-${index}`);
    firstGlyphSamples.push(performance.now() - firstGlyphStarted);
  }

  for (let index = 0; index < 10; index += 1) {
    const started = performance.now();
    renderer.write(replay.subarray(0, 64 * 1024));
    await waitForPaint();
    sustainedOutputSamples.push(performance.now() - started);
  }

  const beforeReplay = memoryBytes();
  for (let index = 0; index < 5; index += 1) {
    const started = performance.now();
    for (let offset = 0; offset < replay.byteLength; offset += 64 * 1024) {
      renderer.write(replay.subarray(offset, Math.min(replay.byteLength, offset + 64 * 1024)));
    }
    await waitForPaint();
    replaySamples.push(performance.now() - started);
  }
  const afterReplay = memoryBytes();

  for (let index = 0; index < 10; index += 1) {
    const started = performance.now();
    renderer.resize(100 + (index % 3), 28 + (index % 2));
    await waitForPaint();
    resizeSettlingSamples.push(performance.now() - started);
  }

  for (let index = 0; index < 10; index += 1) {
    const started = performance.now();
    renderer.dispose();
    await renderer.mount(host);
    mountDisposeSamples.push(performance.now() - started);
  }
  renderer.dispose();
  await waitForPaint();
  const afterDispose = memoryBytes();

  samples.cold_initialization = summarize(coldMountSamples);
  samples.first_byte_to_first_glyph = summarize(firstGlyphSamples);
  samples.sustained_output = summarize(sustainedOutputSamples);
  samples.resize_settling = summarize(resizeSettlingSamples);
  samples.replay_1_mib = summarize(replaySamples);
  samples.repeated_mount_dispose = summarize(mountDisposeSamples);

  const result: BrowserBenchmarkResult = {
    schema: 'hermternal.web-terminal-renderer-browser-benchmark.v1',
    environment: {
      user_agent: navigator.userAgent,
      platform: navigator.platform,
      viewport: `${window.innerWidth}x${window.innerHeight}`,
      device_pixel_ratio: String(window.devicePixelRatio),
      cross_origin_isolated: String(window.crossOriginIsolated)
    },
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
  } finally {
    longTaskObserver?.disconnect();
    renderer.dispose();
    host.remove();
  }
}

void run().catch((error: unknown) => {
  browserWindow[resultKey] = {
    schema: 'hermternal.web-terminal-renderer-browser-benchmark.v1',
    environment: { error: error instanceof Error ? error.message : 'benchmark failed' },
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
