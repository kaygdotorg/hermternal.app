import { CurrentSessionTerminalBridge } from "./current-session-terminal";
import {
  PtyTransportError,
  type PtyConnectionInput,
  type PtyConnectionState,
  type PtyTransport,
  type PtyTransportEvent,
} from "./pty-transport";

const REPETITIONS = 30;
const WARMUPS = 5;
const TIMEOUT_MS = 1;

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((nextResolve) => {
    resolve = nextResolve;
  });
  return { promise, resolve };
}

function createSyntheticTransport(
  connect: (input: PtyConnectionInput) => Promise<void>,
): { pty: PtyTransport; detachCalls: () => number } {
  let state: PtyConnectionState = {
    status: "closed",
    generation: 0,
    mode: "legacy",
    outputMayBeTruncated: false,
  };
  let detachCount = 0;
  const listeners = new Set<(event: PtyTransportEvent) => void>();
  const emitState = (): void => {
    for (const listener of listeners) listener({ type: "state", state });
  };
  return {
    pty: {
      get state() {
        return state;
      },
      async connect(input) {
        await connect(input);
        state = {
          status: "attached",
          generation: state.generation + 1,
          mode: "legacy",
          sessionId: input.sessionId,
          outputMayBeTruncated: false,
        };
        emitState();
      },
      async reconnect() {
        throw new PtyTransportError("legacy-reattach-prohibited");
      },
      sendInput() {},
      resize() {},
      detach() {
        detachCount += 1;
        state = { ...state, status: "detached" };
        emitState();
      },
      close() {
        state = { ...state, status: "closed" };
        emitState();
      },
      subscribe(listener) {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
    },
    detachCalls: () => detachCount,
  };
}

function percentile(samples: readonly number[], percentileValue: number): number {
  const ordered = [...samples].sort((left, right) => left - right);
  const position = (ordered.length - 1) * percentileValue;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower);
}

async function runOnce(): Promise<number> {
  const oldGate = deferred<void>();
  const old = createSyntheticTransport(async () => oldGate.promise);
  const successor = createSyntheticTransport(async () => {});
  const transports = [old.pty, successor.pty];
  const bridge = new CurrentSessionTerminalBridge({
    createTransport: () => {
      const transport = transports.shift();
      if (!transport) throw new Error("unexpected third synthetic transport");
      return transport;
    },
    replacementQuarantineTimeoutMs: TIMEOUT_MS,
  });
  const first = bridge.attach("benchmark-old", new AbortController().signal);
  await Promise.resolve();
  bridge.invalidateBindingForSession("benchmark-old", bridge.lifecycleIdentity);
  const startedAt = performance.now();
  const replacement = bridge.attach(
    "benchmark-successor",
    new AbortController().signal,
  );
  await replacement;
  const elapsed = performance.now() - startedAt;
  if (bridge.state.status !== "attached" || bridge.state.sessionId !== "benchmark-successor") {
    throw new Error("bounded replacement did not become interactive");
  }
  oldGate.resolve(undefined);
  await first.catch(() => undefined);
  if (old.detachCalls() !== 1 || successor.detachCalls() !== 0) {
    throw new Error("late old adapter cleanup was not exactly once and scoped");
  }
  return elapsed;
}

for (let index = 0; index < WARMUPS; index += 1) await runOnce();
const samples: number[] = [];
for (let index = 0; index < REPETITIONS; index += 1) samples.push(await runOnce());
console.log(
  JSON.stringify(
    {
      schema: "hermternal.current-session-terminal-bounded-replacement-benchmark.v1",
      operation: "replace an abort-insensitive pending adapter",
      metric: { name: "successor_interactive_wall_time", unit: "ms", clock: "performance.now" },
      method: "R-7 inclusive linear interpolation",
      provenance: {
        sourceRevision: process.env.GIT_SOURCE_REVISION ?? "unrecorded",
        command: "GIT_SOURCE_REVISION=<source-sha> bun src/lib/terminal/current-session-terminal-bounded-replacement.bench.ts",
        runtime: `Bun ${process.versions.bun ?? process.version}`,
        mode: "test",
      },
      repetitions: REPETITIONS,
      warmups: WARMUPS,
      exclusions: ["network", "Hermes", "credentials", "PTY bytes", "rendering", "tickets"],
      results: {
        min: Math.min(...samples),
        median: percentile(samples, 0.5),
        p95: percentile(samples, 0.95),
        successorInteractive: REPETITIONS,
        lateOldCleanups: REPETITIONS,
        duplicateOrSuccessorCleanups: 0,
      },
      configuration: { replacementQuarantineTimeoutMs: TIMEOUT_MS },
      threshold: null,
    },
    null,
    2,
  ),
);
