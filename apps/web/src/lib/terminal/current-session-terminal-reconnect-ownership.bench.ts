import { CurrentSessionTerminalBridge } from "./current-session-terminal";
import type {
  PtyConnectionInput,
  PtyConnectionState,
  PtyTransport,
  PtyTransportEvent,
} from "./pty-transport";

const REPETITIONS = 30;
const WARMUPS = 5;

function percentile(sorted: readonly number[], quantile: number): number {
  const position = (sorted.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower]!;
  return (
    sorted[lower]! + (sorted[upper]! - sorted[lower]!) * (position - lower)
  );
}

function createSyntheticTransport(): {
  readonly transport: PtyTransport;
  readonly detachCalls: () => number;
} {
  let state: PtyConnectionState = {
    status: "closed",
    generation: 0,
    mode: "legacy",
    outputMayBeTruncated: false,
  };
  let detachCalls = 0;
  const listeners = new Set<(event: PtyTransportEvent) => void>();
  const publish = (): void => {
    for (const listener of listeners) listener({ type: "state", state });
  };
  const connect = async (input: PtyConnectionInput): Promise<void> => {
    state = {
      status: "attached",
      generation: state.generation + 1,
      mode: input.attach ? "attach" : "legacy",
      sessionId: input.sessionId,
      ...(input.attach && input.processIdentity
        ? { processIdentity: input.processIdentity }
        : {}),
      outputMayBeTruncated: false,
    };
    publish();
  };
  const transport: PtyTransport = {
    get state() {
      return state;
    },
    connect,
    reconnect: async () => {
      state = {
        ...state,
        status: "attached",
        generation: state.generation + 1,
      };
      publish();
    },
    sendInput: () => {},
    resize: () => {},
    detach: () => {
      detachCalls += 1;
      state = { ...state, status: "detached" };
      publish();
    },
    close: () => {},
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
  return { transport, detachCalls: () => detachCalls };
}

async function runOnce(): Promise<number> {
  const synthetic = createSyntheticTransport();
  const bridge = new CurrentSessionTerminalBridge({
    createTransport: () => synthetic.transport,
    createAttachment: () => ({
      attach: "benchmark-attach",
      processIdentity: "benchmark-process",
    }),
  });
  const binding = await bridge.attach(
    "benchmark-session",
    new AbortController().signal,
  );
  binding.invalidate();
  await bridge.reconnect();
  if (
    bridge.lifecycleIdentity.binding === undefined ||
    bridge.state.status !== "attached"
  ) {
    throw new Error("direct reconnect did not establish a bridge binding");
  }
  bridge.detach();
  const detachedState = bridge.state;
  if (synthetic.detachCalls() !== 2 || detachedState.status !== "detached") {
    throw new Error(
      "direct reconnect did not receive exactly one later detach cleanup",
    );
  }
  return synthetic.detachCalls();
}

for (let index = 0; index < WARMUPS; index += 1) await runOnce();
const samples: number[] = [];
for (let index = 0; index < REPETITIONS; index += 1) {
  const started = performance.now();
  await runOnce();
  samples.push(performance.now() - started);
}
const sorted = samples.toSorted((left, right) => left - right);
console.log(
  JSON.stringify(
    {
      schema:
        "hermternal.current-session-terminal-reconnect-ownership-benchmark.v1",
      operation: "direct reconnect after binding loss then detach",
      metric: {
        name: "reconnect_owner_settle_wall_time",
        unit: "ms",
        clock: "performance.now",
      },
      method: "R-7 inclusive linear interpolation",
      provenance: {
        sourceRevision: process.env.GIT_SOURCE_REVISION ?? "unrecorded",
        command:
          "GIT_SOURCE_REVISION=<source-sha> bun src/lib/terminal/current-session-terminal-reconnect-ownership.bench.ts",
        exitStatus: 0,
        runtime: `Bun ${process.versions.bun ?? "unknown"}`,
        platform: process.platform,
        architecture: process.arch,
        mode: "test",
      },
      repetitions: REPETITIONS,
      warmups: WARMUPS,
      exclusions: [
        "network",
        "Hermes",
        "credentials",
        "PTY bytes",
        "rendering",
      ],
      results: {
        min: Number(sorted[0]!.toFixed(6)),
        median: Number(percentile(sorted, 0.5).toFixed(6)),
        p95: Number(percentile(sorted, 0.95).toFixed(6)),
        recoveredBindings: REPETITIONS,
        directReconnectDetachCleanups: REPETITIONS,
        duplicateDetachCleanups: 0,
      },
      threshold: null,
    },
    null,
    2,
  ),
);
