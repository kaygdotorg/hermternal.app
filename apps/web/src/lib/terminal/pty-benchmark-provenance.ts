import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpus, release } from "node:os";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export interface PtyBenchmarkBlob {
  readonly path: string;
  readonly gitBlobSha: string;
  readonly sha256: string;
}

export const PTY_BENCHMARK_SOURCES = {
  reconnect: {
    path: "apps/web/src/lib/terminal/pty-reconnect-supersession.bench.ts",
    command: "bun src/lib/terminal/pty-reconnect-supersession.bench.ts",
  },
  connecting: {
    path: "apps/web/src/lib/terminal/pty-connecting-ownership.bench.ts",
    command: "bun src/lib/terminal/pty-connecting-ownership.bench.ts",
  },
} as const;

/** The helper is execution-critical: changing it changes the evidence contract. */
export const PTY_BENCHMARK_PROVENANCE_SOURCE =
  "apps/web/src/lib/terminal/pty-benchmark-provenance.ts";

/**
 * Values reviewed for the checked-in synthetic evidence. Keeping this profile
 * in code prevents a mutable artifact from choosing the runtime or host that
 * supposedly produced it; a different harness requires an explicit review.
 */
export const REVIEWED_PTY_BENCHMARK_ENVIRONMENT = {
  runtime: {
    bun: "1.3.14",
    node: "24.3.0",
    hostNode: "26.7.0",
    packageManager: "bun@1.3.14",
    declaredBun: "1.3.14",
    declaredNode: "26.7.0",
  },
  os: {
    platform: "darwin",
    release: "25.5.0",
    architecture: "arm64",
    cpuModel: "Apple M2 Max",
    cpuCount: 12,
  },
} as const;

export interface PtyBenchmarkProvenance {
  readonly sourceRevision: string;
  readonly generationCommit: string;
  readonly sourceTree: string;
  readonly sourceBlobs: readonly PtyBenchmarkBlob[];
  readonly cleanCheckout: true;
  readonly detachedHead: true;
  readonly command: string;
  readonly sourceCheckout: string;
  readonly runtime: {
    /** Bun's embedded Node-compatible runtime used by the benchmark process. */
    readonly node: string;
    /** Host Node executable checked against package.json engines.node. */
    readonly hostNode: string;
    readonly bun: string;
    readonly packageManager: string;
    readonly declaredBun: string;
    readonly declaredNode: string;
  };
  readonly os: {
    readonly platform: string;
    readonly release: string;
    readonly architecture: string;
    readonly cpuModel: string;
    readonly cpuCount: number;
  };
}

function git(args: readonly string[]): string {
  try {
    return execFileSync("git", [...args], { encoding: "utf8" }).trim();
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new Error(`git ${args.join(" ")} failed${detail}`);
  }
}

function sha256Bytes(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function fileSha256(path: string): string {
  return sha256Bytes(readFileSync(path));
}

interface PackageRuntime {
  readonly packageManager: string;
  readonly declaredBun: string;
  readonly declaredNode: string;
}

function packageRuntime(): PackageRuntime {
  try {
    const packageJson = JSON.parse(readFileSync("package.json", "utf8")) as {
      readonly packageManager?: unknown;
      readonly engines?: { readonly bun?: unknown; readonly node?: unknown };
    };
    if (
      typeof packageJson.packageManager !== "string" ||
      typeof packageJson.engines?.bun !== "string" ||
      typeof packageJson.engines?.node !== "string"
    ) {
      throw new Error("package runtime metadata is incomplete");
    }
    return {
      packageManager: packageJson.packageManager,
      declaredBun: packageJson.engines.bun,
      declaredNode: packageJson.engines.node,
    };
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new Error(`PTY benchmark package runtime metadata is invalid${detail}`);
  }
}

function hostNodeVersion(): string {
  try {
    const version = execFileSync("node", ["--version"], { encoding: "utf8" }).trim();
    if (!/^v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/u.test(version)) {
      throw new Error(`unexpected node version ${version}`);
    }
    return version.slice(1);
  } catch (error) {
    const detail = error instanceof Error ? `: ${error.message}` : "";
    throw new Error(`PTY benchmark host Node version could not be captured${detail}`);
  }
}

function cleanCheckout(): { readonly cleanCheckout: true; readonly detachedHead: true } {
  const status = git(["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status !== "") {
    throw new Error(
      "PTY benchmark requires a clean checkout; run it from the pinned source commit before redirecting evidence",
    );
  }
  if (git(["rev-parse", "--abbrev-ref", "HEAD"]) !== "HEAD") {
    throw new Error(
      "PTY benchmark requires a detached clean checkout; use git switch --detach <sourceRevision>",
    );
  }
  return { cleanCheckout: true, detachedHead: true };
}

function validateBenchmarkSource(benchmarkPath: string, command: string): void {
  const expected = Object.values(PTY_BENCHMARK_SOURCES).find(
    (source) => source.path === benchmarkPath,
  );
  if (!expected || expected.command !== command) {
    throw new Error(
      `PTY benchmark source path and command are not a reviewed pair: ${benchmarkPath} / ${command}`,
    );
  }
}

function validateRevision(revision: string): void {
  if (!/^[0-9a-f]{40}$/u.test(revision)) {
    throw new Error("PTY benchmark source revision must be a full 40-hex commit SHA");
  }
  git(["cat-file", "-e", `${revision}^{commit}`]);
}

export function capturePtyBenchmarkProvenance(
  benchmarkPath: string,
  command: string,
): PtyBenchmarkProvenance {
  validateBenchmarkSource(benchmarkPath, command);
  const sourceRevision = git(["rev-parse", "HEAD"]);
  validateRevision(sourceRevision);
  const declaredRevision = process.env.GIT_SOURCE_REVISION;
  if (declaredRevision !== undefined && declaredRevision !== sourceRevision) {
    throw new Error(
      "GIT_SOURCE_REVISION must equal the actual clean checkout HEAD; arbitrary evidence revisions are rejected",
    );
  }

  const repoRoot = git(["rev-parse", "--show-toplevel"]);
  const paths = [
    benchmarkPath,
    "apps/web/src/lib/terminal/pty-transport.ts",
    "apps/web/package.json",
    "apps/web/bun.lock",
    PTY_BENCHMARK_PROVENANCE_SOURCE,
  ];
  const sourceBlobs = paths.map((path) => ({
    path,
    gitBlobSha: git(["rev-parse", `${sourceRevision}:${path}`]),
    sha256: fileSha256(join(repoRoot, path)),
  }));
  const packageMetadata = packageRuntime();
  const bunVersion = process.versions.bun ?? "";
  if (
    packageMetadata.packageManager !== `bun@${bunVersion}` ||
    packageMetadata.declaredBun !== bunVersion
  ) {
    throw new Error(
      `PTY benchmark Bun runtime ${bunVersion} does not match package runtime ${packageMetadata.packageManager} / ${packageMetadata.declaredBun}`,
    );
  }
  const hostNode = hostNodeVersion();
  if (hostNode !== packageMetadata.declaredNode) {
    throw new Error(
      `PTY benchmark host Node ${hostNode} does not match package.json engines.node ${packageMetadata.declaredNode}`,
    );
  }
  const cpu = cpus();
  const environment = {
    runtime: {
      bun: bunVersion,
      node: process.versions.node ?? "",
      hostNode,
      packageManager: packageMetadata.packageManager,
      declaredBun: packageMetadata.declaredBun,
      declaredNode: packageMetadata.declaredNode,
    },
    os: {
      platform: process.platform,
      release: release(),
      architecture: process.arch,
      cpuModel: cpu[0]?.model ?? "unknown",
      cpuCount: cpu.length,
    },
  } as const;
  if (
    environment.runtime.bun !== REVIEWED_PTY_BENCHMARK_ENVIRONMENT.runtime.bun ||
    environment.runtime.node !== REVIEWED_PTY_BENCHMARK_ENVIRONMENT.runtime.node ||
    environment.runtime.hostNode !== REVIEWED_PTY_BENCHMARK_ENVIRONMENT.runtime.hostNode ||
    environment.runtime.packageManager !==
      REVIEWED_PTY_BENCHMARK_ENVIRONMENT.runtime.packageManager ||
    environment.runtime.declaredBun !==
      REVIEWED_PTY_BENCHMARK_ENVIRONMENT.runtime.declaredBun ||
    environment.runtime.declaredNode !==
      REVIEWED_PTY_BENCHMARK_ENVIRONMENT.runtime.declaredNode ||
    environment.os.platform !== REVIEWED_PTY_BENCHMARK_ENVIRONMENT.os.platform ||
    environment.os.release !== REVIEWED_PTY_BENCHMARK_ENVIRONMENT.os.release ||
    environment.os.architecture !==
      REVIEWED_PTY_BENCHMARK_ENVIRONMENT.os.architecture ||
    environment.os.cpuModel !== REVIEWED_PTY_BENCHMARK_ENVIRONMENT.os.cpuModel ||
    environment.os.cpuCount !== REVIEWED_PTY_BENCHMARK_ENVIRONMENT.os.cpuCount
  ) {
    throw new Error(
      "PTY benchmark environment does not match the reviewed synthetic harness",
    );
  }
  const checkout = cleanCheckout();
  return {
    sourceRevision,
    generationCommit: sourceRevision,
    sourceTree: git(["rev-parse", `${sourceRevision}^{tree}`]),
    sourceBlobs,
    ...checkout,
    command,
    sourceCheckout: "git switch --detach <sourceRevision>",
    runtime: environment.runtime,
    os: environment.os,
  };
}

export function percentile(sorted: readonly number[], quantile: number): number {
  if (sorted.length === 0) throw new Error("cannot calculate a percentile without samples");
  const position = (sorted.length - 1) * quantile;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower]!;
  const fraction = position - lower;
  return sorted[lower]! + (sorted[upper]! - sorted[lower]!) * fraction;
}

export function roundSample(value: number): number {
  return Number(value.toFixed(6));
}

export function distribution(samples: readonly number[]): {
  readonly min: number;
  readonly median: number;
  readonly p95: number;
} {
  const sorted = samples.toSorted((left, right) => left - right);
  return {
    min: roundSample(sorted[0]!),
    median: roundSample(percentile(sorted, 0.5)),
    p95: roundSample(percentile(sorted, 0.95)),
  };
}
