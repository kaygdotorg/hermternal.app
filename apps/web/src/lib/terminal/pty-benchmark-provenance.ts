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

export interface PtyBenchmarkProvenance {
  readonly sourceRevision: string;
  readonly generationCommit: string;
  readonly sourceTree: string;
  readonly sourceBlobs: readonly PtyBenchmarkBlob[];
  readonly cleanCheckout: true;
  readonly command: string;
  readonly sourceCheckout: string;
  readonly runtime: {
    readonly bun: string;
    readonly node: string;
    readonly packageManager: string;
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

function packageManagerVersion(): string {
  try {
    const packageJson = JSON.parse(readFileSync("package.json", "utf8")) as {
      readonly packageManager?: unknown;
    };
    return typeof packageJson.packageManager === "string"
      ? packageJson.packageManager
      : "unknown";
  } catch {
    return "unknown";
  }
}

function cleanCheckout(): true {
  const status = git(["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status !== "") {
    throw new Error(
      "PTY benchmark requires a clean checkout; run it from the pinned source commit before redirecting evidence",
    );
  }
  return true;
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
  const sourceRevision = git(["rev-parse", "HEAD"]);
  validateRevision(sourceRevision);
  const declaredRevision = process.env.GIT_SOURCE_REVISION;
  if (declaredRevision !== undefined && declaredRevision !== sourceRevision) {
    throw new Error(
      "GIT_SOURCE_REVISION must equal the actual clean checkout HEAD; arbitrary evidence revisions are rejected",
    );
  }

  const repoRoot = git(["rev-parse", "--show-toplevel"]);
  const paths = [benchmarkPath, "apps/web/src/lib/terminal/pty-transport.ts", "apps/web/package.json", "apps/web/bun.lock"];
  const sourceBlobs = paths.map((path) => ({
    path,
    gitBlobSha: git(["rev-parse", `${sourceRevision}:${path}`]),
    sha256: fileSha256(join(repoRoot, path)),
  }));
  const cpu = cpus();
  return {
    sourceRevision,
    generationCommit: sourceRevision,
    sourceTree: git(["rev-parse", `${sourceRevision}^{tree}`]),
    sourceBlobs,
    cleanCheckout: cleanCheckout(),
    command,
    sourceCheckout: "git switch --detach <sourceRevision>",
    runtime: {
      bun: process.versions.bun ?? "unknown",
      node: process.versions.node ?? "unknown",
      packageManager: packageManagerVersion(),
    },
    os: {
      platform: process.platform,
      release: release(),
      architecture: process.arch,
      cpuModel: cpu[0]?.model ?? "unknown",
      cpuCount: cpu.length,
    },
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
