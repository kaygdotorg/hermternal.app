import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { relative, resolve } from "node:path";
import {
  validatePtyBenchmarkFile,
  type PtyBenchmarkValidationOptions,
} from "./validate-pty-benchmarks";

const DEFAULT_ARTIFACTS = [
  "src/lib/terminal/pty-reconnect-supersession-benchmark.json",
  "src/lib/terminal/pty-connecting-ownership-benchmark.json",
] as const;

export interface PtyBenchmarkCliOptions {
  readonly optimized: boolean;
  readonly artifactPaths: readonly string[];
}

export function parsePtyBenchmarkCliArgs(
  args: readonly string[],
): PtyBenchmarkCliOptions {
  let optimized = false;
  let endOfOptions = false;
  const artifactPaths: string[] = [];
  for (const arg of args) {
    if (!endOfOptions && arg === "--") {
      endOfOptions = true;
      continue;
    }
    if (!endOfOptions && arg === "--optimized") {
      if (optimized) throw new Error("duplicate --optimized flag");
      optimized = true;
      continue;
    }
    if (!endOfOptions && arg.startsWith("-")) {
      throw new Error(`unknown option ${arg}`);
    }
    artifactPaths.push(arg);
  }
  return { optimized, artifactPaths };
}

const RETAINED_ARTIFACT_SCHEMAS = {
  "src/lib/terminal/pty-reconnect-supersession-benchmark.json":
    "hermternal.pty-reconnect-supersession-benchmark.v2",
  "src/lib/terminal/pty-connecting-ownership-benchmark.json":
    "hermternal.pty-connecting-ownership-benchmark.v2",
} as const;

type RetainedArtifactPath = keyof typeof RETAINED_ARTIFACT_SCHEMAS;

function assertRetainedArtifactPath(path: string): RetainedArtifactPath {
  const repoRoot = execFileSync(
    "git",
    ["rev-parse", "--show-toplevel"],
    { cwd: process.cwd(), encoding: "utf8" },
  ).trim();
  const resolvedPath = realpathSync(resolve(process.cwd(), path));
  const relativePath = relative(repoRoot, resolvedPath);
  const appRelativePath = relativePath.startsWith("apps/web/")
    ? relativePath.slice("apps/web/".length)
    : relativePath;
  if (
    !Object.prototype.hasOwnProperty.call(
      RETAINED_ARTIFACT_SCHEMAS,
      appRelativePath,
    )
  ) {
    throw new Error(
      `artifact path ${path} is not one of the retained PTY benchmark JSON identities`,
    );
  }
  return appRelativePath as RetainedArtifactPath;
}

try {
  const { optimized, artifactPaths } = parsePtyBenchmarkCliArgs(
    process.argv.slice(2),
  );
  const artifacts = artifactPaths.length > 0 ? artifactPaths : DEFAULT_ARTIFACTS;
  const options: PtyBenchmarkValidationOptions = optimized ? { optimized: true } : {};
  for (const artifactPath of artifacts) {
    const retainedPath = assertRetainedArtifactPath(artifactPath);
    validatePtyBenchmarkFile(artifactPath, {
      ...options,
      expectedSchema: RETAINED_ARTIFACT_SCHEMAS[retainedPath],
    });
  }
  process.stdout.write(
    JSON.stringify({
      valid: true,
      optimized,
      validationMode: optimized
        ? "optimized-canonical-provenance-and-proof-ledger"
        : "standard-order-insensitive-provenance-and-proof-ledger",
      artifacts,
    }) + "\n",
  );
} catch (error) {
  process.stderr.write(
    JSON.stringify({
      valid: false,
      error: error instanceof Error ? error.message : "invalid benchmark evidence",
    }) + "\n",
  );
  process.exitCode = 1;
}
