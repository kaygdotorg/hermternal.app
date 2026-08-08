import { validatePtyBenchmarkFile } from "./validate-pty-benchmarks";

const DEFAULT_ARTIFACTS = [
  "src/lib/terminal/pty-reconnect-supersession-benchmark.json",
  "src/lib/terminal/pty-connecting-ownership-benchmark.json",
] as const;

const args = process.argv.slice(2);
const optimized = args.includes("--optimized");
const artifactPaths = args.filter((arg) => arg !== "--optimized");
try {
  const artifacts = artifactPaths.length > 0 ? artifactPaths : DEFAULT_ARTIFACTS;
  for (const artifactPath of artifacts) validatePtyBenchmarkFile(artifactPath);
  process.stdout.write(JSON.stringify({ valid: true, optimized, artifacts }) + "\n");
} catch (error) {
  process.stderr.write(
    JSON.stringify({
      valid: false,
      error: error instanceof Error ? error.message : "invalid benchmark evidence",
    }) + "\n",
  );
  process.exitCode = 1;
}
