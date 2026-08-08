import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  validatePtyBenchmarkArtifact,
  validatePtyBenchmarkFile,
} from "./validate-pty-benchmarks";

const ARTIFACTS = [
  "src/lib/terminal/pty-reconnect-supersession-benchmark.json",
  "src/lib/terminal/pty-connecting-ownership-benchmark.json",
] as const;

describe("PTY benchmark evidence validator", () => {
  it("validates the checked-in deterministic artifacts", () => {
    for (const artifact of ARTIFACTS) expect(() => validatePtyBenchmarkFile(artifact)).not.toThrow();
  });

  it("rejects an arbitrary source revision or missing raw proof", () => {
    const artifact = JSON.parse(
      readFileSync("src/lib/terminal/pty-reconnect-supersession-benchmark.json", "utf8"),
    ) as Record<string, unknown>;
    expect(() =>
      validatePtyBenchmarkArtifact({
        ...artifact,
        provenance: {
          ...(artifact.provenance as Record<string, unknown>),
          sourceRevision: "arbitrary",
        },
      }),
    ).toThrow(/full 40-hex/);
    const firstResult = (artifact.results as Array<Record<string, unknown>>)[0]!;
    expect(() =>
      validatePtyBenchmarkArtifact({
        ...artifact,
        results: [{ ...firstResult, samples: [] }, ...(artifact.results as unknown[]).slice(1)],
      }),
    ).toThrow(/non-empty array/);
  });
});
