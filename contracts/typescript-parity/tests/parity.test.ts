import { describe, expect, it } from "bun:test";
import { mkdir, rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  assertNoNetworkImports,
  assertRejects,
  loadCase,
  loadRegistry,
  repoRootFromModule,
  runParity,
} from "../src/parity";

const repoRoot = repoRootFromModule(import.meta.dir);

async function writeRegistryMutation(mutate: (registry: Record<string, unknown>) => void): Promise<string> {
  const temporaryRoot = join("/tmp", `hermternal-c20-${crypto.randomUUID()}`);
  const fixturesDirectory = join(temporaryRoot, "contracts/fixtures");
  await mkdir(fixturesDirectory, { recursive: true });
  const original = await Bun.file(join(repoRoot, "contracts/fixtures/index.json")).json() as Record<string, unknown>;
  mutate(original);
  await Bun.write(join(fixturesDirectory, "index.json"), `${JSON.stringify(original)}\n`);
  return temporaryRoot;
}

async function writeRawRegistry(contents: string): Promise<string> {
  const temporaryRoot = join("/tmp", `hermternal-c20-${crypto.randomUUID()}`);
  const fixturesDirectory = join(temporaryRoot, "contracts/fixtures");
  await mkdir(fixturesDirectory, { recursive: true });
  await Bun.write(join(fixturesDirectory, "index.json"), contents);
  return temporaryRoot;
}

describe("C-20 TypeScript contract parity", () => {
  it("proves shared semantic outcomes for representative contract families offline", async () => {
    const report = await runParity(repoRoot);
    expect(report.ok).toBe(true);
    expect(report.contract).toBe("dashboard-v0.0.1");
    expect(report.hermesSourceSha).toBe("f5be9236e00ddf2f2a412697f267078fc4ee068e");
    expect(report.syntheticOnly).toBe(true);
    expect(report.liveClaim).toBe(false);
    expect(report.networkCalls).toBe(0);
    expect(report.readyCaseCount).toBeGreaterThanOrEqual(11);
    expect(report.blockedCoverageIds).toContain("chat-stream-and-completion");

    const families = new Set(report.cases.map((entry) => entry.family));
    expect(families).toEqual(new Set(["auth", "connection", "session", "chat", "image", "pty", "deep-link", "compatibility"]));
    expect(report.cases.filter((entry) => entry.family === "chat").every((entry) => entry.status === "blocked")).toBe(true);
    expect(report.cases.filter((entry) => entry.family === "pty").every((entry) => entry.appleDecision === "blocked_platform")).toBe(true);
    expect(report.compatibility.compatible).toBe(false);
    expect(report.compatibility.liveRun).toBe(false);
  });

  it("rejects unknown fixture and case selectors instead of guessing", async () => {
    const registry = await loadRegistry(repoRoot);
    await expect(loadCase(repoRoot, registry, "not-a-fixture", "login-success")).rejects.toMatchObject({ code: "unknown_fixture" });
    await expect(loadCase(repoRoot, registry, "deployment-security-browser-auth", "not-a-case")).rejects.toMatchObject({ code: "unknown_case" });
    await expect(loadCase(repoRoot, registry, "deployment-security-browser-auth", " login-success")).rejects.toMatchObject({ code: "malformed_input" });
  });

  it("rejects malformed or incompatible registry input before reading fixtures", async () => {
    const malformedJsonRoot = await writeRawRegistry("{\n");
    try {
      await expect(loadRegistry(malformedJsonRoot)).rejects.toMatchObject({ code: "malformed_json" });
    } finally {
      await rm(malformedJsonRoot, { recursive: true, force: true });
    }

    const malformedRoot = await writeRegistryMutation((registry) => {
      registry.schema = "unknown.schema";
    });
    try {
      await expect(loadRegistry(malformedRoot)).rejects.toMatchObject({ code: "incompatible_input" });
    } finally {
      await rm(malformedRoot, { recursive: true, force: true });
    }

    const unknownPlatformRoot = await writeRegistryMutation((registry) => {
      const roots = registry.fixture_roots as Array<Record<string, unknown>>;
      const firstRoot = roots[0];
      if (!firstRoot) {
        throw new Error("fixture registry unexpectedly has no roots");
      }
      firstRoot.platforms = ["android"];
    });
    try {
      await expect(loadRegistry(unknownPlatformRoot)).rejects.toMatchObject({ code: "unknown_platform" });
    } finally {
      await rm(unknownPlatformRoot, { recursive: true, force: true });
    }
  });

  it("keeps pending evidence blocked and does not promote a pending chat row", async () => {
    const registry = await loadRegistry(repoRoot);
    const chat = registry.coverage.find((entry) => entry.id === "chat-stream-and-completion");
    expect(chat?.status).toBe("pending");
    const report = await runParity(repoRoot);
    const chatResults = report.cases.filter((entry) => entry.family === "chat");
    expect(chatResults.length).toBe(2);
    expect(chatResults.every((entry) => entry.status === "blocked")).toBe(true);
    expect(chatResults.every((entry) => entry.webDecision === undefined && entry.appleDecision === undefined)).toBe(true);
  });

  it("has no network-capable calls in the parity implementation", async () => {
    const source = await Bun.file(resolve(import.meta.dir, "../src/parity.ts")).text();
    expect(() => assertNoNetworkImports(source)).not.toThrow();
  });

  it("exposes a typed rejection assertion for regression tests", () => {
    expect(() => assertRejects({ code: "wrong" }, "unknown_case")).toThrow(/expected unknown_case rejection/);
  });
});
