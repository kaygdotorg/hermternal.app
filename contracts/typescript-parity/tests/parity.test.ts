import { describe, expect, it } from "bun:test";
import { mkdir, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import {
  assertNoNetworkImports,
  assertRejects,
  loadCase,
  loadRegistry,
  MAX_JSON_BYTES,
  MAX_JSON_DEPTH,
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

type CliResult = { exitCode: number; stdout: string; stderr: string };

function runCli(...args: string[]): CliResult {
  const completed = Bun.spawnSync(
    ["bun", join(repoRoot, "contracts/typescript-parity/src/cli.ts"), ...args],
    {
      cwd: join(repoRoot, "contracts/typescript-parity"),
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  return {
    exitCode: completed.exitCode,
    stdout: new TextDecoder().decode(completed.stdout),
    stderr: new TextDecoder().decode(completed.stderr),
  };
}

async function runCliWithTimeout(...args: string[]): Promise<CliResult & { timedOut: boolean }> {
  const child = Bun.spawn(
    ["bun", join(repoRoot, "contracts/typescript-parity/src/cli.ts"), ...args],
    {
      cwd: join(repoRoot, "contracts/typescript-parity"),
      stdout: "pipe",
      stderr: "pipe",
    },
  );
  let timer: ReturnType<typeof setTimeout> | undefined;
  const completed = await Promise.race([
    child.exited.then((exitCode) => ({ exitCode, timedOut: false as const })),
    new Promise<{ exitCode: number; timedOut: true }>((resolve) => {
      timer = setTimeout(() => {
        child.kill();
        resolve({ exitCode: -1, timedOut: true });
      }, 1_500);
    }),
  ]);
  if (timer) clearTimeout(timer);
  if (completed.timedOut) {
    await Promise.race([child.exited, new Promise((resolve) => setTimeout(resolve, 100))]);
    return { exitCode: completed.exitCode, stdout: "", stderr: "", timedOut: true };
  }
  return {
    exitCode: completed.exitCode,
    stdout: await new Response(child.stdout).text(),
    stderr: await new Response(child.stderr).text(),
    timedOut: false,
  };
}

async function writeParityFixtureTree(): Promise<string> {
  const temporaryRoot = join("/tmp", `hermternal-c20-${crypto.randomUUID()}`);
  const fixturesDirectory = join(temporaryRoot, "contracts/fixtures");
  await mkdir(fixturesDirectory, { recursive: true });
  const registry = await Bun.file(join(repoRoot, "contracts/fixtures/index.json")).json() as {
    fixture_roots: Array<{ files: Array<{ path: string }> }>;
  };
  await Bun.write(
    join(fixturesDirectory, "index.json"),
    await Bun.file(join(repoRoot, "contracts/fixtures/index.json")).arrayBuffer(),
  );
  for (const root of registry.fixture_roots) {
    for (const file of root.files) {
      const destination = join(fixturesDirectory, file.path);
      await mkdir(dirname(destination), { recursive: true });
      await Bun.write(
        destination,
        await Bun.file(join(repoRoot, "contracts/fixtures", file.path)).arrayBuffer(),
      );
    }
  }
  return temporaryRoot;
}

async function mutateParityRegistry(
  temporaryRoot: string,
  mutate: (registry: Record<string, unknown>) => void,
): Promise<void> {
  const indexPath = join(temporaryRoot, "contracts/fixtures/index.json");
  const registry = await Bun.file(indexPath).json() as Record<string, unknown>;
  mutate(registry);
  await Bun.write(indexPath, `${JSON.stringify(registry)}\n`);
}

function createFifo(path: string): void {
  const result = Bun.spawnSync(["mkfifo", path], { stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) {
    throw new Error(`mkfifo failed with exit code ${result.exitCode}`);
  }
}

function cliError(result: { stderr: string }): { code: string; message: string } {
  const parsed = JSON.parse(result.stderr) as { ok: false; error: { code: string; message: string } };
  return parsed.error;
}

function nestedObject(depth: number): string {
  let value = "null";
  for (let index = 0; index < depth; index += 1) {
    value = `{"nested":${value}}`;
  }
  return value;
}

async function refreshManifest(root: string, artifact: string): Promise<void> {
  const artifactPath = join(root, "contracts/fixtures", artifact);
  const bytes = new Uint8Array(await Bun.file(artifactPath).arrayBuffer());
  const digest = createHash("sha256").update(bytes).digest("hex");
  const indexPath = join(root, "contracts/fixtures/index.json");
  const registry = await Bun.file(indexPath).json() as Record<string, unknown>;
  const fixtureRoots = registry.fixture_roots as Array<Record<string, unknown>>;
  const fixtureRoot = fixtureRoots.find((entry) => (entry.files as Array<Record<string, unknown>>).some((file) => file.path === artifact));
  if (!fixtureRoot) throw new Error(`fixture root not found for ${artifact}`);
  const file = (fixtureRoot.files as Array<Record<string, unknown>>).find((entry) => entry.path === artifact);
  if (!file) throw new Error(`fixture artifact not found for ${artifact}`);
  file.sha256 = digest;
  file.size_bytes = bytes.byteLength;
  await Bun.write(indexPath, `${JSON.stringify(registry)}\n`);
}

describe("C-20 TypeScript contract parity", () => {
  it("proves shared semantic outcomes for representative contract families offline", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      const report = await runParity(temporaryRoot);
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
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
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
    const temporaryRoot = await writeParityFixtureTree();
    try {
      const registry = await loadRegistry(temporaryRoot);
      const chat = registry.coverage.find((entry) => entry.id === "chat-stream-and-completion");
      expect(chat?.status).toBe("pending");
      const report = await runParity(temporaryRoot);
      const chatResults = report.cases.filter((entry) => entry.family === "chat");
      expect(chatResults.length).toBe(2);
      expect(chatResults.every((entry) => entry.status === "blocked")).toBe(true);
      expect(chatResults.every((entry) => entry.webDecision === undefined && entry.appleDecision === undefined)).toBe(true);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("has no network-capable calls in the parity implementation", async () => {
    const source = await Bun.file(resolve(import.meta.dir, "../src/parity.ts")).text();
    expect(() => assertNoNetworkImports(source)).not.toThrow();
  });

  it("treats authoritative non-success coverage states as bounded blocked evidence", async () => {
    for (const status of ["empty", "failure", "cancelled", "unknown"] as const) {
      const temporaryRoot = await writeParityFixtureTree();
      try {
        await mutateParityRegistry(temporaryRoot, (registry) => {
          const coverage = registry.coverage as Array<Record<string, unknown>>;
          const row = coverage.find((entry) => entry.id === "image-attachment-lifecycle");
          if (!row) throw new Error("image coverage row is missing");
          row.status = status;
        });
        const report = await runParity(temporaryRoot);
        const imageResults = report.cases.filter((entry) => entry.family === "image");
        expect(report.blockedCoverageIds).toContain("image-attachment-lifecycle");
        expect(imageResults.length).toBe(3);
        expect(imageResults.every((entry) => entry.status === "blocked")).toBe(true);
        expect(imageResults.every((entry) => entry.webDecision === undefined && entry.appleDecision === undefined)).toBe(true);
      } finally {
        await rm(temporaryRoot, { recursive: true, force: true });
      }
    }
  });

  it("supports pending roots without validator or artifact claims", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      const pendingRoot = join(temporaryRoot, "contracts/fixtures/provider-discovery");
      await rm(pendingRoot, { recursive: true, force: true });
      await mutateParityRegistry(temporaryRoot, (registry) => {
        const roots = registry.fixture_roots as Array<Record<string, unknown>>;
        const root = roots.find((entry) => entry.id === "provider-discovery");
        if (!root) throw new Error("provider-discovery root is missing");
        root.status = "pending";
        root.validator = null;
        root.files = [];
        const coverage = registry.coverage as Array<Record<string, unknown>>;
        const row = coverage.find((entry) => entry.id === "provider-discovery");
        if (!row) throw new Error("provider-discovery coverage row is missing");
        row.status = "pending";
      });
      const report = await runParity(temporaryRoot);
      expect(report.blockedCoverageIds).toContain("provider-discovery");
      expect(report.readyCaseCount).toBe(11);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("rejects a deterministic FIFO replacement without hanging the CLI", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      const replacement = join(temporaryRoot, "contracts/fixtures/deployment-security/browser-auth/cases.json");
      await rm(replacement, { force: true });
      createFifo(replacement);
      const result = await runCliWithTimeout("--repo-root", temporaryRoot);
      expect(result.timedOut).toBe(false);
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(cliError(result).code).toBe("unsafe_artifact");
      expect(result.stderr.length).toBeLessThan(1_024);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("returns bounded JSON errors for unknown or positional CLI input", () => {
    const unknown = runCli("--unknown");
    expect(unknown.exitCode).not.toBe(0);
    expect(unknown.stdout).toBe("");
    expect(JSON.parse(unknown.stderr)).toEqual({
      ok: false,
      error: { code: "unknown_input", message: "parity CLI accepts only --repo-root" },
    });

    const positional = runCli("unexpected");
    expect(positional.exitCode).not.toBe(0);
    expect(positional.stdout).toBe("");
    expect(JSON.parse(positional.stderr)).toEqual({
      ok: false,
      error: { code: "malformed_input", message: "parity CLI accepts only --repo-root" },
    });
  });

  it("executes the normal Bun CLI on a complete inventory and blocks an incomplete one", async () => {
    const completeRoot = await writeParityFixtureTree();
    try {
      const result = runCli("--repo-root", completeRoot);
      expect(result.exitCode).toBe(0);
      expect(result.stderr).toBe("");
      const report = JSON.parse(result.stdout) as { ok: boolean; readyCaseCount: number; cases: unknown[] };
      expect(report.ok).toBe(true);
      expect(report.readyCaseCount).toBe(11);
      expect(report.cases.length).toBe(17);
      expect(result.stdout.length).toBeLessThan(16_384);
    } finally {
      await rm(completeRoot, { recursive: true, force: true });
    }

    const unindexedRoot = await writeParityFixtureTree();
    try {
      await Bun.write(join(unindexedRoot, "contracts/fixtures/pty-contract/unindexed.txt"), "not registered\n");
      const unindexed = runCli("--repo-root", unindexedRoot);
      expect(unindexed.exitCode).not.toBe(0);
      expect(unindexed.stdout).toBe("");
      expect(cliError(unindexed).code).toBe("fixture_inventory_invalid");
      expect(unindexed.stderr.length).toBeLessThan(1_024);
    } finally {
      await rm(unindexedRoot, { recursive: true, force: true });
    }

    const incomplete = runCli("--repo-root", repoRoot);
    expect(incomplete.exitCode).not.toBe(0);
    expect(incomplete.stdout).toBe("");
    expect(cliError(incomplete).code).toBe("fixture_inventory_invalid");
    expect(incomplete.stderr.length).toBeLessThan(1_024);
  });

  it("rejects malformed, duplicate-key, deep, oversized, and unknown-field CLI input", async () => {
    const inputs: readonly [string, string, string][] = [
      ["malformed", "{\n", "malformed_json"],
      ["duplicate", '{"schema":"one","schema":"two"}', "duplicate_key"],
      ["deep", nestedObject(MAX_JSON_DEPTH + 2), "json_depth_limit"],
      ["oversized", " ".repeat(MAX_JSON_BYTES + 1), "json_too_large"],
    ];
    for (const [name, contents, code] of inputs) {
      const temporaryRoot = await writeRawRegistry(contents);
      try {
        const result = runCli("--repo-root", temporaryRoot);
        expect(result.exitCode, name).not.toBe(0);
        expect(result.stdout, name).toBe("");
        expect(cliError(result).code, name).toBe(code);
        expect(result.stderr.length, name).toBeLessThan(1_024);
      } finally {
        await rm(temporaryRoot, { recursive: true, force: true });
      }
    }

    const unknownFieldRoot = await writeRegistryMutation((registry) => {
      registry.unexpected = true;
    });
    try {
      const result = runCli("--repo-root", unknownFieldRoot);
      expect(result.exitCode).not.toBe(0);
      expect(cliError(result).code).toBe("unknown_field");
    } finally {
      await rm(unknownFieldRoot, { recursive: true, force: true });
    }
  });

  it("rejects stale oversized and same-size replacement artifacts before parsing", async () => {
    const oversizedRoot = await writeParityFixtureTree();
    try {
      const replacement = join(oversizedRoot, "contracts/fixtures/deployment-security/browser-auth/cases.json");
      await Bun.write(replacement, `{"cases":[]}\n${" ".repeat(2 * 1024 * 1024)}`);
      const result = runCli("--repo-root", oversizedRoot);
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(cliError(result).code).toBe("artifact_size_mismatch");
      expect(result.stderr.length).toBeLessThan(1_024);
    } finally {
      await rm(oversizedRoot, { recursive: true, force: true });
    }

    const hashRoot = await writeParityFixtureTree();
    try {
      const replacement = join(hashRoot, "contracts/fixtures/deployment-security/browser-auth/cases.json");
      const original = await Bun.file(replacement).arrayBuffer();
      const bytes = new Uint8Array(original.byteLength);
      bytes.fill(0x20);
      await Bun.write(replacement, bytes);
      const result = runCli("--repo-root", hashRoot);
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(cliError(result).code).toBe("artifact_hash_mismatch");
      expect(result.stderr.length).toBeLessThan(1_024);
    } finally {
      await rm(hashRoot, { recursive: true, force: true });
    }
  });

  it("bounds compatibility fields before they can enlarge the report", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      const artifact = "source-audit/compatibility-gate/compatibility_record.json";
      const artifactPath = join(temporaryRoot, "contracts/fixtures", artifact);
      const record = await Bun.file(artifactPath).json() as Record<string, unknown>;
      const status = record.status as Record<string, unknown>;
      status.deployment_attestation = "x".repeat(300);
      await Bun.write(artifactPath, `${JSON.stringify(record)}\n`);
      await refreshManifest(temporaryRoot, artifact);
      const result = runCli("--repo-root", temporaryRoot);
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(cliError(result).code).toBe("output_limit");
      expect(result.stderr.length).toBeLessThan(1_024);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("exposes a typed rejection assertion for regression tests", () => {
    expect(() => assertRejects({ code: "wrong" }, "unknown_case")).toThrow(/expected unknown_case rejection/);
  });
});
