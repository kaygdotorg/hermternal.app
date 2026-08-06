import { describe, expect, it } from "bun:test";
import { mkdir, open, readdir, rm, symlink } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import {
  assertNoNetworkImports,
  assertRejects,
  atFdcwdForPlatform,
  boundedErrorText,
  injectReaddirErrorAfter,
  loadCase,
  loadCompatibilityRecord,
  loadRegistry,
  MAX_ERROR_MESSAGE_LENGTH,
  MAX_JSON_BYTES,
  MAX_JSON_DEPTH,
  MAX_REPORT_BYTES,
  observedReaddirEntries,
  PLATFORMS,
  readDescriptorBytes,
  representativeIds,
  repoRootFromModule,
  runParity,
  serializeBoundedJsonLine,
  type FixtureRegistry,
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
    fixture_roots: Array<{ id: string; status: string; validator: string | null; files: Array<{ path: string }> }>;
    coverage: Array<{ id: string; status: string }>;
  };
  await Bun.write(
    join(fixturesDirectory, "index.json"),
    await Bun.file(join(repoRoot, "contracts/fixtures/index.json")).arrayBuffer(),
  );
  for (const metadataPath of [
    "schema.json",
    "validator/validation-baseline.json",
    "validator/test_validate.py",
    "validator/validate.py",
  ]) {
    const destination = join(fixturesDirectory, metadataPath);
    await mkdir(dirname(destination), { recursive: true });
    await Bun.write(destination, await Bun.file(join(repoRoot, "contracts/fixtures", metadataPath)).arrayBuffer());
  }
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

async function createLongRegisteredPath(temporaryRoot: string): Promise<string> {
  const originalRelativePath = "deployment-security/browser-auth/cases.json";
  const longRelativePath = [
    "deployment-security/browser-auth",
    ...Array.from({ length: 8 }, (_, index) => `long-${index}-${"x".repeat(100)}`),
    "cases.json",
  ].join("/");
  const originalPath = join(temporaryRoot, "contracts/fixtures", originalRelativePath);
  const replacementPath = join(temporaryRoot, "contracts/fixtures", longRelativePath);
  await mkdir(dirname(replacementPath), { recursive: true });
  await Bun.write(replacementPath, await Bun.file(originalPath).arrayBuffer());
  await rm(originalPath);
  await mutateParityRegistry(temporaryRoot, (registry) => {
    const roots = registry.fixture_roots as Array<Record<string, unknown>>;
    const root = roots.find((entry) => entry.id === "deployment-security-browser-auth");
    if (!root) throw new Error("browser auth root is missing");
    const files = root.files as Array<Record<string, unknown>>;
    const file = files.find((entry) => entry.path === originalRelativePath);
    if (!file) throw new Error("browser auth cases artifact is missing");
    file.path = longRelativePath;
    file.size_bytes = (file.size_bytes as number) + 1;
    files.sort((left, right) => {
      const leftPath = String(left.path);
      const rightPath = String(right.path);
      return leftPath < rightPath ? -1 : leftPath > rightPath ? 1 : 0;
    });
  });
  return longRelativePath;
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

function expectDeepFrozen(value: unknown, seen = new Set<object>()): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  expect(Object.isFrozen(value)).toBe(true);
  expect(Reflect.ownKeys(value).every((key) => typeof key === "string")).toBe(true);
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (key !== "length") expect(descriptor.enumerable).toBe(true);
    expect("get" in descriptor && descriptor.get !== undefined).toBe(false);
    expect("set" in descriptor && descriptor.set !== undefined).toBe(false);
    if ("value" in descriptor) expectDeepFrozen(descriptor.value, seen);
  }
}

describe("C-20 TypeScript contract parity", () => {
  it("proves shared semantic outcomes for representative contract families offline", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      const report = await runParity(temporaryRoot);
      expectDeepFrozen(report);
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

  it("returns inert snapshots without caller aliases, accessors, or mutable platform state", async () => {
    const registry = await loadRegistry(repoRoot);
    expectDeepFrozen(registry);
    expectDeepFrozen(PLATFORMS);
    expect(() => (PLATFORMS as unknown as string[]).push("android")).toThrow();

    const fixture = await loadCase(repoRoot, registry, "deployment-security-browser-auth", "login-success");
    expectDeepFrozen(fixture);
    expect(fixture.expected).not.toBe(fixture.raw.expected);
    expect(fixture.expected as unknown).toEqual(fixture.raw.expected);
    expect(() => { (fixture.expected as Record<string, unknown>).status = 599; }).toThrow();

    const firstRepresentatives = representativeIds();
    const secondRepresentatives = representativeIds();
    expect(firstRepresentatives).not.toBe(secondRepresentatives);
    expect(firstRepresentatives[0]).not.toBe(secondRepresentatives[0]);
    expectDeepFrozen(firstRepresentatives);
    expect(() => (firstRepresentatives[0]!.caseIds as string[]).push("poisoned")).toThrow();
    expect(representativeIds()).toEqual(secondRepresentatives);

    const copied = structuredClone(registry) as FixtureRegistry;
    await expect(loadCase(repoRoot, copied, "deployment-security-browser-auth", "login-success"))
      .rejects.toMatchObject({ code: "untrusted_registry" });

    let getterCalls = 0;
    const accessorRegistry = {} as FixtureRegistry;
    Object.defineProperty(accessorRegistry, "fixtureRoots", {
      enumerable: false,
      get() { getterCalls += 1; return registry.fixtureRoots; },
    });
    await expect(loadCase(repoRoot, accessorRegistry, "deployment-security-browser-auth", "login-success"))
      .rejects.toMatchObject({ code: "untrusted_registry" });
    expect(getterCalls).toBe(0);

    let proxyReads = 0;
    const proxyRegistry = new Proxy({} as FixtureRegistry, {
      get() { proxyReads += 1; return undefined; },
    });
    await expect(loadCase(repoRoot, proxyRegistry, "deployment-security-browser-auth", "login-success"))
      .rejects.toMatchObject({ code: "untrusted_registry" });
    expect(proxyReads).toBe(0);

    const symbolRegistry = { [Symbol("hidden")]: true } as unknown as FixtureRegistry;
    await expect(loadCase(repoRoot, symbolRegistry, "deployment-security-browser-auth", "login-success"))
      .rejects.toMatchObject({ code: "untrusted_registry" });

    const temporaryRoot = await writeParityFixtureTree();
    try {
      const trusted = await loadRegistry(temporaryRoot);
      const root = trusted.fixtureRoots.find((entry) => entry.id === "deployment-security-browser-auth")!;
      const registered = root.files.find((entry) => entry.path.endsWith("cases.json"))!;
      expect(() => { (registered as { sha256: string }).sha256 = "0".repeat(64); }).toThrow();
      const path = join(temporaryRoot, "contracts/fixtures/deployment-security/browser-auth/cases.json");
      const bytes = new Uint8Array(await Bun.file(path).arrayBuffer());
      bytes[0] = bytes[0] === 0x20 ? 0x21 : 0x20;
      await Bun.write(path, bytes);
      await expect(loadCase(temporaryRoot, trusted, root.id, "login-success"))
        .rejects.toMatchObject({ code: "artifact_hash_mismatch" });
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("rejects the exact browser-auth nested canonical parity reproductions", async () => {
    const artifact = "deployment-security/browser-auth/cases.json";
    const mutations: Array<(record: Record<string, unknown>) => void> = [
      (record) => {
        const cases = record.cases as Array<Record<string, unknown>>;
        (cases.find((entry) => entry.id === "login-success")!.expected as Record<string, unknown>).status = "302";
      },
      (record) => {
        const cases = record.cases as Array<Record<string, unknown>>;
        (cases.find((entry) => entry.id === "login-success")!.expected as Record<string, unknown>).diagnostic = "x".repeat(300);
      },
      (record) => {
        const cases = record.cases as Array<Record<string, unknown>>;
        (cases.find((entry) => entry.id === "login-success")!.expected as Record<string, unknown>).status = 9_007_199_254_740_993;
      },
      (record) => {
        const cases = record.cases as Array<Record<string, unknown>>;
        [cases[0], cases[1]] = [cases[1]!, cases[0]!];
      },
    ];

    for (const mutate of mutations) {
      const temporaryRoot = await writeParityFixtureTree();
      try {
        const path = join(temporaryRoot, "contracts/fixtures", artifact);
        const record = await Bun.file(path).json() as Record<string, unknown>;
        mutate(record);
        await Bun.write(path, `${JSON.stringify(record)}\n`);
        await refreshManifest(temporaryRoot, artifact);
        const registry = await loadRegistry(temporaryRoot);
        await expect(loadCase(temporaryRoot, registry, "deployment-security-browser-auth", "login-success"))
          .rejects.toMatchObject({ code: "incompatible_input" });
      } finally {
        await rm(temporaryRoot, { recursive: true, force: true });
      }
    }
  }, 30_000);

  it("rejects compatibility PR numbers written as lexical floats", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      const artifact = "source-audit/compatibility-gate/compatibility_record.json";
      const path = join(temporaryRoot, "contracts/fixtures", artifact);
      const source = await Bun.file(path).text();
      expect(source).toContain('"number": 221');
      await Bun.write(path, source.replace('"number": 221', '"number": 221.0'));
      await refreshManifest(temporaryRoot, artifact);
      const registry = await loadRegistry(temporaryRoot);
      await expect(loadCompatibilityRecord(temporaryRoot, registry))
        .rejects.toMatchObject({ code: "malformed_input" });
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("matches normal and optimized Python decisions for checked-in compatibility evidence", async () => {
    const validator = join(repoRoot, "contracts/fixtures/source-audit/compatibility-gate/validate.py");
    const record = join(repoRoot, "contracts/fixtures/source-audit/compatibility-gate/compatibility_record.json");
    for (const args of [
      ["python3", validator, "--repo-root", repoRoot, "--record", record],
      ["python3", "-O", validator, "--repo-root", repoRoot, "--record", record],
    ]) {
      const result = Bun.spawnSync(args, { cwd: repoRoot, stdout: "pipe", stderr: "pipe" });
      expect(result.exitCode).not.toBe(0);
    }
    const registry = await loadRegistry(repoRoot);
    await expect(loadCompatibilityRecord(repoRoot, registry))
      .rejects.toMatchObject({ code: "incompatible_input" });
  }, 30_000);

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

  it("parses non-success coverage states but rejects registry bytes outside the aggregate baseline", async () => {
    for (const status of ["empty", "failure", "cancelled", "unknown"] as const) {
      const temporaryRoot = await writeParityFixtureTree();
      try {
        await mutateParityRegistry(temporaryRoot, (registry) => {
          const coverage = registry.coverage as Array<Record<string, unknown>>;
          const row = coverage.find((entry) => entry.id === "image-attachment-lifecycle");
          if (!row) throw new Error("image coverage row is missing");
          row.status = status;
        });
        const registry = await loadRegistry(temporaryRoot);
        expect(registry.coverage.find((entry) => entry.id === "image-attachment-lifecycle")?.status).toBe(status);
        await expect(runParity(temporaryRoot)).rejects.toMatchObject({ code: "artifact_size_mismatch" });
      } finally {
        await rm(temporaryRoot, { recursive: true, force: true });
      }
    }
  }, 30_000);

  it("keeps pending roots blocked while the aggregate baseline rejects unreviewed registry bytes", async () => {
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
      const registry = await loadRegistry(temporaryRoot);
      await expect(loadCase(temporaryRoot, registry, "provider-discovery", "providers-present"))
        .rejects.toMatchObject({ code: "coverage_pending" });
      await expect(runParity(temporaryRoot)).rejects.toMatchObject({ code: "artifact_size_mismatch" });
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }, 30_000);

  it("returns bounded blocked compatibility evidence for a trusted pending aggregate root", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      await rm(join(temporaryRoot, "contracts/fixtures/source-audit/compatibility-gate"), { recursive: true, force: true });
      await mutateParityRegistry(temporaryRoot, (registry) => {
        const roots = registry.fixture_roots as Array<Record<string, unknown>>;
        const root = roots.find((entry) => entry.id === "source-audit-compatibility-gate");
        if (!root) throw new Error("aggregate compatibility root is missing");
        root.status = "pending";
        root.validator = null;
        root.files = [];
        const coverage = registry.coverage as Array<Record<string, unknown>>;
        const row = coverage.find((entry) => entry.id === "compatibility-gate");
        if (!row) throw new Error("aggregate compatibility coverage row is missing");
        row.status = "pending";
      });

      const registry = await loadRegistry(temporaryRoot);
      expect(await loadCompatibilityRecord(temporaryRoot, registry)).toEqual({
        compatible: false,
        liveRun: false,
        deploymentAttestation: "blocked:pending",
        behavioralProbe: "blocked:pending",
        proxyProof: "blocked:pending",
        parityEvidence: "blocked:pending",
        benchmarkEvidence: "blocked:pending",
      });
      await expect(runParity(temporaryRoot)).rejects.toMatchObject({ code: "artifact_size_mismatch" });
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }, 30_000);

  it("rejects a parent-directory symlink replacement before reading its alternate tree", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      const originalDirectory = join(temporaryRoot, "contracts/fixtures/deployment-security/browser-auth");
      const alternateDirectory = join(temporaryRoot, "alternate-browser-auth");
      await mkdir(alternateDirectory, { recursive: true });
      await Bun.write(
        join(alternateDirectory, "cases.json"),
        await Bun.file(join(originalDirectory, "cases.json")).arrayBuffer(),
      );
      const registry = await loadRegistry(temporaryRoot);
      await rm(originalDirectory, { recursive: true, force: true });
      await symlink(alternateDirectory, originalDirectory, "dir");

      await expect(loadCase(temporaryRoot, registry, "deployment-security-browser-auth", "login-success"))
        .rejects.toMatchObject({ code: "unsafe_artifact" });
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("bounds CLI error JSON when a registered artifact path is nearly maximal", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      const longPath = await createLongRegisteredPath(temporaryRoot);
      expect(longPath.length).toBeGreaterThan(900);
      const result = runCli("--repo-root", temporaryRoot);
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout).toBe("");
      const error = cliError(result);
      expect(error.code).toBe("unsafe_path");
      expect(error.message.length).toBeLessThanOrEqual(MAX_ERROR_MESSAGE_LENGTH);
      expect(result.stderr.length).toBeLessThan(512);
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
  }, 30_000);

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
      expect(cliError(result).code).toBe("incompatible_input");
      expect(result.stderr.length).toBeLessThan(1_024);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("enforces canonical aggregate compatibility linkage", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      await mutateParityRegistry(temporaryRoot, (registry) => {
        const roots = registry.fixture_roots as Array<Record<string, unknown>>;
        const aggregate = roots.find((entry) => entry.id === "source-audit-compatibility-gate");
        if (!aggregate) throw new Error("aggregate compatibility root is missing");
        aggregate.coverage_ids = ["deployment-attestation"];

        const coverage = registry.coverage as Array<Record<string, unknown>>;
        const deployment = coverage.find((entry) => entry.id === "deployment-attestation");
        const compatibility = coverage.find((entry) => entry.id === "compatibility-gate");
        if (!deployment || !compatibility) throw new Error("compatibility coverage rows are missing");
        deployment.fixture_ids = [...(deployment.fixture_ids as string[]), aggregate.id].sort();
        compatibility.fixture_ids = (compatibility.fixture_ids as string[]).filter((id) => id !== aggregate.id);
      });
      const result = runCli("--repo-root", temporaryRoot);
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(cliError(result).code).toBe("fixture_inventory_invalid");
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  });

  it("validates canonical registry metadata, identifiers, paths, and integer tokens", async () => {
    const mutations: Array<(registry: Record<string, unknown>) => void> = [
      (registry) => { registry.evidence_status = "complete"; },
      (registry) => {
        const states = registry.states as Array<Record<string, unknown>>;
        states[0]!.gate_decision = "passed";
      },
      (registry) => {
        const redaction = registry.redaction as Record<string, unknown>;
        redaction.contains_credentials = true;
      },
      (registry) => {
        const benchmark = registry.benchmark as Record<string, unknown>;
        benchmark.threshold = 1;
      },
      (registry) => {
        const coverage = registry.coverage as Array<Record<string, unknown>>;
        coverage[0]!.id = "not_ascii_é";
      },
      (registry) => {
        const roots = registry.fixture_roots as Array<Record<string, unknown>>;
        roots[0]!.path = "attachment-policy//nested";
      },
    ];
    for (const mutate of mutations) {
      const temporaryRoot = await writeRegistryMutation(mutate);
      try {
        await expect(loadRegistry(temporaryRoot)).rejects.toBeInstanceOf(Error);
      } finally {
        await rm(temporaryRoot, { recursive: true, force: true });
      }
    }

    const registryText = await Bun.file(join(repoRoot, "contracts/fixtures/index.json")).text();
    const floatSizeRoot = await writeRawRegistry(registryText.replace(/"size_bytes": (\d+)/, '"size_bytes": $1.0'));
    try {
      await expect(loadRegistry(floatSizeRoot)).rejects.toMatchObject({ code: "malformed_input" });
    } finally {
      await rm(floatSizeRoot, { recursive: true, force: true });
    }
  });

  it("validates nested compatibility semantics and the focused node budget", async () => {
    const fabricatedRoot = await writeParityFixtureTree();
    try {
      const artifact = "source-audit/compatibility-gate/compatibility_record.json";
      const artifactPath = join(fabricatedRoot, "contracts/fixtures", artifact);
      const record = await Bun.file(artifactPath).json() as Record<string, unknown>;
      const redaction = record.redaction as Record<string, unknown>;
      redaction.contains_hosts = true;
      await Bun.write(artifactPath, `${JSON.stringify(record)}\n`);
      await refreshManifest(fabricatedRoot, artifact);
      const result = runCli("--repo-root", fabricatedRoot);
      expect(result.exitCode).not.toBe(0);
      expect(cliError(result).code).toBe("live_input");
    } finally {
      await rm(fabricatedRoot, { recursive: true, force: true });
    }

    const semanticMutations: Array<(record: Record<string, unknown>) => void> = [
      (record) => {
        const merged = record.merged_dev as Record<string, unknown>;
        merged.head = "0".repeat(40);
      },
      (record) => {
        const observations = record.observations as Record<string, unknown>;
        const durations = observations.validator_duration_ms as Record<string, unknown>;
        const normal = durations.normal as Record<string, unknown>;
        normal.command = "python3 changed-validator.py";
      },
      (record) => {
        const observations = record.observations as Record<string, unknown>;
        const durations = observations.validator_duration_ms as Record<string, unknown>;
        const optimized = durations.optimized as Record<string, unknown>;
        const distribution = optimized.distribution as Record<string, unknown>;
        distribution.p95 = Number(distribution.p95) + 0.001;
      },
      (record) => {
        const artifacts = record.artifacts as Record<string, unknown>;
        const files = artifacts.files as Array<Record<string, unknown>>;
        files[0]!.sha256 = "0".repeat(64);
        const digest = createHash("sha256");
        for (const file of files) {
          digest.update(`${file.path}\0${file.sha256}\0${file.size_bytes}\n`, "utf8");
        }
        const setDigest = digest.digest("hex");
        artifacts.set_sha256 = setDigest;
        const observations = record.observations as Record<string, unknown>;
        observations.artifact_set_sha256 = setDigest;
        const durations = observations.validator_duration_ms as Record<string, Record<string, unknown>>;
        for (const mode of ["normal", "optimized"]) durations[mode]!.artifact_set_sha256 = setDigest;
      },
      (record) => {
        const artifacts = record.artifacts as Record<string, unknown>;
        const files = artifacts.files as Array<Record<string, unknown>>;
        files[0]!.path = "contracts/fixtures/README.changed.md";
        const digest = createHash("sha256");
        for (const file of files) {
          digest.update(`${file.path}\0${file.sha256}\0${file.size_bytes}\n`, "utf8");
        }
        const setDigest = digest.digest("hex");
        artifacts.set_sha256 = setDigest;
        const observations = record.observations as Record<string, unknown>;
        observations.artifact_set_sha256 = setDigest;
        const durations = observations.validator_duration_ms as Record<string, Record<string, unknown>>;
        for (const mode of ["normal", "optimized"]) durations[mode]!.artifact_set_sha256 = setDigest;
      },
    ];
    for (const mutate of semanticMutations) {
      const semanticRoot = await writeParityFixtureTree();
      try {
        const artifact = "source-audit/compatibility-gate/compatibility_record.json";
        const artifactPath = join(semanticRoot, "contracts/fixtures", artifact);
        const record = await Bun.file(artifactPath).json() as Record<string, unknown>;
        mutate(record);
        await Bun.write(artifactPath, `${JSON.stringify(record)}\n`);
        await refreshManifest(semanticRoot, artifact);
        const result = runCli("--repo-root", semanticRoot);
        expect(result.exitCode).not.toBe(0);
        expect(cliError(result).code).toBe("incompatible_input");
      } finally {
        await rm(semanticRoot, { recursive: true, force: true });
      }
    }

    const nodeRoot = await writeParityFixtureTree();
    try {
      const artifact = "source-audit/compatibility-gate/compatibility_record.json";
      const artifactPath = join(nodeRoot, "contracts/fixtures", artifact);
      const record = await Bun.file(artifactPath).json() as Record<string, unknown>;
      record.blockers = Array.from({ length: 350 }, (_, index) =>
        Object.fromEntries(Array.from({ length: 11 }, (__, key) => [`k${key}`, index])),
      );
      await Bun.write(artifactPath, `${JSON.stringify(record)}\n`);
      await refreshManifest(nodeRoot, artifact);
      const result = runCli("--repo-root", nodeRoot);
      expect(result.exitCode).not.toBe(0);
      expect(cliError(result).code).toBe("json_node_limit");
    } finally {
      await rm(nodeRoot, { recursive: true, force: true });
    }
  }, 30_000);

  it("bounds error text and complete reports by serialized UTF-8 bytes", async () => {
    for (const input of [
      "界".repeat(240),
      String.fromCharCode(0xd800).repeat(240),
      `before${String.fromCharCode(0x2028)}after${String.fromCharCode(0x85)}end`,
    ]) {
      const bounded = boundedErrorText(input, MAX_ERROR_MESSAGE_LENGTH, "fallback");
      expect(new TextEncoder().encode(JSON.stringify(bounded)).byteLength - 2)
        .toBeLessThanOrEqual(MAX_ERROR_MESSAGE_LENGTH);
      expect(bounded).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\ud800-\udfff]/);
    }

    const baseBytes = new TextEncoder().encode(serializeBoundedJsonLine({ padding: "" })).byteLength;
    const exact = serializeBoundedJsonLine({ padding: "x".repeat(MAX_REPORT_BYTES - baseBytes) });
    expect(new TextEncoder().encode(exact).byteLength).toBe(8_192);
    expect(() => serializeBoundedJsonLine({ padding: "x".repeat(MAX_REPORT_BYTES - baseBytes + 1) }))
      .toThrow(expect.objectContaining({ code: "output_limit" }));

    const temporaryRoot = await writeParityFixtureTree();
    try {
      await mutateParityRegistry(temporaryRoot, (registry) => {
        const coverage = registry.coverage as Array<Record<string, unknown>>;
        for (let index = 0; index < 60; index += 1) {
          const prefix = `z${index.toString().padStart(2, "0")}`;
          coverage.push({
            id: `${prefix}-${"x".repeat(115 - prefix.length)}`,
            status: "pending",
            fixture_ids: [],
            platforms: ["web"],
            required_states: ["pending"],
            notes: "bounded synthetic blocked row",
          });
        }
        coverage.sort((left, right) => String(left.id).localeCompare(String(right.id)));
      });
      const result = runCli("--repo-root", temporaryRoot);
      expect(result.exitCode).not.toBe(0);
      expect(result.stdout).toBe("");
      expect(cliError(result).code).toBe("output_limit");
      expect(new TextEncoder().encode(result.stderr).byteLength).toBeLessThan(MAX_REPORT_BYTES);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }, 30_000);

  it("validates the pinned aggregate schema and validation baseline", async () => {
    for (const relativePath of ["schema.json", "validator/validation-baseline.json"]) {
      const temporaryRoot = await writeParityFixtureTree();
      try {
        await rm(join(temporaryRoot, "contracts/fixtures", relativePath), { force: true });
        await expect(runParity(temporaryRoot)).rejects.toMatchObject({
          code: expect.stringMatching(/^(artifact_read_failed|unsafe_artifact)$/),
        });
      } finally {
        await rm(temporaryRoot, { recursive: true, force: true });
      }
    }
  }, 30_000);

  it("fails closed when readdir reports EIO in either inventory pass", async () => {
    const temporaryRoot = await writeParityFixtureTree();
    try {
      injectReaddirErrorAfter(0);
      await expect(runParity(temporaryRoot)).rejects.toMatchObject({ code: "fixture_inventory_invalid" });

      injectReaddirErrorAfter(-1);
      await runParity(temporaryRoot);
      const completeEntryCount = observedReaddirEntries();
      expect(completeEntryCount).toBeGreaterThan(1);

      injectReaddirErrorAfter(completeEntryCount - 1);
      await expect(runParity(temporaryRoot)).rejects.toMatchObject({ code: "fixture_inventory_invalid" });
    } finally {
      injectReaddirErrorAfter(-1);
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }, 30_000);

  it("bounds descriptor-rooted inventory depth and rejects a symlinked root", async () => {
    const deepRoot = await writeParityFixtureTree();
    try {
      let directory = join(deepRoot, "contracts/fixtures/attachment-policy");
      for (let index = 0; index < 34; index += 1) {
        directory = join(directory, `d${index}`);
        await mkdir(directory);
      }
      await Bun.write(join(directory, "extra.txt"), "unindexed\n");
      const result = runCli("--repo-root", deepRoot);
      expect(result.exitCode).not.toBe(0);
      expect(cliError(result).code).toBe("fixture_inventory_invalid");
    } finally {
      await rm(deepRoot, { recursive: true, force: true });
    }

    const symlinkRoot = await writeParityFixtureTree();
    try {
      const fixtureRoot = join(symlinkRoot, "contracts/fixtures/attachment-policy");
      const alternate = join(symlinkRoot, "alternate-attachment-policy");
      await mkdir(alternate);
      await rm(fixtureRoot, { recursive: true, force: true });
      await symlink(alternate, fixtureRoot, "dir");
      const result = runCli("--repo-root", symlinkRoot);
      expect(result.exitCode).not.toBe(0);
      expect(cliError(result).code).toBe("unsafe_artifact");
    } finally {
      await rm(symlinkRoot, { recursive: true, force: true });
    }
  });

  it("uses platform-correct AT_FDCWD values and cleans repeated FIFO descriptors", async () => {
    expect(atFdcwdForPlatform("darwin")).toBe(-2);
    expect(atFdcwdForPlatform("linux")).toBe(-100);

    const blockingDirectory = join("/tmp", `hermternal-c20-blocking-${crypto.randomUUID()}`);
    await mkdir(blockingDirectory);
    const blockingFifo = join(blockingDirectory, "blocked-read");
    createFifo(blockingFifo);
    const blockingHandle = await open(blockingFifo, fsConstants.O_RDWR);
    const beforeTimeout = (await readdir("/dev/fd")).length;
    try {
      const started = Bun.nanoseconds();
      await expect(readDescriptorBytes(blockingHandle.fd, 1, "blocking descriptor"))
        .rejects.toMatchObject({ code: "artifact_read_timeout" });
      expect((Bun.nanoseconds() - started) / 1_000_000).toBeLessThan(2_000);
    } finally {
      await blockingHandle.close();
      await rm(blockingDirectory, { recursive: true, force: true });
    }
    const afterTimeout = (await readdir("/dev/fd")).length;
    expect(afterTimeout).toBeLessThanOrEqual(beforeTimeout);

    const temporaryRoot = await writeParityFixtureTree();
    try {
      const replacement = join(temporaryRoot, "contracts/fixtures/deployment-security/browser-auth/cases.json");
      await rm(replacement, { force: true });
      createFifo(replacement);
      const before = (await readdir("/dev/fd")).length;
      for (let index = 0; index < 20; index += 1) {
        await expect(runParity(temporaryRoot)).rejects.toMatchObject({ code: "unsafe_artifact" });
      }
      const after = (await readdir("/dev/fd")).length;
      expect(after).toBeLessThanOrEqual(before + 2);
    } finally {
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }, 30_000);

  it("exposes a typed rejection assertion for regression tests", () => {
    expect(() => assertRejects({ code: "wrong" }, "unknown_case")).toThrow(/expected unknown_case rejection/);
  });
});
