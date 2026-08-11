import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  LIVE_SCREENSHOT_COMMAND,
  LIVE_SCREENSHOT_PUBLIC_CONTRACT,
  blockedLiveScreenshotManifest,
  inspectPublicPng
} from '../../tests/live/live-screenshot-contract.mjs';
import {
  LIVE_PLAYWRIGHT_TIMEZONE_ID,
  LIVE_RECONCILIATION_TEST_IGNORE,
  LIVE_RECONCILIATION_TEST_MATCH,
  createLivePlaywrightConfig,
  getLivePlaywrightPaths,
  isLiveReconciliationEnabled
} from '../../tests/live/live-playwright-config.mjs';
import {
  LIVE_PROOF_ASSISTANT_MARKER,
  LIVE_PROOF_PROMPT
} from '../../tests/live/live-proof-ledger.mjs';
import { getLiveScreenshotGitChildConfiguration } from '../../tests/live/live-trusted-executables.mjs';
import {
  parseReconciliationSessionMessages,
  reconcileLiveHistory
} from '../../tests/live/live-reconciliation.mjs';
import { requestLiveReconciliationProjection } from '../../tests/live/live-reconciliation-transport.mjs';

const temporaryDirectories: string[] = [];
type SyntheticHistoryMessage = {
  role: 'user' | 'assistant' | 'system' | 'tool';
  content: string | null;
};

const MARKER_AUTHORITY_ANCHORS = Object.freeze([
  'synthetic and mock-only when run offline',
  'HERMES_RUNS_DIR',
  'HERMES_MARKER_PATH',
  'endpoint --marker "$MARKER_PATH"',
  'same held runs-directory descriptor',
  'run.credential`, `run.state.json`, and `run.cidfile`',
  'read_launcher_result.py marker-path',
  'read_launcher_result.py credential-identity',
  '--credential-identity "$credential_identity"',
  'fclonefileat',
  'no-replace quarantine evidence',
  'cleanup/replacement quarantine slots',
  'No live Hermes run, credential handoff, browser capture, or retainable screenshot was performed here'
]);

const WATERMARK_ANCHORS = Object.freeze([
  'nonextractable Web Crypto HMAC-SHA-256 key',
  '`h1:` tag',
  'Canonical history projections are strict on both shape and value',
  'existing durable canonical session',
  'exactly one bounded `GET /api/sessions/:sessionId/messages?limit=500&offset=0` read before the prompt',
  'computes the transient watermark as `max(messages[].id)`, or zero for an empty history',
  'exactly one exact prompt',
  'source-provided event-envelope `session_id`',
  'source status `complete`',
  'one explicit canonical history read',
  'post-watermark user prompt',
  'HERMTERNAL_LIVE_RECONCILIATION=1',
  'live-proof ledger prompt count remains zero',
  'no-match-uncertain',
  'multiple-matches-ambiguous',
  'no-submit reconciliation spec'
]);

const SCREENSHOT_SUPPORT_ANCHORS = Object.freeze([
  'Task #422 adds only the support surfaces required by the approved correction suite',
  'compatible e5-lineage support ports',
  'live-support-parent-compat.mjs',
  'captureLiveChatScreenshotIfEnabled',
  'browser-resolved `timezoneId` `UTC`',
  'raw PNG bytes in memory',
  'manifest pins the closed fields',
  'exact client commit',
  'official Hermes image digest',
  LIVE_SCREENSHOT_COMMAND
]);
const SECURITY_BOUNDARY_ANCHORS = Object.freeze([
  'PW_RUNNER_DEBUG` and `PWDEBUG`',
  'explicit allowlist',
  'inherited `HERMES_TEST_PASSWORD`',
  'exactly 500 messages',
  'duplicate exact assistant markers',
  'sanitizer audits storage without clearing',
  'hermternal.independent-image-review.v1',
  'exact scrubbed PNG SHA-256',
  'explicit `--git-dir` and `--work-tree` paths',
  'repository-local config cannot redirect status',
  'distinct clean/process/fsmonitor helper bypasses',
  'clean/process filters',
  'reciprocal linked-worktree metadata',
  'GIT_ATTR_NOSYSTEM',
  'GIT_NO_REPLACE_OBJECTS',
  '--no-replace-objects',
  'extensions.worktreeConfig',
  'config.worktree',
  'include.path'
]);

const STALE_LAUNCHER_OR_PROOF_TEXT = Object.freeze([
  'INSTANCE=',
  '--instance',
  'with_live_credential.py "$credential_file"',
  'The executed authorized live proof reached',
  'The disposable instance had no authenticated inference provider'
]);
const BROAD_LIVE_COMMAND_PATTERN = new RegExp('bun run --cwd apps/web test:e2e:live(?! --grep)', 'u');
const OFFICIAL_RECONCILIATION_SKIP =
  "test.skip(reconciliationOnly, 'official Hermes prompt lane is disabled during read-only reconciliation');";
const COMPATIBILITY_PROBES = Object.freeze([
  'tests/live/live-proof-parent-compat.mjs',
  'tests/live/live-support-parent-compat.mjs'
]);
const OFFICIAL_SCREENSHOT_CAPTURE_CALL =
  'await captureLiveChatScreenshotIfEnabled({ page, uiState: captureState, proof });';

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

function png(width: number, height: number, extraChunk?: string): Buffer {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const chunk = (type: string, data = Buffer.alloc(0)) => {
    const value = Buffer.alloc(12 + data.length);
    value.writeUInt32BE(data.length, 0);
    value.write(type, 4, 4, 'ascii');
    data.copy(value, 8);
    return value;
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  return Buffer.concat([
    signature,
    chunk('IHDR', ihdr),
    ...(extraChunk ? [chunk(extraChunk)] : []),
    chunk('IDAT', Buffer.from([0])),
    chunk('IEND')
  ]);
}

async function createRetentionFixture(root: string) {
  const retainedDirectory = join(root, 'retained');
  await mkdir(retainedDirectory, { mode: 0o700 });

  const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
  const bytes = png(1440, 960);
  const imageSha256 = captureModule.sha256Hex(bytes);
  const provenance = captureModule.getLiveScreenshotChromiumProvenance();
  const repositoryRoot = resolve(process.cwd(), '../..');
  const gitConfiguration = getLiveScreenshotGitChildConfiguration();
  const clientCommit = execFileSync(
    gitConfiguration.executable,
    ['-C', repositoryRoot, 'rev-parse', 'HEAD'],
    { encoding: 'utf8', env: gitConfiguration.environment }
  ).trim();
  const manifest = captureModule.createLiveScreenshotManifest({
    browserName: 'chromium',
    browserRevision: provenance.revision,
    browserVersion: provenance.version,
    browserExecutableSha256: provenance.executableSha256,
    clientSha: clientCommit,
    devicePixelRatio: 1,
    imageSha256,
    locale: 'en-US',
    timezoneId: 'UTC',
    reducedMotion: 'reduce',
    theme: 'light',
    uiState: 'ready',
    zoom: 1
  });
  const review = {
    schema: 'hermternal.independent-image-review.v1',
    decision: 'approved',
    review_kind: 'independent-human-visual',
    image_sha256: imageSha256
  };

  return {
    captureModule,
    retainedDirectory,
    bytes,
    imageSha256,
    provenance,
    review,
    capture: { bytes, manifest }
  };
}

async function createReviewEvidence(reviewPath: string, reviewText: string) {
  const parentPath = dirname(reviewPath);
  const [fileStats, parentStats, canonical, parentCanonical] = await Promise.all([
    lstat(reviewPath),
    lstat(parentPath),
    realpath(reviewPath),
    realpath(parentPath)
  ]);
  return {
    candidate: reviewPath,
    dev: fileStats.dev,
    ino: fileStats.ino,
    size: fileStats.size,
    sha256: createHash('sha256').update(reviewText, 'utf8').digest('hex'),
    canonical,
    parent: {
      candidate: parentPath,
      dev: parentStats.dev,
      ino: parentStats.ino,
      canonical: parentCanonical
    }
  };
}

async function expectMissing(path: string) {
  await expect(lstat(path)).rejects.toMatchObject({ code: 'ENOENT' });
}

function readOptionalGitConfigValue(
  runGit: (cwd: string, args: string[]) => string,
  cwd: string,
  key: string
) {
  try {
    return runGit(cwd, ['config', '--get', key]).trim();
  } catch (error) {
    const candidate = error as { status?: unknown; stdout?: unknown; stderr?: unknown };
    expect(candidate.status).toBe(1);
    expect(candidate.stdout).toBe('');
    expect(candidate.stderr).toBe('');
    return undefined;
  }
}

type SyntheticGitConfigProbeResult = {
  status: number | null;
  stdout: Buffer | null;
  stderr: Buffer | null;
  error?: Error;
};

function syntheticGitConfigResult(
  status: number | null,
  stdout = '',
  stderr = ''
): SyntheticGitConfigProbeResult {
  return {
    status,
    stdout: Buffer.from(stdout, 'utf8'),
    stderr: Buffer.from(stderr, 'utf8')
  };
}

async function createSyntheticGitConfigRepository(prefix: string) {
  const root = await mkdtemp(join(tmpdir(), prefix));
  temporaryDirectories.push(root);
  const repository = join(root, 'repository');
  await mkdir(repository, { mode: 0o700 });
  const gitConfiguration = getLiveScreenshotGitChildConfiguration();
  const runGit = (args: string[]) =>
    execFileSync(gitConfiguration.executable, args, {
      cwd: repository,
      encoding: 'utf8',
      env: gitConfiguration.environment,
      maxBuffer: 4 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe']
    });
  runGit(['init', '--quiet']);
  return { root, repository, gitConfiguration, runGit };
}

async function mutateSameSizeFile(path: string) {
  const beforeBytes = await readFile(path);
  const beforeStats = await lstat(path);
  if (beforeBytes.length === 0) throw new Error(`cannot mutate empty file: ${path}`);
  const mutatedBytes = Buffer.from(beforeBytes);
  const offset = Math.floor(mutatedBytes.length / 2);
  mutatedBytes[offset] ^= 1;
  await writeFile(path, mutatedBytes);
  const afterStats = await lstat(path);
  expect(afterStats.dev).toBe(beforeStats.dev);
  expect(afterStats.ino).toBe(beforeStats.ino);
  expect(afterStats.size).toBe(beforeStats.size);
  expect(mutatedBytes.equals(beforeBytes)).toBe(false);
  return beforeBytes;
}

describe('live screenshot contract', () => {
  it('pins a closed blocked manifest without inventing retained images', () => {
    const manifest = blockedLiveScreenshotManifest({
      clientCommit: 'a'.repeat(40),
      blocker: 'issue-327-missing-authenticated-inference-capability'
    });

    expect(manifest).toMatchObject({
      ...LIVE_SCREENSHOT_PUBLIC_CONTRACT,
      status: 'blocked',
      client_commit: 'a'.repeat(40),
      blocker: 'issue-327-missing-authenticated-inference-capability',
      images: []
    });
  });

  it('rejects PNG dimensions and ancillary metadata outside the public contract', () => {
    expect(() => inspectPublicPng(png(956, 2022), { width: 1440, height: 960 })).toThrow(
      'expected 1440x960'
    );
    expect(() => inspectPublicPng(png(1440, 960, 'tEXt'), { width: 1440, height: 960 })).toThrow(
      'disallowed tEXt metadata'
    );
  });

  it('documents both approved proof contracts without stale launcher or run claims', async () => {
    const readme = await readFile(resolve(process.cwd(), 'tests/live/README.md'), 'utf8');

    for (const anchor of MARKER_AUTHORITY_ANCHORS) expect(readme).toContain(anchor);
    for (const anchor of WATERMARK_ANCHORS) expect(readme).toContain(anchor);
    for (const anchor of SCREENSHOT_SUPPORT_ANCHORS) expect(readme).toContain(anchor);
    for (const anchor of SECURITY_BOUNDARY_ANCHORS) expect(readme).toContain(anchor);

    expect(readme.split('The host is test-only.').length - 1).toBe(1);
    expect(readme.split('This lane serves the production static build').length - 1).toBe(1);
    const screenshotCommandPattern = new RegExp(
      'bun run --cwd apps/web test:e2e:live(?: --grep "[^"]+")?',
      'gu'
    );
    const screenshotCommands = [...readme.matchAll(screenshotCommandPattern)].map(
      (match) => match[0]
    );
    expect(screenshotCommands.length).toBeGreaterThan(0);
    expect(screenshotCommands.every((command) => command === LIVE_SCREENSHOT_COMMAND)).toBe(true);

    for (const staleText of STALE_LAUNCHER_OR_PROOF_TEXT) expect(readme).not.toContain(staleText);
    expect(readme).not.toMatch(BROAD_LIVE_COMMAND_PATTERN);
  });

  it('executes approved compatibility probes and enforces reconciliation-only selection', async () => {
    const appRoot = process.cwd();
    const repositoryRoot = resolve(appRoot, '../..');

    for (const probe of COMPATIBILITY_PROBES) {
      // The probes are Node ESM compatibility checks. Bun's data-URL resolver
      // cannot execute their isolated historical module fixtures reliably. The
      // test runner's absolute interpreter path avoids ambient PATH lookup;
      // this scrubbed environment keeps credential-bearing parent settings out.
      const nodeExecutable = resolve(process.execPath);
      const output = execFileSync(nodeExecutable, [resolve(appRoot, probe)], {
        cwd: repositoryRoot,
        encoding: 'utf8',
        env: {
          PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
          LC_ALL: 'C',
          LANG: 'C'
        },
        stdio: ['ignore', 'pipe', 'pipe']
      });
      expect(output).toContain(probe.includes('proof-parent') ? 'live-proof-parent-compat:' : 'live-support-parent-compat:');
    }

    expect(isLiveReconciliationEnabled({})).toBe(false);
    expect(isLiveReconciliationEnabled({ HERMTERNAL_LIVE_RECONCILIATION: '1' })).toBe(true);
    expect(() =>
      isLiveReconciliationEnabled({ HERMTERNAL_LIVE_RECONCILIATION: 'true' })
    ).toThrow('HERMTERNAL_LIVE_RECONCILIATION must equal exactly 1 when set');

    const paths = getLivePlaywrightPaths(
      pathToFileURL(resolve(appRoot, 'playwright.live.config.ts')).href
    );
    const reconciliationConfig = createLivePlaywrightConfig({
      paths,
      port: 4187,
      outputDirectory: join(tmpdir(), 'hermternal-live-reconciliation-regression'),
      launchOptions: {},
      desktopChrome: {},
      reconciliationOnly: true
    });
    expect(reconciliationConfig.testMatch).toBe(LIVE_RECONCILIATION_TEST_MATCH);
    expect(reconciliationConfig.testIgnore).toEqual([...LIVE_RECONCILIATION_TEST_IGNORE]);
    expect(reconciliationConfig.testIgnore).toContain('**/official-hermes.spec.ts');
    expect(reconciliationConfig.testIgnore).toContain('**/*capture*.spec.ts');
    expect(reconciliationConfig.use.timezoneId).toBe(LIVE_PLAYWRIGHT_TIMEZONE_ID);

    const normalConfig = createLivePlaywrightConfig({
      paths,
      port: 4187,
      outputDirectory: join(tmpdir(), 'hermternal-live-normal-regression'),
      launchOptions: {},
      desktopChrome: {},
      reconciliationOnly: false
    });
    expect(normalConfig.testMatch).toBeUndefined();
    expect(normalConfig.testIgnore).toBeUndefined();

    const officialSpec = await readFile(resolve(appRoot, 'tests/live/official-hermes.spec.ts'), 'utf8');
    expect(officialSpec).toContain(OFFICIAL_RECONCILIATION_SKIP);
  });

  it('binds the official proof spec to the in-memory screenshot helper', async () => {
    const appRoot = process.cwd();
    const officialSpec = await readFile(resolve(appRoot, 'tests/live/official-hermes.spec.ts'), 'utf8');
    expect(officialSpec).toContain(
      "import { captureLiveChatScreenshotIfEnabled } from './live-screenshot-capture.mjs';"
    );
    expect(officialSpec).toContain(OFFICIAL_SCREENSHOT_CAPTURE_CALL);
    expect(officialSpec).not.toContain('captureReviewedLiveScreenshots');
    expect(officialSpec).not.toContain('retainedScreenshotDirectory');
    expect(officialSpec).not.toContain('page.screenshot');

    const { captureLiveChatScreenshotIfEnabled } = await import(
      '../../tests/live/live-screenshot-capture.mjs'
    );
    const page = new Proxy({}, {
      get() {
        throw new Error('default-off screenshot capture touched the page');
      }
    });
    await expect(
      captureLiveChatScreenshotIfEnabled({
        page,
        uiState: 'ready',
        proof: {},
        environment: {}
      })
    ).resolves.toBeUndefined();
  });

  it('binds provenance children, exact-hash review, and logout-safe capture ordering', async () => {
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    expect(gitConfiguration.executable.startsWith('/')).toBe(true);
    expect(gitConfiguration.environment).not.toHaveProperty('HERMES_TEST_PASSWORD');
    expect(gitConfiguration.environment).not.toHaveProperty('NODE_OPTIONS');
    expect(gitConfiguration.environment).not.toHaveProperty('HTTP_PROXY');
    expect(gitConfiguration.environment.GIT_CONFIG_SYSTEM).toBe('/dev/null');
    expect(gitConfiguration.environment.GIT_CONFIG_GLOBAL).toBe('/dev/null');
    expect(gitConfiguration.environment.GIT_ATTR_NOSYSTEM).toBe('1');
    expect(gitConfiguration.environment.GIT_NO_REPLACE_OBJECTS).toBe('1');
    expect(gitConfiguration.environment.PATH).toBe('/usr/bin:/bin:/usr/sbin:/sbin');

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const imageSha256 = 'a'.repeat(64);
    const review = {
      schema: 'hermternal.independent-image-review.v1',
      decision: 'approved',
      review_kind: 'independent-human-visual',
      image_sha256: imageSha256
    };
    expect(captureModule.validateIndependentImageReviewRecord(review, imageSha256)).toEqual(review);
    expect(() =>
      captureModule.validateIndependentImageReviewRecord(
        { ...review, image_sha256: 'b'.repeat(64) },
        imageSha256
      )
    ).toThrow('independent image review record was not a closed approval');
    expect(() =>
      captureModule.validateIndependentImageReviewRecord(
        { ...review, extra: 'not-allowed' },
        imageSha256
      )
    ).toThrow('unexpected shape');

    const appRoot = process.cwd();
    const captureSource = await readFile(resolve(appRoot, 'tests/live/live-screenshot-capture.mjs'), 'utf8');
    expect(captureSource).toContain('getLiveScreenshotGitChildConfiguration');
    expect(captureSource).toContain('env: childConfiguration.environment');
    expect(captureSource).toContain('--git-dir');
    expect(captureSource).toContain('--work-tree');
    expect(captureSource).toContain('core.worktree=');
    expect(captureSource).toContain('core.attributesFile=/dev/null');
    expect(captureSource).toContain('core.fsmonitor=false');
    expect(captureSource).toContain('core.hooksPath=/dev/null');
    expect(captureSource).toContain('filterOverrides');
    expect(captureSource).toContain('config.worktree');
    expect(captureSource).toContain('include.path');
    expect(captureSource).toContain('spawnSync');
    expect(captureSource).toContain('result.stderr');
    expect(captureSource).toContain("stdio: ['ignore', 'pipe', 'pipe']");
    expect(captureSource).toContain('GIT_NO_REPLACE_OBJECTS');
    expect(captureSource).toContain('--no-replace-objects');
    const trustedGitArgumentsSource = captureSource.slice(
      captureSource.indexOf('function trustedGitArguments'),
      captureSource.indexOf('function runTrustedGit')
    );
    expect(trustedGitArgumentsSource).toContain("'--no-replace-objects'");
    expect(trustedGitArgumentsSource.indexOf("'--no-replace-objects'")).toBeLessThan(
      trustedGitArgumentsSource.indexOf('...args')
    );
    expect(captureSource).toContain('--path-format=absolute');
    expect(captureSource).toContain('readLiveScreenshotRepositoryState');
    expect(captureSource).not.toContain("execFileSync('git'");
    expect(captureSource).not.toContain('pageContext.clearCookies');
    expect(captureSource).toContain('authenticatedContextPreserved: true');
    expect(captureSource).toContain('const captureClone =');
    expect(captureSource).toContain('const serializedPage = serializeResidualSurface(captureClone);');
    const parentProbeSource = await readFile(resolve(appRoot, 'tests/live/live-proof-parent-compat.mjs'), 'utf8');
    expect(parentProbeSource).toContain('env: PROBE_NODE_ENVIRONMENT');
    expect(parentProbeSource).not.toContain('process.env');
    const contractSource = await readFile(resolve(appRoot, 'tests/live/live-screenshot-contract.mjs'), 'utf8');
    expect(contractSource).not.toContain('captureReviewedLiveScreenshots');
    expect(contractSource).not.toContain('page.screenshot');
    const contractTestSource = await readFile(resolve(appRoot, 'src/lib/live-screenshot-contract.test.ts'), 'utf8');
    // Keep this source-level guard from matching its own assertion literal.
    expect(contractTestSource).not.toMatch(/execFileSync\(['"]node['"]/u);
    const officialSpec = await readFile(resolve(appRoot, 'tests/live/official-hermes.spec.ts'), 'utf8');
    expect(officialSpec.indexOf(OFFICIAL_SCREENSHOT_CAPTURE_CALL)).toBeLessThan(
      officialSpec.indexOf('const cookiesBeforeLogout = await context.cookies(proofOrigin);')
    );
    expect(officialSpec).toContain('sanitization is clone-only');
  });

  it.each([
    ['stderr', '', 'warning from git config'],
    ['stdout', 'unexpected no-match output', '']
  ] as const)('rejects extension status 1 with nonempty %s', async (_stream, stdout, stderr) => {
    const { repository } = await createSyntheticGitConfigRepository('hermternal-live-config-probe-extension-');
    const calls: string[][] = [];
    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const spawnSyncImplementation = (_executable: string, args: string[]) => {
      calls.push([...args]);
      return syntheticGitConfigResult(1, stdout, stderr);
    };

    expect(() =>
      captureModule.readLiveScreenshotGitConfigForTest(repository, spawnSyncImplementation)
    ).toThrow('live screenshot repository topology is unsafe or unsupported');
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain('--no-includes');
    expect(calls[0]).toContain('extensions.worktreeConfig');
  });

  it('rejects filter discovery status 1 with stderr instead of treating it as no match', async () => {
    const { repository } = await createSyntheticGitConfigRepository('hermternal-live-config-probe-filter-');
    const calls: string[][] = [];
    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const spawnSyncImplementation = (_executable: string, args: string[]) => {
      calls.push([...args]);
      if (args.includes('extensions.worktreeConfig')) return syntheticGitConfigResult(1);
      if (args.includes('--local')) return syntheticGitConfigResult(1, '', 'warning from git config');
      throw new Error(`unexpected synthetic config probe: ${args.join(' ')}`);
    };

    expect(() =>
      captureModule.readLiveScreenshotGitConfigForTest(repository, spawnSyncImplementation)
    ).toThrow('live screenshot repository topology is unsafe or unsupported');
    expect(calls).toHaveLength(2);
    expect(calls[1]).toContain('--local');
    expect(calls.some((args) => args.includes('--worktree'))).toBe(false);
  });

  it('disables includes for the common extension probe before local include rejection', async () => {
    const { root, repository, runGit } = await createSyntheticGitConfigRepository(
      'hermternal-live-config-probe-common-includes-'
    );
    const includedConfig = join(root, 'included.config');
    await writeFile(
      includedConfig,
      '[extensions]\n\tworktreeConfig = true\n',
      'utf8'
    );
    runGit(['config', 'include.path', includedConfig]);

    const calls: string[][] = [];
    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const spawnSyncImplementation = (_executable: string, args: string[]) => {
      calls.push([...args]);
      if (args.includes('extensions.worktreeConfig')) {
        // Model the included file enabling the extension only when the probe
        // accidentally follows includes. The local probe deliberately returns
        // a clean no-match so a later include rejection cannot mask this check.
        return args.includes('--no-includes')
          ? syntheticGitConfigResult(1)
          : syntheticGitConfigResult(0, 'true\n');
      }
      if (args.includes('--local')) return syntheticGitConfigResult(1);
      if (args.includes('--worktree')) {
        return syntheticGitConfigResult(0, 'filter.included.clean\0');
      }
      throw new Error(`unexpected synthetic config probe: ${args.join(' ')}`);
    };

    const state = captureModule.readLiveScreenshotGitConfigForTest(repository, spawnSyncImplementation);
    expect(state.filterOverrides).toEqual([]);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toContain('--no-includes');
    expect(calls[1]).toContain('--local');
    expect(calls.some((args) => args.includes('--worktree'))).toBe(false);
  });

  it.each([
    ['absent', undefined],
    ['false', 'false']
  ] as const)('does not scan config.worktree when the common extension is %s', async (_mode, configuredValue) => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-config-probe-inapplicable-'));
    temporaryDirectories.push(root);
    const mainRepository = join(root, 'main');
    const worktree = join(root, 'worktree');
    await mkdir(mainRepository, { mode: 0o700 });
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    const runGit = (cwd: string, args: string[]) =>
      execFileSync(gitConfiguration.executable, args, {
        cwd,
        encoding: 'utf8',
        env: gitConfiguration.environment,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      });

    runGit(mainRepository, ['init', '--quiet']);
    runGit(mainRepository, ['config', 'user.name', 'synthetic-live-proof']);
    runGit(mainRepository, ['config', 'user.email', 'synthetic-live-proof@example.invalid']);
    await writeFile(join(mainRepository, 'tracked.txt'), 'clean\n', 'utf8');
    runGit(mainRepository, ['add', 'tracked.txt']);
    runGit(mainRepository, ['commit', '--quiet', '-m', 'initial']);
    runGit(mainRepository, ['worktree', 'add', '--quiet', worktree, 'HEAD']);
    if (configuredValue !== undefined) {
      runGit(mainRepository, ['config', 'extensions.worktreeConfig', configuredValue]);
    }

    const worktreeGitDir = resolve(runGit(worktree, ['rev-parse', '--git-dir']).trim());
    const configWorktree = join(worktreeGitDir, 'config.worktree');
    await writeFile(
      configWorktree,
      '[filter "ignored-worktree"]\n\tclean = synthetic-malicious-helper\n',
      'utf8'
    );
    expect(await readFile(configWorktree, 'utf8')).toContain('filter "ignored-worktree"');

    const calls: string[][] = [];
    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const spawnSyncImplementation = (_executable: string, args: string[]) => {
      calls.push([...args]);
      if (args.includes('extensions.worktreeConfig')) {
        return configuredValue === 'false'
          ? syntheticGitConfigResult(0, 'false\n')
          : syntheticGitConfigResult(1);
      }
      if (args.includes('--local')) return syntheticGitConfigResult(1);
      if (args.includes('--worktree')) {
        // If the inapplicable scope is queried, expose its malicious key so the
        // result proves that the scope was ignored rather than neutralized later.
        return syntheticGitConfigResult(0, 'filter.ignored-worktree.clean\0');
      }
      throw new Error(`unexpected synthetic config probe: ${args.join(' ')}`);
    };

    const state = captureModule.readLiveScreenshotGitConfigForTest(worktree, spawnSyncImplementation);
    expect(state.filterOverrides).toEqual([]);
    expect(calls).toHaveLength(2);
    expect(calls.some((args) => args.includes('--worktree'))).toBe(false);
  });

  it('neutralizes distinct local and worktree helpers selected by tracked attributes', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-git-provenance-'));
    temporaryDirectories.push(root);
    const repository = join(root, 'repository');
    const alternateWorktree = join(root, 'alternate-worktree');
    const cleanMarker = join(root, 'clean-filter-ran');
    const processMarker = join(root, 'process-filter-ran');
    const fsmonitorMarker = join(root, 'fsmonitor-helper-ran');
    const helper = join(root, 'helpers.mjs');
    const attributesFile = join(root, 'attributes');
    const hooks = join(root, 'hooks');
    await mkdir(repository, { mode: 0o700 });
    await mkdir(alternateWorktree, { mode: 0o700 });
    await mkdir(hooks, { mode: 0o700 });
    await writeFile(
      helper,
      String.raw`import { writeFileSync } from 'node:fs';
const [, , mode, marker] = process.argv;
const writePacket = (value) => {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = bytes.length + 4;
  process.stdout.write(length.toString(16).padStart(4, '0'));
  process.stdout.write(bytes);
};
const flush = () => process.stdout.write('0000');
if (mode === 'clean') {
  writeFileSync(marker, 'clean');
  process.stdin.pipe(process.stdout);
} else if (mode === 'fsmonitor') {
  writeFileSync(marker, 'fsmonitor');
  writePacket('git-fsmonitor-server\0version=2\0');
  flush();
} else if (mode === 'process') {
  let pending = Buffer.alloc(0);
  let phase = 'handshake';
  let header = [];
  let content = [];
  const consume = (packet) => {
    if (packet === null) {
      if (phase === 'handshake') {
        writePacket('git-filter-server');
        writePacket('version=2');
        flush();
        phase = 'capabilities';
      } else if (phase === 'capabilities') {
        writePacket('capability=clean');
        flush();
        phase = 'header';
      } else if (phase === 'header') {
        phase = 'content';
      } else {
        if (header.some((value) => value.toString('utf8').startsWith('command=clean'))) {
          writeFileSync(marker, 'process');
        }
        writePacket('status=success');
        flush();
        for (const value of content) writePacket(value);
        flush();
        flush();
        header = [];
        content = [];
        phase = 'header';
      }
      return;
    }
    if (phase === 'header') header.push(packet);
    if (phase === 'content') content.push(packet);
  };
  process.stdin.on('data', (chunk) => {
    pending = Buffer.concat([pending, chunk]);
    for (;;) {
      if (pending.length < 4) return;
      const length = Number.parseInt(pending.subarray(0, 4).toString('ascii'), 16);
      if (length === 0) {
        pending = pending.subarray(4);
        consume(null);
        continue;
      }
      if (!Number.isInteger(length) || length < 4 || pending.length < length) return;
      consume(pending.subarray(4, length));
      pending = pending.subarray(length);
    }
  });
}
`,
      'utf8'
    );
    await chmod(helper, 0o700);
    await writeFile(attributesFile, '*.txt filter=ignored-by-attributes-file\n', 'utf8');

    const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
    const cleanCommand = [process.execPath, helper, 'clean', cleanMarker].map(shellQuote).join(' ');
    const processCommand = [process.execPath, helper, 'process', processMarker].map(shellQuote).join(' ');
    const fsmonitorCommand = [process.execPath, helper, 'fsmonitor', fsmonitorMarker].map(shellQuote).join(' ');
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    const runGit = (args: string[]) =>
      execFileSync(gitConfiguration.executable, args, {
        cwd: repository,
        encoding: 'utf8',
        env: gitConfiguration.environment,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      });

    runGit(['init', '--quiet']);
    runGit(['config', 'user.name', 'synthetic-live-proof']);
    runGit(['config', 'user.email', 'synthetic-live-proof@example.invalid']);
    runGit(['config', 'core.checkStat', 'minimal']);
    runGit(['config', 'core.trustctime', 'false']);
    await writeFile(join(repository, '.gitattributes'), 'clean.txt filter=local-clean\nprocess.txt filter=worktree-process\n', 'utf8');
    await writeFile(join(repository, 'clean.txt'), 'clean\n', 'utf8');
    await writeFile(join(repository, 'process.txt'), 'clean\n', 'utf8');
    runGit(['add', '.gitattributes', 'clean.txt', 'process.txt']);
    runGit(['commit', '--quiet', '-m', 'initial']);
    runGit(['config', 'extensions.worktreeConfig', 'true']);
    runGit(['config', '--worktree', 'extensions.worktreeConfig', 'false']);
    expect(runGit(['config', '--local', '--get', 'extensions.worktreeConfig']).trim()).toBe('true');
    expect(runGit(['config', '--worktree', '--get', 'extensions.worktreeConfig']).trim()).toBe('false');
    runGit(['config', 'filter.local-clean.clean', cleanCommand]);
    runGit(['config', '--worktree', 'filter.worktree-process.process', processCommand]);
    runGit(['config', '--worktree', 'core.fsmonitor', fsmonitorCommand]);
    expect(runGit(['config', '--worktree', '--get', 'filter.worktree-process.process'])).toContain(
      processCommand
    );
    runGit(['config', 'core.hooksPath', hooks]);
    runGit(['config', 'core.attributesFile', attributesFile]);
    expect(runGit(['check-attr', 'filter', '--', 'clean.txt'])).toContain('local-clean');
    expect(runGit(['check-attr', 'filter', '--', 'process.txt'])).toContain('worktree-process');

    const cleanPath = join(repository, 'clean.txt');
    const processPath = join(repository, 'process.txt');
    const cleanBefore = await lstat(cleanPath);
    const processBefore = await lstat(processPath);
    await writeFile(cleanPath, 'dirty\n', 'utf8');
    await writeFile(processPath, 'dirty\n', 'utf8');
    await utimes(cleanPath, cleanBefore.atimeMs / 1000, cleanBefore.mtimeMs / 1000);
    await utimes(processPath, processBefore.atimeMs / 1000, processBefore.mtimeMs / 1000);
    const cleanAfter = await lstat(cleanPath);
    const processAfter = await lstat(processPath);
    for (const [before, after] of [[cleanBefore, cleanAfter], [processBefore, processAfter]]) {
      expect(after.dev).toBe(before.dev);
      expect(after.ino).toBe(before.ino);
      expect(after.size).toBe(before.size);
      expect(after.mtimeMs).toBe(before.mtimeMs);
    }

    // The common extension stays true while config.worktree overrides its own
    // extension value to false; the vulnerable parent still reads its
    // worktree-scoped helpers. It reaches all three independently marked
    // helpers. Explicit renormalization makes clean/process helper reachability
    // deterministic; the fsmonitor response is intentionally minimal, so a Git
    // protocol error is not evidence that the helper was unreachable.
    try {
      runGit(['-c', 'core.fsmonitor=false', 'add', '--renormalize', 'clean.txt']);
    } catch {
      // The clean fixture may fail after receiving the clean request.
    }
    try {
      runGit(['-c', 'core.fsmonitor=false', 'add', '--renormalize', 'process.txt']);
    } catch {
      // The process fixture may fail after receiving the clean request.
    }
    expect(await readFile(cleanMarker, 'utf8')).toBe('clean');
    expect(await readFile(processMarker, 'utf8')).toBe('process');
    await rm(cleanMarker, { force: true });
    await rm(processMarker, { force: true });
    try {
      runGit(['status', '--porcelain=v1', '--untracked-files=no']);
    } catch {
      // The fsmonitor fixture need only prove that Git reached the configured
      // helper; hardened status disables it before any helper can run.
    }
    expect(await readFile(fsmonitorMarker, 'utf8')).toBe('fsmonitor');
    await rm(fsmonitorMarker, { force: true });
    await rm(cleanMarker, { force: true });
    await rm(processMarker, { force: true });

    await writeFile(join(alternateWorktree, '.gitattributes'), await readFile(join(repository, '.gitattributes')));
    await writeFile(join(alternateWorktree, 'clean.txt'), 'clean\n', 'utf8');
    await writeFile(join(alternateWorktree, 'process.txt'), 'clean\n', 'utf8');
    runGit(['config', 'core.worktree', alternateWorktree]);

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const state = captureModule.readLiveScreenshotRepositoryState(repository);
    expect(state.topology).toBe('directory');
    expect(state.workTree).not.toBe(alternateWorktree);
    expect(state.clientSha).toMatch(/^[a-f0-9]{40}$/u);
    expect(state.dirtyTrackedFiles).toContain('clean.txt');
    expect(state.dirtyTrackedFiles).toContain('process.txt');
    await expect(readFile(cleanMarker, 'utf8')).rejects.toThrow();
    await expect(readFile(processMarker, 'utf8')).rejects.toThrow();
    await expect(readFile(fsmonitorMarker, 'utf8')).rejects.toThrow();
  });

  it.each([
    ['absent', undefined],
    ['false', 'false']
  ] as const)('ignores malicious config.worktree when common extensions.worktreeConfig is %s', async (mode, configuredValue) => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-worktree-config-ignored-'));
    temporaryDirectories.push(root);
    const mainRepository = join(root, 'main');
    const worktree = join(root, 'worktree');
    const marker = join(root, 'worktree-filter-ran');
    const helper = join(root, 'worktree-filter.mjs');
    await mkdir(mainRepository, { mode: 0o700 });
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    const runGit = (cwd: string, args: string[]) =>
      execFileSync(gitConfiguration.executable, args, {
        cwd,
        encoding: 'utf8',
        env: gitConfiguration.environment,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      });

    const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
    await writeFile(
      helper,
      String.raw`import { writeFileSync } from 'node:fs';
writeFileSync(process.argv[2], 'worktree');
process.stdin.pipe(process.stdout);
`,
      'utf8'
    );
    await chmod(helper, 0o700);
    const cleanCommand = [process.execPath, helper, marker].map(shellQuote).join(' ');

    runGit(mainRepository, ['init', '--quiet']);
    runGit(mainRepository, ['config', 'user.name', 'synthetic-live-proof']);
    runGit(mainRepository, ['config', 'user.email', 'synthetic-live-proof@example.invalid']);
    await writeFile(join(mainRepository, '.gitattributes'), 'tracked.txt filter=worktree-evil\n', 'utf8');
    await writeFile(join(mainRepository, 'tracked.txt'), 'clean\n', 'utf8');
    runGit(mainRepository, ['add', '.gitattributes', 'tracked.txt']);
    runGit(mainRepository, ['commit', '--quiet', '-m', 'initial']);
    runGit(mainRepository, ['worktree', 'add', '--quiet', worktree, 'HEAD']);
    if (configuredValue !== undefined) {
      runGit(mainRepository, ['config', 'extensions.worktreeConfig', configuredValue]);
    }
    const extensionValue = readOptionalGitConfigValue(
      runGit,
      mainRepository,
      'extensions.worktreeConfig'
    );
    if (mode === 'absent') expect(extensionValue).not.toBe('true');
    else expect(extensionValue).toBe('false');

    const worktreeGitDir = resolve(runGit(worktree, ['rev-parse', '--git-dir']).trim());
    await writeFile(
      join(worktreeGitDir, 'config.worktree'),
      `[filter "worktree-evil"]\n\tclean = ${cleanCommand}\n`,
      'utf8'
    );
    const trackedPath = join(worktree, 'tracked.txt');
    const trackedBefore = await lstat(trackedPath);
    await writeFile(trackedPath, 'dirty\n', 'utf8');
    await utimes(trackedPath, trackedBefore.atimeMs / 1000, trackedBefore.mtimeMs / 1000);

    // The vulnerable parent ignores config.worktree when the common extension
    // is absent or false, so this renormalization must not reach the helper.
    try {
      runGit(worktree, ['add', '--renormalize', 'tracked.txt']);
    } catch {
      // A helper protocol failure is acceptable only if the marker proves a reach.
    }
    await expectMissing(marker);
    runGit(worktree, ['reset', '--quiet', '--', 'tracked.txt']);

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const state = captureModule.readLiveScreenshotRepositoryState(worktree);
    expect(state.topology).toBe('linked-worktree');
    expect(state.workTree).toBe(await realpath(worktree));
    expect(state.dirtyTrackedFiles).toContain('tracked.txt');
    await expectMissing(marker);
  });

  it('rejects repository config includes before helper discovery', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-git-include-'));
    temporaryDirectories.push(root);
    const repository = join(root, 'repository');
    const includedConfig = join(root, 'included.config');
    const marker = join(root, 'included-filter-ran');
    const helper = join(root, 'included-filter.mjs');
    await mkdir(repository, { mode: 0o700 });
    const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
    await writeFile(
      helper,
      String.raw`import { writeFileSync } from 'node:fs';
writeFileSync(process.argv[2], 'included');
process.stdin.pipe(process.stdout);
`,
      'utf8'
    );
    await chmod(helper, 0o700);
    const cleanCommand = [process.execPath, helper, marker].map(shellQuote).join(' ');
    await writeFile(includedConfig, `[filter "evil"]\n\tclean = ${cleanCommand}\n`, 'utf8');
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    const runGit = (args: string[]) =>
      execFileSync(gitConfiguration.executable, args, {
        cwd: repository,
        encoding: 'utf8',
        env: gitConfiguration.environment,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      });
    runGit(['init', '--quiet']);
    runGit(['config', 'user.name', 'synthetic-live-proof']);
    runGit(['config', 'user.email', 'synthetic-live-proof@example.invalid']);
    await writeFile(join(repository, '.gitattributes'), 'tracked.txt filter=evil\n', 'utf8');
    await writeFile(join(repository, 'tracked.txt'), 'clean\n', 'utf8');
    runGit(['add', '.gitattributes', 'tracked.txt']);
    runGit(['commit', '--quiet', '-m', 'initial']);
    runGit(['config', 'include.path', includedConfig]);

    await writeFile(join(repository, 'tracked.txt'), 'dirty\n', 'utf8');
    try {
      runGit(['add', '--renormalize', 'tracked.txt']);
    } catch {
      // The vulnerable parent may fail after receiving the clean request.
    }
    expect(await readFile(marker, 'utf8')).toBe('included');
    await rm(marker, { force: true });

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    expect(() => captureModule.readLiveScreenshotRepositoryState(repository)).toThrow(
      'live screenshot repository topology is unsafe or unsupported'
    );
    await expectMissing(marker);
  });

  it('rejects include.path in applicable config.worktree before helper discovery', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-worktree-include-'));
    temporaryDirectories.push(root);
    const mainRepository = join(root, 'main');
    const worktree = join(root, 'worktree');
    const includedConfig = join(root, 'included.config');
    const marker = join(root, 'worktree-included-filter-ran');
    const helper = join(root, 'worktree-included-filter.mjs');
    await mkdir(mainRepository, { mode: 0o700 });
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    const runGit = (cwd: string, args: string[]) =>
      execFileSync(gitConfiguration.executable, args, {
        cwd,
        encoding: 'utf8',
        env: gitConfiguration.environment,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      });

    const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
    await writeFile(
      helper,
      String.raw`import { writeFileSync } from 'node:fs';
writeFileSync(process.argv[2], 'worktree-included');
process.stdin.pipe(process.stdout);
`,
      'utf8'
    );
    await chmod(helper, 0o700);
    const cleanCommand = [process.execPath, helper, marker].map(shellQuote).join(' ');
    await writeFile(includedConfig, `[filter "evil"]\n\tclean = ${cleanCommand}\n`, 'utf8');

    runGit(mainRepository, ['init', '--quiet']);
    runGit(mainRepository, ['config', 'user.name', 'synthetic-live-proof']);
    runGit(mainRepository, ['config', 'user.email', 'synthetic-live-proof@example.invalid']);
    await writeFile(join(mainRepository, '.gitattributes'), 'tracked.txt filter=evil\n', 'utf8');
    await writeFile(join(mainRepository, 'tracked.txt'), 'clean\n', 'utf8');
    runGit(mainRepository, ['add', '.gitattributes', 'tracked.txt']);
    runGit(mainRepository, ['commit', '--quiet', '-m', 'initial']);
    runGit(mainRepository, ['worktree', 'add', '--quiet', worktree, 'HEAD']);
    runGit(mainRepository, ['config', 'extensions.worktreeConfig', 'true']);
    expect(readOptionalGitConfigValue(runGit, mainRepository, 'extensions.worktreeConfig')).toBe('true');
    runGit(worktree, ['config', '--worktree', 'include.path', includedConfig]);
    expect(runGit(worktree, ['config', '--worktree', '--get', 'include.path']).trim()).toBe(includedConfig);

    await writeFile(join(worktree, 'tracked.txt'), 'dirty\n', 'utf8');
    try {
      runGit(worktree, ['add', '--renormalize', 'tracked.txt']);
    } catch {
      // The vulnerable parent may fail after receiving the clean request.
    }
    expect(await readFile(marker, 'utf8')).toBe('worktree-included');
    await rm(marker, { force: true });

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    expect(() => captureModule.readLiveScreenshotRepositoryState(worktree)).toThrow(
      'live screenshot repository topology is unsafe or unsupported'
    );
    await expectMissing(marker);
  });

  it('attests an ordinary linked worktree without extensions.worktreeConfig', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-linked-worktree-standard-'));
    temporaryDirectories.push(root);
    const mainRepository = join(root, 'main');
    const worktree = join(root, 'worktree');
    await mkdir(mainRepository, { mode: 0o700 });
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    const runGit = (cwd: string, args: string[]) =>
      execFileSync(gitConfiguration.executable, args, {
        cwd,
        encoding: 'utf8',
        env: gitConfiguration.environment,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      });

    runGit(mainRepository, ['init', '--quiet']);
    runGit(mainRepository, ['config', 'user.name', 'synthetic-live-proof']);
    runGit(mainRepository, ['config', 'user.email', 'synthetic-live-proof@example.invalid']);
    await writeFile(join(mainRepository, 'tracked.txt'), 'clean\n', 'utf8');
    runGit(mainRepository, ['add', 'tracked.txt']);
    runGit(mainRepository, ['commit', '--quiet', '-m', 'initial']);
    runGit(mainRepository, ['worktree', 'add', '--quiet', worktree, 'HEAD']);

    const extensionValue = readOptionalGitConfigValue(
      runGit,
      mainRepository,
      'extensions.worktreeConfig'
    );
    expect(extensionValue === undefined || extensionValue === 'false').toBe(true);

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const state = captureModule.readLiveScreenshotRepositoryState(worktree);
    expect(state.topology).toBe('linked-worktree');
    expect(state.workTree).toBe(await realpath(worktree));
    expect(state.clientSha).toMatch(/^[a-f0-9]{40}$/u);
    expect(state.dirtyTrackedFiles).toBe('');
  });

  it('rejects repointed linked-worktree metadata even when skip-worktree hides dirtiness', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-linked-worktree-'));
    temporaryDirectories.push(root);
    const mainRepository = join(root, 'main');
    const worktreeOne = join(root, 'wt1');
    const worktreeTwo = join(root, 'wt2');
    await mkdir(mainRepository, { mode: 0o700 });
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    const runGit = (cwd: string, args: string[]) =>
      execFileSync(gitConfiguration.executable, args, {
        cwd,
        encoding: 'utf8',
        env: gitConfiguration.environment,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      });

    runGit(mainRepository, ['init', '--quiet']);
    runGit(mainRepository, ['config', 'user.name', 'synthetic-live-proof']);
    runGit(mainRepository, ['config', 'user.email', 'synthetic-live-proof@example.invalid']);
    await writeFile(join(mainRepository, 'tracked.txt'), 'clean\n', 'utf8');
    runGit(mainRepository, ['add', 'tracked.txt']);
    runGit(mainRepository, ['commit', '--quiet', '-m', 'initial']);
    runGit(mainRepository, ['worktree', 'add', '--quiet', worktreeOne, 'HEAD']);
    runGit(mainRepository, ['worktree', 'add', '--quiet', worktreeTwo, 'HEAD']);
    runGit(worktreeTwo, ['update-index', '--skip-worktree', 'tracked.txt']);
    await writeFile(join(worktreeOne, 'tracked.txt'), 'dirty wt1\n', 'utf8');

    const worktreeTwoPointer = await readFile(join(worktreeTwo, '.git'), 'utf8');
    await writeFile(join(worktreeOne, '.git'), worktreeTwoPointer, 'utf8');
    const worktreeTwoGitDirectory = resolve(mainRepository, '.git', 'worktrees', 'wt2');
    // Complete the forged swap: wt1's .git points to wt2 metadata, and wt2's
    // metadata points back to wt1's .git. The selected skip-worktree index bit
    // remains the foreign source that makes the vulnerable status appear clean.
    await writeFile(
      join(worktreeTwoGitDirectory, 'gitdir'),
      `gitdir: ${join(worktreeOne, '.git')}\n`,
      'utf8'
    );
    const parentStatus = execFileSync(
      gitConfiguration.executable,
      [
        '--git-dir',
        worktreeTwoGitDirectory,
        '--work-tree',
        worktreeOne,
        '-c',
        `core.worktree=${worktreeOne}`,
        'status',
        '--porcelain=v1',
        '--untracked-files=no'
      ],
      {
        cwd: worktreeOne,
        encoding: 'utf8',
        env: gitConfiguration.environment,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      }
    );
    // The old identity check accepted wt2 metadata for wt1, and wt2's
    // skip-worktree bit made the dirty wt1 source appear clean.
    expect(parentStatus).toBe('');

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    expect(() => captureModule.readLiveScreenshotRepositoryState(worktreeOne)).toThrow(
      'live screenshot repository topology is unsafe or unsupported'
    );
  });

  it('ignores Git replace refs while attesting the original commit tree', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-replace-ref-'));
    temporaryDirectories.push(root);
    const repository = join(root, 'repository');
    await mkdir(repository, { mode: 0o700 });
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    const runGit = (args: string[], environment: NodeJS.ProcessEnv = gitConfiguration.environment) =>
      execFileSync(gitConfiguration.executable, args, {
        cwd: repository,
        encoding: 'utf8',
        env: environment,
        maxBuffer: 4 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe']
      });

    runGit(['init', '--quiet']);
    runGit(['config', 'user.name', 'synthetic-live-proof']);
    runGit(['config', 'user.email', 'synthetic-live-proof@example.invalid']);
    await writeFile(join(repository, 'tracked.txt'), 'original\n', 'utf8');
    runGit(['add', 'tracked.txt']);
    runGit(['commit', '--quiet', '-m', 'original']);
    const originalSha = runGit(['rev-parse', 'HEAD']).trim();
    await writeFile(join(repository, 'tracked.txt'), 'replacement tree\n', 'utf8');
    runGit(['add', 'tracked.txt']);
    runGit(['commit', '--quiet', '-m', 'replacement']);
    const replacementSha = runGit(['rev-parse', 'HEAD']).trim();
    runGit(['reset', '--hard', originalSha]);
    await writeFile(join(repository, 'tracked.txt'), 'replacement tree\n', 'utf8');
    runGit(['add', 'tracked.txt']);
    runGit(['replace', originalSha, replacementSha]);

    const parentEnvironment: NodeJS.ProcessEnv = { ...gitConfiguration.environment };
    delete parentEnvironment.GIT_NO_REPLACE_OBJECTS;
    const replacedTree = runGit(['rev-parse', 'HEAD^{tree}'], parentEnvironment).trim();
    const originalTree = runGit(['rev-parse', 'HEAD^{tree}']).trim();
    expect(replacedTree).not.toBe(originalTree);
    expect(runGit(['status', '--porcelain=v1', '--untracked-files=no'], parentEnvironment)).toBe('');

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const state = captureModule.readLiveScreenshotRepositoryState(repository);
    expect(state.clientSha).toBe(originalSha);
    expect(state.dirtyTrackedFiles).toContain('tracked.txt');
  });

  it('fails closed at the reconciliation history cap and keeps Node/page matching parity', async () => {
    const sessionId = 'synthetic-session';
    const jsonResponse = (value: unknown) => {
      // Rewrap the encoder output in the page-realm constructor used by the
      // synthetic evaluate callback; Node's encoder may return another realm's
      // Uint8Array, which the page transport must not mistake for a stream chunk.
      const bytes = Uint8Array.from(new TextEncoder().encode(JSON.stringify(value)));
      let consumed = false;
      return {
        status: 200,
        headers: {
          get(name: string) {
            return name.toLowerCase() === 'content-type' ? 'application/json' : null;
          }
        },
        body: {
          getReader() {
            return {
              async read() {
                if (consumed) return { done: true, value: undefined };
                consumed = true;
                return { done: false, value: bytes };
              },
              async cancel() {
                consumed = true;
              }
            };
          }
        }
      };
    };
    const runPageHistory = async (messages: SyntheticHistoryMessage[]) => {
      vi.stubGlobal('fetch', vi.fn(async (input: string | URL) => {
        const url = String(input);
        if (url.includes('/messages?')) {
          return jsonResponse({
            session_id: sessionId,
            messages,
            pagination: { limit: 500, offset: 0, returned: messages.length }
          });
        }
        return jsonResponse({
          sessions: [{ id: sessionId, message_count: messages.length }],
          total: 1,
          limit: 100,
          offset: 0
        });
      }));
      try {
        return await requestLiveReconciliationProjection(
          {
            evaluate: async (callback: (args: unknown) => Promise<unknown>, args: unknown) =>
              callback(args)
          },
          { baseURL: 'http://127.0.0.1:4187/', kind: 'history' }
        );
      } finally {
        vi.unstubAllGlobals();
      }
    };

    const cappedMessages: SyntheticHistoryMessage[] = Array.from({ length: 500 }, () => ({
      role: 'assistant',
      content: null
    }));
    expect(() =>
      parseReconciliationSessionMessages(
        {
          session_id: sessionId,
          messages: cappedMessages,
          pagination: { limit: 500, offset: 0, returned: 500 }
        },
        sessionId,
        500
      )
    ).toThrow('live reconciliation message pagination is not complete');
    await expect(runPageHistory(cappedMessages)).rejects.toThrow(
      'live reconciliation message pagination is not complete'
    );
    await expect(
      reconcileLiveHistory({
        sessions: [{ id: sessionId, messageCount: cappedMessages.length }],
        getMessages: async () => cappedMessages
      })
    ).rejects.toThrow('live reconciliation message pagination is not complete');

    const belowCapMessages: SyntheticHistoryMessage[] = Array.from({ length: 499 }, () => ({
      role: 'assistant',
      content: null
    }));
    expect(
      parseReconciliationSessionMessages(
        {
          session_id: sessionId,
          messages: belowCapMessages,
          pagination: { limit: 500, offset: 0, returned: 499 }
        },
        sessionId,
        499
      )
    ).toHaveLength(499);
    await expect(runPageHistory(belowCapMessages)).resolves.toEqual({
      promptMatches: 'zero',
      completedPairs: 'zero',
      status: 'no-match-uncertain'
    });

    const duplicateMarkers: SyntheticHistoryMessage[] = [
      { role: 'user', content: LIVE_PROOF_PROMPT },
      { role: 'assistant', content: LIVE_PROOF_ASSISTANT_MARKER },
      { role: 'assistant', content: LIVE_PROOF_ASSISTANT_MARKER }
    ];
    const nodeDuplicateResult = await reconcileLiveHistory({
      sessions: [{ id: sessionId, messageCount: duplicateMarkers.length }],
      getMessages: async () => duplicateMarkers
    });
    const pageDuplicateResult = await runPageHistory(duplicateMarkers);
    expect(pageDuplicateResult).toEqual(nodeDuplicateResult);
    expect(nodeDuplicateResult).toEqual({
      promptMatches: 'one',
      completedPairs: 'multiple',
      status: 'multiple-matches-ambiguous'
    });

    const fencedMarker: SyntheticHistoryMessage[] = [
      { role: 'user', content: LIVE_PROOF_PROMPT },
      { role: 'user', content: 'unrelated later turn' },
      { role: 'assistant', content: LIVE_PROOF_ASSISTANT_MARKER }
    ];
    const nodeFencedResult = await reconcileLiveHistory({
      sessions: [{ id: sessionId, messageCount: fencedMarker.length }],
      getMessages: async () => fencedMarker
    });
    const pageFencedResult = await runPageHistory(fencedMarker);
    expect(pageFencedResult).toEqual(nodeFencedResult);
    expect(nodeFencedResult).toEqual({
      promptMatches: 'one',
      completedPairs: 'zero',
      status: 'match-unattributed'
    });
  });

  it('publishes only an exact-hash independently approved image bundle', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-screenshot-contract-'));
    temporaryDirectories.push(root);
    const retainedDirectory = join(root, 'retained');
    await mkdir(retainedDirectory, { mode: 0o700 });

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const bytes = png(1440, 960);
    const imageSha256 = captureModule.sha256Hex(bytes);
    const provenance = captureModule.getLiveScreenshotChromiumProvenance();
    const repositoryRoot = resolve(process.cwd(), '../..');
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    const clientCommit = execFileSync(
      gitConfiguration.executable,
      ['-C', repositoryRoot, 'rev-parse', 'HEAD'],
      { encoding: 'utf8', env: gitConfiguration.environment }
    ).trim();
    const manifest = captureModule.createLiveScreenshotManifest({
      browserName: 'chromium',
      browserRevision: provenance.revision,
      browserVersion: provenance.version,
      browserExecutableSha256: provenance.executableSha256,
      clientSha: clientCommit,
      devicePixelRatio: 1,
      imageSha256,
      locale: 'en-US',
      timezoneId: 'UTC',
      reducedMotion: 'reduce',
      theme: 'light',
      uiState: 'ready',
      zoom: 1
    });
    const review = {
      schema: 'hermternal.independent-image-review.v1',
      decision: 'approved',
      review_kind: 'independent-human-visual',
      image_sha256: imageSha256
    };
    const capture = { bytes, manifest };

    await expect(
      captureModule.persistApprovedLiveScreenshot({
        capture,
        destinationDirectory: retainedDirectory,
        review: { ...review, image_sha256: 'b'.repeat(64) },
        provenance
      })
    ).rejects.toThrow('independent image review record was not a closed approval');

    const persisted = await captureModule.persistApprovedLiveScreenshot({
      capture,
      destinationDirectory: retainedDirectory,
      review,
      provenance
    });
    expect(persisted.manifest.review).toBe('independent-approved');
    expect(await readFile(persisted.imagePath)).toEqual(bytes);
    expect(JSON.parse(await readFile(persisted.manifestPath, 'utf8')).imageSha256).toBe(imageSha256);

    await expect(
      captureModule.persistApprovedLiveScreenshot({
        capture,
        destinationDirectory: retainedDirectory,
        review,
        provenance
      })
    ).rejects.toThrow('refuses to overwrite existing bundle');
  });

  it('rejects same-inode same-size review evidence mutation without publishing', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-review-digest-'));
    temporaryDirectories.push(root);
    const fixture = await createRetentionFixture(root);
    // safeReviewRecordEvidence requires the lexical review path to already be
    // canonical; macOS exposes the temporary directory through /tmp -> /private/tmp.
    const reviewPath = join(await realpath(root), 'review.json');
    const reviewText = `${JSON.stringify(fixture.review)}\n`;
    await writeFile(reviewPath, reviewText, { encoding: 'utf8', mode: 0o600 });
    const reviewEvidence = await createReviewEvidence(reviewPath, reviewText);

    const alternateImageSha256 = fixture.imageSha256[0] === '0'
      ? `1${fixture.imageSha256.slice(1)}`
      : `0${fixture.imageSha256.slice(1)}`;
    const mutatedReview = {
      ...fixture.review,
      image_sha256: alternateImageSha256
    };
    expect(
      fixture.captureModule.validateIndependentImageReviewRecord(
        mutatedReview,
        alternateImageSha256
      )
    ).toEqual(mutatedReview);
    const mutatedReviewText = `${JSON.stringify(mutatedReview)}\n`;
    expect(Buffer.byteLength(mutatedReviewText, 'utf8')).toBe(
      Buffer.byteLength(reviewText, 'utf8')
    );
    const beforeMutation = await lstat(reviewPath);
    const beforeDigest = createHash('sha256').update(reviewText, 'utf8').digest('hex');
    await writeFile(reviewPath, mutatedReviewText, 'utf8');
    const afterMutation = await lstat(reviewPath);
    const afterDigest = createHash('sha256').update(mutatedReviewText, 'utf8').digest('hex');
    expect(mutatedReviewText).not.toBe(reviewText);
    expect(afterDigest).not.toBe(beforeDigest);
    expect(afterMutation.dev).toBe(beforeMutation.dev);
    expect(afterMutation.ino).toBe(beforeMutation.ino);
    expect(afterMutation.size).toBe(beforeMutation.size);

    await expect(
      fixture.captureModule.persistApprovedLiveScreenshot({
        capture: fixture.capture,
        destinationDirectory: fixture.retainedDirectory,
        review: fixture.review,
        reviewEvidence,
        provenance: fixture.provenance
      })
    ).rejects.toThrow('live screenshot retention review record changed');
    await expectMissing(join(fixture.retainedDirectory, 'hermternal-chat-proof.bundle'));
  });

  it('rejects a semantically valid review mutation after preflight and before atomic rename', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-review-callback-'));
    temporaryDirectories.push(root);
    const fixture = await createRetentionFixture(root);
    const reviewPath = join(await realpath(root), 'review.json');
    const reviewText = `${JSON.stringify(fixture.review)}\n`;
    await writeFile(reviewPath, reviewText, { encoding: 'utf8', mode: 0o600 });
    const reviewEvidence = await createReviewEvidence(reviewPath, reviewText);
    const alternateImageSha256 = fixture.imageSha256[0] === '0'
      ? `1${fixture.imageSha256.slice(1)}`
      : `0${fixture.imageSha256.slice(1)}`;
    const mutatedReview = { ...fixture.review, image_sha256: alternateImageSha256 };
    const mutatedReviewText = `${JSON.stringify(mutatedReview)}\n`;
    expect(
      fixture.captureModule.validateIndependentImageReviewRecord(
        mutatedReview,
        alternateImageSha256
      )
    ).toEqual(mutatedReview);
    expect(Buffer.byteLength(mutatedReviewText, 'utf8')).toBe(
      Buffer.byteLength(reviewText, 'utf8')
    );
    let atomicRenameObserved = false;
    const bundlePath = join(fixture.retainedDirectory, 'hermternal-chat-proof.bundle');

    await expect(
      fixture.captureModule.persistApprovedLiveScreenshot({
        capture: fixture.capture,
        destinationDirectory: fixture.retainedDirectory,
        review: fixture.review,
        reviewEvidence,
        provenance: fixture.provenance,
        beforeAtomicPublish: async () => {
          await writeFile(reviewPath, mutatedReviewText, 'utf8');
        },
        afterAtomicPublishBeforeVerify: async () => {
          atomicRenameObserved = true;
        }
      })
    ).rejects.toThrow('live screenshot retention review record changed');

    expect(atomicRenameObserved).toBe(false);
    await expectMissing(bundlePath);
    expect(JSON.parse(await readFile(reviewPath, 'utf8'))).toEqual(mutatedReview);
  });

  it('rejects an unexpected staged entry inside the atomic child', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-staged-shape-'));
    temporaryDirectories.push(root);
    const fixture = await createRetentionFixture(root);
    const bundlePath = join(fixture.retainedDirectory, 'hermternal-chat-proof.bundle');

    await expect(
      fixture.captureModule.persistApprovedLiveScreenshot({
        capture: fixture.capture,
        destinationDirectory: fixture.retainedDirectory,
        review: fixture.review,
        provenance: fixture.provenance,
        beforeAtomicPublish: async (stagingDirectory) => {
          await writeFile(join(stagingDirectory, 'unexpected.txt'), 'unexpected\n', {
            encoding: 'utf8',
            flag: 'wx',
            mode: 0o600
          });
        }
      })
    ).rejects.toThrow('live screenshot retention publication and cleanup failed');

    await expectMissing(bundlePath);
  });

  it('preserves a tainted bundle when an unexpected entry appears after enumeration', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-published-shape-'));
    temporaryDirectories.push(root);
    const fixture = await createRetentionFixture(root);
    const bundlePath = join(fixture.retainedDirectory, 'hermternal-chat-proof.bundle');
    let initialEntries: string[] = [];

    await expect(
      fixture.captureModule.persistApprovedLiveScreenshot({
        capture: fixture.capture,
        destinationDirectory: fixture.retainedDirectory,
        review: fixture.review,
        provenance: fixture.provenance,
        afterPublishedEnumeration: async (publishedBundlePath) => {
          initialEntries = (await readdir(publishedBundlePath)).sort();
          await writeFile(join(publishedBundlePath, 'unexpected.txt'), 'unexpected\n', {
            encoding: 'utf8',
            flag: 'wx',
            mode: 0o600
          });
        }
      })
    ).rejects.toThrow('live screenshot retention publication and cleanup failed');

    expect(initialEntries).toEqual(['manifest.json', 'screenshot.png']);
    expect((await readdir(bundlePath)).sort()).toEqual([
      'manifest.json',
      'screenshot.png',
      'unexpected.txt'
    ]);
    expect(await readFile(join(bundlePath, 'unexpected.txt'), 'utf8')).toBe('unexpected\n');
    expect(await readFile(join(bundlePath, 'screenshot.png'))).toEqual(fixture.bytes);
    expect(JSON.parse(await readFile(join(bundlePath, 'manifest.json'), 'utf8')).imageSha256).toBe(
      fixture.imageSha256
    );
  });

  it.each(['screenshot.png', 'manifest.json'] as const)(
    'rejects a same-size staged %s mutation before atomic publish and leaves no public bundle',
    async (entry) => {
      const root = await mkdtemp(join(tmpdir(), 'hermternal-live-staged-digest-'));
      temporaryDirectories.push(root);
      const fixture = await createRetentionFixture(root);
      const bundlePath = join(fixture.retainedDirectory, 'hermternal-chat-proof.bundle');
      let originalBytes: Buffer | undefined;
      let mutationObserved = false;

      await expect(
        fixture.captureModule.persistApprovedLiveScreenshot({
          capture: fixture.capture,
          destinationDirectory: fixture.retainedDirectory,
          review: fixture.review,
          provenance: fixture.provenance,
          beforeAtomicPublish: async (stagingDirectory) => {
            await expectMissing(bundlePath);
            originalBytes = await mutateSameSizeFile(join(stagingDirectory, entry));
            mutationObserved = true;
          },
          beforeStagingCleanup: async (stagingDirectory) => {
            if (!originalBytes) throw new Error('staged mutation did not capture original bytes');
            await writeFile(join(stagingDirectory, entry), originalBytes);
          }
        })
      ).rejects.toThrow('live screenshot retention bundle publication failed');

      expect(mutationObserved).toBe(true);
      await expectMissing(bundlePath);
    }
  );

  it.each(['screenshot.png', 'manifest.json'] as const)(
    'rejects a same-size published %s mutation and removes the tainted bundle',
    async (entry) => {
      const root = await mkdtemp(join(tmpdir(), 'hermternal-live-published-digest-'));
      temporaryDirectories.push(root);
      const fixture = await createRetentionFixture(root);
      const bundlePath = join(fixture.retainedDirectory, 'hermternal-chat-proof.bundle');
      let mutationObserved = false;

      const expectedVerificationError = entry === 'screenshot.png'
        ? 'live screenshot retention published PNG changed'
        : 'live screenshot retention published manifest changed';
      await expect(
        fixture.captureModule.persistApprovedLiveScreenshot({
          capture: fixture.capture,
          destinationDirectory: fixture.retainedDirectory,
          review: fixture.review,
          provenance: fixture.provenance,
          afterAtomicPublishBeforeVerify: async (publishedBundlePath) => {
            const publishedStats = await lstat(publishedBundlePath);
            expect(publishedStats.isDirectory()).toBe(true);
            await mutateSameSizeFile(join(publishedBundlePath, entry));
            mutationObserved = true;
          }
        })
      ).rejects.toThrow(expectedVerificationError);

      expect(mutationObserved).toBe(true);
      await expectMissing(bundlePath);
    }
  );
});
