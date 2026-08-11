import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
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
  'fsmonitor-helper parent bypass',
  'clean/process filters',
  'reciprocal linked-worktree metadata',
  'GIT_NO_REPLACE_OBJECTS'
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
    expect(captureSource).toContain('GIT_NO_REPLACE_OBJECTS');
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

  it('rejects a local core.worktree bypass without executing fsmonitor helpers', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-git-provenance-'));
    temporaryDirectories.push(root);
    const repository = join(root, 'repository');
    const alternateWorktree = join(root, 'alternate-worktree');
    const helperMarker = join(root, 'fsmonitor-helper-ran');
    const helper = join(root, 'fsmonitor-helper.mjs');
    const attributesFile = join(root, 'attributes');
    const hooks = join(root, 'hooks');
    await mkdir(repository, { mode: 0o700 });
    await mkdir(alternateWorktree, { mode: 0o700 });
    await mkdir(hooks, { mode: 0o700 });
    await writeFile(
      helper,
      `#!${process.execPath}\nimport { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(helperMarker)}, 'ran');\n`,
      'utf8'
    );
    await chmod(helper, 0o700);
    await writeFile(attributesFile, '*.txt filter=evil\n', 'utf8');

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
    await writeFile(join(repository, 'tracked.txt'), 'clean\n', 'utf8');
    await writeFile(join(alternateWorktree, 'tracked.txt'), 'clean\n', 'utf8');
    runGit(['add', 'tracked.txt']);
    runGit([
      '-c',
      'user.name=synthetic-live-proof',
      '-c',
      'user.email=synthetic-live-proof@example.invalid',
      'commit',
      '--quiet',
      '-m',
      'initial'
    ]);
    runGit(['config', 'core.worktree', alternateWorktree]);
    runGit(['config', 'core.fsmonitor', helper]);
    runGit(['config', 'core.hooksPath', hooks]);
    runGit(['config', 'core.attributesFile', attributesFile]);
    runGit(['config', 'filter.evil.clean', helper]);
    runGit(['config', 'filter.evil.process', helper]);
    await writeFile(join(repository, 'tracked.txt'), 'dirty actual worktree\n', 'utf8');

    // This is the vulnerable parent behavior: repository-local core.worktree
    // redirects status to the clean alternate path, core.fsmonitor runs a
    // helper, and the attributes/filter pair can run a clean/process helper.
    try {
      runGit(['status', '--porcelain=v1', '--untracked-files=no']);
    } catch {
      // A malicious filter is allowed to make the vulnerable parent command
      // fail; helper execution is the non-vacuous part of this reproduction.
    }
    expect(await readFile(helperMarker, 'utf8')).toBe('ran');
    await rm(helperMarker, { force: true });

    const captureModule = await import('../../tests/live/live-screenshot-capture.mjs');
    const state = captureModule.readLiveScreenshotRepositoryState(repository);
    expect(state.topology).toBe('directory');
    expect(state.workTree).not.toBe(alternateWorktree);
    expect(state.clientSha).toMatch(/^[a-f0-9]{40}$/u);
    expect(state.dirtyTrackedFiles).toContain('tracked.txt');
    await expect(readFile(helperMarker, 'utf8')).rejects.toThrow();
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

    const replacementFirstByte = fixture.imageSha256[0] === '0' ? '1' : '0';
    const mutatedReviewText = reviewText.replace(
      fixture.imageSha256,
      `${replacementFirstByte}${fixture.imageSha256.slice(1)}`
    );
    const beforeMutation = await lstat(reviewPath);
    await writeFile(reviewPath, mutatedReviewText, 'utf8');
    const afterMutation = await lstat(reviewPath);
    expect(mutatedReviewText).not.toBe(reviewText);
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
