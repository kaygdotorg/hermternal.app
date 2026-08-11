import { execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  LIVE_SCREENSHOT_COMMAND,
  LIVE_SCREENSHOT_PUBLIC_CONTRACT,
  blockedLiveScreenshotManifest,
  captureReviewedLiveScreenshots,
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
  'duplicate exact assistant markers'
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
      // cannot execute their isolated historical module fixtures reliably.
      const output = execFileSync('node', [resolve(appRoot, probe)], {
        cwd: repositoryRoot,
        encoding: 'utf8',
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

  it('publishes only scrubbed and independently approved exact-dimension images', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hermternal-live-screenshot-contract-'));
    temporaryDirectories.push(root);
    const outputRoot = join(root, 'output');
    const retainedDirectory = join(root, 'retained');
    await mkdir(outputRoot);
    const scrubHook = join(root, 'scrub.mjs');
    const reviewHook = join(root, 'review.mjs');
    await writeFile(
      scrubHook,
      `#!${process.execPath}\nimport { copyFile } from 'node:fs/promises';\nawait copyFile(process.argv[2], process.argv[3]);\n`
    );
    await writeFile(
      reviewHook,
      `#!${process.execPath}\nimport { createHash } from 'node:crypto';\nimport { readFile, writeFile } from 'node:fs/promises';\nconst bytes = await readFile(process.argv[2]);\nconst image_sha256 = createHash('sha256').update(bytes).digest('hex');\nawait writeFile(process.argv[3], JSON.stringify({ schema: 'hermternal.independent-image-review.v1', decision: 'approved', review_kind: 'independent-human-visual', image_sha256 }));\n`
    );
    await chmod(scrubHook, 0o700);
    await chmod(reviewHook, 0o700);

    let viewport = { width: 1440, height: 960 };
    let evaluateCount = 0;
    const page = {
      setViewportSize: async (next: typeof viewport) => { viewport = next; },
      evaluate: async () => {
        evaluateCount += 1;
        if (evaluateCount % 2 === 0) return undefined;
        return {
          pathname: '/', search: '', hash: '',
          width: viewport.width, height: viewport.height,
          dpr: 1, zoom: 1, locale: 'en-US', themeDark: false,
          reducedMotion: true, readyState: 'complete', workspaceState: 'ready', composerPresent: true
        };
      },
      screenshot: async ({ path }: { path: string }) => writeFile(path, png(viewport.width, viewport.height))
    };
    const repositoryRoot = resolve(process.cwd(), '../..');
    const clientCommit = execFileSync('git', ['-C', repositoryRoot, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const manifest = await captureReviewedLiveScreenshots({
      page: page as unknown as import('@playwright/test').Page,
      outputRoot,
      retainedDirectory,
      repositoryRoot,
      clientCommit,
      scrubHook,
      reviewHook
    });

    expect(manifest.status).toBe('complete');
    expect(manifest.images).toHaveLength(2);
    expect(manifest.images.map((image: { width: number; height: number }) => [image.width, image.height])).toEqual([
      [1440, 960],
      [390, 844]
    ]);
    expect(JSON.parse(await readFile(join(retainedDirectory, 'capture-manifest.json'), 'utf8'))).toEqual(manifest);
    const retainedDesktop = await readFile(join(retainedDirectory, manifest.images[0].file));
    expect(retainedDesktop).toEqual(png(1440, 960));

    // A rerun must not replace reviewed evidence or remove the prior files when
    // exclusive publication detects the existing destination.
    await expect(
      captureReviewedLiveScreenshots({
        page: page as unknown as import('@playwright/test').Page,
        outputRoot,
        retainedDirectory,
        repositoryRoot,
        clientCommit,
        scrubHook,
        reviewHook
      })
    ).rejects.toMatchObject({ code: 'EEXIST' });
    expect(await readFile(join(retainedDirectory, manifest.images[0].file))).toEqual(retainedDesktop);
    expect(JSON.parse(await readFile(join(retainedDirectory, 'capture-manifest.json'), 'utf8'))).toEqual(manifest);
  });
});
