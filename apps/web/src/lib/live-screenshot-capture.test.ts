import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { promises as fsPromises } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { render } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import WorkspacePreview from './workspace/WorkspacePreview.svelte';
import {
  createLivePlaywrightConfig,
  getLivePlaywrightPaths
} from '../../tests/live/live-playwright-config.mjs';
import {
  LIVE_PROOF_ASSISTANT_MARKER,
  LIVE_PROOF_PROMPT
} from '../../tests/live/live-proof-ledger.mjs';
import {
  captureLiveChatScreenshotIfEnabled,
  createLiveScreenshotManifest,
  getLiveScreenshotAtomicRenameChildConfiguration,
  getLiveScreenshotChromiumProvenance,
  getLiveScreenshotChromiumRegistry,
  persistApprovedLiveScreenshot,
  sanitizeLiveChatCapturePresentation,
  serializeLiveScreenshotManifest,
  sha256Hex,
  validateLiveScreenshotManifest
} from '../../tests/live/live-screenshot-capture.mjs';

const browserPrerequisiteEnabled = process.env.HERMTERNAL_LIVE_SCREENSHOT_BROWSER_PREREQUISITE === '1';
const chromiumForPrerequisite = () => createRequire(import.meta.url)('playwright').chromium;

const PNG_BYTES = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  Buffer.from('synthetic-approved-png', 'utf8')
]);
const CLIENT_SHA = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const COMPLETE_LIVE_PROOF = Object.freeze({
  ordered: true,
  websocketOpen: true,
  gatewayReady: true,
  serverFirstReady: true,
  sessionAction: true,
  prompt: true,
  promptAcknowledgement: true,
  delta: true,
  completion: true,
  history: true,
  historyStatusOk: true,
  messageCount: 2,
  promptCount: 1,
  completionCount: 1
});
const FAILED_LIVE_PROOF = Object.freeze({ ...COMPLETE_LIVE_PROOF, ordered: false, completion: false });
const CONTROLLED_TEST_PROVENANCE = Object.freeze({
  ...getLiveScreenshotChromiumRegistry(),
  executablePath: '/controlled/chromium-1234/chrome',
  canonicalPath: '/controlled/chromium-1234/chrome',
  executableSha256: 'a'.repeat(64),
  dev: 1,
  ino: 1
});
const temporaryRoots: string[] = [];
const temporaryGlobalRestores: Array<() => void> = [];

function installSyntheticBrowserStorage() {
  const storage = () => {
    const values = new Map<string, string>();
    return {
      get length() {
        return values.size;
      },
      key(index: number) {
        return [...values.keys()][index] ?? null;
      },
      getItem(key: string) {
        return values.get(key) ?? null;
      },
      setItem(key: string, value: string) {
        values.set(key, String(value));
      },
      removeItem(key: string) {
        values.delete(key);
      },
      clear() {
        values.clear();
      }
    };
  };
  const syntheticValues: Record<string, unknown> = {
    localStorage: storage(),
    sessionStorage: storage(),
    indexedDB: {
      databases: async () => [],
      open: () => {
        throw new Error('synthetic IndexedDB is empty');
      }
    },
    caches: {
      keys: async () => [],
      open: async () => ({ keys: async () => [], match: async () => undefined }),
      delete: async () => true
    }
  };
  for (const [name, value] of Object.entries(syntheticValues)) {
    const previous = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, {
      configurable: true,
      enumerable: previous?.enumerable ?? true,
      writable: true,
      value
    });
    temporaryGlobalRestores.push(() => {
      if (previous) Object.defineProperty(globalThis, name, previous);
      else delete (globalThis as Record<string, unknown>)[name];
    });
  }
}

type FakePageOptions = {
  bytes?: Buffer;
  route?: string;
  viewport?: { width: number; height: number };
  browserVersion?: string;
  executablePath?: string;
  provenance?: ReturnType<typeof getLiveScreenshotChromiumRegistry> & {
    executablePath: string;
    canonicalPath: string;
    executableSha256: string;
    dev: number;
    ino: number;
  };
  beforeLocatorScreenshot?: () => Promise<void>;
};

function captureEnvironment(extra: Record<string, string | undefined> = {}) {
  return {
    HERMTERNAL_LIVE_SCREENSHOT_CAPTURE: '1',
    HERMTERNAL_PAPER_PARITY_APPROVED: '1',
    HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA: CLIENT_SHA,
    ...extra
  };
}

function fakePage(options: FakePageOptions = {}) {
  const bytes = options.bytes ?? PNG_BYTES;
  const pinned = options.provenance ?? CONTROLLED_TEST_PROVENANCE;
  const defaultExecutablePath = pinned.executablePath;
  const locatorScreenshot = vi.fn(async () => {
    await options.beforeLocatorScreenshot?.();
    return bytes;
  });
  let cookies: unknown[] = [];
  const pageContext = {
    browser: () => ({
      browserType: () => ({
        name: () => 'chromium',
        executablePath: () => options.executablePath ?? defaultExecutablePath
      }),
      version: () => options.browserVersion ?? pinned.version
    }),
    cookies: vi.fn(async () => cookies),
    clearCookies: vi.fn(async () => {
      cookies = [];
    })
  };
  const page = {
    url: () => `http://127.0.0.1:4187${options.route ?? '/'}`,
    viewportSize: () => options.viewport ?? { width: 1440, height: 960 },
    context: () => pageContext,
    emulateMedia: vi.fn(async () => undefined),
    evaluate: vi.fn(async (pageFunction: unknown) => {
      if (pageFunction === sanitizeLiveChatCapturePresentation) {
        return {
          sanitized: true,
          captureSelector: '[data-capture-root="live-chat"]',
          removedValueCount: 3,
          prohibitedNodeCount: 0,
          privacy: {
            localStorageCleared: true,
            sessionStorageCleared: true,
            indexedDbCleared: true,
            cacheStorageCleared: true,
            serviceWorkerCacheCleared: true,
            localStorageEntries: 0,
            sessionStorageEntries: 0,
            indexedDbDatabases: 0,
            indexedDbStores: 0,
            indexedDbRecords: 0,
            cacheNames: 0,
            cacheRequests: 0,
            cacheHeaders: 0,
            cacheBodyBytes: 0
          }
        };
      }
      return {
        devicePixelRatio: 1,
        locale: 'en-US',
        reducedMotion: 'reduce',
        theme: 'light',
        zoom: 1
      };
    }),
    locator: vi.fn((selector: string) => {
      if (selector !== '[data-capture-root="live-chat"]') throw new Error('unexpected capture selector');
      return { screenshot: locatorScreenshot };
    }),
    screenshot: vi.fn(async () => bytes),
    locatorScreenshot
  };
  return page;
}

function manifestFixture() {
  const pinned = getLiveScreenshotChromiumRegistry();
  return createLiveScreenshotManifest({
    browserName: 'chromium',
    browserRevision: pinned.revision,
    browserVersion: pinned.version,
    browserExecutableSha256: CONTROLLED_TEST_PROVENANCE.executableSha256,
    clientSha: CLIENT_SHA,
    devicePixelRatio: 1,
    imageSha256: sha256Hex(PNG_BYTES),
    locale: 'en-US',
    reducedMotion: 'reduce',
    theme: 'light',
    uiState: 'ready',
    zoom: 1
  });
}

async function temporaryDirectory() {
  const root = await fsPromises.mkdtemp(join(tmpdir(), 'hermternal-live-screenshot-test-'));
  temporaryRoots.push(root);
  return root;
}

async function startTestOrigin() {
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end('<!doctype html><html><body>test origin</body></html>');
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('test origin did not expose a TCP address');
  }
  return { server, url: `http://127.0.0.1:${address.port}/` };
}

afterEach(async () => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    if (root) await fsPromises.rm(root, { recursive: true, force: true });
  }
  while (temporaryGlobalRestores.length > 0) {
    temporaryGlobalRestores.pop()?.();
  }
});

describe('deterministic live Chat screenshot capture', () => {
  it('is default-off and does not touch the page', async () => {
    const screenshot = vi.fn();
    const result = await captureLiveChatScreenshotIfEnabled({
      page: { screenshot },
      uiState: 'ready',
      environment: {}
    });

    expect(result).toBeUndefined();
    expect(screenshot).not.toHaveBeenCalled();
  });

  it('refuses capture and retention when the causal official-Hermes proof is incomplete', async () => {
    const page = fakePage();
    await expect(
      captureLiveChatScreenshotIfEnabled({
        page,
        uiState: 'ready',
        proof: FAILED_LIVE_PROOF,
        environment: captureEnvironment(),
        provenance: CONTROLLED_TEST_PROVENANCE
      })
    ).rejects.toThrow('complete causal Hermes proof');
    expect(page.emulateMedia).not.toHaveBeenCalled();
    expect(page.evaluate).not.toHaveBeenCalled();
    expect(page.locatorScreenshot).not.toHaveBeenCalled();
  });

  it('sanitizes real live component DOM before the capture-only presentation', async () => {
    render(WorkspacePreview, {
      state: 'ready',
      dataSource: 'live-runtime',
      dataMode: 'live',
      artifactInspectorEnabled: false,
      model: 'PRIVATE PROVIDER MODEL',
      title: 'private live title',
      sessions: [
        {
          id: 'live-session',
          title: 'private session title',
          detail: 'private session detail',
          group: 'recent'
        }
      ],
      timelineItems: [
        { kind: 'user-message', id: 'user-1', text: 'private user prompt' },
        {
          kind: 'assistant-message',
          id: 'assistant-1',
          text: 'private assistant transcript',
          model: 'private model'
        },
        {
          kind: 'tool',
          id: 'tool-1',
          label: 'private tool name',
          detail: 'private tool output',
          status: 'completed'
        }
      ]
    });

    const preview = document.querySelector('[data-testid="runtime-preview"]');
    expect(preview).toBeTruthy();
    expect(preview?.textContent).toContain('private user prompt');
    expect(preview?.querySelector('[data-live-content="conversation-timeline"]')).toBeTruthy();
    expect(preview?.querySelector('.header-model')).toHaveTextContent('PRIVATE PROVIDER MODEL');
    expect(preview?.querySelector('.model-control option')).toHaveTextContent('Atlas · balanced');
    expect([...preview!.querySelectorAll('.group-count')].map((node) => node.textContent)).toEqual([
      '0',
      '1'
    ]);

    installSyntheticBrowserStorage();
    const result = await sanitizeLiveChatCapturePresentation();
    expect(result).toMatchObject({
      sanitized: true,
      captureSelector: '[data-capture-root="live-chat"]',
      removedValueCount: expect.any(Number),
      prohibitedNodeCount: 0
    });
    expect(preview?.querySelector('[data-live-content]')).toBeNull();
    expect(preview?.querySelector('.user-message, .assistant-copy, .tool-row')).toBeNull();
    expect(preview?.querySelector('[data-capture-placeholder="conversation"]')).toHaveTextContent(
      'Conversation preview'
    );
    expect(preview?.textContent).not.toContain('private user prompt');
    expect(preview?.textContent).not.toContain('private assistant transcript');
    expect(preview?.textContent).not.toContain('private tool output');
    expect(preview?.textContent).not.toContain('private session title');
    expect(preview?.textContent).not.toContain('private live title');
    expect(preview?.textContent).not.toContain('PRIVATE PROVIDER MODEL');
    expect(preview?.querySelector('.header-model')).toHaveTextContent('Model');
    expect(preview?.querySelector('.header-model')).toHaveAttribute('aria-label', 'Current model');
    expect([...preview!.querySelectorAll('.group-count')].map((node) => node.textContent)).toEqual([
      '—',
      '—'
    ]);
    expect([...preview!.querySelectorAll('.group-count')].map((node) => node.textContent)).not.toContain('1');
    expect(preview?.querySelector('.model-control .model-short')).toHaveTextContent('Model');
    expect([...preview!.querySelectorAll('.model-control option')]).toHaveLength(1);
    expect(preview?.querySelector('.model-control option')).toHaveTextContent('Model');
    expect(preview?.querySelector<HTMLSelectElement>('.model-control select')?.value).toBe('Model');
  });

  it.skipIf(!browserPrerequisiteEnabled)('scrubs metadata in the real Chromium page realm', async () => {
    const browser = await chromiumForPrerequisite().launch({
      headless: true,
      executablePath: getLiveScreenshotChromiumProvenance().executablePath
    });
    const origin = await startTestOrigin();
    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(origin.url);
      await page.setContent(`
        <section data-testid="runtime-preview">
          <section data-live-content="conversation-timeline">
            <p class="assistant-copy">PRIVATE TRANSCRIPT</p>
          </section>
          <div class="header-model" aria-label="Current model PRIVATE PROVIDER MODEL">
            <span>PRIVATE PROVIDER MODEL</span>
          </div>
          <span class="group-count">1</span>
        </section>
      `);

      await expect(page.evaluate(sanitizeLiveChatCapturePresentation)).resolves.toMatchObject({
        sanitized: true,
        prohibitedNodeCount: 0
      });
      await expect(
        page.evaluate(() => ({
          model: document.querySelector('.header-model')?.textContent?.trim(),
          modelLabel: document.querySelector('.header-model')?.getAttribute('aria-label'),
          count: document.querySelector('.group-count')?.textContent,
          sourceModel: document.documentElement.outerHTML.includes('PRIVATE PROVIDER MODEL'),
          sourceCount: document.querySelector('.group-count')?.textContent === '1'
        }))
      ).resolves.toEqual({
        model: 'Model',
        modelLabel: 'Current model',
        count: '—',
        sourceModel: false,
        sourceCount: false
      });
      await context.close();
    } finally {
      await browser.close();
      await new Promise<void>((resolve) => origin.server.close(() => resolve()));
    }
  });

  it.skipIf(!browserPrerequisiteEnabled)('scrubs short metadata values across duplicate nodes, storage, and serialized capture DOM', async () => {
    const browser = await chromiumForPrerequisite().launch({ headless: true, executablePath: getLiveScreenshotChromiumProvenance().executablePath });
    const origin = await startTestOrigin();
    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(origin.url);
      await page.setContent(`
        <div data-capture-wrapper>
          <section data-testid="runtime-preview">
            <section data-live-content="conversation-timeline"><p class="assistant-copy">PRIVATE TRANSCRIPT</p></section>
            <div class="header-model" data-model="Q" aria-label="Current model Q" title="Q"><span>Q</span></div>
            <div class="header-model" data-model="7" aria-label="Current model 7" title="7"><span>7</span></div>
            <span class="group-count" data-count="Q" aria-label="Q" title="Q" value="Q">Q</span>
            <span class="group-count" data-count="7" aria-label="7" title="7" value="7">7</span>
            <label class="model-control" data-model="Q" aria-label="Q" title="Q">
              <span class="model-short">Q</span>
              <select aria-label="Model" title="Q" data-selected="Q">
                <option value="Atlas · balanced">Atlas · balanced</option>
                <option value="Q">Q</option>
              </select>
            </label>
          </section>
        </div>
      `);
      await page.evaluate(() => {
        localStorage.setItem('Q', '7');
        sessionStorage.setItem('7', 'Q');
      });

      await expect(page.evaluate(sanitizeLiveChatCapturePresentation)).resolves.toMatchObject({
        sanitized: true,
        captureSelector: '[data-capture-root="live-chat"]',
        prohibitedNodeCount: 0
      });
      const result = await page.evaluate(() => {
        const source = document.querySelector('[data-testid="runtime-preview"]');
        return {
          sourceText: source?.textContent,
          sourceMarkup: document.documentElement.outerHTML,
          captureMarkup: document.querySelector('[data-capture-root="live-chat"]')?.outerHTML,
          metadataMarkup: [...(source?.querySelectorAll('.header-model, .group-count, .model-control, .model-control select, .model-control option') ?? [])]
            .map((node) => node.outerHTML)
            .join('\\n'),
          localStorageLength: localStorage.length,
          sessionStorageLength: sessionStorage.length,
          models: [...(source?.querySelectorAll('.header-model') ?? [])].map((node) => node.textContent?.trim()),
          counts: [...(source?.querySelectorAll('.group-count') ?? [])].map((node) => node.textContent?.trim()),
          options: [...(source?.querySelectorAll('.model-control option') ?? [])].map((node) => node.textContent?.trim())
        };
      });
      expect(result.sourceText).not.toContain('Q');
      expect(result.sourceText).not.toContain('7');
      expect(result.sourceMarkup).not.toContain('Q');
      expect(result.captureMarkup).not.toContain('Q');
      expect(result.metadataMarkup).not.toContain('Q');
      expect(result.metadataMarkup).not.toContain('7');
      expect(result.localStorageLength).toBe(0);
      expect(result.sessionStorageLength).toBe(0);
      expect(result.models).toEqual(['Model', 'Model']);
      expect(result.counts).toEqual(['—', '—']);
      expect(result.options).toEqual(['Model']);
      await context.close();
    } finally {
      await browser.close();
      await new Promise<void>((resolve) => origin.server.close(() => resolve()));
    }
  });

  it.skipIf(!browserPrerequisiteEnabled)('fails closed and clears cookies, IndexedDB, Cache Storage, and service-worker cache markers', async () => {
    const browser = await chromiumForPrerequisite().launch({
      headless: true,
      executablePath: getLiveScreenshotChromiumProvenance().executablePath
    });
    const origin = await startTestOrigin();
    const markers = {
      password: 'private-password-marker',
      prompt: LIVE_PROOF_PROMPT,
      completion: LIVE_PROOF_ASSISTANT_MARKER,
      ticket: 'private-ticket-marker'
    };
    try {
      const context = await browser.newContext();
      const page = await context.newPage();
      await page.goto(origin.url);
      await page.setContent(`
        <main>
          <section data-testid="runtime-preview">
            <section data-live-content="conversation-timeline"><p>Conversation preview</p></section>
            <div class="header-model" aria-label="Current model"><span>Model</span></div>
            <span class="group-count">—</span>
          </section>
        </main>
      `);
      await page.evaluate(async (values: typeof markers) => {
        document.cookie = `hermternal-proof=${encodeURIComponent(values.password)}; Path=/`;
        localStorage.setItem('proof-password', values.password);
        sessionStorage.setItem('proof-prompt', values.prompt);

        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.open('hermternal-proof-database', 1);
          request.onupgradeneeded = () => {
            request.result.createObjectStore('proof-records');
          };
          request.onerror = () => reject(request.error ?? new Error('indexedDB setup failed'));
          request.onsuccess = () => {
            const database = request.result;
            const transaction = database.transaction('proof-records', 'readwrite');
            transaction.objectStore('proof-records').put({ value: values.password }, 'proof');
            transaction.oncomplete = () => {
              database.close();
              resolve();
            };
            transaction.onerror = () => reject(transaction.error ?? new Error('indexedDB write failed'));
          };
        });

        const cache = await caches.open('hermternal-prototype-assets');
        const cacheRequest = new Request(
          `${location.origin}/private/${encodeURIComponent(values.password)}`,
          { headers: { 'x-proof-request': values.prompt } }
        );
        const cacheResponse = new Response(values.completion, {
          headers: {
            'content-type': 'text/plain',
            'x-proof-response': values.ticket
          }
        });
        await cache.put(cacheRequest, cacheResponse);
      }, markers);

      const result = await page.evaluate(
        sanitizeLiveChatCapturePresentation,
        Object.values(markers)
      );
      expect(result).toMatchObject({
        sanitized: true,
        prohibitedNodeCount: 0,
        privacy: {
          localStorageCleared: true,
          sessionStorageCleared: true,
          indexedDbCleared: true,
          cacheStorageCleared: true,
          serviceWorkerCacheCleared: true
        }
      });
      await expect(
        page.evaluate(async () => ({
          cookieCleared: document.cookie === '',
          localStorageEntries: localStorage.length,
          sessionStorageEntries: sessionStorage.length,
          indexedDbDatabases: (await indexedDB.databases()).length,
          cacheNames: (await caches.keys()).length
        }))
      ).resolves.toEqual({
        cookieCleared: true,
        localStorageEntries: 0,
        sessionStorageEntries: 0,
        indexedDbDatabases: 0,
        cacheNames: 0
      });
      await context.close();
    } finally {
      await browser.close();
      await new Promise<void>((resolve) => origin.server.close(() => resolve()));
    }
  });

  it.skipIf(!browserPrerequisiteEnabled)('captures the frozen clone when the live DOM is repopulated before screenshot', async () => {
    const browser = await chromiumForPrerequisite().launch({ headless: true, executablePath: getLiveScreenshotChromiumProvenance().executablePath });
    const origin = await startTestOrigin();
    const markup = `
      <div style="width: 1440px; height: 960px">
        <section data-testid="runtime-preview">
          <section data-live-content="conversation-timeline"><div data-capture-placeholder="conversation">Conversation preview</div></section>
          <div class="header-model" aria-label="Current model"><span>Model</span></div>
          <span class="group-count">—</span>
        </section>
      </div>
    `;
    try {
      const baselineContext = await browser.newContext({ viewport: { width: 1440, height: 960 }, deviceScaleFactor: 1 });
      const baselinePage = await baselineContext.newPage();
      await baselinePage.goto(origin.url);
      await baselinePage.setContent(markup);
      const baseline = await captureLiveChatScreenshotIfEnabled({
        page: baselinePage,
        uiState: 'ready',
        environment: captureEnvironment()
      });
      await baselineContext.close();

      const attackContext = await browser.newContext({ viewport: { width: 1440, height: 960 }, deviceScaleFactor: 1 });
      const attackPage = await attackContext.newPage();
      await attackPage.goto(origin.url);
      await attackPage.setContent(markup);
      let repopulated = false;
      const actualLocator = attackPage.locator('[data-capture-root="live-chat"]');
      const originalScreenshot = actualLocator.screenshot.bind(actualLocator);
      const mutablePage = attackPage as unknown as {
        locator: (selector: string) => { screenshot: (options: Record<string, unknown>) => Promise<Buffer> };
      };
      mutablePage.locator = (selector) => ({
        screenshot: async (options) => {
          await attackPage.evaluate(() => {
            const preview = document.querySelector('[data-testid="runtime-preview"]');
            preview?.querySelector('.header-model span')?.replaceChildren(document.createTextNode('HOSTILE PROVIDER Q'));
            preview?.querySelector('.group-count')?.replaceChildren(document.createTextNode('7'));
            const transcript = preview?.querySelector('[data-capture-placeholder="conversation"]');
            const hostileTranscript = document.createElement('div');
            hostileTranscript.className = 'assistant-copy';
            transcript?.append(hostileTranscript);
            localStorage.setItem('Q', '7');
          });
          repopulated = true;
          return originalScreenshot(options);
        }
      });

      const captured = await captureLiveChatScreenshotIfEnabled({
        page: attackPage,
        uiState: 'ready',
        environment: captureEnvironment()
      });
      expect(repopulated).toBe(true);
      expect(captured?.bytes.equals(baseline!.bytes)).toBe(true);
      await expect(
        attackPage.evaluate(() => ({
          liveText: document.querySelector('[data-testid="runtime-preview"]')?.textContent,
          liveStorage: localStorage.getItem('Q'),
          captureText: document.querySelector('[data-capture-root="live-chat"]')?.textContent
        }))
      ).resolves.toEqual({
        liveText: expect.stringContaining('HOSTILE PROVIDER Q'),
        liveStorage: '7',
        captureText: expect.not.stringContaining('HOSTILE PROVIDER Q')
      });
      await attackContext.close();
    } finally {
      await browser.close();
      await new Promise<void>((resolve) => origin.server.close(() => resolve()));
    }
  });

  it.skipIf(!browserPrerequisiteEnabled)('observes the resolved Chromium project viewport and reduced-motion preference', async () => {
    const paths = getLivePlaywrightPaths();
    const resolvedConfig = createLivePlaywrightConfig({
      paths,
      port: 4187,
      outputDirectory: join(tmpdir(), 'synthetic-live-output'),
      launchOptions: { headless: true },
      desktopChrome: {}
    });
    const launchOptions = (resolvedConfig.use?.launchOptions ?? {}) as Record<string, unknown>;
    expect(launchOptions.headless).toBe(true);
    const pinned = getLiveScreenshotChromiumProvenance();
    const browser = await chromiumForPrerequisite().launch({
      headless: true,
      executablePath: pinned.executablePath
    });
    try {
      expect(browser.version()).toBe(pinned.version);
      const contextOptions = (resolvedConfig.use?.contextOptions ?? {}) as Record<string, unknown>;
      const context = await browser.newContext({
        viewport: resolvedConfig.use?.viewport as { width: number; height: number },
        deviceScaleFactor: resolvedConfig.use?.deviceScaleFactor as number,
        locale: resolvedConfig.use?.locale as string,
        reducedMotion: contextOptions.reducedMotion as 'reduce' | 'no-preference'
      });
      const page = await context.newPage();
      await page.setContent('<!doctype html><html><body>resolved page</body></html>');
      expect(page.viewportSize()).toEqual({ width: 1440, height: 960 });
      await expect(
        page.evaluate(() => ({
          width: window.innerWidth,
          height: window.innerHeight,
          reducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches
        }))
      ).resolves.toEqual({ width: 1440, height: 960, reducedMotion: true });
      await context.close();
    } finally {
      await browser.close();
    }
  });

  it('requires the explicit parity gate and a full client SHA', async () => {
    const page = fakePage();

    await expect(
      captureLiveChatScreenshotIfEnabled({
        page,
        uiState: 'ready',
        proof: COMPLETE_LIVE_PROOF,
        environment: {
          HERMTERNAL_LIVE_SCREENSHOT_CAPTURE: '1',
          HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA: 'short'
        }
      })
    ).rejects.toThrow('approved issue #352 Paper parity');

    await expect(
      captureLiveChatScreenshotIfEnabled({
        page,
        uiState: 'ready',
        proof: COMPLETE_LIVE_PROOF,
        environment: {
          HERMTERNAL_LIVE_SCREENSHOT_CAPTURE: '1',
          HERMTERNAL_PAPER_PARITY_APPROVED: '1',
          HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA: 'short'
        }
      })
    ).rejects.toThrow('explicit full client SHA');
    expect(page.screenshot).not.toHaveBeenCalled();
  });

  it('passes only the trusted minimal environment to the atomic-rename child', () => {
    const configuration = getLiveScreenshotAtomicRenameChildConfiguration();
    expect(configuration.environment).not.toHaveProperty('HERMES_TEST_PASSWORD');
    expect(configuration.environment).not.toHaveProperty('NODE_OPTIONS');
    expect(configuration.environment).not.toHaveProperty('PYTHONPATH');
    const observed = JSON.parse(
      execFileSync(
        configuration.executable,
        [
          '-I',
          '-S',
          '-c',
          'import json, os; print(json.dumps(dict(os.environ), sort_keys=True))'
        ],
        { env: configuration.environment, encoding: 'utf8' }
      )
    ) as Record<string, string>;
    expect(observed).toMatchObject(configuration.environment);
    for (const key of [
      'HERMES_TEST_USERNAME',
      'HERMES_TEST_PASSWORD',
      'NODE_OPTIONS',
      'PYTHONPATH',
      'PYTHONHOME',
      'HTTP_PROXY',
      'HTTPS_PROXY',
      'ALL_PROXY',
      'NO_PROXY'
    ]) {
      expect(observed).not.toHaveProperty(key);
    }
  });

  it.skipIf(!browserPrerequisiteEnabled)('rejects wrong Chromium version, revision, or executable before page mutation', async () => {
    const pinned = getLiveScreenshotChromiumProvenance();
    for (const page of [
      fakePage({ browserVersion: '151.0.7922.35' }),
      fakePage({ executablePath: pinned.executablePath.replace('chromium-1234', 'chromium-9999') }),
      fakePage({ executablePath: '/tmp/unapproved-chromium' })
    ]) {
      await expect(
        captureLiveChatScreenshotIfEnabled({
          page,
          uiState: 'ready',
          proof: COMPLETE_LIVE_PROOF,
          environment: captureEnvironment()
        })
      ).rejects.toThrow('Chromium provenance is not pinned');
      expect(page.emulateMedia).not.toHaveBeenCalled();
      expect(page.evaluate).not.toHaveBeenCalled();
      expect(page.locatorScreenshot).not.toHaveBeenCalled();
    }
  });

  it('preflights retention before any page mutation for invalid review or destination', async () => {
    const root = await temporaryDirectory();
    const validDestination = join(root, 'valid-destination');
    await fsPromises.mkdir(validDestination);
    const victim = join(root, 'victim');
    await fsPromises.mkdir(victim);
    const fileDestination = join(root, 'file-destination');
    await fsPromises.writeFile(fileDestination, 'not a directory', 'utf8');
    const cases = [
      {
        name: 'invalid review',
        environment: captureEnvironment({
          HERMTERNAL_LIVE_SCREENSHOT_RETAIN: '1',
          HERMTERNAL_LIVE_SCREENSHOT_REVIEW: 'pending-independent-review',
          HERMTERNAL_LIVE_SCREENSHOT_DESTINATION: validDestination
        }),
        error: 'independent approval'
      },
      {
        name: 'missing destination',
        environment: captureEnvironment({
          HERMTERNAL_LIVE_SCREENSHOT_RETAIN: '1',
          HERMTERNAL_LIVE_SCREENSHOT_REVIEW: 'independent-approved'
        }),
        error: 'explicit destination'
      },
      {
        name: 'nonexistent destination',
        environment: captureEnvironment({
          HERMTERNAL_LIVE_SCREENSHOT_RETAIN: '1',
          HERMTERNAL_LIVE_SCREENSHOT_REVIEW: 'independent-approved',
          HERMTERNAL_LIVE_SCREENSHOT_DESTINATION: join(root, 'missing')
        }),
        error: 'destination is unavailable'
      },
      {
        name: 'non-directory destination',
        environment: captureEnvironment({
          HERMTERNAL_LIVE_SCREENSHOT_RETAIN: '1',
          HERMTERNAL_LIVE_SCREENSHOT_REVIEW: 'independent-approved',
          HERMTERNAL_LIVE_SCREENSHOT_DESTINATION: fileDestination
        }),
        error: 'not a directory'
      },
      {
        name: 'symlink destination',
        environment: captureEnvironment({
          HERMTERNAL_LIVE_SCREENSHOT_RETAIN: '1',
          HERMTERNAL_LIVE_SCREENSHOT_REVIEW: 'independent-approved',
          HERMTERNAL_LIVE_SCREENSHOT_DESTINATION: join(root, 'symlink-destination')
        }),
        error: 'contains a symlink'
      }
    ];
    await fsPromises.symlink(victim, join(root, 'symlink-destination'));

    for (const testCase of cases) {
      const page = fakePage();
      await expect(
        captureLiveChatScreenshotIfEnabled({
          page,
          uiState: 'ready',
          proof: COMPLETE_LIVE_PROOF,
          environment: testCase.environment
        })
      ).rejects.toThrow(testCase.error);
      expect(page.emulateMedia).not.toHaveBeenCalled();
      expect(page.evaluate).not.toHaveBeenCalled();
      expect(page.locatorScreenshot).not.toHaveBeenCalled();
      expect(page.screenshot).not.toHaveBeenCalled();
    }
  });

  it.skipIf(!browserPrerequisiteEnabled)('captures after valid retention preflight but publishes zero bytes after destination replacement', async () => {
    const root = await temporaryDirectory();
    const destination = join(root, 'destination');
    const replacement = join(root, 'replacement');
    await fsPromises.mkdir(destination);
    await fsPromises.mkdir(replacement);
    const page = fakePage({
      beforeLocatorScreenshot: async () => {
        await fsPromises.rm(destination, { recursive: true, force: true });
        await fsPromises.symlink(replacement, destination);
      }
    });

    await expect(
      captureLiveChatScreenshotIfEnabled({
        page,
        uiState: 'ready',
        proof: COMPLETE_LIVE_PROOF,
        environment: captureEnvironment({
          HERMTERNAL_LIVE_SCREENSHOT_RETAIN: '1',
          HERMTERNAL_LIVE_SCREENSHOT_REVIEW: 'independent-approved',
          HERMTERNAL_LIVE_SCREENSHOT_DESTINATION: destination
        })
      })
    ).rejects.toThrow(/symlink|changed/);
    expect(page.evaluate).toHaveBeenCalled();
    expect(page.locatorScreenshot).toHaveBeenCalled();
    expect(await fsPromises.readdir(replacement)).toEqual([]);
  });

  it.skipIf(!browserPrerequisiteEnabled)('pins the route, dimensions, browser inputs, UI state, attestation, and image hash deterministically', async () => {
    const first = await captureLiveChatScreenshotIfEnabled({
      page: fakePage(),
      uiState: 'ready',
      environment: captureEnvironment()
    });
    const second = await captureLiveChatScreenshotIfEnabled({
      page: fakePage(),
      uiState: 'ready',
      environment: captureEnvironment()
    });

    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first?.manifest).toEqual(second?.manifest);
    expect(serializeLiveScreenshotManifest(first!.manifest)).toBe(
      serializeLiveScreenshotManifest(second!.manifest)
    );
    expect(first?.manifest.viewport).toEqual({ width: 1440, height: 960 });
    expect(first?.manifest.browser).toMatchObject({
      name: 'chromium',
      revision: getLiveScreenshotChromiumRegistry().revision,
      version: getLiveScreenshotChromiumRegistry().version,
      zoom: 1
    });
    expect(first?.manifest.locale).toBe('en-US');
    expect(first?.manifest.reducedMotion).toBe('reduce');
    expect(first?.manifest.hermes).toMatchObject({
      imageDigest: expect.stringMatching(/^sha256:[a-f0-9]{64}$/),
      sourceSha: expect.stringMatching(/^[a-f0-9]{40}$/),
      attestation: 'official-upstream-image-digest'
    });
    expect(first?.manifest.imageSha256).toBe(sha256Hex(PNG_BYTES));
    expect(first?.bytes.equals(second!.bytes)).toBe(true);
  });

  it('fails closed for unsafe metadata and unknown manifest fields', () => {
    const manifest = manifestFixture();
    const unsafeField = {
      ...manifest,
      hermes: { ...manifest.hermes, prompt: 'synthetic-prompt' }
    };
    expect(() => validateLiveScreenshotManifest(unsafeField)).toThrow(
      'unexpected shape'
    );

    const unsafeVersion = {
      ...manifest,
      browser: { ...manifest.browser, version: 'chrome-password' }
    };
    expect(() => validateLiveScreenshotManifest(unsafeVersion)).toThrow(
      'unsafe metadata'
    );
  });

  it.skipIf(!browserPrerequisiteEnabled)('rejects non-approved routes and dimensions before screenshot bytes exist', async () => {
    const wrongRoute = fakePage({ route: '/?prompt=synthetic' });
    await expect(
      captureLiveChatScreenshotIfEnabled({
        page: wrongRoute,
        uiState: 'ready',
        environment: captureEnvironment()
      })
    ).rejects.toThrow('approved root route');
    expect(wrongRoute.screenshot).not.toHaveBeenCalled();
    expect(wrongRoute.locatorScreenshot).not.toHaveBeenCalled();

    const wrongViewport = fakePage({ viewport: { width: 956, height: 2022 } });
    await expect(
      captureLiveChatScreenshotIfEnabled({
        page: wrongViewport,
        uiState: 'ready',
        environment: captureEnvironment()
      })
    ).rejects.toThrow('1440x960');
    expect(wrongViewport.screenshot).not.toHaveBeenCalled();
    expect(wrongViewport.locatorScreenshot).not.toHaveBeenCalled();
  });

  it('refuses a symlink or path-replaced retention directory', async () => {
    const root = await temporaryDirectory();
    const victim = join(root, 'victim');
    const destination = join(root, 'destination');
    await fsPromises.mkdir(victim);
    await fsPromises.writeFile(join(victim, 'must-survive.txt'), 'victim-survives', 'utf8');
    await fsPromises.symlink(victim, destination);

    await expect(
      persistApprovedLiveScreenshot({
        capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
        destinationDirectory: destination,
        review: 'independent-approved',
      provenance: CONTROLLED_TEST_PROVENANCE
      })
    ).rejects.toThrow('symlink');
    expect(await fsPromises.readFile(join(victim, 'must-survive.txt'), 'utf8')).toBe(
      'victim-survives'
    );

    await fsPromises.rm(destination, { force: true });
    await fsPromises.mkdir(destination);
    await fsPromises.rm(destination, { recursive: true, force: true });
    await fsPromises.symlink(victim, destination);
    await expect(
      persistApprovedLiveScreenshot({
        capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
        destinationDirectory: destination,
        review: 'independent-approved',
      provenance: CONTROLLED_TEST_PROVENANCE
      })
    ).rejects.toThrow('symlink');
    expect(await fsPromises.readFile(join(victim, 'must-survive.txt'), 'utf8')).toBe(
      'victim-survives'
    );
  });

  it('cleans private staging files when bundle construction fails', async () => {
    const destination = await temporaryDirectory();
    const originalWriteFile = fsPromises.writeFile;
    let writeCount = 0;
    fsPromises.writeFile = async (...args: Parameters<typeof originalWriteFile>) => {
      writeCount += 1;
      if (writeCount === 2) throw new Error('synthetic manifest staging failure');
      return originalWriteFile(...args);
    };

    try {
      await expect(
        persistApprovedLiveScreenshot({
          capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
          destinationDirectory: destination,
          review: 'independent-approved',
          provenance: CONTROLLED_TEST_PROVENANCE
        })
      ).rejects.toThrow('synthetic manifest staging failure');
    } finally {
      fsPromises.writeFile = originalWriteFile;
    }

    expect(await fsPromises.readdir(destination)).toEqual([]);
  });

  it('preserves a replacement staging pathname during cleanup races', async () => {
    const destination = await temporaryDirectory();
    const replacementRoot = await temporaryDirectory();
    const replacement = join(replacementRoot, 'replacement-staging');
    await fsPromises.mkdir(replacement);
    await fsPromises.writeFile(join(replacement, 'sentinel.txt'), 'keep me', 'utf8');
    const originalWriteFile = fsPromises.writeFile;
    let writeCount = 0;
    let racedStagingDirectory: string | undefined;
    fsPromises.writeFile = async (...args: Parameters<typeof originalWriteFile>) => {
      writeCount += 1;
      if (writeCount === 2) throw new Error('synthetic manifest staging failure');
      return originalWriteFile(...args);
    };

    try {
      await expect(
        persistApprovedLiveScreenshot({
          capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
          destinationDirectory: destination,
          review: 'independent-approved',
          provenance: CONTROLLED_TEST_PROVENANCE,
          beforeStagingCleanup: async (stagingDirectory) => {
            racedStagingDirectory = stagingDirectory;
            await fsPromises.rm(stagingDirectory, { recursive: true, force: true });
            await fsPromises.symlink(replacement, stagingDirectory);
          }
        })
      ).rejects.toThrow('publication and cleanup failed');
    } finally {
      fsPromises.writeFile = originalWriteFile;
    }

    expect(await fsPromises.readFile(join(replacement, 'sentinel.txt'), 'utf8')).toBe('keep me');
    const replacementStats = await fsPromises.lstat(replacement);
    expect(replacementStats.isDirectory()).toBe(true);
    if (racedStagingDirectory) await fsPromises.rm(racedStagingDirectory, { force: true });
  });

  it('publishes zero bytes when the staged source is replaced before atomic rename', async () => {
    const destination = await temporaryDirectory();
    let racedStagingDirectory = '';
    let replacementParent = '';
    let parentTombstone = '';
    const originalRename = fsPromises.rename;
    fsPromises.rename = async (source, target) => {
      const result = await originalRename(source, target);
      if (String(target).includes('-cleanup-')) {
        parentTombstone = String(target);
      }
      return result;
    };

    try {
      await expect(
        persistApprovedLiveScreenshot({
          capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
          destinationDirectory: destination,
          review: 'independent-approved',
          provenance: CONTROLLED_TEST_PROVENANCE,
          beforeAtomicPublish: async (stagingDirectory) => {
            racedStagingDirectory = stagingDirectory;
            replacementParent = dirname(stagingDirectory);
            await fsPromises.rm(stagingDirectory, { recursive: true, force: true });
            await fsPromises.mkdir(stagingDirectory);
            await fsPromises.writeFile(join(stagingDirectory, 'attacker.txt'), 'must survive', 'utf8');
          }
        })
      ).rejects.toThrow('publication and cleanup failed');
    } finally {
      fsPromises.rename = originalRename;
    }

    expect(await fsPromises.readdir(destination)).toEqual([]);
    expect(parentTombstone).not.toBe('');
    expect(await fsPromises.readFile(join(parentTombstone, basename(racedStagingDirectory), 'attacker.txt'), 'utf8')).toBe('must survive');
    await fsPromises.rm(parentTombstone, { recursive: true, force: true });
  });

  it('publishes zero bytes when the private staging parent is replaced before atomic rename', async () => {
    const destination = await temporaryDirectory();
    const replacementParent = await temporaryDirectory();
    let stagingParent = '';

    await expect(
      persistApprovedLiveScreenshot({
        capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
        destinationDirectory: destination,
        review: 'independent-approved',
        provenance: CONTROLLED_TEST_PROVENANCE,
        beforeAtomicPublish: async (stagingDirectory) => {
          stagingParent = dirname(stagingDirectory);
          await fsPromises.rm(stagingParent, { recursive: true, force: true });
          await fsPromises.symlink(replacementParent, stagingParent);
        }
      })
    ).rejects.toThrow('publication and cleanup failed');

    expect(await fsPromises.readdir(destination)).toEqual([]);
    expect((await fsPromises.lstat(stagingParent)).isSymbolicLink()).toBe(true);
    await fsPromises.rm(stagingParent, { force: true });
  });

  it('publishes zero PNG or manifest bytes into a replacement destination during a race', async () => {
    const root = await temporaryDirectory();
    const destination = join(root, 'destination');
    const replacement = join(root, 'replacement');
    await fsPromises.mkdir(destination);
    await fsPromises.mkdir(replacement);

    await expect(
      persistApprovedLiveScreenshot({
        capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
        destinationDirectory: destination,
        review: 'independent-approved',
        provenance: CONTROLLED_TEST_PROVENANCE,
        beforeAtomicPublish: async () => {
          await fsPromises.rm(destination, { recursive: true, force: true });
          await fsPromises.symlink(replacement, destination);
        }
      })
    ).rejects.toThrow('destination changed');

    expect(await fsPromises.readdir(replacement)).toEqual([]);
  });

  it('persists only approved PNG bytes and the bounded manifest without overwrite', async () => {
    const destination = await temporaryDirectory();
    const result = await persistApprovedLiveScreenshot({
      capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
      destinationDirectory: destination,
      review: 'independent-approved',
      provenance: CONTROLLED_TEST_PROVENANCE
    });

    expect(result.bundlePath).toBe(join(destination, 'hermternal-chat-proof.bundle'));
    expect(await fsPromises.readdir(destination)).toEqual(['hermternal-chat-proof.bundle']);
    expect(await fsPromises.readFile(result.imagePath)).toEqual(PNG_BYTES);
    expect(JSON.parse(await fsPromises.readFile(result.manifestPath, 'utf8'))).toEqual(
      result.manifest
    );
    await expect(
      persistApprovedLiveScreenshot({
        capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
        destinationDirectory: destination,
        review: 'independent-approved',
      provenance: CONTROLLED_TEST_PROVENANCE
      })
    ).rejects.toThrow('refuses to overwrite');
  });
});
