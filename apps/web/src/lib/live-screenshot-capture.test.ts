import { promises as fsPromises } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { chromium } from 'playwright';
import { render } from '@testing-library/svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import WorkspacePreview from './workspace/WorkspacePreview.svelte';
import liveConfig from '../../playwright.live.config';
import {
  captureLiveChatScreenshot,
  captureLiveChatScreenshotIfEnabled,
  createLiveScreenshotManifest,
  persistApprovedLiveScreenshot,
  sanitizeLiveChatCapturePresentation,
  serializeLiveScreenshotManifest,
  sha256Hex,
  validateLiveScreenshotManifest
} from '../../tests/live/live-screenshot-capture.mjs';

const PNG_BYTES = Buffer.concat([
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  Buffer.from('synthetic-approved-png', 'utf8')
]);
const CLIENT_SHA = 'a'.repeat(40);
const temporaryRoots: string[] = [];

function fakePage(options: { bytes?: Buffer; route?: string; viewport?: { width: number; height: number } } = {}) {
  const bytes = options.bytes ?? PNG_BYTES;
  const page = {
    url: () => `http://127.0.0.1:4187${options.route ?? '/'}`,
    viewportSize: () => options.viewport ?? { width: 1440, height: 960 },
    context: () => ({
      browser: () => ({
        browserType: () => ({ name: () => 'chromium' }),
        version: () => '140.0.7339.0'
      })
    }),
    emulateMedia: vi.fn(async () => undefined),
    evaluate: vi.fn(async (pageFunction: unknown) => {
      if (pageFunction === sanitizeLiveChatCapturePresentation) {
        return { sanitized: true, removedValueCount: 3, prohibitedNodeCount: 0 };
      }
      return {
        devicePixelRatio: 1,
        locale: 'en-US',
        reducedMotion: 'reduce',
        theme: 'light',
        zoom: 1
      };
    }),
    screenshot: vi.fn(async () => bytes)
  };
  return page;
}

function manifestFixture() {
  return createLiveScreenshotManifest({
    browserName: 'chromium',
    browserVersion: '140.0.7339.0',
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

afterEach(async () => {
  while (temporaryRoots.length > 0) {
    const root = temporaryRoots.pop();
    if (root) await fsPromises.rm(root, { recursive: true, force: true });
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

  it('sanitizes real live component DOM before the capture-only presentation', () => {
    render(WorkspacePreview, {
      state: 'ready',
      dataSource: 'live-runtime',
      dataMode: 'live',
      artifactInspectorEnabled: false,
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

    const result = sanitizeLiveChatCapturePresentation();
    expect(result).toEqual({ sanitized: true, removedValueCount: expect.any(Number), prohibitedNodeCount: 0 });
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
  });

  it('observes the resolved Chromium project viewport and reduced-motion preference', async () => {
    const globalUse = (liveConfig.use ?? {}) as Record<string, unknown>;
    const projectUse = (liveConfig.projects?.[0]?.use ?? {}) as Record<string, unknown>;
    const resolvedUse = { ...globalUse, ...projectUse };
    const browser = await chromium.launch({ headless: true });
    try {
      const contextOptions = (resolvedUse.contextOptions ?? {}) as Record<string, unknown>;
      const context = await browser.newContext({
        viewport: resolvedUse.viewport as { width: number; height: number },
        deviceScaleFactor: resolvedUse.deviceScaleFactor as number,
        locale: resolvedUse.locale as string,
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
        environment: {
          HERMTERNAL_LIVE_SCREENSHOT_CAPTURE: '1',
          HERMTERNAL_PAPER_PARITY_APPROVED: '1',
          HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA: 'short'
        }
      })
    ).rejects.toThrow('explicit full client SHA');
    expect(page.screenshot).not.toHaveBeenCalled();
  });

  it('pins the route, dimensions, browser inputs, UI state, attestation, and image hash deterministically', async () => {
    const first = await captureLiveChatScreenshot({
      page: fakePage(),
      clientSha: CLIENT_SHA,
      paperParityApproved: true,
      stateStable: true,
      uiState: 'ready'
    });
    const second = await captureLiveChatScreenshot({
      page: fakePage(),
      clientSha: CLIENT_SHA,
      paperParityApproved: true,
      stateStable: true,
      uiState: 'ready'
    });

    expect(first).toBeDefined();
    expect(second).toBeDefined();
    expect(first?.manifest).toEqual(second?.manifest);
    expect(serializeLiveScreenshotManifest(first!.manifest)).toBe(
      serializeLiveScreenshotManifest(second!.manifest)
    );
    expect(first?.manifest.viewport).toEqual({ width: 1440, height: 960 });
    expect(first?.manifest.browser).toMatchObject({ name: 'chromium', zoom: 1 });
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

  it('rejects non-approved routes and dimensions before screenshot bytes exist', async () => {
    const wrongRoute = fakePage({ route: '/?prompt=synthetic' });
    await expect(
      captureLiveChatScreenshot({
        page: wrongRoute,
        clientSha: CLIENT_SHA,
        paperParityApproved: true,
        stateStable: true,
        uiState: 'ready'
      })
    ).rejects.toThrow('approved root route');
    expect(wrongRoute.screenshot).not.toHaveBeenCalled();

    const wrongViewport = fakePage({ viewport: { width: 956, height: 2022 } });
    await expect(
      captureLiveChatScreenshot({
        page: wrongViewport,
        clientSha: CLIENT_SHA,
        paperParityApproved: true,
        stateStable: true,
        uiState: 'ready'
      })
    ).rejects.toThrow('1440x960');
    expect(wrongViewport.screenshot).not.toHaveBeenCalled();
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
        review: 'independent-approved'
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
        review: 'independent-approved'
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
          review: 'independent-approved'
        })
      ).rejects.toThrow('synthetic manifest staging failure');
    } finally {
      fsPromises.writeFile = originalWriteFile;
    }

    expect(await fsPromises.readdir(destination)).toEqual([]);
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
      review: 'independent-approved'
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
        review: 'independent-approved'
      })
    ).rejects.toThrow('refuses to overwrite');
  });
});
