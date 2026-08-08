import { promises as fsPromises } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  captureLiveChatScreenshot,
  captureLiveChatScreenshotIfEnabled,
  createLiveScreenshotManifest,
  persistApprovedLiveScreenshot,
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
    evaluate: vi.fn(async () => ({
      devicePixelRatio: 1,
      locale: 'en-US',
      reducedMotion: 'reduce',
      theme: 'light',
      zoom: 1
    })),
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

  it('cleans private staging files when publication fails', async () => {
    const destination = await temporaryDirectory();
    const originalLink = fsPromises.link;
    let linkCount = 0;
    fsPromises.link = async (...args: Parameters<typeof originalLink>) => {
      linkCount += 1;
      if (linkCount === 2) throw new Error('synthetic manifest publication failure');
      return originalLink(...args);
    };

    try {
      await expect(
        persistApprovedLiveScreenshot({
          capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
          destinationDirectory: destination,
          review: 'independent-approved'
        })
      ).rejects.toThrow('synthetic manifest publication failure');
    } finally {
      fsPromises.link = originalLink;
    }

    expect(await fsPromises.readdir(destination)).toEqual([]);
  });

  it('persists only approved PNG bytes and the bounded manifest without overwrite', async () => {
    const destination = await temporaryDirectory();
    const result = await persistApprovedLiveScreenshot({
      capture: { bytes: PNG_BYTES, manifest: manifestFixture() },
      destinationDirectory: destination,
      review: 'independent-approved'
    });

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
