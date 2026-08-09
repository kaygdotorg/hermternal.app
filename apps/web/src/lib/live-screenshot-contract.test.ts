import { execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  LIVE_SCREENSHOT_PUBLIC_CONTRACT,
  blockedLiveScreenshotManifest,
  captureReviewedLiveScreenshots,
  inspectPublicPng
} from '../../tests/live/live-screenshot-contract.mjs';

const temporaryDirectories: string[] = [];

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
