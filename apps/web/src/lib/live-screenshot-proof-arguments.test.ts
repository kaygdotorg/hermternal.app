import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

const screenshotTestSource = readFileSync(
  resolve(process.cwd(), 'src/lib/live-screenshot-capture.test.ts'),
  'utf8'
);

function bodyForTest(title: string): string {
  const titleIndex = screenshotTestSource.indexOf(title);
  if (titleIndex < 0) {
    throw new Error(`screenshot test title is missing: ${title}`);
  }
  const bodyStart = screenshotTestSource.indexOf('\n', titleIndex) + 1;
  const nextTest = screenshotTestSource.indexOf('\n  it', bodyStart);
  return screenshotTestSource.slice(bodyStart, nextTest < 0 ? undefined : nextTest);
}

function captureArgumentBlocks(body: string): string[] {
  return [...body.matchAll(/captureLiveChatScreenshotIfEnabled\(\{([\s\S]*?)\n\s*\}\)/g)].map(
    (match) => match[1]
  );
}

describe('live screenshot proof argument policy', () => {
  it('keeps the four diagnostic capture calls bound to the complete proof gate', () => {
    // These browser-prerequisite cases still type-check even when skipped. Keep their
    // explicit proof binding so route and manifest failures cannot bypass the gate.
    const cases = [
      {
        title: 'pins the route, dimensions, browser inputs, UI state, attestation, and image hash deterministically',
        calls: 2
      },
      {
        title: 'rejects non-approved routes and dimensions before screenshot bytes exist',
        calls: 2
      }
    ];

    for (const { title, calls: expectedCalls } of cases) {
      const calls = captureArgumentBlocks(bodyForTest(title));
      expect(calls).toHaveLength(expectedCalls);
      expect(calls.every((call) => /\bproof:\s*COMPLETE_LIVE_PROOF\b/.test(call))).toBe(true);
    }
  });
});
