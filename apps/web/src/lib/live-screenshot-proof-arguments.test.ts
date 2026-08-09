import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

const screenshotTestSource = readFileSync(
  resolve(process.cwd(), 'src/lib/live-screenshot-capture.test.ts'),
  'utf8'
);

function captureArgumentBlocks(source: string): string[] {
  return [...source.matchAll(/captureLiveChatScreenshotIfEnabled\(\{([\s\S]*?)\n\s*\}\)/g)].map(
    (match) => match[1]
  );
}

describe('live screenshot proof argument policy', () => {
  it('keeps every proof-required capture call bound to the complete proof gate', () => {
    // Default-off and skipped browser-prerequisite cases still type-check. Scan every
    // capture call so a future diagnostic path cannot omit the causal proof argument;
    // only the explicit incomplete-proof rejection case may use FAILED_LIVE_PROOF.
    const calls = captureArgumentBlocks(screenshotTestSource);
    const intentionallyIncompleteCalls = calls.filter((call) =>
      /\bproof:\s*FAILED_LIVE_PROOF\b/.test(call)
    );
    const proofRequiredCalls = calls.filter(
      (call) => !/\bproof:\s*FAILED_LIVE_PROOF\b/.test(call)
    );
    const missingCompleteProofCalls = proofRequiredCalls.filter(
      (call) => !/\bproof:\s*COMPLETE_LIVE_PROOF\b/.test(call)
    );

    expect(calls).toHaveLength(13);
    expect(intentionallyIncompleteCalls).toHaveLength(1);
    expect(
      missingCompleteProofCalls,
      'every proof-required diagnostic capture call must pass COMPLETE_LIVE_PROOF'
    ).toHaveLength(0);
  });
});
