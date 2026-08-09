import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  createLivePlaywrightConfig,
  getLivePlaywrightPaths
} from '../../tests/live/live-playwright-config.mjs';
import {
  createLiveProofLedger,
  createLiveProofTestSigner,
  matchLiveProofLedger
} from '../../tests/live/live-proof-ledger.mjs';

function configForReconciliationSelection() {
  const appRoot = resolve(process.cwd());
  const paths = getLivePlaywrightPaths(pathToFileURL(resolve(appRoot, 'playwright.live.config.ts')).href);
  return createLivePlaywrightConfig({
    paths,
    port: 4187,
    outputDirectory: join(tmpdir(), 'hermternal-reconciliation-selection'),
    launchOptions: { headless: true },
    desktopChrome: {},
    // Keep this harness compatible with the shared factory that existed on the
    // rejected parent; the assertion must fail on that factory, not on a new
    // mode-only export imported by the correction.
    reconciliationOnly: process.env.HERMTERNAL_LIVE_RECONCILIATION === '1'
  });
}

describe('reconciliation test selection contract', () => {
  it('selects only the no-submit spec and excludes prompt lanes on exact opt-in', () => {
    const previous = process.env.HERMTERNAL_LIVE_RECONCILIATION;
    process.env.HERMTERNAL_LIVE_RECONCILIATION = '1';
    try {
      const config = configForReconciliationSelection();
      expect(config.testMatch).toBe('**/reconcile-live-proof.spec.ts');
      expect(config.testIgnore).toEqual([
        '**/official-hermes.spec.ts',
        '**/*capture*.spec.ts'
      ]);
      expect(config.testMatch).not.toContain('official-hermes');
      expect(config.testMatch).not.toContain('capture');
      expect(matchLiveProofLedger(createLiveProofLedger(256, {
        signer: createLiveProofTestSigner(),
        allowTestSigner: true
      }).snapshot(), {})).toMatchObject({
        promptCount: 0,
        completionCount: 0
      });
    } finally {
      if (previous === undefined) delete process.env.HERMTERNAL_LIVE_RECONCILIATION;
      else process.env.HERMTERNAL_LIVE_RECONCILIATION = previous;
    }
  });
});
