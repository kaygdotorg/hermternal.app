import { expect, test as base } from '@playwright/test';
import {
  finalizeLiveTest,
  liveCredentialValues,
  scrubLivePage
} from './live-artifact-policy.mjs';

export { expect };
export const test = base;

test.afterEach(async ({ page }, testInfo) => {
  const secrets = liveCredentialValues();
  let scrubError: unknown;
  try {
    await scrubLivePage(page);
  } catch (error) {
    // Only page.isClosed() can suppress the evaluator failure. Keep every
    // other error until diagnostics are redacted and cleanup has completed.
    scrubError = error;
  }
  await finalizeLiveTest({ testInfo, scrubError, secrets });
});
