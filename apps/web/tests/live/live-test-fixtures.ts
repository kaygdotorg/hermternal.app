import { expect, test as base } from '@playwright/test';
import {
  liveCredentialValues,
  redactTestErrors,
  removeLiveArtifacts,
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
    // scrubLivePage only absorbs a definitively closed or crashed page. Keep
    // every other evaluator failure until cleanup completes, then fail the
    // teardown instead of silently trusting an unverified DOM boundary.
    scrubError = error;
  }
  if (scrubError) redactTestErrors([scrubError], secrets);
  redactTestErrors(testInfo.errors, secrets);
  // A custom reporter never serializes attachments, and removing references
  // prevents a future reporter from retaining a file after the page is scrubbed.
  testInfo.attachments.length = 0;
  await removeLiveArtifacts(testInfo.outputDir);
  if (scrubError) throw scrubError;
});
