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
  try {
    await scrubLivePage(page);
  } catch {
    // A crashed or closed page cannot contain a readable live form anymore.
  }
  redactTestErrors(testInfo.errors, secrets);
  // A custom reporter never serializes attachments, and removing references
  // prevents a future reporter from retaining a file after the page is scrubbed.
  testInfo.attachments.length = 0;
  await removeLiveArtifacts(testInfo.outputDir);
});
