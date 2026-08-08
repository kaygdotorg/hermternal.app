import { defineConfig, devices } from '@playwright/test';
import { resolve } from 'node:path';
import {
  liveArtifactOutputDirectory,
  liveArtifactOutputOwnershipToken
} from './tests/live/live-artifact-policy.mjs';

const port = Number(process.env.PLAYWRIGHT_LIVE_PORT ?? 4187);
const liveIpcGuard = resolve(process.cwd(), 'tests/live/live-ipc-guard.cjs');
const existingNodeOptions = process.env.NODE_OPTIONS?.trim() ?? '';
if (!existingNodeOptions.includes(liveIpcGuard)) {
  process.env.NODE_OPTIONS = [existingNodeOptions, `--require=${liveIpcGuard}`]
    .filter(Boolean)
    .join(' ');
}
const liveOutputDirectory = liveArtifactOutputDirectory();
// Global teardown may run in a separate Node process, so pass only the safe
// temporary path and its run-ownership token through the environment; no
// credential value is exported.
process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR = liveOutputDirectory;
process.env.PLAYWRIGHT_LIVE_OUTPUT_TOKEN = liveArtifactOutputOwnershipToken();

export default defineConfig({
  testDir: './tests/live',
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  // Live credentials must never enter the repository's retained test-results
  // directory or a standard reporter's locator/DOM failure context.
  outputDir: liveOutputDirectory,
  preserveOutput: 'never',
  reporter: [['./tests/live/safe-reporter.mjs']],
  globalTeardown: './tests/live/live-artifact-teardown.mjs',
  timeout: 120_000,
  expect: { timeout: 30_000 },
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: 'off',
    video: 'off',
    screenshot: 'off',
    colorScheme: 'light'
  },
  webServer: {
    // This disposable host keeps browser traffic same-origin while Hermes stays
    // behind the local SSH tunnel. It is not a production deployment path.
    command: `bun run build && node tests/live/live-host.mjs --port ${port}`,
    url: `http://127.0.0.1:${port}/`,
    reuseExistingServer: false,
    timeout: 120_000
  },
  projects: [
    {
      name: 'chromium-live',
      use: { ...devices['Desktop Chrome'] }
    }
  ]
});
