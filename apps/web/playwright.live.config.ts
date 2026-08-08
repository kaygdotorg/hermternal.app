import { defineConfig, devices } from '@playwright/test';
import { join, resolve } from 'node:path';
import {
  assertLiveRunnerDebugDisabled,
  liveArtifactOutputDirectory,
  liveArtifactOutputOwnershipToken
} from './tests/live/live-artifact-policy.mjs';

// Playwright's debug mode inherits worker stderr directly, bypassing the IPC
// guard. Reject it before the runner can spawn a credential-bearing worker.
assertLiveRunnerDebugDisabled();

// Playwright appends LastRunReporter after global teardown. Its default
// `.last-run.json` path would recreate the project output directory after the
// owned root has been removed, so force the Unix null sink for this Unix-only
// proof lane instead of retaining a markerless post-teardown artifact.
process.env.PLAYWRIGHT_LAST_RUN_OUTPUT_FILE = '/dev/null';

const port = Number(process.env.PLAYWRIGHT_LIVE_PORT ?? 4187);
const liveIpcGuard = resolve(process.cwd(), 'tests/live/live-ipc-guard.cjs');
const existingNodeOptions = process.env.NODE_OPTIONS?.trim() ?? '';
if (!existingNodeOptions.includes(liveIpcGuard)) {
  process.env.NODE_OPTIONS = [existingNodeOptions, `--require=${liveIpcGuard}`]
    .filter(Boolean)
    .join(' ');
}
const liveOutputDirectory = liveArtifactOutputDirectory();
// Playwright clears the project output directory before a run. Keep that
// disposable subtree below the immutable run root so the owner marker and
// root-level handoff artifacts survive worker and retry boundaries.
const livePlaywrightOutputDirectory = join(liveOutputDirectory, '.playwright-output');
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
  outputDir: livePlaywrightOutputDirectory,
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
