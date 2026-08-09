import { defineConfig, devices } from '@playwright/test';
import { devNull } from 'node:os';
import { getLivePlaywrightPaths, createLivePlaywrightConfig } from './tests/live/live-playwright-config.mjs';
import { getLiveScreenshotChromiumLaunchOptions } from './tests/live/live-screenshot-capture.mjs';
import {
  assertLiveRunnerDebugDisabled,
  liveArtifactOutputDirectory,
  liveArtifactOutputOwnershipToken
} from './tests/live/live-artifact-policy.mjs';

// Playwright's debug mode inherits worker stderr directly, bypassing the IPC
// guard. Reject PW_RUNNER_DEBUG and PWDEBUG before the runner can spawn a
// credential-bearing worker or switch the browser to a headed/UI mode.
assertLiveRunnerDebugDisabled();

if (
  process.env.HERMTERNAL_LIVE_RECONCILIATION === '1' &&
  process.env.HERMTERNAL_LIVE_SCREENSHOT_CAPTURE === '1'
) {
  throw new Error('live reconciliation mode cannot be combined with screenshot capture');
}

const paths = getLivePlaywrightPaths();
const port = Number(process.env.PLAYWRIGHT_LIVE_PORT ?? 4187);

// This call is the synchronous opt-in boundary. When capture is enabled it
// validates the checkout, package/lock pins, Chromium registry, and exact
// regular executable before any artifact root, web server, browser, or page
// can be created. Default-off imports do not resolve the browser cache.
const liveCaptureLaunchOptions = getLiveScreenshotChromiumLaunchOptions();

// Playwright appends LastRunReporter after global teardown. Its default
// `.last-run.json` path would recreate the project output directory after the
// owned root has been removed, so use the platform null sink instead of
// retaining a markerless post-teardown artifact.
process.env.PLAYWRIGHT_LAST_RUN_OUTPUT_FILE = devNull;

const existingNodeOptions = process.env.NODE_OPTIONS?.trim() ?? '';
if (!existingNodeOptions.includes(paths.ipcGuardFile)) {
  process.env.NODE_OPTIONS = [existingNodeOptions, `--require=${paths.ipcGuardFile}`]
    .filter(Boolean)
    .join(' ');
}

const liveOutputDirectory = liveArtifactOutputDirectory();
// Playwright clears the project output directory before a run. Keep that
// disposable subtree below the immutable run root so the owner marker and
// root-level handoff artifacts survive worker and retry boundaries.
process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR = liveOutputDirectory;
// Global teardown may run in a separate Node process, so pass only the safe
// temporary path and its run-ownership token through the environment; no
// credential value is exported.
process.env.PLAYWRIGHT_LIVE_OUTPUT_TOKEN = liveArtifactOutputOwnershipToken();

export default defineConfig(
  createLivePlaywrightConfig({
    paths,
    port,
    outputDirectory: liveOutputDirectory,
    launchOptions: liveCaptureLaunchOptions,
    desktopChrome: devices['Desktop Chrome']
  })
);
