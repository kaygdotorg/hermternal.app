import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LIVE_RECONCILIATION_ENV } from './live-reconciliation.mjs';

export const LIVE_RECONCILIATION_TEST_MATCH = '**/reconcile-live-proof.spec.ts';
export const LIVE_RECONCILIATION_TEST_IGNORE = Object.freeze([
  '**/official-hermes.spec.ts',
  '**/*capture*.spec.ts'
]);

/**
 * Return whether the read-only reconciliation lane is selected. A present
 * value must be the exact opt-in token so `true`, `yes`, and other truthy
 * spellings can never silently select a different Playwright test set.
 *
 * @param {Record<string, string | undefined>} [environment]
 */
export function isLiveReconciliationEnabled(environment = process.env) {
  const value = environment[LIVE_RECONCILIATION_ENV];
  if (value !== undefined && value !== '1') {
    throw new Error(`${LIVE_RECONCILIATION_ENV} must equal exactly 1 when set`);
  }
  return value === '1';
}

/**
 * Derive every live-run path from the config module location. This module is
 * intentionally side-effect free: importing it must not inspect browser
 * provenance, create artifact roots, or mutate runner environment variables.
 *
 * @param {string} [configUrl]
 */
export function getLivePlaywrightPaths(configUrl = new URL('../../playwright.live.config.ts', import.meta.url).href) {
  const configFile = fileURLToPath(configUrl);
  const appRoot = dirname(configFile);
  const liveTestsDirectory = join(appRoot, 'tests', 'live');
  return Object.freeze({
    appRoot,
    repositoryRoot: resolve(appRoot, '..', '..'),
    configFile,
    liveTestsDirectory,
    ipcGuardFile: join(liveTestsDirectory, 'live-ipc-guard.cjs'),
    liveHostFile: join(liveTestsDirectory, 'live-host.mjs'),
    safeReporterFile: join(liveTestsDirectory, 'safe-reporter.mjs'),
    teardownFile: join(liveTestsDirectory, 'live-artifact-teardown.mjs')
  });
}

/** @param {string} value */
function shellQuote(value) {
  if (process.platform === 'win32') {
    return `"${value.replaceAll('"', '\\"')}"`;
  }
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/**
 * Build the Playwright configuration without importing Playwright or mutating
 * process state. The live entrypoint supplies already validated launch options
 * and owned output paths after its synchronous preflight.
 *
 * @param {{
 *   paths: ReturnType<typeof getLivePlaywrightPaths>,
 *   port: number,
 *   outputDirectory: string,
 *   launchOptions: Record<string, unknown>,
 *   desktopChrome: Record<string, unknown>,
 *   reconciliationOnly?: boolean
 * }} options
 */
export function createLivePlaywrightConfig({
  paths,
  port,
  outputDirectory,
  launchOptions,
  desktopChrome,
  reconciliationOnly = false
}) {
  if (typeof reconciliationOnly !== 'boolean') {
    throw new Error('live reconciliation test selection must be boolean');
  }
  const command = `bun run build && node ${shellQuote(paths.liveHostFile)} --port ${port}`;
  const viewport = { width: 1440, height: 960 };
  const contextOptions = { reducedMotion: 'reduce' };
  return {
    testDir: paths.liveTestsDirectory,
    ...(reconciliationOnly
      ? {
          testMatch: LIVE_RECONCILIATION_TEST_MATCH,
          testIgnore: [...LIVE_RECONCILIATION_TEST_IGNORE]
        }
      : {}),
    fullyParallel: false,
    forbidOnly: true,
    retries: 0,
    outputDir: join(outputDirectory, '.playwright-output'),
    preserveOutput: 'never',
    reporter: [[paths.safeReporterFile]],
    globalTeardown: paths.teardownFile,
    timeout: 120_000,
    expect: { timeout: 30_000 },
    use: {
      baseURL: `http://127.0.0.1:${port}`,
      viewport,
      deviceScaleFactor: 1,
      locale: 'en-US',
      contextOptions,
      trace: 'off',
      video: 'off',
      screenshot: 'off',
      colorScheme: 'light',
      launchOptions
    },
    webServer: {
      command,
      cwd: paths.appRoot,
      url: `http://127.0.0.1:${port}/`,
      reuseExistingServer: false,
      timeout: 120_000
    },
    projects: [
      {
        name: 'chromium-live',
        use: {
          ...desktopChrome,
          viewport,
          deviceScaleFactor: 1,
          locale: 'en-US',
          contextOptions,
          colorScheme: 'light',
          trace: 'off',
          video: 'off',
          screenshot: 'off',
          launchOptions
        }
      }
    ]
  };
}
