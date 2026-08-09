import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const LIVE_CONFIG_RELATIVE_PATH = '../../playwright.live.config.ts';

/**
 * Derive every live-run path from the config module location. This module is
 * intentionally side-effect free: importing it must not inspect browser
 * provenance, create artifact roots, or mutate runner environment variables.
 * The default is strict so production cannot guess a path when a bundler
 * supplies a non-file import.meta.url; Vitest callers pass an explicit file URL.
 *
 * @param {string | URL} [configUrl]
 */
export function getLivePlaywrightPaths(
  configUrl = new URL(LIVE_CONFIG_RELATIVE_PATH, import.meta.url).href
) {
  const parsedConfigUrl = new URL(configUrl);
  if (parsedConfigUrl.protocol !== 'file:') {
    throw new TypeError('live Playwright config URL must use the file: scheme');
  }
  const configFile = fileURLToPath(parsedConfigUrl);
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
 *   desktopChrome: Record<string, unknown>
 * }} options
 */
export function createLivePlaywrightConfig({
  paths,
  port,
  outputDirectory,
  launchOptions,
  desktopChrome
}) {
  const command = `bun run build && node ${shellQuote(paths.liveHostFile)} --port ${port}`;
  const viewport = { width: 1440, height: 960 };
  const contextOptions = { reducedMotion: 'reduce' };
  return {
    testDir: paths.liveTestsDirectory,
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
