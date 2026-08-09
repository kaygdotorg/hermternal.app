import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.PLAYWRIGHT_PORT ?? 4173);

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: 'retain-on-failure',
    colorScheme: 'light'
  },
  webServer: {
    // Vite preview does not implement the documented private-route fallback.
    // Use the production-build evidence host so worker install can fetch both
    // /service-worker.js and its /200.html precache entry.
    command: `bun run build && node tests/static/static-host.mjs --port ${port}`,
    url: `http://127.0.0.1:${port}/`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  },
  projects: [
    {
      name: 'chromium',
      // Credential-bearing groups run only in the artifact-safe projects below.
      grepInvert: /credential-safe/u,
      use: { ...devices['Desktop Chrome'] }
    },
    {
      name: 'chromium-auth-safe',
      // Playwright trace snapshots retain DOM and action arguments. Keep every
      // credential-bearing lane in a worker whose public project config proves
      // trace, screenshot, and video are disabled. The true no-JavaScript lane
      // is isolated in the dedicated project below.
      grep: /credential-safe/u,
      grepInvert: /first-load no-script product route/u,
      use: {
        ...devices['Desktop Chrome'],
        trace: 'off',
        screenshot: 'off',
        video: 'off'
      }
    },
    {
      name: 'chromium-js-disabled',
      grep: /first-load no-script product route/u,
      use: {
        ...devices['Desktop Chrome'],
        javaScriptEnabled: false,
        trace: 'off',
        screenshot: 'off',
        video: 'off'
      }
    }
  ]
});
