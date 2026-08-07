import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.PLAYWRIGHT_LIVE_PORT ?? 4187);

export default defineConfig({
  testDir: './tests/live',
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  reporter: 'list',
  timeout: 120_000,
  expect: { timeout: 30_000 },
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    // Live credentials must never enter retained Playwright traces.
    trace: 'off',
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
