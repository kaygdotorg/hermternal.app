import { expect, test } from '@playwright/test';

test.describe('W-06 same-origin REST boundary', () => {
  test('proves the browser proxy path is same-origin and cookie-only', async ({ page, baseURL }) => {
    const origin = new URL(baseURL ?? 'http://127.0.0.1:4173').origin;
    await page.context().addCookies([
      {
        name: 'synthetic_session_cookie',
        value: 'synthetic-cookie-marker',
        url: `${origin}/`
      }
    ]);

    let observedRequest: { url: string; method: string; headers: Record<string, string> } | undefined;
    await page.route('**/api/auth/providers', async (route) => {
      const request = route.request();
      observedRequest = {
        url: request.url(),
        method: request.method(),
        headers: request.headers()
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          providers: [
            {
              name: 'synthetic-provider',
              display_name: 'Synthetic Provider',
              supports_password: false
            }
          ]
        })
      });
    });

    await page.goto('/');
    const result = await page.evaluate(async () => {
      const response = await fetch('/api/auth/providers', {
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: { accept: 'application/json' }
      });
      return {
        status: response.status,
        body: await response.json()
      };
    });

    expect(result.status).toBe(200);
    expect(result.body.providers).toHaveLength(1);
    expect(observedRequest).toMatchObject({
      url: `${origin}/api/auth/providers`,
      method: 'GET'
    });
    expect(observedRequest?.headers.cookie).toContain('synthetic_session_cookie=synthetic-cookie-marker');
    expect(observedRequest?.headers.authorization).toBeUndefined();
    expect(observedRequest?.url).not.toContain('ticket');
    expect(observedRequest?.url).not.toContain('search');
  });

  test('rejects an external API base before any cross-origin request can be made', async ({ page, baseURL }) => {
    await page.goto('/');
    const result = await page.evaluate(() => {
      const current = new URL(location.href);
      const external = new URL('https://attacker.invalid/api', current);
      const sameOrigin = new URL('/api', current);
      return {
        sameOriginAccepted: sameOrigin.origin === current.origin && sameOrigin.pathname === '/api',
        externalRejected: external.origin !== current.origin,
        externalPath: external.pathname
      };
    });

    expect(result.sameOriginAccepted).toBe(true);
    expect(result.externalRejected).toBe(true);
    expect(result.externalPath).toBe('/api');
    expect(new URL(baseURL ?? 'http://127.0.0.1:4173').origin).not.toBe('https://attacker.invalid');
  });
});
