import { expect, test, type Page } from '@playwright/test';

type BrowserProofResult = {
  providers: Array<{ name: string; displayName: string; supportsPassword: boolean }>;
  calls: Array<{
    input: string;
    method: string | null;
    credentials: string | null;
    cache: string | null;
    redirect: string | null;
    headers: Record<string, string>;
    hasBody: boolean;
    hasAuthorization: boolean;
  }>;
  forbidden: Array<{ apiBaseUrl: string; errorCode: string | null }>;
  forbiddenFetcherCalls: number;
};

type W06ProofWindow = Window & {
  __hermternalW06BrowserProof?: () => Promise<BrowserProofResult>;
};

async function waitForBrowserProof(page: Page): Promise<void> {
  // The route document is static, but its bundled proof callback is installed
  // during hydration. Wait for that reviewed boundary before evaluating it so
  // test scheduling cannot turn a valid bundle into a false missing-proof failure.
  await page.waitForFunction(
    () => typeof (window as W06ProofWindow).__hermternalW06BrowserProof === 'function'
  );
}

test.describe('W-06 same-origin REST boundary', () => {
  test('executes the exported transport in the browser context', async ({ page }) => {
    await page.goto('/__w06/transport');
    await waitForBrowserProof(page);
    await page.context().addCookies([
      {
        name: 'synthetic_session_cookie',
        value: 'synthetic-cookie-marker',
        url: new URL(page.url()).origin + '/'
      }
    ]);

    const result = await page.evaluate(async () => {
      const proofWindow = window as W06ProofWindow;
      if (!proofWindow.__hermternalW06BrowserProof) {
        throw new Error('The bundled W-06 browser proof is not available.');
      }
      return await proofWindow.__hermternalW06BrowserProof();
    });
    const proof = result as BrowserProofResult;

    expect(proof.providers).toEqual([
      {
        name: 'synthetic-provider',
        displayName: 'Synthetic Provider',
        supportsPassword: false
      }
    ]);
    expect(proof.calls).toEqual([
      {
        input: '/api/auth/providers',
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: { accept: 'application/json' },
        hasBody: false,
        hasAuthorization: false
      }
    ]);
  });

  test('rejects forbidden origins and API roots before the transport fetcher runs', async ({ page }) => {
    await page.goto('/__w06/transport');
    await waitForBrowserProof(page);

    const result = await page.evaluate(async () => {
      const proofWindow = window as W06ProofWindow;
      if (!proofWindow.__hermternalW06BrowserProof) {
        throw new Error('The bundled W-06 browser proof is not available.');
      }
      return await proofWindow.__hermternalW06BrowserProof();
    });
    const proof = result as BrowserProofResult;

    expect(proof.forbidden).toEqual([
      { apiBaseUrl: 'https://attacker.invalid/api', errorCode: 'invalid-url' },
      { apiBaseUrl: '//attacker.invalid/api', errorCode: 'invalid-url' },
      { apiBaseUrl: '/api/search', errorCode: 'invalid-url' },
      { apiBaseUrl: '/api/ws-ticket', errorCode: 'invalid-url' }
    ]);
    expect(proof.forbiddenFetcherCalls).toBe(0);
  });
});
