import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('reconciliation login cleanup ordering contract', () => {
  it('marks session risk before login transport and always keeps cleanup independent', async () => {
    const source = await readFile(
      resolve(process.cwd(), 'tests/live/reconcile-live-proof.spec.ts'),
      'utf8'
    );
    const loginRiskMark = source.indexOf('markLoginRequest();');
    const loginTransport = source.indexOf("kind: 'login'");
    expect(loginRiskMark).toBeGreaterThanOrEqual(0);
    expect(loginTransport).toBeGreaterThan(loginRiskMark);
    expect(source).toContain('logout: () => logoutAndVerify(context, baseURL)');
    expect(source).toContain('clearCookies: async () =>');
    expect(source).toContain('clearBrowserState: () => clearBrowserState(context, baseURL)');
    expect(source).not.toContain('if (authenticated)');
    expect(source).not.toContain('let authenticated');
  });
});
