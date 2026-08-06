import { describe, expect, it, vi } from 'vitest';
import { discoverProviders, ProviderDiscoveryError, type ProviderDiscoveryFetch } from './provider-discovery';

function jsonResponse(body: string, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(body, {
    status,
    headers: {
      'content-type': 'application/json',
      ...headers
    }
  });
}

function providerPayload(): string {
  return JSON.stringify({
    providers: [
      {
        name: 'nous',
        display_name: 'Nous',
        supports_password: false
      },
      {
        name: 'hermes-password',
        display_name: 'Hermes password',
        supports_password: true
      }
    ]
  });
}

function cancellableResponse(
  status: number,
  contentType: string,
  headers: Record<string, string> = {}
): { response: Response; wasCancelled: () => boolean } {
  let cancelled = false;
  const response = new Response(
    new ReadableStream<Uint8Array>({
      cancel() {
        cancelled = true;
      }
    }),
    { status, headers: { 'content-type': contentType, ...headers } }
  );
  return { response, wasCancelled: () => cancelled };
}

describe('discoverProviders', () => {
  it('uses the strict same-origin GET boundary and preserves source order', async () => {
    const fetcher = vi.fn<ProviderDiscoveryFetch>().mockResolvedValue(jsonResponse(providerPayload()));

    const result = await discoverProviders({ fetch: fetcher });

    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledWith(
      '/api/auth/providers',
      expect.objectContaining({
        method: 'GET',
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        headers: { accept: 'application/json' },
        signal: expect.any(AbortSignal)
      })
    );
    expect(result.providers.map((provider) => provider.id)).toEqual(['nous', 'hermes-password']);
    expect(result.providers[0]?.kind).toBe('unavailable');
    expect(result.providers[1]?.kind).toBe('password');
  });

  it('rejects a successful empty registry because the pinned no-provider shape is an exact 503', async () => {
    const fetcher = vi.fn<ProviderDiscoveryFetch>().mockResolvedValue(jsonResponse('{"providers":[]}'));

    await expect(discoverProviders({ fetch: fetcher })).rejects.toMatchObject({ code: 'invalid-response' });
  });

  it('rejects malformed JSON, non-JSON whitespace, and duplicate JSON keys', async () => {
    const malformed = vi.fn<ProviderDiscoveryFetch>().mockResolvedValue(jsonResponse('{"providers":'));
    await expect(discoverProviders({ fetch: malformed })).rejects.toMatchObject({ code: 'malformed-json' });

    const nonJsonWhitespace = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(jsonResponse('{ "providers":[]}'));
    await expect(discoverProviders({ fetch: nonJsonWhitespace })).rejects.toMatchObject({ code: 'malformed-json' });

    const duplicate = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(jsonResponse('{"providers":[],"providers":[]}'));
    await expect(discoverProviders({ fetch: duplicate })).rejects.toMatchObject({ code: 'malformed-json' });
  });

  it('rejects unsafe and duplicate provider identities without turning names into capability policy', async () => {
    const unsafe = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(
        jsonResponse('{"providers":[{"name":"Nous","display_name":"Nous","supports_password":false}]}')
      );
    await expect(discoverProviders({ fetch: unsafe })).rejects.toMatchObject({ code: 'invalid-response' });

    const duplicate = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(
        jsonResponse(
          '{"providers":[{"name":"nous","display_name":"Nous","supports_password":false},{"name":"nous","display_name":"Nous 2","supports_password":false}]}'
        )
      );
    await expect(discoverProviders({ fetch: duplicate })).rejects.toMatchObject({ code: 'invalid-response' });

    const providerNeutral = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(
        jsonResponse(
          '{"providers":[{"name":"future-provider","display_name":"Future Provider","supports_password":false}]}'
        )
      );
    await expect(discoverProviders({ fetch: providerNeutral })).resolves.toMatchObject({
      providers: [{ id: 'future-provider', kind: 'unavailable' }]
    });
  });

  it('rejects unknown envelope, provider-row, and 503 keys instead of silently widening the schema', async () => {
    for (const body of [
      '{"providers":[{"name":"nous","display_name":"Nous","supports_password":false}],"version":2}',
      '{"providers":[{"name":"nous","display_name":"Nous","supports_password":false,"callback_url":"/auth/callback"}]}'
    ]) {
      const fetcher = vi.fn<ProviderDiscoveryFetch>().mockResolvedValue(jsonResponse(body));
      await expect(discoverProviders({ fetch: fetcher })).rejects.toMatchObject({ code: 'invalid-response' });
    }

    const widenedUnavailable = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(jsonResponse('{"detail":"no auth providers registered","retry_after":1}', 503));
    await expect(discoverProviders({ fetch: widenedUnavailable })).rejects.toMatchObject({
      code: 'invalid-response',
      status: 503
    });
  });

  it('recognizes only the reviewed empty-registry 503 response', async () => {
    const unavailable = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(jsonResponse('{"detail":"no auth providers registered"}', 503));
    await expect(discoverProviders({ fetch: unavailable })).rejects.toMatchObject({
      code: 'provider-unavailable',
      status: 503
    });

    const incompatible = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(jsonResponse('{"detail":"temporary outage"}', 503));
    await expect(discoverProviders({ fetch: incompatible })).rejects.toMatchObject({
      code: 'invalid-response',
      status: 503
    });
  });

  it('rejects non-JSON, redirects, and oversized bodies without echoing response data', async () => {
    const html = vi.fn<ProviderDiscoveryFetch>().mockResolvedValue(
      new Response('<html>secret server detail</html>', {
        status: 200,
        headers: { 'content-type': 'text/html' }
      })
    );
    await expect(discoverProviders({ fetch: html })).rejects.toMatchObject({ code: 'invalid-response' });
    await expect(discoverProviders({ fetch: html })).rejects.not.toThrow('secret server detail');

    const redirect = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(
        new Response('', { status: 302, headers: { location: '/login', 'content-type': 'application/json' } })
      );
    await expect(discoverProviders({ fetch: redirect })).rejects.toMatchObject({ code: 'redirect' });

    const oversized = vi
      .fn<ProviderDiscoveryFetch>()
      .mockResolvedValue(jsonResponse('{"providers":[]}', 200, { 'content-length': '100' }));
    await expect(discoverProviders({ fetch: oversized, maxBodyBytes: 10 })).rejects.toMatchObject({
      code: 'body-too-large'
    });
  });

  it('cancels rejected response bodies before returning bounded diagnostics', async () => {
    for (const [status, contentType, expectedCode] of [
      [200, 'text/html', 'invalid-response'],
      [302, 'application/json', 'redirect'],
      [500, 'application/json', 'http'],
      [503, 'text/html', 'invalid-response']
    ] as const) {
      const tracked = cancellableResponse(status, contentType);
      const fetcher = vi.fn<ProviderDiscoveryFetch>().mockResolvedValue(tracked.response);

      await expect(discoverProviders({ fetch: fetcher })).rejects.toMatchObject({ code: expectedCode, status });
      expect(tracked.wasCancelled()).toBe(true);
    }
  });

  it('cancels bodies rejected from malformed or oversized declared lengths', async () => {
    for (const [declaredLength, maxBodyBytes, expectedCode] of [
      ['invalid', 128, 'invalid-response'],
      ['129', 128, 'body-too-large']
    ] as const) {
      const tracked = cancellableResponse(200, 'application/json', { 'content-length': declaredLength });
      const fetcher = vi.fn<ProviderDiscoveryFetch>().mockResolvedValue(tracked.response);

      await expect(discoverProviders({ fetch: fetcher, maxBodyBytes })).rejects.toMatchObject({ code: expectedCode });
      expect(tracked.wasCancelled()).toBe(true);
    }
  });

  it('cancels an active response reader after headers when the caller aborts or the timeout expires', async () => {
    const callerTracked = cancellableResponse(200, 'application/json');
    const callerFetch = vi.fn<ProviderDiscoveryFetch>().mockResolvedValue(callerTracked.response);
    const controller = new AbortController();
    const callerResult = discoverProviders({ fetch: callerFetch, signal: controller.signal, timeoutMs: 1_000 });
    await vi.waitFor(() => expect(callerFetch).toHaveBeenCalledOnce());
    controller.abort();

    await expect(callerResult).rejects.toMatchObject({ code: 'aborted' });
    await vi.waitFor(() => expect(callerTracked.wasCancelled()).toBe(true));

    const timeoutTracked = cancellableResponse(200, 'application/json');
    const timeoutFetch = vi.fn<ProviderDiscoveryFetch>().mockResolvedValue(timeoutTracked.response);
    await expect(discoverProviders({ fetch: timeoutFetch, timeoutMs: 5 })).rejects.toMatchObject({ code: 'timeout' });
    await vi.waitFor(() => expect(timeoutTracked.wasCancelled()).toBe(true));
  });

  it('maps network failures, caller aborts, and timeouts to bounded diagnostics', async () => {
    const network = vi.fn<ProviderDiscoveryFetch>().mockRejectedValue(new Error('private server detail'));
    await expect(discoverProviders({ fetch: network })).rejects.toMatchObject({ code: 'network' });
    await expect(discoverProviders({ fetch: network })).rejects.not.toThrow('private server detail');

    const abortController = new AbortController();
    const pending = vi.fn<ProviderDiscoveryFetch>().mockImplementation(
      (_input, init) =>
        new Promise<Response>((resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), {
            once: true
          });
          void resolve;
        })
    );
    const aborted = discoverProviders({ fetch: pending, signal: abortController.signal, timeoutMs: 1_000 });
    abortController.abort();
    await expect(aborted).rejects.toMatchObject({ code: 'aborted' });

    const slow = vi.fn<ProviderDiscoveryFetch>().mockImplementation(() => new Promise<Response>(() => {}));
    await expect(discoverProviders({ fetch: slow, timeoutMs: 5 })).rejects.toMatchObject({ code: 'timeout' });
  });

  it('fails before calling fetch for an already-aborted signal and invalid bounds', async () => {
    const fetcher = vi.fn<ProviderDiscoveryFetch>();
    const controller = new AbortController();
    controller.abort();

    await expect(discoverProviders({ fetch: fetcher, signal: controller.signal })).rejects.toMatchObject({
      code: 'aborted'
    });
    expect(fetcher).not.toHaveBeenCalled();

    await expect(discoverProviders({ fetch: fetcher, timeoutMs: 30_001 })).rejects.toBeInstanceOf(
      ProviderDiscoveryError
    );
  });
});
