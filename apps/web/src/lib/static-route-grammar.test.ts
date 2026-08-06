import { describe, expect, it } from 'vitest';
import {
  CLIENT_ROUTE_PATTERN,
  isReservedPath,
  isSupportedClientRoute,
  RESERVED_PATH_PREFIXES
} from './static-route-grammar.mjs';
import { createServiceWorkerPolicy } from './service-worker-policy';
import {
  CLIENT_ROUTE_PATTERN as HOST_CLIENT_ROUTE_PATTERN,
  RESERVED_PATH_PREFIXES as HOST_RESERVED_PATH_PREFIXES,
  resolveStaticPath
} from '../../tests/static/static-host.mjs';

const origin = 'https://prototype.test';
const buildDirectory = '/tmp/hermternal-static-proof';
const policy = createServiceWorkerPolicy({
  version: 'route-parity',
  build: [],
  files: []
});

function navigationRequest(pathname: string): Request {
  return { url: `${origin}${pathname}`, method: 'GET', mode: 'navigate' } as Request;
}

describe('canonical static route grammar', () => {
  it('shares the exact client-route pattern and reserved prefixes with the static host', () => {
    expect(HOST_CLIENT_ROUTE_PATTERN.source).toBe(CLIENT_ROUTE_PATTERN.source);
    expect(HOST_RESERVED_PATH_PREFIXES).toEqual(RESERVED_PATH_PREFIXES);
  });

  it('serves the non-product W-06 browser proof from its generated route document', () => {
    expect(resolveStaticPath('/__w06/transport', buildDirectory)).toBe(
      `${buildDirectory}/__w06/transport/index.html`
    );
  });

  it('keeps worker and host decisions aligned for canonical deep-link cases', () => {
    const supported = [
      '/v1/c/abcdefghijklmnop',
      '/v1/c/abcdefghijklmnop/m/qrstuvwxyzabcdef'
    ];
    const denied = [
      '/v1/c/short',
      '/v1/c/abcdefghijklmnop?token=synthetic',
      '/v1/c/abcdefghijklmnop/',
      '/api/../v1/c/abcdefghijklmnop',
      '/api/%2e%2e/v1/c/abcdefghijklmnop',
      '/api\\..\\v1/c/abcdefghijklmnop',
      '/apiary/v1/c/abcdefghijklmnop'
    ];

    for (const pathname of supported) {
      expect(isSupportedClientRoute(pathname)).toBe(true);
      expect(resolveStaticPath(pathname, buildDirectory)).toBe(`${buildDirectory}/200.html`);
      expect(policy.cachePathForRequest(navigationRequest(pathname), origin)).toBe('/200.html');
    }

    for (const pathname of denied) {
      expect(isSupportedClientRoute(pathname)).toBe(false);
      expect(resolveStaticPath(pathname, buildDirectory)).toBeUndefined();
      expect(policy.cachePathForRequest(navigationRequest(pathname), origin)).toBeUndefined();
    }

    for (const prefix of RESERVED_PATH_PREFIXES) {
      expect(isReservedPath(prefix)).toBe(true);
      expect(isReservedPath(`${prefix}/nested`)).toBe(true);
    }
  });
});
