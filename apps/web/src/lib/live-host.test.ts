import { describe, expect, it } from 'vitest';
import { createLiveHost, validateLiveTarget } from '../../tests/live/live-host.mjs';

describe('disposable live proof target', () => {
  it.each([
    'http://127.0.0.1:19131',
    'http://127.255.255.254:19131/',
    'http://[::1]:19131',
    'http://localhost:19131'
  ])('accepts the reviewed loopback form %s', (value) => {
    const target = validateLiveTarget(value);

    expect(target.protocol).toBe('http:');
    expect(target.pathname).toBe('/');
  });

  it('requires an explicit HERMES_LIVE_TARGET when no target is supplied', () => {
    const previousTarget = process.env.HERMES_LIVE_TARGET;
    delete process.env.HERMES_LIVE_TARGET;
    try {
      expect(() => createLiveHost()).toThrow(/HERMES_LIVE_TARGET is required/iu);
    } finally {
      if (previousTarget === undefined) delete process.env.HERMES_LIVE_TARGET;
      else process.env.HERMES_LIVE_TARGET = previousTarget;
    }
  });

  it('requires an explicit port in the live target', () => {
    expect(() => validateLiveTarget('http://127.0.0.1')).toThrow(/explicit port/iu);
  });

  it.each([
    'https://127.0.0.1:19131',
    'http://localhost/',
    'http://[::1]',
    'http://127.0.0.1.evil.example:19131',
    'http://2130706433:19131',
    'http://0177.0.0.1:19131',
    'http://127.1:19131',
    'http://127.0.0.1%2eexample:19131',
    'http://user:password@127.0.0.1:19131',
    'http://[::ffff:127.0.0.1]:19131',
    'http://localhost.:19131',
    'http://127.0.0.1:00080',
    'http://127.0.0.1:65536',
    'http://127.0.0.1:19131/api',
    'http://127.0.0.1:19131?probe=1',
    'http://127.0.0.1:19131#fragment',
    'http://127.0.0.1:19131\\api',
    ' http://127.0.0.1:19131'
  ])('rejects unsafe or ambiguous target %s', (value) => {
    expect(() => validateLiveTarget(value)).toThrow();
  });

  it('rejects normalized URL objects instead of trusting their canonical href', () => {
    const normalizedTargets = [
      new URL('http://127.0.0.1:19131'),
      new URL('http://2130706433:19131'),
      new URL('http://0177.0.0.1:19131'),
      new URL('http://127.1:19131'),
      new URL('http://127.0.0.1:00080')
    ];

    for (const target of normalizedTargets) {
      expect(() => validateLiveTarget(target)).toThrow();
    }
  });

  it('rejects an unsafe target synchronously before creating a proxy-capable host', () => {
    expect(() =>
      createLiveHost({
        target: 'http://user:password@127.0.0.1:19131'
      })
    ).toThrow(/plain HTTP|userinfo/iu);
  });
});
