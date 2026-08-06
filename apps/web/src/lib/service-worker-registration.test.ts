import { afterEach, describe, expect, it, vi } from 'vitest';
import { SERVICE_WORKER_SCRIPT_PATH } from './service-worker-policy';
import { registerServiceWorker } from './service-worker-registration';

const registration = {} as ServiceWorkerRegistration;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('registerServiceWorker', () => {
  it('registers the fixed worker from the root scope without awaiting startup', () => {
    const register = vi.fn(() => Promise.resolve(registration));

    const teardown = registerServiceWorker({ register });

    expect(register).toHaveBeenCalledOnce();
    expect(register).toHaveBeenCalledWith(SERVICE_WORKER_SCRIPT_PATH, { scope: '/' });
    teardown();
  });

  it('fails closed when service workers are unsupported', () => {
    vi.stubGlobal('navigator', {});

    expect(() => registerServiceWorker()).not.toThrow();
    expect(registerServiceWorker()).toEqual(expect.any(Function));
  });

  it('swallows registration failures without logging URL or error details', async () => {
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const register = vi.fn(() =>
      Promise.reject(new Error('https://prototype.test/private?token=synthetic'))
    );

    const teardown = registerServiceWorker({ register });
    await Promise.resolve();
    await Promise.resolve();
    teardown();

    expect(consoleError).not.toHaveBeenCalled();
    expect(consoleWarn).not.toHaveBeenCalled();
  });

  it('does not reload initial control when the page started uncontrolled', () => {
    const reload = vi.fn();
    vi.stubGlobal('location', { reload });
    const listeners = new Map<string, EventListener>();
    const container = {
      controller: null as ServiceWorker | null,
      register: vi.fn(() => Promise.resolve(registration)),
      addEventListener: vi.fn((type: string, listener: EventListener) => {
        listeners.set(type, listener);
      }),
      removeEventListener: vi.fn((type: string) => {
        listeners.delete(type);
      })
    };

    const teardown = registerServiceWorker(container);
    container.controller = {} as ServiceWorker;
    listeners.get('controllerchange')?.(new Event('controllerchange'));

    expect(reload).not.toHaveBeenCalled();
    teardown();
  });

  it('reloads once for a live update on an already controlled page', () => {
    const reload = vi.fn();
    vi.stubGlobal('location', { reload });
    const listeners = new Map<string, EventListener>();
    const container = {
      controller: {} as ServiceWorker | null,
      register: vi.fn(() => Promise.resolve(registration)),
      addEventListener: vi.fn((type: string, listener: EventListener) => {
        listeners.set(type, listener);
      }),
      removeEventListener: vi.fn((type: string) => {
        listeners.delete(type);
      })
    };

    const teardown = registerServiceWorker(container);
    container.controller = null;
    listeners.get('controllerchange')?.(new Event('controllerchange'));
    container.controller = {} as ServiceWorker;
    listeners.get('controllerchange')?.(new Event('controllerchange'));
    listeners.get('controllerchange')?.(new Event('controllerchange'));

    expect(reload).toHaveBeenCalledOnce();
    teardown();
  });

  it('tears down idempotently and suppresses a late controller change', () => {
    const reload = vi.fn();
    vi.stubGlobal('location', { reload });
    const listeners = new Map<string, EventListener>();
    const container = {
      controller: {} as ServiceWorker,
      register: vi.fn(() => Promise.resolve(registration)),
      addEventListener: vi.fn((type: string, listener: EventListener) => {
        listeners.set(type, listener);
      }),
      removeEventListener: vi.fn((type: string) => {
        listeners.delete(type);
      })
    };

    const teardown = registerServiceWorker(container);
    teardown();
    teardown();
    listeners.get('controllerchange')?.(new Event('controllerchange'));

    expect(container.removeEventListener).toHaveBeenCalledOnce();
    expect(reload).not.toHaveBeenCalled();
  });
});
