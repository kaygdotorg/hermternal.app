import { expect, test, type Page } from '@playwright/test';
import {
  clearNativeStorage,
  installNativeCredentialProof,
  readNativeCredentialEvidence,
  readStorageEvidence,
  scrubNativeCredentialProof,
  seedNativeStorage,
  storageEvidenceEqual,
  type StorageEvidence
} from './auth-proof';

const AUTH_ME_PATTERN = '**/api/auth/me';
const PROVIDERS_PATTERN = '**/api/auth/providers';
const AUTH_PROOF_GLOBAL = '__hermternalNativeAuthProof';
const HMAC_GLOBAL = '__hermternalNativeAuthProofHmacKey';
const HMAC_DESCRIPTOR_PROBE = '__hermternalAuthProofHmacDescriptorProbe';
const ARRAY_PROBE_GLOBAL = '__hermternalAuthProofCanonicalArrayProbe';
const CLEANUP_PROBE_GLOBAL = '__hermternalAuthProofCleanupProbe';

function supportedEvidence(): StorageEvidence {
  return {
    cryptoSupported: true,
    status: 'supported',
    truncated: false,
    readFailure: false,
    recordCount: 4,
    digestCount: 4,
    recordLimit: 2_048,
    cookieCount: 1,
    localStorageEntryCount: 1,
    sessionStorageEntryCount: 1,
    indexedDbSupported: true,
    indexedDbRecordCount: 1,
    indexedDbUnexpectedDatabaseCount: 0,
    indexedDbDatabaseCount: 1,
    indexedDbStoreCount: 1,
    cookieTruncated: false,
    localStorageTruncated: false,
    sessionStorageTruncated: false,
    indexedDbTruncated: false,
    truncation: {
      any: false,
      cookie: false,
      localStorage: false,
      sessionStorage: false,
      indexedDb: false
    },
    fingerprint: '0'.repeat(64)
  };
}

async function openPasswordPage(page: Page): Promise<void> {
  await page.route(AUTH_ME_PATTERN, async (route) => {
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ detail: 'not authenticated' })
    });
  });
  await page.route(PROVIDERS_PATTERN, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
      })
    });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Disposable Basic' }).click();
  await expect(page.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute(
    'data-field-ownership',
    'ready'
  );
}

async function closePasswordPageRoutes(page: Page): Promise<void> {
  await page.unroute(AUTH_ME_PATTERN).catch(() => undefined);
  await page.unroute(PROVIDERS_PATTERN).catch(() => undefined);
}

type CanonicalArrayVariant = 'sparse' | 'accessor' | 'extra' | 'symbol' | 'prototype' | 'proxy';

async function installCanonicalArrayProbe(page: Page, variant: CanonicalArrayVariant): Promise<void> {
  await page.evaluate(
    ({ globalName, variant }) => {
      if (typeof IDBObjectStore === 'undefined') throw new Error('IndexedDB object store is unavailable.');
      const originalDescriptor = Object.getOwnPropertyDescriptor(IDBObjectStore.prototype, 'get');
      if (!originalDescriptor || !('value' in originalDescriptor) || typeof originalDescriptor.value !== 'function') {
        throw new Error('IndexedDB get descriptor is unavailable.');
      }
      const originalGet = originalDescriptor.value as (this: IDBObjectStore, query?: IDBValidKey) => IDBRequest;
      let getterCalls = 0;
      const array = new Array<number>(3);
      array[0] = 1;
      array[2] = 3;
      if (variant === 'accessor') {
        Object.defineProperty(array, '1', {
          configurable: true,
          enumerable: true,
          get: () => {
            getterCalls += 1;
            return 2;
          }
        });
      } else if (variant === 'extra') {
        (array as number[] & { extra?: number }).extra = 4;
      } else if (variant === 'symbol') {
        Object.defineProperty(array, Symbol('extra'), { configurable: true, value: 4 });
      } else if (variant === 'prototype') {
        Object.setPrototypeOf(array, { injected: true });
      }
      const value = variant === 'proxy' ? new Proxy(array, {}) : array;
      const wrappedGet = function (this: IDBObjectStore, query?: IDBValidKey): IDBRequest {
        const request = Reflect.apply(originalGet, this, query === undefined ? [] : [query]);
        if (query === 'same-key') {
          Object.defineProperty(request, 'result', {
            configurable: true,
            enumerable: false,
            get: () => value
          });
        }
        return request;
      };
      let restored = false;
      const restore = (): { restored: boolean; getterCalls: number } => {
        if (!restored) {
          Object.defineProperty(IDBObjectStore.prototype, 'get', originalDescriptor);
          delete (window as unknown as Record<string, unknown>)[globalName];
          restored = true;
        }
        return { restored, getterCalls };
      };
      Object.defineProperty(IDBObjectStore.prototype, 'get', {
        ...originalDescriptor,
        value: wrappedGet
      });
      Object.defineProperty(window, globalName, {
        configurable: true,
        enumerable: false,
        writable: false,
        value: { restore }
      });
    },
    { globalName: ARRAY_PROBE_GLOBAL, variant }
  );
}

async function restoreCanonicalArrayProbe(page: Page): Promise<{ restored: boolean; getterCalls: number }> {
  return await page.evaluate((globalName) => {
    const probe = (window as unknown as Record<string, unknown>)[globalName] as
      | { restore?: () => { restored: boolean; getterCalls: number } }
      | undefined;
    if (!probe?.restore) return { restored: true, getterCalls: 0 };
    try {
      return probe.restore();
    } catch {
      return { restored: false, getterCalls: 0 };
    }
  }, ARRAY_PROBE_GLOBAL);
}

async function installCleanupSetterFailure(page: Page): Promise<void> {
  await page.evaluate((globalName) => {
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (!descriptor?.set) throw new Error('Input value descriptor is unavailable.');
    const originalSetter = descriptor.set;
    const failingSetter = function (this: HTMLInputElement, value: string): void {
      if (this.id === 'auth-password' && value === '') throw new Error('cleanup setter failure');
      originalSetter.call(this, value);
    };
    Object.defineProperty(HTMLInputElement.prototype, 'value', { ...descriptor, set: failingSetter });
    Object.defineProperty(window, globalName, {
      configurable: true,
      enumerable: false,
      writable: false,
      value: { descriptor }
    });
  }, CLEANUP_PROBE_GLOBAL);
}

async function installCleanupListenerFailure(page: Page): Promise<void> {
  await page.evaluate((globalName) => {
    const form = document.querySelector('form[aria-label="Hermes password sign in"]');
    if (!(form instanceof HTMLFormElement)) throw new Error('Password form is unavailable.');
    const original = form.removeEventListener;
    Object.defineProperty(form, 'removeEventListener', {
      configurable: true,
      enumerable: false,
      writable: true,
      value: function (): never {
        throw new Error('cleanup listener failure');
      }
    });
    Object.defineProperty(window, globalName, {
      configurable: true,
      enumerable: false,
      writable: false,
      value: { form, original }
    });
  }, CLEANUP_PROBE_GLOBAL);
}

async function restoreCleanupProbe(page: Page): Promise<void> {
  await page.evaluate((globalName) => {
    const windowRecord = window as unknown as Record<string, unknown>;
    const probe = windowRecord[globalName] as
      | { descriptor?: PropertyDescriptor; form?: HTMLFormElement; original?: typeof EventTarget.prototype.removeEventListener }
      | undefined;
    try {
      if (probe?.descriptor) Object.defineProperty(HTMLInputElement.prototype, 'value', probe.descriptor);
      if (probe?.form && probe.original) {
        Object.defineProperty(probe.form, 'removeEventListener', {
          configurable: true,
          enumerable: false,
          writable: true,
          value: probe.original
        });
        Reflect.deleteProperty(probe.form, 'removeEventListener');
      }
    } finally {
      delete windowRecord[globalName];
    }
  }, CLEANUP_PROBE_GLOBAL);
}

test.describe('credential-safe auth-proof helper regressions', () => {
  test('credential-safe evidence equality rejects exact-shape violations without invoking getters', async () => {
    const base = supportedEvidence();
    expect(storageEvidenceEqual(base, supportedEvidence())).toBe(true);

    const extraEnumerable = { ...base, extraField: true } as StorageEvidence & { extraField: boolean };
    expect(storageEvidenceEqual(base, extraEnumerable)).toBe(false);

    const extraNonEnumerable = supportedEvidence() as StorageEvidence & { extraField?: boolean };
    Object.defineProperty(extraNonEnumerable, 'extraField', {
      configurable: true,
      enumerable: false,
      value: true
    });
    expect(storageEvidenceEqual(base, extraNonEnumerable)).toBe(false);

    const symbolExtra = supportedEvidence();
    Object.defineProperty(symbolExtra, Symbol('extra'), { configurable: true, value: true });
    expect(storageEvidenceEqual(base, symbolExtra)).toBe(false);

    const inherited = Object.create({ inheritedField: true }) as StorageEvidence;
    Object.assign(inherited, base);
    expect(storageEvidenceEqual(base, inherited)).toBe(false);

    const customPrototype = supportedEvidence();
    Object.setPrototypeOf(customPrototype, { inheritedField: true });
    expect(storageEvidenceEqual(base, customPrototype)).toBe(false);

    let getterCalls = 0;
    const accessor = supportedEvidence();
    Object.defineProperty(accessor, 'fingerprint', {
      configurable: true,
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return '0'.repeat(64);
      }
    });
    expect(storageEvidenceEqual(base, accessor)).toBe(false);
    expect(getterCalls).toBe(0);

    const setter = supportedEvidence();
    Object.defineProperty(setter, 'fingerprint', {
      configurable: true,
      enumerable: true,
      set: () => undefined
    });
    expect(storageEvidenceEqual(base, setter)).toBe(false);

    const movedKey = supportedEvidence() as StorageEvidence & { moved?: unknown };
    delete (movedKey as Record<string, unknown>).fingerprint;
    movedKey.moved = true;
    expect(storageEvidenceEqual(base, movedKey)).toBe(false);

    const proxy = new Proxy(supportedEvidence(), {
      get: () => {
        throw new Error('proxy get must not be used');
      }
    });
    expect(storageEvidenceEqual(base, proxy)).toBe(false);

    const unsupported = {
      cryptoSupported: false,
      status: 'unsupported',
      truncated: null,
      readFailure: true,
      recordCount: null,
      digestCount: null,
      recordLimit: null,
      cookieCount: null,
      localStorageEntryCount: null,
      sessionStorageEntryCount: null,
      indexedDbSupported: null,
      indexedDbRecordCount: null,
      indexedDbUnexpectedDatabaseCount: null,
      indexedDbDatabaseCount: null,
      indexedDbStoreCount: null,
      cookieTruncated: null,
      localStorageTruncated: null,
      sessionStorageTruncated: null,
      indexedDbTruncated: null,
      truncation: { any: null, cookie: null, localStorage: null, sessionStorage: null, indexedDb: null },
      fingerprint: null
    } satisfies StorageEvidence;
    expect(storageEvidenceEqual(unsupported, unsupported)).toBe(false);
  });

  test('credential-safe array canonicalization preserves sparse holes and rejects unsafe shapes without getter calls', async ({ page }) => {
    await openPasswordPage(page);
    try {
      for (const variant of ['sparse', 'accessor', 'extra', 'symbol', 'prototype', 'proxy'] as const) {
        await seedNativeStorage(page);
        await installCanonicalArrayProbe(page, variant);
        let evidence: Awaited<ReturnType<typeof readStorageEvidence>>;
        try {
          evidence = await readStorageEvidence(page);
        } finally {
          const observation = await restoreCanonicalArrayProbe(page);
          expect(observation.restored).toBe(true);
          if (variant === 'accessor') expect(observation.getterCalls).toBe(0);
        }
        if (variant === 'sparse') {
          expect(evidence.status).toBe('supported');
          expect(storageEvidenceEqual(evidence, evidence)).toBe(true);
        } else {
          expect(evidence.status).toBe('unsupported');
          expect(storageEvidenceEqual(evidence, evidence)).toBe(false);
        }
        await clearNativeStorage(page);
      }
    } finally {
      await restoreCanonicalArrayProbe(page);
      await clearNativeStorage(page).catch(() => undefined);
      await closePasswordPageRoutes(page);
    }
  });

  test('credential-safe HMAC ownership restores prior descriptors and never removes a replacement state', async ({ page }) => {
    await openPasswordPage(page);
    try {
      for (const descriptorKind of ['data', 'accessor'] as const) {
        await page.evaluate(({ descriptorKind, descriptorProbeGlobal, hmacGlobal }) => {
          const getter = () => undefined;
          const setter = (_next: unknown): void => undefined;
          const descriptor: PropertyDescriptor = descriptorKind === 'data'
            ? { configurable: true, enumerable: true, writable: true, value: undefined }
            : { configurable: true, enumerable: false, get: getter, set: setter };
          Object.defineProperty(window, hmacGlobal, descriptor);
          Object.defineProperty(window, descriptorProbeGlobal, {
            configurable: true,
            enumerable: false,
            writable: false,
            value: { descriptor, getter, setter }
          });
        }, {
          descriptorKind,
          descriptorProbeGlobal: HMAC_DESCRIPTOR_PROBE,
          hmacGlobal: HMAC_GLOBAL
        });
        const evidence = await readStorageEvidence(page);
        expect(evidence.status).toBe('supported');
        await clearNativeStorage(page);
        const restored = await page.evaluate(({ descriptorProbeGlobal, hmacGlobal, descriptorKind }) => {
          const record = (window as unknown as Record<string, unknown>)[descriptorProbeGlobal] as
            | { descriptor?: PropertyDescriptor; getter?: () => undefined; setter?: (_next: unknown) => void }
            | undefined;
          const current = Object.getOwnPropertyDescriptor(window, hmacGlobal);
          const expected = record?.descriptor;
          const sameDescriptor = (left?: PropertyDescriptor, right?: PropertyDescriptor): boolean => {
            if (!left || !right) return left === right;
            if (left.configurable !== right.configurable || left.enumerable !== right.enumerable) return false;
            const leftData = Object.prototype.hasOwnProperty.call(left, 'value');
            const rightData = Object.prototype.hasOwnProperty.call(right, 'value');
            if (leftData !== rightData) return false;
            if (leftData) return left.value === right.value && left.writable === right.writable;
            return left.get === right.get && left.set === right.set;
          };
          return {
            descriptorRestored: sameDescriptor(current, expected),
            dataUndefined: descriptorKind === 'data' && current?.value === undefined,
            accessorIdentity: descriptorKind === 'accessor' && current?.get === record?.getter && current?.set === record?.setter
          };
        }, {
          descriptorProbeGlobal: HMAC_DESCRIPTOR_PROBE,
          hmacGlobal: HMAC_GLOBAL,
          descriptorKind
        });
        expect(restored.descriptorRestored).toBe(true);
        expect(restored.dataUndefined).toBe(descriptorKind === 'data');
        expect(restored.accessorIdentity).toBe(descriptorKind === 'accessor');
        await page.evaluate((probeGlobal) => {
          delete (window as unknown as Record<string, unknown>)[probeGlobal];
        }, HMAC_DESCRIPTOR_PROBE);
      }

      await seedNativeStorage(page);
      const supported = await readStorageEvidence(page);
      expect(supported.status).toBe('supported');
      await page.evaluate(({ hmacGlobal, probeGlobal }) => {
        const windowRecord = window as unknown as Record<string, unknown>;
        const state = windowRecord[hmacGlobal];
        const replacement = { replacement: true };
        Object.defineProperty(window, probeGlobal, {
          configurable: true,
          enumerable: false,
          writable: false,
          value: { state, replacement }
        });
        Object.defineProperty(window, hmacGlobal, {
          configurable: true,
          enumerable: false,
          writable: true,
          value: replacement
        });
      }, { hmacGlobal: HMAC_GLOBAL, probeGlobal: HMAC_DESCRIPTOR_PROBE });
      let cleanupFailed = false;
      try {
        await clearNativeStorage(page);
      } catch (error) {
        cleanupFailed = error instanceof Error && error.message === 'Native storage cleanup failed: hmac-global';
      }
      expect(cleanupFailed).toBe(true);
      const replacementRetained = await page.evaluate(({ hmacGlobal, probeGlobal }) => {
        const windowRecord = window as unknown as Record<string, unknown>;
        const probe = windowRecord[probeGlobal] as { replacement?: unknown } | undefined;
        return {
          replacementStillCurrent: windowRecord[hmacGlobal] === probe?.replacement,
          replacementIsObject: typeof windowRecord[hmacGlobal] === 'object' && windowRecord[hmacGlobal] !== null
        };
      }, { hmacGlobal: HMAC_GLOBAL, probeGlobal: HMAC_DESCRIPTOR_PROBE });
      expect(replacementRetained.replacementStillCurrent).toBe(true);
      expect(replacementRetained.replacementIsObject).toBe(true);
      await page.evaluate(({ hmacGlobal, probeGlobal }) => {
        const windowRecord = window as unknown as Record<string, unknown>;
        const probe = windowRecord[probeGlobal] as { state?: unknown } | undefined;
        Object.defineProperty(window, hmacGlobal, {
          configurable: true,
          enumerable: false,
          writable: false,
          value: probe?.state
        });
      }, { hmacGlobal: HMAC_GLOBAL, probeGlobal: HMAC_DESCRIPTOR_PROBE });
      await clearNativeStorage(page);
      await page.evaluate((probeGlobal) => {
        delete (window as unknown as Record<string, unknown>)[probeGlobal];
      }, HMAC_DESCRIPTOR_PROBE);
    } finally {
      await clearNativeStorage(page).catch(() => undefined);
      await page.evaluate((descriptorProbeGlobal) => {
        delete (window as unknown as Record<string, unknown>)[descriptorProbeGlobal];
      }, HMAC_DESCRIPTOR_PROBE).catch(() => undefined);
      await closePasswordPageRoutes(page);
    }
  });

  test('credential-safe native proof cleanup surfaces failures and succeeds on retry', async ({ page }) => {
    await openPasswordPage(page);
    try {
      for (const failureKind of ['setter', 'listener'] as const) {
        await installNativeCredentialProof(page);
        if (failureKind === 'setter') await installCleanupSetterFailure(page);
        else await installCleanupListenerFailure(page);

        let firstFailure = '';
        try {
          await scrubNativeCredentialProof(page);
        } catch (error) {
          firstFailure = error instanceof Error ? error.message : '';
        }
        expect(firstFailure.startsWith('Native auth proof cleanup failed:')).toBe(true);
        const retained = await page.evaluate((globalName) => {
          const windowRecord = window as unknown as Record<string, unknown>;
          const proof = windowRecord[globalName] as { kind?: string; state?: { formDataListener?: unknown } } | undefined;
          const password = document.querySelector('#auth-password') as HTMLInputElement | null;
          return {
            proofRetained: proof?.kind === 'native-auth-proof',
            listenerRetained: typeof proof?.state?.formDataListener === 'function',
            passwordNonEmpty: password !== null && password.value !== ''
          };
        }, AUTH_PROOF_GLOBAL);
        expect(retained.proofRetained).toBe(true);
        if (failureKind === 'listener') expect(retained.listenerRetained).toBe(true);

        await restoreCleanupProbe(page);
        await scrubNativeCredentialProof(page);
        const cleared = await page.evaluate(() => {
          const username = document.querySelector('#auth-username') as HTMLInputElement | null;
          const password = document.querySelector('#auth-password') as HTMLInputElement | null;
          return {
            proofAbsent: !Object.prototype.hasOwnProperty.call(window, '__hermternalNativeAuthProof'),
            liveNonEmptyCount: Number(username?.value !== '') + Number(password?.value !== ''),
            defaultNonEmptyCount: Number(username?.defaultValue !== '') + Number(password?.defaultValue !== ''),
            serializedValueAttributeCount: Number(username?.hasAttribute('value')) + Number(password?.hasAttribute('value'))
          };
        });
        expect(cleared.proofAbsent).toBe(true);
        expect(cleared.liveNonEmptyCount).toBe(0);
        expect(cleared.defaultNonEmptyCount).toBe(0);
        expect(cleared.serializedValueAttributeCount).toBe(0);
      }
    } finally {
      await restoreCleanupProbe(page);
      await scrubNativeCredentialProof(page).catch(() => undefined);
      await closePasswordPageRoutes(page);
    }
  });

  test('credential-safe proof cleanup reports page-evaluation failure without exposing details', async ({ page }) => {
    await page.close();
    await expect(scrubNativeCredentialProof(page)).rejects.toThrow('Native auth proof cleanup failed: page-evaluate');
  });
});
