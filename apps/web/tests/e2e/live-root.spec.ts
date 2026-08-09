import { expect, test, type Route } from '@playwright/test';
import {
  clearNativeStorage,
  installNativeCredentialProof,
  overwriteNativeStorage,
  readNativeCredentialEvidence,
  readStorageEvidence,
  scrubNativeCredentialProof,
  seedNativeStorage,
  storageEvidenceEqual
} from './auth-proof';

test('normal root verifies identity and discovers password providers', async ({ page }) => {
  let identityRequestCount = 0;
  let providerRequestCount = 0;

  await page.route('**/api/auth/me', async (route) => {
    identityRequestCount += 1;
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ detail: 'not authenticated' })
    });
  });
  await page.route('**/api/auth/providers', async (route) => {
    providerRequestCount += 1;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
      })
    });
  });

  await page.goto('/');

  await expect(page.getByRole('button', { name: 'Disposable Basic' })).toBeVisible();
  expect(identityRequestCount).toBe(1);
  expect(providerRequestCount).toBe(1);
  await expect(page.getByTestId('status-success')).toHaveCount(0);
});

// Live-root authentication proof setup is credential-bearing. Disable all
// retained Playwright artifacts for this lane; evidence returns only counts,
// booleans, or non-reversible storage equality.
test.describe('credential-safe live-root authentication lanes', () => {

  test('native password button activation clears live values without navigation, storage mutation, serialization, or retained artifacts', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const authMePattern = '**/api/auth/me';
    const providersPattern = '**/api/auth/providers';
    const authMeHandler = async (route: Route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'not authenticated' })
      });
    };
    const providersHandler = async (route: Route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
        })
      });
    };

    for (const activation of ['click', 'enter'] as const) {
      const cdp = await page.context().newCDPSession(page);
      let requestCount = 0;
      let navigationCount = 0;
      let scriptDisabled = false;
      const onRequest = (request: { isNavigationRequest(): boolean }) => {
        requestCount += 1;
        if (request.isNavigationRequest()) navigationCount += 1;
      };
      try {
        await cdp.send('Emulation.setScriptExecutionDisabled', { value: false });
        await page.route(authMePattern, authMeHandler);
        await page.route(providersPattern, providersHandler);
        await page.goto('/');
        await page.getByRole('button', { name: 'Disposable Basic' }).click();
        await expect(page.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready');
        const originalUrl = page.url();
        const originalHistoryLength = await page.evaluate(() => history.length);

        await seedNativeStorage(page);
        const seededStorage = await readStorageEvidence(page);
        await overwriteNativeStorage(page);
        const overwrittenStorage = await readStorageEvidence(page);
        expect(storageEvidenceEqual(seededStorage, overwrittenStorage)).toBe(false);
        await seedNativeStorage(page);
        const storageBefore = await readStorageEvidence(page);
        expect(storageEvidenceEqual(seededStorage, storageBefore)).toBe(true);

        await installNativeCredentialProof(page);
        const signIn = page.getByRole('button', { name: 'Sign in' });
        const signInBox = await signIn.boundingBox();
        if (!signInBox || signInBox.width <= 0 || signInBox.height <= 0) {
          throw new Error('Sign-in target geometry unavailable.');
        }
        await signIn.focus();
        await expect(signIn).toBeFocused();

        await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });
        scriptDisabled = true;
        requestCount = 0;
        navigationCount = 0;
        page.on('request', onRequest);
        // Locator actions can evaluate JavaScript while the page is script-disabled.
        // Use the geometry and focus captured above with protocol-level input only.
        if (activation === 'click') {
          await page.mouse.click(
            signInBox.x + signInBox.width / 2,
            signInBox.y + signInBox.height / 2
          );
        } else {
          await page.keyboard.press('Enter');
        }

        await cdp.send('Emulation.setScriptExecutionDisabled', { value: false });
        scriptDisabled = false;
        const credentialEvidence = await readNativeCredentialEvidence(page);
        expect(credentialEvidence.liveValueMatchCount).toBe(0);
        expect(credentialEvidence.liveNonEmptyCount).toBe(0);
        expect(credentialEvidence.defaultValueMatchCount).toBe(0);
        expect(credentialEvidence.serializedCredentialCount).toBe(0);
        expect(credentialEvidence.formDataEventCount).toBe(0);
        expect(credentialEvidence.formDataConstructionCount).toBe(0);
        expect(credentialEvidence.formDataCredentialEntryCount).toBe(0);
        await expect(page).toHaveURL(originalUrl);
        expect(await page.evaluate(() => history.length)).toBe(originalHistoryLength);
        expect(navigationCount).toBe(0);
        expect(requestCount).toBe(0);
        expect(storageEvidenceEqual(storageBefore, await readStorageEvidence(page))).toBe(true);
      } finally {
        page.off('request', onRequest);
        await page.unroute(authMePattern, authMeHandler).catch(() => undefined);
        await page.unroute(providersPattern, providersHandler).catch(() => undefined);
        if (scriptDisabled) await cdp.send('Emulation.setScriptExecutionDisabled', { value: false }).catch(() => undefined);
        await scrubNativeCredentialProof(page);
        await clearNativeStorage(page);
        await cdp.detach().catch(() => undefined);
      }
    }
  });

  test('native field Enter preserves live values while failing closed without navigation, storage mutation, serialization, or observed FormData activity', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const authMePattern = '**/api/auth/me';
    const providersPattern = '**/api/auth/providers';
    const authMeHandler = async (route: Route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'not authenticated' })
      });
    };
    const providersHandler = async (route: Route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
        })
      });
    };
    const cdp = await page.context().newCDPSession(page);
    let requestCount = 0;
    let navigationCount = 0;
    let scriptDisabled = false;
    const onRequest = (request: { isNavigationRequest(): boolean }) => {
      requestCount += 1;
      if (request.isNavigationRequest()) navigationCount += 1;
    };

    try {
      await cdp.send('Emulation.setScriptExecutionDisabled', { value: false });
      await page.route(authMePattern, authMeHandler);
      await page.route(providersPattern, providersHandler);

      await page.goto('/');
      await page.getByRole('button', { name: 'Disposable Basic' }).click();
      const form = page.getByRole('form', { name: 'Hermes password sign in' });
      await expect(form).toHaveAttribute('data-field-ownership', 'ready');

      const originalUrl = page.url();
      const originalHistoryLength = await page.evaluate(() => history.length);
      await seedNativeStorage(page);
      const seededStorage = await readStorageEvidence(page);
      await overwriteNativeStorage(page);
      const overwrittenStorage = await readStorageEvidence(page);
      expect(storageEvidenceEqual(seededStorage, overwrittenStorage)).toBe(false);
      await seedNativeStorage(page);
      const storageBefore = await readStorageEvidence(page);
      expect(storageEvidenceEqual(seededStorage, storageBefore)).toBe(true);

      await installNativeCredentialProof(page);
      const password = page.getByRole('textbox', { name: 'Password' });
      const passwordBox = await password.boundingBox();
      if (!passwordBox || passwordBox.width <= 0 || passwordBox.height <= 0) {
        throw new Error('Password target geometry unavailable.');
      }
      await password.focus();
      await expect(password).toBeFocused();

      await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });
      scriptDisabled = true;
      requestCount = 0;
      navigationCount = 0;
      page.on('request', onRequest);
      // Keep the field focused before scripts are disabled; only protocol
      // keyboard input is permitted during the native-only action window.
      await page.keyboard.press('Enter');

      await cdp.send('Emulation.setScriptExecutionDisabled', { value: false });
      scriptDisabled = false;
      const credentialEvidence = await readNativeCredentialEvidence(page);
      expect(credentialEvidence.liveValueMatchCount).toBe(2);
      expect(credentialEvidence.liveNonEmptyCount).toBe(2);
      expect(credentialEvidence.defaultValueMatchCount).toBe(0);
      expect(credentialEvidence.serializedCredentialCount).toBe(0);
      expect(credentialEvidence.formDataEventCount).toBe(0);
      expect(credentialEvidence.formDataConstructionCount).toBe(0);
      expect(credentialEvidence.formDataCredentialEntryCount).toBe(0);
      await expect(page).toHaveURL(originalUrl);
      expect(await page.evaluate(() => history.length)).toBe(originalHistoryLength);
      expect(navigationCount).toBe(0);
      expect(requestCount).toBe(0);
      expect(storageEvidenceEqual(storageBefore, await readStorageEvidence(page))).toBe(true);
    } finally {
      page.off('request', onRequest);
      await page.unroute(authMePattern, authMeHandler).catch(() => undefined);
      await page.unroute(providersPattern, providersHandler).catch(() => undefined);
      if (scriptDisabled) await cdp.send('Emulation.setScriptExecutionDisabled', { value: false }).catch(() => undefined);
      await scrubNativeCredentialProof(page);
      await clearNativeStorage(page);
      await cdp.detach().catch(() => undefined);
    }
  });

  test('storage evidence fails closed for injected HMAC and IndexedDB failures', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const authMePattern = '**/api/auth/me';
    const providersPattern = '**/api/auth/providers';
    const spyGlobal = '__hermternalStorageEvidenceIdbSpy';
    const reviewedDatabaseName = '__hermternal_native_auth_proof__';
    const reviewedStoreName = 'proof';
    const reviewedKey = 'same-key';
    const authMeHandler = async (route: Route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'not authenticated' })
      });
    };
    const providersHandler = async (route: Route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
        })
      });
    };

    try {
      await page.route(authMePattern, authMeHandler);
      await page.route(providersPattern, providersHandler);
      await page.goto('/');
      await seedNativeStorage(page);

      const supported = await readStorageEvidence(page);
      expect(supported.cryptoSupported).toBe(true);
      expect(supported.status).toBe('supported');
      expect(supported.truncated).toBe(false);
      expect(supported.readFailure).toBe(false);
      expect(typeof supported.fingerprint).toBe('string');

      const failClosedInjections = [
        'crypto-unavailable',
        'import-key',
        'probe-sign',
        'sign',
        'cookie-read',
        'local-storage-read',
        'session-storage-read',
        'idb-metadata',
        'idb-open',
        'idb-read',
        'canonicalization'
      ] as const;
      for (const injectFailure of failClosedInjections) {
        const failed = await readStorageEvidence(page, { injectFailure });
        expect(failed).toMatchObject({
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
        });
        expect(storageEvidenceEqual(supported, failed)).toBe(false);
        expect(storageEvidenceEqual(failed, failed)).toBe(false);
      }

      const truncated = await readStorageEvidence(page, { injectFailure: 'truncation' });
      expect(truncated.cryptoSupported).toBe(true);
      expect(truncated.status).toBe('truncated');
      expect(truncated.truncated).toBe(true);
      expect(truncated.readFailure).toBe(false);
      expect(truncated.recordCount).toBeNull();
      expect(truncated.digestCount).toBeNull();
      expect(truncated.fingerprint).toBeNull();
      expect(truncated.recordLimit).toBeGreaterThan(0);
      expect(truncated.cookieCount).toBeNull();
      expect(truncated.localStorageEntryCount).toBeNull();
      expect(truncated.sessionStorageEntryCount).toBeNull();
      expect(truncated.indexedDbSupported).toBeNull();
      expect(truncated.indexedDbRecordCount).toBeNull();
      expect(truncated.indexedDbUnexpectedDatabaseCount).toBeNull();
      expect(truncated.indexedDbDatabaseCount).toBeNull();
      expect(truncated.indexedDbStoreCount).toBeNull();
      expect(truncated.cookieTruncated).toBe(true);
      expect(truncated.localStorageTruncated).toBe(false);
      expect(truncated.sessionStorageTruncated).toBe(false);
      expect(truncated.indexedDbTruncated).toBe(false);
      expect(truncated.truncation).toEqual({ any: true, cookie: true, localStorage: false, sessionStorage: false, indexedDb: false });
      expect(storageEvidenceEqual(supported, truncated)).toBe(false);
      expect(storageEvidenceEqual(truncated, truncated)).toBe(false);

      await page.evaluate(({ globalName, databaseName, storeName, key }) => {
        const windowRecord = window as unknown as Record<string, unknown>;
        const factoryPrototype = Object.getPrototypeOf(indexedDB) as IDBFactory;
        const databasePrototype = IDBDatabase.prototype;
        const storePrototype = IDBObjectStore.prototype;
        const databasesDescriptor = Object.getOwnPropertyDescriptor(factoryPrototype, 'databases');
        const openDescriptor = Object.getOwnPropertyDescriptor(factoryPrototype, 'open');
        const transactionDescriptor = Object.getOwnPropertyDescriptor(databasePrototype, 'transaction');
        const countDescriptor = Object.getOwnPropertyDescriptor(storePrototype, 'count');
        const getDescriptor = Object.getOwnPropertyDescriptor(storePrototype, 'get');
        if (!databasesDescriptor || !openDescriptor || !transactionDescriptor || !countDescriptor || !getDescriptor) {
          throw new Error('IndexedDB spy surface unavailable.');
        }

        const state = {
          databasesCalls: 0,
          openCalls: 0,
          openMismatchCount: 0,
          transactionCalls: 0,
          transactionMismatchCount: 0,
          countCalls: 0,
          countMismatchCount: 0,
          getCalls: 0,
          getMismatchCount: 0
        };
        const originalDatabases = factoryPrototype.databases;
        const originalOpen = factoryPrototype.open;
        const originalTransaction = databasePrototype.transaction;
        const originalCount = storePrototype.count;
        const originalGet = storePrototype.get;
        Object.defineProperty(factoryPrototype, 'databases', {
          ...databasesDescriptor,
          value: function (this: IDBFactory, ...args: unknown[]) {
            state.databasesCalls += 1;
            return Reflect.apply(originalDatabases, this, args);
          }
        });
        Object.defineProperty(factoryPrototype, 'open', {
          ...openDescriptor,
          value: function (this: IDBFactory, name: string, version?: number) {
            state.openCalls += 1;
            if (name !== databaseName) state.openMismatchCount += 1;
            return Reflect.apply(originalOpen, this, version === undefined ? [name] : [name, version]);
          }
        });
        Object.defineProperty(databasePrototype, 'transaction', {
          ...transactionDescriptor,
          value: function (this: IDBDatabase, storeNames: string | string[], mode?: IDBTransactionMode) {
            state.transactionCalls += 1;
            const names = Array.isArray(storeNames) ? storeNames : [storeNames];
            if (names.some((name) => name !== storeName) || mode !== 'readonly') state.transactionMismatchCount += 1;
            return Reflect.apply(originalTransaction, this, mode === undefined ? [storeNames] : [storeNames, mode]);
          }
        });
        Object.defineProperty(storePrototype, 'count', {
          ...countDescriptor,
          value: function (this: IDBObjectStore, query?: IDBValidKey | IDBKeyRange) {
            state.countCalls += 1;
            if (!(query instanceof IDBKeyRange) || query.lower !== key || query.upper !== key) state.countMismatchCount += 1;
            return Reflect.apply(originalCount, this, query === undefined ? [] : [query]);
          }
        });
        Object.defineProperty(storePrototype, 'get', {
          ...getDescriptor,
          value: function (this: IDBObjectStore, query: IDBValidKey | IDBKeyRange) {
            state.getCalls += 1;
            if (query !== key) state.getMismatchCount += 1;
            return Reflect.apply(originalGet, this, [query]);
          }
        });
        Object.defineProperty(windowRecord, globalName, {
          configurable: true,
          enumerable: false,
          value: {
            state,
            factoryPrototype,
            databasePrototype,
            storePrototype,
            databasesDescriptor,
            openDescriptor,
            transactionDescriptor,
            countDescriptor,
            getDescriptor
          }
        });
      }, { globalName: spyGlobal, databaseName: reviewedDatabaseName, storeName: reviewedStoreName, key: reviewedKey });

      const spiedEvidence = await readStorageEvidence(page);
      expect(spiedEvidence.cryptoSupported).toBe(true);
      expect(spiedEvidence.status).toBe('supported');
      expect(spiedEvidence.truncated).toBe(false);
      const spyEvidence = await page.evaluate((globalName) => {
        const probe = (window as unknown as Record<string, unknown>)[globalName] as
          | { state: Record<string, number> }
          | undefined;
        return {
          databasesCalls: probe?.state.databasesCalls ?? 0,
          openCalls: probe?.state.openCalls ?? 0,
          openMismatchCount: probe?.state.openMismatchCount ?? 0,
          transactionCalls: probe?.state.transactionCalls ?? 0,
          transactionMismatchCount: probe?.state.transactionMismatchCount ?? 0,
          countCalls: probe?.state.countCalls ?? 0,
          countMismatchCount: probe?.state.countMismatchCount ?? 0,
          getCalls: probe?.state.getCalls ?? 0,
          getMismatchCount: probe?.state.getMismatchCount ?? 0
        };
      }, spyGlobal);
      expect(spyEvidence.databasesCalls).toBeGreaterThan(0);
      expect(spyEvidence.openCalls).toBeGreaterThan(0);
      expect(spyEvidence.openMismatchCount).toBe(0);
      expect(spyEvidence.transactionCalls).toBeGreaterThan(0);
      expect(spyEvidence.transactionMismatchCount).toBe(0);
      expect(spyEvidence.countCalls).toBeGreaterThan(0);
      expect(spyEvidence.countMismatchCount).toBe(0);
      expect(spyEvidence.getCalls).toBeGreaterThan(0);
      expect(spyEvidence.getMismatchCount).toBe(0);
    } finally {
      const restoration = await page.evaluate((globalName) => {
        const windowRecord = window as unknown as Record<string, unknown>;
        const probe = windowRecord[globalName] as
          | {
              factoryPrototype: IDBFactory;
              databasePrototype: IDBDatabase;
              storePrototype: IDBObjectStore;
              databasesDescriptor: PropertyDescriptor;
              openDescriptor: PropertyDescriptor;
              transactionDescriptor: PropertyDescriptor;
              countDescriptor: PropertyDescriptor;
              getDescriptor: PropertyDescriptor;
            }
          | undefined;
        if (!probe) return { restored: true, spyAbsent: true };
        try {
          Object.defineProperty(probe.factoryPrototype, 'databases', probe.databasesDescriptor);
          Object.defineProperty(probe.factoryPrototype, 'open', probe.openDescriptor);
          Object.defineProperty(probe.databasePrototype, 'transaction', probe.transactionDescriptor);
          Object.defineProperty(probe.storePrototype, 'count', probe.countDescriptor);
          Object.defineProperty(probe.storePrototype, 'get', probe.getDescriptor);
          delete windowRecord[globalName];
          return {
            restored: true,
            spyAbsent: !Object.prototype.hasOwnProperty.call(windowRecord, globalName)
          };
        } catch {
          return { restored: false, spyAbsent: false };
        }
      }, spyGlobal).catch(() => ({ restored: false, spyAbsent: false }));
      try {
        expect(restoration.restored).toBe(true);
        expect(restoration.spyAbsent).toBe(true);
      } finally {
        await clearNativeStorage(page);
        await page.unroute(authMePattern, authMeHandler).catch(() => undefined);
        await page.unroute(providersPattern, providersHandler).catch(() => undefined);
      }
    }
  });

  test('native proof rollback restores listener, constructor, controls, and prior global after a setter failure', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const authMePattern = '**/api/auth/me';
    const providersPattern = '**/api/auth/providers';
    const rollbackProbeGlobal = '__hermternalNativeAuthInstallRollbackProbe';
    const authMeHandler = async (route: Parameters<Parameters<typeof page.route>[1]>[0]) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'not authenticated' })
      });
    };
    const providersHandler = async (route: Parameters<Parameters<typeof page.route>[1]>[0]) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
        })
      });
    };

    try {
      await page.route(authMePattern, authMeHandler);
      await page.route(providersPattern, providersHandler);
      await page.goto('/');
      await page.getByRole('button', { name: 'Disposable Basic' }).click();
      await expect(page.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute(
        'data-field-ownership',
        'ready'
      );

      await page.evaluate((globalName) => {
        const form = document.querySelector('form[aria-label="Hermes password sign in"]') as HTMLFormElement | null;
        const password = document.querySelector('#auth-password') as HTMLInputElement | null;
        const username = document.querySelector('#auth-username') as HTMLInputElement | null;
        if (!form || !password || !username) throw new Error('Rollback probe controls unavailable.');

        const formDataDescriptor = Object.getOwnPropertyDescriptor(window, 'FormData');
        const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
        if (!valueDescriptor?.set) throw new Error('Rollback probe setter unavailable.');
        const originalAddDescriptor = Object.getOwnPropertyDescriptor(form, 'addEventListener');
        const originalRemoveDescriptor = Object.getOwnPropertyDescriptor(form, 'removeEventListener');
        const originalAdd = form.addEventListener;
        const originalRemove = form.removeEventListener;
        const originalSetter = valueDescriptor.set;
        const state = {
          addCount: 0,
          removeCount: 0,
          formData: window.FormData,
          formDataDescriptor,
          valueDescriptor,
          originalSetter,
          originalAddDescriptor,
          originalRemoveDescriptor,
          form
        };
        const formRecord = form as unknown as Record<string, unknown>;
        Object.defineProperty(form, 'addEventListener', {
          configurable: true,
          enumerable: true,
          writable: true,
          value: function (type: string, listener: EventListenerOrEventListenerObject, options?: boolean | AddEventListenerOptions) {
            if (type === 'formdata') state.addCount += 1;
            return originalAdd.call(this, type, listener, options);
          }
        });
        Object.defineProperty(form, 'removeEventListener', {
          configurable: true,
          enumerable: true,
          writable: true,
          value: function (type: string, listener: EventListenerOrEventListenerObject, options?: boolean | EventListenerOptions) {
            if (type === 'formdata') state.removeCount += 1;
            return originalRemove.call(this, type, listener, options);
          }
        });
        Object.defineProperty(HTMLInputElement.prototype, 'value', {
          ...valueDescriptor,
          set(this: HTMLInputElement, nextValue: string) {
            if (this.id === 'auth-password' && nextValue.startsWith('native-proof-')) {
              throw new Error('Injected native-proof password setter failure.');
            }
            return originalSetter.call(this, nextValue);
          }
        });
        Object.defineProperty(window, globalName, { configurable: true, value: state });
        void formRecord;
      }, rollbackProbeGlobal);

      await expect(installNativeCredentialProof(page)).rejects.toThrow(
        'Injected native-proof password setter failure.'
      );

      const rollbackEvidence = await page.evaluate((globalName) => {
        const windowRecord = window as unknown as Record<string, unknown>;
        const state = windowRecord[globalName] as
          | {
              addCount: number;
              removeCount: number;
              formData: typeof FormData;
              formDataDescriptor?: PropertyDescriptor;
            }
          | undefined;
        const username = document.querySelector('#auth-username') as HTMLInputElement | null;
        const password = document.querySelector('#auth-password') as HTMLInputElement | null;
        const currentDescriptor = Object.getOwnPropertyDescriptor(window, 'FormData');
        const sameDescriptor = (left?: PropertyDescriptor, right?: PropertyDescriptor): boolean => {
          if (!left || !right) return left === right;
          return (
            left.configurable === right.configurable &&
            left.enumerable === right.enumerable &&
            ('value' in left) === ('value' in right) &&
            (!('value' in left) || left.value === right.value) &&
            (!('writable' in left) || left.writable === right.writable) &&
            (!('get' in left) || left.get === right.get) &&
            (!('set' in left) || left.set === right.set)
          );
        };
        return {
          globalAbsentOrUndefined: !Object.prototype.hasOwnProperty.call(windowRecord, '__hermternalNativeAuthProof') ||
            windowRecord.__hermternalNativeAuthProof === undefined,
          formDataRestored: state !== undefined && window.FormData === state.formData &&
            sameDescriptor(currentDescriptor, state.formDataDescriptor),
          addCount: state?.addCount ?? 0,
          removeCount: state?.removeCount ?? 0,
          usernameLiveEmpty: username?.value === '',
          usernameDefaultEmpty: username?.defaultValue === '',
          usernameAttributeAbsent: username?.hasAttribute('value') === false,
          passwordLiveEmpty: password?.value === '',
          passwordDefaultEmpty: password?.defaultValue === '',
          passwordAttributeAbsent: password?.hasAttribute('value') === false
        };
      }, rollbackProbeGlobal);
      expect(rollbackEvidence.globalAbsentOrUndefined).toBe(true);
      expect(rollbackEvidence.formDataRestored).toBe(true);
      expect(rollbackEvidence.addCount).toBe(1);
      expect(rollbackEvidence.removeCount).toBe(1);
      expect(rollbackEvidence.usernameLiveEmpty).toBe(true);
      expect(rollbackEvidence.usernameDefaultEmpty).toBe(true);
      expect(rollbackEvidence.usernameAttributeAbsent).toBe(true);
      expect(rollbackEvidence.passwordLiveEmpty).toBe(true);
      expect(rollbackEvidence.passwordDefaultEmpty).toBe(true);
      expect(rollbackEvidence.passwordAttributeAbsent).toBe(true);
    } finally {
      await scrubNativeCredentialProof(page);
      await page.evaluate((globalName) => {
        const windowRecord = window as unknown as Record<string, unknown>;
        const state = windowRecord[globalName] as
          | {
              form: HTMLFormElement;
              valueDescriptor: PropertyDescriptor;
              originalAddDescriptor?: PropertyDescriptor;
              originalRemoveDescriptor?: PropertyDescriptor;
            }
          | undefined;
        if (state) {
          Object.defineProperty(HTMLInputElement.prototype, 'value', state.valueDescriptor);
          if (state.originalAddDescriptor) {
            Object.defineProperty(state.form, 'addEventListener', state.originalAddDescriptor);
          } else {
            delete (state.form as unknown as Record<string, unknown>).addEventListener;
          }
          if (state.originalRemoveDescriptor) {
            Object.defineProperty(state.form, 'removeEventListener', state.originalRemoveDescriptor);
          } else {
            delete (state.form as unknown as Record<string, unknown>).removeEventListener;
          }
        }
        delete windowRecord[globalName];
      }, rollbackProbeGlobal).catch(() => undefined);
      await page.unroute(authMePattern, authMeHandler).catch(() => undefined);
      await page.unroute(providersPattern, providersHandler).catch(() => undefined);
    }
  });

  test('native proof rejects hidden extra and reordered controls before credential injection', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const authMePattern = '**/api/auth/me';
    const providersPattern = '**/api/auth/providers';
    const authMeHandler = async (route: Route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'not authenticated' })
      });
    };
    const providersHandler = async (route: Route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
        })
      });
    };

    try {
      await page.route(authMePattern, authMeHandler);
      await page.route(providersPattern, providersHandler);

      for (const mutation of ['hidden-extra', 'reordered', 'duplicate'] as const) {
        await page.goto('/');
        await page.getByRole('button', { name: 'Disposable Basic' }).click();
        const form = page.getByRole('form', { name: 'Hermes password sign in' });
        await expect(form).toHaveAttribute('data-field-ownership', 'ready');
        await page.evaluate((currentMutation) => {
          const form = document.querySelector('form[aria-label="Hermes password sign in"]') as HTMLFormElement | null;
          const username = form?.querySelector('input#auth-username') as HTMLInputElement | null;
          const password = form?.querySelector('input#auth-password') as HTMLInputElement | null;
          if (!form || !username || !password) throw new Error('Native auth proof controls are unavailable.');

          if (currentMutation === 'hidden-extra') {
            const extra = document.createElement('input');
            extra.type = 'hidden';
            extra.name = 'injected-control';
            form.appendChild(extra);
          } else if (currentMutation === 'reordered') {
            form.insertBefore(password, username);
          } else {
            form.appendChild(username.cloneNode(true));
          }
        }, mutation);

        await expect(installNativeCredentialProof(page)).rejects.toThrow(
          mutation === 'duplicate'
            ? 'Native auth proof controls are ambiguous.'
            : 'Native auth proof controls are not the reviewed pair.'
        );
        const boundedEvidence = await page.evaluate(() => {
          const windowRecord = window as unknown as Record<string, unknown>;
          const form = document.querySelector('form[aria-label="Hermes password sign in"]') as HTMLFormElement | null;
          const username = form?.querySelector('input#auth-username');
          const password = form?.querySelector('input#auth-password');
          const inputs = form ? Array.from(form.querySelectorAll('input')) : [];
          return {
            proofAbsentOrUndefined: !Object.prototype.hasOwnProperty.call(windowRecord, '__hermternalNativeAuthProof') ||
              windowRecord.__hermternalNativeAuthProof === undefined,
            inputCount: inputs.length,
            reviewedOrder: inputs.length === 2 && inputs[0] === username && inputs[1] === password
          };
        });
        expect(boundedEvidence.proofAbsentOrUndefined).toBe(true);
        if (mutation === 'hidden-extra' || mutation === 'duplicate') {
          expect(boundedEvidence.inputCount).toBe(3);
        } else {
          expect(boundedEvidence.inputCount).toBe(2);
          expect(boundedEvidence.reviewedOrder).toBe(false);
        }
      }
    } finally {
      await scrubNativeCredentialProof(page);
      await clearNativeStorage(page);
      await page.unroute(authMePattern, authMeHandler).catch(() => undefined);
      await page.unroute(providersPattern, providersHandler).catch(() => undefined);
    }
  });

  test('native proof restores pre-existing data and accessor globals after install failure', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const authMePattern = '**/api/auth/me';
    const providersPattern = '**/api/auth/providers';
    const proofGlobal = '__hermternalNativeAuthProof';
    const descriptorProbeGlobal = '__hermternalNativeAuthDescriptorProbe';
    const authMeHandler = async (route: Route) => {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'not authenticated' })
      });
    };
    const providersHandler = async (route: Route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          providers: [{ name: 'basic', display_name: 'Disposable Basic', supports_password: true }]
        })
      });
    };

    try {
      await page.route(authMePattern, authMeHandler);
      await page.route(providersPattern, providersHandler);
      await page.goto('/');
      await page.getByRole('button', { name: 'Disposable Basic' }).click();
      await expect(page.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute(
        'data-field-ownership',
        'ready'
      );

      for (const descriptorKind of ['data', 'accessor'] as const) {
        await page.evaluate(({ descriptorKind, descriptorProbeGlobal, proofGlobal }) => {
          const sentinel = { kind: descriptorKind };
          const getter = () => sentinel;
          const setter = (_next: unknown): void => undefined;
          const descriptor: PropertyDescriptor = descriptorKind === 'data'
            ? { configurable: true, enumerable: true, writable: true, value: sentinel }
            : { configurable: true, enumerable: false, get: getter, set: setter };
          Object.defineProperty(window, proofGlobal, descriptor);
          Object.defineProperty(window, descriptorProbeGlobal, {
            configurable: true,
            value: { descriptor, sentinel, getter, setter }
          });
        }, { descriptorKind, descriptorProbeGlobal, proofGlobal });

        try {
          await expect(installNativeCredentialProof(page, { injectFailure: 'after-formdata-install' })).rejects.toThrow(
            'Injected native auth proof install failure.'
          );
          const evidence = await page.evaluate(({ descriptorProbeGlobal, proofGlobal }) => {
            const windowRecord = window as unknown as Record<string, unknown>;
            const probe = windowRecord[descriptorProbeGlobal] as
              | {
                  descriptor: PropertyDescriptor;
                  sentinel: unknown;
                  getter: () => unknown;
                  setter: (_next: unknown) => void;
                }
              | undefined;
            const current = Object.getOwnPropertyDescriptor(window, proofGlobal);
            const sameDescriptor = (left?: PropertyDescriptor, right?: PropertyDescriptor): boolean => {
              if (!left || !right) return left === right;
              return (
                left.configurable === right.configurable &&
                left.enumerable === right.enumerable &&
                ('value' in left) === ('value' in right) &&
                (!('value' in left) || left.value === right.value) &&
                (!('writable' in left) || left.writable === right.writable) &&
                (!('get' in left) || left.get === right.get) &&
                (!('set' in left) || left.set === right.set)
              );
            };
            return {
              descriptorRestored: sameDescriptor(current, probe?.descriptor),
              dataValueRestored: current !== undefined && 'value' in current && current.value === probe?.sentinel,
              accessorFunctionsRestored: current !== undefined && !('value' in current) &&
                current.get === probe?.getter && current.set === probe?.setter
            };
          }, { descriptorProbeGlobal, proofGlobal });
          expect(evidence.descriptorRestored).toBe(true);
          if (descriptorKind === 'data') expect(evidence.dataValueRestored).toBe(true);
          else expect(evidence.accessorFunctionsRestored).toBe(true);
        } finally {
          await scrubNativeCredentialProof(page);
          await page.evaluate(({ descriptorProbeGlobal, proofGlobal }) => {
            delete (window as unknown as Record<string, unknown>)[proofGlobal];
            delete (window as unknown as Record<string, unknown>)[descriptorProbeGlobal];
          }, { descriptorProbeGlobal, proofGlobal });
        }
      }
    } finally {
      await scrubNativeCredentialProof(page);
      await page.unroute(authMePattern, authMeHandler).catch(() => undefined);
      await page.unroute(providersPattern, providersHandler).catch(() => undefined);
    }
  });
});
