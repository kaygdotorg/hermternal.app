import { randomUUID } from 'node:crypto';
import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { createServer } from 'node:net';
import type { Readable } from 'node:stream';
import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page, type Route } from '@playwright/test';
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

let uiPreviewOrigin = '';
let previewProcess: ChildProcessByStdio<null, Readable, Readable> | undefined;

type PreviewDiagnosticCode =
  | 'preview-process-error'
  | 'preview-process-exit'
  | 'preview-readiness-http-failure'
  | 'preview-readiness-fetch-failure'
  | 'preview-readiness-timeout';

type PreviewDiagnosticStream = 'stdout' | 'stderr';

type PreviewDiagnostics = {
  lastErrorCode: PreviewDiagnosticCode | null;
  stdoutChunkCount: number;
  stdoutByteCount: number;
  stderrChunkCount: number;
  stderrByteCount: number;
  processErrorCount: number;
  processExitCount: number;
  processExitCode: number | null;
  processTerminatedBySignal: boolean;
  readinessHttpFailureCount: number;
  readinessHttpStatus: number | null;
  readinessFetchFailureCount: number;
};

const MAX_PREVIEW_DIAGNOSTIC_CHUNKS = 1_024;
const MAX_PREVIEW_DIAGNOSTIC_BYTES = 64 * 1_024;

function createPreviewDiagnostics(): PreviewDiagnostics {
  return {
    lastErrorCode: null,
    stdoutChunkCount: 0,
    stdoutByteCount: 0,
    stderrChunkCount: 0,
    stderrByteCount: 0,
    processErrorCount: 0,
    processExitCount: 0,
    processExitCode: null,
    processTerminatedBySignal: false,
    readinessHttpFailureCount: 0,
    readinessHttpStatus: null,
    readinessFetchFailureCount: 0
  };
}

function boundedIncrement(value: number, limit: number): number {
  return Math.min(limit, value + 1);
}

function boundedByteCount(value: number, amount: number): number {
  if (!Number.isSafeInteger(amount) || amount < 0) return value;
  return Math.min(MAX_PREVIEW_DIAGNOSTIC_BYTES, value + amount);
}

function recordPreviewOutput(
  diagnostics: PreviewDiagnostics,
  stream: PreviewDiagnosticStream,
  chunk: Buffer
): void {
  if (stream === 'stdout') {
    diagnostics.stdoutChunkCount = boundedIncrement(diagnostics.stdoutChunkCount, MAX_PREVIEW_DIAGNOSTIC_CHUNKS);
    diagnostics.stdoutByteCount = boundedByteCount(diagnostics.stdoutByteCount, chunk.byteLength);
    return;
  }
  diagnostics.stderrChunkCount = boundedIncrement(diagnostics.stderrChunkCount, MAX_PREVIEW_DIAGNOSTIC_CHUNKS);
  diagnostics.stderrByteCount = boundedByteCount(diagnostics.stderrByteCount, chunk.byteLength);
}

function recordPreviewProcessError(diagnostics: PreviewDiagnostics, _rawError: unknown): void {
  // Deliberately ignore the raw error object. Its message, stack, and cause may
  // contain arbitrary URLs, headers, payloads, or credential-adjacent values.
  diagnostics.lastErrorCode = 'preview-process-error';
  diagnostics.processErrorCount = boundedIncrement(diagnostics.processErrorCount, MAX_PREVIEW_DIAGNOSTIC_CHUNKS);
}

function recordPreviewProcessExit(
  diagnostics: PreviewDiagnostics,
  code: number | null,
  signal: NodeJS.Signals | null
): void {
  diagnostics.lastErrorCode = 'preview-process-exit';
  diagnostics.processExitCount = boundedIncrement(diagnostics.processExitCount, MAX_PREVIEW_DIAGNOSTIC_CHUNKS);
  diagnostics.processExitCode = Number.isSafeInteger(code) ? code : null;
  diagnostics.processTerminatedBySignal = signal !== null;
}

function recordPreviewReadinessHttpFailure(diagnostics: PreviewDiagnostics, status: number): void {
  diagnostics.lastErrorCode = 'preview-readiness-http-failure';
  diagnostics.readinessHttpFailureCount = boundedIncrement(
    diagnostics.readinessHttpFailureCount,
    MAX_PREVIEW_DIAGNOSTIC_CHUNKS
  );
  diagnostics.readinessHttpStatus = Number.isSafeInteger(status) && status >= 100 && status <= 599 ? status : null;
}

function recordPreviewReadinessFetchFailure(diagnostics: PreviewDiagnostics): void {
  diagnostics.lastErrorCode = 'preview-readiness-fetch-failure';
  diagnostics.readinessFetchFailureCount = boundedIncrement(
    diagnostics.readinessFetchFailureCount,
    MAX_PREVIEW_DIAGNOSTIC_CHUNKS
  );
}

function snapshotPreviewDiagnostics(diagnostics: PreviewDiagnostics): PreviewDiagnostics {
  return { ...diagnostics };
}

function createPreviewDiagnosticError(code: PreviewDiagnosticCode, diagnostics: PreviewDiagnostics): Error {
  const snapshot = snapshotPreviewDiagnostics(diagnostics);
  return new Error(
    `UI preview ${code}; stdoutChunks=${snapshot.stdoutChunkCount}; stdoutBytes=${snapshot.stdoutByteCount}; ` +
      `stderrChunks=${snapshot.stderrChunkCount}; stderrBytes=${snapshot.stderrByteCount}; ` +
      `processErrors=${snapshot.processErrorCount}; processExits=${snapshot.processExitCount}; ` +
      `exitCode=${snapshot.processExitCode ?? 'null'}; terminatedBySignal=${snapshot.processTerminatedBySignal}; ` +
      `httpFailures=${snapshot.readinessHttpFailureCount}; httpStatus=${snapshot.readinessHttpStatus ?? 'null'}; ` +
      `fetchFailures=${snapshot.readinessFetchFailureCount}`
  );
}

let previewDiagnostics = createPreviewDiagnostics();
let previewLifecycleHandlers:
  | {
      collectStdoutDiagnostics: (chunk: Buffer) => void;
      collectStderrDiagnostics: (chunk: Buffer) => void;
      onError: (error: Error) => void;
      onExit: (code: number | null, signal: NodeJS.Signals | null) => void;
    }
  | undefined;

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', () => reject(new Error('UI preview port reservation failed.')));
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('The UI preview test could not reserve a local port.');
  }

  const port = address.port;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(new Error('UI preview port release failed.')) : resolve()));
  });
  return port;
}

async function waitForPreview(url: string): Promise<void> {
  const deadline = Date.now() + 15_000;

  while (Date.now() < deadline) {
    if (previewProcess?.exitCode !== null && previewProcess?.exitCode !== undefined) {
      throw createPreviewDiagnosticError('preview-process-exit', previewDiagnostics);
    }

    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) break;
    // Bound every fetch independently so a hung preview cannot consume time
    // past the shared readiness deadline or mask a process failure. The URL is
    // used only for the request and never enters retained diagnostics.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), remainingMs);
    try {
      const response = await fetch(url, { redirect: 'manual', signal: controller.signal });
      if (response.status >= 200 && response.status < 400) return;
      recordPreviewReadinessHttpFailure(previewDiagnostics, response.status);
    } catch {
      // Fetch errors can contain URLs, headers, or payload-adjacent details;
      // retain only a bounded counter and fixed failure code.
      recordPreviewReadinessFetchFailure(previewDiagnostics);
    } finally {
      clearTimeout(timeout);
    }

    const delayMs = Math.min(100, Math.max(0, deadline - Date.now()));
    if (delayMs === 0) break;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }

  throw createPreviewDiagnosticError('preview-readiness-timeout', previewDiagnostics);
}

function previewUrl(path: string): string {
  if (!uiPreviewOrigin) throw new Error('The isolated UI preview server is not ready.');
  return `${uiPreviewOrigin}${path}`;
}

type PreviewCredentialEvidence = {
  liveValueMatchCount: number;
  liveNonEmptyCount: number;
  crossFieldValueMatchCount: number;
  defaultValueMatchCount: number;
  serializedCredentialCount: number;
  renderedCredentialCount: number;
};

const PREVIEW_CREDENTIAL_PROBE = '__uiPreviewCredentialProbe';

// Keep one-use preview values inside the browser realm. The probe exposes only
// bounded counts so Playwright never receives a credential through an action
// argument, matcher, or reporter-visible result.
async function installPreviewCredentialProbe(page: Page): Promise<void> {
  await page.evaluate((probeName) => {
    const windowRecord = window as unknown as Record<string, unknown>;
    if (windowRecord[probeName]) throw new Error('Preview credential probe is already installed.');

    let usernameSecret = '';
    let passwordSecret = '';
    let probe: {
      seed: () => void;
      read: () => PreviewCredentialEvidence;
      scrub: () => void;
    };

    const findControls = (): {
      form: HTMLFormElement | null;
      username: HTMLInputElement | null;
      password: HTMLInputElement | null;
    } => {
      const form = document.querySelector('form[aria-label="Hermes password sign in"]') as HTMLFormElement | null;
      const username = form?.querySelector('input[data-fixture-field="username"]') as HTMLInputElement | null;
      const password = form?.querySelector('input[data-fixture-field="password"]') as HTMLInputElement | null;
      return { form, username, password };
    };

    const requireControls = (): {
      form: HTMLFormElement;
      username: HTMLInputElement;
      password: HTMLInputElement;
    } => {
      const controls = findControls();
      if (!controls.form || !controls.username || !controls.password) {
        throw new Error('Preview credential controls are unavailable.');
      }
      return {
        form: controls.form,
        username: controls.username,
        password: controls.password
      };
    };

    const setInputValue = (input: HTMLInputElement, value: string): void => {
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
      if (!setter) throw new Error('Preview credential value setter is unavailable.');
      setter.call(input, value);
      input.dispatchEvent(new Event('input', { bubbles: true }));
    };

    const seed = (): void => {
      const { username, password } = requireControls();
      usernameSecret = crypto.randomUUID();
      passwordSecret = crypto.randomUUID();
      setInputValue(username, usernameSecret);
      setInputValue(password, passwordSecret);
    };

    const read = (): PreviewCredentialEvidence => {
      const { form, username, password } = requireControls();
      const liveValues = [username.value, password.value];
      const expectedValues = [usernameSecret, passwordSecret];
      const defaultValues = [username.defaultValue, password.defaultValue];
      const serializedValues = [username.getAttribute('value'), password.getAttribute('value')];
      const renderedText = form.textContent ?? '';

      return {
        liveValueMatchCount: liveValues.reduce(
          (count, value, index) => count + Number(value !== '' && value === expectedValues[index]),
          0
        ),
        liveNonEmptyCount: liveValues.filter((value) => value !== '').length,
        crossFieldValueMatchCount:
          Number(passwordSecret !== '' && username.value === passwordSecret) +
          Number(usernameSecret !== '' && password.value === usernameSecret),
        defaultValueMatchCount: defaultValues.reduce(
          (count, value) => count + Number(value !== '' && (value === usernameSecret || value === passwordSecret)),
          0
        ),
        serializedCredentialCount: serializedValues.reduce(
          (count, value) => count + Number(value !== null && (value === usernameSecret || value === passwordSecret)),
          0
        ),
        renderedCredentialCount:
          Number(usernameSecret !== '' && renderedText.includes(usernameSecret)) +
          Number(passwordSecret !== '' && renderedText.includes(passwordSecret))
      };
    };

    const scrub = (): void => {
      const { username, password } = findControls();
      for (const input of [username, password]) {
        if (!input) continue;
        input.value = '';
        input.defaultValue = '';
        input.removeAttribute('value');
      }
      usernameSecret = '';
      passwordSecret = '';
      if (windowRecord[probeName] === probe) delete windowRecord[probeName];
    };

    probe = { seed, read, scrub };
    windowRecord[probeName] = probe;
  }, PREVIEW_CREDENTIAL_PROBE);
}

async function seedPreviewCredentials(page: Page): Promise<void> {
  await page.evaluate((probeName) => {
    const probe = (window as unknown as Record<string, unknown>)[probeName] as
      | { seed?: () => void }
      | undefined;
    if (typeof probe?.seed !== 'function') throw new Error('Preview credential probe is unavailable.');
    probe.seed();
  }, PREVIEW_CREDENTIAL_PROBE);
}

async function readPreviewCredentialEvidence(page: Page): Promise<PreviewCredentialEvidence> {
  return page.evaluate((probeName) => {
    const probe = (window as unknown as Record<string, unknown>)[probeName] as
      | { read?: () => PreviewCredentialEvidence }
      | undefined;
    if (typeof probe?.read !== 'function') throw new Error('Preview credential probe is unavailable.');
    return probe.read();
  }, PREVIEW_CREDENTIAL_PROBE);
}

async function scrubPreviewCredentialProbe(page: Page): Promise<void> {
  await page
    .evaluate((probeName) => {
      const probe = (window as unknown as Record<string, unknown>)[probeName] as
        | { scrub?: () => void }
        | undefined;
      probe?.scrub?.();
    }, PREVIEW_CREDENTIAL_PROBE)
    .catch(() => undefined);
}

type PreviewIndexedDbSpyOptions = {
  databaseName: string;
  objectStoreName: string;
  objectKey: string;
  globalName: string;
};

type PreviewIndexedDbSpyObservation = {
  databaseEnumerationCount: number;
  databaseOpenCount: number;
  reviewedDatabaseOpenCount: number;
  unrelatedDatabaseOpenCount: number;
  transactionInvocationCount: number;
  reviewedStoreInvocationCount: number;
  unrelatedStoreInvocationCount: number;
  countInvocationCount: number;
  getInvocationCount: number;
  reviewedKeyInvocationCount: number;
  unrelatedKeyInvocationCount: number;
};

type PreviewIndexedDbSpyCleanup = {
  restored: boolean;
  cleanupFailure: boolean;
};

async function installPreviewIndexedDbSpy(page: Page, options: PreviewIndexedDbSpyOptions): Promise<boolean> {
  return page.evaluate(
    ({ databaseName, objectStoreName, objectKey, globalName }) => {
      const previousGlobalDescriptor = Object.getOwnPropertyDescriptor(window, globalName);
      if (
        typeof indexedDB === 'undefined' ||
        typeof indexedDB.open !== 'function' ||
        typeof indexedDB.databases !== 'function' ||
        typeof IDBDatabase === 'undefined' ||
        typeof IDBObjectStore === 'undefined' ||
        typeof IDBKeyRange === 'undefined'
      ) {
        return false;
      }

      const factory = indexedDB;
      const factoryPrototype = Object.getPrototypeOf(factory) as IDBFactory;
      const originalOpenDescriptor = Object.getOwnPropertyDescriptor(factoryPrototype, 'open');
      const originalDatabasesDescriptor = Object.getOwnPropertyDescriptor(factoryPrototype, 'databases');
      const originalTransactionDescriptor = Object.getOwnPropertyDescriptor(IDBDatabase.prototype, 'transaction');
      const originalCountDescriptor = Object.getOwnPropertyDescriptor(IDBObjectStore.prototype, 'count');
      const originalGetDescriptor = Object.getOwnPropertyDescriptor(IDBObjectStore.prototype, 'get');
      const originalOpen = factoryPrototype.open as unknown;
      const originalDatabases = factoryPrototype.databases as unknown;
      const originalTransaction = IDBDatabase.prototype.transaction as unknown;
      const originalCount = IDBObjectStore.prototype.count as unknown;
      const originalGet = IDBObjectStore.prototype.get as unknown;
      if (
        !originalOpenDescriptor ||
        !originalDatabasesDescriptor ||
        !originalTransactionDescriptor ||
        !originalCountDescriptor ||
        !originalGetDescriptor ||
        typeof originalOpen !== 'function' ||
        typeof originalDatabases !== 'function' ||
        typeof originalTransaction !== 'function' ||
        typeof originalCount !== 'function' ||
        typeof originalGet !== 'function'
      ) {
        return false;
      }

      const sameDescriptor = (left: PropertyDescriptor | undefined, right: PropertyDescriptor | undefined): boolean => {
        if (!left || !right) return left === right;
        if (left.configurable !== right.configurable || left.enumerable !== right.enumerable) return false;
        const leftIsData = 'value' in left;
        if (leftIsData !== ('value' in right)) return false;
        if (leftIsData) return left.value === right.value && left.writable === right.writable;
        return left.get === right.get && left.set === right.set;
      };
      const defineWrapped = (
        target: object,
        property: string,
        descriptor: PropertyDescriptor | undefined,
        value: unknown
      ): void => {
        Object.defineProperty(
          target,
          property,
          descriptor && 'value' in descriptor
            ? { ...descriptor, value }
            : {
                configurable: descriptor?.configurable ?? true,
                enumerable: descriptor?.enumerable ?? false,
                writable: true,
                value
              }
        );
      };
      const restoreDescriptor = (
        target: object,
        property: string,
        descriptor: PropertyDescriptor | undefined
      ): boolean => {
        try {
          if (descriptor) Object.defineProperty(target, property, descriptor);
          else if (!Reflect.deleteProperty(target, property)) return false;
          return sameDescriptor(Object.getOwnPropertyDescriptor(target, property), descriptor);
        } catch {
          return false;
        }
      };

      const originalOpenMethod = originalOpen as (...args: unknown[]) => unknown;
      const originalDatabasesMethod = originalDatabases as (...args: unknown[]) => unknown;
      const originalTransactionMethod = originalTransaction as (...args: unknown[]) => unknown;
      const originalCountMethod = originalCount as (...args: unknown[]) => unknown;
      const originalGetMethod = originalGet as (...args: unknown[]) => unknown;
      let databaseEnumerationCount = 0;
      let databaseOpenCount = 0;
      let reviewedDatabaseOpenCount = 0;
      let unrelatedDatabaseOpenCount = 0;
      let transactionInvocationCount = 0;
      let reviewedStoreInvocationCount = 0;
      let unrelatedStoreInvocationCount = 0;
      let countInvocationCount = 0;
      let getInvocationCount = 0;
      let reviewedKeyInvocationCount = 0;
      let unrelatedKeyInvocationCount = 0;

      const open = function (this: IDBFactory, name: string, version?: number): IDBOpenDBRequest {
        databaseOpenCount += 1;
        if (name === databaseName) reviewedDatabaseOpenCount += 1;
        else unrelatedDatabaseOpenCount += 1;
        const argumentsList = version === undefined ? [name] : [name, version];
        return Reflect.apply(originalOpenMethod, this, argumentsList) as IDBOpenDBRequest;
      };
      const databases = function (this: IDBFactory): Promise<IDBDatabaseInfo[]> {
        databaseEnumerationCount += 1;
        return Reflect.apply(originalDatabasesMethod, this, []) as Promise<IDBDatabaseInfo[]>;
      };
      const transaction = function (
        this: IDBDatabase,
        storeNames: string | string[],
        mode?: IDBTransactionMode,
        options?: IDBTransactionOptions
      ): IDBTransaction {
        transactionInvocationCount += 1;
        const names = Array.isArray(storeNames) ? storeNames : [storeNames];
        for (const name of names) {
          if (name === objectStoreName) reviewedStoreInvocationCount += 1;
          else unrelatedStoreInvocationCount += 1;
        }
        const argumentsList: unknown[] = [storeNames];
        if (mode !== undefined) argumentsList.push(mode);
        if (options !== undefined) argumentsList.push(options);
        return Reflect.apply(originalTransactionMethod, this, argumentsList) as IDBTransaction;
      };
      const count = function (this: IDBObjectStore, query?: IDBValidKey | IDBKeyRange): IDBRequest {
        countInvocationCount += 1;
        const reviewed = query instanceof IDBKeyRange
          ? query.lower === objectKey && query.upper === objectKey && !query.lowerOpen && !query.upperOpen
          : query === objectKey;
        if (reviewed) reviewedKeyInvocationCount += 1;
        else unrelatedKeyInvocationCount += 1;
        const argumentsList = query === undefined ? [] : [query];
        return Reflect.apply(originalCountMethod, this, argumentsList) as IDBRequest;
      };
      const get = function (this: IDBObjectStore, query?: IDBValidKey): IDBRequest {
        getInvocationCount += 1;
        if (query === objectKey) reviewedKeyInvocationCount += 1;
        else unrelatedKeyInvocationCount += 1;
        const argumentsList = query === undefined ? [] : [query];
        return Reflect.apply(originalGetMethod, this, argumentsList) as IDBRequest;
      };

      const read = (): PreviewIndexedDbSpyObservation => ({
        databaseEnumerationCount,
        databaseOpenCount,
        reviewedDatabaseOpenCount,
        unrelatedDatabaseOpenCount,
        transactionInvocationCount,
        reviewedStoreInvocationCount,
        unrelatedStoreInvocationCount,
        countInvocationCount,
        getInvocationCount,
        reviewedKeyInvocationCount,
        unrelatedKeyInvocationCount
      });
      let publishedProbe: {
        read: () => PreviewIndexedDbSpyObservation;
        restore: () => PreviewIndexedDbSpyCleanup;
      };
      let cleanupComplete = false;
      const restore = (): PreviewIndexedDbSpyCleanup => {
        if (cleanupComplete) return { restored: true, cleanupFailure: false };
        const methodResults = [
          restoreDescriptor(factoryPrototype, 'open', originalOpenDescriptor),
          restoreDescriptor(factoryPrototype, 'databases', originalDatabasesDescriptor),
          restoreDescriptor(IDBDatabase.prototype, 'transaction', originalTransactionDescriptor),
          restoreDescriptor(IDBObjectStore.prototype, 'count', originalCountDescriptor),
          restoreDescriptor(IDBObjectStore.prototype, 'get', originalGetDescriptor)
        ];
        const currentGlobalDescriptor = Object.getOwnPropertyDescriptor(window, globalName);
        const globalResult =
          currentGlobalDescriptor && 'value' in currentGlobalDescriptor && currentGlobalDescriptor.value === publishedProbe
            ? restoreDescriptor(window, globalName, previousGlobalDescriptor)
            : false;
        const restored = [...methodResults, globalResult].every(Boolean);
        if (restored) cleanupComplete = true;
        return { restored, cleanupFailure: !restored };
      };

      publishedProbe = { read, restore };
      try {
        defineWrapped(factoryPrototype, 'open', originalOpenDescriptor, open);
        defineWrapped(factoryPrototype, 'databases', originalDatabasesDescriptor, databases);
        defineWrapped(IDBDatabase.prototype, 'transaction', originalTransactionDescriptor, transaction);
        defineWrapped(IDBObjectStore.prototype, 'count', originalCountDescriptor, count);
        defineWrapped(IDBObjectStore.prototype, 'get', originalGetDescriptor, get);
        // Publish last. If a pre-existing global rejects replacement, every method
        // above is rolled back and the prior global descriptor is restored exactly.
        Object.defineProperty(window, globalName, {
          configurable: true,
          enumerable: false,
          writable: false,
          value: publishedProbe
        });
      } catch {
        restoreDescriptor(factoryPrototype, 'open', originalOpenDescriptor);
        restoreDescriptor(factoryPrototype, 'databases', originalDatabasesDescriptor);
        restoreDescriptor(IDBDatabase.prototype, 'transaction', originalTransactionDescriptor);
        restoreDescriptor(IDBObjectStore.prototype, 'count', originalCountDescriptor);
        restoreDescriptor(IDBObjectStore.prototype, 'get', originalGetDescriptor);
        restoreDescriptor(window, globalName, previousGlobalDescriptor);
        return false;
      }
      return true;
    },
    options
  );
}

async function restorePreviewIndexedDbSpy(page: Page, globalName: string): Promise<PreviewIndexedDbSpyCleanup> {
  return page
    .evaluate((name): PreviewIndexedDbSpyCleanup => {
      const descriptor = Object.getOwnPropertyDescriptor(window, name);
      if (!descriptor) return { restored: false, cleanupFailure: true };
      if (!('value' in descriptor)) return { restored: false, cleanupFailure: true };
      const spy = descriptor.value as { restore?: () => PreviewIndexedDbSpyCleanup };
      if (typeof spy.restore !== 'function') return { restored: false, cleanupFailure: true };
      try {
        const result = spy.restore();
        return {
          restored: result.restored === true,
          cleanupFailure: result.cleanupFailure === true || result.restored !== true
        };
      } catch {
        return { restored: false, cleanupFailure: true };
      }
    }, globalName)
    .catch(() => ({ restored: false, cleanupFailure: true }));
}

test.beforeAll(async () => {
  const port = await reservePort();
  uiPreviewOrigin = `http://127.0.0.1:${port}`;
  previewDiagnostics = createPreviewDiagnostics();
  const serverProcess = spawn('bun', ['run', 'preview', '--', '--host', '127.0.0.1', '--port', String(port)], {
    cwd: process.cwd(),
    stdio: ['ignore', 'pipe', 'pipe']
  });
  previewProcess = serverProcess;

  const collectStdoutDiagnostics = (chunk: Buffer): void => {
    recordPreviewOutput(previewDiagnostics, 'stdout', chunk);
  };
  const collectStderrDiagnostics = (chunk: Buffer): void => {
    recordPreviewOutput(previewDiagnostics, 'stderr', chunk);
  };
  let rejectProcessFailure: (error: Error) => void = () => undefined;
  const processFailure = new Promise<never>((_, reject) => {
    rejectProcessFailure = reject;
  });
  const onProcessError = (error: Error): void => {
    recordPreviewProcessError(previewDiagnostics, error);
    rejectProcessFailure(createPreviewDiagnosticError('preview-process-error', previewDiagnostics));
  };
  const onProcessExit = (code: number | null, signal: NodeJS.Signals | null): void => {
    recordPreviewProcessExit(previewDiagnostics, code, signal);
    rejectProcessFailure(createPreviewDiagnosticError('preview-process-exit', previewDiagnostics));
  };
  serverProcess.stdout.on('data', collectStdoutDiagnostics);
  serverProcess.stderr.on('data', collectStderrDiagnostics);
  serverProcess.once('error', onProcessError);
  serverProcess.once('exit', onProcessExit);
  previewLifecycleHandlers = {
    collectStdoutDiagnostics,
    collectStderrDiagnostics,
    onError: onProcessError,
    onExit: onProcessExit
  };

  await Promise.race([waitForPreview(previewUrl('/ui-preview')), processFailure]);
});

test.afterAll(async () => {
  const processToStop = previewProcess;
  const lifecycleHandlers = previewLifecycleHandlers;
  previewProcess = undefined;
  previewLifecycleHandlers = undefined;
  if (!processToStop) return;

  if (lifecycleHandlers) {
    processToStop.stdout.off('data', lifecycleHandlers.collectStdoutDiagnostics);
    processToStop.stderr.off('data', lifecycleHandlers.collectStderrDiagnostics);
    processToStop.off('error', lifecycleHandlers.onError);
    processToStop.off('exit', lifecycleHandlers.onExit);
  }
  if (processToStop.exitCode !== null) return;

  const waitForExit = (timeoutMs: number): Promise<boolean> =>
    new Promise((resolve) => {
      let settled = false;
      const finish = (exited: boolean): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        processToStop.off('exit', onExit);
        processToStop.off('error', onError);
        resolve(exited);
      };
      const onExit = (): void => finish(true);
      const onError = (): void => finish(false);
      const timeout = setTimeout(() => finish(false), timeoutMs);
      processToStop.once('exit', onExit);
      processToStop.once('error', onError);
    });

  const gracefulExit = waitForExit(2_000);
  try {
    processToStop.kill('SIGTERM');
  } catch {
    // The process may have exited between the exit check and termination.
  }
  if (await gracefulExit) return;
  if (processToStop.exitCode !== null) return;

  const forcedExit = waitForExit(1_000);
  try {
    processToStop.kill('SIGKILL');
  } catch {
    // Best-effort escalation when graceful termination did not complete.
  }
  await forcedExit;
});

test('preview diagnostics discard generated secret markers from child output and errors', () => {
  const secretMarker = `preview-secret-${randomUUID()}`;
  const diagnostics = createPreviewDiagnostics();

  // Simulate hostile child output containing URL, header, payload, and
  // credential-adjacent markers. The collector retains only scalar counts.
  recordPreviewOutput(
    diagnostics,
    'stdout',
    Buffer.from(`url=https://preview.invalid/${secretMarker} authorization=${secretMarker}`)
  );
  recordPreviewOutput(
    diagnostics,
    'stderr',
    Buffer.from(`payload=${secretMarker} Error: ${secretMarker}`)
  );
  recordPreviewProcessError(diagnostics, new Error(secretMarker));

  let thrownDiagnostic: unknown;
  try {
    throw createPreviewDiagnosticError('preview-process-error', diagnostics);
  } catch (error) {
    thrownDiagnostic = error;
  }

  const thrownText =
    thrownDiagnostic instanceof Error
      ? `${thrownDiagnostic.name}\n${thrownDiagnostic.message}\n${thrownDiagnostic.stack ?? ''}`
      : String(thrownDiagnostic);
  const retainedCandidateArtifacts = JSON.stringify({
    diagnostics: snapshotPreviewDiagnostics(diagnostics),
    thrownDiagnostic: thrownDiagnostic instanceof Error
      ? { name: thrownDiagnostic.name, message: thrownDiagnostic.message, stack: thrownDiagnostic.stack ?? null }
      : null
  });

  expect(thrownText).not.toContain(secretMarker);
  expect(retainedCandidateArtifacts).not.toContain(secretMarker);
  expect(diagnostics.lastErrorCode).toBe('preview-process-error');
  expect(diagnostics.stdoutChunkCount).toBe(1);
  expect(diagnostics.stderrChunkCount).toBe(1);
  expect(diagnostics.processErrorCount).toBe(1);
  expect(diagnostics.stdoutByteCount).toBeGreaterThan(0);
  expect(diagnostics.stderrByteCount).toBeGreaterThan(0);
});

for (const viewport of [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'narrow', width: 390, height: 844 }
]) {
  test(`${viewport.name} UI preview keeps both surfaces usable`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto(previewUrl('/ui-preview'));

    await expect(page.getByRole('heading', { name: 'Runtime and authentication states' })).toBeVisible();
    await expect(page.getByTestId('runtime-preview')).toBeVisible();
    await expect(page.getByTestId('auth-preview')).toBeVisible();

    const overflow = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth
    }));
    expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
  });
}

test('UI preview exposes local state controls and dark appearance', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'));

  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('streaming');
  await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('failure');
  await page.getByRole('combobox', { name: 'Appearance' }).selectOption('dark');

  await expect(page.getByTestId('runtime-preview')).toHaveAttribute('data-state', 'streaming');
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'failure');
  await expect(page.getByTestId('runtime-preview')).toHaveAttribute('data-appearance', 'dark');
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-appearance', 'dark');
  await expect(page.getByText('Synthetic preview response')).toBeVisible();
  await expect(page.getByText('Local fixture playback · no live Hermes connection')).toBeVisible();
  await expect(page.getByRole('article', { name: 'Synthetic preview response from a local fixture' })).toBeVisible();
  await expect(page.getByText('Hermes is responding')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Sign-in did not complete' })).toBeVisible();
});

test('Paper desktop geometry keeps the fixed three-column workspace and composer baseline', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 960 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  const workspace = page.locator('.workspace-preview');
  const workspaceBox = await workspace.boundingBox();
  const gridBox = await workspace.locator('.workspace-grid').boundingBox();
  const sidebarBox = await workspace.locator('.sidebar').boundingBox();
  const conversationBox = await workspace.locator('.conversation-panel').boundingBox();
  const inspectorBox = await workspace.locator('.desktop-inspector').boundingBox();
  const composerBox = await workspace.getByRole('form', { name: 'Message composer' }).boundingBox();
  expect(workspaceBox).not.toBeNull();
  expect(gridBox).not.toBeNull();
  expect(sidebarBox).not.toBeNull();
  expect(conversationBox).not.toBeNull();
  expect(inspectorBox).not.toBeNull();
  expect(composerBox).not.toBeNull();

  expect(workspaceBox?.width).toBe(1440);
  expect(workspaceBox?.height).toBe(960);
  expect(gridBox?.x).toBe(workspaceBox?.x);
  expect(gridBox?.y).toBe(workspaceBox?.y);
  expect(gridBox?.width).toBe(1440);
  expect(gridBox?.height).toBe(928);
  expect(sidebarBox?.x).toBe((workspaceBox?.x ?? 0) + 16);
  expect(conversationBox?.x).toBe((workspaceBox?.x ?? 0) + 16 + 276 + 16);
  expect(inspectorBox?.x).toBe((workspaceBox?.x ?? 0) + 16 + 276 + 16 + 720 + 16);
  expect(sidebarBox?.y).toBe((workspaceBox?.y ?? 0) + 16);
  expect(conversationBox?.y).toBe((workspaceBox?.y ?? 0) + 16);
  expect(inspectorBox?.y).toBe((workspaceBox?.y ?? 0) + 16);
  expect(sidebarBox?.width).toBe(276);
  expect(conversationBox?.width).toBe(720);
  expect(inspectorBox?.width).toBe(380);
  expect(sidebarBox?.height).toBe(928);
  expect(conversationBox?.height).toBe(928);
  expect(inspectorBox?.height).toBe(928);
  expect(composerBox?.height).toBe(112);
  expect(Math.abs((composerBox?.y ?? 0) - ((workspaceBox?.y ?? 0) + 800))).toBeLessThanOrEqual(1);

  const computedGrid = await workspace.locator('.workspace-grid').evaluate((element) => {
    const style = getComputedStyle(element);
    return { columns: style.gridTemplateColumns, rows: style.gridTemplateRows };
  });
  expect(computedGrid.columns).toBe('276px 720px 380px');
  expect(computedGrid.rows).toBe('928px');
  await expect(workspace.locator('.conversation-body .timeline')).toHaveCSS('overflow-y', 'auto');
});

test('Paper mobile geometry uses the fixed shell, modal drawers, and local Send action', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));

  const auth = page.locator('.auth-preview');
  const authStatusBar = page.locator('.mobile-status-bar');
  const authBox = await auth.boundingBox();
  const authStatusBox = await authStatusBar.boundingBox();
  expect(authBox).not.toBeNull();
  expect(authStatusBox).not.toBeNull();
  expect(Math.abs((authStatusBox?.y ?? 0) - (authBox?.y ?? 0))).toBeLessThanOrEqual(1);

  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');
  const workspace = page.locator('.workspace-preview');
  const workspaceBox = await workspace.boundingBox();
  const statusBar = workspace.locator('.workspace-mobile-status-bar');
  const toolbar = workspace.locator('.mobile-toolbar');
  const conversation = workspace.locator('.conversation-panel');
  const composer = page.getByRole('form', { name: 'Message composer' });
  const workspaceStatusBox = await statusBar.boundingBox();
  const toolbarBox = await toolbar.boundingBox();
  const conversationBox = await conversation.boundingBox();
  const composerBox = await composer.boundingBox();
  expect(workspaceBox).not.toBeNull();
  expect(workspaceStatusBox).not.toBeNull();
  expect(toolbarBox).not.toBeNull();
  expect(conversationBox).not.toBeNull();
  expect(composerBox).not.toBeNull();
  expect(workspaceBox?.width).toBe(390);
  expect(workspaceBox?.height).toBe(844);
  expect(workspaceStatusBox?.x).toBe(workspaceBox?.x);
  expect(workspaceStatusBox?.y).toBe(workspaceBox?.y);
  expect(workspaceStatusBox?.width).toBe(390);
  expect(workspaceStatusBox?.height).toBe(62);
  expect(toolbarBox?.x).toBe(workspaceBox?.x);
  expect(toolbarBox?.y).toBe((workspaceBox?.y ?? 0) + 62);
  expect(toolbarBox?.width).toBe(390);
  expect(toolbarBox?.height).toBe(64);
  expect(conversationBox?.x).toBe(workspaceBox?.x);
  expect(conversationBox?.y).toBe((workspaceBox?.y ?? 0) + 126);
  expect(conversationBox?.width).toBe(390);
  expect(conversationBox?.height).toBe(718);
  expect(composerBox?.y).toBe((workspaceBox?.y ?? 0) + 728);
  expect(composerBox?.height).toBe(100);
  await expect(workspace.locator('.workspace-grid .desktop-inspector')).toBeHidden();

  const conversations = page.getByRole('button', { name: 'Open conversations' });
  await conversations.click();
  const scrim = page.getByTestId('mobile-drawer-scrim');
  const sessionDrawer = page.getByTestId('mobile-session-drawer');
  const scrimBox = await scrim.boundingBox();
  const sessionDrawerBox = await sessionDrawer.boundingBox();
  expect(scrimBox).not.toBeNull();
  expect(sessionDrawerBox).not.toBeNull();
  expect(scrimBox?.x).toBe(workspaceBox?.x);
  expect(scrimBox?.y).toBe((workspaceBox?.y ?? 0) + 62);
  expect(scrimBox?.width).toBe(390);
  expect(scrimBox?.height).toBe(782);
  expect(sessionDrawerBox?.x).toBe((workspaceBox?.x ?? 0) + 12);
  expect(sessionDrawerBox?.y).toBe((workspaceBox?.y ?? 0) + 74);
  expect(sessionDrawerBox?.width).toBe(342);
  expect(sessionDrawerBox?.height).toBe(756);
  await expect(sessionDrawer).toHaveAttribute('role', 'dialog');
  await expect(sessionDrawer).toHaveAttribute('aria-modal', 'true');
  await expect(workspace.locator('.workspace-underlay')).toHaveAttribute('inert', '');
  await expect(workspace.locator('.workspace-underlay')).toHaveAttribute('aria-hidden', 'true');
  await expect(sessionDrawer.locator('button:not([disabled])').first()).toBeFocused();

  const sessionFocusables = sessionDrawer.locator(
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  );
  await sessionFocusables.last().focus();
  await page.keyboard.press('Tab');
  await expect(sessionFocusables.first()).toBeFocused();
  await page.keyboard.press('Shift+Tab');
  await expect(sessionFocusables.last()).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(sessionDrawer).toBeHidden();
  await expect(conversations).toBeFocused();

  const workspaceTrigger = page.getByRole('button', { name: 'Open workspace' });
  await workspaceTrigger.click();
  const workspaceDrawer = page.getByTestId('mobile-workspace-drawer');
  const workspaceAfterSessionBox = await workspace.boundingBox();
  const workspaceDrawerBox = await workspaceDrawer.boundingBox();
  expect(workspaceAfterSessionBox).not.toBeNull();
  expect(workspaceDrawerBox).not.toBeNull();
  expect(workspaceDrawerBox?.x).toBe((workspaceAfterSessionBox?.x ?? 0) + 12);
  expect(workspaceDrawerBox?.y).toBe((workspaceAfterSessionBox?.y ?? 0) + 74);
  expect(workspaceDrawerBox?.width).toBe(366);
  expect(workspaceDrawerBox?.height).toBe(756);
  await expect(workspace.locator('.workspace-grid .desktop-inspector')).toBeHidden();
  await expect(workspaceDrawer.locator('.inspector')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(workspaceDrawer).toBeHidden();
  await expect(workspaceTrigger).toBeFocused();

  await composer.getByRole('textbox', { name: 'Message Hermes' }).fill('Pointer fixture');
  await page.getByRole('button', { name: 'Send message' }).click();
  await expect(page.locator('.section-note').first()).toHaveText('send');
});

test('Paper effective width switches exactly at 760px without a tabbed desktop replacement', async ({ page }) => {
  for (const width of [760, 761]) {
    await page.setViewportSize({ width, height: 844 });
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');
    const workspace = page.locator('.workspace-preview');
    expect((await workspace.boundingBox())?.width).toBe(width);

    if (width === 760) {
      await expect(workspace.locator('.mobile-toolbar')).toBeVisible();
      await expect(workspace.locator('.conversation-header')).toBeHidden();
    } else {
      await expect(workspace.locator('.mobile-toolbar')).toBeHidden();
      await expect(workspace.locator('.conversation-header')).toBeVisible();
      await expect(workspace.locator('.sidebar')).toBeVisible();
    }
  }
});

test('Paper action labels stay under a stationary pointer through repeated hover transitions', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 960 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  const workspace = page.locator('.workspace-preview');
  const actionLabels = [
    'Chat mode selected',
    'Open terminal mode',
    'Allow once',
    'Allow for session',
    'Always allow',
    'Deny',
    'Open artifact preview',
    'Download artifact preview'
  ];

  for (const ariaLabel of actionLabels) {
    const pill = workspace.getByRole('button', { name: ariaLabel });
    const copy = pill.locator('.pill-copy');
    await expect(pill).toBeVisible();

    for (let run = 0; run < 3; run += 1) {
      // Reset the previous reveal before putting the pointer over the next
      // control. The pointer then stays at one fixed screen coordinate for the
      // entire transition, exposing layout-induced hover loops.
      await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
      await page.mouse.move(0, 0);
      await expect
        .poll(
          () =>
            pill.evaluate((element) => {
              const copy = element.querySelector<HTMLElement>('.pill-copy');
              return {
                opacity: copy ? getComputedStyle(copy).opacity : '',
                maxWidth: copy ? getComputedStyle(copy).maxWidth : ''
              };
            }),
          { message: `${ariaLabel} resting state` }
        )
        .toEqual({ opacity: '0', maxWidth: '0px' });

      const resting = await pill.evaluate((element) => {
        const copy = element.querySelector<HTMLElement>('.pill-copy');
        const rect = element.getBoundingClientRect();
        const iconRect = element.querySelector<HTMLElement>('.icon-slot')?.getBoundingClientRect();
        return {
          width: rect.width,
          opacity: copy ? getComputedStyle(copy).opacity : '',
          maxWidth: copy ? getComputedStyle(copy).maxWidth : '',
          iconOffset: iconRect ? iconRect.x - rect.x : null
        };
      });
      expect(resting.opacity, ariaLabel).toBe('0');
      expect(resting.maxWidth, ariaLabel).toBe('0px');
      expect(resting.width, ariaLabel).toBe(44);

      const box = await pill.boundingBox();
      expect(box, ariaLabel).not.toBeNull();
      await page.mouse.move((box?.x ?? 0) + (box?.width ?? 0) / 2, (box?.y ?? 0) + (box?.height ?? 0) / 2);

      const samples: Array<{ hovered: boolean; opacity: string; maxWidth: number; copyWidth: number }> = [];
      for (let sample = 0; sample < 10; sample += 1) {
        await page.waitForTimeout(30);
        samples.push(
          await pill.evaluate((element) => {
            const copy = element.querySelector<HTMLElement>('.pill-copy');
            const style = copy ? getComputedStyle(copy) : undefined;
            return {
              hovered: element.matches(':hover'),
              opacity: style?.opacity ?? '',
              maxWidth: Number.parseFloat(style?.maxWidth ?? '0'),
              copyWidth: copy?.getBoundingClientRect().width ?? 0
            };
          })
        );
      }

      expect(samples.every((sample) => sample.hovered), ariaLabel).toBe(true);
      const revealed = samples.at(-1);
      expect(revealed?.opacity, ariaLabel).toBe('1');
      expect(revealed?.maxWidth, ariaLabel).toBeGreaterThan(0);
      expect(revealed?.copyWidth, ariaLabel).toBeGreaterThan(0);

      const hovered = await pill.evaluate((element) => {
        const rect = element.getBoundingClientRect();
        const iconRect = element.querySelector<HTMLElement>('.icon-slot')?.getBoundingClientRect();
        return { width: rect.width, iconOffset: iconRect ? iconRect.x - rect.x : null };
      });
      // The label is a visual overlay. The real 44px hit target and fixed icon
      // slot stay put while the surrounding layout remains unchanged.
      expect(hovered.width, ariaLabel).toBe(resting.width);
      expect(hovered.iconOffset, ariaLabel).toBeCloseTo(resting.iconOffset ?? 0, 4);
    }

    if (!(await pill.isDisabled())) {
      await page.mouse.move(0, 0);
      await page.waitForTimeout(220);
      await pill.focus();
      await expect.poll(() => copy.evaluate((element) => getComputedStyle(element).opacity), { message: ariaLabel }).toBe('1');
    }
  }
});

test('Paper mode overlays clear adjacent controls and preserve long localized focus labels', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 960 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  const workspace = page.locator('.workspace-preview');
  const terminal = workspace.getByRole('button', { name: 'Open terminal mode' });
  const terminalCopy = terminal.locator('.pill-copy');
  const approval = workspace.getByRole('button', { name: 'Allow once' });
  const approvalCopy = approval.locator('.pill-copy');
  await terminal.hover();
  await expect(terminalCopy).toHaveCSS('opacity', '1');

  const stacking = await page.evaluate(() => {
    const modeControls = document.querySelector<HTMLElement>('.mode-controls');
    const terminal = document.querySelector<HTMLElement>('button[aria-label="Open terminal mode"]');
    const terminalCopy = terminal?.querySelector<HTMLElement>('.pill-copy');
    const workspaceOptions = document.querySelector<HTMLElement>('button[aria-label="Workspace options"]');
    if (!modeControls || !terminal || !terminalCopy || !workspaceOptions) return null;

    const modeRect = modeControls.getBoundingClientRect();
    const terminalRect = terminal.getBoundingClientRect();
    const copyRect = terminalCopy.getBoundingClientRect();
    const optionsRect = workspaceOptions.getBoundingClientRect();
    const optionsCenterX = optionsRect.left + optionsRect.width / 2;
    const optionsCenterY = optionsRect.top + optionsRect.height / 2;
    const hit = document.elementFromPoint(optionsCenterX, optionsCenterY);
    const modeZIndex = Number.parseInt(getComputedStyle(modeControls).zIndex, 10);
    const optionsZIndex = Number.parseInt(getComputedStyle(workspaceOptions).zIndex, 10);

    return {
      modeWidth: modeRect.width,
      terminalWidth: terminalRect.width,
      copyWidth: copyRect.width,
      copyRight: copyRect.right,
      optionsLeft: optionsRect.left,
      overlapX: Math.min(copyRect.right, optionsRect.right) - Math.max(copyRect.left, optionsRect.left),
      overlapY: Math.min(copyRect.bottom, optionsRect.bottom) - Math.max(copyRect.top, optionsRect.top),
      modeZIndex: Number.isNaN(modeZIndex) ? 0 : modeZIndex,
      optionsZIndex: Number.isNaN(optionsZIndex) ? 0 : optionsZIndex,
      hitLabel: hit?.closest('button')?.getAttribute('aria-label') ?? null,
      copyOpacity: getComputedStyle(terminalCopy).opacity
    };
  });

  expect(stacking).not.toBeNull();
  expect(stacking?.modeWidth).toBe(92);
  expect(stacking?.terminalWidth).toBe(44);
  expect(stacking?.copyWidth).toBeGreaterThan(44);
  expect(stacking?.copyRight).toBeGreaterThan(stacking?.optionsLeft ?? 0);
  expect(stacking?.overlapX).toBeGreaterThan(0);
  expect(stacking?.overlapY).toBeGreaterThan(0);
  expect(stacking?.modeZIndex).toBeGreaterThan(stacking?.optionsZIndex ?? 0);
  expect(stacking?.copyOpacity).toBe('1');
  // The label is pointer-transparent, so the adjacent control remains the
  // hit target even while the label paints above it.
  expect(stacking?.hitLabel).toBe('Workspace options');

  await page.mouse.move(0, 0);
  await expect(terminalCopy).toHaveCSS('opacity', '0');
  await approval.evaluate((element) => {
    const label = element.querySelector<HTMLElement>('.pill-label');
    if (label) label.textContent = 'Einmal zulassen · lokalisierte Arbeitsbereichssteuerung';
  });
  // Use an enabled approval action for the keyboard branch. Mode switching is
  // intentionally disabled in this preview, while approval focus is real.
  await approval.focus();
  await expect(approval).toBeFocused();
  await expect(approvalCopy).toHaveCSS('opacity', '1');

  const localized = await approval.evaluate((element) => {
    const copy = element.querySelector<HTMLElement>('.pill-copy');
    const label = element.querySelector<HTMLElement>('.pill-label');
    const buttonRect = element.getBoundingClientRect();
    const copyRect = copy?.getBoundingClientRect();
    return {
      buttonWidth: buttonRect.width,
      copyWidth: copyRect?.width ?? 0,
      copyMaxWidth: Number.parseFloat(copy ? getComputedStyle(copy).maxWidth : '0'),
      labelText: label?.textContent ?? '',
      copyClientWidth: copy?.clientWidth ?? 0,
      copyScrollWidth: copy?.scrollWidth ?? 0
    };
  });

  expect(localized.buttonWidth).toBe(44);
  expect(localized.copyWidth).toBeGreaterThan(44);
  expect(localized.copyMaxWidth).toBeGreaterThan(120);
  expect(localized.copyMaxWidth).toBeLessThanOrEqual(180);
  expect(localized.labelText).toContain('lokalisierte');
  expect(localized.copyScrollWidth).toBeGreaterThan(localized.copyClientWidth);
  await expect(approval).toBeFocused();
});

test('provider choices route to deterministic local password and callback states', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'));

  await page.getByRole('button', { name: 'Nous' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'callback');
  await expect(page.getByRole('heading', { name: 'Completing sign-in' })).toBeFocused();

  await page.getByRole('button', { name: 'Cancel and return to providers' }).click();
  await page.getByRole('button', { name: 'Hermes password' }).click();
  await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password');
  await expect(page.getByLabel('Username')).toBeFocused();
});

test('approved compatibility gates inert every underlying action for pointer, keyboard, and accessibility users', async ({
  page
}) => {
  for (const fixture of [
    {
      state: 'compatibility-check-failed',
      heading: 'Compatibility check failed',
      appearance: 'light',
      viewport: { width: 1440, height: 900 }
    },
    {
      state: 'unsupported-version',
      heading: 'Unsupported Hermes revision',
      appearance: 'dark',
      viewport: { width: 390, height: 844 }
    }
  ]) {
    await page.setViewportSize(fixture.viewport);
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Appearance' }).selectOption(fixture.appearance);
    await page.getByRole('combobox', { name: 'Runtime state' }).selectOption(fixture.state);

    const preview = page.getByTestId('runtime-preview');
    const underlay = page.getByTestId('workspace-underlay');
    const retry = preview.getByRole('button', { name: 'Retry compatibility check' });
    const returnToSignIn = preview.getByRole('button', { name: 'Return to sign-in' });
    await expect(page.getByRole('heading', { name: fixture.heading })).toBeVisible();
    await expect(underlay).toHaveAttribute('inert', '');
    await expect(retry).toBeFocused();

    // The workspace remains visibly recognizable behind the gate, but inert
    // removes every descendant from keyboard, pointer, and accessibility APIs.
    await expect(underlay.locator('.workspace-grid')).toBeVisible();
    await expect(underlay.locator('[aria-label="Start a new chat"]')).toHaveCount(1);
    await expect(underlay.getByRole('button')).toHaveCount(0);
    await expect(underlay.getByRole('textbox')).toHaveCount(0);
    await expect(preview.getByRole('button')).toHaveCount(2);

    const sidebar = underlay.locator('.sidebar');
    await expect(sidebar).not.toHaveClass(/open/);
    const blockedNewChat = underlay.locator('[aria-label="Start a new chat"]');
    await blockedNewChat.dispatchEvent('pointerdown', { button: 0, pointerType: 'mouse' });
    await blockedNewChat.evaluate((element: HTMLElement) => element.click());
    await underlay
      .locator('[aria-label="Edit conversation title"]')
      .first()
      .evaluate((element: HTMLElement) => element.click());
    await underlay
      .locator('[aria-label="Open conversations"]')
      .evaluate((element: HTMLElement) => element.click());
    await expect(page.locator('.section-note').first()).toHaveText('No runtime action yet');
    await expect(page.getByTestId('mobile-title-editor')).toHaveCount(0);
    await expect(sidebar).not.toHaveClass(/open/);

    await underlay.locator('[aria-label="Start a new chat"]').evaluate((element: HTMLElement) => element.focus());
    await expect(retry).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(returnToSignIn).toBeFocused();
    await page.keyboard.press('Shift+Tab');
    await expect(retry).toBeFocused();

    await retry.click();
    await expect(page.locator('.section-note').first()).toHaveText('retry-compatibility-check');
    await returnToSignIn.focus();
    await page.keyboard.press('Enter');
    await expect(page.locator('.section-note').first()).toHaveText('return-to-sign-in');

    const overflow = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth
    }));
    expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
  }
});

test('narrow title editing uses the compound island, separate workspace action, dimmer, and represented keyboard', async ({
  page
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  const island = page.locator('.mobile-title-island');
  await expect(island.getByRole('button', { name: 'Open conversations' })).toBeVisible();
  await expect(island.getByRole('button', { name: 'Edit conversation title' })).toBeVisible();
  await expect(island.getByRole('button', { name: 'Open workspace' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Open workspace' })).toBeVisible();

  const workspace = page.locator('.workspace-preview');
  const workspaceBox = await workspace.boundingBox();
  await island.getByRole('button', { name: 'Edit conversation title' }).click();
  const titleLayer = page.getByTestId('mobile-title-editor');
  const dimmer = page.locator('.title-edit-dimmer');
  const dimmerBox = await dimmer.boundingBox();
  await expect(titleLayer).toBeVisible();
  await expect(titleLayer).toHaveAttribute('role', 'dialog');
  await expect(titleLayer).toHaveAttribute('aria-modal', 'true');
  await expect(page.getByTestId('represented-mobile-keyboard')).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Conversation title' })).toBeFocused();
  expect(dimmerBox).not.toBeNull();
  expect(dimmerBox?.x).toBe(workspaceBox?.x);
  expect(dimmerBox?.y).toBe((workspaceBox?.y ?? 0) + 62);
  expect(dimmerBox?.width).toBe(390);
  expect(dimmerBox?.height).toBe(782);
  expect(await dimmer.evaluate((node) => getComputedStyle(node).backdropFilter)).toContain('blur');

  await page.keyboard.press('Escape');
  await expect(titleLayer).toBeHidden();
  await expect(island.getByRole('button', { name: 'Edit conversation title' })).toBeFocused();
});

// Auth controls are credential-bearing during setup. Keep this entire lane out
// of Playwright traces, screenshots, and video; assertions return only bounded
// counts or booleans, and cleanup scrubs controls before the lane exits.
test.describe('credential-safe authentication preview lanes', () => {

  test('password preview submits only a credential-free local fixture action', async ({ page }) => {
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');

    const fixtureForm = page.getByRole('form', { name: 'Hermes password sign in' });
    const username = page.getByLabel('Username');
    const password = page.getByRole('textbox', { name: 'Password' });
    await expect(fixtureForm).toHaveAttribute('autocomplete', 'off');
    await expect(fixtureForm).toHaveAttribute('data-form-type', 'other');
    await expect(fixtureForm).toHaveAttribute('method', 'dialog');
    await expect(fixtureForm).toHaveAttribute('data-field-ownership', 'ready');
    await expect(username).not.toHaveAttribute('name', /.+/);
    await expect(username).toHaveAttribute('data-fixture-field', 'username');
    await expect(username).toHaveAttribute('autocomplete', 'off');
    await expect(password).not.toHaveAttribute('name', /.+/);
    await expect(password).toHaveAttribute('data-fixture-field', 'password');
    await expect(password).toHaveAttribute('autocomplete', 'off');

    await installPreviewCredentialProbe(page);
    try {
      await seedPreviewCredentials(page);
      const seededEvidence = await readPreviewCredentialEvidence(page);
      expect(seededEvidence.liveValueMatchCount).toBe(2);
      expect(seededEvidence.liveNonEmptyCount).toBe(2);
      expect(seededEvidence.crossFieldValueMatchCount).toBe(0);
      const signIn = page.getByRole('button', { name: 'Sign in' });
      await signIn.evaluate((button) => button.setAttribute('data-pointer-owner', 'password-submit'));
      const signInBox = await signIn.boundingBox();
      expect(signInBox).not.toBeNull();
      await page.mouse.move(
        (signInBox?.x ?? 0) + (signInBox?.width ?? 0) / 2,
        (signInBox?.y ?? 0) + (signInBox?.height ?? 0) / 2
      );
      await page.mouse.down();

      // Pointer-down activation clears both controls and publishes the local action
      // before pointer up. The button must stay mounted to consume its one matching
      // compatibility click instead of replacing the form mid-gesture.
      await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password-submitting');
      const pointerEvidence = await readPreviewCredentialEvidence(page);
      expect(pointerEvidence.liveValueMatchCount).toBe(0);
      expect(pointerEvidence.liveNonEmptyCount).toBe(0);
      expect(pointerEvidence.defaultValueMatchCount).toBe(0);
      expect(pointerEvidence.serializedCredentialCount).toBe(0);
      expect(pointerEvidence.renderedCredentialCount).toBe(0);
      await expect(page.getByRole('button', { name: 'Signing in' })).toHaveAttribute(
        'data-pointer-owner',
        'password-submit'
      );
      const authActionNote = page.locator('.section-note').nth(1);
      await expect(authActionNote).toHaveText('submit-password-fixture');
      await expect(authActionNote).toHaveAttribute('data-auth-action-count', '1');
      await page.mouse.up();

      await expect(authActionNote).toHaveText('submit-password-fixture');
      await expect(authActionNote).toHaveAttribute('data-auth-action-count', '1');
      await expect(page.getByText(/sent only to the configured/i)).not.toBeVisible();
    } finally {
      await scrubPreviewCredentialProbe(page);
    }
  });

  test('hydrated password submission remains keyboard accessible and credential-free', async ({ page }) => {
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');
    const auth = page.getByTestId('auth-preview');
    const form = page.getByRole('form', { name: 'Hermes password sign in' });
    const password = page.getByRole('textbox', { name: 'Password' });
    await expect(form).toHaveAttribute('data-field-ownership', 'ready');

    await installPreviewCredentialProbe(page);
    try {
      await seedPreviewCredentials(page);
      const seededEvidence = await readPreviewCredentialEvidence(page);
      expect(seededEvidence.liveValueMatchCount).toBe(2);
      expect(seededEvidence.liveNonEmptyCount).toBe(2);
      expect(seededEvidence.crossFieldValueMatchCount).toBe(0);
      await password.press('Enter');

      await expect(auth).toHaveAttribute('data-state', 'password-submitting');
      const keyboardEvidence = await readPreviewCredentialEvidence(page);
      expect(keyboardEvidence.liveValueMatchCount).toBe(0);
      expect(keyboardEvidence.liveNonEmptyCount).toBe(0);
      expect(keyboardEvidence.defaultValueMatchCount).toBe(0);
      expect(keyboardEvidence.serializedCredentialCount).toBe(0);
      expect(keyboardEvidence.renderedCredentialCount).toBe(0);
      await expect(page.locator('.section-note').nth(1)).toHaveText('submit-password-fixture');
      await expect(page.locator('.section-note').nth(1)).toHaveAttribute('data-auth-action-count', '1');
    } finally {
      await scrubPreviewCredentialProbe(page);
    }
  });

  test('password cancellation keeps the current action name and returns to owned password entry', async ({ page }) => {
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');

    const auth = page.getByTestId('auth-preview');
    const form = page.getByRole('form', { name: 'Hermes password sign in' });
    const password = page.getByRole('textbox', { name: 'Password' });
    await expect(form).toHaveAttribute('data-field-ownership', 'ready');

    await installPreviewCredentialProbe(page);
    try {
      await seedPreviewCredentials(page);
      const seededEvidence = await readPreviewCredentialEvidence(page);
      expect(seededEvidence.liveValueMatchCount).toBe(2);
      expect(seededEvidence.liveNonEmptyCount).toBe(2);
      expect(seededEvidence.crossFieldValueMatchCount).toBe(0);
      await password.press('Enter');
      await expect(auth).toHaveAttribute('data-state', 'password-submitting');

      const cancel = page.getByRole('button', { name: 'Cancel sign-in' });
      await expect(cancel).toBeVisible();
      await expect(page.getByRole('button', { name: 'Back to providers' })).toHaveCount(0);
      await cancel.click();

      await expect(auth).toHaveAttribute('data-state', 'password');
      await expect(form).toHaveAttribute('data-field-ownership', 'ready');
      const cancellationEvidence = await readPreviewCredentialEvidence(page);
      expect(cancellationEvidence.liveValueMatchCount).toBe(0);
      expect(cancellationEvidence.liveNonEmptyCount).toBe(0);
      expect(cancellationEvidence.defaultValueMatchCount).toBe(0);
      expect(cancellationEvidence.serializedCredentialCount).toBe(0);
      expect(cancellationEvidence.renderedCredentialCount).toBe(0);
      await expect(page.getByLabel('Username')).toBeFocused();
      await expect(page.locator('.section-note').nth(1)).toHaveText('cancel-sign-in');
    } finally {
      await scrubPreviewCredentialProbe(page);
    }
  });

  test('password cancellation preserves one Pill gesture across pointerup, pointercancel, and compatibility click', async ({ page }) => {
    for (const terminalEvent of ['pointerup', 'pointercancel'] as const) {
      await page.goto(previewUrl('/ui-preview'));
      await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');

      const auth = page.getByTestId('auth-preview');
      const form = page.getByRole('form', { name: 'Hermes password sign in' });
      const password = page.getByRole('textbox', { name: 'Password' });
      const actionNote = page.locator('.section-note').nth(1);
      await expect(form).toHaveAttribute('data-field-ownership', 'ready');

      await installPreviewCredentialProbe(page);
      try {
        await seedPreviewCredentials(page);
      const seededEvidence = await readPreviewCredentialEvidence(page);
      expect(seededEvidence.liveValueMatchCount).toBe(2);
      expect(seededEvidence.liveNonEmptyCount).toBe(2);
      expect(seededEvidence.crossFieldValueMatchCount).toBe(0);
        await password.press('Enter');
        await expect(auth).toHaveAttribute('data-state', 'password-submitting');
        await expect(actionNote).toHaveAttribute('data-auth-action-count', '1');

        const cancel = page.getByRole('button', { name: 'Cancel sign-in' });
        await cancel.evaluate((button) => button.setAttribute('data-pointer-owner', 'cancel-sign-in'));
        await cancel.dispatchEvent('pointerdown', { button: 0, pointerType: 'mouse' });
        await expect(auth).toHaveAttribute('data-state', 'password');

        const returned = page.getByRole('button', { name: 'Back to providers' });
        await expect(returned).toHaveAttribute('data-pointer-owner', 'cancel-sign-in');
        if (terminalEvent === 'pointerup') {
          await returned.dispatchEvent('pointerup', { button: 0, pointerType: 'mouse' });
        } else {
          await returned.dispatchEvent('pointercancel', { pointerType: 'mouse' });
        }
        await returned.dispatchEvent('click', { detail: 1 });

        await expect(auth).toHaveAttribute('data-state', 'password');
        await expect(actionNote).toHaveText('cancel-sign-in');
        await expect(actionNote).toHaveAttribute('data-auth-action-count', '2');
        await expect(form).toHaveAttribute('data-field-ownership', 'ready');
        const gestureEvidence = await readPreviewCredentialEvidence(page);
        expect(gestureEvidence.liveValueMatchCount).toBe(0);
        expect(gestureEvidence.liveNonEmptyCount).toBe(0);
        expect(gestureEvidence.defaultValueMatchCount).toBe(0);
        expect(gestureEvidence.serializedCredentialCount).toBe(0);
        expect(gestureEvidence.renderedCredentialCount).toBe(0);
        await expect(page.getByLabel('Username')).toBeFocused();
      } finally {
        await scrubPreviewCredentialProbe(page);
      }
    }
  });

test('first-load no-script product route exposes only the inert loading boundary', async ({ page }, testInfo) => {
  expect(testInfo.project.name).toBe('chromium-js-disabled');
  const cdp = await page.context().newCDPSession(page);
  let authRequestCount = 0;
  const onRequest = (request: { url(): string }) => {
    if (/\/api\/auth\//u.test(request.url())) authRequestCount += 1;
  };
  page.on('request', onRequest);

  try {
    await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });
    await page.goto(previewUrl('/'));

    await expect(page.getByLabel('Starting Hermternal')).toHaveAttribute('aria-busy', 'true');
    await expect(page.getByTestId('auth-preview')).toHaveCount(0);
    await expect(page.getByRole('form', { name: 'Hermes password sign in' })).toHaveCount(0);
    await expect(page.locator('input[type="password"]')).toHaveCount(0);
    const passwordTextVisible = (await page.getByText(/password/i).count()) > 0;
    expect(passwordTextVisible).toBe(false);
    expect(authRequestCount).toBe(0);
  } finally {
    page.off('request', onRequest);
    await cdp.send('Emulation.setScriptExecutionDisabled', { value: false }).catch(() => undefined);
    await cdp.detach().catch(() => undefined);
  }
});

  test('native password activation clears live values without navigation, storage mutation, serialization, or retained artifacts', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    for (const activation of ['click', 'enter'] as const) {
      let requestCount = 0;
      let navigationCount = 0;
      let scriptDisabled = false;
      const onRequest = (request: { isNavigationRequest(): boolean }) => {
        requestCount += 1;
        if (request.isNavigationRequest()) navigationCount += 1;
      };
      const cdp = await page.context().newCDPSession(page);
      try {
        await cdp.send('Emulation.setScriptExecutionDisabled', { value: false });
        await page.goto(previewUrl('/ui-preview'));
        await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');
        await expect(page.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready');
        const originalUrl = page.url();
        const originalHistoryLength = await page.evaluate(() => history.length);
        const signIn = page.getByRole('button', { name: 'Sign in' });
        const signInBox = await signIn.boundingBox();
        expect(signInBox).not.toBeNull();
        await signIn.focus();
        await expect(signIn).toBeFocused();

        // Seed noncredentialed values so same-key overwrites are detectable,
        // then prove the sanitizer distinguishes an overwrite before the native
        // action begins. Only counts and digest equality leave the page.
        await seedNativeStorage(page);
        const seededStorage = await readStorageEvidence(page);
        expect(seededStorage.cryptoSupported).toBe(true);
        await overwriteNativeStorage(page);
        const overwrittenStorage = await readStorageEvidence(page);
        expect(storageEvidenceEqual(seededStorage, overwrittenStorage)).toBe(false);
        await seedNativeStorage(page);
        const storageBefore = await readStorageEvidence(page);
        expect(storageEvidenceEqual(seededStorage, storageBefore)).toBe(true);

        await installNativeCredentialProof(page);
        const preActionEvidence = await readNativeCredentialEvidence(page);
        expect(preActionEvidence.liveValueMatchCount).toBe(2);
        await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });
        scriptDisabled = true;

        // The disabled-script action is the only period observed by protocol
        // counters, so setup traffic cannot be misattributed to native proof.
        requestCount = 0;
        navigationCount = 0;
        page.on('request', onRequest);
        // Use protocol input only after script execution is disabled. The
        // geometry and focus are captured above while locator actions remain safe.
        if (activation === 'click') {
          await page.mouse.click(
            (signInBox?.x ?? 0) + (signInBox?.width ?? 0) / 2,
            (signInBox?.y ?? 0) + (signInBox?.height ?? 0) / 2
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
        if (scriptDisabled) {
          await cdp.send('Emulation.setScriptExecutionDisabled', { value: false }).catch(() => undefined);
        }
        await scrubNativeCredentialProof(page);
        await clearNativeStorage(page);
        await cdp.detach().catch(() => undefined);
      }
    }
  });

  test('storage evidence fails closed for injected crypto, signing, canonicalization, and truncation failures', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const expectUnsupported = (evidence: Awaited<ReturnType<typeof readStorageEvidence>>): void => {
      expect(evidence).toEqual({
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
    };

    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');
    await expect(page.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute(
      'data-field-ownership',
      'ready'
    );

    try {
      await seedNativeStorage(page);
      const supportedStorage = await readStorageEvidence(page);
      expect(supportedStorage.status).toBe('supported');
      expect(supportedStorage.cryptoSupported).toBe(true);
      expect(supportedStorage.readFailure).toBe(false);
      expect(supportedStorage.truncated).toBe(false);
      expect(storageEvidenceEqual(supportedStorage, supportedStorage)).toBe(true);

      for (const injectFailure of [
        'random',
        'import-key',
        'probe-sign',
        'sign',
        'cookie-sign',
        'idb-enumeration-unavailable',
        'canonicalization',
        'truncation'
      ] as const) {
        const failedStorage = await readStorageEvidence(page, { injectFailure });
        if (injectFailure === 'truncation') {
          expect(failedStorage).toEqual({
            cryptoSupported: true,
            status: 'truncated',
            truncated: true,
            readFailure: false,
            recordCount: null,
            digestCount: null,
            recordLimit: 2_048,
            cookieCount: null,
            localStorageEntryCount: null,
            sessionStorageEntryCount: null,
            indexedDbSupported: null,
            indexedDbRecordCount: null,
            indexedDbUnexpectedDatabaseCount: null,
            indexedDbDatabaseCount: null,
            indexedDbStoreCount: null,
            cookieTruncated: true,
            localStorageTruncated: false,
            sessionStorageTruncated: false,
            indexedDbTruncated: false,
            truncation: { any: true, cookie: true, localStorage: false, sessionStorage: false, indexedDb: false },
            fingerprint: null
          });
        } else {
          expectUnsupported(failedStorage);
        }
        expect(storageEvidenceEqual(supportedStorage, failedStorage)).toBe(false);
        expect(storageEvidenceEqual(failedStorage, failedStorage)).toBe(false);
      }
    } finally {
      await scrubNativeCredentialProof(page);
      await clearNativeStorage(page);
    }
  });

  test('storage evidence opens only the reviewed IndexedDB database, store, and key', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const reviewedLabels = {
      database: '__hermternal_native_auth_proof__',
      store: 'proof',
      key: 'same-key'
    } as const;
    const spyGlobal = '__uiPreviewStorageEvidenceIndexedDbSpy';
    let methodsRestored = false;
    let cleanupFailure = false;

    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');
    await expect(page.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute(
      'data-field-ownership',
      'ready'
    );

    try {
      await seedNativeStorage(page);

      // Install the spy only after seeding so setup writes cannot be mistaken for
      // evidence reads. It retains only counts plus the reviewed labels; no raw
      // IndexedDB names, keys, values, or thrown messages cross the page boundary.
      const spyInstalled = await installPreviewIndexedDbSpy(page, {
        databaseName: reviewedLabels.database,
        objectStoreName: reviewedLabels.store,
        objectKey: reviewedLabels.key,
        globalName: spyGlobal
      });
      expect(spyInstalled).toBe(true);

      const storageEvidence = await readStorageEvidence(page);
      expect(storageEvidence.status).toBe('supported');
      expect(storageEvidence.cryptoSupported).toBe(true);
      expect(storageEvidence.readFailure).toBe(false);
      expect(storageEvidenceEqual(storageEvidence, storageEvidence)).toBe(true);

      const observations = await page.evaluate((globalName): PreviewIndexedDbSpyObservation | null => {
        const descriptor = Object.getOwnPropertyDescriptor(window, globalName);
        if (!descriptor || !('value' in descriptor)) return null;
        const spy = descriptor.value as { read?: () => PreviewIndexedDbSpyObservation };
        return typeof spy.read === 'function' ? spy.read() : null;
      }, spyGlobal);
      expect(observations).not.toBeNull();
      expect(observations?.databaseEnumerationCount).toBe(1);
      expect(observations?.databaseOpenCount).toBe(1);
      expect(observations?.reviewedDatabaseOpenCount).toBe(1);
      expect(observations?.unrelatedDatabaseOpenCount).toBe(0);
      expect(observations?.transactionInvocationCount).toBe(1);
      expect(observations?.reviewedStoreInvocationCount).toBe(1);
      expect(observations?.unrelatedStoreInvocationCount).toBe(0);
      expect(observations?.countInvocationCount).toBe(1);
      expect(observations?.getInvocationCount).toBe(1);
      expect(observations?.reviewedKeyInvocationCount).toBe(2);
      expect(observations?.unrelatedKeyInvocationCount).toBe(0);
    } finally {
      const restoration = await restorePreviewIndexedDbSpy(page, spyGlobal);
      methodsRestored = restoration.restored;
      cleanupFailure = restoration.cleanupFailure;
      await scrubNativeCredentialProof(page);
      await clearNativeStorage(page);
    }

    expect(methodsRestored).toBe(true);
    expect(cleanupFailure).toBe(false);
  });

  test('preview IndexedDB spy cleanup reports ownership loss and succeeds on retry', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const spyGlobal = '__uiPreviewStorageEvidenceIndexedDbSpy';
    const recoveryGlobal = '__uiPreviewStorageEvidenceIndexedDbRecovery';
    let cleanupCompleted = false;
    await page.goto(previewUrl('/ui-preview'));

    try {
      const spyInstalled = await installPreviewIndexedDbSpy(page, {
        databaseName: '__hermternal_native_auth_proof__',
        objectStoreName: 'proof',
        objectKey: 'same-key',
        globalName: spyGlobal
      });
      expect(spyInstalled).toBe(true);

      const moved = await page.evaluate(({ globalName, recoveryName }) => {
        const descriptor = Object.getOwnPropertyDescriptor(window, globalName);
        if (!descriptor || !('value' in descriptor)) return false;
        if (!Reflect.deleteProperty(window, globalName)) return false;
        Object.defineProperty(window, recoveryName, {
          configurable: true,
          enumerable: false,
          writable: false,
          value: descriptor.value
        });
        return true;
      }, { globalName: spyGlobal, recoveryName: recoveryGlobal });
      expect(moved).toBe(true);

      const failedCleanup = await restorePreviewIndexedDbSpy(page, spyGlobal);
      expect(failedCleanup.restored).toBe(false);
      expect(failedCleanup.cleanupFailure).toBe(true);

      const republished = await page.evaluate(({ globalName, recoveryName }) => {
        const descriptor = Object.getOwnPropertyDescriptor(window, recoveryName);
        if (!descriptor || !('value' in descriptor)) return false;
        Object.defineProperty(window, globalName, {
          configurable: true,
          enumerable: false,
          writable: false,
          value: descriptor.value
        });
        return Reflect.deleteProperty(window, recoveryName);
      }, { globalName: spyGlobal, recoveryName: recoveryGlobal });
      expect(republished).toBe(true);

      const retriedCleanup = await restorePreviewIndexedDbSpy(page, spyGlobal);
      expect(retriedCleanup.restored).toBe(true);
      expect(retriedCleanup.cleanupFailure).toBe(false);
      cleanupCompleted = true;
    } finally {
      if (!cleanupCompleted) {
        await page.evaluate(({ globalName, recoveryName }) => {
          const current = Object.getOwnPropertyDescriptor(window, globalName);
          const recovery = Object.getOwnPropertyDescriptor(window, recoveryName);
          const candidate = current && 'value' in current ? current.value : recovery && 'value' in recovery ? recovery.value : null;
          if (candidate && typeof (candidate as { restore?: () => unknown }).restore === 'function') {
            try {
              (candidate as { restore: () => unknown }).restore();
            } catch {
              // The test result already reports the sanitized cleanup failure.
            }
          }
          if (current?.configurable) Reflect.deleteProperty(window, globalName);
          if (recovery?.configurable) Reflect.deleteProperty(window, recoveryName);
        }, { globalName: spyGlobal, recoveryName: recoveryGlobal });
      }
    }
  });

  test('preview IndexedDB spy rollback preserves an existing falsy non-writable global', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

    const spyGlobal = '__uiPreviewStorageEvidenceIndexedDbSpy';
    const baselineGlobal = '__uiPreviewStorageEvidenceIndexedDbBaseline';
    await page.goto(previewUrl('/ui-preview'));

    try {
      await page.evaluate(({ globalName, baselineName }) => {
        const factory = indexedDB;
        const databasePrototype = IDBDatabase.prototype;
        const storePrototype = IDBObjectStore.prototype;
        const state = {
          open: factory.open,
          databases: factory.databases,
          transaction: databasePrototype.transaction,
          count: storePrototype.count,
          get: storePrototype.get,
          openDescriptor: Object.getOwnPropertyDescriptor(factory, 'open'),
          databasesDescriptor: Object.getOwnPropertyDescriptor(factory, 'databases'),
          transactionDescriptor: Object.getOwnPropertyDescriptor(databasePrototype, 'transaction'),
          countDescriptor: Object.getOwnPropertyDescriptor(storePrototype, 'count'),
          getDescriptor: Object.getOwnPropertyDescriptor(storePrototype, 'get')
        };
        Object.defineProperty(window, baselineName, {
          configurable: true,
          enumerable: false,
          writable: false,
          value: state
        });
        Object.defineProperty(window, globalName, {
          configurable: false,
          enumerable: false,
          writable: false,
          value: false
        });
      }, { globalName: spyGlobal, baselineName: baselineGlobal });

      const spyInstalled = await installPreviewIndexedDbSpy(page, {
        databaseName: '__hermternal_native_auth_proof__',
        objectStoreName: 'proof',
        objectKey: 'same-key',
        globalName: spyGlobal
      });
      expect(spyInstalled).toBe(false);

      const rollback = await page.evaluate(({ globalName, baselineName }) => {
        const windowDescriptor = Object.getOwnPropertyDescriptor(window, globalName);
        const baselineDescriptor = Object.getOwnPropertyDescriptor(window, baselineName);
        const baseline = baselineDescriptor && 'value' in baselineDescriptor
          ? baselineDescriptor.value as {
              open: unknown;
              databases: unknown;
              transaction: unknown;
              count: unknown;
              get: unknown;
              openDescriptor?: PropertyDescriptor;
              databasesDescriptor?: PropertyDescriptor;
              transactionDescriptor?: PropertyDescriptor;
              countDescriptor?: PropertyDescriptor;
              getDescriptor?: PropertyDescriptor;
            }
          : undefined;
        const sameDescriptor = (
          left: PropertyDescriptor | undefined,
          right: PropertyDescriptor | undefined
        ): boolean => {
          if (!left || !right) return left === right;
          if (left.configurable !== right.configurable || left.enumerable !== right.enumerable) return false;
          const leftIsData = 'value' in left;
          if (leftIsData !== ('value' in right)) return false;
          if (leftIsData) return left.value === right.value && left.writable === right.writable;
          return left.get === right.get && left.set === right.set;
        };
        return {
          globalPresent: Boolean(windowDescriptor),
          globalIsFalse: Boolean(
            windowDescriptor && 'value' in windowDescriptor && windowDescriptor.value === false
          ),
          globalConfigurable: windowDescriptor?.configurable ?? null,
          globalEnumerable: windowDescriptor?.enumerable ?? null,
          globalWritable: windowDescriptor && 'writable' in windowDescriptor ? windowDescriptor.writable ?? null : null,
          methodIdentityRestored: Boolean(
            baseline &&
              indexedDB.open === baseline.open &&
              indexedDB.databases === baseline.databases &&
              IDBDatabase.prototype.transaction === baseline.transaction &&
              IDBObjectStore.prototype.count === baseline.count &&
              IDBObjectStore.prototype.get === baseline.get
          ),
          descriptorShapeRestored: Boolean(
            baseline &&
              sameDescriptor(Object.getOwnPropertyDescriptor(indexedDB, 'open'), baseline.openDescriptor) &&
              sameDescriptor(Object.getOwnPropertyDescriptor(indexedDB, 'databases'), baseline.databasesDescriptor) &&
              sameDescriptor(
                Object.getOwnPropertyDescriptor(IDBDatabase.prototype, 'transaction'),
                baseline.transactionDescriptor
              ) &&
              sameDescriptor(Object.getOwnPropertyDescriptor(IDBObjectStore.prototype, 'count'), baseline.countDescriptor) &&
              sameDescriptor(Object.getOwnPropertyDescriptor(IDBObjectStore.prototype, 'get'), baseline.getDescriptor)
          )
        };
      }, { globalName: spyGlobal, baselineName: baselineGlobal });

      expect(rollback.globalPresent).toBe(true);
      expect(rollback.globalIsFalse).toBe(true);
      expect(rollback.globalConfigurable).toBe(false);
      expect(rollback.globalEnumerable).toBe(false);
      expect(rollback.globalWritable).toBe(false);
      expect(rollback.methodIdentityRestored).toBe(true);
      expect(rollback.descriptorShapeRestored).toBe(true);
    } finally {
      await page.evaluate((baselineName) => {
        const descriptor = Object.getOwnPropertyDescriptor(window, baselineName);
        if (descriptor?.configurable) Reflect.deleteProperty(window, baselineName);
      }, baselineGlobal);
    }
  });

  test('password ownership fences delayed hydration, rapid focus transfer, and keyboard submission', async ({ page }) => {
  await page.addInitScript(() => {
    const frames: Array<(timestamp: number) => void> = [];
    Object.defineProperty(window, 'requestAnimationFrame', {
      configurable: true,
      value: (callback: (timestamp: number) => void) => {
        frames.push(callback);
        return frames.length;
      }
    });
    Object.defineProperty(window, 'cancelAnimationFrame', {
      configurable: true,
      value: (handle: number) => {
        frames.splice(Math.max(0, handle - 1), 1);
      }
    });
    Object.defineProperty(window, 'releaseAuthFrames', {
      configurable: true,
      value: () => {
        const pending = frames.splice(0);
        for (const callback of pending) callback(performance.now());
      }
    });
  });

  await page.goto(previewUrl('/ui-preview'));
  const auth = page.getByTestId('auth-preview');
  const authState = page.getByRole('combobox', { name: 'Authentication state' });
  await authState.selectOption('password');

  const form = page.getByRole('form', { name: 'Hermes password sign in' });
  const username = page.getByLabel('Username');
  const password = page.getByRole('textbox', { name: 'Password' });
  await installPreviewCredentialProbe(page);
  try {
    await expect(form).toHaveAttribute('data-field-ownership', 'pending');
    await expect(username).toHaveAttribute('readonly', '');
    await expect(password).toHaveAttribute('readonly', '');

    // A rapid keyboard event while the focus transfer is queued cannot populate
    // either field because both controls are still read-only.
    await password.focus();
    await page.keyboard.press('KeyQ');
    const pendingEvidence = await readPreviewCredentialEvidence(page);
    expect(pendingEvidence.liveNonEmptyCount).toBe(0);
    expect(pendingEvidence.liveValueMatchCount).toBe(0);

    await page.evaluate(() => {
      (window as unknown as Window & { releaseAuthFrames: () => void }).releaseAuthFrames();
    });
    await expect(form).toHaveAttribute('data-field-ownership', 'ready');
    await expect(username).toBeFocused();

    for (let attempt = 0; attempt < 3; attempt += 1) {
      await password.click();
      await expect(password).toBeFocused();
      await seedPreviewCredentials(page);
      const seededEvidence = await readPreviewCredentialEvidence(page);
      expect(seededEvidence.liveValueMatchCount).toBe(2);
      expect(seededEvidence.liveNonEmptyCount).toBe(2);
      expect(seededEvidence.crossFieldValueMatchCount).toBe(0);
      const populatedEvidence = await readPreviewCredentialEvidence(page);
      expect(populatedEvidence.liveValueMatchCount).toBe(2);
      expect(populatedEvidence.liveNonEmptyCount).toBe(2);
      expect(populatedEvidence.crossFieldValueMatchCount).toBe(0);

      await password.press('Enter');
      await expect(auth).toHaveAttribute('data-state', 'password-submitting');
      const clearedEvidence = await readPreviewCredentialEvidence(page);
      expect(clearedEvidence.liveValueMatchCount).toBe(0);
      expect(clearedEvidence.liveNonEmptyCount).toBe(0);
      expect(clearedEvidence.defaultValueMatchCount).toBe(0);
      expect(clearedEvidence.serializedCredentialCount).toBe(0);
      expect(clearedEvidence.renderedCredentialCount).toBe(0);

      if (attempt < 2) {
        await authState.selectOption('password');
        await page.evaluate(() => {
          (window as unknown as Window & { releaseAuthFrames: () => void }).releaseAuthFrames();
        });
        await expect(form).toHaveAttribute('data-field-ownership', 'ready');
        await expect(username).toBeFocused();
      }
    }
  } finally {
    await scrubPreviewCredentialProbe(page);
  }
});

  test('native field Enter preserves live values while failing closed without navigation, storage mutation, serialization, or observed FormData activity', async ({ page }, testInfo) => {
    expect(testInfo.project.name).toBe('chromium-auth-safe');
    expect(testInfo.project.use.trace).toBe('off');
    expect(testInfo.project.use.screenshot).toBe('off');
    expect(testInfo.project.use.video).toBe('off');

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
      await page.goto(previewUrl('/ui-preview'));
      await page.getByRole('combobox', { name: 'Authentication state' }).selectOption('password');
      const form = page.getByRole('form', { name: 'Hermes password sign in' });
      const password = page.getByRole('textbox', { name: 'Password' });
      await expect(form).toHaveAttribute('data-field-ownership', 'ready');
      const passwordBox = await password.boundingBox();
      expect(passwordBox).not.toBeNull();
      await password.focus();
      await expect(password).toBeFocused();

      const originalUrl = page.url();
      const originalHistoryLength = await page.evaluate(() => history.length);
      await seedNativeStorage(page);
      const seededStorage = await readStorageEvidence(page);
      expect(seededStorage.cryptoSupported).toBe(true);
      await overwriteNativeStorage(page);
      const overwrittenStorage = await readStorageEvidence(page);
      expect(storageEvidenceEqual(seededStorage, overwrittenStorage)).toBe(false);
      await seedNativeStorage(page);
      const storageBefore = await readStorageEvidence(page);
      expect(storageEvidenceEqual(seededStorage, storageBefore)).toBe(true);

      await installNativeCredentialProof(page);
      await cdp.send('Emulation.setScriptExecutionDisabled', { value: true });
      scriptDisabled = true;

      // Protocol request counts begin after setup. Enter from an input has no
      // running handler or native reset target, so retaining live values is the
      // expected bounded DOM-retention outcome while the action fails closed.
      requestCount = 0;
      navigationCount = 0;
      page.on('request', onRequest);
      // Focus and geometry were captured before script execution was disabled;
      // raw keyboard input is the only action allowed in this interval.
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
      if (scriptDisabled) {
        await cdp.send('Emulation.setScriptExecutionDisabled', { value: false }).catch(() => undefined);
      }
      await scrubNativeCredentialProof(page);
      await clearNativeStorage(page);
      await cdp.detach().catch(() => undefined);
    }
  });
});

test('Pill consumes one pointer gesture across leave, re-entry, and compatibility click', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');
  // The trigger remains in the inert, aria-hidden underlay while its modal
  // drawer is open, so inspect the stable DOM control rather than the exposed
  // accessibility tree for the state assertion.
  const workspace = page.locator('button[aria-label="Open workspace"]');

  await workspace.dispatchEvent('pointerdown', { button: 0, pointerType: 'mouse' });
  await expect(workspace).toHaveAttribute('aria-expanded', 'true');
  await workspace.dispatchEvent('pointerleave', { pointerType: 'mouse' });
  await workspace.dispatchEvent('pointerenter', { pointerType: 'mouse' });
  await workspace.dispatchEvent('pointerup', { button: 0, pointerType: 'mouse' });
  await workspace.dispatchEvent('click', { detail: 1 });
  await expect(workspace).toHaveAttribute('aria-expanded', 'true');

  // The open drawer makes the underlay inert, so Escape is the modal close
  // path. Keyboard activation is then verified from the restored trigger.
  await page.keyboard.press('Escape');
  await expect(workspace).toHaveAttribute('aria-expanded', 'false');
  await expect(workspace).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(workspace).toHaveAttribute('aria-expanded', 'true');
});

test('opt-in live provider discovery uses the same-origin GET boundary and transitions from pending to success', async ({
  page
}) => {
  test.skip(
    process.env.VITE_HERMES_LIVE_AUTH_DISCOVERY !== 'true',
    'Set VITE_HERMES_LIVE_AUTH_DISCOVERY=true to build the opt-in live discovery lane.'
  );

  let requestCount = 0;
  let requestMethodIsGet = true;
  let requestHasAuthorization = false;
  let requestHasQuery = false;
  let releaseResponse!: () => void;
  const responseGate = new Promise<void>((resolve) => {
    releaseResponse = resolve;
  });

  const routePattern = '**/api/auth/providers';
  const routeHandler = async (route: Route): Promise<void> => {
    const request = route.request();
    requestCount += 1;
    requestMethodIsGet &&= request.method() === 'GET';
    requestHasAuthorization ||= Boolean(request.headers().authorization);
    try {
      requestHasQuery ||= new URL(request.url()).search.length > 0;
    } catch {
      requestHasQuery = true;
    }
    await responseGate;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        providers: [
          { name: 'nous', display_name: 'Nous', supports_password: false },
          { name: 'hermes-password', display_name: 'Hermes password', supports_password: true }
        ]
      })
    });
  };

  try {
    await page.route(routePattern, routeHandler);
    await page.goto(previewUrl('/ui-preview?authDiscovery=live'));
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-discovery-mode', 'live');
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'discovery-pending');
    await expect(page.getByTestId('auth-preview').getByRole('status')).toContainText('Discovering sign-in methods');
    await expect(page.getByRole('heading', { name: 'Discovering sign-in methods' })).toBeFocused();
    const liveStateOutput = page.getByRole('combobox', { name: 'Authentication state' });
    await expect(liveStateOutput).toBeDisabled();

    releaseResponse();
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection');
    await expect(page.getByRole('button', { name: 'Nous, unavailable' })).toBeDisabled();
    await expect(page.getByRole('button', { name: 'Hermes password' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Connect to Hermes' })).toBeFocused();

    await liveStateOutput.evaluate((select: HTMLSelectElement) => {
      select.value = 'discovery-empty';
      select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection');

    // `supports_password: false` does not prove OAuth capability. Only the
    // password-capable provider advances through this reviewed response shape.
    await page.getByRole('button', { name: 'Hermes password' }).click();
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password');
    await expect(page.getByLabel('Username')).toBeFocused();

    expect(requestCount).toBe(1);
    expect(requestMethodIsGet).toBe(true);
    expect(requestHasAuthorization).toBe(false);
    expect(requestHasQuery).toBe(false);
  } finally {
    releaseResponse();
    await page.unroute(routePattern, routeHandler).catch(() => undefined);
  }
});

test('opt-in live provider discovery fails closed on reviewed 503 and retries idempotently', async ({ page }) => {
  test.skip(
    process.env.VITE_HERMES_LIVE_AUTH_DISCOVERY !== 'true',
    'Set VITE_HERMES_LIVE_AUTH_DISCOVERY=true to build the opt-in live discovery lane.'
  );

  let requestCount = 0;
  const routePattern = '**/api/auth/providers';
  const routeHandler = async (route: Route): Promise<void> => {
    requestCount += 1;
    if (requestCount === 1) {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'no auth providers registered' })
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        providers: [{ name: 'nous', display_name: 'Nous', supports_password: false }]
      })
    });
  };

  try {
    await page.route(routePattern, routeHandler);
    await page.goto(previewUrl('/ui-preview?authDiscovery=live'));
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-unavailable');
    await expect(page.getByTestId('auth-preview').getByRole('alert')).toContainText('No sign-in method is available');
    await expect(page.getByRole('heading', { name: 'Provider discovery stopped' })).toBeFocused();
    await expect(page.getByRole('combobox', { name: 'Authentication state' })).toBeDisabled();

    await page.getByRole('button', { name: 'Retry discovery' }).click();
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection');
    await expect(page.getByRole('button', { name: 'Nous' })).toBeVisible();
    expect(requestCount).toBe(2);
  } finally {
    await page.unroute(routePattern, routeHandler).catch(() => undefined);
  }
});

test('opt-in live provider discovery exposes cancellation and retries after abort', async ({ page }) => {
  test.skip(
    process.env.VITE_HERMES_LIVE_AUTH_DISCOVERY !== 'true',
    'Set VITE_HERMES_LIVE_AUTH_DISCOVERY=true to build the opt-in live discovery lane.'
  );

  let requestCount = 0;
  let releaseFirstResponse!: () => void;
  const firstResponseGate = new Promise<void>((resolve) => {
    releaseFirstResponse = resolve;
  });

  const routePattern = '**/api/auth/providers';
  const routeHandler = async (route: Route): Promise<void> => {
    requestCount += 1;
    if (requestCount === 1) {
      await firstResponseGate;
      try {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ providers: [{ name: 'nous', display_name: 'Nous', supports_password: false }] })
        });
      } catch {
        // The browser cancellation is the behavior under test.
      }
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ providers: [{ name: 'nous', display_name: 'Nous', supports_password: false }] })
    });
  };

  try {
    await page.route(routePattern, routeHandler);
    await page.goto(previewUrl('/ui-preview?authDiscovery=live'));
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'discovery-pending');
    await page.getByRole('button', { name: 'Cancel discovery' }).click();
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'discovery-aborted');
    await expect(page.getByTestId('auth-preview').getByRole('alert')).toContainText('Provider discovery was cancelled');
    await expect(page.getByRole('heading', { name: 'Provider discovery was cancelled' })).toBeFocused();

    releaseFirstResponse();
    await page.getByRole('button', { name: 'Retry discovery' }).click();
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection');
    expect(requestCount).toBe(2);
  } finally {
    releaseFirstResponse();
    await page.unroute(routePattern, routeHandler).catch(() => undefined);
  }
});

test('discovery fixture states remain accessible across empty, malformed, unavailable, aborted, and retry variants', async ({
  page
}) => {
  await page.goto(previewUrl('/ui-preview'));

  for (const state of [
    'discovery-empty',
    'discovery-malformed',
    'provider-unavailable',
    'discovery-aborted',
    'discovery-retry'
  ]) {
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption(state);
    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, state).toEqual([]);
  }
});

test('UI preview state branches have no axe violations in light, dark, desktop, and narrow layouts', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  for (const fixture of [
    {
      runtime: 'compatibility-check-failed',
      auth: 'password-submitting',
      appearance: 'light',
      viewport: { width: 1440, height: 900 }
    },
    {
      runtime: 'unsupported-version',
      auth: 'failure',
      appearance: 'dark',
      viewport: { width: 390, height: 844 }
    },
    {
      runtime: 'ready',
      auth: 'session-expired',
      appearance: 'light',
      viewport: { width: 768, height: 1024 }
    },
    {
      runtime: 'offline',
      auth: 'discovery-retry',
      appearance: 'dark',
      viewport: { width: 640, height: 900 }
    }
  ]) {
    await page.setViewportSize(fixture.viewport);
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Runtime state' }).selectOption(fixture.runtime);
    await page.getByRole('combobox', { name: 'Authentication state' }).selectOption(fixture.auth);
    await page.getByRole('combobox', { name: 'Appearance' }).selectOption(fixture.appearance);

    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations, JSON.stringify(fixture)).toEqual([]);
  }
});

test('records production preview timing without a threshold', async ({ page }) => {
  await page.goto(previewUrl('/ui-preview'), { waitUntil: 'networkidle' });

  const measurement = await page.evaluate(() => {
    const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
    return {
      domContentLoaded: navigation?.domContentLoadedEventEnd ?? null,
      loadEventEnd: navigation?.loadEventEnd ?? null,
      transferSize: navigation?.transferSize ?? null,
      resourceCount: performance.getEntriesByType('resource').length
    };
  });

  console.info('production ui-preview measurement', measurement);
  expect(measurement).toBeTruthy();
});

test('visible UI controls keep the shared 44px effective target', async ({ page }) => {
  for (const viewport of [
    { width: 1440, height: 900 },
    { width: 390, height: 844 }
  ]) {
    await page.setViewportSize(viewport);
    await page.goto(previewUrl('/ui-preview'));

    const undersizedControls = await page.evaluate(() =>
      Array.from(document.querySelectorAll('button, select, input, textarea'))
        .filter((element) => {
          const target = element.closest('label') ?? element;
          const style = getComputedStyle(target);
          const rect = target.getBoundingClientRect();
          return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 10 && rect.height > 10;
        })
        .filter((element) => {
          const target = element.closest('label') ?? element;
          const rect = target.getBoundingClientRect();
          return rect.width < 44 || rect.height < 44;
        })
        .map((element) => {
          const target = element.closest('label') ?? element;
          const rect = target.getBoundingClientRect();
          return {
            label: element.getAttribute('aria-label') ?? element.textContent?.trim() ?? element.tagName,
            width: rect.width,
            height: rect.height
          };
        })
    );

    expect(undersizedControls).toEqual([]);
  }
});

test('narrow reduced-transparency mode computes fully opaque materials without blur or saturation', async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);
  try {
    await cdp.send('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-reduced-transparency', value: 'reduce' }]
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  expect(await page.evaluate(() => matchMedia('(prefers-reduced-transparency: reduce)').matches)).toBe(true);
  const materials = await page.locator('.workspace-preview').evaluate((preview) => {
    const styleFor = (selector: string) => {
      const element = preview.querySelector(selector);
      if (!element) throw new Error(`Missing reduced-transparency fixture: ${selector}`);
      const style = getComputedStyle(element);
      return { backdropFilter: style.backdropFilter, backgroundColor: style.backgroundColor };
    };
    return {
      mobilePill: styleFor('.mobile-toolbar > .pill'),
      titleIsland: styleFor('.mobile-title-island'),
      conversationPanel: styleFor('.conversation-panel'),
      composer: styleFor('.composer')
    };
  });

    for (const material of Object.values(materials)) {
      expect(material.backdropFilter).toBe('none');
      expect(material.backgroundColor).toMatch(/^rgb\(/);
      expect(material.backgroundColor).not.toMatch(/^rgba\(/);
    }
  } finally {
    await cdp.detach().catch(() => undefined);
  }
});

test('forced-colors mode keeps the workspace chrome and focus ring discoverable', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active' });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(previewUrl('/ui-preview'));
  await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('ready');

  expect(await page.evaluate(() => matchMedia('(forced-colors: active)').matches)).toBe(true);
  const chrome = await page.locator('.workspace-preview').evaluate((preview) => {
    const element = preview.querySelector('.composer');
    if (!element) throw new Error('Missing workspace composer.');
    const style = getComputedStyle(element);
    return { backgroundColor: style.backgroundColor, borderColor: style.borderColor, boxShadow: style.boxShadow };
  });

  expect(chrome.backgroundColor).toMatch(/^rgb/);
  expect(chrome.borderColor).toMatch(/^rgb/);
  expect(chrome.boxShadow).toBe('none');

  const conversations = page.getByRole('button', { name: 'Open conversations' });
  await conversations.focus();
  await expect(conversations).toBeFocused();
  const outline = await conversations.evaluate((element) => getComputedStyle(element).outlineColor);
  expect(outline).toMatch(/^rgb/);
});

test('UI preview stays local at the 200% browser-zoom reflow equivalent with reduced motion', async ({ page }) => {
  let unexpectedRequestCount = 0;
  const expectedOrigin = uiPreviewOrigin;

  const routePattern = '**/*';
  const routeHandler = async (route: Route): Promise<void> => {
    const requestUrl = new URL(route.request().url());
    if (requestUrl.origin !== expectedOrigin) {
      unexpectedRequestCount += 1;
      await route.abort();
      return;
    }
    await route.continue();
  };

  try {
    await page.route(routePattern, routeHandler);
    await page.emulateMedia({ reducedMotion: 'reduce' });
    // Chromium exposes no stable cross-platform Ctrl-plus API. A real 640 CSS-pixel
    // layout viewport reproduces a 1280px desktop viewport at 200% browser zoom
    // without relying on the non-standard CSS zoom property.
    await page.setViewportSize({ width: 640, height: 900 });
    await page.goto(previewUrl('/ui-preview'));
    await page.getByRole('combobox', { name: 'Runtime state' }).selectOption('compatibility-check-failed');
    await page.getByRole('button', { name: 'Nous' }).click();
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'callback');
    await page.getByRole('button', { name: 'Cancel and return to providers' }).click();
    await page.getByRole('button', { name: 'Hermes password' }).click();
    await expect(page.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password');

    await expect(page.getByRole('heading', { name: 'Runtime and authentication states' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.clientWidth)).toBe(640);
    expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
    const hasReducedTransparencyFallback = await page.evaluate(() =>
      Array.from(document.styleSheets).some((styleSheet) => {
        try {
          return Array.from(styleSheet.cssRules).some((rule) => rule.cssText.includes('prefers-reduced-transparency'));
        } catch {
          return false;
        }
      })
    );
    expect(hasReducedTransparencyFallback).toBe(true);
    expect(unexpectedRequestCount).toBe(0);

    const overflow = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth
    }));
    expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
  } finally {
    await page.unroute(routePattern, routeHandler).catch(() => undefined);
  }
});
