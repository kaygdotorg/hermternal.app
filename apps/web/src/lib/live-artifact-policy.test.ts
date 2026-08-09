import { Buffer } from 'node:buffer';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { promises as fsPromises } from 'node:fs';
import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { basename, join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createLivePlaywrightConfig,
  getLivePlaywrightPaths,
  isLiveReconciliationEnabled
} from '../../tests/live/live-playwright-config.mjs';
import { createLiveProofLedger, matchLiveProofLedger } from '../../tests/live/live-proof-ledger.mjs';
import {
  LIVE_ARTIFACT_REDACTION,
  assertLiveRunnerDebugDisabled,
  finalizeLiveTest,
  liveArtifactOutputDirectory,
  liveCredentialValues,
  redactLiveText,
  redactLiveTransportMessage,
  redactTestErrors,
  removeLiveArtifacts,
  scrubLivePage
} from '../../tests/live/live-artifact-policy.mjs';

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

const execFileAsync = promisify(execFile);
const appRoot = existsSync(resolve(process.cwd(), 'node_modules/@playwright/test/cli.js'))
  ? resolve(process.cwd())
  : resolve(process.cwd(), 'apps/web');
const policyPath = resolve(appRoot, 'tests/live/live-artifact-policy.mjs');
const teardownPath = resolve(appRoot, 'tests/live/live-artifact-teardown.mjs');
const guardPath = resolve(appRoot, 'tests/live/live-ipc-guard.cjs');
const playwrightCliPath = resolve(appRoot, 'node_modules/@playwright/test/cli.js');
const playwrightEntryUrl = pathToFileURL(
  resolve(appRoot, 'node_modules/@playwright/test/index.mjs')
).href;

/**
 * Run an isolated Playwright 1.62.1 worker with the live policy imported before
 * the test body. The reporter serializes worker-mapped errors, stdio, and
 * attachment bodies, making a leaked credential observable without using the
 * real Hermes lane or a browser.
 */
async function runSyntheticPlaywright(
  specSource: string,
  options: {
    runnerDebug?: string;
    retries?: number;
    reportOutputRoot?: boolean;
  } = {}
): Promise<{
  code: number;
  stdout: string;
  stderr: string;
}> {
  const workspace = await mkdtemp(join(tmpdir(), 'hermternal-live-policy-playwright-'));
  const configPath = join(workspace, 'playwright.config.mjs');
  const specPath = join(workspace, 'synthetic.spec.mjs');
  const reporterPath = join(workspace, 'reporter.mjs');
  const policyUrl = pathToFileURL(policyPath).href;
  const reporterSource = `
function render(value) {
  if (Buffer.isBuffer(value)) {
    return JSON.stringify({ base64: value.toString('base64'), text: value.toString('utf8') });
  }
  return JSON.stringify(value);
}
export default class SyntheticReporter {
  onStdOut(chunk) {
    process.stdout.write('STDOUT:' + render(chunk) + '\\n');
  }
  onStdErr(chunk) {
    process.stdout.write('STDERR:' + render(chunk) + '\\n');
  }
  onStepEnd(_test, _result, step) {
    process.stdout.write('STEP:' + JSON.stringify(step.error) + '\\n');
  }
  onTestEnd(_test, result) {
    const attachments = (result.attachments ?? []).map((attachment) => ({
      name: attachment.name,
      body: attachment.body === undefined ? undefined : render(attachment.body)
    }));
    process.stdout.write('TEST:' + result.status + ':' + JSON.stringify({ errors: result.errors, attachments }) + '\\n');
  }
  onEnd(result) {
    if (process.env.SYNTHETIC_REPORT_OUTPUT_ROOT)
      process.stdout.write('ROOT:' + process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR + '\\n');
    process.stdout.write('END:' + result.status + '\\n');
  }
}
`;
  const configSource = `
import { defineConfig } from ${JSON.stringify(playwrightEntryUrl)};
import { devNull } from 'node:os';
import { join } from 'node:path';
import {
  assertLiveRunnerDebugDisabled,
  liveArtifactOutputDirectory,
  liveArtifactOutputOwnershipToken
} from ${JSON.stringify(policyUrl)};
assertLiveRunnerDebugDisabled();
// Keep Playwright's post-teardown LastRunReporter from recreating a markerless
// project-output directory after global teardown removes the owned root.
process.env.PLAYWRIGHT_LAST_RUN_OUTPUT_FILE = devNull;
const outputDir = liveArtifactOutputDirectory();
const projectOutputDir = join(outputDir, '.playwright-output');
process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR = outputDir;
process.env.PLAYWRIGHT_LIVE_OUTPUT_TOKEN = liveArtifactOutputOwnershipToken();
const guardPath = ${JSON.stringify(guardPath)};
const existingNodeOptions = process.env.NODE_OPTIONS?.trim() ?? '';
if (!existingNodeOptions.includes(guardPath))
  process.env.NODE_OPTIONS = [existingNodeOptions, '--require=' + guardPath].filter(Boolean).join(' ');
export default defineConfig({
  testDir: ${JSON.stringify(workspace)},
  testMatch: /synthetic\\.spec\\.mjs/,
  fullyParallel: false,
  workers: 1,
  retries: ${String(options.retries ?? 0)},
  timeout: 20_000,
  outputDir: projectOutputDir,
  preserveOutput: 'never',
  reporter: [[${JSON.stringify(reporterPath)}]],
  globalTeardown: ${JSON.stringify(teardownPath)},
  use: {}
});
`;
  await Promise.all([
    writeFile(configPath, configSource, 'utf8'),
    writeFile(specPath, specSource.replaceAll('__POLICY_URL__', policyUrl), 'utf8'),
    writeFile(reporterPath, reporterSource, 'utf8')
  ]);
  const childEnvironment: NodeJS.ProcessEnv = {
    ...process.env,
    HERMES_TEST_PASSWORD: 'synthetic-password'
  };
  if (options.runnerDebug === undefined) delete childEnvironment.PW_RUNNER_DEBUG;
  else childEnvironment.PW_RUNNER_DEBUG = options.runnerDebug;
  if (options.reportOutputRoot) childEnvironment.SYNTHETIC_REPORT_OUTPUT_ROOT = '1';
  else delete childEnvironment.SYNTHETIC_REPORT_OUTPUT_ROOT;

  try {
    try {
      const result = await execFileAsync(
        process.execPath,
        [playwrightCliPath, 'test', '--config', configPath],
        {
          cwd: appRoot,
          env: childEnvironment,
          maxBuffer: 4 * 1024 * 1024,
          timeout: 10_000,
          encoding: 'utf8'
        }
      );
      return { code: 0, stdout: result.stdout, stderr: result.stderr };
    } catch (error) {
      const failure = error as NodeJS.ErrnoException & { stdout?: string; stderr?: string; code?: number };
      return {
        code: typeof failure.code === 'number' ? failure.code : 1,
        stdout: failure.stdout ?? '',
        stderr: failure.stderr ?? ''
      };
    }
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}

afterEach(async () => {
  // Each unit test gets a clean run root. This is global cleanup for the Vitest
  // harness; finalizeLiveTest itself only removes a per-test child directory.
  await removeLiveArtifacts(liveArtifactOutputDirectory());
});

describe('live Playwright artifact policy', () => {
  it('redacts realistic Playwright error contexts, matcher results, and native Error causes', () => {
    const sourceLocation = { file: '/tmp/live-proof.spec.ts', line: 42, column: 7 };
    const nestedCause = new Error('nested synthetic-password') as Error & {
      cause?: unknown;
    };
    Object.defineProperty(nestedCause, 'stack', {
      configurable: true,
      value: 'Error: nested synthetic-password\n<input value="synthetic-user">',
      writable: true
    });

    const rootError = new Error('expect(locator).toHaveText: synthetic-password') as Error & {
      errorContext?: string;
      matcherResult?: Record<string, unknown>;
    };
    Object.defineProperty(rootError, 'cause', {
      configurable: true,
      value: nestedCause,
      writable: true
    });
    rootError.errorContext = '- textbox "synthetic-user": synthetic-password';
    rootError.matcherResult = {
      message: 'expect(locator).toHaveValue: synthetic-password',
      actual: '<input id="auth-password" value="synthetic-password">',
      expected: 'synthetic-password',
      log: ['locator resolved with synthetic-user', 'value=synthetic-password'],
      ariaSnapshot: '- textbox "synthetic-user": synthetic-password'
    };

    const serializedTestInfoError = {
      location: sourceLocation,
      message: 'expect(locator).toHaveText: synthetic-password',
      stack: '<textarea>synthetic-password</textarea>',
      value: 'synthetic-password',
      // Playwright's public TestInfoError shape stores this as a serialized
      // string, not as a nested matcherResult object.
      errorContext: '- textbox "synthetic-user": synthetic-password'
    };
    const errors = [rootError, serializedTestInfoError];
    const sanitized = redactTestErrors(errors, [
      'synthetic-user',
      'synthetic-password'
    ]) as Array<Record<string, unknown>>;
    const sanitizedRoot = sanitized[0];
    const sanitizedCause = sanitizedRoot.cause as Record<string, unknown>;
    const sanitizedMatcherResult = sanitizedRoot.matcherResult as Record<string, unknown>;

    expect(sanitizedRoot.message).toBe(
      `expect(locator).toHaveText: ${LIVE_ARTIFACT_REDACTION}`
    );
    expect(sanitizedRoot.stack).toContain(LIVE_ARTIFACT_REDACTION);
    expect(sanitizedRoot.errorContext).toBe(
      `- textbox "${LIVE_ARTIFACT_REDACTION}": ${LIVE_ARTIFACT_REDACTION}`
    );
    expect(sanitizedMatcherResult).toEqual({
      message: `expect(locator).toHaveValue: ${LIVE_ARTIFACT_REDACTION}`,
      actual: `<input id="auth-password" value="${LIVE_ARTIFACT_REDACTION}">`,
      expected: LIVE_ARTIFACT_REDACTION,
      log: [
        `locator resolved with ${LIVE_ARTIFACT_REDACTION}`,
        `value=${LIVE_ARTIFACT_REDACTION}`
      ],
      ariaSnapshot: `- textbox "${LIVE_ARTIFACT_REDACTION}": ${LIVE_ARTIFACT_REDACTION}`
    });
    expect(sanitizedCause.message).toBe(`nested ${LIVE_ARTIFACT_REDACTION}`);
    expect(sanitizedCause.stack).toContain(LIVE_ARTIFACT_REDACTION);
    expect(sanitized[1]).toEqual({
      message: `expect(locator).toHaveText: ${LIVE_ARTIFACT_REDACTION}`,
      stack: `<textarea>${LIVE_ARTIFACT_REDACTION}</textarea>`,
      value: LIVE_ARTIFACT_REDACTION,
      errorContext: `- textbox "${LIVE_ARTIFACT_REDACTION}": ${LIVE_ARTIFACT_REDACTION}`
    });
    // The source graph is intentionally untouched; only the returned snapshot
    // is suitable for a reporter or retained TestInfo error.
    expect(rootError.message).toContain('synthetic-password');
    expect(serializedTestInfoError.value).toBe('synthetic-password');

    const unlistedQuotedValue = redactLiveText('<input value="unlisted-value">', []) as string;
    const unlistedUnquotedValue = redactLiveText('<input value=unlisted-value>', []) as string;
    const unknownValueAttribute = redactLiveText(
      '<div data-note="value=unlisted-value" value=unlisted-value>label</div>',
      []
    ) as string;
    expect(unlistedQuotedValue).toContain(LIVE_ARTIFACT_REDACTION);
    expect(unlistedUnquotedValue).toContain(LIVE_ARTIFACT_REDACTION);
    expect(unknownValueAttribute).toContain(LIVE_ARTIFACT_REDACTION);
    expect(unlistedUnquotedValue).not.toContain('unlisted-value');
    expect(unknownValueAttribute).toContain('data-note="value=unlisted-value"');
    expect(unknownValueAttribute).toContain(`value=${LIVE_ARTIFACT_REDACTION}`);
    const unlistedFormMarkup = redactLiveText(
      '<select><option>unlisted-option</option></select><div contenteditable>unlisted-editable</div>',
      []
    ) as string;
    expect(unlistedFormMarkup).toContain(LIVE_ARTIFACT_REDACTION);
    expect(unlistedFormMarkup).not.toContain('unlisted-option');
    expect(unlistedFormMarkup).not.toContain('unlisted-editable');
    expect(liveCredentialValues({})).toContain('hermternal-test');
  });

  it('rejects Playwright runner and UI debug modes before the live worker can start', () => {
    expect(() => assertLiveRunnerDebugDisabled({ PW_RUNNER_DEBUG: '1' })).toThrow(
      'PW_RUNNER_DEBUG is incompatible with the credential-redacted live lane'
    );
    expect(() => assertLiveRunnerDebugDisabled({ PWDEBUG: '1' })).toThrow(
      'PWDEBUG is incompatible with the deterministic headless live lane'
    );
    expect(() => assertLiveRunnerDebugDisabled({ PW_RUNNER_DEBUG: undefined, PWDEBUG: undefined })).not.toThrow();
  });

  it('structurally redacts textarea and select bodies and fails closed on malformed forms', () => {
    const cases = [
      '<textarea><!-- </textarea> -->unlisted-secret</textarea><div contenteditable="true">second-secret</div>',
      '<textarea>unlisted-secret<div contenteditable="true">second-secret</div>',
      '<select><!-- </select> --><option>unlisted-option</option></select><div contenteditable="true">second-secret</div>',
      '<select><option>unlisted-option<div contenteditable="true">second-secret</div>',
      '<select><option>unlisted-option</select><div contenteditable="true">second-secret</div>'
    ];

    for (const markup of cases) {
      const redacted = redactLiveText(markup, []) as string;
      expect(redacted).toContain(LIVE_ARTIFACT_REDACTION);
      expect(redacted).not.toContain('unlisted-secret');
      expect(redacted).not.toContain('unlisted-option');
      expect(redacted).not.toContain('second-secret');
    }

    const validTextarea = redactLiveText('<textarea>unlisted-secret</textarea>', []) as string;
    const validSelect = redactLiveText(
      '<select><option value=unlisted-option>unlisted-option</option></select>',
      []
    ) as string;
    expect(validTextarea).toBe(`<textarea>${LIVE_ARTIFACT_REDACTION}</textarea>`);
    expect(validSelect).toBe(`<select>${LIVE_ARTIFACT_REDACTION}</select>`);
  });

  it('redacts nested serialized contenteditable markup with matching closing tags', () => {
    const nestedMarkup =
      '<section><div id="outer" contenteditable="PLAINTEXT-ONLY"><span>synthetic-password</span><div>synthetic-user</div></div><div contenteditable="false">retained-ui-label</div></section>';
    const redacted = redactLiveText(nestedMarkup, []) as string;

    expect(redacted).toContain(
      `<div id="outer" contenteditable="PLAINTEXT-ONLY">${LIVE_ARTIFACT_REDACTION}</div>`
    );
    expect(redacted).toContain('retained-ui-label');
    expect(redacted).not.toContain('synthetic-password');
    expect(redacted).not.toContain('synthetic-user');

    const sameTagNesting =
      '<div contenteditable="true"><div>inner synthetic-password</div>outer synthetic-user</div>';
    const sameTagRedacted = redactLiveText(sameTagNesting, []) as string;
    expect(sameTagRedacted).toBe(
      `<div contenteditable="true">${LIVE_ARTIFACT_REDACTION}</div>`
    );
  });

  it('fails closed for malformed or mismatched serialized editable markup', () => {
    const missingClosing = '<div contenteditable="plaintext-only"><span>synthetic-password</span>';
    const mismatchedNestedTags =
      '<div contenteditable="true"><span>synthetic-password</div></span><p>synthetic-user</p>';

    const missingClosingRedacted = redactLiveText(missingClosing, []) as string;
    const mismatchedRedacted = redactLiveText(mismatchedNestedTags, []) as string;

    expect(missingClosingRedacted).toContain(LIVE_ARTIFACT_REDACTION);
    expect(missingClosingRedacted).not.toContain('synthetic-password');
    expect(mismatchedRedacted).toContain(LIVE_ARTIFACT_REDACTION);
    expect(mismatchedRedacted).not.toContain('synthetic-password');
    expect(mismatchedRedacted).not.toContain('synthetic-user');
  });

  it('fails closed when malformed text precedes later editable markup, including encoded secrets', () => {
    const cases = [
      'text < 5 <div contenteditable="true">synthetic-password</div>',
      'text < 5 <div contenteditable="future-mode">unknown-credential</div>',
      'text < 5 <div contenteditable="true">synthetic&#45;password</div>',
      'text < 5 <div contenteditable="future-mode">unknown&#x2d;credential</div>'
    ];

    for (const markup of cases) {
      const redacted = redactLiveText(markup, []) as string;
      expect(redacted).toContain(LIVE_ARTIFACT_REDACTION);
      expect(redacted).not.toContain('synthetic-password');
      expect(redacted).not.toContain('synthetic&#45;password');
      expect(redacted).not.toContain('unknown-credential');
      expect(redacted).not.toContain('unknown&#x2d;credential');
    }

    const unknownMode = redactLiveText(
      '<div contenteditable="future-mode">unknown-credential</div>',
      []
    ) as string;
    expect(unknownMode).toContain(LIVE_ARTIFACT_REDACTION);
    expect(unknownMode).not.toContain('unknown-credential');

    const dataNoteProbe = redactLiveText(
      '<div data-note="contenteditable=false" contenteditable="true">synthetic-password</div>',
      []
    ) as string;
    expect(dataNoteProbe).toContain(
      `<div data-note="contenteditable=false" contenteditable="true">${LIVE_ARTIFACT_REDACTION}</div>`
    );
    expect(dataNoteProbe).not.toContain('synthetic-password');

    const duplicateAttributeProbe = redactLiveText(
      '<div contenteditable="false" contenteditable="true">synthetic-password</div>',
      []
    ) as string;
    expect(duplicateAttributeProbe).toContain(LIVE_ARTIFACT_REDACTION);
    expect(duplicateAttributeProbe).not.toContain('synthetic-password');
  });

  it('fails closed for unterminated comments before or inside editable markup', () => {
    const insideEditable =
      '<div contenteditable="plaintext-only"><!-- <span>synthetic-password</span>';
    const afterEditable =
      '<div contenteditable="true">safe-ui</div><!-- synthetic-user';
    const topLevel = '<!-- <div contenteditable="true">synthetic-password';
    const malformedComment =
      '<div contenteditable="true"><!-- synthetic-password --';

    for (const markup of [insideEditable, afterEditable, topLevel, malformedComment]) {
      const redacted = redactLiveText(markup, []) as string;
      expect(redacted).toContain(LIVE_ARTIFACT_REDACTION);
      expect(redacted).not.toContain('synthetic-password');
      expect(redacted).not.toContain('synthetic-user');
    }
  });

  it('fails closed for unreadable diagnostics and never relies on source writes', () => {
    const falseSetterTarget = { message: 'synthetic-password' };
    const falseSetter = new Proxy(falseSetterTarget, { set: () => false });
    const silentSetterTarget = { message: 'synthetic-password' };
    const silentSetter = new Proxy(silentSetterTarget, { set: () => true });
    const falseSnapshot = redactTestErrors([falseSetter], ['synthetic-password']);
    const silentSnapshot = redactTestErrors([silentSetter], ['synthetic-password']);

    expect(JSON.stringify(falseSnapshot)).not.toContain('synthetic-password');
    expect(JSON.stringify(silentSnapshot)).not.toContain('synthetic-password');
    expect(falseSetterTarget.message).toBe('synthetic-password');
    expect(silentSetterTarget.message).toBe('synthetic-password');

    const throwingGetter = {};
    Object.defineProperty(throwingGetter, 'message', {
      configurable: true,
      enumerable: true,
      get: () => {
        throw new Error('diagnostic getter failed');
      },
      set: () => undefined
    });
    const throwingDescriptor = new Proxy(
      { message: 'synthetic-password' },
      {
        getOwnPropertyDescriptor: () => {
          throw new Error('diagnostic descriptor failed');
        }
      }
    );

    expect(() => redactTestErrors([throwingGetter], ['synthetic-password'])).toThrow(
      'redaction failed'
    );
    expect(() => redactTestErrors([throwingDescriptor], ['synthetic-password'])).toThrow(
      'redaction failed'
    );
  });

  it('checks descriptor read-back and fails closed for spoofed or incomplete descriptors', () => {
    const spoofedDataTarget = { message: LIVE_ARTIFACT_REDACTION };
    const spoofedData = new Proxy(spoofedDataTarget, {
      get: (target, key, receiver) =>
        key === 'message' ? 'synthetic-password' : Reflect.get(target, key, receiver),
      getOwnPropertyDescriptor: () => ({
        value: LIVE_ARTIFACT_REDACTION,
        writable: true,
        enumerable: true,
        configurable: true
      })
    });
    const spoofedDataSnapshot = redactTestErrors([spoofedData], [
      'synthetic-password'
    ]) as Array<Record<string, unknown>>;
    expect(spoofedDataSnapshot[0].message).toBe(LIVE_ARTIFACT_REDACTION);
    expect(JSON.stringify(spoofedDataSnapshot)).not.toContain('synthetic-password');

    const incompleteDataTarget = { message: LIVE_ARTIFACT_REDACTION };
    const incompleteData = new Proxy(incompleteDataTarget, {
      getOwnPropertyDescriptor: () => ({ value: LIVE_ARTIFACT_REDACTION })
    });
    expect(() => redactTestErrors([incompleteData], ['synthetic-password'])).toThrow(
      'redaction failed'
    );

    let accessorValue = 'synthetic-password';
    const accessorTarget = {};
    const accessorGetter = () => accessorValue;
    const accessorSetter = (value: string) => {
      accessorValue = value;
    };
    Object.defineProperty(accessorTarget, 'message', {
      configurable: true,
      enumerable: true,
      get: accessorGetter,
      set: accessorSetter
    });
    const spoofedAccessor = new Proxy(accessorTarget, {
      get: (target, key, receiver) =>
        key === 'message' ? LIVE_ARTIFACT_REDACTION : Reflect.get(target, key, receiver),
      getOwnPropertyDescriptor: () => ({
        configurable: true,
        enumerable: true,
        get: accessorGetter,
        set: accessorSetter
      })
    });
    const spoofedAccessorSnapshot = redactTestErrors([spoofedAccessor], [
      'synthetic-password'
    ]) as Array<Record<string, unknown>>;
    expect(spoofedAccessorSnapshot[0].message).toBe(LIVE_ARTIFACT_REDACTION);
    expect(accessorValue).toBe('synthetic-password');

    let ordinaryAccessorValue = 'synthetic-password';
    const ordinaryAccessor = {};
    Object.defineProperty(ordinaryAccessor, 'message', {
      configurable: true,
      enumerable: true,
      get: () => ordinaryAccessorValue,
      set: (value: string) => {
        ordinaryAccessorValue = value;
      }
    });
    const ordinarySnapshot = redactTestErrors([ordinaryAccessor], [
      'synthetic-password'
    ]) as Array<Record<string, unknown>>;
    expect(ordinarySnapshot[0].message).toBe(LIVE_ARTIFACT_REDACTION);
    expect(ordinaryAccessorValue).toBe('synthetic-password');

    const incompleteAccessorTarget = {};
    Object.defineProperty(incompleteAccessorTarget, 'message', {
      configurable: true,
      enumerable: true,
      get: () => LIVE_ARTIFACT_REDACTION,
      set: () => undefined
    });
    const incompleteAccessor = new Proxy(incompleteAccessorTarget, {
      getOwnPropertyDescriptor: () => ({ get: () => LIVE_ARTIFACT_REDACTION })
    });
    expect(() => redactTestErrors([incompleteAccessor], ['synthetic-password'])).toThrow(
      'redaction failed'
    );
  });

  it('detaches stateful Proxy diagnostics and suppresses unsafe toJSON hooks', () => {
    let reads = 0;
    const alternating = new Proxy(
      { message: 'synthetic-password' },
      {
        get: (target, key, receiver) => {
          if (key === 'message') {
            reads += 1;
            return reads % 2 === 0
              ? 'synthetic-password'
              : LIVE_ARTIFACT_REDACTION;
          }
          return Reflect.get(target, key, receiver);
        }
      }
    );

    const sanitized = redactTestErrors([alternating], [
      'synthetic-password'
    ]);
    const serialized = JSON.stringify(sanitized);
    expect(serialized).not.toContain('synthetic-password');
    expect(serialized).toContain(LIVE_ARTIFACT_REDACTION);

    const diagnostic = { message: 'safe' };
    Object.defineProperty(diagnostic, 'toJSON', {
      enumerable: true,
      value: () => ({ leaked: 'synthetic-password' })
    });
    const sanitizedWithToJson = redactTestErrors([diagnostic], [
      'synthetic-password'
    ]);
    expect(JSON.stringify(sanitizedWithToJson)).not.toContain('synthetic-password');

    const arrayToJson = Object.getOwnPropertyDescriptor(Array.prototype, 'toJSON');
    const objectToJson = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    try {
      Object.defineProperty(Array.prototype, 'toJSON', {
        configurable: true,
        enumerable: false,
        value: () => ({ leaked: 'synthetic-password' }),
        writable: true
      });
      Object.defineProperty(Object.prototype, 'toJSON', {
        configurable: true,
        enumerable: false,
        value: () => ({ leaked: 'synthetic-password' }),
        writable: true
      });

      const poisonedSnapshot = redactTestErrors(
        [{ nested: ['synthetic-password'] }],
        ['synthetic-password']
      );
      expect(JSON.stringify(poisonedSnapshot)).not.toContain('synthetic-password');
      const safeEntry = redactTestErrors([{ message: 'safe' }], [
        'synthetic-password'
      ])[0];
      poisonedSnapshot.push(safeEntry);
      const mappedSnapshot = poisonedSnapshot.map((entry) => entry);
      expect(mappedSnapshot).toHaveLength(2);
      expect(JSON.stringify(mappedSnapshot)).not.toContain('synthetic-password');
      expect(JSON.stringify(poisonedSnapshot)).not.toContain('synthetic-password');
    } finally {
      if (arrayToJson) Object.defineProperty(Array.prototype, 'toJSON', arrayToJson);
      else delete (Array.prototype as { toJSON?: unknown }).toJSON;
      if (objectToJson) Object.defineProperty(Object.prototype, 'toJSON', objectToJson);
      else delete (Object.prototype as { toJSON?: unknown }).toJSON;
    }
  });

  it('scrubs every valid editable content mode before page teardown', async () => {
    document.body.innerHTML = `
      <form>
        <input id="auth-username" value="synthetic-user">
        <input id="auth-password" value="synthetic-password">
        <textarea>synthetic-password</textarea>
        <select><option selected>synthetic-user</option></select>
        <div id="true-editable" contenteditable="true">synthetic-password</div>
        <div id="empty-editable" contenteditable="">synthetic-user</div>
        <div id="plaintext-editable" contenteditable="plaintext-only">synthetic-password</div>
        <div id="uppercase-plaintext-editable" contenteditable="PLAINTEXT-ONLY">synthetic-user</div>
        <div id="not-editable" contenteditable="false">retained-ui-label</div>
      </form>
    `;

    await scrubLivePage({ evaluate: async (callback) => callback() });

    expect(document.querySelector<HTMLInputElement>('#auth-username')?.value).toBe('');
    expect(document.querySelector<HTMLInputElement>('#auth-password')?.value).toBe('');
    expect(document.querySelector('textarea')?.textContent).toBe('');
    expect(document.querySelector('select')?.selectedIndex).toBe(-1);
    expect(document.querySelector('select')?.textContent).toBe('');
    expect(document.querySelector('#true-editable')?.textContent).toBe('');
    expect(document.querySelector('#empty-editable')?.textContent).toBe('');
    expect(document.querySelector('#plaintext-editable')?.textContent).toBe('');
    expect(document.querySelector('#uppercase-plaintext-editable')?.textContent).toBe('');
    expect(document.querySelector('#not-editable')?.textContent).toBe('retained-ui-label');
    expect(document.documentElement.outerHTML).not.toContain('synthetic-user');
    expect(document.documentElement.outerHTML).not.toContain('synthetic-password');
  });

  it('fails live scrub errors closed only when page termination is observed', async () => {
    const liveFailure = new Error('evaluate failed for synthetic-password');

    await expect(
      scrubLivePage({
        isClosed: () => false,
        evaluate: async () => {
          throw liveFailure;
        }
      })
    ).rejects.toBe(liveFailure);

    await expect(
      scrubLivePage({
        isClosed: () => true,
        evaluate: async () => {
          throw new Error('unrelated evaluator failure');
        }
      })
    ).resolves.toBeUndefined();

    await expect(
      scrubLivePage({
        isClosed: () => false,
        evaluate: async () => {
          throw new Error('page.evaluate: Page crashed');
        }
      })
    ).rejects.toThrow('Page crashed');

    await expect(
      scrubLivePage({
        evaluate: async () => {
          throw new Error('missing termination proof');
        }
      })
    ).rejects.toThrow('missing termination proof');

    await expect(
      scrubLivePage({
        isClosed: () => {
          throw new Error('state unavailable');
        },
        evaluate: async () => {
          throw new Error('state could not be read');
        }
      })
    ).rejects.toThrow('state could not be read');
  });

  it('handles cycles and rejects bounded traversal overflow', () => {
    const cyclic: Record<string, unknown> = { message: 'synthetic-password' };
    cyclic.self = cyclic;
    const sanitized = redactTestErrors([cyclic], [
      'synthetic-password'
    ]) as Array<Record<string, unknown>>;
    expect(sanitized[0].message).toBe(LIVE_ARTIFACT_REDACTION);
    expect(sanitized[0].self).toBe(LIVE_ARTIFACT_REDACTION);
    expect(JSON.stringify(sanitized)).not.toContain('synthetic-password');
    expect(cyclic.message).toBe('synthetic-password');
    expect(cyclic.self).toBe(cyclic);

    let deep: Record<string, unknown> = { value: 'synthetic-password' };
    for (let index = 0; index < 20; index += 1) deep = { next: deep };
    expect(() => redactTestErrors([deep], ['synthetic-password'])).toThrow('budget');

    const wide = Array.from({ length: 513 }, () => 'synthetic-password');
    expect(() => redactTestErrors([wide], ['synthetic-password'])).toThrow('budget');
    expect(() => redactLiveText('x'.repeat(256 * 1024 + 1), [])).toThrow('budget');
  });

  it('replaces retained errors with trusted snapshots before cleanup', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    const testOutput = join(outputRoot, 'replaces-retained-errors');
    await mkdir(testOutput, { recursive: true });
    await writeFile(join(testOutput, 'error-context.md'), 'synthetic-password', 'utf8');

    const sourceDiagnostic = { message: 'synthetic-password' };
    const testInfo = {
      attachments: [{ name: 'live-error', path: join(testOutput, 'error-context.md') }],
      errors: [sourceDiagnostic],
      outputDir: testOutput
    };

    const sourceScrubError = new Error('scrub failed synthetic-password');
    let thrown: unknown;
    try {
      await finalizeLiveTest({
        testInfo,
        scrubError: sourceScrubError,
        secrets: ['synthetic-password']
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeDefined();
    expect(thrown).not.toBe(sourceScrubError);
    expect((thrown as Record<string, unknown>).message).toBe(
      `scrub failed ${LIVE_ARTIFACT_REDACTION}`
    );
    expect(JSON.stringify(thrown)).not.toContain('synthetic-password');
    expect(testInfo.attachments).toHaveLength(0);
    expect(testInfo.errors).toHaveLength(1);
    expect((testInfo.errors[0] as { message: string }).message).toBe(
      LIVE_ARTIFACT_REDACTION
    );
    expect(JSON.stringify(testInfo.errors)).not.toContain('synthetic-password');
    const safeExtra = redactTestErrors([{ message: 'safe' }], [
      'synthetic-password'
    ])[0] as { message: string };
    testInfo.errors.push(safeExtra);
    expect(testInfo.errors.map((entry) => entry)).toHaveLength(2);
    expect(JSON.stringify(testInfo.errors)).not.toContain('synthetic-password');
    expect(sourceDiagnostic.message).toBe('synthetic-password');
    expect(await exists(testOutput)).toBe(false);
    expect(await exists(outputRoot)).toBe(true);
  });

  it('protects Playwright worker-mapped IPC errors from inherited serializers', async () => {
    const objectToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    const arrayToJSON = Object.getOwnPropertyDescriptor(Array.prototype, 'toJSON');
    const outputRoot = liveArtifactOutputDirectory();
    const leak = () => ({ leaked: 'synthetic-password' });
    const mapToTestInfoErrorPayload = (error: Record<string, unknown>): Record<string, unknown> => {
      const payload: Record<string, unknown> = {};
      for (const key of ['message', 'stack', 'value']) {
        if (error[key] !== undefined) payload[key] = error[key];
      }
      if (error.cause !== undefined && error.cause !== null) {
        payload.cause = mapToTestInfoErrorPayload(error.cause as Record<string, unknown>);
      }
      return payload;
    };

    Object.defineProperty(Object.prototype, 'toJSON', {
      configurable: true,
      enumerable: false,
      value: leak,
      writable: true
    });
    Object.defineProperty(Array.prototype, 'toJSON', {
      configurable: true,
      enumerable: false,
      value: leak,
      writable: true
    });

    try {
      await mkdir(outputRoot, { recursive: true });
      const testInfo: {
        attachments: unknown[];
        errors: Array<Record<string, unknown>>;
        outputDir: string;
      } = {
        attachments: [],
        errors: [{ message: 'synthetic-password', stack: 'Error: synthetic-password' }],
        outputDir: outputRoot
      };
      const vulnerableMapping = testInfo.errors.map((error) => ({ message: error.message }));
      expect(JSON.stringify(vulnerableMapping)).toContain('synthetic-password');

      await finalizeLiveTest({ testInfo, secrets: ['synthetic-password'] });

      // This mirrors Playwright's worker-side
      // `testInfo.errors.map(toTestInfoErrorPayload)` followed by IPC
      // serialization. The mapped objects are ordinary `{}` payloads, so the
      // source array's safe own `toJSON` alone would not protect this boundary.
      const mappedErrors = testInfo.errors.map((error) =>
        mapToTestInfoErrorPayload(error as Record<string, unknown>)
      );
      expect(JSON.stringify(mappedErrors)).toContain('synthetic-password');
      const safeTransportMessage = redactLiveTransportMessage(
        { errors: mappedErrors },
        ['synthetic-password']
      ) as { errors: Array<Record<string, unknown>> };
      expect(JSON.stringify(safeTransportMessage)).not.toContain('synthetic-password');
      expect(safeTransportMessage.errors).toHaveLength(1);
      expect(safeTransportMessage.errors[0].message).toBe(LIVE_ARTIFACT_REDACTION);

      // The real worker keeps using the array after afterEach: push, map, and
      // iteration must remain ordinary Playwright-compatible operations.
      testInfo.errors.push({ message: LIVE_ARTIFACT_REDACTION });
      expect([...testInfo.errors]).toHaveLength(2);
      const postCleanupMapping = testInfo.errors.map((error) => ({ message: error.message }));
      expect(JSON.stringify(postCleanupMapping)).toContain('synthetic-password');
      expect(
        JSON.stringify(redactLiveTransportMessage(postCleanupMapping, ['synthetic-password']))
      ).not.toContain('synthetic-password');
    } finally {
      if (objectToJSON) Object.defineProperty(Object.prototype, 'toJSON', objectToJSON);
      else delete (Object.prototype as { toJSON?: unknown }).toJSON;
      if (arrayToJSON) Object.defineProperty(Array.prototype, 'toJSON', arrayToJSON);
      else delete (Array.prototype as { toJSON?: unknown }).toJSON;
      await rm(outputRoot, { recursive: true, force: true });
    }
  });

  it('redacts Playwright binary stdio and attachment transport fields', () => {
    const secretBytes = Buffer.from('synthetic-password', 'utf8').toString('base64');
    const safeBytes = Buffer.from('safe-binary', 'utf8').toString('base64');
    const safeStdout = redactLiveTransportMessage(
      { method: '__dispatch__', params: { method: 'stdOut', params: { buffer: safeBytes } } },
      ['synthetic-password']
    ) as { params: { params: { buffer: string } } };
    const redactedStdout = redactLiveTransportMessage(
      { method: '__dispatch__', params: { method: 'stdErr', params: { buffer: secretBytes } } },
      ['synthetic-password']
    ) as { params: { params: { buffer: string } } };
    const redactedAttachment = redactLiveTransportMessage(
      { method: '__dispatch__', params: { method: 'attach', params: { body: secretBytes } } },
      ['synthetic-password']
    ) as { params: { params: { body: string } } };

    expect(safeStdout.params.params.buffer).toBe(safeBytes);
    expect(redactedStdout.params.params.buffer).toBe(
      Buffer.from(LIVE_ARTIFACT_REDACTION, 'utf8').toString('base64')
    );
    expect(redactedAttachment.params.params.body).toBe(
      Buffer.from(LIVE_ARTIFACT_REDACTION, 'utf8').toString('base64')
    );

    // Exercise KMP fallback after a partial prefix mismatch before a later match.
    const repeatedPrefixSecret = 'abab';
    const repeatedPrefixBytes = Buffer.from('abacabab', 'utf8').toString('base64');
    const redactedRepeatedPrefix = redactLiveTransportMessage(
      {
        method: '__dispatch__',
        params: { method: 'stdOut', params: { buffer: repeatedPrefixBytes } }
      },
      [repeatedPrefixSecret]
    ) as { params: { params: { buffer: string } } };
    expect(redactedRepeatedPrefix.params.params.buffer).toBe(
      Buffer.from(LIVE_ARTIFACT_REDACTION, 'utf8').toString('base64')
    );

    expect(() =>
      redactLiveTransportMessage(
        { method: '__dispatch__', params: { method: 'stdOut', params: { buffer: 'not-base64!' } } },
        ['synthetic-password']
      )
    ).toThrow();
    expect(() =>
      redactLiveTransportMessage(
        {
          method: '__dispatch__',
          params: { method: 'stdOut', params: { buffer: 'A'.repeat(256 * 1024 + 4) } }
        },
        ['synthetic-password']
      )
    ).toThrow();
  });

  it('protects frozen read-only TestInfo errors at the actual Playwright IPC boundary', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { finalizeLiveTest } from '__POLICY_URL__';
const secret = 'synthetic-password';
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo, secrets: [secret] });
});
test('frozen read-only errors', async ({}, testInfo) => {
  test.fail();
  const sourceErrors = Object.freeze([{ message: secret, stack: 'Error: ' + secret }]);
  Object.defineProperty(testInfo, 'errors', {
    configurable: true,
    enumerable: true,
    get: () => sourceErrors,
    set: () => {
      throw new Error('errors are read-only');
    }
  });
});
`);
    expect(result.code).toBe(0);
    expect(result.stdout + result.stderr).not.toContain('synthetic-password');
    expect(result.stdout).toContain(LIVE_ARTIFACT_REDACTION);
  }, 30_000);

  it('protects non-configurable hostile Object and Array serializers in a worker', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { finalizeLiveTest } from '__POLICY_URL__';
const secret = 'synthetic-password';
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo, secrets: [secret] });
});
test('non-configurable hostile serializers', async () => {
  test.fail();
  Object.defineProperty(Object.prototype, 'toJSON', {
    configurable: false,
    enumerable: false,
    value: () => ({ leaked: secret }),
    writable: false
  });
  Object.defineProperty(Array.prototype, 'toJSON', {
    configurable: false,
    enumerable: false,
    value: () => ({ leaked: secret }),
    writable: false
  });
  await test.step('credential-bearing step', async () => {
    throw new Error(secret);
  });
});
`);
    expect(result.code).toBe(0);
    expect(result.stdout + result.stderr).not.toContain('synthetic-password');
    expect(result.stdout).toContain(LIVE_ARTIFACT_REDACTION);
  }, 30_000);

  it('protects IPC when Object.create is replaced before a failed step', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { finalizeLiveTest } from '__POLICY_URL__';
const secret = 'synthetic-password';
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo, secrets: [secret] });
});
test('mutated Object.create', async () => {
  test.fail();
  const originalCreate = Object.create;
  // Delegate ordinary allocations so Playwright's worker lifecycle remains
  // intact; poison only the null-prototype snapshot allocation used by the
  // vulnerable redaction path.
  Object.create = (prototype, properties) => {
    const created = originalCreate(prototype, properties);
    if (prototype === null && new Error().stack?.includes('createSnapshotContainer')) {
      Object.defineProperty(created, 'toJSON', {
        configurable: true,
        enumerable: false,
        value: () => ({ leaked: secret }),
        writable: true
      });
    }
    return created;
  };
  await test.step('credential-bearing step', async () => {
    throw new Error(secret);
  });
});
`);
    const output = result.stdout + result.stderr;
    expect(result.code).toBe(0);
    expect(output).not.toContain('synthetic-password');
    expect(result.stdout).toContain(LIVE_ARTIFACT_REDACTION);
  }, 30_000);

  it('protects step-end IPC emitted before afterEach runs', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { finalizeLiveTest } from '__POLICY_URL__';
const secret = 'synthetic-password';
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo, secrets: [secret] });
});
test('step IPC before cleanup', async () => {
  test.fail();
  await test.step('credential-bearing step', async () => {
    throw new Error(secret);
  });
});
`);
    expect(result.code).toBe(0);
    expect(result.stdout + result.stderr).not.toContain('synthetic-password');
    expect(result.stdout).toContain(LIVE_ARTIFACT_REDACTION);
  }, 30_000);

  it('captures immutable credential values before worker test code can delete them', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { finalizeLiveTest } from '__POLICY_URL__';
const secret = 'synthetic-password';
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo });
});
test('preload credential capture', async () => {
  test.fail();
  delete process.env.HERMES_TEST_PASSWORD;
  await test.step('credential-bearing step', async () => {
    throw new Error(secret);
  });
});
`);
    expect(result.code).toBe(0);
    expect(result.stdout + result.stderr).not.toContain('synthetic-password');
    expect(result.stdout).toContain(LIVE_ARTIFACT_REDACTION);
  }, 30_000);

  it('redacts binary worker stdio and attachment bodies while preserving safe bytes', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { finalizeLiveTest } from '__POLICY_URL__';
const secret = 'synthetic-password';
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo, secrets: [secret] });
});
test('binary transport diagnostics', async ({}, testInfo) => {
  process.stdout.write(Buffer.from(secret, 'utf8'));
  process.stdout.write(Buffer.from('safe-stdout', 'utf8'));
  process.stderr.write(Buffer.from(secret, 'utf8'));
  process.stderr.write(Buffer.from('safe-stderr', 'utf8'));
  await testInfo.attach('binary-secret', {
    body: Buffer.from(secret, 'utf8'),
    contentType: 'application/octet-stream'
  });
  await testInfo.attach('binary-safe', {
    body: Buffer.from('safe-attachment', 'utf8'),
    contentType: 'application/octet-stream'
  });
});
`);
    const output = result.stdout + result.stderr;
    expect(result.code).toBe(0);
    expect(output).not.toContain('synthetic-password');
    expect(output).toContain(LIVE_ARTIFACT_REDACTION);
    expect(output).toContain('safe-stdout');
    expect(output).toContain('safe-stderr');
    expect(output).toContain('safe-attachment');
    expect(result.stdout).toContain('END:passed');
  }, 30_000);

  it('redacts every stdout and stderr credential split boundary in the real worker', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { finalizeLiveTest } from '__POLICY_URL__';
const secret = 'synthetic-password';
const bytes = Buffer.from(secret, 'utf8');
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo, secrets: [secret] });
});
test('binary split boundaries', async () => {
  for (let boundary = 1; boundary < bytes.length; boundary += 1) {
    process.stdout.write(bytes.subarray(0, boundary));
    await new Promise((resolve) => setImmediate(resolve));
    process.stdout.write(bytes.subarray(boundary));
    await new Promise((resolve) => setImmediate(resolve));
    process.stderr.write(bytes.subarray(0, boundary));
    await new Promise((resolve) => setImmediate(resolve));
    process.stderr.write(bytes.subarray(boundary));
    await new Promise((resolve) => setImmediate(resolve));
  }
  process.stdout.write(Buffer.from('safe-split-stdout', 'utf8'));
  process.stderr.write(Buffer.from('safe-split-stderr', 'utf8'));
});
`);
    const output = result.stdout + result.stderr;
    expect(result.code).toBe(0);
    expect(output).not.toContain('synthetic-password');
    expect(output).toContain(LIVE_ARTIFACT_REDACTION);
    expect(output).toContain('safe-split-stdout');
    expect(output).toContain('safe-split-stderr');
    expect(result.stdout).toContain('END:passed');
  }, 30_000);

  it('rejects PW_RUNNER_DEBUG before a live worker can start', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
const secret = 'synthetic-password';
test('debug mode must be rejected', async () => {
  throw new Error(secret);
});
`, { runnerDebug: '1' });
    const output = result.stdout + result.stderr;
    expect(result.code).not.toBe(0);
    expect(output).not.toContain('synthetic-password');
    expect(output).toContain('PW_RUNNER_DEBUG is incompatible with the credential-redacted live lane');
    expect(output).not.toContain('TEST:');
  }, 30_000);

  it('runs attachment and output cleanup before propagating a redaction failure', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    const testOutput = join(outputRoot, 'redaction-failure');
    await mkdir(testOutput, { recursive: true });
    await writeFile(join(testOutput, 'error-context.md'), 'synthetic-password', 'utf8');

    const throwingDiagnostic = {};
    Object.defineProperty(throwingDiagnostic, 'message', {
      configurable: true,
      enumerable: true,
      get: () => {
        throw new Error('diagnostic getter failed');
      },
      set: () => undefined
    });
    const testInfo = {
      attachments: [{ name: 'live-error', path: join(testOutput, 'error-context.md') }],
      errors: [throwingDiagnostic],
      outputDir: testOutput
    };

    await expect(
      finalizeLiveTest({ testInfo, secrets: ['synthetic-password'] })
    ).rejects.toThrow('redaction failed');
    expect(testInfo.attachments).toHaveLength(0);
    expect(testInfo.errors).toEqual([LIVE_ARTIFACT_REDACTION]);
    expect(JSON.stringify(testInfo.errors)).not.toContain('synthetic-password');
    expect(await exists(testOutput)).toBe(false);
    expect(await exists(outputRoot)).toBe(true);
  });

  it('aggregates redaction and attachment cleanup failures without exposing raw errors', async () => {
    const attachmentTarget = [{ name: 'hostile' }];
    const attachments = new Proxy(attachmentTarget, {
      set(target, property, value) {
        if (property === 'length') throw new Error('hostile attachment setter');
        return Reflect.set(target, property, value);
      }
    });
    const throwingDiagnostic = {};
    Object.defineProperty(throwingDiagnostic, 'message', {
      configurable: true,
      enumerable: true,
      get: () => {
        throw new Error('raw diagnostic getter leaked');
      }
    });
    const testInfo = {
      attachments,
      errors: [throwingDiagnostic],
      outputDir: join(tmpdir(), 'hermternal-unowned-finalization-output')
    };

    let failure: unknown;
    try {
      await finalizeLiveTest({ testInfo, secrets: ['synthetic-password'] });
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(AggregateError);
    expect((failure as AggregateError).message).toBe('live test finalization failed');
    expect(JSON.stringify((failure as AggregateError).errors)).not.toContain('raw diagnostic getter leaked');
    expect(attachments).toHaveLength(1);
  });

  it('uses preloaded aggregate and array intrinsics when globals are poisoned', async () => {
    const policyUrl = pathToFileURL(policyPath).href;
    const probe = `
      const policy = await import(${JSON.stringify(policyUrl)});
      const root = policy.liveArtifactOutputDirectory();
      const attachments = new Proxy([{ name: 'hostile' }], {
        set(target, property, value) {
          if (property === 'length') throw new Error('hostile attachment setter');
          return Reflect.set(target, property, value);
        }
      });
      const originalPush = Array.prototype.push;
      const originalAggregateError = globalThis.AggregateError;
      Array.prototype.push = () => { throw new Error('poisoned Array.push'); };
      Object.defineProperty(globalThis, 'AggregateError', {
        configurable: true,
        writable: true,
        value: function PoisonedAggregateError() {
          throw new Error('poisoned AggregateError');
        }
      });
      let failure;
      try {
        await policy.finalizeLiveTest({
          testInfo: {
            attachments,
            errors: [],
            outputDir: '/private/tmp/hermternal-unowned-poisoned-output'
          },
          scrubError: new Error('safe scrub failure')
        });
      } catch (error) {
        failure = error;
      } finally {
        Array.prototype.push = originalPush;
        Object.defineProperty(globalThis, 'AggregateError', {
          configurable: true,
          writable: true,
          value: originalAggregateError
        });
      }
      if (!failure || failure.message !== 'live test finalization failed')
        throw new Error('captured finalization intrinsics were not used');
      await policy.removeLiveArtifacts(root);
      process.stdout.write('POISON_INTRINSICS_OK');
    `;
    const result = await execFileAsync(process.execPath, ['-e', probe], {
      cwd: appRoot,
      env: { ...process.env, HERMES_TEST_PASSWORD: undefined },
      maxBuffer: 2 * 1024 * 1024,
      encoding: 'utf8'
    });
    expect(result.stdout).toContain('POISON_INTRINSICS_OK');
  }, 30_000);

  it('binds cleanup to the owned inode across an initial replacement race', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    const ownedArtifact = join(outputRoot, 'owned-only.txt');
    const replacementArtifact = join(outputRoot, 'replacement.txt');
    await mkdir(outputRoot, { recursive: true });
    await writeFile(ownedArtifact, 'synthetic-password', 'utf8');

    const originalRename = fsPromises.rename;
    let swapped = false;
    fsPromises.rename = async (source, target) => {
      const result = await originalRename(source, target);
      if (!swapped && String(source) === outputRoot) {
        swapped = true;
        await mkdir(outputRoot, { recursive: true });
        await writeFile(replacementArtifact, 'replacement-survives', 'utf8');
      }
      return result;
    };

    try {
      await removeLiveArtifacts(outputRoot);
    } finally {
      fsPromises.rename = originalRename;
    }

    expect(swapped).toBe(true);
    expect(await exists(replacementArtifact)).toBe(true);
    expect(await exists(ownedArtifact)).toBe(false);
    await rm(outputRoot, { recursive: true, force: true });
  });

  it('preserves a final tombstone replacement and never calls recursive rm', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    const ownedArtifact = join(outputRoot, 'owned-only.txt');
    let finalTombstone = '';
    let replacementRoot = '';
    let originalBackup = '';
    let quarantineParentTombstone = '';
    let replaced = false;
    let recursiveRmCalled = false;
    await mkdir(outputRoot, { recursive: true });
    await writeFile(ownedArtifact, 'owned-content', 'utf8');

    const originalRename = fsPromises.rename;
    const originalRmdir = fsPromises.rmdir;
    const originalRm = fsPromises.rm;
    fsPromises.rm = async (...args) => {
      recursiveRmCalled = true;
      return originalRm(...args);
    };
    fsPromises.rename = async (source, target) => {
      const result = await originalRename(source, target);
      if (String(target).includes('-parent-delete-')) quarantineParentTombstone = String(target);
      return result;
    };
    fsPromises.rmdir = async (target) => {
      const targetPath = String(target);
      if (!replaced && targetPath.includes('-owned-')) {
        replaced = true;
        finalTombstone = targetPath;
        originalBackup = `${targetPath}-owned-backup`;
        await originalRename(targetPath, originalBackup);
        replacementRoot = targetPath;
        await mkdir(replacementRoot, { recursive: true });
        await writeFile(join(replacementRoot, 'replacement.txt'), 'replacement-survives', 'utf8');
      }
      return originalRmdir(target);
    };

    try {
      await expect(removeLiveArtifacts(outputRoot)).rejects.toThrow('quarantine remnant');
    } finally {
      fsPromises.rename = originalRename;
      fsPromises.rmdir = originalRmdir;
      fsPromises.rm = originalRm;
    }

    expect(replaced).toBe(true);
    expect(finalTombstone).not.toBe('');
    expect(quarantineParentTombstone).not.toBe('');
    expect(await exists(join(quarantineParentTombstone, basename(replacementRoot), 'replacement.txt'))).toBe(true);
    expect(await exists(join(quarantineParentTombstone, basename(originalBackup)))).toBe(true);
    expect(await exists(outputRoot)).toBe(false);
    expect(recursiveRmCalled).toBe(false);

    await rm(quarantineParentTombstone, { recursive: true, force: true });
  });

  it('cleans an empty quarantine parent after verification fails closed', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    let quarantinePath = '';
    let removedByRace = false;
    await mkdir(outputRoot, { recursive: true });
    await writeFile(join(outputRoot, 'owned-only.txt'), 'owned-content', 'utf8');

    const originalRename = fsPromises.rename;
    const originalRm = fsPromises.rm;
    fsPromises.rename = async (source, target) => {
      const result = await originalRename(source, target);
      if (String(source) === outputRoot && !removedByRace) {
        removedByRace = true;
        quarantinePath = String(target);
        await originalRm(target, { recursive: true, force: true });
      }
      return result;
    };

    try {
      await expect(removeLiveArtifacts(outputRoot)).rejects.toThrow('identity changed');
    } finally {
      fsPromises.rename = originalRename;
    }

    expect(removedByRace).toBe(true);
    expect(quarantinePath).not.toBe('');
    expect(await exists(quarantinePath)).toBe(false);
    expect(await exists(resolve(quarantinePath, '..'))).toBe(false);
  });

  it('preserves a tampered quarantine-parent tombstone instead of removing its replacement', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    let parentTombstone = '';
    let originalParent = '';
    await mkdir(outputRoot, { recursive: true });
    await writeFile(join(outputRoot, 'owned-only.txt'), 'owned-content', 'utf8');

    const originalRename = fsPromises.rename;
    fsPromises.rename = async (source, target) => {
      const result = await originalRename(source, target);
      if (String(target).includes('-parent-delete-')) {
        parentTombstone = String(target);
        originalParent = `${parentTombstone}-original`;
        await originalRename(parentTombstone, originalParent);
        await mkdir(parentTombstone);
        await writeFile(join(parentTombstone, 'replacement-survives.txt'), 'keep me', 'utf8');
      }
      return result;
    };

    try {
      await expect(removeLiveArtifacts(outputRoot)).rejects.toThrow('quarantine identity changed');
    } finally {
      fsPromises.rename = originalRename;
    }

    expect(parentTombstone).not.toBe('');
    expect(await readFile(join(parentTombstone, 'replacement-survives.txt'), 'utf8')).toBe('keep me');
    expect(await exists(originalParent)).toBe(true);
    await rm(parentTombstone, { recursive: true, force: true });
    await rm(originalParent, { recursive: true, force: true });
  });

  it('keeps live output outside retained test-results and removes the complete run root', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    const nestedOutput = join(outputRoot, 'chromium-live', 'failed-test');
    await mkdir(nestedOutput, { recursive: true });
    const artifact = join(nestedOutput, 'error-context.md');
    await writeFile(artifact, 'synthetic-password', 'utf8');

    await removeLiveArtifacts(outputRoot);

    expect(await exists(outputRoot)).toBe(false);
    expect(outputRoot).not.toContain(`${join('apps', 'web', 'test-results')}`);

    // Recreating the exact path without the run-owned marker must not inherit
    // the deleted root's ownership token or become cleanup-eligible.
    await mkdir(outputRoot, { recursive: true });
    const recreatedArtifact = join(outputRoot, 'recreated.txt');
    await writeFile(recreatedArtifact, 'synthetic-password', 'utf8');
    await removeLiveArtifacts(outputRoot);
    expect(await exists(recreatedArtifact)).toBe(true);
    await rm(outputRoot, { recursive: true, force: true });

    const descendantRoot = liveArtifactOutputDirectory();
    const descendant = join(descendantRoot, 'nested');
    await mkdir(descendant, { recursive: true });
    const descendantArtifact = join(descendant, 'report.txt');
    await writeFile(descendantArtifact, 'safe fixture', 'utf8');
    await removeLiveArtifacts(descendant);
    expect(await exists(descendantArtifact)).toBe(true);
    await removeLiveArtifacts(descendantRoot);
    expect(await exists(descendantRoot)).toBe(false);

    const retainedDirectory = await import('node:fs/promises').then(({ mkdtemp }) =>
      mkdtemp(join('/tmp', 'hermternal-retained-'))
    );
    try {
      const retainedArtifact = join(retainedDirectory, 'report.txt');
      await writeFile(retainedArtifact, 'safe fixture', 'utf8');
      await removeLiveArtifacts(retainedDirectory);
      expect(await exists(retainedArtifact)).toBe(true);

      const prefixCollision = join(tmpdir(), 'hermternal-playwright-live-prefix-collision');
      await mkdir(prefixCollision, { recursive: true });
      const collisionArtifact = join(prefixCollision, 'report.txt');
      await writeFile(collisionArtifact, 'safe fixture', 'utf8');
      await removeLiveArtifacts(prefixCollision);
      expect(await exists(collisionArtifact)).toBe(true);

      const symlinkDirectory = join(tmpdir(), 'hermternal-playwright-live-symlink');
      try {
        await symlink(retainedDirectory, symlinkDirectory);
        await removeLiveArtifacts(symlinkDirectory);
        expect(await exists(symlinkDirectory)).toBe(true);
        expect(await exists(retainedArtifact)).toBe(true);
      } finally {
        await rm(symlinkDirectory, { recursive: true, force: true });
        await rm(prefixCollision, { recursive: true, force: true });
      }
    } finally {
      await rm(retainedDirectory, { recursive: true, force: true });
    }
  });

  it('preserves one owned run root across two Playwright tests and removes it globally', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { finalizeLiveTest } from '__POLICY_URL__';
const root = process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR;
if (!root) throw new Error('missing synthetic output root');
const secret = 'synthetic-password';
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo, secrets: [secret] });
});
test('first owned test', async ({}, testInfo) => {
  await mkdir(testInfo.outputDir, { recursive: true });
  await writeFile(join(testInfo.outputDir, 'per-test-secret.txt'), secret, 'utf8');
  await writeFile(join(root, 'run-level.txt'), 'root-level-survives', 'utf8');
});
test('second owned test sees the same root', async ({}, testInfo) => {
  const marker = await readFile(join(root, '.hermternal-live-artifact-owner'), 'utf8');
  if (!marker.endsWith('\\n')) throw new Error('run marker was not preserved');
  const runLevel = await readFile(join(root, 'run-level.txt'), 'utf8');
  if (runLevel !== 'root-level-survives') throw new Error('root-level artifact was removed');
  const entries = await readdir(root, { recursive: true });
  if (entries.some((entry) => String(entry).endsWith('per-test-secret.txt')))
    throw new Error('per-test output was not removed');
  await mkdir(testInfo.outputDir, { recursive: true });
});
`);
    if (result.code !== 0) throw new Error(`synthetic lifecycle failed\\n${result.stdout}\\n${result.stderr}`);
    expect(result.stdout + result.stderr).not.toContain('synthetic-password');
    expect(result.stdout).toContain('END:passed');
  }, 30_000);

  it('refuses per-test cleanup through a replaceable symlink ancestor', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { finalizeLiveTest } from '__POLICY_URL__';
const root = process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR;
if (!root) throw new Error('missing synthetic output root');
const secret = 'synthetic-password';
let victim;
let victimFile;
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo, secrets: [secret] });
});
test.afterAll(async () => {
  if (!victimFile) throw new Error('missing symlink victim');
  const contents = await readFile(victimFile, 'utf8').catch(() => 'missing');
  process.stdout.write('VICTIM:' + contents + '\\n');
  await rm(victim, { recursive: true, force: true });
});
test('symlink ancestor stays outside cleanup', async ({}, testInfo) => {
  const ancestor = join(root, '.playwright-output');
  const relativeOutput = relative(ancestor, testInfo.outputDir);
  if (!relativeOutput || relativeOutput.startsWith('..'))
    throw new Error('missing nested project output ancestor');
  victim = await mkdtemp(join(tmpdir(), 'hermternal-live-symlink-victim-'));
  const victimOutput = join(victim, relativeOutput);
  await mkdir(victimOutput, { recursive: true });
  victimFile = join(victimOutput, 'must-survive.txt');
  await writeFile(victimFile, 'victim-survives', 'utf8');
  await rm(ancestor, { recursive: true, force: true });
  await symlink(victim, ancestor);
});
`);
    const output = result.stdout + result.stderr;
    expect(result.code).toBe(0);
    expect(output).not.toContain('synthetic-password');
    expect(output).toContain('VICTIM:victim-survives');
    expect(result.stdout).toContain('END:passed');
  }, 30_000);

  it('preserves one run root across a retry and sequential worker tests until global teardown', async () => {
    const result = await runSyntheticPlaywright(`
import { test } from ${JSON.stringify(playwrightEntryUrl)};
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { finalizeLiveTest } from '__POLICY_URL__';
const root = process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR;
if (!root) throw new Error('missing synthetic output root');
const secret = 'synthetic-password';
const present = async (path) => {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
};
test.describe.configure({ mode: 'serial' });
test.afterEach(async ({}, testInfo) => {
  await finalizeLiveTest({ testInfo, secrets: [secret] });
});
test('retry keeps the owned root', async ({}, testInfo) => {
  await mkdir(testInfo.outputDir, { recursive: true });
  await writeFile(
    join(testInfo.outputDir, 'attempt.txt'),
    String(testInfo.retry),
    'utf8'
  );
  if (testInfo.retry === 0) {
    await writeFile(join(root, 'run-level.txt'), 'root-level-survives', 'utf8');
    await writeFile(join(root, 'first-output-dir.txt'), testInfo.outputDir, 'utf8');
    throw new Error('synthetic retry only');
  }
  const firstOutputDir = (await readFile(join(root, 'first-output-dir.txt'), 'utf8')).trim();
  if (await present(firstOutputDir)) throw new Error('first retry output survived');
  const marker = await readFile(join(root, '.hermternal-live-artifact-owner'), 'utf8');
  if (!marker.endsWith('\\n')) throw new Error('run marker was not preserved');
  const runLevel = await readFile(join(root, 'run-level.txt'), 'utf8');
  if (runLevel !== 'root-level-survives') throw new Error('root-level artifact was removed');
  await writeFile(join(root, 'retry-output-dir.txt'), testInfo.outputDir, 'utf8');
});
test('sequential test sees the same root', async ({}, testInfo) => {
  const marker = await readFile(join(root, '.hermternal-live-artifact-owner'), 'utf8');
  if (!marker.endsWith('\\n')) throw new Error('run marker was not preserved');
  const runLevel = await readFile(join(root, 'run-level.txt'), 'utf8');
  if (runLevel !== 'root-level-survives') throw new Error('root-level artifact was removed');
  const firstOutputDir = (await readFile(join(root, 'first-output-dir.txt'), 'utf8')).trim();
  const retryOutputDir = (await readFile(join(root, 'retry-output-dir.txt'), 'utf8')).trim();
  if (await present(firstOutputDir) || await present(retryOutputDir))
    throw new Error('per-test output survived until the next sequential test');
  await mkdir(testInfo.outputDir, { recursive: true });
});
`, { retries: 1, reportOutputRoot: true });
    const output = result.stdout + result.stderr;
    const rootStart = output.indexOf('ROOT:');
    const root = rootStart < 0
      ? undefined
      : output.slice(rootStart + 'ROOT:'.length).split('\\n', 1)[0].trim();
    try {
      expect(result.code).toBe(0);
      expect(output).not.toContain('synthetic-password');
      expect(result.stdout).toContain('END:passed');
      expect(root).toBeTruthy();
      expect(root && await exists(root)).toBe(false);
    } finally {
      if (root) await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  it('pins the delegated live config to no media artifacts, safe reporting, and fixed paths', async () => {
    const configSource = await readFile(resolve(appRoot, 'playwright.live.config.ts'), 'utf8');
    expect(configSource).toContain('getLivePlaywrightPaths');
    expect(configSource).toContain('createLivePlaywrightConfig');
    expect(configSource).toContain('getLiveScreenshotChromiumLaunchOptions');
    expect(configSource).toContain('devNull');
    expect(configSource).toContain('assertLiveRunnerDebugDisabled');

    const paths = getLivePlaywrightPaths(pathToFileURL(resolve(appRoot, 'playwright.live.config.ts')).href);
    const outputDirectory = join(tmpdir(), 'hermternal-config-contract');
    const config = createLivePlaywrightConfig({
      paths,
      port: 4187,
      outputDirectory,
      launchOptions: { headless: true },
      desktopChrome: {}
    });
    expect(config.testDir).toBe(paths.liveTestsDirectory);
    expect(config.outputDir).toBe(join(outputDirectory, '.playwright-output'));
    expect(config.preserveOutput).toBe('never');
    expect(config.reporter).toEqual([[paths.safeReporterFile]]);
    expect(config.globalTeardown).toBe(paths.teardownFile);
    expect(config.use).toMatchObject({
      viewport: { width: 1440, height: 960 },
      deviceScaleFactor: 1,
      locale: 'en-US',
      trace: 'off',
      video: 'off',
      screenshot: 'off',
      launchOptions: { headless: true }
    });
    expect(config.projects[0].use).toMatchObject({
      viewport: { width: 1440, height: 960 },
      deviceScaleFactor: 1,
      locale: 'en-US',
      trace: 'off',
      video: 'off',
      screenshot: 'off',
      launchOptions: { headless: true }
    });
  });

  it('selects exactly the no-submit reconciliation lane and keeps its prompt ledger empty', async () => {
    expect(() => isLiveReconciliationEnabled({ HERMTERNAL_LIVE_RECONCILIATION: 'true' })).toThrow(
      'must equal exactly 1'
    );
    expect(() => isLiveReconciliationEnabled({ HERMTERNAL_LIVE_RECONCILIATION: 'yes' })).toThrow(
      'must equal exactly 1'
    );

    const childEnvironment: NodeJS.ProcessEnv = {
      ...process.env,
      HERMTERNAL_LIVE_RECONCILIATION: '1'
    };
    delete childEnvironment.HERMTERNAL_LIVE_SCREENSHOT_CAPTURE;
    delete childEnvironment.HERMES_TEST_PASSWORD;
    delete childEnvironment.PW_RUNNER_DEBUG;
    delete childEnvironment.PWDEBUG;
    const configUrl = pathToFileURL(resolve(appRoot, 'playwright.live.config.ts')).href;
    const policyUrl = pathToFileURL(policyPath).href;
    const probe = `
      import { removeLiveArtifacts } from ${JSON.stringify(policyUrl)};
      let root;
      try {
        const loaded = await import(${JSON.stringify(configUrl)} + '?selection=' + Date.now());
        root = process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR;
        const config = loaded.default;
        if (config.testMatch !== '**/reconcile-live-proof.spec.ts') throw new Error('wrong reconciliation test match');
        const ignored = config.testIgnore;
        if (!Array.isArray(ignored) || !ignored.includes('**/official-hermes.spec.ts') || !ignored.includes('**/*capture*.spec.ts'))
          throw new Error('wrong reconciliation test ignore set');
        process.stdout.write('CONFIG_SELECTION_OK');
      } finally {
        if (root) await removeLiveArtifacts(root);
      }
    `;
    const result = await execFileAsync(process.execPath, ['-e', probe], {
      cwd: appRoot,
      env: childEnvironment,
      maxBuffer: 4 * 1024 * 1024,
      timeout: 30_000,
      encoding: 'utf8'
    });
    const output = result.stdout + result.stderr;
    expect(output).toContain('CONFIG_SELECTION_OK');
    expect(await exists(resolve(appRoot, 'tests/live/reconcile-live-proof.spec.ts'))).toBe(true);
    const reconciliationSource = await readFile(
      resolve(appRoot, 'tests/live/reconcile-live-proof.spec.ts'),
      'utf8'
    );
    expect(reconciliationSource).not.toContain("prompt.submit");
    expect(reconciliationSource).not.toContain("Message Hermes");

    const emptyLedger = createLiveProofLedger();
    expect(matchLiveProofLedger(emptyLedger.snapshot(), {})).toMatchObject({
      promptCount: 0,
      completionCount: 0
    });
  });

  it('executes the actual live config guard and path injection in an isolated child', async () => {
    const configUrl = pathToFileURL(resolve(appRoot, 'playwright.live.config.ts')).href;
    const policyUrl = pathToFileURL(policyPath).href;
    const probe = `
      import { devNull } from 'node:os';
      import { removeLiveArtifacts } from ${JSON.stringify(policyUrl)};
      let root;
      try {
        const loaded = await import(${JSON.stringify(configUrl)});
        root = process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR;
        if (!root || !process.env.PLAYWRIGHT_LIVE_OUTPUT_TOKEN) throw new Error('missing live output injection');
        if (!process.env.NODE_OPTIONS?.includes('live-ipc-guard.cjs')) throw new Error('missing actual IPC guard injection');
        if (process.env.PLAYWRIGHT_LAST_RUN_OUTPUT_FILE !== devNull) throw new Error('missing null sink');
        if (loaded.default.outputDir !== root + '/.playwright-output') throw new Error('wrong delegated output path');
        process.stdout.write('CONFIG_PROBE_OK');
      } finally {
        if (root) await removeLiveArtifacts(root);
      }
    `;
    const childEnvironment: NodeJS.ProcessEnv = { ...process.env, NODE_OPTIONS: '' };
    delete childEnvironment.HERMES_TEST_USERNAME;
    delete childEnvironment.HERMES_TEST_PASSWORD;
    delete childEnvironment.PW_RUNNER_DEBUG;
    delete childEnvironment.PWDEBUG;
    const result = await execFileAsync(process.execPath, ['-e', probe], {
      cwd: appRoot,
      env: childEnvironment,
      maxBuffer: 2 * 1024 * 1024,
      encoding: 'utf8'
    });
    expect(result.stdout).toContain('CONFIG_PROBE_OK');
  }, 30_000);
});
