import { promises as fsPromises } from 'node:fs';
import { access, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  LIVE_ARTIFACT_REDACTION,
  finalizeLiveTest,
  liveArtifactOutputDirectory,
  liveCredentialValues,
  redactLiveText,
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
    await mkdir(outputRoot, { recursive: true });
    await writeFile(join(outputRoot, 'error-context.md'), 'synthetic-password', 'utf8');

    const sourceDiagnostic = { message: 'synthetic-password' };
    const testInfo = {
      attachments: [{ name: 'live-error', path: join(outputRoot, 'error-context.md') }],
      errors: [sourceDiagnostic],
      outputDir: outputRoot
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
    expect(await exists(outputRoot)).toBe(false);
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
      expect(JSON.stringify(mappedErrors)).not.toContain('synthetic-password');
      expect(mappedErrors).toHaveLength(1);
      expect(mappedErrors[0].message).toBe(LIVE_ARTIFACT_REDACTION);

      // The real worker keeps using the array after afterEach: push, map, and
      // iteration must remain ordinary Playwright-compatible operations.
      testInfo.errors.push({ message: LIVE_ARTIFACT_REDACTION });
      expect([...testInfo.errors]).toHaveLength(2);
      expect(JSON.stringify(testInfo.errors.map((error) => ({ message: error.message })))).not.toContain(
        'synthetic-password'
      );
    } finally {
      if (objectToJSON) Object.defineProperty(Object.prototype, 'toJSON', objectToJSON);
      else delete (Object.prototype as { toJSON?: unknown }).toJSON;
      if (arrayToJSON) Object.defineProperty(Array.prototype, 'toJSON', arrayToJSON);
      else delete (Array.prototype as { toJSON?: unknown }).toJSON;
      await rm(outputRoot, { recursive: true, force: true });
    }
  });

  it('runs attachment and output cleanup before propagating a redaction failure', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    await mkdir(outputRoot, { recursive: true });
    await writeFile(join(outputRoot, 'error-context.md'), 'synthetic-password', 'utf8');

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
      attachments: [{ name: 'live-error', path: join(outputRoot, 'error-context.md') }],
      errors: [throwingDiagnostic],
      outputDir: outputRoot
    };

    await expect(
      finalizeLiveTest({ testInfo, secrets: ['synthetic-password'] })
    ).rejects.toThrow('redaction failed');
    expect(testInfo.attachments).toHaveLength(0);
    expect(testInfo.errors).toEqual([LIVE_ARTIFACT_REDACTION]);
    expect(JSON.stringify(testInfo.errors)).not.toContain('synthetic-password');
    expect(await exists(outputRoot)).toBe(false);
  });

  it('binds cleanup to the owned inode across a replacement race', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    const ownedArtifact = join(outputRoot, 'owned-only.txt');
    const backupRoot = `${outputRoot}-race-backup`;
    const replacementArtifact = join(outputRoot, 'replacement.txt');
    await rm(backupRoot, { recursive: true, force: true });
    await mkdir(outputRoot, { recursive: true });
    await writeFile(ownedArtifact, 'synthetic-password', 'utf8');

    const originalRm = fsPromises.rm;
    let swapped = false;
    fsPromises.rm = async (target, options) => {
      if (!swapped) {
        swapped = true;
        try {
          await fsPromises.rename(outputRoot, backupRoot);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        }
        await mkdir(outputRoot, { recursive: true });
        await writeFile(replacementArtifact, 'replacement-survives', 'utf8');
      }
      return originalRm(target, options);
    };

    try {
      await removeLiveArtifacts(outputRoot);
    } finally {
      fsPromises.rm = originalRm;
    }

    expect(swapped).toBe(true);
    expect(await exists(replacementArtifact)).toBe(true);
    if (await exists(backupRoot)) {
      expect(await exists(join(backupRoot, 'owned-only.txt'))).toBe(true);
    }
    await rm(outputRoot, { recursive: true, force: true });
    await rm(backupRoot, { recursive: true, force: true });
  });

  it('preserves a quarantine replacement across the final identity check', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    const ownedArtifact = join(outputRoot, 'owned-only.txt');
    let quarantinePath = '';
    let deletionPath = '';
    let ownedBackup = '';
    let renameCalls = 0;
    await mkdir(outputRoot, { recursive: true });
    await writeFile(ownedArtifact, 'owned-content', 'utf8');

    const originalRename = fsPromises.rename;
    fsPromises.rename = async (source, target) => {
      renameCalls += 1;
      const sourcePath = String(source);
      const targetPath = String(target);
      if (renameCalls === 2) {
        quarantinePath = sourcePath;
        deletionPath = targetPath;
        ownedBackup = `${sourcePath}-owned-backup`;
        await originalRename(source, ownedBackup);
        await mkdir(sourcePath, { recursive: true });
        await writeFile(join(sourcePath, 'replacement.txt'), 'replacement-survives', 'utf8');
      }
      return originalRename(source, target);
    };

    try {
      await removeLiveArtifacts(outputRoot);
    } finally {
      fsPromises.rename = originalRename;
    }

    expect(renameCalls).toBeGreaterThanOrEqual(2);
    expect(await exists(join(deletionPath, 'replacement.txt'))).toBe(true);
    expect(await exists(join(ownedBackup, 'owned-only.txt'))).toBe(true);
    expect(await exists(outputRoot)).toBe(false);

    await rm(deletionPath, { recursive: true, force: true });
    await rm(ownedBackup, { recursive: true, force: true });
    if (deletionPath) {
      await rm(resolve(deletionPath, '..'), { recursive: true, force: true });
    }
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
      await removeLiveArtifacts(outputRoot);
    } finally {
      fsPromises.rename = originalRename;
    }

    expect(removedByRace).toBe(true);
    expect(quarantinePath).not.toBe('');
    expect(await exists(quarantinePath)).toBe(false);
    expect(await exists(resolve(quarantinePath, '..'))).toBe(false);
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

  it('pins the live config to no media artifacts, no retained output, and safe reporting', async () => {
    const config = await readFile(resolve(process.cwd(), 'playwright.live.config.ts'), 'utf8');

    expect(config).toContain('outputDir: liveOutputDirectory');
    expect(config).toContain('PLAYWRIGHT_LIVE_OUTPUT_TOKEN');
    expect(config).toContain("preserveOutput: 'never'");
    expect(config).toContain("reporter: [['./tests/live/safe-reporter.mjs']]");
    expect(config).toContain("globalTeardown: './tests/live/live-artifact-teardown.mjs'");
    expect(config).toContain("trace: 'off'");
    expect(config).toContain("video: 'off'");
    expect(config).toContain("screenshot: 'off'");
  });
});
