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

    redactTestErrors(errors, ['synthetic-user', 'synthetic-password']);

    expect(rootError.message).toBe(`expect(locator).toHaveText: ${LIVE_ARTIFACT_REDACTION}`);
    expect(rootError.stack).toContain(LIVE_ARTIFACT_REDACTION);
    expect(rootError.errorContext).toBe(
      `- textbox "${LIVE_ARTIFACT_REDACTION}": ${LIVE_ARTIFACT_REDACTION}`
    );
    expect(rootError.matcherResult).toEqual({
      message: `expect(locator).toHaveValue: ${LIVE_ARTIFACT_REDACTION}`,
      actual: `<input id="auth-password" value="${LIVE_ARTIFACT_REDACTION}">`,
      expected: LIVE_ARTIFACT_REDACTION,
      log: [
        `locator resolved with ${LIVE_ARTIFACT_REDACTION}`,
        `value=${LIVE_ARTIFACT_REDACTION}`
      ],
      ariaSnapshot: `- textbox "${LIVE_ARTIFACT_REDACTION}": ${LIVE_ARTIFACT_REDACTION}`
    });
    expect(nestedCause.message).toBe(`nested ${LIVE_ARTIFACT_REDACTION}`);
    expect(nestedCause.stack).toContain(LIVE_ARTIFACT_REDACTION);
    expect(serializedTestInfoError).toEqual({
      location: sourceLocation,
      message: `expect(locator).toHaveText: ${LIVE_ARTIFACT_REDACTION}`,
      stack: `<textarea>${LIVE_ARTIFACT_REDACTION}</textarea>`,
      value: LIVE_ARTIFACT_REDACTION,
      errorContext: `- textbox "${LIVE_ARTIFACT_REDACTION}": ${LIVE_ARTIFACT_REDACTION}`
    });

    expect(redactLiveText('<input value="unlisted-value">', [])).toContain(LIVE_ARTIFACT_REDACTION);
    const unlistedFormMarkup = redactLiveText(
      '<select><option>unlisted-option</option></select><div contenteditable>unlisted-editable</div>',
      []
    ) as string;
    expect(unlistedFormMarkup).toContain(LIVE_ARTIFACT_REDACTION);
    expect(unlistedFormMarkup).not.toContain('unlisted-option');
    expect(unlistedFormMarkup).not.toContain('unlisted-editable');
    expect(liveCredentialValues({})).toContain('hermternal-test');
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

  it('fails closed when diagnostic writes are rejected, silent, or unreadable', () => {
    const falseSetter = new Proxy(
      { message: 'synthetic-password' },
      { set: () => false }
    );
    const silentSetterTarget = { message: 'synthetic-password' };
    const silentSetter = new Proxy(silentSetterTarget, {
      set: () => true
    });
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

    expect(() => redactTestErrors([falseSetter], ['synthetic-password'])).toThrow(
      'redaction failed'
    );
    expect(() => redactTestErrors([silentSetter], ['synthetic-password'])).toThrow(
      'redaction failed'
    );
    expect(silentSetterTarget.message).toBe('synthetic-password');
    expect(() => redactTestErrors([throwingGetter], ['synthetic-password'])).toThrow(
      'redaction failed'
    );
    expect(() => redactTestErrors([throwingDescriptor], ['synthetic-password'])).toThrow(
      'redaction failed'
    );
  });

  it('verifies unchanged data and accessor reads and rejects spoofed or incomplete descriptors', () => {
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
    expect(() => redactTestErrors([spoofedData], ['synthetic-password'])).toThrow(
      'redaction failed'
    );

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
    expect(() => redactTestErrors([spoofedAccessor], ['synthetic-password'])).toThrow(
      'redaction failed'
    );

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
    redactTestErrors([ordinaryAccessor], ['synthetic-password']);
    expect(ordinaryAccessorValue).toBe(LIVE_ARTIFACT_REDACTION);

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
    redactTestErrors([cyclic], ['synthetic-password']);
    expect(cyclic.message).toBe(LIVE_ARTIFACT_REDACTION);
    expect(cyclic.self).toBe(cyclic);

    let deep: Record<string, unknown> = { value: 'synthetic-password' };
    for (let index = 0; index < 20; index += 1) deep = { next: deep };
    expect(() => redactTestErrors([deep], ['synthetic-password'])).toThrow('budget');

    const wide = Array.from({ length: 513 }, () => 'synthetic-password');
    expect(() => redactTestErrors([wide], ['synthetic-password'])).toThrow('budget');
    expect(() => redactLiveText('x'.repeat(256 * 1024 + 1), [])).toThrow('budget');
  });

  it('runs attachment and output cleanup before propagating a redaction failure', async () => {
    const outputRoot = liveArtifactOutputDirectory();
    await mkdir(outputRoot, { recursive: true });
    await writeFile(join(outputRoot, 'error-context.md'), 'synthetic-password', 'utf8');

    const immutableDiagnostic = {} as { message: string };
    Object.defineProperty(immutableDiagnostic, 'message', {
      configurable: false,
      enumerable: true,
      value: 'synthetic-password',
      writable: false
    });
    const testInfo = {
      attachments: [{ name: 'live-error', path: join(outputRoot, 'error-context.md') }],
      errors: [immutableDiagnostic],
      outputDir: outputRoot
    };

    await expect(
      finalizeLiveTest({ testInfo, secrets: ['synthetic-password'] })
    ).rejects.toThrow('redaction failed');
    expect(testInfo.attachments).toHaveLength(0);
    expect(await exists(outputRoot)).toBe(false);
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
