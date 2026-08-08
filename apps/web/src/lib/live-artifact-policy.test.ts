import { readFile } from 'node:fs/promises';
import { access, mkdir, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  LIVE_ARTIFACT_REDACTION,
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
  it('redacts credentials and serialized form values from structured errors', () => {
    const sourceLocation = { file: '/tmp/live-proof.spec.ts', line: 42, column: 7 };
    const errors = [
      {
        message: 'username=synthetic-user password=synthetic-password',
        stack: '<input id="auth-password" value="synthetic-password">',
        cause: {
          value: 'synthetic-password',
          errorContext: { matcherResult: { ariaSnapshot: 'nested synthetic-password' } }
        },
        errorContext: {
          location: sourceLocation,
          matcherResult: {
            actual: '<input value="synthetic-password">',
            ariaSnapshot: '- textbox "synthetic-user": synthetic-password',
            nested: [{ message: 'synthetic-password' }]
          }
        }
      }
    ];

    redactTestErrors(errors, ['synthetic-user', 'synthetic-password']);

    expect(errors[0]).toEqual({
      message: `username=${LIVE_ARTIFACT_REDACTION} password=${LIVE_ARTIFACT_REDACTION}`,
      stack: `<input id="auth-password" value="${LIVE_ARTIFACT_REDACTION}">`,
      cause: {
        value: LIVE_ARTIFACT_REDACTION,
        errorContext: { matcherResult: { ariaSnapshot: `nested ${LIVE_ARTIFACT_REDACTION}` } }
      },
      errorContext: {
        location: sourceLocation,
        matcherResult: {
          actual: `<input value="${LIVE_ARTIFACT_REDACTION}">`,
          ariaSnapshot: `- textbox "${LIVE_ARTIFACT_REDACTION}": ${LIVE_ARTIFACT_REDACTION}`,
          nested: [{ message: LIVE_ARTIFACT_REDACTION }]
        }
      }
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

  it('fails live scrub errors closed but tolerates only definitive page termination', async () => {
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
    ).resolves.toBeUndefined();
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

    const retainedDirectory = await import('node:fs/promises').then(({ mkdtemp }) => mkdtemp(join('/tmp', 'hermternal-retained-')));
    try {
      const retainedArtifact = join(retainedDirectory, 'report.txt');
      await writeFile(retainedArtifact, 'safe fixture', 'utf8');
      await removeLiveArtifacts(retainedDirectory);
      expect(await exists(retainedArtifact)).toBe(true);
    } finally {
      await rm(retainedDirectory, { recursive: true, force: true });
    }
  });

  it('pins the live config to no media artifacts, no retained output, and safe reporting', async () => {
    const config = await readFile(resolve(process.cwd(), 'playwright.live.config.ts'), 'utf8');

    expect(config).toContain('outputDir: liveOutputDirectory');
    expect(config).toContain("preserveOutput: 'never'");
    expect(config).toContain("reporter: [['./tests/live/safe-reporter.mjs']]");
    expect(config).toContain("globalTeardown: './tests/live/live-artifact-teardown.mjs'");
    expect(config).toContain("trace: 'off'");
    expect(config).toContain("video: 'off'");
    expect(config).toContain("screenshot: 'off'");
  });
});
