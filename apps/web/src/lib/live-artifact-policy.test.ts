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
    const errors = [
      {
        message: 'username=synthetic-user password=synthetic-password',
        stack: '<input id="auth-password" value="synthetic-password">',
        cause: { value: 'synthetic-password' }
      }
    ];

    redactTestErrors(errors, ['synthetic-user', 'synthetic-password']);

    expect(errors[0]).toEqual({
      message: `username=${LIVE_ARTIFACT_REDACTION} password=${LIVE_ARTIFACT_REDACTION}`,
      stack: `<input id="auth-password" value="${LIVE_ARTIFACT_REDACTION}">`,
      cause: { value: LIVE_ARTIFACT_REDACTION }
    });
    expect(redactLiveText('<input value="unlisted-value">', [])).toContain(LIVE_ARTIFACT_REDACTION);
    expect(liveCredentialValues({})).toContain('hermternal-test');
  });

  it('scrubs live form controls before page teardown', async () => {
    document.body.innerHTML = `
      <form>
        <input id="auth-username" value="synthetic-user">
        <input id="auth-password" value="synthetic-password">
        <textarea>synthetic-password</textarea>
        <select><option selected>synthetic-user</option></select>
        <div contenteditable="true">synthetic-password</div>
      </form>
    `;

    await scrubLivePage({ evaluate: async (callback) => callback() });

    expect(document.querySelector<HTMLInputElement>('#auth-username')?.value).toBe('');
    expect(document.querySelector<HTMLInputElement>('#auth-password')?.value).toBe('');
    expect(document.querySelector('textarea')?.textContent).toBe('');
    expect(document.querySelector('select')?.selectedIndex).toBe(-1);
    expect(document.querySelector('select')?.textContent).toBe('');
    expect(document.querySelector('[contenteditable="true"]')?.textContent).toBe('');
    expect(document.documentElement.outerHTML).not.toContain('synthetic-user');
    expect(document.documentElement.outerHTML).not.toContain('synthetic-password');
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
