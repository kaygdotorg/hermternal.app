import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getLiveScreenshotGitChildConfiguration } from './live-trusted-executables.mjs';

const PARENT_COMMIT = '77c6701c652a6bbd23d2c32227dcd61c34dd8c33';
const probeDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(probeDirectory, '../../../..');

const SUPPORT_PATHS = Object.freeze([
  'apps/web/tests/live/live-playwright-config.mjs',
  'apps/web/tests/live/live-screenshot-capture.mjs',
  'apps/web/tests/live/live-reconciliation.mjs',
  'apps/web/tests/live/live-reconciliation-auth.mjs',
  'apps/web/tests/live/live-reconciliation-transport.mjs',
  'apps/web/tests/live/live-proof-status.mjs',
  'apps/web/tests/live/reconcile-live-proof.spec.ts'
]);
const SCREENSHOT_TEST_PATH = 'apps/web/src/lib/live-screenshot-capture.test.ts';
const SCREENSHOT_CONTRACT_PATH = 'apps/web/tests/live/live-screenshot-contract.mjs';
const OFFICIAL_SPEC_PATH = 'apps/web/tests/live/official-hermes.spec.ts';
const SCREENSHOT_COMMAND_PATTERN = /export const LIVE_SCREENSHOT_COMMAND\s*=\s*'([^']+)'/u;
const TEST_TITLE_PATTERN = /\btest\('([^']+)'/gu;

/**
 * Read a historical path from the local Git object database without checking
 * out or importing the parent. Missing support files are the expected failure
 * evidence for this migration probe, so their read errors are converted to an
 * explicit `undefined` result while Git stderr remains suppressed.
 *
 * @param {string} commit
 * @param {string} path
 * @returns {string | undefined}
 */
function readGitFile(commit, path) {
  try {
    const gitConfiguration = getLiveScreenshotGitChildConfiguration();
    return execFileSync(gitConfiguration.executable, ['show', `${commit}:${path}`], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: gitConfiguration.environment,
      stdio: ['ignore', 'pipe', 'ignore']
    });
  } catch {
    return undefined;
  }
}

/** @param {string} path */
function readChildFile(path) {
  return readFileSync(resolve(repositoryRoot, path), 'utf8');
}

/** @param {string} source */
function readScreenshotCommand(source) {
  const match = source.match(SCREENSHOT_COMMAND_PATTERN);
  assert.ok(match, 'screenshot contract command is missing');
  return match[1];
}

/** @param {string} source */
function readTestTitles(source) {
  return [...source.matchAll(TEST_TITLE_PATTERN)].map((match) => match[1]);
}

const parentScreenshotTest = readGitFile(PARENT_COMMIT, SCREENSHOT_TEST_PATH);
assert.equal(typeof parentScreenshotTest, 'string', 'exact parent screenshot test is missing');
assert.match(
  parentScreenshotTest,
  /from ['"]\.\.\/\.\.\/tests\/live\/live-playwright-config\.mjs['"]/u,
  'parent screenshot test no longer records its config dependency'
);
assert.match(
  parentScreenshotTest,
  /from ['"]\.\.\/\.\.\/tests\/live\/live-screenshot-capture\.mjs['"]/u,
  'parent screenshot test no longer records its capture dependency'
);

for (const path of SUPPORT_PATHS) {
  assert.equal(
    readGitFile(PARENT_COMMIT, path),
    undefined,
    `exact parent unexpectedly contains support path ${path}`
  );
  assert.doesNotThrow(() => readChildFile(path), `repaired support path is missing: ${path}`);
}

const parentContract = readGitFile(PARENT_COMMIT, SCREENSHOT_CONTRACT_PATH);
const parentSpec = readGitFile(PARENT_COMMIT, OFFICIAL_SPEC_PATH);
assert.equal(typeof parentContract, 'string', 'exact parent screenshot contract is missing');
assert.equal(typeof parentSpec, 'string', 'exact parent official spec is missing');
const parentCommand = readScreenshotCommand(parentContract);
const parentTitles = readTestTitles(parentSpec);
const parentGrepTitle = parentCommand.match(/--grep "([^"]+)"/u)?.[1];
assert.equal(typeof parentGrepTitle, 'string', 'parent screenshot command has no exact grep title');
assert.equal(
  parentTitles.includes(parentGrepTitle),
  false,
  'exact parent unexpectedly satisfies the unchanged screenshot grep contract'
);

const childContract = readChildFile(SCREENSHOT_CONTRACT_PATH);
const childSpec = readChildFile(OFFICIAL_SPEC_PATH);
const childCommand = readScreenshotCommand(childContract);
const childTitles = readTestTitles(childSpec);
const childGrepTitle = childCommand.match(/--grep "([^"]+)"/u)?.[1];
assert.equal(typeof childGrepTitle, 'string', 'repaired screenshot command has no exact grep title');
assert.equal(
  childTitles.filter((title) => title === childGrepTitle).length,
  1,
  'repaired official spec does not expose exactly one matching screenshot title'
);

const childConfig = readChildFile('apps/web/tests/live/live-playwright-config.mjs');
assert.match(childConfig, /from ['"]\.\/live-reconciliation\.mjs['"]/u);
assert.match(readChildFile('apps/web/playwright.live.config.ts'), /live-playwright-config\.mjs/u);
assert.match(readChildFile('apps/web/playwright.live.config.ts'), /live-screenshot-capture\.mjs/u);

console.log(
  `live-support-parent-compat: exact parent ${PARENT_COMMIT.slice(0, 12)} lacks the delegated live support lane and has a stale screenshot grep; repaired child restores the compatible e5 support set and one exact title match`
);
