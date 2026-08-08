import { rm } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

export const LIVE_ARTIFACT_REDACTION = '[redacted-live-credential]';
const LIVE_OUTPUT_PREFIX = 'hermternal-playwright-live-';
const LIVE_DEFAULT_USERNAME = 'hermternal-test';
const LIVE_SECRET_ENV_NAMES = ['HERMES_TEST_USERNAME', 'HERMES_TEST_PASSWORD'];
const LIVE_PAGE_TERMINATION_PATTERN =
  /(?:target page, context or browser has been closed|(?:page|browser|context)(?: has been| was| has)? closed|(?:page|browser|context)(?: has)? crashed)/iu;

/**
 * Read the explicitly supplied live-proof values plus the fixed synthetic
 * username fallback used by the live spec. The values stay in the test process
 * and are used to redact diagnostics; they are never written to a report or
 * passed to a browser artifact.
 *
 * @param {Record<string, string | undefined>} [environment]
 * @returns {string[]}
 */
export function liveCredentialValues(environment = process.env) {
  const values = [LIVE_DEFAULT_USERNAME];
  for (const name of LIVE_SECRET_ENV_NAMES) {
    const value = environment[name];
    if (typeof value === 'string' && value.length > 0) values.push(value);
  }
  return [...new Set(values)];
}

/**
 * Keep live Playwright output in a unique OS-temporary directory instead of
 * the repository's retained `test-results` path.
 *
 * @param {number} [processId]
 * @returns {string}
 */
export function liveArtifactOutputDirectory(processId = process.pid) {
  return resolve(tmpdir(), `${LIVE_OUTPUT_PREFIX}${processId}`);
}

/**
 * @param {string} directory
 * @returns {boolean}
 */
export function isLiveArtifactDirectory(directory) {
  const candidate = resolve(directory);
  const pathFromTemporaryRoot = relative(resolve(tmpdir()), candidate);
  const [rootName] = pathFromTemporaryRoot.split(sep);
  return rootName.startsWith(LIVE_OUTPUT_PREFIX) && rootName.length > LIVE_OUTPUT_PREFIX.length;
}

/**
 * Replace known synthetic credentials first, then redact credential-shaped
 * input values from HTML snippets. The second pass protects failure contexts
 * that serialize a DOM value after a locator assertion has already failed.
 *
 * @param {unknown} value
 * @param {Iterable<string>} [secrets]
 * @returns {unknown}
 */
export function redactLiveText(value, secrets = liveCredentialValues()) {
  if (typeof value !== 'string') return value;
  let redacted = value;
  for (const secret of [...new Set(secrets)].filter((item) => item.length > 0).sort((a, b) => b.length - a.length)) {
    redacted = redacted.split(secret).join(LIVE_ARTIFACT_REDACTION);
  }

  redacted = redacted.replace(
    /(<(?:input|textarea)\b[^>]*\bvalue=)(["'])(.*?)\2/giu,
    (_match, prefix, quote) => `${prefix}${quote}${LIVE_ARTIFACT_REDACTION}${quote}`
  );
  redacted = redacted.replace(/(<textarea\b[^>]*>)[\s\S]*?(<\/textarea>)/giu, `$1${LIVE_ARTIFACT_REDACTION}$2`);
  redacted = redacted.replace(/(<select\b[^>]*>)[\s\S]*?(<\/select>)/giu, `$1${LIVE_ARTIFACT_REDACTION}$2`);
  return redacted.replace(
    /(<[a-z][^>]*\bcontenteditable(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?[^>]*>)[\s\S]*?(<\/[a-z][^>]*>)/giu,
    `$1${LIVE_ARTIFACT_REDACTION}$2`
  );
}

/**
 * Treat only an observed closed page or a known Playwright termination error as
 * safe to skip. A generic evaluate failure must remain visible to the test so
 * the teardown cannot silently pass with an unverified DOM scrub.
 *
 * @param {{ isClosed?: () => boolean } | undefined} page
 * @param {unknown} error
 * @returns {boolean}
 */
export function isDefinitivelyClosedOrCrashed(page, error) {
  try {
    if (typeof page?.isClosed === 'function' && page.isClosed()) return true;
  } catch {
    // If page state cannot be read, the error still needs a known termination
    // message before teardown may treat it as safe.
  }
  const errorRecord =
    error !== null && typeof error === 'object'
      ? /** @type {{ message?: unknown }} */ (error)
      : undefined;
  const message =
    typeof error === 'string' ? error : typeof errorRecord?.message === 'string' ? errorRecord.message : '';
  return LIVE_PAGE_TERMINATION_PATTERN.test(message);
}

/**
 * Mutate Playwright's structured error objects before a reporter can serialize
 * them. Diagnostic strings are redacted recursively, including nested
 * errorContext/matcherResult/ariaSnapshot values; source locations remain useful.
 *
 * @param {unknown} errors
 * @param {Iterable<string>} [secrets]
 * @param {Set<object>} [visited]
 * @returns {void}
 */
export function redactTestErrors(errors, secrets = liveCredentialValues(), visited = new Set()) {
  if (!Array.isArray(errors)) return;
  for (const error of errors) redactTestError(error, secrets, visited);
}

/**
 * @param {any} error
 * @param {Iterable<string>} secrets
 * @param {Set<object>} visited
 * @returns {void}
 */
function redactTestError(error, secrets, visited) {
  if (error === null || typeof error !== 'object' || visited.has(error)) return;
  visited.add(error);
  const directTextFields = new Set(['message', 'stack', 'snippet', 'value']);
  for (const field of directTextFields) {
    if (typeof error[field] === 'string') error[field] = redactLiveText(error[field], secrets);
    else if (error[field] && typeof error[field] === 'object') {
      error[field] = redactTestDiagnosticValue(error[field], secrets, visited);
    }
  }
  for (const [field, value] of Object.entries(error)) {
    if (directTextFields.has(field) || field === 'location') continue;
    error[field] = redactTestDiagnosticValue(value, secrets, visited);
  }
  // Error properties such as `cause` and Playwright's error context can be
  // non-enumerable in some serializers, so visit them explicitly as well.
  for (const field of ['cause', 'errorContext', 'matcherResult']) {
    if (field in error) error[field] = redactTestDiagnosticValue(error[field], secrets, visited);
  }
}

/**
 * @param {any} value
 * @param {Iterable<string>} secrets
 * @param {Set<object>} visited
 * @returns {any}
 */
function redactTestDiagnosticValue(value, secrets, visited) {
  if (typeof value === 'string') return redactLiveText(value, secrets);
  if (value === null || typeof value !== 'object' || visited.has(value)) return value;
  visited.add(value);
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      value[index] = redactTestDiagnosticValue(value[index], secrets, visited);
    }
    return value;
  }
  for (const [field, nestedValue] of Object.entries(value)) {
    if (field === 'location') continue;
    value[field] = redactTestDiagnosticValue(nestedValue, secrets, visited);
  }
  return value;
}

/**
 * Scrub every live form control before Playwright closes the page. This is a
 * last-resort boundary for DOM snapshots and manually attached diagnostics;
 * the live config separately disables screenshots, videos, and traces.
 *
 * @param {{ evaluate: (pageFunction: () => void) => Promise<unknown>, isClosed?: () => boolean }} page
 * @returns {Promise<void>}
 */
export async function scrubLivePage(page) {
  try {
    await page.evaluate(() => {
      const editableModes = new Set(['', 'true', 'plaintext-only']);
      for (const element of document.querySelectorAll('input, textarea, select, [contenteditable]')) {
        if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
          element.value = '';
          element.removeAttribute('value');
          if (element instanceof HTMLTextAreaElement) element.textContent = '';
        }
        if (element instanceof HTMLSelectElement) {
          element.selectedIndex = -1;
          // Remove option text and selected attributes too; selectedIndex alone
          // does not erase serialized option content from a later DOM dump.
          element.textContent = '';
        }
        const contentEditableMode = element.getAttribute('contenteditable')?.trim().toLowerCase() ?? null;
        if (
          element instanceof HTMLElement &&
          (element.isContentEditable ||
            (contentEditableMode !== null && editableModes.has(contentEditableMode)))
        )
          element.textContent = '';
      }
      if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
    });
  } catch (error) {
    if (!isDefinitivelyClosedOrCrashed(page, error)) throw error;
  }
}

/**
 * Remove a live output directory only when it is inside this run's unique
 * temporary root. Refusing other paths prevents cleanup from deleting an
 * unrelated developer or CI artifact directory.
 *
 * @param {string} directory
 * @returns {Promise<void>}
 */
export async function removeLiveArtifacts(directory) {
  if (!isLiveArtifactDirectory(directory)) return;
  await rm(resolve(directory), { recursive: true, force: true });
}
