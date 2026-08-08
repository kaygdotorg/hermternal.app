import { rm } from 'node:fs/promises';
import { relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

export const LIVE_ARTIFACT_REDACTION = '[redacted-live-credential]';
const LIVE_OUTPUT_PREFIX = 'hermternal-playwright-live-';
const LIVE_DEFAULT_USERNAME = 'hermternal-test';
const LIVE_SECRET_ENV_NAMES = ['HERMES_TEST_USERNAME', 'HERMES_TEST_PASSWORD'];
const REDACTION_MAX_DEPTH = 16;
const REDACTION_MAX_NODES = 2048;
const REDACTION_MAX_STRINGS = 4096;
const REDACTION_MAX_STRING_LENGTH = 256 * 1024;
const REDACTION_MAX_TOTAL_STRING_LENGTH = 4 * 1024 * 1024;
const REDACTION_MAX_ARRAY_ITEMS = 512;
const REDACTION_MAX_PROPERTIES = 1024;
const REDACTION_BUDGET_MESSAGE = 'live artifact redaction budget exceeded';
const REDACTION_FAILURE_MESSAGE = 'live artifact redaction failed';
const HTML_UNTERMINATED_COMMENT = -2;
const EDITABLE_CONTENT_MODES = new Set(['', 'true', 'plaintext-only']);
const HTML_VOID_ELEMENTS = new Set([
  'area',
  'base',
  'br',
  'col',
  'embed',
  'hr',
  'img',
  'input',
  'link',
  'meta',
  'param',
  'source',
  'track',
  'wbr'
]);

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
 * Find the end of one HTML tag while respecting quoted attribute values.
 * Returning no boundary is intentionally fail-closed for editable markup.
 *
 * @param {string} value
 * @param {number} start
 * @returns {number}
 */
function findHtmlTagEnd(value, start) {
  if (value.startsWith('<!--', start)) {
    const commentEnd = value.indexOf('-->', start + 4);
    return commentEnd < 0 ? HTML_UNTERMINATED_COMMENT : commentEnd + 2;
  }
  let quote = '';
  for (let index = start + 1; index < value.length; index += 1) {
    const character = value[index];
    if (quote) {
      if (character === quote) quote = '';
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === '>') return index;
  }
  return -1;
}

/**
 * @param {string} value
 * @param {number} start
 * @param {number} end
 * @returns {{ closing: boolean, name: string, selfClosing: boolean } | undefined}
 */
function parseHtmlTag(value, start, end) {
  if (value.startsWith('<!--', start)) return undefined;
  let cursor = start + 1;
  let closing = false;
  if (value[cursor] === '/') {
    closing = true;
    cursor += 1;
  }
  if (value[cursor] === '!' || value[cursor] === '?') return undefined;
  while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;
  const nameStart = cursor;
  if (!/[A-Za-z]/u.test(value[cursor] ?? '')) return undefined;
  cursor += 1;
  while (cursor < end && /[A-Za-z0-9:_-]/u.test(value[cursor])) cursor += 1;
  const name = value.slice(nameStart, cursor).toLowerCase();
  return {
    closing,
    name,
    selfClosing: !closing && /\/\s*>$/u.test(value.slice(start, end + 1))
  };
}

/**
 * @param {string} tag
 * @returns {boolean}
 */
function hasEditableContentAttribute(tag) {
  const match = /(?:^|[\s<])contenteditable(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/iu.exec(tag);
  if (!match) return false;
  const mode = (match[1] ?? match[2] ?? match[3] ?? '').trim().toLowerCase();
  return EDITABLE_CONTENT_MODES.has(mode);
}

/**
 * @param {string} value
 * @param {number} start
 * @returns {{ start: number, end: number, tag: { closing: boolean, name: string, selfClosing: boolean } } | { malformedStart: number } | undefined}
 */
function findNextEditableOpening(value, start) {
  let cursor = start;
  while (cursor < value.length) {
    const opening = value.indexOf('<', cursor);
    if (opening < 0) return undefined;
    const end = findHtmlTagEnd(value, opening);
    if (end === HTML_UNTERMINATED_COMMENT) return { malformedStart: opening };
    if (end < 0) {
      return hasEditableContentAttribute(value.slice(opening)) ? { malformedStart: opening } : undefined;
    }
    const tag = parseHtmlTag(value, opening, end);
    if (tag && !tag.closing && !tag.selfClosing && hasEditableContentAttribute(value.slice(opening, end + 1))) {
      return { start: opening, end, tag };
    }
    cursor = end + 1;
  }
  return undefined;
}

/**
 * @param {string} value
 * @param {{ end: number, tag: { name: string } }} opening
 * @returns {{ start: number, end: number } | undefined}
 */
function findMatchingClosingTag(value, opening) {
  const stack = [opening.tag.name];
  let cursor = opening.end + 1;
  while (cursor < value.length) {
    const next = value.indexOf('<', cursor);
    if (next < 0) return undefined;
    const end = findHtmlTagEnd(value, next);
    if (end === HTML_UNTERMINATED_COMMENT || end < 0) return undefined;
    const tag = parseHtmlTag(value, next, end);
    if (tag) {
      if (tag.closing) {
        if (stack.at(-1) !== tag.name) return undefined;
        stack.pop();
        if (stack.length === 0) return { start: next, end };
      } else if (!tag.selfClosing && !HTML_VOID_ELEMENTS.has(tag.name)) {
        stack.push(tag.name);
      }
    }
    cursor = end + 1;
  }
  return undefined;
}

/**
 * Replace the contents of each valid contenteditable element using a balanced
 * tag scan. A regular expression cannot distinguish an inner `</div>` from
 * the matching close for an outer editable region, so an incomplete boundary
 * redacts the remainder instead of leaving an untrusted fragment behind.
 *
 * @param {string} value
 * @returns {string}
 */
function redactContentEditableMarkup(value) {
  let cursor = 0;
  let redacted = '';
  while (cursor < value.length) {
    const opening = findNextEditableOpening(value, cursor);
    if (!opening) {
      redacted += value.slice(cursor);
      break;
    }
    if ('malformedStart' in opening) {
      redacted += value.slice(cursor, opening.malformedStart);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    redacted += value.slice(cursor, opening.start);
    const closing = findMatchingClosingTag(value, opening);
    redacted += value.slice(opening.start, opening.end + 1);
    if (!closing) {
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    redacted += LIVE_ARTIFACT_REDACTION;
    redacted += value.slice(closing.start, closing.end + 1);
    cursor = closing.end + 1;
  }
  return redacted;
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
  if (value.length > REDACTION_MAX_STRING_LENGTH) throw new Error(REDACTION_BUDGET_MESSAGE);
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
  return redactContentEditableMarkup(redacted);
}

/**
 * Only an observed `page.isClosed() === true` result proves that teardown no
 * longer has a live DOM boundary. Error message text is never trusted because
 * a generic evaluator can report words such as "page crashed" while the page
 * remains open and readable.
 *
 * @param {{ isClosed?: () => boolean } | undefined} page
 * @returns {boolean}
 */
export function isDefinitivelyClosed(page) {
  try {
    return typeof page?.isClosed === 'function' && page.isClosed() === true;
  } catch {
    return false;
  }
}

/**
 * @typedef {{ visited: Set<object>, nodes: number, strings: number, totalStringLength: number, arrayItems: number, properties: number }} RedactionState
 */

/**
 * @returns {RedactionState}
 */
function createRedactionState() {
  return {
    visited: new Set(),
    nodes: 0,
    strings: 0,
    totalStringLength: 0,
    arrayItems: 0,
    properties: 0
  };
}

/**
 * @returns {never}
 */
function throwRedactionBudget() {
  throw new Error(REDACTION_BUDGET_MESSAGE);
}

/**
 * @returns {never}
 */
function throwRedactionFailure() {
  throw new Error(REDACTION_FAILURE_MESSAGE);
}

/**
 * @param {RedactionState} state
 * @param {number} depth
 */
function consumeRedactionNode(state, depth) {
  if (depth > REDACTION_MAX_DEPTH || state.nodes >= REDACTION_MAX_NODES) throwRedactionBudget();
  state.nodes += 1;
}

/**
 * @param {string} value
 * @param {Iterable<string>} secrets
 * @param {RedactionState} state
 * @returns {string}
 */
function redactBoundedString(value, secrets, state) {
  if (
    value.length > REDACTION_MAX_STRING_LENGTH ||
    state.strings >= REDACTION_MAX_STRINGS ||
    state.totalStringLength + value.length > REDACTION_MAX_TOTAL_STRING_LENGTH
  ) {
    throwRedactionBudget();
  }
  state.strings += 1;
  state.totalStringLength += value.length;
  return /** @type {string} */ (redactLiveText(value, secrets));
}

/**
 * @param {object} target
 * @param {string | symbol} key
 * @param {PropertyDescriptor} descriptor
 * @param {unknown} value
 */
function writeDiagnosticValue(target, key, descriptor, value) {
  if (Object.is(value, descriptor.value)) return;
  if (descriptor.writable !== true) throwRedactionFailure();
  let didSet;
  let updatedDescriptor;
  let readBack;
  try {
    didSet = Reflect.set(target, key, value);
    updatedDescriptor = Reflect.getOwnPropertyDescriptor(target, key);
    readBack = Reflect.get(target, key);
  } catch {
    throwRedactionFailure();
  }
  if (
    didSet !== true ||
    !updatedDescriptor ||
    !('value' in updatedDescriptor) ||
    !Object.is(updatedDescriptor.value, value) ||
    !Object.is(readBack, value) ||
    updatedDescriptor.writable !== descriptor.writable ||
    updatedDescriptor.enumerable !== descriptor.enumerable ||
    updatedDescriptor.configurable !== descriptor.configurable
  ) {
    throwRedactionFailure();
  }
}

/**
 * @param {object} target
 * @param {string | symbol} key
 * @param {PropertyDescriptor} descriptor
 * @param {unknown} value
 */
function verifyAccessorWrite(target, key, descriptor, value) {
  let updatedDescriptor;
  let readBack;
  try {
    updatedDescriptor = Reflect.getOwnPropertyDescriptor(target, key);
    readBack = Reflect.get(target, key);
  } catch {
    throwRedactionFailure();
  }
  if (
    !updatedDescriptor ||
    'value' in updatedDescriptor ||
    updatedDescriptor.get !== descriptor.get ||
    updatedDescriptor.set !== descriptor.set ||
    updatedDescriptor.enumerable !== descriptor.enumerable ||
    updatedDescriptor.configurable !== descriptor.configurable ||
    !Object.is(readBack, value)
  ) {
    throwRedactionFailure();
  }
}

/**
 * @param {object} target
 * @param {string | symbol} key
 * @param {PropertyDescriptor} descriptor
 * @param {Iterable<string>} secrets
 * @param {RedactionState} state
 * @param {number} depth
 */
function redactAccessorValue(target, key, descriptor, secrets, state, depth) {
  if (typeof descriptor.get !== 'function') return;
  let current;
  try {
    current = Reflect.get(target, key);
  } catch {
    throwRedactionFailure();
  }
  const redacted = redactTestDiagnosticValue(current, secrets, state, depth + 1);
  if (Object.is(redacted, current)) return;
  if (typeof descriptor.set !== 'function') throwRedactionFailure();
  let didSet;
  try {
    didSet = Reflect.set(target, key, redacted);
  } catch {
    throwRedactionFailure();
  }
  if (didSet !== true) throwRedactionFailure();
  verifyAccessorWrite(target, key, descriptor, redacted);
}

/**
 * Traverse own string and symbol properties, including non-enumerable native
 * Error fields. Cycles are skipped by identity; every other limit fails closed
 * so a reporter cannot serialize a partially redacted diagnostic graph.
 *
 * @param {any} value
 * @param {Iterable<string>} secrets
 * @param {RedactionState} state
 * @param {number} depth
 * @returns {any}
 */
function redactTestDiagnosticValue(value, secrets, state, depth) {
  if (typeof value === 'string') return redactBoundedString(value, secrets, state);
  if (value === null || typeof value !== 'object') return value;
  if (state.visited.has(value)) return value;
  consumeRedactionNode(state, depth);
  state.visited.add(value);

  /** @type {(string | symbol)[]} */
  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    throwRedactionFailure();
  }
  if (keys.length > REDACTION_MAX_PROPERTIES) throwRedactionBudget();
  if (Array.isArray(value)) {
    if (value.length > REDACTION_MAX_ARRAY_ITEMS || state.arrayItems + value.length > REDACTION_MAX_ARRAY_ITEMS) {
      throwRedactionBudget();
    }
    state.arrayItems += value.length;
  }

  for (const key of keys) {
    if (Array.isArray(value) && key === 'length') continue;
    if (key === 'location') continue;
    state.properties += 1;
    if (state.properties > REDACTION_MAX_PROPERTIES) throwRedactionBudget();
    /** @type {PropertyDescriptor | undefined} */
    let descriptor;
    try {
      descriptor = Reflect.getOwnPropertyDescriptor(value, key);
    } catch {
      throwRedactionFailure();
    }
    if (!descriptor) throwRedactionFailure();
    if ('value' in descriptor) {
      const redacted = redactTestDiagnosticValue(descriptor.value, secrets, state, depth + 1);
      writeDiagnosticValue(value, key, descriptor, redacted);
    } else {
      redactAccessorValue(value, key, descriptor, secrets, state, depth);
    }
  }
  return value;
}

/**
 * Mutate Playwright's structured error objects before a reporter can serialize
 * them. Own non-enumerable Error fields, nested causes, TestInfoError strings,
 * matcher results, and ARIA snapshots are all included in the bounded walk.
 *
 * @param {unknown} errors
 * @param {Iterable<string>} [secrets]
 * @returns {void}
 */
export function redactTestErrors(errors, secrets = liveCredentialValues()) {
  if (!Array.isArray(errors)) return;
  const state = createRedactionState();
  redactTestDiagnosticValue(errors, secrets, state, 0);
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
    if (!isDefinitivelyClosed(page)) throw error;
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

/**
 * Redact teardown diagnostics and always remove attachments/output. A redaction
 * failure wins over the original scrub failure so an unredacted error is never
 * rethrown; cleanup still runs from the `finally` block before propagation.
 *
 * @param {{ testInfo: { errors: unknown[], attachments: unknown[], outputDir: string }, scrubError?: unknown, secrets?: Iterable<string> }} options
 * @returns {Promise<void>}
 */
export async function finalizeLiveTest({ testInfo, scrubError, secrets = liveCredentialValues() }) {
  const scrubDiagnostics = scrubError === undefined ? undefined : [scrubError];
  let redactionError;
  let cleanupError;
  try {
    if (scrubDiagnostics) {
      try {
        redactTestErrors(scrubDiagnostics, secrets);
      } catch (error) {
        redactionError = error;
      }
    }
    try {
      redactTestErrors(testInfo.errors, secrets);
    } catch (error) {
      redactionError ??= error;
    }
  } finally {
    try {
      testInfo.attachments.length = 0;
    } catch (error) {
      cleanupError = error;
    }
    try {
      await removeLiveArtifacts(testInfo.outputDir);
    } catch (error) {
      cleanupError ??= error;
    }
  }
  if (redactionError !== undefined) throw redactionError;
  if (scrubDiagnostics) throw scrubDiagnostics[0];
  if (cleanupError !== undefined) throw cleanupError;
}
