import { randomBytes } from 'node:crypto';
import { lstatSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { basename, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

export const LIVE_ARTIFACT_REDACTION = '[redacted-live-credential]';
const LIVE_OUTPUT_PREFIX = 'hermternal-playwright-live-';
const LIVE_OUTPUT_OWNER_FILE = '.hermternal-live-artifact-owner';
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
const HTML_MALFORMED_TAG = -3;
function createLiveArtifactRoot() {
  const root = mkdtempSync(join(resolve(tmpdir()), LIVE_OUTPUT_PREFIX));
  const ownerToken = randomBytes(32).toString('hex');
  writeFileSync(join(root, LIVE_OUTPUT_OWNER_FILE), `${ownerToken}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600
  });
  return { root, ownerToken };
}

/** @type {{ root: string, ownerToken: string } | undefined} */
let liveArtifactRun;
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
 * @param {{ root: string, ownerToken: string }} run
 * @returns {boolean}
 */
function hasOwnedRootMarker(run) {
  try {
    const rootStats = lstatSync(run.root);
    const ownerPath = join(run.root, LIVE_OUTPUT_OWNER_FILE);
    const ownerStats = lstatSync(ownerPath);
    return (
      rootStats.isDirectory() &&
      !rootStats.isSymbolicLink() &&
      ownerStats.isFile() &&
      !ownerStats.isSymbolicLink() &&
      readFileSync(ownerPath, 'utf8') === `${run.ownerToken}\n`
    );
  } catch {
    return false;
  }
}

/**
 * Keep live Playwright output in a unique OS-temporary directory instead of
 * the repository's retained `test-results` path. The directory is created on
 * first use and recreated only after its exact run root has been removed.
 *
 * @returns {string}
 */
export function liveArtifactOutputDirectory() {
  if (!liveArtifactRun || !hasOwnedRootMarker(liveArtifactRun)) liveArtifactRun = createLiveArtifactRoot();
  return liveArtifactRun.root;
}

/**
 * @returns {string}
 */
export function liveArtifactOutputOwnershipToken() {
  liveArtifactOutputDirectory();
  if (!liveArtifactRun) throw new Error('live artifact output root unavailable');
  return liveArtifactRun.ownerToken;
}

/**
 * @returns {string}
 */
function liveArtifactCleanupRoot() {
  const configuredRoot = process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR;
  return typeof configuredRoot === 'string' && configuredRoot.length > 0
    ? resolve(configuredRoot)
    : liveArtifactOutputDirectory();
}

/**
 * Read the configured owner token only for the exact configured root. The
 * module-local root is used by unit tests; Playwright's global teardown uses
 * the explicit path and token exported through its process environment.
 *
 * @param {string} candidate
 * @returns {string | undefined}
 */
function ownerTokenFor(candidate) {
  if (liveArtifactRun && candidate === liveArtifactRun.root && hasOwnedRootMarker(liveArtifactRun)) {
    return liveArtifactRun.ownerToken;
  }
  const configuredRoot = process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR;
  const configuredToken = process.env.PLAYWRIGHT_LIVE_OUTPUT_TOKEN;
  if (
    typeof configuredRoot !== 'string' ||
    typeof configuredToken !== 'string' ||
    candidate !== resolve(configuredRoot)
  ) {
    return undefined;
  }
  return configuredToken;
}

/**
 * Validate the exact run root before deletion. Prefix matches, descendants,
 * symlink roots, and roots without the run-owned marker or run-bound token are
 * never accepted.
 *
 * @param {string} directory
 * @returns {boolean}
 */
export function isLiveArtifactDirectory(directory) {
  const candidate = resolve(directory);
  const pathFromTemporaryRoot = relative(resolve(tmpdir()), candidate);
  const [rootName, ...remainder] = pathFromTemporaryRoot.split(sep);
  if (
    !rootName ||
    remainder.length > 0 ||
    rootName !== basename(candidate) ||
    !rootName.startsWith(LIVE_OUTPUT_PREFIX)
  ) {
    return false;
  }
  const ownerToken = ownerTokenFor(candidate);
  if (!ownerToken) return false;
  try {
    const rootStats = lstatSync(candidate);
    if (!rootStats.isDirectory() || rootStats.isSymbolicLink()) return false;
    const ownerPath = join(candidate, LIVE_OUTPUT_OWNER_FILE);
    try {
      const ownerStats = lstatSync(ownerPath);
      if (!ownerStats.isFile() || ownerStats.isSymbolicLink()) return false;
      return readFileSync(ownerPath, 'utf8') === `${ownerToken}\n`;
    } catch {
      // A per-test cleanup can remove the root before Playwright recreates the
      // exact configured directory for its next test. The in-memory or
      // environment-passed owner token still binds this exact path to the run.
      return (
        (liveArtifactRun !== undefined && candidate === liveArtifactRun.root) ||
        candidate === resolve(process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR ?? '')
      );
    }
  } catch {
    return false;
  }
}

/**
 * Find the end of one HTML tag while respecting quoted attribute values.
 * A non-tag `<` is malformed rather than text that may be skipped, because
 * continuing from a later `>` could hide a subsequent editable credential.
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
  const firstCharacter = value[start + 1];
  if (firstCharacter !== '/' && !/[A-Za-z]/u.test(firstCharacter ?? '')) return HTML_MALFORMED_TAG;
  let quote = '';
  for (let index = start + 1; index < value.length; index += 1) {
    const character = value[index];
    if (character === '<') return HTML_MALFORMED_TAG;
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
  while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;
  const nameStart = cursor;
  if (!/[A-Za-z]/u.test(value[cursor] ?? '')) return undefined;
  cursor += 1;
  while (cursor < end && /[A-Za-z0-9:_-]/u.test(value[cursor])) cursor += 1;
  const name = value.slice(nameStart, cursor).toLowerCase();
  while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;

  if (closing) {
    return cursor === end ? { closing, name, selfClosing: false } : undefined;
  }

  const selfClosing = value[cursor] === '/';
  if (selfClosing) cursor += 1;
  while (cursor < end) {
    if (!/[A-Za-z_:]/u.test(value[cursor] ?? '')) {
      if (value[cursor] === '/' && cursor + 1 === end) {
        cursor += 1;
        break;
      }
      return undefined;
    }
    cursor += 1;
    while (cursor < end && /[A-Za-z0-9:._-]/u.test(value[cursor])) cursor += 1;
    while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;
    if (value[cursor] !== '=') continue;
    cursor += 1;
    while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;
    const quote = value[cursor];
    if (quote === '"' || quote === "'") {
      cursor += 1;
      while (cursor < end && value[cursor] !== quote) {
        if (value[cursor] === '<') return undefined;
        cursor += 1;
      }
      if (value[cursor] !== quote) return undefined;
      cursor += 1;
    } else {
      const valueStart = cursor;
      while (cursor < end && !/\s/u.test(value[cursor])) {
        if (/[<"'=]/u.test(value[cursor])) return undefined;
        cursor += 1;
      }
      if (cursor === valueStart) return undefined;
    }
    while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;
    if (cursor === end) break;
    if (value[cursor] === '/' && cursor + 1 === end) {
      cursor += 1;
      break;
    }
  }
  return cursor === end ? { closing, name, selfClosing } : undefined;
}

/**
 * @param {string} tag
 * @returns {boolean}
 */
function hasEditableContentAttribute(tag) {
  const match = /(?:^|[\s<])contenteditable(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/iu.exec(tag);
  if (!match) return false;
  const mode = (match[1] ?? match[2] ?? match[3] ?? '').trim().toLowerCase();
  // Unknown values are treated as potentially editable. Preserving their
  // contents would let a future browser mode or malformed serialization bypass
  // this last-resort artifact boundary; only explicit false is safe.
  return mode !== 'false';
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
    if (end === HTML_UNTERMINATED_COMMENT || end === HTML_MALFORMED_TAG) {
      return { malformedStart: opening };
    }
    if (end < 0) return { malformedStart: opening };
    const tag = parseHtmlTag(value, opening, end);
    if (!tag) {
      // A terminated non-comment construct is still unknown markup. Do not
      // jump to its closing `>` because that can skip an editable element.
      if (value.startsWith('<!--', opening)) {
        cursor = end + 1;
        continue;
      }
      return { malformedStart: opening };
    }
    if (!tag.closing && !tag.selfClosing && hasEditableContentAttribute(value.slice(opening, end + 1))) {
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
    if (end === HTML_UNTERMINATED_COMMENT || end === HTML_MALFORMED_TAG || end < 0) return undefined;
    const tag = parseHtmlTag(value, next, end);
    if (!tag) {
      if (value.startsWith('<!--', next)) {
        cursor = end + 1;
        continue;
      }
      return undefined;
    }
    if (tag.closing) {
      if (stack.at(-1) !== tag.name) return undefined;
      stack.pop();
      if (stack.length === 0) return { start: next, end };
    } else if (!tag.selfClosing && !HTML_VOID_ELEMENTS.has(tag.name)) {
      stack.push(tag.name);
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
 * @param {PropertyDescriptor | undefined} descriptor
 */
function validateDataDescriptor(descriptor) {
  if (
    !descriptor ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'writable') ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'enumerable') ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'configurable') ||
    Object.prototype.hasOwnProperty.call(descriptor, 'get') ||
    Object.prototype.hasOwnProperty.call(descriptor, 'set') ||
    typeof descriptor.writable !== 'boolean' ||
    typeof descriptor.enumerable !== 'boolean' ||
    typeof descriptor.configurable !== 'boolean'
  ) {
    throwRedactionFailure();
  }
}

/**
 * @param {PropertyDescriptor | undefined} descriptor
 */
function validateAccessorDescriptor(descriptor) {
  if (
    !descriptor ||
    Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
    Object.prototype.hasOwnProperty.call(descriptor, 'writable') ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'get') ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'set') ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'enumerable') ||
    !Object.prototype.hasOwnProperty.call(descriptor, 'configurable') ||
    (descriptor.get !== undefined && typeof descriptor.get !== 'function') ||
    (descriptor.set !== undefined && typeof descriptor.set !== 'function') ||
    typeof descriptor.enumerable !== 'boolean' ||
    typeof descriptor.configurable !== 'boolean'
  ) {
    throwRedactionFailure();
  }
}

/**
 * @param {PropertyDescriptor | undefined} actual
 * @param {PropertyDescriptor} expected
 * @returns {boolean}
 */
function sameDataDescriptor(actual, expected) {
  if (!actual) return false;
  return (
    Object.prototype.hasOwnProperty.call(actual, 'value') &&
    Object.prototype.hasOwnProperty.call(actual, 'writable') &&
    Object.prototype.hasOwnProperty.call(actual, 'enumerable') &&
    Object.prototype.hasOwnProperty.call(actual, 'configurable') &&
    Object.is(actual.value, expected.value) &&
    actual.writable === expected.writable &&
    actual.enumerable === expected.enumerable &&
    actual.configurable === expected.configurable
  );
}

/**
 * @param {PropertyDescriptor | undefined} actual
 * @param {PropertyDescriptor} expected
 * @returns {boolean}
 */
function sameAccessorDescriptor(actual, expected) {
  if (!actual) return false;
  return (
    !Object.prototype.hasOwnProperty.call(actual, 'value') &&
    !Object.prototype.hasOwnProperty.call(actual, 'writable') &&
    Object.prototype.hasOwnProperty.call(actual, 'get') &&
    Object.prototype.hasOwnProperty.call(actual, 'set') &&
    Object.prototype.hasOwnProperty.call(actual, 'enumerable') &&
    Object.prototype.hasOwnProperty.call(actual, 'configurable') &&
    actual.get === expected.get &&
    actual.set === expected.set &&
    actual.enumerable === expected.enumerable &&
    actual.configurable === expected.configurable
  );
}

/**
 * @param {object} target
 * @param {string | symbol} key
 * @param {PropertyDescriptor} descriptor
 * @param {unknown} value
 */
function writeDiagnosticValue(target, key, descriptor, value) {
  try {
    validateDataDescriptor(descriptor);
  } catch {
    throwRedactionFailure();
  }

  let observedDescriptor;
  let readBack;
  try {
    observedDescriptor = Reflect.getOwnPropertyDescriptor(target, key);
    readBack = Reflect.get(target, key);
  } catch {
    throwRedactionFailure();
  }
  if (
    !observedDescriptor ||
    (() => {
      try {
        validateDataDescriptor(observedDescriptor);
        return !sameDataDescriptor(observedDescriptor, descriptor) || !Object.is(readBack, descriptor.value);
      } catch {
        return true;
      }
    })()
  ) {
    throwRedactionFailure();
  }
  if (Object.is(value, descriptor.value)) return;
  if (descriptor.writable !== true) throwRedactionFailure();

  let didSet;
  try {
    didSet = Reflect.set(target, key, value);
    observedDescriptor = Reflect.getOwnPropertyDescriptor(target, key);
    readBack = Reflect.get(target, key);
  } catch {
    throwRedactionFailure();
  }
  if (
    didSet !== true ||
    !observedDescriptor ||
    (() => {
      try {
        validateDataDescriptor(observedDescriptor);
        return !sameDataDescriptor(observedDescriptor, { ...descriptor, value });
      } catch {
        return true;
      }
    })() ||
    !Object.is(readBack, value)
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
function verifyAccessorObservation(target, key, descriptor, value) {
  try {
    validateAccessorDescriptor(descriptor);
  } catch {
    throwRedactionFailure();
  }
  let observedDescriptor;
  let readBack;
  let getterReadBack;
  try {
    observedDescriptor = Reflect.getOwnPropertyDescriptor(target, key);
    readBack = Reflect.get(target, key);
    if (typeof descriptor.get === 'function') getterReadBack = Reflect.apply(descriptor.get, target, []);
  } catch {
    throwRedactionFailure();
  }
  try {
    validateAccessorDescriptor(observedDescriptor);
  } catch {
    throwRedactionFailure();
  }
  if (
    !sameAccessorDescriptor(observedDescriptor, descriptor) ||
    !Object.is(readBack, value) ||
    (typeof descriptor.get === 'function' && !Object.is(getterReadBack, value))
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
  try {
    validateAccessorDescriptor(descriptor);
  } catch {
    throwRedactionFailure();
  }
  let current;
  try {
    current = Reflect.get(target, key);
  } catch {
    throwRedactionFailure();
  }
  const redacted = redactTestDiagnosticValue(current, secrets, state, depth + 1);
  if (Object.is(redacted, current)) {
    verifyAccessorObservation(target, key, descriptor, current);
    return;
  }
  if (typeof descriptor.set !== 'function') throwRedactionFailure();
  let didSet;
  try {
    didSet = Reflect.set(target, key, redacted);
  } catch {
    throwRedactionFailure();
  }
  if (didSet !== true) throwRedactionFailure();
  verifyAccessorObservation(target, key, descriptor, redacted);
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
      await removeLiveArtifacts(liveArtifactCleanupRoot());
    } catch (error) {
      cleanupError ??= error;
    }
  }
  if (redactionError !== undefined) throw redactionError;
  if (scrubDiagnostics) throw scrubDiagnostics[0];
  if (cleanupError !== undefined) throw cleanupError;
}
