import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';
import { lstatSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { promises as fsPromises } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { tmpdir } from 'node:os';

// Capture every ECMAScript intrinsic used by the redaction boundary while this
// worker-only module is preloaded. Test code is allowed to replace globals and
// prototype methods, but the transport guard must continue using these exact
// native functions. Calls below use the captured Reflect.apply rather than a
// mutable Function.prototype.call property.
const SAFE_ARRAY = Array;
const SAFE_ARRAY_IS_ARRAY = Array.isArray;
const SAFE_ARRAY_AT = Array.prototype.at;
const SAFE_ARRAY_FILTER = Array.prototype.filter;
const SAFE_ARRAY_JOIN = Array.prototype.join;
const SAFE_ARRAY_POP = Array.prototype.pop;
const SAFE_ARRAY_PUSH = Array.prototype.push;
const SAFE_ARRAY_REVERSE = Array.prototype.reverse;
const SAFE_ARRAY_SORT = Array.prototype.sort;
const SAFE_BUFFER_FROM = Buffer.from;
const SAFE_BUFFER_TO_STRING = Buffer.prototype.toString;
const SAFE_ERROR = Error;
const SAFE_AGGREGATE_ERROR = AggregateError;
const SAFE_MAP = Map;
const SAFE_MAP_GET = Map.prototype.get;
const SAFE_MAP_HAS = Map.prototype.has;
const SAFE_MAP_SET = Map.prototype.set;
const SAFE_MATH_FLOOR = Math.floor;
const SAFE_NUMBER_IS_SAFE_INTEGER = Number.isSafeInteger;
const SAFE_OBJECT_CREATE = Object.create;
const SAFE_OBJECT_DEFINE_PROPERTY = Object.defineProperty;
const SAFE_OBJECT_FREEZE = Object.freeze;
const SAFE_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR = Object.getOwnPropertyDescriptor;
const SAFE_OBJECT_IS = Object.is;
const SAFE_OBJECT_HAS_OWN_PROPERTY = Object.prototype.hasOwnProperty;
const SAFE_REFLECT_APPLY = Reflect.apply;
const SAFE_REFLECT_GET = Reflect.get;
const SAFE_REFLECT_GET_OWN_PROPERTY_DESCRIPTOR = Reflect.getOwnPropertyDescriptor;
const SAFE_REFLECT_OWN_KEYS = Reflect.ownKeys;
const SAFE_REGEXP_TEST = RegExp.prototype.test;
const SAFE_SET = Set;
const SAFE_SET_ADD = Set.prototype.add;
const SAFE_SET_DELETE = Set.prototype.delete;
const SAFE_SET_HAS = Set.prototype.has;
const SAFE_STRING = String;
const SAFE_STRING_INDEX_OF = String.prototype.indexOf;
const SAFE_STRING_SLICE = String.prototype.slice;
const SAFE_STRING_SPLIT = String.prototype.split;
const SAFE_STRING_STARTS_WITH = String.prototype.startsWith;
const SAFE_STRING_TO_LOWER_CASE = String.prototype.toLowerCase;
const SAFE_STRING_TRIM = String.prototype.trim;
const SAFE_SYMBOL_SPECIES = Symbol.species;

/**
 * Invoke a captured intrinsic without consulting mutable function prototypes.
 *
 * @param {Function} method
 * @param {unknown} receiver
 * @param {unknown[]} [argumentsList]
 * @returns {unknown}
 */
function trustedApply(method, receiver, argumentsList = []) {
  return SAFE_REFLECT_APPLY(method, receiver, argumentsList);
}

/**
 * @param {object} target
 * @param {PropertyKey} key
 * @returns {boolean}
 */
function trustedHasOwn(target, key) {
  return /** @type {boolean} */ (trustedApply(SAFE_OBJECT_HAS_OWN_PROPERTY, target, [key]));
}

/**
 * Copy a finite array without consulting its iterator or mutable Set methods.
 * The preload guard passes arrays, and rejecting other shapes keeps a hostile
 * iterable from executing code inside the redaction boundary.
 *
 * @param {unknown} values
 * @returns {unknown[]}
 */
function trustedArrayCopy(values) {
  if (!SAFE_ARRAY_IS_ARRAY(values)) throw new SAFE_ERROR(REDACTION_FAILURE_MESSAGE);
  const copy = new SAFE_ARRAY();
  for (let index = 0; index < values.length; index += 1) {
    trustedApply(SAFE_ARRAY_PUSH, copy, [values[index]]);
  }
  return copy;
}

/**
 * @param {unknown[]} values
 * @returns {unknown[]}
 */
function trustedUniqueArray(values) {
  const seen = new SAFE_SET();
  const unique = new SAFE_ARRAY();
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (trustedApply(SAFE_SET_HAS, seen, [value])) continue;
    trustedApply(SAFE_SET_ADD, seen, [value]);
    trustedApply(SAFE_ARRAY_PUSH, unique, [value]);
  }
  return unique;
}

/**
 * @param {string} value
 * @param {number} start
 * @param {number} [end]
 * @returns {string}
 */
function trustedStringSlice(value, start, end) {
  return /** @type {string} */ (trustedApply(SAFE_STRING_SLICE, value, [start, end]));
}

/**
 * @param {string} value
 * @param {string} search
 * @param {number} [position]
 * @returns {number}
 */
function trustedStringIndexOf(value, search, position) {
  return /** @type {number} */ (trustedApply(SAFE_STRING_INDEX_OF, value, [search, position]));
}

/**
 * @param {string} value
 * @param {string} search
 * @param {number} [position]
 * @returns {boolean}
 */
function trustedStringStartsWith(value, search, position) {
  return /** @type {boolean} */ (trustedApply(SAFE_STRING_STARTS_WITH, value, [search, position]));
}

/**
 * @param {string} value
 * @returns {string}
 */
function trustedStringLowerCase(value) {
  return /** @type {string} */ (trustedApply(SAFE_STRING_TO_LOWER_CASE, value));
}

/**
 * @param {string} value
 * @returns {string}
 */
function trustedStringTrim(value) {
  return /** @type {string} */ (trustedApply(SAFE_STRING_TRIM, value));
}

/**
 * @param {string} value
 * @param {string} separator
 * @returns {string[]}
 */
function trustedStringSplit(value, separator) {
  return /** @type {string[]} */ (trustedApply(SAFE_STRING_SPLIT, value, [separator]));
}

/**
 * @param {unknown[]} value
 * @param {string} separator
 * @returns {string}
 */
function trustedArrayJoin(value, separator) {
  return /** @type {string} */ (trustedApply(SAFE_ARRAY_JOIN, value, [separator]));
}

/**
 * @param {unknown} secrets
 * @returns {string[]}
 */
function trustedSortedSecrets(secrets) {
  const copied = trustedArrayCopy(secrets);
  /** @type {string[]} */
  const filtered = new SAFE_ARRAY();
  for (let index = 0; index < copied.length; index += 1) {
    const secret = copied[index];
    if (typeof secret === 'string' && secret.length > 0) {
      trustedApply(SAFE_ARRAY_PUSH, filtered, [secret]);
    }
  }
  trustedApply(SAFE_ARRAY_SORT, filtered, [
    /**
     * @param {string} a
     * @param {string} b
     * @returns {number}
     */
    (a, b) => b.length - a.length
  ]);
  return /** @type {string[]} */ (filtered);
}

/**
 * @param {RegExp} expression
 * @param {string} value
 * @returns {boolean}
 */
function trustedRegExpTest(expression, value) {
  return /** @type {boolean} */ (trustedApply(SAFE_REGEXP_TEST, expression, [value]));
}

export const LIVE_ARTIFACT_REDACTION = '[redacted-live-credential]';
const LIVE_OUTPUT_PREFIX = 'hermternal-playwright-live-';
const LIVE_OUTPUT_OWNER_FILE = '.hermternal-live-artifact-owner';
const LIVE_DEFAULT_USERNAME = 'hermternal-test';
const LIVE_SECRET_ENV_NAMES = ['HERMES_TEST_USERNAME', 'HERMES_TEST_PASSWORD'];
const PRELOADED_LIVE_CREDENTIAL_VALUES = SAFE_OBJECT_FREEZE(
  trustedUniqueArray([
    LIVE_DEFAULT_USERNAME,
    ...LIVE_SECRET_ENV_NAMES
      .map((name) => process.env[name])
      .filter((value) => typeof value === 'string' && value.length > 0)
  ])
);
const REDACTION_MAX_DEPTH = 16;
const REDACTION_MAX_NODES = 2048;
const REDACTION_MAX_STRINGS = 4096;
const REDACTION_MAX_STRING_LENGTH = 256 * 1024;
const REDACTION_MAX_TOTAL_STRING_LENGTH = 4 * 1024 * 1024;
const REDACTION_MAX_ARRAY_ITEMS = 512;
const REDACTION_MAX_PROPERTIES = 1024;
const REDACTION_MAX_BINARY_BYTES = /** @type {number} */ (
  trustedApply(SAFE_MATH_FLOOR, undefined, [REDACTION_MAX_STRING_LENGTH * 3 / 4])
);
const REDACTION_MAX_BINARY_PATTERNS = 256;
const REDACTION_BUDGET_MESSAGE = 'live artifact redaction budget exceeded';
const REDACTION_FAILURE_MESSAGE = 'live artifact redaction failed';
const LIVE_BINARY_REDACTION = /** @type {string} */ (
  trustedApply(SAFE_BUFFER_TO_STRING, trustedApply(SAFE_BUFFER_FROM, Buffer, [LIVE_ARTIFACT_REDACTION, 'utf8']), ['base64'])
);
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
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
const HTML_VOID_ELEMENTS = new SAFE_SET([
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
 * Return the immutable credential snapshot captured when this worker module was
 * preloaded. An explicit environment remains available for deterministic unit
 * tests, but the default finalizer path never reads a worker-mutated env object.
 *
 * @param {Record<string, string | undefined>} [environment]
 * @returns {string[]}
 */
export function liveCredentialValues(environment) {
  if (environment === undefined) {
    return /** @type {string[]} */ (trustedArrayCopy(PRELOADED_LIVE_CREDENTIAL_VALUES));
  }
  const values = [LIVE_DEFAULT_USERNAME];
  for (let index = 0; index < LIVE_SECRET_ENV_NAMES.length; index += 1) {
    const name = LIVE_SECRET_ENV_NAMES[index];
    const value = environment[name];
    if (typeof value === 'string' && value.length > 0) {
      trustedApply(SAFE_ARRAY_PUSH, values, [value]);
    }
  }
  return /** @type {string[]} */ (trustedUniqueArray(values));
}

/**
 * Reject Playwright's debug modes before it can replace worker IPC with direct
 * stderr inheritance or switch the browser to a headed/UI launch. The live lane
 * promises detached, redacted diagnostics and deterministic headless capture.
 *
 * @param {Record<string, string | undefined>} [environment]
 */
export function assertLiveRunnerDebugDisabled(environment = process.env) {
  if (environment.PW_RUNNER_DEBUG) {
    throw new SAFE_ERROR('PW_RUNNER_DEBUG is incompatible with the credential-redacted live lane');
  }
  if (environment.PWDEBUG) {
    throw new SAFE_ERROR('PWDEBUG is incompatible with the deterministic headless live lane');
  }
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
  if (liveArtifactRun && hasOwnedRootMarker(liveArtifactRun)) return liveArtifactRun.root;

  // Playwright deserializes the config in each worker process. Adopt the exact
  // parent-created root only when its inherited token and marker still match;
  // never create a fresh root in a worker and silently split one run across
  // retries or sequential workers.
  const configuredRoot = process.env.PLAYWRIGHT_LIVE_OUTPUT_DIR;
  const configuredToken = process.env.PLAYWRIGHT_LIVE_OUTPUT_TOKEN;
  if (configuredRoot !== undefined || configuredToken !== undefined) {
    if (typeof configuredRoot === 'string' && typeof configuredToken === 'string') {
      const configuredRun = { root: resolve(configuredRoot), ownerToken: configuredToken };
      if (hasOwnedRootMarker(configuredRun)) {
        liveArtifactRun = configuredRun;
        return configuredRun.root;
      }
    }
    throw new SAFE_ERROR('live artifact output root ownership could not be validated');
  }

  liveArtifactRun = createLiveArtifactRoot();
  return liveArtifactRun.root;
}

/**
 * @returns {string}
 */
export function liveArtifactOutputOwnershipToken() {
  liveArtifactOutputDirectory();
  if (!liveArtifactRun) throw new SAFE_ERROR('live artifact output root unavailable');
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
  const [rootName, ...remainder] = trustedStringSplit(pathFromTemporaryRoot, sep);
  if (
    !rootName ||
    remainder.length > 0 ||
    rootName !== basename(candidate) ||
    !trustedStringStartsWith(rootName, LIVE_OUTPUT_PREFIX)
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
    } catch (error) {
      // A missing marker is never ownership evidence. The exact path may have
      // been removed and recreated by another process, so markerless roots are
      // refused even when the path still matches this run's configured root.
      if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return false;
      throw new SAFE_ERROR('live artifact ownership inspection failed');
    }
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return false;
    throw new SAFE_ERROR('live artifact ownership inspection failed');
  }
}

/**
 * Capture the ownership proof and inode identity used for an atomic cleanup
 * handoff. The evidence is intentionally read again after the public path
 * check, so a later rename can be compared with the exact directory observed.
 *
 * @typedef {{ candidate: string, ownerToken: string, dev: number, ino: number }} LiveArtifactEvidence
 *
 * @param {string} directory
 * @returns {LiveArtifactEvidence | undefined}
 */
function liveArtifactEvidence(directory) {
  const candidate = resolve(directory);
  if (!isLiveArtifactDirectory(candidate)) return undefined;
  const ownerToken = ownerTokenFor(candidate);
  if (!ownerToken) return undefined;
  try {
    const rootStats = lstatSync(candidate);
    const ownerPath = join(candidate, LIVE_OUTPUT_OWNER_FILE);
    const ownerStats = lstatSync(ownerPath);
    if (
      !rootStats.isDirectory() ||
      rootStats.isSymbolicLink() ||
      !ownerStats.isFile() ||
      ownerStats.isSymbolicLink() ||
      readFileSync(ownerPath, 'utf8') !== `${ownerToken}\n`
    ) {
      return undefined;
    }
    return { candidate, ownerToken, dev: rootStats.dev, ino: rootStats.ino };
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return undefined;
    throw new SAFE_ERROR('live artifact ownership inspection failed');
  }
}

/**
 * Verify a quarantined directory without trusting its new path. Both the
 * original directory identity and its run-owned marker must still match before
 * bounded cleanup is permitted.
 *
 * @param {string} quarantinePath
 * @param {LiveArtifactEvidence} evidence
 * @returns {boolean}
 */
function isVerifiedQuarantine(quarantinePath, evidence) {
  try {
    const rootStats = lstatSync(quarantinePath);
    const ownerPath = join(quarantinePath, LIVE_OUTPUT_OWNER_FILE);
    const ownerStats = lstatSync(ownerPath);
    return (
      rootStats.isDirectory() &&
      !rootStats.isSymbolicLink() &&
      rootStats.dev === evidence.dev &&
      rootStats.ino === evidence.ino &&
      ownerStats.isFile() &&
      !ownerStats.isSymbolicLink() &&
      readFileSync(ownerPath, 'utf8') === `${evidence.ownerToken}\n`
    );
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return false;
    throw new SAFE_ERROR('live artifact quarantine inspection failed');
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
  if (trustedStringStartsWith(value, '<!--', start)) {
    const commentEnd = trustedStringIndexOf(value,'-->', start + 4);
    return commentEnd < 0 ? HTML_UNTERMINATED_COMMENT : commentEnd + 2;
  }
  const firstCharacter = value[start + 1];
  if (firstCharacter !== '/' && !trustedRegExpTest(/[A-Za-z]/u, firstCharacter ?? '')) return HTML_MALFORMED_TAG;
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
 * @typedef {{ name: string, value: string | undefined, valueStart: number | undefined, valueEnd: number | undefined, quote: string | undefined }} HtmlAttribute
 * @typedef {{ closing: boolean, name: string, selfClosing: boolean, ambiguous: boolean, attributes: HtmlAttribute[] }} HtmlTag
 */

/**
 * Parse a tag's actual attributes. Attribute text inside quoted values is never
 * interpreted as markup, duplicate attributes are marked ambiguous, and any
 * malformed boundary fails closed before it can be used for redaction.
 *
 * @param {string} value
 * @param {number} start
 * @param {number} end
 * @returns {HtmlTag | undefined}
 */
function parseHtmlTag(value, start, end) {
  if (trustedStringStartsWith(value, '<!--', start)) return undefined;
  let cursor = start + 1;
  let closing = false;
  if (value[cursor] === '/') {
    closing = true;
    cursor += 1;
  }
  if (value[cursor] === '!' || value[cursor] === '?') return undefined;
  while (cursor < end && trustedRegExpTest(/\s/u, value[cursor])) cursor += 1;
  const nameStart = cursor;
  if (!trustedRegExpTest(/[A-Za-z]/u, value[cursor] ?? '')) return undefined;
  cursor += 1;
  while (cursor < end && trustedRegExpTest(/[A-Za-z0-9:_-]/u, value[cursor])) cursor += 1;
  const name = trustedStringLowerCase(trustedStringSlice(value, nameStart, cursor));
  while (cursor < end && trustedRegExpTest(/\s/u, value[cursor])) cursor += 1;

  if (closing) {
    return cursor === end
      ? { closing, name, selfClosing: false, ambiguous: false, attributes: [] }
      : undefined;
  }

  /** @type {HtmlAttribute[]} */
  const attributes = [];
  const seenNames = new SAFE_SET();
  let ambiguous = false;
  let selfClosing = false;
  while (cursor < end) {
    if (value[cursor] === '/') {
      cursor += 1;
      while (cursor < end && trustedRegExpTest(/\s/u, value[cursor])) cursor += 1;
      if (cursor !== end) return undefined;
      selfClosing = true;
      break;
    }
    if (!trustedRegExpTest(/[A-Za-z_:]/u, value[cursor] ?? '')) return undefined;
    const attributeStart = cursor;
    cursor += 1;
    while (cursor < end && trustedRegExpTest(/[A-Za-z0-9:._-]/u, value[cursor])) cursor += 1;
    const attributeName = trustedStringLowerCase(trustedStringSlice(value, attributeStart, cursor));
    if (trustedApply(SAFE_SET_HAS, seenNames, [attributeName])) ambiguous = true;
    trustedApply(SAFE_SET_ADD, seenNames, [attributeName]);
    while (cursor < end && trustedRegExpTest(/\s/u, value[cursor])) cursor += 1;

    let attributeValue;
    let valueStart;
    let valueEnd;
    let quote;
    if (value[cursor] === '=') {
      cursor += 1;
      while (cursor < end && trustedRegExpTest(/\s/u, value[cursor])) cursor += 1;
      if (cursor >= end) return undefined;
      quote = value[cursor] === '"' || value[cursor] === "'" ? value[cursor] : undefined;
      if (quote) {
        valueStart = cursor + 1;
        cursor += 1;
        while (cursor < end && value[cursor] !== quote) {
          if (value[cursor] === '<') return undefined;
          cursor += 1;
        }
        if (value[cursor] !== quote) return undefined;
        valueEnd = cursor;
        attributeValue = trustedStringSlice(value,valueStart, valueEnd);
        cursor += 1;
      } else {
        valueStart = cursor;
        while (cursor < end && !trustedRegExpTest(/\s/u, value[cursor])) {
          if (trustedRegExpTest(/[<"'=]/u, value[cursor])) return undefined;
          cursor += 1;
        }
        if (cursor === valueStart) return undefined;
        valueEnd = cursor;
        attributeValue = trustedStringSlice(value,valueStart, valueEnd);
      }
    }
    trustedApply(SAFE_ARRAY_PUSH, attributes, [{
      name: attributeName,
      value: attributeValue,
      valueStart,
      valueEnd,
      quote
    }]);
    while (cursor < end && trustedRegExpTest(/\s/u, value[cursor])) cursor += 1;
  }

  return { closing, name, selfClosing, ambiguous, attributes };
}

/**
 * @param {HtmlTag} tag
 * @returns {boolean}
 */
function hasEditableContentAttribute(tag) {
  const matches = /** @type {HtmlAttribute[]} */ (
    trustedApply(SAFE_ARRAY_FILTER, tag.attributes, [
      /** @param {HtmlAttribute} attribute */
      (attribute) => attribute.name === 'contenteditable'
    ])
  );
  if (matches.length !== 1) return matches.length > 0;
  const mode = trustedStringLowerCase(trustedStringTrim(matches[0].value ?? ''));
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
    const opening = trustedStringIndexOf(value,'<', cursor);
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
      if (trustedStringStartsWith(value, '<!--', opening)) {
        cursor = end + 1;
        continue;
      }
      return { malformedStart: opening };
    }
    if (tag.ambiguous) return { malformedStart: opening };
    if (!tag.closing && !tag.selfClosing && hasEditableContentAttribute(tag)) {
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
    const next = trustedStringIndexOf(value,'<', cursor);
    if (next < 0) return undefined;
    const end = findHtmlTagEnd(value, next);
    if (end === HTML_UNTERMINATED_COMMENT || end === HTML_MALFORMED_TAG || end < 0) return undefined;
    const tag = parseHtmlTag(value, next, end);
    if (!tag) {
      if (trustedStringStartsWith(value, '<!--', next)) {
        cursor = end + 1;
        continue;
      }
      return undefined;
    }
    if (tag.ambiguous) return undefined;
    if (tag.closing) {
      if (trustedApply(SAFE_ARRAY_AT, stack, [-1]) !== tag.name) return undefined;
      trustedApply(SAFE_ARRAY_POP, stack);
      if (stack.length === 0) return { start: next, end };
    } else if (!tag.selfClosing && !trustedApply(SAFE_SET_HAS, HTML_VOID_ELEMENTS, [tag.name])) {
      trustedApply(SAFE_ARRAY_PUSH, stack, [tag.name]);
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
      redacted += trustedStringSlice(value,cursor);
      break;
    }
    if ('malformedStart' in opening) {
      redacted += trustedStringSlice(value,cursor, opening.malformedStart);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    redacted += trustedStringSlice(value,cursor, opening.start);
    const closing = findMatchingClosingTag(value, opening);
    redacted += trustedStringSlice(value,opening.start, opening.end + 1);
    if (!closing) {
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    redacted += LIVE_ARTIFACT_REDACTION;
    redacted += trustedStringSlice(value,closing.start, closing.end + 1);
    cursor = closing.end + 1;
  }
  return redacted;
}

/**
 * @param {string} value
 * @param {number} start
 * @returns {{ start: number, end: number, tag: HtmlTag } | { malformedStart: number } | undefined}
 */
function findNextStructuredFormOpening(value, start) {
  let cursor = start;
  while (cursor < value.length) {
    const opening = trustedStringIndexOf(value,'<', cursor);
    if (opening < 0) return undefined;
    const end = findHtmlTagEnd(value, opening);
    if (end === HTML_UNTERMINATED_COMMENT || end === HTML_MALFORMED_TAG || end < 0) {
      return { malformedStart: opening };
    }
    const tag = parseHtmlTag(value, opening, end);
    if (!tag) return { malformedStart: opening };
    if (tag.ambiguous) return { malformedStart: opening };
    if (!tag.closing && (tag.name === 'textarea' || tag.name === 'select')) {
      if (tag.selfClosing) return { malformedStart: opening };
      return { start: opening, end, tag };
    }
    cursor = end + 1;
  }
  return undefined;
}

/**
 * Raw-text textarea content has no nested markup boundary that can be trusted
 * in a serialized diagnostic. Any markup-like token, comment, malformed tag,
 * mismatched close, or missing close fails closed instead of allowing a later
 * credential to remain observable.
 *
 * @param {string} value
 * @param {{ end: number, tag: HtmlTag }} opening
 * @returns {{ start: number, end: number } | undefined}
 */
function findTextareaClosingTag(value, opening) {
  let cursor = opening.end + 1;
  while (cursor < value.length) {
    const next = trustedStringIndexOf(value,'<', cursor);
    if (next < 0) return undefined;
    const end = findHtmlTagEnd(value, next);
    if (end === HTML_UNTERMINATED_COMMENT || end === HTML_MALFORMED_TAG || end < 0) {
      return undefined;
    }
    const tag = parseHtmlTag(value, next, end);
    if (!tag || tag.ambiguous || !tag.closing || tag.name !== opening.tag.name || tag.attributes.length > 0) {
      return undefined;
    }
    return { start: next, end };
  }
  return undefined;
}

/**
 * Select content is validated as a small tag grammar before it is replaced.
 * Only option/optgroup nesting is accepted; comments, unknown nested tags,
 * mismatched closes, raw-text `<` tokens, and unclosed elements fail closed.
 *
 * @param {string} value
 * @param {{ end: number, tag: HtmlTag }} opening
 * @returns {{ start: number, end: number } | undefined}
 */
function findSelectClosingTag(value, opening) {
  const stack = ['select'];
  let cursor = opening.end + 1;
  while (cursor < value.length) {
    const next = trustedStringIndexOf(value,'<', cursor);
    if (next < 0) return undefined;
    const end = findHtmlTagEnd(value, next);
    if (end === HTML_UNTERMINATED_COMMENT || end === HTML_MALFORMED_TAG || end < 0) {
      return undefined;
    }
    const tag = parseHtmlTag(value, next, end);
    if (!tag || tag.ambiguous || tag.selfClosing) return undefined;
    const parent = trustedApply(SAFE_ARRAY_AT, stack, [-1]);
    if (tag.closing) {
      if (tag.attributes.length > 0 || parent !== tag.name) return undefined;
      trustedApply(SAFE_ARRAY_POP, stack);
      if (stack.length === 0) return { start: next, end };
    } else {
      const allowed =
        (parent === 'select' && (tag.name === 'option' || tag.name === 'optgroup')) ||
        (parent === 'optgroup' && tag.name === 'option');
      if (!allowed) return undefined;
      trustedApply(SAFE_ARRAY_PUSH, stack, [tag.name]);
    }
    cursor = end + 1;
  }
  return undefined;
}

/**
 * Redact textarea and select contents only after validating their serialized
 * boundaries. Replacing the entire user-controlled body also removes unknown
 * option text and values, while structural validation prevents comments or a
 * premature closing tag from hiding a later credential.
 *
 * @param {string} value
 * @returns {string}
 */
function redactStructuredFormMarkup(value) {
  let cursor = 0;
  let redacted = '';
  while (cursor < value.length) {
    const opening = findNextStructuredFormOpening(value, cursor);
    if (!opening) {
      redacted += trustedStringSlice(value,cursor);
      break;
    }
    if ('malformedStart' in opening) {
      redacted += trustedStringSlice(value,cursor, opening.malformedStart);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    redacted += trustedStringSlice(value,cursor, opening.start);
    const closing =
      opening.tag.name === 'textarea'
        ? findTextareaClosingTag(value, opening)
        : findSelectClosingTag(value, opening);
    redacted += trustedStringSlice(value,opening.start, opening.end + 1);
    if (!closing) {
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    redacted += LIVE_ARTIFACT_REDACTION;
    redacted += trustedStringSlice(value,closing.start, closing.end + 1);
    cursor = closing.end + 1;
  }
  return redacted;
}

/**
 * Redact every actual `value` attribute, including unquoted values and values
 * not present in the known secret list. Attribute positions come from the
 * structured tag parser, so text such as `data-note="value=secret"` cannot be
 * mistaken for an input attribute. Any ambiguous or malformed tag redacts the
 * remainder instead of preserving a possibly serialized credential.
 *
 * @param {string} value
 * @returns {string}
 */
function redactSerializedValueAttributes(value) {
  let cursor = 0;
  let redacted = '';
  while (cursor < value.length) {
    const opening = trustedStringIndexOf(value,'<', cursor);
    if (opening < 0) {
      redacted += trustedStringSlice(value,cursor);
      break;
    }
    const end = findHtmlTagEnd(value, opening);
    if (end === HTML_UNTERMINATED_COMMENT) {
      redacted += trustedStringSlice(value,cursor, opening);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    if (end === HTML_MALFORMED_TAG || end < 0) {
      redacted += trustedStringSlice(value,cursor, opening);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    const tag = parseHtmlTag(value, opening, end);
    if (!tag) {
      if (trustedStringStartsWith(value, '<!--', opening)) {
        redacted += trustedStringSlice(value,cursor, end + 1);
        cursor = end + 1;
        continue;
      }
      redacted += trustedStringSlice(value,cursor, opening);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    if (tag.ambiguous) {
      redacted += trustedStringSlice(value,cursor, opening);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    let redactedTag = trustedStringSlice(value,opening, end + 1);
    const valueAttributes = /** @type {HtmlAttribute[]} */ (
      trustedApply(SAFE_ARRAY_FILTER, tag.attributes, [
        /** @param {HtmlAttribute} attribute */
        (attribute) =>
          attribute.name === 'value' &&
          attribute.valueStart !== undefined &&
          attribute.valueEnd !== undefined
      ])
    );
    const reversedValueAttributes = /** @type {HtmlAttribute[]} */ (
      trustedApply(SAFE_ARRAY_REVERSE, valueAttributes)
    );
    for (let index = 0; index < reversedValueAttributes.length; index += 1) {
      const attribute = reversedValueAttributes[index];
      const localStart = /** @type {number} */ (attribute.valueStart) - opening;
      const localEnd = /** @type {number} */ (attribute.valueEnd) - opening;
      redactedTag = `${trustedStringSlice(redactedTag, 0, localStart)}${LIVE_ARTIFACT_REDACTION}${trustedStringSlice(redactedTag, localEnd)}`;
    }
    redacted += trustedStringSlice(value,cursor, opening);
    redacted += redactedTag;
    cursor = end + 1;
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
  if (value.length > REDACTION_MAX_STRING_LENGTH) throw new SAFE_ERROR(REDACTION_BUDGET_MESSAGE);
  let redacted = value;
  const sortedSecrets = trustedSortedSecrets(secrets);
  for (let index = 0; index < sortedSecrets.length; index += 1) {
    const secret = sortedSecrets[index];
    redacted = trustedArrayJoin(
      trustedStringSplit(redacted, secret),
      LIVE_ARTIFACT_REDACTION
    );
  }

  redacted = redactSerializedValueAttributes(redacted);
  redacted = redactStructuredFormMarkup(redacted);
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
 * @typedef {{ active: Set<object>, snapshots: Map<object, unknown>, nodes: number, strings: number, totalStringLength: number, arrayItems: number, properties: number }} RedactionState
 */

/**
 * @returns {RedactionState}
 */
function createRedactionState() {
  return {
    active: new SAFE_SET(),
    snapshots: new SAFE_MAP(),
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
  throw new SAFE_ERROR(REDACTION_BUDGET_MESSAGE);
}

/**
 * @returns {never}
 */
function throwRedactionFailure() {
  throw new SAFE_ERROR(REDACTION_FAILURE_MESSAGE);
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
    !trustedHasOwn(descriptor, 'value') ||
    !trustedHasOwn(descriptor, 'writable') ||
    !trustedHasOwn(descriptor, 'enumerable') ||
    !trustedHasOwn(descriptor, 'configurable') ||
    trustedHasOwn(descriptor, 'get') ||
    trustedHasOwn(descriptor, 'set') ||
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
    trustedHasOwn(descriptor, 'value') ||
    trustedHasOwn(descriptor, 'writable') ||
    !trustedHasOwn(descriptor, 'get') ||
    !trustedHasOwn(descriptor, 'set') ||
    !trustedHasOwn(descriptor, 'enumerable') ||
    !trustedHasOwn(descriptor, 'configurable') ||
    (descriptor.get !== undefined && typeof descriptor.get !== 'function') ||
    (descriptor.set !== undefined && typeof descriptor.set !== 'function') ||
    typeof descriptor.enumerable !== 'boolean' ||
    typeof descriptor.configurable !== 'boolean'
  ) {
    throwRedactionFailure();
  }
}

/**
 * Define an own data property on a null-prototype snapshot without invoking
 * the legacy `__proto__` setter. Snapshot properties are plain data, so later
 * reporter serialization cannot invoke source getters, proxies, or `toJSON`.
 *
 * @param {Record<string, unknown> | unknown[]} target
 * @param {string} key
 * @param {unknown} value
 */
function defineSnapshotProperty(target, key, value) {
  try {
    SAFE_OBJECT_DEFINE_PROPERTY(target, key, {
      configurable: true,
      enumerable: true,
      value,
      writable: true
    });
  } catch {
    throwRedactionFailure();
  }
}

/**
 * Construct a real Array with normal push/map/iterator behavior while
 * ensuring arrays created by map/filter/slice keep the same safe serializer.
 * The own species constructor avoids falling back to a poisoned ambient
 * Array.prototype.toJSON on representative reporter transformations.
 *
 * @param {number} length
 * @returns {unknown[]}
 */
function createSerializationSafeArray(length) {
  /** @type {unknown[]} */
  const snapshot = new SAFE_ARRAY(length);
  try {
    SAFE_OBJECT_DEFINE_PROPERTY(snapshot, 'toJSON', {
      configurable: false,
      enumerable: false,
      value() {
        return this;
      },
      writable: false
    });
    SAFE_OBJECT_DEFINE_PROPERTY(snapshot, 'constructor', {
      configurable: false,
      enumerable: false,
      value: createSerializationSafeArray,
      writable: false
    });
  } catch {
    throwRedactionFailure();
  }
  return snapshot;
}

try {
  SAFE_OBJECT_DEFINE_PROPERTY(createSerializationSafeArray, SAFE_SYMBOL_SPECIES, {
    configurable: false,
    enumerable: false,
    value: createSerializationSafeArray,
    writable: false
  });
} catch {
  throwRedactionFailure();
}

/**
 * Create a snapshot container with no ambient serialization hooks. Arrays keep
 * their normal Array behavior and receive a safe own serializer, while object
 * snapshots use a null prototype. This prevents a reporter's later
 * JSON.stringify from invoking poisoned Array.prototype.toJSON or
 * Object.prototype.toJSON hooks.
 *
 * @param {boolean} array
 * @returns {Record<string, unknown> | unknown[]}
 */
function createSnapshotContainer(array) {
  if (!array) return SAFE_OBJECT_CREATE(null);
  return createSerializationSafeArray(0);
}

/**
 * Traverse diagnostics into a trusted JSON-safe plain snapshot. The source
 * graph is never mutated or retained in the returned value. This is deliberate:
 * a stateful Proxy can change after a successful read-back, and own `toJSON`
 * hooks can reveal a secret during later reporter serialization. Skipping those
 * hooks and replacing the reporter's error array with this snapshot closes both
 * boundaries.
 *
 * @param {unknown} value
 * @param {Iterable<string>} secrets
 * @param {RedactionState} state
 * @param {number} depth
 * @returns {unknown}
 */
function redactTestDiagnosticValue(value, secrets, state, depth) {
  if (typeof value === 'string') return redactBoundedString(value, secrets, state);
  if (value === null || typeof value === 'boolean' || typeof value === 'number') return value;
  if (typeof value === 'undefined') return undefined;
  if (typeof value === 'bigint') return redactBoundedString(SAFE_STRING(value), secrets, state);
  if (typeof value === 'function' || typeof value === 'symbol') return LIVE_ARTIFACT_REDACTION;
  if (typeof value !== 'object') return LIVE_ARTIFACT_REDACTION;
  if (trustedApply(SAFE_SET_HAS, state.active, [value])) return LIVE_ARTIFACT_REDACTION;
  if (trustedApply(SAFE_MAP_HAS, state.snapshots, [value])) return trustedApply(SAFE_MAP_GET, state.snapshots, [value]);

  consumeRedactionNode(state, depth);
  const snapshot = createSnapshotContainer(SAFE_ARRAY_IS_ARRAY(value));
  trustedApply(SAFE_MAP_SET, state.snapshots, [value, snapshot]);
  trustedApply(SAFE_SET_ADD, state.active, [value]);
  try {
    /** @type {(string | symbol)[]} */
    let keys;
    try {
      keys = SAFE_REFLECT_OWN_KEYS(value);
    } catch {
      throwRedactionFailure();
    }
    if (keys.length > REDACTION_MAX_PROPERTIES) throwRedactionBudget();
    if (SAFE_ARRAY_IS_ARRAY(value)) {
      let length;
      try {
        length = SAFE_REFLECT_GET(value, 'length');
      } catch {
        throwRedactionFailure();
      }
      if (
        typeof length !== 'number' ||
        !SAFE_NUMBER_IS_SAFE_INTEGER(length) ||
        length < 0 ||
        length > REDACTION_MAX_ARRAY_ITEMS ||
        state.arrayItems + length > REDACTION_MAX_ARRAY_ITEMS
      ) {
        throwRedactionBudget();
      }
      state.arrayItems += length;
    }

    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      const key = keys[keyIndex];
      if (typeof key !== 'string') continue;
      // Safe snapshot arrays own non-configurable `toJSON` and `constructor`
      // properties. They are transport mechanics, not diagnostic fields; copying
      // the constructor back would collide with the destination's pinned species
      // constructor and fail closed under an inherited hostile serializer.
      if (
        key === 'location' ||
        key === 'toJSON' ||
        (SAFE_ARRAY_IS_ARRAY(value) && (key === 'length' || key === 'constructor'))
      ) continue;
      state.properties += 1;
      if (state.properties > REDACTION_MAX_PROPERTIES) throwRedactionBudget();
      /** @type {PropertyDescriptor | undefined} */
      let descriptor;
      try {
        descriptor = SAFE_REFLECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
      } catch {
        throwRedactionFailure();
      }
      if (!descriptor) throwRedactionFailure();
      try {
        if ('value' in descriptor) validateDataDescriptor(descriptor);
        else validateAccessorDescriptor(descriptor);
      } catch {
        throwRedactionFailure();
      }
      let observed;
      try {
        // Read once. Any stateful source behavior is consumed here and cannot
        // affect the already-created plain snapshot later.
        observed = SAFE_REFLECT_GET(value, key);
      } catch {
        throwRedactionFailure();
      }

      // A descriptor that disagrees with the observable value is not trusted.
      // Keep the detached snapshot safe without retaining either side of the
      // disagreement; this also handles stateful Proxy reads that alternate
      // between a marker and a credential.
      let descriptorMatchesReadBack;
      if ('value' in descriptor) {
        descriptorMatchesReadBack = SAFE_OBJECT_IS(descriptor.value, observed);
      } else if (typeof descriptor.get === 'function') {
        let getterReadBack;
        try {
          getterReadBack = trustedApply(descriptor.get, value, []);
        } catch {
          throwRedactionFailure();
        }
        descriptorMatchesReadBack = SAFE_OBJECT_IS(getterReadBack, observed);
      } else {
        descriptorMatchesReadBack = observed === undefined;
      }
      if (!descriptorMatchesReadBack) {
        defineSnapshotProperty(snapshot, key, LIVE_ARTIFACT_REDACTION);
        continue;
      }

      const sanitized = redactTestDiagnosticValue(observed, secrets, state, depth + 1);
      defineSnapshotProperty(snapshot, key, sanitized);
    }
    return snapshot;
  } finally {
    trustedApply(SAFE_SET_DELETE, state.active, [value]);
  }
}

/**
 * Build a trusted plain snapshot for Playwright diagnostics. Callers must use
 * the returned value for retained or reporter-visible errors; the untrusted
 * source graph is intentionally left untouched.
 *
 * @param {unknown} errors
 * @param {Iterable<string>} [secrets]
 * @returns {unknown[]}
 */
export function redactTestErrors(errors, secrets = liveCredentialValues()) {
  if (!SAFE_ARRAY_IS_ARRAY(errors)) throwRedactionFailure();
  const state = createRedactionState();
  const snapshot = redactTestDiagnosticValue(errors, secrets, state, 0);
  if (!SAFE_ARRAY_IS_ARRAY(snapshot)) throwRedactionFailure();
  return snapshot;
}

/**
 * @typedef {{ bytes: Buffer, prefixTable: number[] }} BinaryCredentialPattern
 */

/**
 * Build a KMP prefix table for one captured credential encoding. The table lets
 * the transport boundary detect both a complete credential and a decoded buffer
 * suffix that is a non-empty credential prefix in linear time. Redacting that
 * whole buffer is intentionally conservative: it prevents a parent reporter
 * from reconstructing a credential by concatenating adjacent stdio messages.
 *
 * @param {Buffer} bytes
 * @returns {number[]}
 */
function binaryPrefixTable(bytes) {
  /** @type {number[]} */
  const table = new SAFE_ARRAY(bytes.length);
  table[0] = 0;
  let prefixLength = 0;
  for (let index = 1; index < bytes.length; index += 1) {
    while (prefixLength > 0 && bytes[index] !== bytes[prefixLength]) {
      prefixLength = table[prefixLength - 1];
    }
    if (bytes[index] === bytes[prefixLength]) prefixLength += 1;
    table[index] = prefixLength;
  }
  return table;
}

/**
 * @param {Iterable<string>} secrets
 * @returns {BinaryCredentialPattern[]}
 */
function credentialBytePatterns(secrets) {
  /** @type {BinaryCredentialPattern[]} */
  const patterns = [];
  const copiedSecrets = trustedArrayCopy(secrets);
  if (copiedSecrets.length > REDACTION_MAX_BINARY_PATTERNS) throwRedactionBudget();
  const encodings = ['utf8', 'utf16le'];
  for (let secretIndex = 0; secretIndex < copiedSecrets.length; secretIndex += 1) {
    const secret = copiedSecrets[secretIndex];
    if (typeof secret !== 'string' || secret.length === 0) continue;
    for (let encodingIndex = 0; encodingIndex < encodings.length; encodingIndex += 1) {
      const encoding = encodings[encodingIndex];
      const bytes = /** @type {Buffer} */ (
        trustedApply(SAFE_BUFFER_FROM, Buffer, [secret, encoding])
      );
      if (bytes.length > 0 && bytes.length <= REDACTION_MAX_BINARY_BYTES) {
        trustedApply(SAFE_ARRAY_PUSH, patterns, [{ bytes, prefixTable: binaryPrefixTable(bytes) }]);
      }
    }
  }
  return patterns;
}

/**
 * Detect a complete credential match or a non-empty suffix prefix. KMP keeps
 * this bounded by the decoded message and captured-pattern sizes instead of
 * allocating every possible suffix. A positive final match is sufficient for
 * split-write protection; the entire current field is replaced before IPC.
 *
 * @param {Buffer} bytes
 * @param {BinaryCredentialPattern} pattern
 * @returns {boolean}
 */
function hasCredentialMatchOrPrefixSuffix(bytes, pattern) {
  let prefixLength = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    while (prefixLength > 0 && bytes[index] !== pattern.bytes[prefixLength]) {
      prefixLength = pattern.prefixTable[prefixLength - 1];
    }
    if (bytes[index] === pattern.bytes[prefixLength]) prefixLength += 1;
    if (prefixLength === pattern.bytes.length) return true;
  }
  return prefixLength > 0;
}

/**
 * Decode one Playwright protocol base64 field strictly. Buffer.from's base64
 * parser accepts malformed input and silently discards invalid bytes, so both
 * the alphabet and canonical round-trip are checked before any byte search.
 * A suffix that is a non-empty credential prefix is also replaced so separate
 * parent IPC messages cannot be concatenated into the original credential.
 *
 * @param {unknown} encoded
 * @param {BinaryCredentialPattern[]} patterns
 * @returns {string}
 */
function redactProtocolBase64(encoded, patterns) {
  if (typeof encoded !== 'string') throwRedactionFailure();
  if (encoded.length > REDACTION_MAX_STRING_LENGTH || !trustedRegExpTest(BASE64_PATTERN, encoded)) {
    throwRedactionBudget();
  }
  let bytes;
  try {
    bytes = /** @type {Buffer} */ (
      trustedApply(SAFE_BUFFER_FROM, Buffer, [encoded, 'base64'])
    );
  } catch {
    throwRedactionFailure();
  }
  const canonical = /** @type {string} */ (
    trustedApply(SAFE_BUFFER_TO_STRING, bytes, ['base64'])
  );
  if (bytes.length > REDACTION_MAX_BINARY_BYTES || canonical !== encoded) {
    throwRedactionBudget();
  }
  for (let index = 0; index < patterns.length; index += 1) {
    const pattern = /** @type {BinaryCredentialPattern} */ (patterns[index]);
    if (hasCredentialMatchOrPrefixSuffix(bytes, pattern)) return LIVE_BINARY_REDACTION;
  }
  return encoded;
}

/**
 * @param {unknown} value
 * @param {string} key
 * @returns {{ present: boolean, value?: unknown }}
 */
function snapshotProperty(value, key) {
  if (value === null || typeof value !== 'object') throwRedactionFailure();
  let descriptor;
  try {
    descriptor = SAFE_OBJECT_GET_OWN_PROPERTY_DESCRIPTOR(value, key);
  } catch {
    throwRedactionFailure();
  }
  if (!descriptor) return { present: false };
  if (!trustedHasOwn(descriptor, 'value')) throwRedactionFailure();
  return { present: true, value: descriptor.value };
}

/**
 * Rewrite only the binary fields used by Playwright's worker protocol. The
 * generic detached snapshot protects ordinary strings, while this protocol
 * layer decodes stdOut/stdErr buffers and attach bodies so base64 transport
 * cannot carry a credential past the parent boundary.
 *
 * @param {unknown} snapshot
 * @param {BinaryCredentialPattern[]} patterns
 */
function redactPlaywrightBinaryFields(snapshot, patterns) {
  if (snapshot === null || typeof snapshot !== 'object') return;
  const outerMethod = snapshotProperty(snapshot, 'method');
  if (!outerMethod.present || outerMethod.value !== '__dispatch__') return;
  const outerParams = snapshotProperty(snapshot, 'params');
  if (!outerParams.present || outerParams.value === null || typeof outerParams.value !== 'object') {
    throwRedactionFailure();
  }
  const eventMethod = snapshotProperty(outerParams.value, 'method');
  if (
    !eventMethod.present ||
    (eventMethod.value !== 'stdOut' &&
      eventMethod.value !== 'stdErr' &&
      eventMethod.value !== 'attach')
  ) return;
  const eventParams = snapshotProperty(outerParams.value, 'params');
  if (!eventParams.present || eventParams.value === null || typeof eventParams.value !== 'object') {
    throwRedactionFailure();
  }
  const field = eventMethod.value === 'attach' ? 'body' : 'buffer';
  const encoded = snapshotProperty(eventParams.value, field);
  if (!encoded.present || encoded.value === undefined) return;
  defineSnapshotProperty(
    /** @type {Record<string, unknown>} */ (eventParams.value),
    field,
    redactProtocolBase64(encoded.value, patterns)
  );
}

/**
 * Detach and redact one complete Playwright worker IPC message. This boundary
 * runs on `process.send`, not in afterEach: step-end and test-end payloads can
 * be emitted before a fixture cleanup hook, and Playwright's mapped error
 * objects are ordinary objects that do not inherit our array snapshot hooks.
 * If traversal fails, the caller must not send the original message.
 *
 * @param {unknown} message
 * @param {Iterable<string>} [secrets]
 * @returns {unknown}
 */
export function redactLiveTransportMessage(message, secrets = liveCredentialValues()) {
  const capturedSecrets = /** @type {string[]} */ (
    SAFE_OBJECT_FREEZE(trustedArrayCopy(secrets))
  );
  const state = createRedactionState();
  const snapshot = redactTestDiagnosticValue(message, capturedSecrets, state, 0);
  redactPlaywrightBinaryFields(snapshot, credentialBytePatterns(capturedSecrets));
  return snapshot;
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
      // This callback runs in the browser realm, so use that realm's native Set
      // rather than a Node preload capture that would not be defined remotely.
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
 * @typedef {{ dev: number, ino: number }} DirectoryIdentity
 */

/** @param {string} directory @returns {DirectoryIdentity} */
function readDirectoryIdentity(directory) {
  try {
    const stats = lstatSync(directory);
    if (!stats.isDirectory() || stats.isSymbolicLink()) {
      throw new SAFE_ERROR('live artifact quarantine identity is unsafe');
    }
    return { dev: stats.dev, ino: stats.ino };
  } catch (error) {
    if (error instanceof SAFE_ERROR) throw error;
    throw new SAFE_ERROR('live artifact quarantine identity is unavailable');
  }
}

/**
 * Remove an empty quarantine parent without recursively trusting its path. The
 * identity-bound rename to a unique tombstone closes the check-to-rmdir gap:
 * only the directory whose device/inode was observed can reach non-recursive
 * removal, while a replacement remains at its own tombstone if the handoff
 * does not preserve identity.
 *
 * @param {string} quarantineParent
 * @param {DirectoryIdentity} expected
 * @returns {Promise<void>}
 */
async function removeEmptyQuarantineParent(quarantineParent, expected) {
  if (!sameDirectoryIdentity(quarantineParent, expected)) {
    throw new SAFE_ERROR('live artifact quarantine identity changed');
  }
  const tombstone = uniqueSiblingPath(dirname(quarantineParent), basename(quarantineParent), 'parent-delete');
  try {
    await fsPromises.rename(quarantineParent, tombstone);
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return;
    throw new SAFE_ERROR('live artifact quarantine cleanup failed');
  }
  if (!sameDirectoryIdentity(tombstone, expected)) {
    throw new SAFE_ERROR('live artifact quarantine identity changed');
  }
  try {
    await fsPromises.rmdir(tombstone);
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return;
    throw new SAFE_ERROR('live artifact quarantine cleanup failed');
  }
}

/**
 * @param {string} path
 * @param {DirectoryIdentity} expected
 * @returns {import('node:fs').Stats | undefined}
 */
function sameDirectoryIdentity(path, expected) {
  try {
    const stats = lstatSync(path);
    return stats.isDirectory() && !stats.isSymbolicLink() && stats.dev === expected.dev && stats.ino === expected.ino
      ? stats
      : undefined;
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return undefined;
    throw new SAFE_ERROR('live artifact identity inspection failed');
  }
}

const SAFE_CLEANUP_MESSAGES = new SAFE_SET([
  'live artifact ownership inspection failed',
  'live artifact quarantine inspection failed',
  'live artifact path inspection failed',
  'live artifact identity inspection failed',
  'live artifact quarantine identity is unavailable',
  'live artifact quarantine identity changed',
  'live artifact quarantine cleanup failed',
  'live artifact cleanup identity changed',
  'live artifact cleanup handoff failed',
  'live artifact cleanup inspection failed',
  'live artifact cleanup child disappeared',
  'live artifact cleanup child handoff failed',
  'live artifact cleanup child identity changed',
  'live artifact cleanup child removal failed',
  'live artifact cleanup left a quarantine remnant',
  'live artifact test output inspection failed',
  'live artifact test output handoff failed',
  'live artifact test output identity changed',
  'live artifact root changed during test cleanup',
  'live artifact cleanup failed',
  'live test attachments could not be cleared'
]);

/**
 * @param {unknown} error
 * @param {string} fallback
 * @returns {Error}
 */
function safeCleanupError(error, fallback) {
  if (
    error instanceof SAFE_ERROR &&
    typeof error.message === 'string' &&
    trustedApply(SAFE_SET_HAS, SAFE_CLEANUP_MESSAGES, [error.message])
  ) {
    return new SAFE_ERROR(error.message);
  }
  return new SAFE_ERROR(fallback);
}

/**
 * @param {unknown[]} failures
 * @param {string} message
 * @returns {Error}
 */
function safeFailureAggregate(failures, message) {
  /** @type {unknown[]} */
  const safeFailures = new SAFE_ARRAY();
  for (let index = 0; index < failures.length; index += 1) {
    trustedApply(SAFE_ARRAY_PUSH, safeFailures, [failures[index]]);
  }
  return new SAFE_AGGREGATE_ERROR(safeFailures, message);
}

/**
 * @param {unknown} primary
 * @param {unknown} secondary
 * @param {string} fallback
 * @returns {Error}
 */
function combineCleanupFailures(primary, secondary, fallback) {
  const first = safeCleanupError(primary, fallback);
  if (secondary === undefined) return first;
  const second = safeCleanupError(secondary, fallback);
  return safeFailureAggregate([first, second], first.message);
}

/**
 * @param {string} parent
 * @param {string} name
 * @param {string} purpose
 * @returns {string}
 */
function uniqueSiblingPath(parent, name, purpose) {
  return join(parent, `.${name}-${purpose}-${randomBytes(16).toString('hex')}`);
}

/**
 * @param {string} root
 * @param {string} candidate
 * @returns {boolean}
 */
function isStrictOwnedDescendant(root, candidate) {
  const remainder = relative(resolve(root), resolve(candidate));
  return remainder.length > 0 && remainder !== '..' && !trustedStringStartsWith(remainder, `..${sep}`);
}

/**
 * Verify every path component between the owned root and a per-test output
 * directory. A candidate lstat alone follows replaceable ancestor symlinks;
 * realpath/lstat checks reject that shape before the first rename. This is a
 * fail-closed lexical boundary for the path-based Node filesystem API.
 *
 * @param {string} root
 * @param {string} candidate
 * @returns {boolean}
 */
function hasOwnedPathAncestors(root, candidate) {
  const resolvedRoot = resolve(root);
  const resolvedCandidate = resolve(candidate);
  if (!isStrictOwnedDescendant(resolvedRoot, resolvedCandidate)) return false;
  try {
    const canonicalRoot = realpathSync(resolvedRoot);
    const remainder = relative(resolvedRoot, resolvedCandidate);
    const components = trustedStringSplit(remainder, sep);
    let current = resolvedRoot;
    for (let index = 0; index < components.length; index += 1) {
      current = join(current, components[index]);
      const stats = lstatSync(current);
      if (!stats.isDirectory() || stats.isSymbolicLink()) return false;
      const canonicalCurrent = realpathSync(current);
      const expectedCanonical = join(canonicalRoot, relative(resolvedRoot, current));
      if (canonicalCurrent !== expectedCanonical) return false;
    }
    return true;
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return false;
    throw new SAFE_ERROR('live artifact path inspection failed');
  }
}

/**
 * Delete one owned directory tree without recursively trusting a pathname. The
 * directory is first renamed to a fresh sibling tombstone, so a replacement at
 * the caller's path is never inspected or deleted. Every child is detached and
 * identity-checked before non-recursive unlink/rmdir. Any failed identity check
 * or filesystem operation is reported while the unverified remnant is kept.
 *
 * @param {string} directory
 * @param {DirectoryIdentity} expected
 * @returns {Promise<void>}
 */
async function removeOwnedTree(directory, expected) {
  if (!sameDirectoryIdentity(directory, expected)) {
    throw new SAFE_ERROR('live artifact cleanup identity changed');
  }

  const ownedPath = uniqueSiblingPath(dirname(directory), basename(directory), 'owned');
  try {
    await fsPromises.rename(directory, ownedPath);
  } catch {
    throw new SAFE_ERROR('live artifact cleanup handoff failed');
  }
  if (!sameDirectoryIdentity(ownedPath, expected)) {
    throw new SAFE_ERROR('live artifact cleanup identity changed');
  }

  let entries;
  try {
    entries = await fsPromises.readdir(ownedPath, { withFileTypes: true });
  } catch {
    throw new SAFE_ERROR('live artifact cleanup inspection failed');
  }

  for (const entry of entries) {
    const sourcePath = join(ownedPath, entry.name);
    let childStats;
    try {
      childStats = lstatSync(sourcePath);
    } catch {
      throw new SAFE_ERROR('live artifact cleanup child disappeared');
    }
    const childPath = uniqueSiblingPath(ownedPath, entry.name, 'delete');
    try {
      await fsPromises.rename(sourcePath, childPath);
    } catch {
      throw new SAFE_ERROR('live artifact cleanup child handoff failed');
    }

    try {
      const movedStats = lstatSync(childPath);
      if (
        movedStats.dev !== childStats.dev ||
        movedStats.ino !== childStats.ino ||
        (!movedStats.isDirectory() && !movedStats.isFile() && !movedStats.isSymbolicLink())
      ) {
        throw new SAFE_ERROR('live artifact cleanup child identity changed');
      }
      if (movedStats.isDirectory() && !movedStats.isSymbolicLink()) {
        // A failed recursive handoff leaves the tombstone and any safe remnant
        // in place. Never fall back to recursive deletion of that path.
        await removeOwnedTree(childPath, movedStats);
      } else {
        // An exact identity-matched symlink is unlinked as a directory entry;
        // its target is never followed. The same path is not reused after the
        // handoff, so a replacement cannot become this unlink target.
        await fsPromises.unlink(childPath);
      }
      continue;
    } catch (error) {
      if (error instanceof SAFE_ERROR) throw error;
      // Preserve an unreadable or replaced remnant and report the failure.
      throw new SAFE_ERROR('live artifact cleanup child removal failed');
    }
  }

  if (!sameDirectoryIdentity(ownedPath, expected)) {
    throw new SAFE_ERROR('live artifact cleanup identity changed');
  }
  try {
    // rmdir is intentionally non-recursive. A non-empty replacement fails and
    // remains available for inspection rather than being recursively removed.
    await fsPromises.rmdir(ownedPath);
  } catch {
    throw new SAFE_ERROR('live artifact cleanup left a quarantine remnant');
  }
}

/**
 * Remove one Playwright test output directory while preserving the run root,
 * owner marker, and root-level artifacts for later tests. Every ancestor is
 * lstat/realpath checked before the child is moved to a private quarantine;
 * replacement symlink ancestors fail closed before recursive traversal. Any
 * owned cleanup or quarantine-parent failure is propagated without masking the
 * other failure.
 *
 * @param {string} directory
 * @returns {Promise<void>}
 */
async function removeLiveTestArtifacts(directory) {
  const root = liveArtifactCleanupRoot();
  const rootEvidence = liveArtifactEvidence(root);
  if (!rootEvidence) return;
  const candidate = resolve(directory);
  if (!hasOwnedPathAncestors(root, candidate)) return;

  let candidateStats;
  try {
    candidateStats = lstatSync(candidate);
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return;
    throw new SAFE_ERROR('live artifact test output inspection failed');
  }
  if (!candidateStats.isDirectory() || candidateStats.isSymbolicLink()) return;

  /** @type {string | undefined} */
  let quarantineParent;
  /** @type {DirectoryIdentity | undefined} */
  let quarantineIdentity;
  let primaryError;
  try {
    quarantineParent = mkdtempSync(join(resolve(tmpdir()), 'hermternal-live-test-quarantine-'));
    quarantineIdentity = readDirectoryIdentity(quarantineParent);
    await fsPromises.rename(candidate, join(quarantineParent, basename(candidate)));
    if (!isLiveArtifactDirectory(root) || !sameDirectoryIdentity(root, rootEvidence)) {
      throw new SAFE_ERROR('live artifact root changed during test cleanup');
    }
    const quarantinedStats = sameDirectoryIdentity(
      join(quarantineParent, basename(candidate)),
      candidateStats
    );
    if (!quarantinedStats) {
      throw new SAFE_ERROR('live artifact test output identity changed');
    }
    await removeOwnedTree(join(quarantineParent, basename(candidate)), quarantinedStats);
  } catch (error) {
    primaryError = safeCleanupError(error, 'live artifact test output handoff failed');
  } finally {
    if (quarantineParent && quarantineIdentity) {
      try {
        await removeEmptyQuarantineParent(quarantineParent, quarantineIdentity);
      } catch (error) {
        primaryError = primaryError
          ? combineCleanupFailures(primaryError, error, 'live artifact quarantine cleanup failed')
          : safeCleanupError(error, 'live artifact quarantine cleanup failed');
      }
    }
  }
  if (primaryError) throw primaryError;
}

/**
 * Remove the complete live output root only after an identity-bound atomic
 * handoff. The owned root moves through private, unguessable tombstones.
 * Recursive pathname deletion is deliberately not used: every child is
 * detached and verified before non-recursive removal, and a final replacement
 * survives a failed rmdir rather than becoming an rm target. Cleanup failures
 * are propagated and combined so quarantine remnants are never silently
 * abandoned or allowed to mask the primary identity failure.
 *
 * @param {string} directory
 * @returns {Promise<void>}
 */
export async function removeLiveArtifacts(directory) {
  const evidence = liveArtifactEvidence(directory);
  if (!evidence) return;

  let quarantineParent;
  let quarantineIdentity;
  let primaryError;
  try {
    quarantineParent = mkdtempSync(join(resolve(tmpdir()), 'hermternal-live-quarantine-'));
    quarantineIdentity = readDirectoryIdentity(quarantineParent);
    const quarantinePath = join(quarantineParent, basename(evidence.candidate));
    await fsPromises.rename(evidence.candidate, quarantinePath);
    if (!isVerifiedQuarantine(quarantinePath, evidence)) {
      throw new SAFE_ERROR('live artifact cleanup identity changed');
    }

    const deletionPath = uniqueSiblingPath(quarantineParent, basename(evidence.candidate), 'delete');
    await fsPromises.rename(quarantinePath, deletionPath);
    if (!isVerifiedQuarantine(deletionPath, evidence)) {
      throw new SAFE_ERROR('live artifact cleanup identity changed');
    }

    const finalPath = uniqueSiblingPath(quarantineParent, basename(evidence.candidate), 'final');
    await fsPromises.rename(deletionPath, finalPath);
    const finalStats = sameDirectoryIdentity(finalPath, evidence);
    if (!finalStats) {
      throw new SAFE_ERROR('live artifact cleanup identity changed');
    }

    await removeOwnedTree(finalPath, finalStats);
  } catch (error) {
    primaryError = safeCleanupError(error, 'live artifact cleanup handoff failed');
  } finally {
    if (quarantineParent && quarantineIdentity) {
      try {
        await removeEmptyQuarantineParent(quarantineParent, quarantineIdentity);
      } catch (error) {
        primaryError = primaryError
          ? combineCleanupFailures(primaryError, error, 'live artifact quarantine cleanup failed')
          : safeCleanupError(error, 'live artifact quarantine cleanup failed');
      }
    }
  }
  if (primaryError) throw primaryError;
}

/**
 * Replace the reporter-visible TestInfo array with trusted snapshot values. The
 * property assignment is preferred because it detaches the original array; the
 * mutation fallback supports a host that exposes a stable array reference. A
 * silent or rejected replacement fails closed instead of retaining the source
 * graph for Playwright to serialize later.
 *
 * @param {{ errors: unknown[] }} testInfo
 * @param {unknown[]} snapshot
 */
function replaceDiagnosticArray(testInfo, snapshot) {
  try {
    testInfo.errors = snapshot;
    if (testInfo.errors === snapshot) return;
  } catch {
    // Fall through to the stable-array path below.
  }

  const target = testInfo.errors;
  if (!SAFE_ARRAY_IS_ARRAY(target)) throwRedactionFailure();
  try {
    target.length = 0;
    for (let index = 0; index < snapshot.length; index += 1) {
      trustedApply(SAFE_ARRAY_PUSH, target, [snapshot[index]]);
    }
    if (target.length !== snapshot.length) throwRedactionFailure();
    for (let index = 0; index < snapshot.length; index += 1) {
      if (!SAFE_OBJECT_IS(target[index], snapshot[index])) throwRedactionFailure();
    }
  } catch {
    throwRedactionFailure();
  }
}

/**
 * Redact teardown diagnostics and always remove attachments/output. Redaction,
 * scrub, and cleanup failures are converted to fixed safe errors and aggregated
 * so cleanup failure is never masked by an earlier assertion failure. Reporter-
 * visible errors are replaced with trusted plain snapshots before propagation.
 *
 * @param {{ testInfo: { errors: unknown[], attachments: unknown[], outputDir: string }, scrubError?: unknown, secrets?: Iterable<string> }} options
 * @returns {Promise<void>}
 */
export async function finalizeLiveTest({ testInfo, scrubError, secrets = liveCredentialValues() }) {
  const scrubDiagnostics = scrubError === undefined ? undefined : [scrubError];
  let safeScrubDiagnostic;
  let redactionError;
  /** @type {unknown[]} */
  const cleanupFailures = new SAFE_ARRAY();
  try {
    if (scrubDiagnostics) {
      try {
        const snapshot = redactTestErrors(scrubDiagnostics, secrets);
        safeScrubDiagnostic = snapshot[0];
      } catch (error) {
        redactionError = error;
      }
    }
    let safeErrors;
    try {
      safeErrors = redactTestErrors(testInfo.errors, secrets);
    } catch (error) {
      redactionError ??= error;
    }
    try {
      replaceDiagnosticArray(testInfo, safeErrors ?? [LIVE_ARTIFACT_REDACTION]);
    } catch (error) {
      redactionError ??= error;
    }
  } finally {
    try {
      const attachments = testInfo.attachments;
      if (!SAFE_ARRAY_IS_ARRAY(attachments)) {
        throw new SAFE_ERROR('live test attachments were not cleared');
      }
      attachments.length = 0;
      if (testInfo.attachments !== attachments || attachments.length !== 0) {
        throw new SAFE_ERROR('live test attachments were not cleared');
      }
    } catch {
      trustedApply(SAFE_ARRAY_PUSH, cleanupFailures, [
        new SAFE_ERROR('live test attachments could not be cleared')
      ]);
    }
    try {
      await removeLiveTestArtifacts(testInfo.outputDir ?? liveArtifactCleanupRoot());
    } catch {
      trustedApply(SAFE_ARRAY_PUSH, cleanupFailures, [
        new SAFE_ERROR('live artifact cleanup failed')
      ]);
    }
  }

  /** @type {unknown[]} */
  const failures = new SAFE_ARRAY();
  if (redactionError !== undefined) {
    const message = redactionError instanceof SAFE_ERROR &&
      (redactionError.message === REDACTION_FAILURE_MESSAGE || redactionError.message === REDACTION_BUDGET_MESSAGE)
      ? redactionError.message
      : REDACTION_FAILURE_MESSAGE;
    trustedApply(SAFE_ARRAY_PUSH, failures, [new SAFE_ERROR(message)]);
  }
  if (scrubDiagnostics) {
    trustedApply(SAFE_ARRAY_PUSH, failures, [
      safeScrubDiagnostic ?? new SAFE_ERROR('live page scrub failed')
    ]);
  }
  for (let index = 0; index < cleanupFailures.length; index += 1) {
    trustedApply(SAFE_ARRAY_PUSH, failures, [cleanupFailures[index]]);
  }
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) {
    throw safeFailureAggregate(failures, 'live test finalization failed');
  }
}
