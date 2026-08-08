import { randomBytes } from 'node:crypto';
import { lstatSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { promises as fsPromises } from 'node:fs';
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
      // A missing marker is never ownership evidence. The exact path may have
      // been removed and recreated by another process, so markerless roots are
      // refused even when the path still matches this run's configured root.
      return false;
    }
  } catch {
    return false;
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
  } catch {
    return undefined;
  }
}

/**
 * Verify a quarantined directory without trusting its new path. Both the
 * original directory identity and its run-owned marker must still match before
 * recursive deletion is permitted.
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
  while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;

  if (closing) {
    return cursor === end
      ? { closing, name, selfClosing: false, ambiguous: false, attributes: [] }
      : undefined;
  }

  const attributes = [];
  const seenNames = new Set();
  let ambiguous = false;
  let selfClosing = false;
  while (cursor < end) {
    if (value[cursor] === '/') {
      cursor += 1;
      while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;
      if (cursor !== end) return undefined;
      selfClosing = true;
      break;
    }
    if (!/[A-Za-z_:]/u.test(value[cursor] ?? '')) return undefined;
    const attributeStart = cursor;
    cursor += 1;
    while (cursor < end && /[A-Za-z0-9:._-]/u.test(value[cursor])) cursor += 1;
    const attributeName = value.slice(attributeStart, cursor).toLowerCase();
    if (seenNames.has(attributeName)) ambiguous = true;
    seenNames.add(attributeName);
    while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;

    let attributeValue;
    let valueStart;
    let valueEnd;
    let quote;
    if (value[cursor] === '=') {
      cursor += 1;
      while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;
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
        attributeValue = value.slice(valueStart, valueEnd);
        cursor += 1;
      } else {
        valueStart = cursor;
        while (cursor < end && !/\s/u.test(value[cursor])) {
          if (/[<"'=]/u.test(value[cursor])) return undefined;
          cursor += 1;
        }
        if (cursor === valueStart) return undefined;
        valueEnd = cursor;
        attributeValue = value.slice(valueStart, valueEnd);
      }
    }
    attributes.push({
      name: attributeName,
      value: attributeValue,
      valueStart,
      valueEnd,
      quote
    });
    while (cursor < end && /\s/u.test(value[cursor])) cursor += 1;
  }

  return { closing, name, selfClosing, ambiguous, attributes };
}

/**
 * @param {HtmlTag} tag
 * @returns {boolean}
 */
function hasEditableContentAttribute(tag) {
  const matches = tag.attributes.filter(({ name }) => name === 'contenteditable');
  if (matches.length !== 1) return matches.length > 0;
  const mode = (matches[0].value ?? '').trim().toLowerCase();
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
    if (tag.ambiguous) return undefined;
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
 * @param {string} value
 * @param {number} start
 * @returns {{ start: number, end: number, tag: HtmlTag } | { malformedStart: number } | undefined}
 */
function findNextStructuredFormOpening(value, start) {
  let cursor = start;
  while (cursor < value.length) {
    const opening = value.indexOf('<', cursor);
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
    const next = value.indexOf('<', cursor);
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
    const next = value.indexOf('<', cursor);
    if (next < 0) return undefined;
    const end = findHtmlTagEnd(value, next);
    if (end === HTML_UNTERMINATED_COMMENT || end === HTML_MALFORMED_TAG || end < 0) {
      return undefined;
    }
    const tag = parseHtmlTag(value, next, end);
    if (!tag || tag.ambiguous || tag.selfClosing) return undefined;
    const parent = stack.at(-1);
    if (tag.closing) {
      if (tag.attributes.length > 0 || parent !== tag.name) return undefined;
      stack.pop();
      if (stack.length === 0) return { start: next, end };
    } else {
      const allowed =
        (parent === 'select' && (tag.name === 'option' || tag.name === 'optgroup')) ||
        (parent === 'optgroup' && tag.name === 'option');
      if (!allowed) return undefined;
      stack.push(tag.name);
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
      redacted += value.slice(cursor);
      break;
    }
    if ('malformedStart' in opening) {
      redacted += value.slice(cursor, opening.malformedStart);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    redacted += value.slice(cursor, opening.start);
    const closing =
      opening.tag.name === 'textarea'
        ? findTextareaClosingTag(value, opening)
        : findSelectClosingTag(value, opening);
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
    const opening = value.indexOf('<', cursor);
    if (opening < 0) {
      redacted += value.slice(cursor);
      break;
    }
    const end = findHtmlTagEnd(value, opening);
    if (end === HTML_UNTERMINATED_COMMENT) {
      redacted += value.slice(cursor, opening);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    if (end === HTML_MALFORMED_TAG || end < 0) {
      redacted += value.slice(cursor, opening);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    const tag = parseHtmlTag(value, opening, end);
    if (!tag) {
      if (value.startsWith('<!--', opening)) {
        redacted += value.slice(cursor, end + 1);
        cursor = end + 1;
        continue;
      }
      redacted += value.slice(cursor, opening);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    if (tag.ambiguous) {
      redacted += value.slice(cursor, opening);
      redacted += LIVE_ARTIFACT_REDACTION;
      break;
    }
    let redactedTag = value.slice(opening, end + 1);
    const valueAttributes = tag.attributes.filter(
      ({ name, valueStart, valueEnd }) => name === 'value' && valueStart !== undefined && valueEnd !== undefined
    );
    for (const attribute of valueAttributes.reverse()) {
      const localStart = /** @type {number} */ (attribute.valueStart) - opening;
      const localEnd = /** @type {number} */ (attribute.valueEnd) - opening;
      redactedTag = `${redactedTag.slice(0, localStart)}${LIVE_ARTIFACT_REDACTION}${redactedTag.slice(localEnd)}`;
    }
    redacted += value.slice(cursor, opening);
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
  if (value.length > REDACTION_MAX_STRING_LENGTH) throw new Error(REDACTION_BUDGET_MESSAGE);
  let redacted = value;
  for (const secret of [...new Set(secrets)].filter((item) => item.length > 0).sort((a, b) => b.length - a.length)) {
    redacted = redacted.split(secret).join(LIVE_ARTIFACT_REDACTION);
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
    active: new Set(),
    snapshots: new Map(),
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
 * Node's IPC serializer invokes an inherited `toJSON` on the ordinary object
 * literals produced by Playwright's worker-side `toTestInfoErrorPayload`.
 * Keep the normal Array push/map/iterator lifecycle intact, but pin the two
 * ambient prototype hooks to a detached null-prototype serializer before the
 * worker returns the test result. A non-configurable hostile hook cannot be
 * made safe, so the live lane fails closed rather than allowing an untrusted
 * IPC payload.
 */
/** @this {Record<string, unknown> | unknown[]} */
function safeWorkerToJSON() {
  const source = this;
  if (Array.isArray(source)) {
    /** @type {unknown[]} */
    const snapshot = [];
    // A null prototype keeps Vitest/Node serializers from calling this hook
    // again while preserving Array.isArray and JSON array transport semantics.
    Object.setPrototypeOf(snapshot, null);
    for (let index = 0; index < source.length; index += 1) snapshot[index] = source[index];
    return snapshot;
  }
  const snapshot = Object.create(null);
  for (const key of Object.keys(source)) snapshot[key] = source[key];
  return snapshot;
}

function installSafeWorkerSerialization() {
  for (const prototype of [Object.prototype, Array.prototype]) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(prototype, 'toJSON');
    } catch {
      throwRedactionFailure();
    }
    if (descriptor && !('value' in descriptor) && !descriptor.configurable) {
      throwRedactionFailure();
    }
    if (descriptor && 'value' in descriptor && !descriptor.configurable && descriptor.writable === false) {
      throwRedactionFailure();
    }
    try {
      Object.defineProperty(prototype, 'toJSON', {
        configurable: descriptor?.configurable ?? true,
        enumerable: descriptor?.enumerable ?? false,
        value: safeWorkerToJSON,
        writable: descriptor?.writable ?? true
      });
    } catch {
      throwRedactionFailure();
    }
    try {
      if (Object.getOwnPropertyDescriptor(prototype, 'toJSON')?.value !== safeWorkerToJSON) {
        throwRedactionFailure();
      }
    } catch {
      throwRedactionFailure();
    }
  }
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
    Object.defineProperty(target, key, {
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
  const snapshot = new Array(length);
  try {
    Object.defineProperty(snapshot, 'toJSON', {
      configurable: false,
      enumerable: false,
      value() {
        return this;
      },
      writable: false
    });
    Object.defineProperty(snapshot, 'constructor', {
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
  Object.defineProperty(createSerializationSafeArray, Symbol.species, {
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
  if (!array) return Object.create(null);
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
  if (typeof value === 'bigint') return redactBoundedString(String(value), secrets, state);
  if (typeof value === 'function' || typeof value === 'symbol') return LIVE_ARTIFACT_REDACTION;
  if (typeof value !== 'object') return LIVE_ARTIFACT_REDACTION;
  if (state.active.has(value)) return LIVE_ARTIFACT_REDACTION;
  if (state.snapshots.has(value)) return state.snapshots.get(value);

  consumeRedactionNode(state, depth);
  const snapshot = createSnapshotContainer(Array.isArray(value));
  state.snapshots.set(value, snapshot);
  state.active.add(value);
  try {
    /** @type {(string | symbol)[]} */
    let keys;
    try {
      keys = Reflect.ownKeys(value);
    } catch {
      throwRedactionFailure();
    }
    if (keys.length > REDACTION_MAX_PROPERTIES) throwRedactionBudget();
    if (Array.isArray(value)) {
      let length;
      try {
        length = Reflect.get(value, 'length');
      } catch {
        throwRedactionFailure();
      }
      if (
        typeof length !== 'number' ||
        !Number.isSafeInteger(length) ||
        length < 0 ||
        length > REDACTION_MAX_ARRAY_ITEMS ||
        state.arrayItems + length > REDACTION_MAX_ARRAY_ITEMS
      ) {
        throwRedactionBudget();
      }
      state.arrayItems += length;
    }

    for (const key of keys) {
      if (typeof key !== 'string') continue;
      if (key === 'location' || key === 'toJSON' || (Array.isArray(value) && key === 'length')) continue;
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
        observed = Reflect.get(value, key);
      } catch {
        throwRedactionFailure();
      }

      // A descriptor that disagrees with the observable value is not trusted.
      // Keep the detached snapshot safe without retaining either side of the
      // disagreement; this also handles stateful Proxy reads that alternate
      // between a marker and a credential.
      let descriptorMatchesReadBack;
      if ('value' in descriptor) {
        descriptorMatchesReadBack = Object.is(descriptor.value, observed);
      } else if (typeof descriptor.get === 'function') {
        let getterReadBack;
        try {
          getterReadBack = Reflect.apply(descriptor.get, value, []);
        } catch {
          throwRedactionFailure();
        }
        descriptorMatchesReadBack = Object.is(getterReadBack, observed);
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
    state.active.delete(value);
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
  if (!Array.isArray(errors)) throwRedactionFailure();
  const state = createRedactionState();
  const snapshot = redactTestDiagnosticValue(errors, secrets, state, 0);
  if (!Array.isArray(snapshot)) throwRedactionFailure();
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
 * Remove an empty quarantine parent without recursively trusting its path. A
 * replacement or an unverified remnant makes the non-recursive remove fail,
 * which preserves that unrelated content for the caller to inspect.
 *
 * @param {string} quarantineParent
 * @returns {Promise<void>}
 */
async function removeEmptyQuarantineParent(quarantineParent) {
  // rmdir is intentionally non-recursive and refuses symlinks/non-empty
  // directories, so a replacement cannot be removed as a cleanup side effect.
  await fsPromises.rmdir(quarantineParent).catch(() => undefined);
}

/**
 * Remove a live output directory only after an identity-bound atomic handoff.
 * The owned root is first renamed into a private temporary quarantine. It is
 * then renamed again to an unguessable tombstone and reverified at that final
 * path before recursive deletion. The second rename means a replacement at the
 * quarantine path is never passed directly to rm; an identity mismatch fails
 * closed and safe remnants are cleaned without recursive path trust.
 *
 * @param {string} directory
 * @returns {Promise<void>}
 */
export async function removeLiveArtifacts(directory) {
  const evidence = liveArtifactEvidence(directory);
  if (!evidence) return;

  let quarantineParent;
  let quarantinePath;
  try {
    quarantineParent = mkdtempSync(join(resolve(tmpdir()), 'hermternal-live-quarantine-'));
    quarantinePath = join(quarantineParent, basename(evidence.candidate));
    await fsPromises.rename(evidence.candidate, quarantinePath);
  } catch {
    if (quarantineParent) await removeEmptyQuarantineParent(quarantineParent);
    return;
  }

  if (!isVerifiedQuarantine(quarantinePath, evidence)) {
    await removeEmptyQuarantineParent(quarantineParent);
    return;
  }

  const deletionPath = join(
    quarantineParent,
    `.${basename(evidence.candidate)}-delete-${randomBytes(16).toString('hex')}`
  );
  try {
    await fsPromises.rename(quarantinePath, deletionPath);
  } catch {
    await removeEmptyQuarantineParent(quarantineParent);
    return;
  }

  if (!isVerifiedQuarantine(deletionPath, evidence)) {
    // Do not move an unverified entry back over a path that may now belong to
    // another process. Leaving the non-empty private quarantine parent is the
    // safe outcome; the caller can inspect or remove those untrusted remnants.
    await removeEmptyQuarantineParent(quarantineParent);
    return;
  }

  try {
    await fsPromises.rm(deletionPath, { recursive: true, force: true });
  } finally {
    await removeEmptyQuarantineParent(quarantineParent);
  }
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
  if (!Array.isArray(target)) throwRedactionFailure();
  try {
    target.length = 0;
    for (let index = 0; index < snapshot.length; index += 1) {
      target.push(snapshot[index]);
    }
    if (target.length !== snapshot.length) throwRedactionFailure();
    for (let index = 0; index < snapshot.length; index += 1) {
      if (!Object.is(target[index], snapshot[index])) throwRedactionFailure();
    }
  } catch {
    throwRedactionFailure();
  }
}

/**
 * Redact teardown diagnostics and always remove attachments/output. A redaction
 * failure wins over the original scrub failure so an unredacted error is never
 * rethrown; cleanup still runs from the `finally` block before propagation.
 * Reporter-visible errors are replaced with trusted plain snapshots before the
 * function returns or throws.
 *
 * @param {{ testInfo: { errors: unknown[], attachments: unknown[], outputDir: string }, scrubError?: unknown, secrets?: Iterable<string> }} options
 * @returns {Promise<void>}
 */
export async function finalizeLiveTest({ testInfo, scrubError, secrets = liveCredentialValues() }) {
  const scrubDiagnostics = scrubError === undefined ? undefined : [scrubError];
  let safeScrubDiagnostic;
  let redactionError;
  let cleanupError;
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
    try {
      // Playwright maps this array into ordinary IPC payload objects after the
      // hook returns. Pin inherited serializers before that worker handoff;
      // replacing only the source array would leave those mapped objects
      // exposed to Object.prototype.toJSON.
      installSafeWorkerSerialization();
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
  if (scrubDiagnostics) throw safeScrubDiagnostic ?? new Error('live page scrub failed');
  if (cleanupError !== undefined) throw cleanupError;
}
