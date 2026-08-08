import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, realpathSync, promises as fsPromises } from 'node:fs';
import { join, parse, relative, resolve, sep } from 'node:path';

/**
 * This module is the only explicit screenshot path in the live lane. It is
 * opt-in, keeps screenshot bytes in memory until an independent reviewer
 * approves retention, and emits a fixed-key manifest rather than browser or
 * Hermes diagnostics. The normal live config still disables Playwright's
 * automatic screenshots, traces, videos, output retention, and unsafe reporter.
 */

export const LIVE_SCREENSHOT_MANIFEST_SCHEMA = 'hermternal.live-chat-screenshot.v1';
export const LIVE_SCREENSHOT_ISSUE = 353;
export const LIVE_SCREENSHOT_ROUTE = '/';
export const LIVE_SCREENSHOT_TEST_COMMAND = 'bun run --cwd apps/web test:e2e:live';
export const LIVE_SCREENSHOT_CAPTURE_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_CAPTURE';
export const LIVE_SCREENSHOT_PARITY_ENV = 'HERMTERNAL_PAPER_PARITY_APPROVED';
export const LIVE_SCREENSHOT_CLIENT_SHA_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA';
export const LIVE_SCREENSHOT_RETAIN_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_RETAIN';
export const LIVE_SCREENSHOT_REVIEW_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_REVIEW';
export const LIVE_SCREENSHOT_DESTINATION_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_DESTINATION';
export const LIVE_SCREENSHOT_FILE_STEM = 'hermternal-chat-proof';

export const LIVE_SCREENSHOT_VIEWPORT = Object.freeze({ width: 1440, height: 960 });
export const LIVE_SCREENSHOT_DEVICE_PIXEL_RATIO = 1;
export const LIVE_SCREENSHOT_BROWSER_ZOOM = 1;
export const LIVE_SCREENSHOT_LOCALE = 'en-US';
export const LIVE_SCREENSHOT_THEME_VALUES = Object.freeze(['light', 'dark']);
export const LIVE_SCREENSHOT_REDUCED_MOTION_VALUES = Object.freeze([
  'reduce',
  'no-preference'
]);
export const LIVE_SCREENSHOT_UI_STATES = Object.freeze(['empty', 'ready']);

// These values mirror the reviewed official browser-chat compatibility input.
// They are public provenance, not credentials. A mismatch is rejected rather
// than silently recording a different deployment or source revision.
export const LIVE_SCREENSHOT_HERMES_IMAGE_DIGEST =
  'sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e';
export const LIVE_SCREENSHOT_HERMES_SOURCE_SHA =
  'f5be9236e00ddf2f2a412697f267078fc4ee068e';
export const LIVE_SCREENSHOT_HERMES_ATTESTATION = 'official-upstream-image-digest';

const LIVE_SCREENSHOT_PENDING_REVIEW = 'pending-independent-review';
const LIVE_SCREENSHOT_APPROVED_REVIEW = 'independent-approved';
const MAX_IMAGE_BYTES = 32 * 1024 * 1024;
const MAX_BROWSER_VERSION_LENGTH = 128;
const MAX_RETAINED_FILE_STEM_LENGTH = 64;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const COMMIT_SHA_PATTERN = /^[a-f0-9]{40}$/u;
const SAFE_BROWSER_VERSION_PATTERN = /^[A-Za-z0-9._+ -]{1,128}$/u;
const SAFE_FILE_STEM_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/u;
const FORBIDDEN_PUBLIC_TEXT_PATTERN =
  /(?:password|credential|cookie|ticket|prompt|transcript|provider|websocket|web-socket|pty|stdout|stderr|trace|dom|html|request[._ -]?id|session[._ -]?id|hostname|secret)/iu;
const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const ATOMIC_RENAME_SCRIPT = String.raw`
import ctypes
import errno
import os
import platform
import sys

source_fd = int(sys.argv[1])
destination_fd = int(sys.argv[2])
source_name = sys.argv[3].encode('utf-8')
destination_name = sys.argv[4].encode('utf-8')

libc = ctypes.CDLL(None, use_errno=True)
if sys.platform == 'darwin':
    rename = libc.renameatx_np
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(source_fd, source_name, destination_fd, destination_name, 0x00000004)
elif sys.platform.startswith('linux'):
    rename = getattr(libc, 'renameat2', None)
    if rename is not None:
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(source_fd, source_name, destination_fd, destination_name, 0x00000001)
    else:
        syscall_number = {
            'x86_64': 316,
            'aarch64': 276,
            'arm64': 276,
        }.get(platform.machine())
        if syscall_number is None:
            raise OSError(errno.ENOTSUP, 'renameat2 is unavailable')
        syscall = libc.syscall
        syscall.restype = ctypes.c_long
        result = syscall(
            syscall_number,
            source_fd,
            source_name,
            destination_fd,
            destination_name,
            0x00000001,
        )
else:
    raise OSError(errno.ENOTSUP, 'exclusive directory rename is unavailable')

if result != 0:
    error_number = ctypes.get_errno()
    sys.exit(error_number or 1)
`;

const MANIFEST_KEYS = [
  'schema',
  'issue',
  'route',
  'viewport',
  'devicePixelRatio',
  'browser',
  'theme',
  'reducedMotion',
  'locale',
  'uiState',
  'clientSha',
  'hermes',
  'testCommand',
  'imageSha256',
  'review'
];
const VIEWPORT_KEYS = ['width', 'height'];
const BROWSER_KEYS = ['name', 'version', 'zoom'];
const HERMES_KEYS = ['imageDigest', 'sourceSha', 'attestation'];

/** @param {unknown} value */
function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** @param {unknown} value @param {string} label */
function rejectIfUnsafePublicText(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024) {
    throw new Error(`live screenshot manifest ${label} is not bounded`);
  }
  if (/[^\x20-\x7e]/u.test(value) || FORBIDDEN_PUBLIC_TEXT_PATTERN.test(value)) {
    throw new Error(`live screenshot manifest ${label} contains unsafe metadata`);
  }
}

/** @param {unknown} value @param {string[]} expected @param {string} label */
function requireExactKeys(value, expected, label) {
  if (!isRecord(value)) throw new Error(`live screenshot manifest ${label} is not an object`);
  const objectValue = /** @type {Record<string, unknown>} */ (value);
  const actual = Object.keys(objectValue);
  if (
    actual.length !== expected.length ||
    expected.some((key, index) => actual[index] !== key)
  ) {
    throw new Error(`live screenshot manifest ${label} has an unexpected shape`);
  }
}

/** @param {unknown} value */
function assertImageBytes(value) {
  // Vitest's jsdom realm and the Node Playwright realm can expose distinct
  // Uint8Array constructors. Check the transferable byte shape instead of an
  // instanceof identity that would reject a real screenshot buffer in tests.
  const candidate = /** @type {{ byteLength?: unknown, length?: unknown }} */ (value);
  if (
    value === null ||
    typeof value !== 'object' ||
    typeof candidate.byteLength !== 'number' ||
    typeof candidate.length !== 'number' ||
    candidate.length === 0 ||
    candidate.length > MAX_IMAGE_BYTES
  ) {
    throw new Error('live screenshot bytes are not bounded');
  }
  const bytes = Buffer.from(/** @type {ArrayLike<number>} */ (value));
  if (!bytes.subarray(0, PNG_SIGNATURE.length).equals(PNG_SIGNATURE)) {
    throw new Error('live screenshot bytes are not an approved PNG');
  }
  return bytes;
}

/** @param {Uint8Array} bytes */
export function sha256Hex(bytes) {
  const safeBytes = assertImageBytes(bytes);
  return createHash('sha256').update(safeBytes).digest('hex');
}

/**
 * Validate a public manifest without accepting arbitrary metadata. The exact
 * key order is intentional: canonical JSON is used as a reproducible sidecar.
 *
 * @param {unknown} value
 * @returns {Record<string, unknown>}
 */
export function validateLiveScreenshotManifest(value) {
  requireExactKeys(value, MANIFEST_KEYS, 'root');
  const manifest = /** @type {Record<string, any>} */ (value);

  if (manifest.schema !== LIVE_SCREENSHOT_MANIFEST_SCHEMA) {
    throw new Error('live screenshot manifest schema is not pinned');
  }
  if (manifest.issue !== LIVE_SCREENSHOT_ISSUE) {
    throw new Error('live screenshot manifest issue is not pinned');
  }
  if (manifest.route !== LIVE_SCREENSHOT_ROUTE) {
    throw new Error('live screenshot manifest route is not pinned');
  }
  requireExactKeys(manifest.viewport, VIEWPORT_KEYS, 'viewport');
  if (
    manifest.viewport.width !== LIVE_SCREENSHOT_VIEWPORT.width ||
    manifest.viewport.height !== LIVE_SCREENSHOT_VIEWPORT.height
  ) {
    throw new Error('live screenshot manifest viewport is not pinned');
  }
  if (manifest.devicePixelRatio !== LIVE_SCREENSHOT_DEVICE_PIXEL_RATIO) {
    throw new Error('live screenshot manifest device pixel ratio is not pinned');
  }

  requireExactKeys(manifest.browser, BROWSER_KEYS, 'browser');
  if (manifest.browser.name !== 'chromium') {
    throw new Error('live screenshot manifest browser is not pinned');
  }
  if (
    typeof manifest.browser.version !== 'string' ||
    manifest.browser.version.length > MAX_BROWSER_VERSION_LENGTH ||
    !SAFE_BROWSER_VERSION_PATTERN.test(manifest.browser.version)
  ) {
    throw new Error('live screenshot manifest browser version is not bounded');
  }
  if (manifest.browser.zoom !== LIVE_SCREENSHOT_BROWSER_ZOOM) {
    throw new Error('live screenshot manifest browser zoom is not pinned');
  }

  if (!LIVE_SCREENSHOT_THEME_VALUES.includes(manifest.theme)) {
    throw new Error('live screenshot manifest theme is not pinned');
  }
  if (!LIVE_SCREENSHOT_REDUCED_MOTION_VALUES.includes(manifest.reducedMotion)) {
    throw new Error('live screenshot manifest reduced motion is not pinned');
  }
  if (manifest.locale !== LIVE_SCREENSHOT_LOCALE) {
    throw new Error('live screenshot manifest locale is not pinned');
  }
  if (!LIVE_SCREENSHOT_UI_STATES.includes(manifest.uiState)) {
    throw new Error('live screenshot manifest UI state is not approved');
  }
  if (typeof manifest.clientSha !== 'string' || !COMMIT_SHA_PATTERN.test(manifest.clientSha)) {
    throw new Error('live screenshot manifest client SHA is not a full commit');
  }

  requireExactKeys(manifest.hermes, HERMES_KEYS, 'hermes');
  if (manifest.hermes.imageDigest !== LIVE_SCREENSHOT_HERMES_IMAGE_DIGEST) {
    throw new Error('live screenshot manifest Hermes image digest is not approved');
  }
  if (manifest.hermes.sourceSha !== LIVE_SCREENSHOT_HERMES_SOURCE_SHA) {
    throw new Error('live screenshot manifest Hermes source SHA is not approved');
  }
  if (manifest.hermes.attestation !== LIVE_SCREENSHOT_HERMES_ATTESTATION) {
    throw new Error('live screenshot manifest Hermes attestation is not approved');
  }
  if (manifest.testCommand !== LIVE_SCREENSHOT_TEST_COMMAND) {
    throw new Error('live screenshot manifest test command is not pinned');
  }
  if (typeof manifest.imageSha256 !== 'string' || !SHA256_PATTERN.test(manifest.imageSha256)) {
    throw new Error('live screenshot manifest image SHA-256 is not bounded');
  }
  if (
    manifest.review !== LIVE_SCREENSHOT_PENDING_REVIEW &&
    manifest.review !== LIVE_SCREENSHOT_APPROVED_REVIEW
  ) {
    throw new Error('live screenshot manifest review state is not approved');
  }

  // Check every public string after shape validation. This rejects a future
  // field value that attempts to smuggle a ticket, prompt, transcript, host,
  // or diagnostic even if its surrounding shape remains unchanged.
  for (const [key, text] of [
    ['schema', manifest.schema],
    ['route', manifest.route],
    ['browser.name', manifest.browser.name],
    ['browser.version', manifest.browser.version],
    ['theme', manifest.theme],
    ['reducedMotion', manifest.reducedMotion],
    ['locale', manifest.locale],
    ['uiState', manifest.uiState],
    ['clientSha', manifest.clientSha],
    ['hermes.imageDigest', manifest.hermes.imageDigest],
    ['hermes.sourceSha', manifest.hermes.sourceSha],
    ['hermes.attestation', manifest.hermes.attestation],
    ['testCommand', manifest.testCommand],
    ['imageSha256', manifest.imageSha256],
    ['review', manifest.review]
  ]) {
    rejectIfUnsafePublicText(text, key);
  }
  return manifest;
}

/**
 * @typedef {{
 *   browserName: string,
 *   browserVersion: string,
 *   clientSha: string,
 *   devicePixelRatio: number,
 *   imageSha256: string,
 *   locale: string,
 *   reducedMotion: 'reduce' | 'no-preference',
 *   theme: 'light' | 'dark',
 *   uiState: 'empty' | 'ready',
 *   zoom: number,
 *   review?: 'pending-independent-review' | 'independent-approved'
 * }} LiveScreenshotManifestInput
 */

/**
 * Build the allowlisted manifest. No timestamp, URL authority, session ID,
 * prompt, transcript, browser state, or provider payload is accepted here.
 *
 * @param {LiveScreenshotManifestInput} input
 */
export function createLiveScreenshotManifest(input) {
  const manifest = {
    schema: LIVE_SCREENSHOT_MANIFEST_SCHEMA,
    issue: LIVE_SCREENSHOT_ISSUE,
    route: LIVE_SCREENSHOT_ROUTE,
    viewport: {
      width: LIVE_SCREENSHOT_VIEWPORT.width,
      height: LIVE_SCREENSHOT_VIEWPORT.height
    },
    devicePixelRatio: input.devicePixelRatio,
    browser: {
      name: input.browserName,
      version: input.browserVersion,
      zoom: input.zoom
    },
    theme: input.theme,
    reducedMotion: input.reducedMotion,
    locale: input.locale,
    uiState: input.uiState,
    clientSha: input.clientSha,
    hermes: {
      imageDigest: LIVE_SCREENSHOT_HERMES_IMAGE_DIGEST,
      sourceSha: LIVE_SCREENSHOT_HERMES_SOURCE_SHA,
      attestation: LIVE_SCREENSHOT_HERMES_ATTESTATION
    },
    testCommand: LIVE_SCREENSHOT_TEST_COMMAND,
    imageSha256: input.imageSha256,
    review: input.review ?? LIVE_SCREENSHOT_PENDING_REVIEW
  };
  validateLiveScreenshotManifest(manifest);
  return Object.freeze(manifest);
}

/** @param {Record<string, unknown>} manifest */
export function serializeLiveScreenshotManifest(manifest) {
  validateLiveScreenshotManifest(manifest);
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

/** @param {Record<string, string | undefined>} [environment] */
export function isLiveScreenshotCaptureEnabled(environment = process.env) {
  return environment[LIVE_SCREENSHOT_CAPTURE_ENV] === '1';
}

/**
 * Replace every live-derived conversation surface with bounded, semantic
 * placeholders before the PNG is rendered. This function is intentionally
 * self-contained because Playwright serializes it into the page realm. The
 * component markers identify the only DOM regions that may contain live
 * session, transcript, provider/model metadata, or composer data; the
 * post-transform assertions fail closed if a marker or a known live value
 * remains.
 */
export function sanitizeLiveChatCapturePresentation() {
  const preview = document.querySelector('[data-testid="runtime-preview"]');
  if (!(preview instanceof HTMLElement)) {
    throw new Error('live screenshot capture workspace is unavailable');
  }
  // Keep placeholders inside this page-evaluated function; Playwright does not
  // serialize module lexical bindings with the function body.
  const modelPlaceholder = 'Model';
  const sessionCountPlaceholder = '—';

  /** @type {string[]} */
  const oldLiveValues = [];
  /** @type {string[]} */
  const oldMetadataValues = [];
  /** @param {unknown} value */
  const remember = (value) => {
    if (typeof value === 'string' && value.trim().length > 0) oldLiveValues.push(value.trim());
  };
  /** @param {unknown} value */
  const rememberMetadata = (value) => {
    remember(value);
    if (typeof value === 'string' && value.trim().length > 0) oldMetadataValues.push(value.trim());
  };
  /** @param {Element} element */
  const rememberDynamicAttributes = (element) => {
    remember(element.getAttribute('aria-label'));
    remember(element.getAttribute('title'));
    const candidate = /** @type {Element & { value?: unknown }} */ (element);
    if ('value' in candidate) remember(candidate.value);
  };

  const timeline = preview.querySelector('[data-live-content="conversation-timeline"]');
  if (!(timeline instanceof HTMLElement)) {
    throw new Error('live screenshot capture transcript surface is unavailable');
  }
  timeline.querySelectorAll(
    '.user-message, .assistant-copy, .tool-row, .approval-card, .clarification-card, .image-card, .streaming-card, .stopped-card, .loading-card'
  ).forEach((element) => {
    remember(element.textContent);
    element.querySelectorAll('[aria-label], [title]').forEach(rememberDynamicAttributes);
  });

  preview.querySelectorAll('[data-live-content="session-list"] .session-row').forEach((row) => {
    remember(row.querySelector('.pill-label')?.textContent);
    remember(row.querySelector('.pill-description')?.textContent);
    const button = row.querySelector('button');
    if (button) rememberDynamicAttributes(button);
  });

  preview.querySelectorAll('.header-model').forEach((model) => {
    rememberMetadata(model.textContent);
    rememberMetadata(model.getAttribute('aria-label'));
    rememberMetadata(model.getAttribute('title'));
  });
  preview.querySelectorAll('.group-count').forEach((count) => {
    rememberMetadata(count.textContent);
  });

  preview.querySelectorAll('[data-live-content="conversation-title"]').forEach((region) => {
    region.querySelectorAll('[aria-label="Edit conversation title"] .pill-label').forEach((label) => {
      remember(label.textContent);
    });
    region.querySelectorAll('input').forEach(rememberDynamicAttributes);
  });
  preview.querySelectorAll('[data-live-content="composer"] textarea, [data-live-content="composer"] input').forEach(
    rememberDynamicAttributes
  );

  timeline.replaceChildren();
  const conversationPlaceholder = document.createElement('div');
  conversationPlaceholder.setAttribute('aria-label', 'Conversation preview');
  conversationPlaceholder.setAttribute('data-capture-placeholder', 'conversation');
  conversationPlaceholder.textContent = 'Conversation preview';
  timeline.append(conversationPlaceholder);
  timeline.setAttribute('data-capture-sanitized', '1');
  timeline.removeAttribute('data-live-content');

  preview.querySelectorAll('[data-live-content="session-list"]').forEach((list) => {
    list.querySelectorAll('.session-row').forEach((row) => {
      const button = row.querySelector('button');
      if (!button) return;
      button.setAttribute('aria-label', 'Open conversation');
      button.setAttribute('title', 'Open conversation');
      const label = button.querySelector('.pill-label');
      if (label) label.textContent = 'Conversation';
      button.querySelector('.pill-description')?.remove();
    });
    list.setAttribute('data-capture-sanitized', '1');
    list.removeAttribute('data-live-content');
  });

  preview.querySelectorAll('.header-model').forEach((model) => {
    const label = model.querySelector('span');
    if (label) label.textContent = modelPlaceholder;
    else model.textContent = modelPlaceholder;
    model.setAttribute('aria-label', 'Current model');
    model.setAttribute('title', 'Current model');
    model.setAttribute('data-capture-sanitized', '1');
  });
  preview.querySelectorAll('.group-count').forEach((count) => {
    count.textContent = sessionCountPlaceholder;
    count.setAttribute('data-capture-sanitized', '1');
  });

  preview.querySelectorAll('[data-live-content="conversation-title"]').forEach((region) => {
    region.querySelectorAll('[aria-label="Edit conversation title"] .pill-label').forEach((label) => {
      label.textContent = 'Chat session';
    });
    region.querySelectorAll('[aria-label="Edit conversation title"]').forEach((button) => {
      button.setAttribute('aria-label', 'Edit conversation title');
      button.setAttribute('title', 'Edit conversation title');
    });
    region.querySelectorAll('input').forEach((input) => {
      input.value = '';
      input.removeAttribute('value');
      input.setAttribute('placeholder', 'Chat session');
    });
    region.setAttribute('data-capture-sanitized', '1');
    region.removeAttribute('data-live-content');
  });

  preview.querySelectorAll('[data-live-content="composer"]').forEach((composer) => {
    composer.querySelectorAll('textarea, input').forEach((input) => {
      const field = /** @type {HTMLInputElement | HTMLTextAreaElement} */ (input);
      field.value = '';
      field.removeAttribute('value');
    });
    composer.querySelectorAll('[contenteditable="true"]').forEach((element) => {
      element.textContent = '';
    });
    composer.setAttribute('data-capture-sanitized', '1');
    composer.removeAttribute('data-live-content');
  });

  const prohibitedSelectors =
    '.user-message, .assistant-copy, .tool-row, .approval-card, .clarification-card, .image-card, .streaming-card, .stopped-card, .loading-card';
  if (preview.querySelector(prohibitedSelectors)) {
    throw new Error('live screenshot capture retained prohibited conversation content');
  }
  if (preview.querySelector('[data-live-content]')) {
    throw new Error('live screenshot capture retained an unsanitized live DOM marker');
  }

  let storageText = '';
  try {
    storageText = `${Object.values(localStorage).join('\n')}\n${Object.values(sessionStorage).join('\n')}`;
  } catch {
    // Some jsdom and opaque browser documents do not expose storage. The DOM
    // marker and value checks above remain mandatory in those realms.
  }
  const serializedPage = `${document.documentElement.outerHTML}\n${storageText}`;
  const fixedPresentationText = new Set([
    'Hermes',
    'Model',
    'Current model',
    '—',
    'Conversation',
    'Open conversation',
    'Chat session',
    'Edit conversation title',
    'Conversation preview',
    'Message Hermes',
    'Conversation title'
  ]);
  const residual = [...new Set(oldLiveValues)].filter(
    (value) => value.length >= 3 && !fixedPresentationText.has(value) && serializedPage.includes(value)
  );
  const metadataResidual = [...new Set(oldMetadataValues)].filter((value) => {
    if (fixedPresentationText.has(value)) return false;
    return [...preview.querySelectorAll('.header-model, .group-count')].some((element) => {
      return (
        element.textContent?.includes(value) ||
        element.getAttribute('aria-label')?.includes(value) ||
        element.getAttribute('title')?.includes(value)
      );
    });
  });
  if (residual.length > 0 || metadataResidual.length > 0) {
    throw new Error('live screenshot capture found prohibited live text or data');
  }

  return Object.freeze({
    sanitized: true,
    removedValueCount: oldLiveValues.length,
    prohibitedNodeCount: 0
  });
}

/**
 * Read the explicit opt-in gate. A missing or malformed input is never
 * interpreted as permission to capture or retain a live screenshot.
 *
 * @param {Record<string, string | undefined>} environment
 */
function requireCaptureGate(environment) {
  if (environment[LIVE_SCREENSHOT_PARITY_ENV] !== '1') {
    throw new Error('live screenshot capture requires approved issue #352 Paper parity');
  }
  const clientSha = environment[LIVE_SCREENSHOT_CLIENT_SHA_ENV];
  if (typeof clientSha !== 'string' || !COMMIT_SHA_PATTERN.test(clientSha)) {
    throw new Error('live screenshot capture requires an explicit full client SHA');
  }
  let checkoutSha;
  try {
    checkoutSha = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    throw new Error('live screenshot capture could not attest the client checkout');
  }
  if (checkoutSha !== clientSha) {
    throw new Error('live screenshot capture client SHA does not match the checkout');
  }
  return clientSha;
}

/** @param {unknown} page @param {string} method */
function requirePageMethod(page, method) {
  const candidate = /** @type {Record<string, unknown>} */ (page);
  if (!isRecord(page) || typeof candidate[method] !== 'function') {
    throw new Error(`live screenshot capture page.${method} is unavailable`);
  }
}

/** @typedef {{ bytes: Buffer, manifest: Record<string, unknown> }} LiveScreenshotCapture */

/**
 * Capture only a reviewed, stable state. The PNG is returned in memory and is
 * not attached to Playwright, stdout, stderr, a trace, a video, or test output.
 *
 * @returns {Promise<LiveScreenshotCapture | undefined>}
 * @param {{
 *   page: any,
 *   clientSha: string,
 *   enabled?: boolean,
 *   paperParityApproved: boolean,
 *   stateStable: boolean,
 *   uiState: 'empty' | 'ready',
 *   theme?: 'light' | 'dark',
 *   reducedMotion?: 'reduce' | 'no-preference'
 * }} options
 */
export async function captureLiveChatScreenshot({
  page,
  clientSha,
  enabled = true,
  paperParityApproved,
  stateStable,
  uiState,
  theme = 'light',
  reducedMotion = 'reduce'
}) {
  if (!enabled) return undefined;
  if (paperParityApproved !== true) {
    throw new Error('live screenshot capture requires approved issue #352 Paper parity');
  }
  if (stateStable !== true) {
    throw new Error('live screenshot capture requires a stable Chat UI state');
  }
  if (!COMMIT_SHA_PATTERN.test(clientSha)) {
    throw new Error('live screenshot capture requires an explicit full client SHA');
  }
  if (!LIVE_SCREENSHOT_THEME_VALUES.includes(theme)) {
    throw new Error('live screenshot capture theme is not approved');
  }
  if (!LIVE_SCREENSHOT_REDUCED_MOTION_VALUES.includes(reducedMotion)) {
    throw new Error('live screenshot capture reduced motion is not approved');
  }
  if (!LIVE_SCREENSHOT_UI_STATES.includes(uiState)) {
    throw new Error('live screenshot capture UI state is not approved');
  }

  requirePageMethod(page, 'url');
  requirePageMethod(page, 'viewportSize');
  requirePageMethod(page, 'context');
  requirePageMethod(page, 'emulateMedia');
  requirePageMethod(page, 'evaluate');
  requirePageMethod(page, 'screenshot');

  const url = new URL(page.url());
  if (url.pathname !== LIVE_SCREENSHOT_ROUTE || url.search || url.hash) {
    throw new Error('live screenshot capture route is not the approved root route');
  }
  const viewport = page.viewportSize();
  if (
    !viewport ||
    viewport.width !== LIVE_SCREENSHOT_VIEWPORT.width ||
    viewport.height !== LIVE_SCREENSHOT_VIEWPORT.height
  ) {
    throw new Error('live screenshot capture viewport is not 1440x960');
  }

  await page.emulateMedia({
    colorScheme: theme,
    reducedMotion
  });

  const browser = page.context().browser?.();
  if (!browser || typeof browser.browserType !== 'function' || typeof browser.version !== 'function') {
    throw new Error('live screenshot capture browser provenance is unavailable');
  }
  const browserType = browser.browserType();
  const browserName = browserType?.name?.();
  const browserVersion = browser.version();
  if (browserName !== 'chromium' || typeof browserVersion !== 'string') {
    throw new Error('live screenshot capture requires Chromium browser provenance');
  }

  const observed = await page.evaluate(() => ({
    devicePixelRatio: window.devicePixelRatio,
    locale: navigator.language,
    reducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches
      ? 'reduce'
      : 'no-preference',
    theme: window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
    zoom: window.visualViewport?.scale ?? 0
  }));
  if (
    observed.devicePixelRatio !== LIVE_SCREENSHOT_DEVICE_PIXEL_RATIO ||
    observed.locale !== LIVE_SCREENSHOT_LOCALE ||
    observed.reducedMotion !== reducedMotion ||
    observed.theme !== theme ||
    observed.zoom !== LIVE_SCREENSHOT_BROWSER_ZOOM
  ) {
    throw new Error('live screenshot capture browser inputs are not pinned');
  }

  // Complete all live proof assertions before this call. The page is then
  // transformed in-place into a capture-only presentation that contains no
  // user, assistant, tool, title, provider/model metadata, session counts, or
  // composer values. The sanitizer validates the DOM and storage boundary
  // immediately before the screenshot operation.
  const presentation = await page.evaluate(sanitizeLiveChatCapturePresentation);
  if (!presentation || presentation.sanitized !== true || presentation.prohibitedNodeCount !== 0) {
    throw new Error('live screenshot capture presentation was not sanitized');
  }

  const bytes = assertImageBytes(
    await page.screenshot({
      type: 'png',
      animations: 'disabled',
      caret: 'hide',
      fullPage: false
    })
  );
  const manifest = createLiveScreenshotManifest({
    browserName,
    browserVersion,
    clientSha,
    devicePixelRatio: observed.devicePixelRatio,
    imageSha256: sha256Hex(bytes),
    locale: observed.locale,
    reducedMotion: observed.reducedMotion,
    theme: observed.theme,
    uiState,
    zoom: observed.zoom
  });
  return { bytes: Buffer.from(bytes), manifest };
}

/**
 * The live spec calls this helper after its stable-state assertions. Default
 * runs return before touching the page. Retention additionally requires an
 * explicit independent-review value and an operator-supplied destination.
 *
 * @returns {Promise<LiveScreenshotCapture | undefined>}
 * @param {{ page: any, uiState: 'empty' | 'ready', environment?: Record<string, string | undefined> }} options
 */
export async function captureLiveChatScreenshotIfEnabled({
  page,
  uiState,
  environment = process.env
}) {
  if (!isLiveScreenshotCaptureEnabled(environment)) return undefined;
  const clientSha = requireCaptureGate(environment);
  const capture = await captureLiveChatScreenshot({
    page,
    clientSha,
    enabled: true,
    paperParityApproved: true,
    stateStable: true,
    uiState
  });
  if (!capture) throw new Error('live screenshot capture result is unavailable');
  if (environment[LIVE_SCREENSHOT_RETAIN_ENV] === '1') {
    if (environment[LIVE_SCREENSHOT_REVIEW_ENV] !== LIVE_SCREENSHOT_APPROVED_REVIEW) {
      throw new Error('live screenshot retention requires independent approval');
    }
    const destination = environment[LIVE_SCREENSHOT_DESTINATION_ENV];
    if (!destination) {
      throw new Error('live screenshot retention requires an explicit destination');
    }
    await persistApprovedLiveScreenshot({
      capture,
      destinationDirectory: destination,
      fileStem: LIVE_SCREENSHOT_FILE_STEM,
      review: LIVE_SCREENSHOT_APPROVED_REVIEW
    });
  }
  return capture;
}

/** @typedef {{ candidate: string, dev: number, ino: number, canonical: string }} DirectoryEvidence */

/**
 * Verify an existing destination and every existing ancestor without following
 * a symlink. The destination is intentionally not created by this function;
 * the operator must prepare the reviewed retention directory first.
 *
 * @param {string} directory
 * @returns {DirectoryEvidence}
 */
function safeDestinationEvidence(directory) {
  const candidate = resolve(directory);
  const parsed = parse(candidate);
  const components = relative(parsed.root, candidate).split(sep).filter(Boolean);
  let current = parsed.root;
  let canonicalParent;
  try {
    canonicalParent = realpathSync(parsed.root);
  } catch {
    throw new Error('live screenshot retention root is unavailable');
  }
  let lexicalParent = parsed.root;
  const stableSystemSymlinks = new Set(['/tmp', '/var']);
  for (const component of components) {
    current = join(lexicalParent, component);
    let stats;
    let canonicalCurrent;
    try {
      stats = lstatSync(current);
      canonicalCurrent = realpathSync(current);
    } catch {
      throw new Error('live screenshot retention destination is unavailable');
    }
    const isDestination = current === candidate;
    if (stats.isSymbolicLink()) {
      if (isDestination || !stableSystemSymlinks.has(current)) {
        throw new Error('live screenshot retention destination contains a symlink');
      }
      // macOS exposes /var and /tmp through stable system symlinks. Continue
      // from their canonical inode while rejecting every project-level link.
      canonicalParent = canonicalCurrent;
      lexicalParent = current;
      continue;
    }
    if (!stats.isDirectory()) {
      throw new Error('live screenshot retention destination is not a directory');
    }
    const expectedCanonical = join(canonicalParent, component);
    if (canonicalCurrent !== expectedCanonical) {
      throw new Error('live screenshot retention destination path was replaced');
    }
    canonicalParent = canonicalCurrent;
    lexicalParent = current;
  }
  let stats;
  let canonical;
  try {
    stats = lstatSync(candidate);
    canonical = realpathSync(candidate);
  } catch {
    throw new Error('live screenshot retention destination is unavailable');
  }
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw new Error('live screenshot retention destination is not a directory');
  }
  return { candidate, dev: stats.dev, ino: stats.ino, canonical };
}

/** @param {DirectoryEvidence} evidence */
function assertSameDestination(evidence) {
  let stats;
  let canonical;
  try {
    stats = lstatSync(evidence.candidate);
    canonical = realpathSync(evidence.candidate);
  } catch {
    throw new Error('live screenshot retention destination disappeared');
  }
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    stats.dev !== evidence.dev ||
    stats.ino !== evidence.ino ||
    canonical !== evidence.canonical
  ) {
    throw new Error('live screenshot retention destination changed');
  }
}

/**
 * Open the destination only after lexical and canonical identity checks, then
 * compare the open handle's inode. Once held, the directory descriptor anchors
 * the final publication even if an attacker replaces the visible pathname.
 *
 * @param {DirectoryEvidence} evidence
 */
async function openVerifiedDestination(evidence) {
  let handle;
  try {
    handle = await fsPromises.open(evidence.candidate, 'r');
    const stats = await handle.stat();
    if (
      !stats.isDirectory() ||
      stats.dev !== evidence.dev ||
      stats.ino !== evidence.ino
    ) {
      throw new Error('live screenshot retention destination changed');
    }
    return handle;
  } catch (error) {
    if (handle) await handle.close().catch(() => undefined);
    if (error instanceof Error && error.message.includes('destination changed')) throw error;
    throw new Error('live screenshot retention destination disappeared');
  }
}

/** @param {any} handle @param {DirectoryEvidence} evidence */
async function assertDestinationHandle(handle, evidence) {
  const stats = await handle.stat();
  if (!stats.isDirectory() || stats.dev !== evidence.dev || stats.ino !== evidence.ino) {
    throw new Error('live screenshot retention destination changed');
  }
}

/** @param {string} directory */
/** @param {string} path */
function pathExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/** @param {string} directory */
async function verifyPrivateStagingDirectory(directory) {
  const stats = lstatSync(directory);
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    (stats.mode & 0o077) !== 0 ||
    (currentUid !== undefined && stats.uid !== currentUid)
  ) {
    throw new Error('live screenshot staging directory is not private');
  }
  const entries = (await fsPromises.readdir(directory)).sort();
  if (entries.length !== 2 || entries[0] !== 'manifest.json' || entries[1] !== 'screenshot.png') {
    throw new Error('live screenshot staging bundle is incomplete');
  }
  for (const entry of entries) {
    const entryPath = join(directory, entry);
    const entryStats = lstatSync(entryPath);
    if (!entryStats.isFile() || entryStats.isSymbolicLink()) {
      throw new Error('live screenshot staging bundle contains an unsafe entry');
    }
  }
}

/**
 * @param {string[]} args
 * @param {number[]} fileDescriptors
 * @returns {Promise<void>}
 */
function runAtomicRename(args, fileDescriptors) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn('python3', args, {
      stdio: ['ignore', 'ignore', 'ignore', ...fileDescriptors],
      windowsHide: true
    });
    child.once('error', rejectPromise);
    child.once('exit', (code) => {
      if (code === 0) {
        resolvePromise();
        return;
      }
      const error = /** @type {Error & { code?: number }} */ (
        new Error('exclusive directory rename failed')
      );
      error.code = code ?? 1;
      rejectPromise(error);
    });
  });
}

/**
 * Publish a complete staging directory with one exclusive atomic directory
 * rename. The Python shim calls the platform's no-replace rename primitive
 * (`renameatx_np` on macOS and `renameat2` on Linux) using open directory file
 * descriptors, so a replaced visible destination receives no bundle bytes.
 *
 * @param {{ stagingDirectory: string, destination: DirectoryEvidence, beforeAtomicPublish?: () => Promise<void> }} options
 */
async function publishStagedBundle({ stagingDirectory, destination, beforeAtomicPublish }) {
  const stagingParentPath = parse(stagingDirectory).dir;
  const stagingName = parse(stagingDirectory).base;
  const stagingParent = await fsPromises.open(stagingParentPath, 'r');
  const destinationHandle = await openVerifiedDestination(destination);
  try {
    // Test-only adversarial hook. The real lane never supplies it; the open
    // descriptor remains the publication anchor if the pathname is replaced.
    if (beforeAtomicPublish) await beforeAtomicPublish();
    assertSameDestination(destination);
    await assertDestinationHandle(destinationHandle, destination);
    await runAtomicRename(
      [
        '-c',
        ATOMIC_RENAME_SCRIPT,
        '3',
        '4',
        stagingName,
        `${LIVE_SCREENSHOT_FILE_STEM}.bundle`
      ],
      [stagingParent.fd, destinationHandle.fd]
    );
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 17) {
      throw new Error('live screenshot retention refuses to overwrite existing bundle');
    }
    if (error instanceof Error && error.message.includes('destination changed')) throw error;
    throw new Error('live screenshot retention bundle publication failed');
  } finally {
    await destinationHandle.close().catch(() => undefined);
    await stagingParent.close().catch(() => undefined);
  }
}

/**
 * Persist only the exact PNG bytes and allowlisted manifest after a manual
 * independent review. The complete bundle is built privately, then published
 * as `destination/<stem>.bundle/` in one exclusive atomic directory operation;
 * no PNG or manifest is opened through a final public pathname.
 *
 * @param {{
 *   capture: { bytes: Uint8Array, manifest: Record<string, unknown> },
 *   destinationDirectory: string,
 *   fileStem?: string,
 *   review: 'independent-approved',
 *   beforeAtomicPublish?: () => Promise<void>
 * }} options
 */
export async function persistApprovedLiveScreenshot({
  capture,
  destinationDirectory,
  fileStem = LIVE_SCREENSHOT_FILE_STEM,
  review,
  beforeAtomicPublish
}) {
  if (review !== LIVE_SCREENSHOT_APPROVED_REVIEW) {
    throw new Error('live screenshot retention requires independent approval');
  }
  if (!capture || !isRecord(capture) || !isRecord(capture.manifest)) {
    throw new Error('live screenshot capture result is unavailable');
  }
  if (!SAFE_FILE_STEM_PATTERN.test(fileStem) || fileStem.length > MAX_RETAINED_FILE_STEM_LENGTH) {
    throw new Error('live screenshot retention file name is not bounded');
  }
  if (fileStem !== LIVE_SCREENSHOT_FILE_STEM) {
    throw new Error('live screenshot retention file name is not pinned');
  }
  const bytes = assertImageBytes(capture.bytes);
  const sourceManifest = /** @type {any} */ (
    validateLiveScreenshotManifest(capture.manifest)
  );
  if (sourceManifest.review !== LIVE_SCREENSHOT_PENDING_REVIEW) {
    throw new Error('live screenshot capture is not awaiting independent review');
  }
  if (sourceManifest.imageSha256 !== sha256Hex(bytes)) {
    throw new Error('live screenshot bytes do not match the manifest hash');
  }
  const manifest = createLiveScreenshotManifest({
    browserName: sourceManifest.browser.name,
    browserVersion: sourceManifest.browser.version,
    clientSha: sourceManifest.clientSha,
    devicePixelRatio: sourceManifest.devicePixelRatio,
    imageSha256: sourceManifest.imageSha256,
    locale: sourceManifest.locale,
    reducedMotion: sourceManifest.reducedMotion,
    theme: sourceManifest.theme,
    uiState: sourceManifest.uiState,
    zoom: sourceManifest.browser.zoom,
    review: LIVE_SCREENSHOT_APPROVED_REVIEW
  });
  const manifestText = serializeLiveScreenshotManifest(manifest);
  const evidence = safeDestinationEvidence(destinationDirectory);
  const bundlePath = join(evidence.candidate, `${fileStem}.bundle`);
  if (pathExists(bundlePath)) {
    throw new Error('live screenshot retention refuses to overwrite existing bundle');
  }

  let stagingDirectory;
  let published = false;
  try {
    // Stage outside the destination pathname. Require the same filesystem so
    // the final publication remains a single atomic rename, never a copy.
    stagingDirectory = await fsPromises.mkdtemp(join(resolve(process.env.TMPDIR ?? '/tmp'), `.${fileStem}-capture-`));
    await fsPromises.chmod(stagingDirectory, 0o700);
    await fsPromises.writeFile(join(stagingDirectory, 'screenshot.png'), bytes, {
      encoding: null,
      flag: 'wx',
      mode: 0o600
    });
    await fsPromises.writeFile(join(stagingDirectory, 'manifest.json'), manifestText, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600
    });
    await verifyPrivateStagingDirectory(stagingDirectory);
    const stagingStats = lstatSync(stagingDirectory);
    const destinationStats = lstatSync(evidence.candidate);
    if (stagingStats.dev !== destinationStats.dev) {
      throw new Error('live screenshot staging filesystem is not atomic');
    }

    assertSameDestination(evidence);
    await publishStagedBundle({
      stagingDirectory,
      destination: evidence,
      beforeAtomicPublish
    });
    published = true;
    assertSameDestination(evidence);
    return {
      bundlePath,
      imagePath: join(bundlePath, 'screenshot.png'),
      manifestPath: join(bundlePath, 'manifest.json'),
      manifest
    };
  } finally {
    if (stagingDirectory && !published) {
      try {
        const stats = lstatSync(stagingDirectory);
        if (stats.isDirectory() && !stats.isSymbolicLink()) {
          await fsPromises.rm(stagingDirectory, { recursive: true, force: true });
        }
      } catch {
        // Never follow or recursively remove a replaced staging path.
      }
    }
  }
}
