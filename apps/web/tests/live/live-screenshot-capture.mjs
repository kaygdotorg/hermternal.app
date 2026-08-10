import { createRequire } from 'node:module';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import {
  accessSync,
  constants as fsConstants,
  lstatSync,
  readFileSync,
  realpathSync,
  promises as fsPromises
} from 'node:fs';
import { basename, dirname, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertLiveProofLedgerCaptureReady } from './live-proof-ledger.mjs';
import { LIVE_SCREENSHOT_COMMAND } from './live-screenshot-contract.mjs';
import { LIVE_PLAYWRIGHT_TIMEZONE_ID } from './live-playwright-config.mjs';

/**
 * This module is the only explicit screenshot path in the live lane. It is
 * opt-in, keeps screenshot bytes in memory until an independent reviewer
 * approves retention, and emits a fixed-key manifest rather than browser or
 * Hermes diagnostics. The normal live config still disables Playwright's
 * automatic screenshots, traces, videos, output retention, and unsafe reporter.
 */

export const LIVE_SCREENSHOT_MANIFEST_SCHEMA = 'hermternal.live-chat-screenshot.v2';
export const LIVE_SCREENSHOT_ISSUE = 353;
export const LIVE_SCREENSHOT_ROUTE = '/';
// Keep the retained manifest tied to the reviewed one-test command. The broad
// live runner command is intentionally not sufficient evidence for issue #353.
export const LIVE_SCREENSHOT_TEST_COMMAND = LIVE_SCREENSHOT_COMMAND;
export const LIVE_SCREENSHOT_TIMEZONE_ID = LIVE_PLAYWRIGHT_TIMEZONE_ID;
export const LIVE_SCREENSHOT_CAPTURE_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_CAPTURE';
export const LIVE_SCREENSHOT_PARITY_ENV = 'HERMTERNAL_PAPER_PARITY_APPROVED';
export const LIVE_SCREENSHOT_CLIENT_SHA_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_CLIENT_SHA';
export const LIVE_SCREENSHOT_RETAIN_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_RETAIN';
export const LIVE_SCREENSHOT_REVIEW_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_REVIEW';
export const LIVE_SCREENSHOT_DESTINATION_ENV = 'HERMTERNAL_LIVE_SCREENSHOT_DESTINATION';
export const LIVE_SCREENSHOT_FILE_STEM = 'hermternal-chat-proof';
export const LIVE_SCREENSHOT_CAPTURE_SELECTOR = '[data-capture-root="live-chat"]';

const LIVE_SCREENSHOT_PLAYWRIGHT_VERSION = '1.62.1';
const LIVE_SCREENSHOT_CHROMIUM_REVISION = '1234';
const LIVE_SCREENSHOT_CHROMIUM_VERSION = '151.0.7922.34';
const CHROMIUM_REVISION_PATTERN = /(?:^|[\\/])chromium-([0-9]+)(?:[\\/]|$)/u;
const LIVE_SCREENSHOT_MODULE_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const LIVE_SCREENSHOT_APP_ROOT = resolve(LIVE_SCREENSHOT_MODULE_DIRECTORY, '../..');
const LIVE_SCREENSHOT_REPOSITORY_ROOT = resolve(LIVE_SCREENSHOT_APP_ROOT, '../..');

/** @typedef {{ playwrightVersion: string, revision: string, version: string }} ChromiumRegistry */
/** @typedef {{ playwrightVersion: string, revision: string, version: string, executablePath: string, canonicalPath: string, executableSha256: string, dev: number, ino: number }} ChromiumProvenance */

/**
 * Resolve the registry metadata only after the explicit capture gate has been
 * accepted. Importing the default-off helper must not require a browser cache.
 * The package, app manifest, and lockfile are checked together so dependency
 * drift cannot silently select a different browsers.json.
 */
function readPinnedChromiumRegistry() {
  try {
    const require = createRequire(import.meta.url);
    /** @param {string} name */
    const packageEntry = (name) => require.resolve(`${name}/package.json`);
    const playwrightPackage = JSON.parse(readFileSync(packageEntry('playwright'), 'utf8'));
    const testPackage = JSON.parse(readFileSync(packageEntry('@playwright/test'), 'utf8'));
    const playwrightCoreEntry = require.resolve('playwright-core');
    const corePackage = JSON.parse(readFileSync(join(dirname(playwrightCoreEntry), 'package.json'), 'utf8'));
    const browsersPath = join(dirname(playwrightCoreEntry), 'browsers.json');
    const browsersManifest = JSON.parse(readFileSync(browsersPath, 'utf8'));
    const appPackage = JSON.parse(readFileSync(join(LIVE_SCREENSHOT_APP_ROOT, 'package.json'), 'utf8'));
    const lockfile = readFileSync(join(LIVE_SCREENSHOT_APP_ROOT, 'bun.lock'), 'utf8');
    const browserEntries = /** @type {Array<{ name?: unknown, revision?: unknown, browserVersion?: unknown }>} */ (
      browsersManifest.browsers ?? []
    );
    const chromiumEntry = browserEntries.find((entry) => entry.name === 'chromium');
    const playwrightDependency = appPackage.devDependencies?.playwright;
    const testDependency = appPackage.devDependencies?.['@playwright/test'];
    /** @param {string} name */
    const exactLockEntry = (name) =>
      lockfile.includes(`\"${name}\": [\"${name}@${LIVE_SCREENSHOT_PLAYWRIGHT_VERSION}\"`);
    if (
      playwrightPackage.name !== 'playwright' ||
      playwrightPackage.version !== LIVE_SCREENSHOT_PLAYWRIGHT_VERSION ||
      playwrightPackage.dependencies?.['playwright-core'] !== LIVE_SCREENSHOT_PLAYWRIGHT_VERSION ||
      testPackage.name !== '@playwright/test' ||
      testPackage.version !== LIVE_SCREENSHOT_PLAYWRIGHT_VERSION ||
      testPackage.dependencies?.playwright !== LIVE_SCREENSHOT_PLAYWRIGHT_VERSION ||
      corePackage.name !== 'playwright-core' ||
      corePackage.version !== LIVE_SCREENSHOT_PLAYWRIGHT_VERSION ||
      playwrightDependency !== LIVE_SCREENSHOT_PLAYWRIGHT_VERSION ||
      testDependency !== LIVE_SCREENSHOT_PLAYWRIGHT_VERSION ||
      !exactLockEntry('@playwright/test') ||
      !exactLockEntry('playwright') ||
      !exactLockEntry('playwright-core') ||
      !chromiumEntry ||
      chromiumEntry.revision !== LIVE_SCREENSHOT_CHROMIUM_REVISION ||
      chromiumEntry.browserVersion !== LIVE_SCREENSHOT_CHROMIUM_VERSION
    ) {
      throw new Error('pinned Playwright or Chromium metadata is unavailable');
    }
    return Object.freeze({
      playwrightVersion: LIVE_SCREENSHOT_PLAYWRIGHT_VERSION,
      revision: chromiumEntry.revision,
      version: chromiumEntry.browserVersion
    });
  } catch {
    throw new Error('live screenshot capture could not derive pinned Chromium registry');
  }
}

/**
 * Resolve and validate the registry-derived executable path at capture time.
 * The path is an observation used to bind the running browser; it is never
 * retained in the public manifest or accepted from environment input.
 */
function readPinnedChromiumProvenance() {
  const registry = readPinnedChromiumRegistry();
  try {
    const require = createRequire(import.meta.url);
    const playwright = require('playwright');
    const executablePath = playwright.chromium.executablePath();
    if (typeof executablePath !== 'string' || !CHROMIUM_REVISION_PATTERN.test(executablePath)) {
      throw new Error('pinned Chromium executable path is unavailable');
    }
    const revisionMatch = executablePath.match(CHROMIUM_REVISION_PATTERN);
    if (!revisionMatch || revisionMatch[1] !== registry.revision) {
      throw new Error('pinned Chromium executable revision is not approved');
    }
    const statsBefore = lstatSync(executablePath);
    accessSync(executablePath, fsConstants.X_OK);
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
    if (
      !statsBefore.isFile() ||
      statsBefore.isSymbolicLink() ||
      (currentUid !== undefined && statsBefore.uid !== currentUid) ||
      (statsBefore.mode & 0o022) !== 0
    ) {
      throw new Error('pinned Chromium executable is not a private regular file');
    }
    const canonicalPath = realpathSync(executablePath);
    if (canonicalPath !== executablePath) {
      throw new Error('pinned Chromium executable path is not canonical');
    }
    const executableSha256 = createHash('sha256').update(readFileSync(executablePath)).digest('hex');
    const statsAfter = lstatSync(executablePath);
    if (
      !statsAfter.isFile() ||
      statsAfter.isSymbolicLink() ||
      statsAfter.dev !== statsBefore.dev ||
      statsAfter.ino !== statsBefore.ino ||
      statsAfter.size !== statsBefore.size ||
      realpathSync(executablePath) !== canonicalPath ||
      createHash('sha256').update(readFileSync(executablePath)).digest('hex') !== executableSha256
    ) {
      throw new Error('pinned Chromium executable changed during validation');
    }
    return Object.freeze({
      ...registry,
      executablePath,
      canonicalPath,
      executableSha256,
      dev: statsAfter.dev,
      ino: statsAfter.ino
    });
  } catch {
    throw new Error('live screenshot capture could not derive pinned Chromium provenance');
  }
}

/**
 * Resolve the only supported opt-in browser launch. Registry metadata is
 * validated before Playwright is asked for its executable path; the returned
 * path and digest are then revalidated by the capture helper before and after
 * page work. The digest is passed only through the test process environment,
 * never into public screenshot metadata except as an integrity hash.
 */
export function getLiveScreenshotChromiumLaunchOptions(environment = process.env) {
  if (!isLiveScreenshotCaptureEnabled(environment)) {
    return Object.freeze({ headless: true });
  }
  const configuration = validateLiveScreenshotCaptureConfiguration(environment);
  if (!configuration) throw new Error('live screenshot capture configuration is unavailable');
  const { provenance } = configuration;
  return Object.freeze({
    headless: true,
    executablePath: provenance.executablePath
  });
}

export function getLiveScreenshotChromiumRegistry() {
  return readPinnedChromiumRegistry();
}

export function getLiveScreenshotChromiumProvenance() {
  return readPinnedChromiumProvenance();
}

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
const TRUSTED_PYTHON_EXECUTABLES = Object.freeze([
  '/usr/bin/python3',
  '/opt/homebrew/bin/python3',
  '/usr/local/bin/python3',
  '/opt/local/bin/python3'
]);
const TRUSTED_STAGING_SYSTEM_ROOT = process.platform === 'darwin' ? '/private/tmp' : '/tmp';
const ATOMIC_RENAME_SCRIPT = String.raw`
import ctypes
import errno
import os
import platform
import stat
import sys

source_fd = int(sys.argv[1])
destination_fd = int(sys.argv[2])
source_name = sys.argv[3].encode('utf-8')
destination_name = sys.argv[4].encode('utf-8')
source_dev = int(sys.argv[5])
source_ino = int(sys.argv[6])
parent_dev = int(sys.argv[7])
parent_ino = int(sys.argv[8])
screenshot_dev = int(sys.argv[9])
screenshot_ino = int(sys.argv[10])
screenshot_size = int(sys.argv[11])
manifest_dev = int(sys.argv[12])
manifest_ino = int(sys.argv[13])
manifest_size = int(sys.argv[14])

def verify_source():
    parent_stat = os.fstat(source_fd)
    if parent_stat.st_dev != parent_dev or parent_stat.st_ino != parent_ino:
        raise OSError(errno.EAGAIN, 'staging parent identity changed')
    source_directory_fd = os.open(
        source_name,
        os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0),
        dir_fd=source_fd,
    )
    try:
        source_stat = os.fstat(source_directory_fd)
        if (
            not stat.S_ISDIR(source_stat.st_mode)
            or source_stat.st_dev != source_dev
            or source_stat.st_ino != source_ino
        ):
            raise OSError(errno.EAGAIN, 'staging directory identity changed')
        for name, expected_dev, expected_ino, expected_size in (
            (b'screenshot.png', screenshot_dev, screenshot_ino, screenshot_size),
            (b'manifest.json', manifest_dev, manifest_ino, manifest_size),
        ):
            entry_stat = os.stat(name, dir_fd=source_directory_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(entry_stat.st_mode)
                or entry_stat.st_dev != expected_dev
                or entry_stat.st_ino != expected_ino
                or entry_stat.st_size != expected_size
            ):
                raise OSError(errno.EAGAIN, 'staging entry identity changed')
    finally:
        os.close(source_directory_fd)

verify_source()

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

/** @returns {string} */
function trustedPythonExecutable() {
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  for (const candidate of TRUSTED_PYTHON_EXECUTABLES) {
    try {
      const expectedPath = resolve(candidate);
      const canonicalPath = realpathSync(expectedPath);
      if (canonicalPath !== expectedPath) continue;
      let current = expectedPath;
      for (;;) {
        const stats = lstatSync(current);
        const canonical = realpathSync(current);
        if (
          (current !== expectedPath && !stats.isDirectory()) ||
          stats.isSymbolicLink() ||
          canonical !== resolve(current) ||
          (stats.mode & 0o022) !== 0
        ) {
          throw new Error('untrusted Python path component');
        }
        if (current === parse(current).root) break;
        current = dirname(current);
      }
      const stats = lstatSync(expectedPath);
      accessSync(expectedPath, fsConstants.X_OK);
      if (
        stats.isFile() &&
        !stats.isSymbolicLink() &&
        (currentUid === undefined || stats.uid === currentUid || stats.uid === 0) &&
        (stats.mode & 0o022) === 0
      ) {
        return expectedPath;
      }
    } catch {
      // Try the next fixed system path. Environment PATH is intentionally not
      // consulted because it is not a trusted executable-selection boundary.
    }
  }
  throw new Error('live screenshot atomic rename Python executable is unavailable');
}

const ATOMIC_RENAME_CHILD_ENVIRONMENT = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  LC_ALL: 'C',
  LANG: 'C',
  PYTHONNOUSERSITE: '1'
});

export function getLiveScreenshotAtomicRenameChildConfiguration() {
  return Object.freeze({
    executable: trustedPythonExecutable(),
    environment: ATOMIC_RENAME_CHILD_ENVIRONMENT
  });
}

/**
 * @typedef {{ path: string, canonical: string, dev: number, ino: number, systemCanonical: string, systemDev: number, systemIno: number }} StagingParentEvidence
 */

/** @returns {{ canonical: string, dev: number, ino: number }} */
function readTrustedStagingSystemRoot() {
  try {
    const stats = lstatSync(TRUSTED_STAGING_SYSTEM_ROOT);
    const canonical = realpathSync(TRUSTED_STAGING_SYSTEM_ROOT);
    if (
      !stats.isDirectory() ||
      stats.isSymbolicLink() ||
      canonical !== resolve(TRUSTED_STAGING_SYSTEM_ROOT) ||
      ((stats.mode & 0o002) !== 0 && (stats.mode & 0o1000) === 0)
    ) {
      throw new Error('live screenshot staging system root is unsafe');
    }
    return { canonical, dev: stats.dev, ino: stats.ino };
  } catch (error) {
    if (error instanceof Error && error.message === 'live screenshot staging system root is unsafe') {
      throw error;
    }
    throw new Error('live screenshot staging system root is unavailable');
  }
}

/** @param {string} path @param {{ canonical: string, dev: number, ino: number }} systemRoot @returns {StagingParentEvidence} */
function readStagingParentEvidence(path, systemRoot) {
  try {
    const stats = lstatSync(path);
    const canonical = realpathSync(path);
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
    if (
      !stats.isDirectory() ||
      stats.isSymbolicLink() ||
      (stats.mode & 0o077) !== 0 ||
      (currentUid !== undefined && stats.uid !== currentUid) ||
      canonical !== resolve(path)
    ) {
      throw new Error('live screenshot staging parent is not private');
    }
    return {
      path,
      canonical,
      dev: stats.dev,
      ino: stats.ino,
      systemCanonical: systemRoot.canonical,
      systemDev: systemRoot.dev,
      systemIno: systemRoot.ino
    };
  } catch (error) {
    if (error instanceof Error && error.message === 'live screenshot staging parent is not private') {
      throw error;
    }
    throw new Error('live screenshot staging parent is unavailable');
  }
}

/** @param {StagingParentEvidence} expected */
function assertStagingParentEvidence(expected) {
  let observed;
  try {
    const systemRoot = readTrustedStagingSystemRoot();
    if (
      systemRoot.canonical !== expected.systemCanonical ||
      systemRoot.dev !== expected.systemDev ||
      systemRoot.ino !== expected.systemIno
    ) {
      throw new Error('live screenshot staging parent changed');
    }
    observed = readStagingParentEvidence(expected.path, systemRoot);
  } catch {
    throw new Error('live screenshot staging parent changed');
  }
  if (
    observed.canonical !== expected.canonical ||
    observed.dev !== expected.dev ||
    observed.ino !== expected.ino
  ) {
    throw new Error('live screenshot staging parent changed');
  }
  return observed;
}

/** @returns {Promise<StagingParentEvidence>} */
async function createPrivateStagingParent() {
  const systemBefore = readTrustedStagingSystemRoot();
  const path = await fsPromises.mkdtemp(join(systemBefore.canonical, '.hermternal-live-staging-parent-'));
  let createdIdentity;
  try {
    const createdStats = lstatSync(path);
    if (!createdStats.isDirectory() || createdStats.isSymbolicLink()) {
      throw new Error('live screenshot staging parent is not private');
    }
    createdIdentity = { dev: createdStats.dev, ino: createdStats.ino };
    await fsPromises.chmod(path, 0o700);
    const systemAfter = readTrustedStagingSystemRoot();
    if (
      systemAfter.canonical !== systemBefore.canonical ||
      systemAfter.dev !== systemBefore.dev ||
      systemAfter.ino !== systemBefore.ino
    ) {
      throw new Error('live screenshot staging system root changed');
    }
    const evidence = readStagingParentEvidence(path, systemBefore);
    if (evidence.dev !== createdIdentity.dev || evidence.ino !== createdIdentity.ino) {
      throw new Error('live screenshot staging parent changed');
    }
    return evidence;
  } catch (error) {
    if (createdIdentity) {
      try {
        const current = lstatSync(path);
        if (
          current.isDirectory() &&
          !current.isSymbolicLink() &&
          current.dev === createdIdentity.dev &&
          current.ino === createdIdentity.ino
        ) {
          await fsPromises.rmdir(path);
        }
      } catch {
        // Never follow a replacement path during rollback. The original fixed
        // creation failure remains the only public result.
      }
    }
    if (error instanceof Error && error.message.startsWith('live screenshot staging')) throw error;
    throw new Error('live screenshot staging parent is unavailable');
  }
}

/** @param {string} path @param {StagingParentEvidence} expected */
async function removePrivateStagingParent(path, expected) {
  if (resolve(path) !== resolve(expected.path)) {
    throw new Error('live screenshot staging parent identity changed');
  }
  const observed = assertStagingParentEvidence(expected);
  const tombstone = join(
    dirname(expected.path),
    `.${basename(expected.path)}-cleanup-${randomBytes(12).toString('hex')}`
  );
  try {
    await fsPromises.rename(expected.path, tombstone);
  } catch (error) {
    if (isNotFoundError(error)) return;
    throw new Error('live screenshot staging parent cleanup failed');
  }
  let tombstoneStats;
  try {
    tombstoneStats = lstatSync(tombstone);
  } catch {
    throw new Error('live screenshot staging parent cleanup failed');
  }
  if (
    !tombstoneStats.isDirectory() ||
    tombstoneStats.isSymbolicLink() ||
    tombstoneStats.dev !== observed.dev ||
    tombstoneStats.ino !== observed.ino
  ) {
    throw new Error('live screenshot staging parent identity changed');
  }
  try {
    await fsPromises.rmdir(tombstone);
  } catch (error) {
    if (isNotFoundError(error)) return;
    throw new Error('live screenshot staging parent cleanup failed');
  }
}

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
  'timezoneId',
  'uiState',
  'clientSha',
  'hermes',
  'testCommand',
  'imageSha256',
  'review'
];
const VIEWPORT_KEYS = ['width', 'height'];
const BROWSER_KEYS = ['name', 'version', 'revision', 'executableSha256', 'zoom'];
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
  if (FORBIDDEN_PUBLIC_TEXT_PATTERN.test(manifest.browser.version)) {
    throw new Error('live screenshot manifest browser.version contains unsafe metadata');
  }
  if (manifest.browser.version !== readPinnedChromiumRegistry().version) {
    throw new Error('live screenshot manifest Chromium version is not pinned');
  }
  if (
    typeof manifest.browser.revision !== 'string' ||
    !/^[0-9]+$/u.test(manifest.browser.revision)
  ) {
    throw new Error('live screenshot manifest browser revision is not bounded');
  }
  if (manifest.browser.revision !== readPinnedChromiumRegistry().revision) {
    throw new Error('live screenshot manifest Chromium revision is not pinned');
  }
  if (
    typeof manifest.browser.executableSha256 !== 'string' ||
    !SHA256_PATTERN.test(manifest.browser.executableSha256)
  ) {
    throw new Error('live screenshot manifest executable digest is not bounded');
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
  if (manifest.timezoneId !== LIVE_SCREENSHOT_TIMEZONE_ID) {
    throw new Error('live screenshot manifest timezone is not pinned');
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
    ['browser.revision', manifest.browser.revision],
    ['browser.executableSha256', manifest.browser.executableSha256],
    ['theme', manifest.theme],
    ['reducedMotion', manifest.reducedMotion],
    ['locale', manifest.locale],
    ['timezoneId', manifest.timezoneId],
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
 *   browserRevision: string,
 *   browserVersion: string,
 *   browserExecutableSha256: string,
 *   clientSha: string,
 *   devicePixelRatio: number,
 *   imageSha256: string,
 *   locale: string,
 *   timezoneId: string,
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
      revision: input.browserRevision,
      executableSha256: input.browserExecutableSha256,
      zoom: input.zoom
    },
    theme: input.theme,
    reducedMotion: input.reducedMotion,
    locale: input.locale,
    timezoneId: input.timezoneId,
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
 * placeholders before the PNG is rendered. The live Svelte tree is never the
 * screenshot target: after validation this function creates an inert,
 * listener-free DOM clone that cannot receive WebSocket or component updates.
 * This function is self-contained because Playwright serializes it into the
 * page realm.
 *
 * @param {string[]} [sensitiveMarkers]
 */
export async function sanitizeLiveChatCapturePresentation(sensitiveMarkers = []) {
  const preview = document.querySelector('[data-testid="runtime-preview"]');
  if (!(preview instanceof HTMLElement)) {
    throw new Error('live screenshot capture workspace is unavailable');
  }
  const sourceContainer = preview.parentElement;
  if (!(sourceContainer instanceof HTMLElement)) {
    throw new Error('live screenshot capture workspace container is unavailable');
  }
  const captureSelector = '[data-capture-root="live-chat"]';
  document.querySelectorAll(captureSelector).forEach((node) => node.remove());
  if (document.querySelector(captureSelector)) {
    throw new Error('live screenshot capture found an unremovable capture root');
  }

  // Keep placeholders inside this page-evaluated function; Playwright does not
  // serialize module lexical bindings with the function body.
  const modelPlaceholder = 'Model';
  const sessionCountPlaceholder = '—';

  /** @returns {never} */
  const privacyOverflow = () => {
    throw new Error('live screenshot capture privacy scan exceeded bounds');
  };
  const maxSensitiveValues = 512;
  const maxSensitiveValueLength = 4 * 1024;
  const maxStorageEntries = 256;
  const maxStorageBytes = 1024 * 1024;
  const maxIndexedDbDatabases = 32;
  const maxIndexedDbStores = 128;
  const maxIndexedDbRecords = 512;
  const maxCacheEntries = 64;
  const maxCacheRequests = 512;
  const maxCacheHeaders = 256;
  const maxCacheBodyBytes = 4 * 1024 * 1024;
  /** @type {string[]} */
  const oldLiveValues = [];
  /** @type {string[]} */
  const oldMetadataValues = [];
  /** @param {unknown} value */
  const remember = (value) => {
    if (typeof value !== 'string') return;
    const trimmed = value.trim();
    if (trimmed.length === 0) return;
    if (trimmed.length > maxSensitiveValueLength || oldLiveValues.length >= maxSensitiveValues) {
      privacyOverflow();
    }
    oldLiveValues.push(trimmed);
  };
  /** @param {unknown} value */
  const rememberMetadata = (value) => {
    if (typeof value !== 'string') return;
    const trimmed = value.trim();
    if (trimmed.length === 0) return;
    if (trimmed.length > maxSensitiveValueLength || oldMetadataValues.length >= maxSensitiveValues) {
      privacyOverflow();
    }
    oldMetadataValues.push(trimmed);
  };
  const markerValues = [
    ...(Array.isArray(sensitiveMarkers) ? sensitiveMarkers : []),
    'password',
    'prompt',
    'completion',
    'ticket'
  ].filter((value) => typeof value === 'string' && value.length > 0 && value.length <= maxSensitiveValueLength);
  const markerPattern = /(?:password|prompt|completion|ticket)/iu;
  /** @param {unknown} value @returns {string} */
  const inspectionText = (value) => {
    if (typeof value === 'string') {
      if (value.length > maxSensitiveValueLength) privacyOverflow();
      return value;
    }
    let serialized = '';
    try {
      serialized = JSON.stringify(value) ?? '';
    } catch {
      privacyOverflow();
    }
    if (serialized.length > maxSensitiveValueLength) {
      privacyOverflow();
    }
    return serialized;
  };
  /** @param {unknown} value */
  const containsPrivacyMarker = (value) => {
    const text = inspectionText(value);
    return markerPattern.test(text) || markerValues.some((marker) => {
      if (marker.length <= 1) {
        const escaped = marker.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
        return new RegExp(`(?:^|[^\\p{L}\\p{N}_])${escaped}(?:$|[^\\p{L}\\p{N}_])`, 'u').test(text);
      }
      return text.includes(marker);
    });
  };
  /** @param {Element} element */
  const rememberDynamicAttributes = (element) => {
    remember(element.getAttribute('aria-label'));
    remember(element.getAttribute('title'));
    const candidate = /** @type {Element & { value?: unknown }} */ (element);
    if ('value' in candidate) remember(candidate.value);
  };
  /** @param {Element} element */
  const rememberMetadataElement = (element) => {
    const nodes = [element, ...element.querySelectorAll('*')];
    for (const node of nodes) {
      rememberMetadata(node.textContent);
      for (const name of node.getAttributeNames()) {
        if (name === 'class' || name === 'style') continue;
        rememberMetadata(node.getAttribute(name));
      }
      const candidate = /** @type {Element & { value?: unknown }} */ (node);
      if ('value' in candidate) rememberMetadata(candidate.value);
    }
  };
  /** @param {Element} element */
  const clearMetadataAttributes = (element) => {
    for (const name of element.getAttributeNames()) {
      if (name.startsWith('aria-') || name === 'title' || name === 'value' || name.startsWith('data-')) {
        element.removeAttribute(name);
      }
    }
  };
  /** @param {Element} element @param {string} value */
  const metadataSurfaceContains = (element, value) => {
    const nodes = [element, ...element.querySelectorAll('*')];
    return nodes.some((node) => {
      if (node.textContent?.trim() === value) return true;
      const candidate = /** @type {Element & { value?: unknown }} */ (node);
      if (typeof candidate.value === 'string' && candidate.value === value) return true;
      return node.getAttributeNames().some((name) => {
        if (name === 'class' || name === 'style' || name === 'data-capture-sanitized') return false;
        if (!name.startsWith('aria-') && name !== 'title' && name !== 'value' && !name.startsWith('data-')) {
          return false;
        }
        return node.getAttribute(name) === value;
      });
    });
  };
  /** @param {Element} element */
  const serializeMetadataSurface = (element) => {
    const projection = /** @type {Element} */ (element.cloneNode(true));
    [projection, ...projection.querySelectorAll('*')].forEach((node) => {
      node.getAttributeNames().forEach((name) => {
        if (
          name === 'class' ||
          name === 'style' ||
          name === 'data-capture-sanitized' ||
          (!name.startsWith('aria-') && name !== 'title' && name !== 'value' && !name.startsWith('data-'))
        ) {
          node.removeAttribute(name);
        }
      });
    });
    return projection.outerHTML;
  };

  // These selectors are the current WorkspacePreview component contract. The
  // old data-live-content markers were never emitted by Timeline, SessionList,
  // ConversationHeader, or Composer and caused the f7 live-component proof to
  // fail before it could sanitize the actual page.
  const timeline = preview.querySelector('[data-testid="conversation-timeline"]');
  if (!(timeline instanceof HTMLElement)) {
    throw new Error('live screenshot capture transcript surface is unavailable');
  }
  timeline.querySelectorAll(
    '.user-message, .assistant-copy, .tool-row, .approval-card, .clarification-card, .image-card, .streaming-card, .stopped-card, .loading-card'
  ).forEach((element) => {
    remember(element.textContent);
    element.querySelectorAll('[aria-label], [title]').forEach(rememberDynamicAttributes);
  });

  preview.querySelectorAll('nav[aria-label="Conversations"].session-list .session-row').forEach((row) => {
    remember(row.querySelector('.pill-label')?.textContent);
    remember(row.querySelector('.pill-description')?.textContent);
    const button = row.querySelector('button');
    if (button) rememberDynamicAttributes(button);
  });

  const metadataElements = [
    ...preview.querySelectorAll('.header-model, .group-count, .model-control, .model-control select, .model-control option')
  ];
  metadataElements.forEach(rememberMetadataElement);

  preview.querySelectorAll('button[aria-label="Edit conversation title"] .pill-label').forEach((label) => {
    remember(label.textContent);
  });
  preview.querySelectorAll('.title-region input').forEach(rememberDynamicAttributes);
  preview.querySelectorAll('form[aria-label="Message composer"].composer textarea, form[aria-label="Message composer"].composer input').forEach(
    rememberDynamicAttributes
  );

  timeline.replaceChildren();
  const conversationPlaceholder = document.createElement('div');
  conversationPlaceholder.setAttribute('aria-label', 'Conversation preview');
  conversationPlaceholder.setAttribute('data-capture-placeholder', 'conversation');
  conversationPlaceholder.textContent = 'Conversation preview';
  timeline.append(conversationPlaceholder);
  timeline.setAttribute('data-capture-sanitized', 'true');
  timeline.removeAttribute('data-live-content');

  preview.querySelectorAll('nav[aria-label="Conversations"].session-list').forEach((list) => {
    list.querySelectorAll('.session-row').forEach((row) => {
      const button = row.querySelector('button');
      if (!button) return;
      button.setAttribute('aria-label', 'Open conversation');
      button.setAttribute('title', 'Open conversation');
      const label = button.querySelector('.pill-label');
      if (label) label.textContent = 'Conversation';
      button.querySelector('.pill-description')?.remove();
    });
    list.setAttribute('data-capture-sanitized', 'true');
    list.removeAttribute('data-live-content');
  });

  preview.querySelectorAll('.header-model').forEach((model) => {
    const label = model.querySelector('span');
    if (label) label.textContent = modelPlaceholder;
    else {
      const replacement = document.createElement('span');
      replacement.textContent = modelPlaceholder;
      model.append(replacement);
    }
    clearMetadataAttributes(model);
    model.setAttribute('aria-label', 'Current model');
    model.setAttribute('title', 'Current model');
    model.setAttribute('data-capture-sanitized', 'true');
  });
  preview.querySelectorAll('.group-count').forEach((count) => {
    count.textContent = sessionCountPlaceholder;
    clearMetadataAttributes(count);
    count.setAttribute('data-capture-sanitized', 'true');
  });
  preview.querySelectorAll('.model-control').forEach((control) => {
    clearMetadataAttributes(control);
    const shortLabel = control.querySelector('.model-short');
    if (shortLabel) shortLabel.textContent = modelPlaceholder;
    const select = control.querySelector('select');
    if (select) {
      const width = select.getBoundingClientRect().width;
      select.replaceChildren();
      const option = document.createElement('option');
      option.value = modelPlaceholder;
      option.textContent = modelPlaceholder;
      option.selected = true;
      select.append(option);
      select.value = modelPlaceholder;
      clearMetadataAttributes(select);
      select.setAttribute('aria-label', 'Model');
      if (width > 0) select.style.width = `${width}px`;
    }
    control.setAttribute('data-capture-sanitized', 'true');
  });

  // Clear metadata-bearing attributes on descendants as well as the root. The
  // desktop and mobile copies contain separate icon/select subtrees, so a
  // source value in an aria/data/title/value attribute must not survive only
  // because the visible root was replaced.
  preview.querySelectorAll('.header-model, .group-count, .model-control').forEach((root) => {
    [root, ...root.querySelectorAll('*')].forEach(clearMetadataAttributes);
  });
  preview.querySelectorAll('.header-model').forEach((model) => {
    model.setAttribute('aria-label', 'Current model');
    model.setAttribute('title', 'Current model');
    model.setAttribute('data-capture-sanitized', 'true');
  });
  preview.querySelectorAll('.group-count').forEach((count) => {
    count.setAttribute('data-capture-sanitized', 'true');
  });
  preview.querySelectorAll('.model-control').forEach((control) => {
    control.setAttribute('data-capture-sanitized', 'true');
    control.querySelector('select')?.setAttribute('aria-label', 'Model');
  });

  preview.querySelectorAll('button[aria-label="Edit conversation title"]').forEach((button) => {
    const label = button.querySelector('.pill-label');
    if (label) label.textContent = 'Chat session';
    button.setAttribute('aria-label', 'Edit conversation title');
    button.setAttribute('title', 'Edit conversation title');
    button.setAttribute('data-capture-sanitized', 'true');
  });
  preview.querySelectorAll('.title-region input').forEach((input) => {
    const field = /** @type {HTMLInputElement} */ (input);
    field.value = '';
    field.removeAttribute('value');
    field.setAttribute('placeholder', 'Chat session');
  });
  preview.querySelectorAll('.title-region').forEach((region) => {
    region.setAttribute('data-capture-sanitized', 'true');
    region.removeAttribute('data-live-content');
  });

  preview.querySelectorAll('form[aria-label="Message composer"].composer').forEach((composer) => {
    composer.querySelectorAll('textarea, input').forEach((input) => {
      const field = /** @type {HTMLInputElement | HTMLTextAreaElement} */ (input);
      field.value = '';
      field.removeAttribute('value');
    });
    composer.querySelectorAll('[contenteditable="true"]').forEach((element) => {
      element.textContent = '';
    });
    composer.setAttribute('data-capture-sanitized', 'true');
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

  /** @param {Storage} storage */
  const scrubStorage = (storage) => {
    if (!storage || typeof storage.length !== 'number' || typeof storage.key !== 'function' || typeof storage.clear !== 'function') {
      throw new Error('live screenshot capture storage boundary is unavailable');
    }
    let entryCount = 0;
    let byteCount = 0;
    for (let index = 0; index < storage.length; index += 1) {
      entryCount += 1;
      if (entryCount > maxStorageEntries) privacyOverflow();
      const key = storage.key(index);
      if (typeof key !== 'string') throw new Error('live screenshot capture storage boundary is unavailable');
      const value = storage.getItem(key);
      if (typeof value !== 'string') throw new Error('live screenshot capture storage boundary is unavailable');
      byteCount += key.length + value.length;
      if (byteCount > maxStorageBytes) privacyOverflow();
      rememberMetadata(key);
      rememberMetadata(value);
      containsPrivacyMarker(key);
      containsPrivacyMarker(value);
    }
    storage.clear();
    if (storage.length !== 0) throw new Error('live screenshot capture storage was not cleared');
    return entryCount;
  };
  if (typeof localStorage === 'undefined' || typeof sessionStorage === 'undefined') {
    throw new Error('live screenshot capture storage boundary is unavailable');
  }
  const localStorageEntryCount = scrubStorage(localStorage);
  const sessionStorageEntryCount = scrubStorage(sessionStorage);

  const listIndexedDbDatabases = async () => {
    if (typeof indexedDB === 'undefined' || typeof indexedDB.databases !== 'function' || typeof indexedDB.open !== 'function') {
      throw new Error('live screenshot capture IndexedDB boundary is unavailable');
    }
    const databases = await indexedDB.databases();
    if (!Array.isArray(databases) || databases.length > maxIndexedDbDatabases) privacyOverflow();
    return databases;
  };
  /** @param {string} name @returns {Promise<IDBDatabase>} */
  const openIndexedDb = (name) => new Promise((resolve, reject) => {
    const request = indexedDB.open(name);
    request.onerror = () => reject(new Error('live screenshot capture IndexedDB boundary is unavailable'));
    request.onblocked = () => reject(new Error('live screenshot capture IndexedDB deletion was blocked'));
    request.onsuccess = () => resolve(request.result);
  });
  /** @param {IDBDatabase} database @param {string} storeName @returns {Promise<number>} */
  const scanIndexedDbStore = (database, storeName) => new Promise((resolve, reject) => {
    let recordCount = 0;
    let request;
    try {
      request = database.transaction(storeName, 'readonly').objectStore(storeName).openCursor();
    } catch {
      reject(new Error('live screenshot capture IndexedDB boundary is unavailable'));
      return;
    }
    request.onerror = () => reject(new Error('live screenshot capture IndexedDB boundary is unavailable'));
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) {
        resolve(recordCount);
        return;
      }
      recordCount += 1;
      if (recordCount > maxIndexedDbRecords) {
        reject(new Error('live screenshot capture privacy scan exceeded bounds'));
        return;
      }
      containsPrivacyMarker(cursor.key);
      containsPrivacyMarker(cursor.value);
      cursor.continue();
    };
  });
  /** @param {string} name @returns {Promise<void>} */
  const deleteIndexedDb = (name) => new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onerror = () => reject(new Error('live screenshot capture IndexedDB deletion failed'));
    request.onblocked = () => reject(new Error('live screenshot capture IndexedDB deletion was blocked'));
    request.onsuccess = () => resolve(undefined);
  });
  const indexedDbBefore = await listIndexedDbDatabases();
  let indexedDbStoreCount = 0;
  let indexedDbRecordCount = 0;
  for (const databaseInfo of indexedDbBefore) {
    if (!databaseInfo || typeof databaseInfo.name !== 'string' || databaseInfo.name.length > maxSensitiveValueLength) {
      privacyOverflow();
    }
    const databaseName = /** @type {string} */ (databaseInfo.name);
    containsPrivacyMarker(databaseName);
    const database = await openIndexedDb(databaseName);
    try {
      const storeNames = [...database.objectStoreNames];
      indexedDbStoreCount += storeNames.length;
      if (indexedDbStoreCount > maxIndexedDbStores) privacyOverflow();
      for (const storeName of storeNames) {
        if (typeof storeName !== 'string' || storeName.length > maxSensitiveValueLength) privacyOverflow();
        containsPrivacyMarker(storeName);
        indexedDbRecordCount += await scanIndexedDbStore(database, storeName);
        if (indexedDbRecordCount > maxIndexedDbRecords) privacyOverflow();
      }
    } finally {
      database.close();
    }
    await deleteIndexedDb(databaseName);
  }
  if ((await listIndexedDbDatabases()).length !== 0) {
    throw new Error('live screenshot capture IndexedDB was not cleared');
  }

  if (typeof caches === 'undefined' || typeof caches.keys !== 'function' || typeof caches.open !== 'function' || typeof caches.delete !== 'function') {
    throw new Error('live screenshot capture Cache Storage boundary is unavailable');
  }
  const cacheNames = await caches.keys();
  if (!Array.isArray(cacheNames) || cacheNames.length > maxCacheEntries) privacyOverflow();
  let cacheRequestCount = 0;
  let cacheHeaderCount = 0;
  let cacheBodyBytes = 0;
  for (const cacheName of cacheNames) {
    if (typeof cacheName !== 'string' || cacheName.length > maxSensitiveValueLength) privacyOverflow();
    containsPrivacyMarker(cacheName);
    const cache = await caches.open(cacheName);
    if (!cache || typeof cache.keys !== 'function' || typeof cache.match !== 'function') {
      throw new Error('live screenshot capture Cache Storage boundary is unavailable');
    }
    const requests = await cache.keys();
    if (!Array.isArray(requests) || requests.length > maxCacheRequests) privacyOverflow();
    for (const request of requests) {
      cacheRequestCount += 1;
      if (cacheRequestCount > maxCacheRequests || !request || typeof request.url !== 'string') privacyOverflow();
      containsPrivacyMarker(request.url);
      for (const [name, value] of request.headers.entries()) {
        cacheHeaderCount += 1;
        if (cacheHeaderCount > maxCacheHeaders) privacyOverflow();
        containsPrivacyMarker(name);
        containsPrivacyMarker(value);
      }
      const response = await cache.match(request);
      if (!response) continue;
      for (const [name, value] of response.headers.entries()) {
        cacheHeaderCount += 1;
        if (cacheHeaderCount > maxCacheHeaders) privacyOverflow();
        containsPrivacyMarker(name);
        containsPrivacyMarker(value);
      }
      const body = await response.clone().text();
      cacheBodyBytes += body.length;
      if (cacheBodyBytes > maxCacheBodyBytes) privacyOverflow();
      containsPrivacyMarker(body);
    }
    if (!(await caches.delete(cacheName))) {
      throw new Error('live screenshot capture Cache Storage was not cleared');
    }
  }
  if ((await caches.keys()).length !== 0) {
    throw new Error('live screenshot capture Cache Storage was not cleared');
  }
  preview.querySelectorAll('.model-control select').forEach((select) => {
    const candidate = /** @type {HTMLSelectElement} */ (select);
    candidate.selectedIndex = 0;
    candidate.value = modelPlaceholder;
  });

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
  /** @param {Element} element */
  const serializeResidualSurface = (element) => {
    const projection = /** @type {Element} */ (element.cloneNode(true));
    [projection, ...projection.querySelectorAll('*')].forEach((node) => {
      node.getAttributeNames().forEach((name) => {
        if (name === 'class' || name === 'style' || name.startsWith('data-svelte-')) {
          node.removeAttribute(name);
        }
      });
    });
    return `${projection.textContent ?? ''}\n${projection.outerHTML}`;
  };
  const serializedPage = serializeResidualSurface(document.documentElement);
  /** @param {string} serialized @param {string} value */
  const valueAppears = (serialized, value) => {
    if (value.length <= 1) {
      const escaped = value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
      return new RegExp(`(?:^|[^\\p{L}\\p{N}_])${escaped}(?:$|[^\\p{L}\\p{N}_])`, 'u').test(serialized);
    }
    return serialized.includes(value);
  };
  const residual = [...new Set(oldLiveValues)].filter(
    (value) => !fixedPresentationText.has(value) && valueAppears(serializedPage, value)
  );
  const metadataSurfaces = [
    ...preview.querySelectorAll('.header-model, .group-count, .model-control, .model-control select, .model-control option')
  ];
  const serializedMetadata = metadataSurfaces.map(serializeMetadataSurface).join('\n');
  const metadataResidual = [...new Set(oldMetadataValues)].filter(
    (value) =>
      !fixedPresentationText.has(value) &&
      (metadataSurfaces.some((element) => metadataSurfaceContains(element, value)) ||
        valueAppears(serializedMetadata, value))
  );
  if (residual.length > 0 || metadataResidual.length > 0) {
    throw new Error(
      `live screenshot capture found prohibited live text or data (${residual.length} general, ${metadataResidual.length} metadata lengths ${residual.map((value) => value.length).join(',')}|${metadataResidual.map((value) => value.length).join(',')})`
    );
  }

  const body = document.body;
  if (!(body instanceof HTMLElement)) {
    throw new Error('live screenshot capture document body is unavailable');
  }
  const captureHost = document.createElement('div');
  captureHost.setAttribute('data-capture-root', 'live-chat');
  captureHost.setAttribute('aria-hidden', 'true');
  captureHost.setAttribute('inert', '');
  captureHost.style.position = 'fixed';
  captureHost.style.top = '0';
  captureHost.style.left = '0';
  captureHost.style.width = '1440px';
  captureHost.style.height = '960px';
  captureHost.style.overflow = 'hidden';
  captureHost.style.zIndex = '2147483647';
  captureHost.style.pointerEvents = 'none';
  captureHost.style.contain = 'layout paint size';
  captureHost.style.isolation = 'isolate';
  const backgroundCandidates = [sourceContainer, preview, body]
    .map((element) => getComputedStyle(element).backgroundColor)
    .filter((color) => color && !/^transparent$/iu.test(color) && !/rgba?\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\)/iu.test(color));
  captureHost.style.backgroundColor = backgroundCandidates[0] ?? '#fff';

  const captureClone = /** @type {HTMLElement} */ (sourceContainer.cloneNode(true));
  captureClone.setAttribute('data-capture-clone', 'true');
  captureClone.style.width = '100%';
  captureClone.style.height = '960px';
  captureClone.style.minHeight = '960px';
  captureHost.append(captureClone);
  body.append(captureHost);

  const captureRect = captureHost.getBoundingClientRect();
  if (
    (captureRect.width !== 0 || captureRect.height !== 0) &&
    (captureRect.width !== 1440 || captureRect.height !== 960)
  ) {
    captureHost.remove();
    throw new Error('live screenshot capture clone dimensions are not pinned');
  }
  const cloneMetadataSurfaces = [
    ...captureHost.querySelectorAll('.header-model, .group-count, .model-control, .model-control select, .model-control option')
  ];
  const cloneSerializedMetadata = cloneMetadataSurfaces.map(serializeMetadataSurface).join('\n');
  const cloneMetadataResidual = [...new Set(oldMetadataValues)].filter(
    (value) =>
      !fixedPresentationText.has(value) &&
      (cloneMetadataSurfaces.some((element) => metadataSurfaceContains(element, value)) ||
        valueAppears(cloneSerializedMetadata, value))
  );
  const serializedClone = serializeResidualSurface(captureHost);
  const cloneResidual = [...new Set(oldLiveValues)].filter(
    (value) => !fixedPresentationText.has(value) && valueAppears(serializedClone, value)
  );
  if (
    document.querySelectorAll(captureSelector).length !== 1 ||
    captureHost.querySelector('[data-live-content], .user-message, .assistant-copy, .tool-row') ||
    cloneResidual.length > 0 ||
    cloneMetadataResidual.length > 0 ||
    cloneMetadataSurfaces.some((element) => {
      const candidate = /** @type {Element & { value?: unknown }} */ (element);
      return typeof candidate.value === 'string' && candidate.value.length > 0 && candidate.value !== modelPlaceholder;
    })
  ) {
    captureHost.remove();
    throw new Error('live screenshot capture clone was not sanitized');
  }

  return Object.freeze({
    sanitized: true,
    captureSelector,
    removedValueCount: oldLiveValues.length,
    prohibitedNodeCount: 0,
    privacy: {
      localStorageCleared: true,
      sessionStorageCleared: true,
      indexedDbCleared: true,
      cacheStorageCleared: true,
      serviceWorkerCacheCleared: true,
      localStorageEntries: localStorageEntryCount,
      sessionStorageEntries: sessionStorageEntryCount,
      indexedDbDatabases: indexedDbBefore.length,
      indexedDbStores: indexedDbStoreCount,
      indexedDbRecords: indexedDbRecordCount,
      cacheNames: cacheNames.length,
      cacheRequests: cacheRequestCount,
      cacheHeaders: cacheHeaderCount,
      cacheBodyBytes
    }
  });
}

/**
 * Read the explicit opt-in gate. A missing or malformed input is never
 * interpreted as permission to capture or retain a live screenshot.
 *
 * @param {Record<string, string | undefined>} environment
 * @param {string} [repositoryRoot]
 */
function requireCaptureGate(environment, repositoryRoot = LIVE_SCREENSHOT_REPOSITORY_ROOT) {
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
      cwd: repositoryRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    throw new Error('live screenshot capture could not attest the client checkout');
  }
  if (checkoutSha !== clientSha) {
    throw new Error('live screenshot capture client SHA does not match the checkout');
  }
  let dirtyTrackedFiles;
  try {
    dirtyTrackedFiles = execFileSync('git', ['status', '--porcelain=v1', '--untracked-files=no'], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch {
    throw new Error('live screenshot capture could not attest a clean client checkout');
  }
  if (dirtyTrackedFiles.length > 0) {
    throw new Error('live screenshot capture requires a clean tracked checkout');
  }
  return clientSha;
}

/**
 * Synchronously validate the full capture configuration before Playwright can
 * create an artifact root, start its web server, launch a browser, navigate, or
 * hand credentials to the live host. Default-off calls perform no provenance
 * lookup and return without filesystem mutation beyond module loading.
 *
 * @param {Record<string, string | undefined>} [environment]
 */
export function validateLiveScreenshotCaptureConfiguration(environment = process.env) {
  if (!isLiveScreenshotCaptureEnabled(environment)) return undefined;
  const clientSha = requireCaptureGate(environment);
  const provenance = readPinnedChromiumProvenance();
  return Object.freeze({ clientSha, provenance });
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
 *   proof?: Record<string, unknown>,
 *   uiState: 'empty' | 'ready',
 *   sensitiveMarkers?: string[],
 *   theme?: 'light' | 'dark',
 *   reducedMotion?: 'reduce' | 'no-preference',
 *   provenance?: ChromiumProvenance
 * }} options
 */
async function captureLiveChatScreenshot({
  page,
  clientSha,
  enabled = true,
  proof,
  uiState,
  sensitiveMarkers = [],
  theme = 'light',
  reducedMotion = 'reduce',
  provenance
}) {
  if (!enabled) return undefined;
  assertLiveProofLedgerCaptureReady(proof);
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
  requirePageMethod(page, 'locator');

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

  const pinnedChromium = provenance ?? readPinnedChromiumProvenance();
  const pageContext = page.context();
  const browser = pageContext.browser?.();
  if (!browser || typeof browser.browserType !== 'function' || typeof browser.version !== 'function') {
    throw new Error('live screenshot capture browser provenance is unavailable');
  }
  const browserType = browser.browserType();
  const browserName = browserType?.name?.();
  const browserVersion = browser.version();
  const runtimeExecutablePath = browserType?.executablePath?.();
  if (
    browserName !== 'chromium' ||
    browserVersion !== pinnedChromium.version ||
    runtimeExecutablePath !== pinnedChromium.executablePath ||
    !CHROMIUM_REVISION_PATTERN.test(runtimeExecutablePath ?? '') ||
    runtimeExecutablePath.match(CHROMIUM_REVISION_PATTERN)?.[1] !== pinnedChromium.revision
  ) {
    throw new Error('live screenshot capture Chromium provenance is not pinned');
  }

  if (typeof pageContext.cookies !== 'function' || typeof pageContext.clearCookies !== 'function') {
    throw new Error('live screenshot capture cookie boundary is unavailable');
  }
  const cookiesBefore = await pageContext.cookies();
  if (!Array.isArray(cookiesBefore)) {
    throw new Error('live screenshot capture cookie boundary is unavailable');
  }
  await pageContext.clearCookies();
  const cookiesAfter = await pageContext.cookies();
  if (!Array.isArray(cookiesAfter) || cookiesAfter.length !== 0) {
    throw new Error('live screenshot capture cookie boundary is unavailable');
  }

  await page.emulateMedia({
    colorScheme: theme,
    reducedMotion
  });

  const observed = await page.evaluate(() => ({
    devicePixelRatio: window.devicePixelRatio,
    locale: navigator.language,
    timezoneId: Intl.DateTimeFormat().resolvedOptions().timeZone,
    reducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches
      ? 'reduce'
      : 'no-preference',
    theme: window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
    zoom: window.visualViewport?.scale ?? 0
  }));
  if (
    observed.devicePixelRatio !== LIVE_SCREENSHOT_DEVICE_PIXEL_RATIO ||
    observed.locale !== LIVE_SCREENSHOT_LOCALE ||
    observed.timezoneId !== LIVE_SCREENSHOT_TIMEZONE_ID ||
    observed.reducedMotion !== reducedMotion ||
    observed.theme !== theme ||
    observed.zoom !== LIVE_SCREENSHOT_BROWSER_ZOOM
  ) {
    throw new Error('live screenshot capture browser inputs are not pinned');
  }

  // Complete all live proof assertions before this call. The sanitizer leaves
  // the Svelte-owned tree only as a checked source and creates an inert clone;
  // the screenshot locator targets that clone, never the mutable live page.
  const presentation = await page.evaluate(sanitizeLiveChatCapturePresentation, sensitiveMarkers);
  const privacy = presentation && isRecord(presentation.privacy) ? presentation.privacy : undefined;
  if (
    !presentation ||
    presentation.sanitized !== true ||
    presentation.prohibitedNodeCount !== 0 ||
    presentation.captureSelector !== LIVE_SCREENSHOT_CAPTURE_SELECTOR ||
    !privacy ||
    privacy.localStorageCleared !== true ||
    privacy.sessionStorageCleared !== true ||
    privacy.indexedDbCleared !== true ||
    privacy.cacheStorageCleared !== true ||
    privacy.serviceWorkerCacheCleared !== true
  ) {
    throw new Error('live screenshot capture presentation was not sanitized');
  }

  const captureLocator = page.locator(presentation.captureSelector);
  if (!captureLocator || typeof captureLocator.screenshot !== 'function') {
    throw new Error('live screenshot capture locator is unavailable');
  }
  const bytes = assertImageBytes(
    await captureLocator.screenshot({
      type: 'png',
      animations: 'disabled',
      caret: 'hide'
    })
  );
  const afterCaptureProvenance = provenance ?? readPinnedChromiumProvenance();
  if (
    afterCaptureProvenance.executablePath !== pinnedChromium.executablePath ||
    afterCaptureProvenance.executableSha256 !== pinnedChromium.executableSha256 ||
    afterCaptureProvenance.dev !== pinnedChromium.dev ||
    afterCaptureProvenance.ino !== pinnedChromium.ino
  ) {
    throw new Error('live screenshot executable changed during capture');
  }
  const manifest = createLiveScreenshotManifest({
    browserName,
    browserRevision: pinnedChromium.revision,
    browserVersion,
    browserExecutableSha256: pinnedChromium.executableSha256,
    clientSha,
    devicePixelRatio: observed.devicePixelRatio,
    imageSha256: sha256Hex(bytes),
    locale: observed.locale,
    timezoneId: observed.timezoneId,
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
 * @param {{ page: any, uiState: 'empty' | 'ready', proof: Record<string, unknown>, environment?: Record<string, string | undefined>, provenance?: ChromiumProvenance }} options
 */
export async function captureLiveChatScreenshotIfEnabled({
  page,
  uiState,
  proof,
  environment = process.env,
  provenance
}) {
  if (!isLiveScreenshotCaptureEnabled(environment)) return undefined;
  assertLiveProofLedgerCaptureReady(proof);
  let retentionDestination;
  if (environment[LIVE_SCREENSHOT_RETAIN_ENV] === '1') {
    if (environment[LIVE_SCREENSHOT_REVIEW_ENV] !== LIVE_SCREENSHOT_APPROVED_REVIEW) {
      throw new Error('live screenshot retention requires independent approval');
    }
    const destination = environment[LIVE_SCREENSHOT_DESTINATION_ENV];
    if (!destination) {
      throw new Error('live screenshot retention requires an explicit destination');
    }
    // Validate review and destination identity before any page method can
    // mutate the live page or create a screenshot. Persistence repeats this
    // check after capture to close the preflight-to-publish TOCTOU window.
    retentionDestination = safeDestinationEvidence(destination);
  }
  const clientSha = requireCaptureGate(environment);
  const capture = await captureLiveChatScreenshot({
    page,
    clientSha,
    enabled: true,
    proof,
    uiState,
    sensitiveMarkers: /** @type {string[]} */ (
      [environment.HERMES_TEST_PASSWORD, environment.HERMES_TEST_USERNAME].filter(
        (value) => typeof value === 'string'
      )
    ),
    provenance
  });
  if (!capture) throw new Error('live screenshot capture result is unavailable');
  if (retentionDestination) {
    await persistApprovedLiveScreenshot({
      capture,
      destinationDirectory: retentionDestination.candidate,
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
    let closeFailed = false;
    if (handle) {
      try {
        await handle.close();
      } catch {
        closeFailed = true;
      }
    }
    if (closeFailed) throw new Error('live screenshot retention handle cleanup failed');
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

/** @param {string} path */
function pathExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * @typedef {{ dev: number, ino: number, size: number }} StagingFileIdentity
 * @typedef {{ dev: number, ino: number, parent: StagingParentEvidence, screenshot: StagingFileIdentity, manifest: StagingFileIdentity }} StagingEvidence
 * @typedef {{ dev: number, ino: number, parent: StagingParentEvidence, screenshot?: StagingFileIdentity, manifest?: StagingFileIdentity }} StagingCleanupEvidence
 */

/** @param {unknown} error */
function isNotFoundError(error) {
  return error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT';
}

/**
 * Remove only files this module created, and only while the original staging
 * directory, parent, and each observed file identity remain bound. Partial
 * evidence is accepted after a write failure; an unexpected or unverified
 * entry is preserved and reported instead of being followed.
 *
 * @param {string} directory
 * @param {StagingCleanupEvidence} expected
 */
async function removePrivateStagingDirectory(directory, expected) {
  if (resolve(dirname(directory)) !== resolve(expected.parent.path)) {
    throw new Error('live screenshot staging parent binding changed');
  }
  assertStagingParentEvidence(expected.parent);
  let stats;
  try {
    stats = lstatSync(directory);
  } catch (error) {
    if (isNotFoundError(error)) return;
    throw new Error('live screenshot staging cleanup inspection failed');
  }
  if (
    !stats.isDirectory() ||
    stats.isSymbolicLink() ||
    stats.dev !== expected.dev ||
    stats.ino !== expected.ino
  ) {
    throw new Error('live screenshot staging identity changed during cleanup');
  }

  let entries;
  try {
    entries = (await fsPromises.readdir(directory)).sort();
  } catch {
    throw new Error('live screenshot staging cleanup inspection failed');
  }
  const ownedEntries = ['manifest.json', 'screenshot.png'];
  if (entries.some((entry) => !ownedEntries.includes(entry))) {
    throw new Error('live screenshot staging cleanup found an unexpected entry');
  }

  for (const entry of entries) {
    assertStagingParentEvidence(expected.parent);
    const current = lstatSync(directory);
    if (
      !current.isDirectory() ||
      current.isSymbolicLink() ||
      current.dev !== expected.dev ||
      current.ino !== expected.ino
    ) {
      throw new Error('live screenshot staging identity changed during cleanup');
    }
    const entryPath = join(directory, entry);
    let entryStats;
    try {
      entryStats = lstatSync(entryPath);
    } catch {
      throw new Error('live screenshot staging entry disappeared during cleanup');
    }
    const expectedEntry = expected[entry === 'screenshot.png' ? 'screenshot' : 'manifest'];
    if (
      !expectedEntry ||
      !entryStats.isFile() ||
      entryStats.isSymbolicLink() ||
      entryStats.dev !== expectedEntry.dev ||
      entryStats.ino !== expectedEntry.ino ||
      entryStats.size !== expectedEntry.size
    ) {
      throw new Error('live screenshot staging entry identity changed during cleanup');
    }
    try {
      await fsPromises.unlink(entryPath);
    } catch {
      throw new Error('live screenshot staging entry cleanup failed');
    }
  }

  assertStagingParentEvidence(expected.parent);
  const current = lstatSync(directory);
  if (
    !current.isDirectory() ||
    current.isSymbolicLink() ||
    current.dev !== expected.dev ||
    current.ino !== expected.ino
  ) {
    throw new Error('live screenshot staging identity changed during cleanup');
  }
  try {
    await fsPromises.rmdir(directory);
  } catch {
    throw new Error('live screenshot staging cleanup left a remnant');
  }
}

/**
 * Validate and snapshot the private staging directory identity. The returned
 * device/inode/size evidence is passed to the atomic rename child, which
 * revalidates the source immediately before the no-overwrite rename.
 *
 * @param {string} directory
 * @param {StagingParentEvidence} parent
 * @returns {Promise<StagingEvidence>}
 */
async function verifyPrivateStagingDirectory(directory, parent) {
  if (resolve(dirname(directory)) !== resolve(parent.path)) {
    throw new Error('live screenshot staging parent binding changed');
  }
  assertStagingParentEvidence(parent);
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
  /** @type {Record<string, StagingFileIdentity>} */
  const files = {};
  for (const entry of entries) {
    const entryPath = join(directory, entry);
    const entryStats = lstatSync(entryPath);
    if (!entryStats.isFile() || entryStats.isSymbolicLink() || (entryStats.mode & 0o077) !== 0) {
      throw new Error('live screenshot staging bundle contains an unsafe entry');
    }
    files[entry] = { dev: entryStats.dev, ino: entryStats.ino, size: entryStats.size };
  }
  return {
    dev: stats.dev,
    ino: stats.ino,
    parent,
    screenshot: files['screenshot.png'],
    manifest: files['manifest.json']
  };
}

/** @param {string} directory @param {StagingEvidence} expected */
async function assertStagingEvidence(directory, expected) {
  if (resolve(dirname(directory)) !== resolve(expected.parent.path)) {
    throw new Error('live screenshot staging parent binding changed');
  }
  const observed = await verifyPrivateStagingDirectory(directory, expected.parent);
  if (
    observed.dev !== expected.dev ||
    observed.ino !== expected.ino ||
    observed.parent.dev !== expected.parent.dev ||
    observed.parent.ino !== expected.parent.ino ||
    !observed.screenshot ||
    !observed.manifest ||
    !expected.screenshot ||
    !expected.manifest ||
    observed.screenshot.dev !== expected.screenshot.dev ||
    observed.screenshot.ino !== expected.screenshot.ino ||
    observed.screenshot.size !== expected.screenshot.size ||
    observed.manifest.dev !== expected.manifest.dev ||
    observed.manifest.ino !== expected.manifest.ino ||
    observed.manifest.size !== expected.manifest.size
  ) {
    throw new Error('live screenshot staging identity changed');
  }
  return observed;
}

/**
 * @param {string[]} args
 * @param {number[]} fileDescriptors
 * @returns {Promise<void>}
 */
function runAtomicRename(args, fileDescriptors) {
  // Do not inherit the live runner environment into the Python child. The
  // primitive needs only fixed command lookup, locale stability, and the opt-
  // out for user site packages; credentials, NODE_OPTIONS, PYTHONPATH, proxy
  // settings, test markers, and runner debug variables must not cross this
  // process boundary. Isolation flags also disable user startup/site hooks.
  const childConfiguration = getLiveScreenshotAtomicRenameChildConfiguration();
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(childConfiguration.executable, ['-I', '-S', ...args], {
      env: childConfiguration.environment,
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
 * descriptors. It revalidates the staging parent, directory, and both bundle
 * files by device/inode/size immediately before rename, so a source swap cannot
 * publish attacker-controlled bytes and a replaced destination receives no
 * bytes.
 *
 * @param {{ stagingDirectory: string, stagingEvidence: StagingEvidence, destination: DirectoryEvidence, beforeAtomicPublish?: (directory: string) => Promise<void> }} options
 * @returns {Promise<{ renamed: boolean, closeFailure?: Error }>}
 */
async function publishStagedBundle({ stagingDirectory, stagingEvidence, destination, beforeAtomicPublish }) {
  const stagingParentPath = dirname(stagingDirectory);
  const stagingName = basename(stagingDirectory);
  if (resolve(stagingParentPath) !== resolve(stagingEvidence.parent.path)) {
    throw new Error('live screenshot staging parent binding changed');
  }
  let stagingParent;
  let stagingHandle;
  let destinationHandle;
  let failure;
  let renamed = false;
  try {
    stagingParent = await fsPromises.open(stagingParentPath, 'r');
    stagingHandle = await fsPromises.open(stagingDirectory, 'r');
    destinationHandle = await openVerifiedDestination(destination);

    await assertStagingEvidence(stagingDirectory, stagingEvidence);
    const openParentStats = await stagingParent.stat();
    const openStagingStats = await stagingHandle.stat();
    if (
      !openParentStats.isDirectory() ||
      openParentStats.dev !== stagingEvidence.parent.dev ||
      openParentStats.ino !== stagingEvidence.parent.ino ||
      !openStagingStats.isDirectory() ||
      openStagingStats.dev !== stagingEvidence.dev ||
      openStagingStats.ino !== stagingEvidence.ino
    ) {
      throw new Error('live screenshot staging identity changed');
    }
    // Test-only adversarial hook. The real lane never supplies it; all source
    // and destination identities are revalidated after this hook returns.
    if (beforeAtomicPublish) await beforeAtomicPublish(stagingDirectory);
    await assertStagingEvidence(stagingDirectory, stagingEvidence);
    assertSameDestination(destination);
    await assertDestinationHandle(destinationHandle, destination);
    await runAtomicRename(
      [
        '-c',
        ATOMIC_RENAME_SCRIPT,
        '3',
        '4',
        stagingName,
        `${LIVE_SCREENSHOT_FILE_STEM}.bundle`,
        String(stagingEvidence.dev),
        String(stagingEvidence.ino),
        String(stagingEvidence.parent.dev),
        String(stagingEvidence.parent.ino),
        String(stagingEvidence.screenshot.dev),
        String(stagingEvidence.screenshot.ino),
        String(stagingEvidence.screenshot.size),
        String(stagingEvidence.manifest.dev),
        String(stagingEvidence.manifest.ino),
        String(stagingEvidence.manifest.size)
      ],
      [stagingParent.fd, destinationHandle.fd]
    );
    // Record this before closing descriptors. A close failure must not make the
    // caller treat the already-moved source as unpublished.
    renamed = true;
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 17) {
      failure = new Error('live screenshot retention refuses to overwrite existing bundle');
    } else if (error instanceof Error && (
      error.message.includes('destination changed') ||
      error.message.includes('staging identity') ||
      error.message.includes('staging entry') ||
      error.message.includes('staging parent')
    )) {
      failure = error;
    } else {
      failure = new Error('live screenshot retention bundle publication failed');
    }
  }

  let closeFailure;
  for (const handle of [destinationHandle, stagingHandle, stagingParent].reverse()) {
    if (!handle) continue;
    try {
      await handle.close();
    } catch {
      closeFailure ??= new Error('live screenshot retention handle cleanup failed');
    }
  }
  if (failure) throw failure;
  return { renamed, closeFailure };
}

/**
 * Verify the published bundle before reporting success. This checks the exact
 * two-entry shape, private regular-file identities, manifest bytes, PNG bytes,
 * and image hash after the atomic rename. Any replacement or content drift is
 * reported with a fixed message; the final pathname is never accepted merely
 * because the directory rename returned success.
 *
 * @param {string} bundlePath
 * @param {Buffer} expectedBytes
 * @param {string} expectedManifestText
 */
async function verifyPublishedBundle(bundlePath, expectedBytes, expectedManifestText) {
  let bundleStats;
  try {
    bundleStats = lstatSync(bundlePath);
  } catch {
    throw new Error('live screenshot retention published bundle is unavailable');
  }
  if (!bundleStats.isDirectory() || bundleStats.isSymbolicLink()) {
    throw new Error('live screenshot retention published bundle is unsafe');
  }
  let entries;
  try {
    entries = (await fsPromises.readdir(bundlePath)).sort();
  } catch {
    throw new Error('live screenshot retention published bundle is unavailable');
  }
  if (entries.length !== 2 || entries[0] !== 'manifest.json' || entries[1] !== 'screenshot.png') {
    throw new Error('live screenshot retention published bundle shape changed');
  }
  /** @type {Record<string, { dev: number, ino: number, size: number }>} */
  const identities = {};
  for (const entry of entries) {
    const entryPath = join(bundlePath, entry);
    let stats;
    try {
      stats = lstatSync(entryPath);
    } catch {
      throw new Error('live screenshot retention published bundle entry disappeared');
    }
    if (!stats.isFile() || stats.isSymbolicLink() || (stats.mode & 0o077) !== 0) {
      throw new Error('live screenshot retention published bundle entry is unsafe');
    }
    identities[entry] = { dev: stats.dev, ino: stats.ino, size: stats.size };
  }
  let screenshot;
  let manifest;
  try {
    screenshot = await fsPromises.readFile(join(bundlePath, 'screenshot.png'));
    manifest = await fsPromises.readFile(join(bundlePath, 'manifest.json'), 'utf8');
  } catch {
    throw new Error('live screenshot retention published bundle content is unavailable');
  }
  if (!screenshot.equals(expectedBytes) || sha256Hex(screenshot) !== sha256Hex(expectedBytes)) {
    throw new Error('live screenshot retention published PNG changed');
  }
  if (manifest !== expectedManifestText) {
    throw new Error('live screenshot retention published manifest changed');
  }
  const afterBundleStats = lstatSync(bundlePath);
  if (afterBundleStats.dev !== bundleStats.dev || afterBundleStats.ino !== bundleStats.ino) {
    throw new Error('live screenshot retention published bundle identity changed');
  }
  for (const entry of entries) {
    const after = lstatSync(join(bundlePath, entry));
    const before = identities[entry];
    if (
      after.dev !== before.dev ||
      after.ino !== before.ino ||
      after.size !== before.size
    ) {
      throw new Error('live screenshot retention published bundle entry changed');
    }
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
 *   provenance?: ChromiumProvenance,
 *   beforeAtomicPublish?: (directory: string) => Promise<void>,
 *   beforeStagingCleanup?: (directory: string) => Promise<void>
 * }} options
 */
export async function persistApprovedLiveScreenshot({
  capture,
  destinationDirectory,
  fileStem = LIVE_SCREENSHOT_FILE_STEM,
  review,
  provenance,
  beforeAtomicPublish,
  beforeStagingCleanup
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
  const currentProvenance = provenance ?? readPinnedChromiumProvenance();
  if (
    sourceManifest.browser.revision !== currentProvenance.revision ||
    sourceManifest.browser.version !== currentProvenance.version ||
    sourceManifest.browser.executableSha256 !== currentProvenance.executableSha256
  ) {
    throw new Error('live screenshot executable provenance changed');
  }
  const manifest = createLiveScreenshotManifest({
    browserName: sourceManifest.browser.name,
    browserRevision: sourceManifest.browser.revision,
    browserVersion: sourceManifest.browser.version,
    browserExecutableSha256: sourceManifest.browser.executableSha256,
    clientSha: sourceManifest.clientSha,
    devicePixelRatio: sourceManifest.devicePixelRatio,
    imageSha256: sourceManifest.imageSha256,
    locale: sourceManifest.locale,
    timezoneId: sourceManifest.timezoneId,
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
  /** @type {StagingParentEvidence | undefined} */
  let stagingParentEvidence;
  /** @type {StagingCleanupEvidence | undefined} */
  let stagingIdentity;
  /** @type {StagingEvidence | undefined} */
  let stagingEvidence;
  let published = false;
  let result;
  let operationError;
  try {
    // Stage below a private parent whose device/inode is retained through
    // source revalidation, publication, and cleanup. This avoids trusting a
    // replaceable TMPDIR path while keeping the final rename on one filesystem.
    stagingParentEvidence = await createPrivateStagingParent();
    stagingDirectory = await fsPromises.mkdtemp(
      join(stagingParentEvidence.path, `.${fileStem}-capture-`)
    );
    const createdStagingStats = lstatSync(stagingDirectory);
    if (
      !createdStagingStats.isDirectory() ||
      createdStagingStats.isSymbolicLink() ||
      resolve(dirname(stagingDirectory)) !== resolve(stagingParentEvidence.path)
    ) {
      throw new Error('live screenshot staging directory is not private');
    }
    stagingIdentity = {
      dev: createdStagingStats.dev,
      ino: createdStagingStats.ino,
      parent: stagingParentEvidence
    };
    await fsPromises.chmod(stagingDirectory, 0o700);
    await fsPromises.writeFile(join(stagingDirectory, 'screenshot.png'), bytes, {
      encoding: null,
      flag: 'wx',
      mode: 0o600
    });
    const screenshotStats = lstatSync(join(stagingDirectory, 'screenshot.png'));
    if (!screenshotStats.isFile() || screenshotStats.isSymbolicLink()) {
      throw new Error('live screenshot staging bundle contains an unsafe entry');
    }
    stagingIdentity.screenshot = {
      dev: screenshotStats.dev,
      ino: screenshotStats.ino,
      size: screenshotStats.size
    };
    await fsPromises.writeFile(join(stagingDirectory, 'manifest.json'), manifestText, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600
    });
    const manifestStats = lstatSync(join(stagingDirectory, 'manifest.json'));
    if (!manifestStats.isFile() || manifestStats.isSymbolicLink()) {
      throw new Error('live screenshot staging bundle contains an unsafe entry');
    }
    stagingIdentity.manifest = {
      dev: manifestStats.dev,
      ino: manifestStats.ino,
      size: manifestStats.size
    };
    stagingEvidence = await verifyPrivateStagingDirectory(stagingDirectory, stagingParentEvidence);
    stagingIdentity = stagingEvidence;
    const destinationStats = lstatSync(evidence.candidate);
    if (stagingEvidence.dev !== destinationStats.dev) {
      throw new Error('live screenshot staging filesystem is not atomic');
    }

    assertSameDestination(evidence);
    const publication = await publishStagedBundle({
      stagingDirectory,
      stagingEvidence,
      destination: evidence,
      beforeAtomicPublish
    });
    // The atomic rename has already moved the source when `renamed` is true;
    // close failures must not send the outer cleanup back to the old pathname.
    published = publication.renamed;
    if (!published) throw new Error('live screenshot retention bundle publication failed');
    assertSameDestination(evidence);
    await verifyPublishedBundle(bundlePath, bytes, manifestText);
    if (publication.closeFailure) throw publication.closeFailure;
    result = {
      bundlePath,
      imagePath: join(bundlePath, 'screenshot.png'),
      manifestPath: join(bundlePath, 'manifest.json'),
      manifest
    };
  } catch (error) {
    operationError = error instanceof Error
      ? error
      : new Error('live screenshot retention publication failed');
  }

  /** @type {Error[]} */
  const cleanupFailures = [];
  if (stagingDirectory && stagingIdentity && !published) {
    try {
      // Test-only race hook runs before identity-anchored cleanup. If it
      // replaces the pathname, the helper observes the inode mismatch and
      // leaves the replacement untouched while reporting the failure.
      await beforeStagingCleanup?.(stagingDirectory);
    } catch {
      cleanupFailures.push(new Error('live screenshot staging cleanup hook failed'));
    }
    try {
      await removePrivateStagingDirectory(stagingDirectory, stagingIdentity);
    } catch {
      cleanupFailures.push(new Error('live screenshot staging cleanup failed'));
    }
  }
  if (stagingParentEvidence) {
    try {
      await removePrivateStagingParent(stagingParentEvidence.path, stagingParentEvidence);
    } catch {
      cleanupFailures.push(new Error('live screenshot staging parent cleanup failed'));
    }
  }

  if (operationError && cleanupFailures.length > 0) {
    throw new Error('live screenshot retention publication and cleanup failed');
  }
  if (operationError) throw operationError;
  if (cleanupFailures.length > 0) {
    throw new Error('live screenshot retention cleanup failed');
  }
  if (!result) throw new Error('live screenshot retention result is unavailable');
  return result;
}
