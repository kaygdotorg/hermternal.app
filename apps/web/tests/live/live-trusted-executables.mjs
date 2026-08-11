import {
  accessSync,
  constants as fsConstants,
  lstatSync,
  realpathSync
} from 'node:fs';
import { dirname, join, parse, relative, resolve, sep } from 'node:path';

/**
 * These are reviewed system entry points, not ambient command lookup. The
 * returned executable is always the canonical target after the fixed lexical
 * candidate has passed ownership, mode, and parent-chain checks.
 */
const TRUSTED_GIT_EXECUTABLES = Object.freeze([
  '/usr/bin/git',
  '/opt/homebrew/bin/git',
  '/usr/local/bin/git',
  '/opt/local/bin/git'
]);

const TRUSTED_GIT_ENVIRONMENT = Object.freeze({
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  LC_ALL: 'C',
  LANG: 'C',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_OPTIONAL_LOCKS: '0'
});

function currentUid() {
  return typeof process.getuid === 'function' ? process.getuid() : undefined;
}

/** @param {string} path */
function assertTrustedDirectoryChain(path) {
  if (typeof path !== 'string' || !path.startsWith('/')) {
    throw new Error('trusted executable path is not absolute');
  }
  const root = parse(path).root;
  let current = root;
  for (const component of relative(root, path).split(sep).filter(Boolean)) {
    current = join(current, component);
    const stats = lstatSync(current);
    if (
      !stats.isDirectory() ||
      stats.isSymbolicLink() ||
      (stats.mode & 0o022) !== 0 ||
      (currentUid() !== undefined && stats.uid !== 0 && stats.uid !== currentUid())
    ) {
      throw new Error('trusted executable parent is unsafe');
    }
  }
}

/** @param {string} candidate */
function validateTrustedExecutable(candidate) {
  if (typeof candidate !== 'string' || !candidate.startsWith('/') || resolve(candidate) !== candidate) {
    throw new Error('trusted executable path is not absolute');
  }
  const lexicalStats = lstatSync(candidate);
  assertTrustedDirectoryChain(dirname(candidate));
  const canonicalPath = realpathSync(candidate);
  assertTrustedDirectoryChain(dirname(canonicalPath));
  const stats = lstatSync(canonicalPath);
  if (
    !stats.isFile() ||
    stats.isSymbolicLink() ||
    (stats.mode & 0o111) === 0 ||
    (stats.mode & 0o022) !== 0 ||
    (currentUid() !== undefined && stats.uid !== 0 && stats.uid !== currentUid())
  ) {
    throw new Error('trusted executable is not a private regular file');
  }
  if (!lexicalStats.isFile() && !lexicalStats.isSymbolicLink()) {
    throw new Error('trusted executable entry is not a file');
  }
  accessSync(canonicalPath, fsConstants.X_OK);
  if (realpathSync(canonicalPath) !== canonicalPath) {
    throw new Error('trusted executable target is not canonical');
  }
  return canonicalPath;
}

/** @returns {string} */
function trustedGitExecutable() {
  for (const candidate of TRUSTED_GIT_EXECUTABLES) {
    try {
      return validateTrustedExecutable(candidate);
    } catch {
      // Fixed candidates only. Never consult PATH after a candidate fails.
    }
  }
  throw new Error('trusted git executable is unavailable');
}

/**
 * Return the absolute git executable and an explicit environment. The
 * environment intentionally omits HERMES_TEST_PASSWORD, NODE_OPTIONS, proxy
 * variables, HOME, and arbitrary inherited values before provenance commands
 * cross the child-process boundary.
 */
export function getLiveScreenshotGitChildConfiguration() {
  return Object.freeze({
    executable: trustedGitExecutable(),
    environment: TRUSTED_GIT_ENVIRONMENT
  });
}
