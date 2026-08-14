export const TERMINAL_ONLY_MODULE_IDENTITIES = Object.freeze([
  'node_modules/@wterm/dom/dist/index.js',
  'node_modules/@wterm/ghostty/dist/index.js',
  'node_modules/@wterm/ghostty/wasm/ghostty-vt.wasm?url'
]);

function isPathSegment(segment, { allowQuery = false } = {}) {
  if (segment.length === 0 || segment === '.' || segment === '..') return false;
  if (/[\\%#:]/.test(segment)) return false;
  return allowQuery || !segment.includes('?');
}

function canonicalizeNodeModulesPath(manifestKey) {
  if (
    typeof manifestKey !== 'string' ||
    manifestKey.length === 0 ||
    manifestKey.startsWith('/') ||
    /^[A-Za-z]:[\\/]/.test(manifestKey) ||
    manifestKey.includes('\\') ||
    /%(?:2f|5c)/i.test(manifestKey)
  ) {
    return null;
  }

  const segments = manifestKey.split('/');
  if (segments.some((segment) => segment.length === 0)) return null;

  const nodeModulesIndexes = segments.reduce((indexes, segment, index) => {
    if (segment === 'node_modules') indexes.push(index);
    return indexes;
  }, []);
  if (nodeModulesIndexes.length !== 1) return null;

  const [nodeModulesIndex] = nodeModulesIndexes;
  const prefix = segments.slice(0, nodeModulesIndex);
  let externalRootStarted = false;
  for (const segment of prefix) {
    if (segment === '..') {
      // Leading parent segments identify an external/workspace root. A parent
      // segment after a literal root would make the package identity depend on
      // filesystem normalization, so reject it instead of resolving it.
      if (externalRootStarted) return null;
      continue;
    }
    if (!isPathSegment(segment)) return null;
    if (segment === 'node_modules') return null;
    externalRootStarted = true;
  }

  const suffix = segments.slice(nodeModulesIndex + 1);
  if (
    suffix.length === 0 ||
    suffix.some((segment, index) =>
      !isPathSegment(segment, { allowQuery: index === suffix.length - 1 })
    )
  ) {
    return null;
  }

  return `node_modules/${suffix.join('/')}`;
}

export function canonicalizeTerminalModuleKey(manifestKey) {
  const canonicalKey = canonicalizeNodeModulesPath(manifestKey);
  return canonicalKey && TERMINAL_ONLY_MODULE_IDENTITIES.includes(canonicalKey) ? canonicalKey : null;
}

function looksLikeTerminalModuleKey(manifestKey) {
  if (typeof manifestKey !== 'string') return false;
  const slashSeparatedKey = manifestKey
    .replaceAll('\\', '/')
    .replace(/%2f/gi, '/')
    .replace(/%5c/gi, '/');
  return TERMINAL_ONLY_MODULE_IDENTITIES.some((identity) => {
    const packagePath = identity.slice('node_modules/'.length);
    return (
      slashSeparatedKey === identity ||
      slashSeparatedKey.startsWith(identity) ||
      slashSeparatedKey.includes(`/${identity}`) ||
      slashSeparatedKey === packagePath ||
      slashSeparatedKey.startsWith(packagePath) ||
      slashSeparatedKey.includes(`/${packagePath}`)
    );
  });
}

export function indexTerminalOnlyManifestEntries(manifestEntries) {
  const indexedEntries = new Map();
  for (const [manifestKey, entry] of manifestEntries) {
    const canonicalKey = canonicalizeTerminalModuleKey(manifestKey);
    if (!canonicalKey) {
      if (looksLikeTerminalModuleKey(manifestKey)) {
        throw new Error(`Client manifest contains an invalid terminal dependency identity: ${manifestKey}`);
      }
      continue;
    }

    const previous = indexedEntries.get(canonicalKey);
    if (previous) {
      throw new Error(
        `Client manifest contains duplicate terminal dependency identity: ${canonicalKey} (${previous.manifestKey}, ${manifestKey})`
      );
    }
    indexedEntries.set(canonicalKey, { manifestKey, entry });
  }
  return indexedEntries;
}

export function assertTerminalOnlyModulesRemainDynamic(manifestEntries) {
  const indexedEntries = indexTerminalOnlyManifestEntries(manifestEntries);
  for (const identity of TERMINAL_ONLY_MODULE_IDENTITIES) {
    if (!indexedEntries.get(identity)?.entry?.isDynamicEntry) {
      throw new Error(`Terminal-only dependency must remain dynamic: ${identity}`);
    }
  }
  return indexedEntries;
}
