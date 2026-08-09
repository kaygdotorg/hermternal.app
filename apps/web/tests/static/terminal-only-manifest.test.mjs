import assert from 'node:assert/strict';
import test from 'node:test';

import {
  TERMINAL_ONLY_MODULE_IDENTITIES,
  assertTerminalOnlyModulesRemainDynamic,
  canonicalizeTerminalModuleKey
} from './terminal-only-manifest.mjs';

const externalRoot = '../../../hermternal-terminal-deps';

function terminalManifest() {
  return new Map(
    TERMINAL_ONLY_MODULE_IDENTITIES.map((identity) => [
      `${externalRoot}/${identity}`,
      { isDynamicEntry: true }
    ])
  );
}

function assertRejectsInvalidTerminalIdentity(manifestKey) {
  const manifestEntries = terminalManifest();
  manifestEntries.set(manifestKey, { isDynamicEntry: false });

  assert.throws(
    () => assertTerminalOnlyModulesRemainDynamic(manifestEntries),
    (error) =>
      error instanceof Error &&
      error.message === `Client manifest contains an invalid terminal dependency identity: ${manifestKey}`
  );
}

test('canonicalizes workspace and external relative node_modules roots', () => {
  assert.equal(
    canonicalizeTerminalModuleKey('node_modules/@wterm/dom/dist/index.js'),
    'node_modules/@wterm/dom/dist/index.js'
  );
  assert.equal(
    canonicalizeTerminalModuleKey(
      '../../../hermternal-terminal-deps/node_modules/@wterm/dom/dist/index.js'
    ),
    'node_modules/@wterm/dom/dist/index.js'
  );
  assert.equal(
    canonicalizeTerminalModuleKey('../../workspace/node_modules/@wterm/ghostty/dist/index.js'),
    'node_modules/@wterm/ghostty/dist/index.js'
  );
});

test('rejects lookalikes, ambiguous traversal, encoded separators, and non-node_modules paths', () => {
  for (const manifestKey of [
    'node_modules/@wterm/dom/dist/index.js.map',
    `${externalRoot}/node_modules/@wterm/dom/dist/index.js/extra`,
    `${externalRoot}/node_modules/@wterm/dom/dist/../index.js`,
    `${externalRoot}/workspace/../node_modules/@wterm/dom/dist/index.js`,
    `${externalRoot}/node_modules%2f@wterm%2fdom%2fdist%2findex.js`,
    'src/@wterm/dom/dist/index.js',
    '/workspace/node_modules/@wterm/dom/dist/index.js'
  ]) {
    assert.equal(canonicalizeTerminalModuleKey(manifestKey), null, manifestKey);
  }
});

test('accepts every terminal-only dependency from an external relative root', () => {
  const indexedEntries = assertTerminalOnlyModulesRemainDynamic(terminalManifest());
  for (const identity of TERMINAL_ONLY_MODULE_IDENTITIES) {
    assert.equal(indexedEntries.get(identity)?.manifestKey, `${externalRoot}/${identity}`);
  }
});

test('rejects a terminal-only dependency that is static or shared', () => {
  const manifestEntries = terminalManifest();
  const domKey = `${externalRoot}/node_modules/@wterm/dom/dist/index.js`;
  manifestEntries.set(domKey, { isDynamicEntry: false });

  assert.throws(
    () => assertTerminalOnlyModulesRemainDynamic(manifestEntries),
    /Terminal-only dependency must remain dynamic: node_modules\/@wterm\/dom\/dist\/index\.js/
  );
});

test('rejects duplicate canonical identities from workspace and external roots', () => {
  const manifestEntries = terminalManifest();
  manifestEntries.set('node_modules/@wterm/dom/dist/index.js', { isDynamicEntry: true });

  assert.throws(
    () => assertTerminalOnlyModulesRemainDynamic(manifestEntries),
    /duplicate terminal dependency identity: node_modules\/@wterm\/dom\/dist\/index\.js/
  );
});

test('rejects a malformed terminal lookalike even beside a valid dynamic entry', () => {
  const manifestEntries = terminalManifest();
  manifestEntries.set(
    `${externalRoot}/node_modules/@wterm/dom/dist/index.js.map`,
    { isDynamicEntry: true }
  );

  assert.throws(
    () => assertTerminalOnlyModulesRemainDynamic(manifestEntries),
    /invalid terminal dependency identity/
  );
});

test('rejects a static terminal traversal alias with an intermediate segment', () => {
  assertRejectsInvalidTerminalIdentity(
    `${externalRoot}/node_modules/@wterm/dom/dist/x/../index.js`
  );
});

test('rejects a static terminal traversal alias that backs out of dist', () => {
  assertRejectsInvalidTerminalIdentity(
    `${externalRoot}/node_modules/@wterm/dom/dist/../index.js`
  );
});

test('rejects an encoded static terminal traversal alias', () => {
  assertRejectsInvalidTerminalIdentity(
    `${externalRoot}/node_modules/@wterm/dom/dist/%2e%2e/index.js`
  );
});

test('rejects duplicate canonical identities even when both entries are static', () => {
  const manifestEntries = terminalManifest();
  const externalDomKey = `${externalRoot}/node_modules/@wterm/dom/dist/index.js`;
  manifestEntries.set(externalDomKey, { isDynamicEntry: false });
  manifestEntries.set('node_modules/@wterm/dom/dist/index.js', { isDynamicEntry: false });

  assert.throws(
    () => assertTerminalOnlyModulesRemainDynamic(manifestEntries),
    (error) =>
      error instanceof Error &&
      error.message ===
        'Client manifest contains duplicate terminal dependency identity: ' +
        'node_modules/@wterm/dom/dist/index.js ' +
        `(${externalDomKey}, node_modules/@wterm/dom/dist/index.js)`
  );
});

test('does not substitute a non-node_modules path for a terminal dependency', () => {
  const manifestEntries = terminalManifest();
  manifestEntries.delete(`${externalRoot}/node_modules/@wterm/dom/dist/index.js`);
  manifestEntries.set('src/@wterm/dom/dist/index.js', { isDynamicEntry: true });

  assert.throws(
    () => assertTerminalOnlyModulesRemainDynamic(manifestEntries),
    /invalid terminal dependency identity/
  );
});
