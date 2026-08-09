import assert from 'node:assert/strict';
import test from 'node:test';

import { assertTerminalLazyBoundary } from './terminal-lazy-boundary.mjs';

const importerKey = 'src/routes/+page.svelte';

const rendererKey = 'src/lib/terminal/renderer.ts';
const terminalDependencyKey = 'node_modules/@wterm/ghostty/dist/index.js';
const terminalTransitiveKey = 'node_modules/@wterm/ghostty/dist/internal.js';

function manifest({ importer = {}, terminalDependency = {}, terminalTransitive = {} } = {}) {
  return new Map([
    [importerKey, { file: '_app/immutable/nodes/2.safe.js', ...importer }],
    [rendererKey, { file: '_app/immutable/chunks/renderer.safe.js', dynamicImports: [terminalDependencyKey] }],
    [
      terminalDependencyKey,
      { file: '_app/immutable/chunks/terminal.safe.js', imports: [terminalTransitiveKey], ...terminalDependency }
    ],
    [terminalTransitiveKey, { file: '_app/immutable/chunks/worker.safe.js', ...terminalTransitive }]
  ]);
}

test('rejects neutral-name CSS owned by the renderer dependency graph', () => {
  const manifestEntries = manifest({
    importer: { css: ['_app/immutable/assets/vendor.opaque.css'] },
    terminalDependency: { css: ['_app/immutable/assets/vendor.opaque.css'] }
  });

  assert.throws(
    () => assertTerminalLazyBoundary(new Set([importerKey]), manifestEntries),
    /Terminal renderer output entered the initial route closure: .*vendor\.opaque\.css/
  );
});

test('rejects neutral-name WASM owned by the renderer dependency graph', () => {
  const manifestEntries = manifest({
    importer: { assets: ['_app/immutable/assets/asset.opaque.wasm'] },
    terminalDependency: { assets: ['_app/immutable/assets/asset.opaque.wasm'] }
  });

  assert.throws(
    () => assertTerminalLazyBoundary(new Set([importerKey]), manifestEntries),
    /Terminal renderer output entered the initial route closure: .*asset\.opaque\.wasm/
  );
});

test('rejects a neutral-name renderer root JavaScript entry in the static route closure', () => {
  const manifestEntries = manifest();

  assert.throws(
    () => assertTerminalLazyBoundary(new Set([importerKey, rendererKey]), manifestEntries),
    new RegExp(`Terminal renderer dependency entered the initial route closure: ${rendererKey}`)
  );
});

test('rejects a neutral-name transitive renderer JavaScript entry in the static route closure', () => {
  const manifestEntries = manifest();

  assert.throws(
    () => assertTerminalLazyBoundary(new Set([importerKey, terminalTransitiveKey]), manifestEntries),
    new RegExp(`Terminal renderer dependency entered the initial route closure: ${terminalTransitiveKey}`)
  );
});

test('accepts benign route CSS and assets outside renderer provenance', () => {
  const manifestEntries = manifest({
    importer: {
      css: ['_app/immutable/assets/app.safe.css'],
      assets: ['_app/immutable/assets/icon.safe.svg']
    }
  });

  const outputs = assertTerminalLazyBoundary(new Set([importerKey]), manifestEntries);

  assert.deepEqual(
    outputs,
    new Set([
      '_app/immutable/nodes/2.safe.js',
      '_app/immutable/assets/app.safe.css',
      '_app/immutable/assets/icon.safe.svg'
    ])
  );
});
