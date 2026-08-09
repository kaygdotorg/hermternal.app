import { access, readFile, readdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { cwd } from 'node:process';
import { assertTerminalLazyBoundary } from './terminal-lazy-boundary.mjs';

const outputDirectory = join(cwd(), 'build');

async function exists(path) {
  await access(path);
}

await exists(join(outputDirectory, 'index.html'));
await exists(join(outputDirectory, '200.html'));
await exists(join(outputDirectory, 'manifest.webmanifest'));
await exists(join(outputDirectory, 'service-worker.js'));

const outputEntries = await readdir(outputDirectory);
if (outputEntries.includes('server')) {
  throw new Error('Static adapter output must not contain a server directory.');
}

const index = await readFile(join(outputDirectory, 'index.html'), 'utf8');
if (!index.includes('manifest.webmanifest')) {
  throw new Error('The static entry point must reference the PWA manifest.');
}

const clientManifestPath = join(cwd(), '.svelte-kit', 'output', 'client', '.vite', 'manifest.json');
await exists(clientManifestPath);
const clientManifest = JSON.parse(await readFile(clientManifestPath, 'utf8'));
const manifestEntries = new Map(Object.entries(clientManifest));
const rendererKey = 'src/lib/terminal/renderer.ts';
const rendererEntry = manifestEntries.get(rendererKey);
if (!rendererEntry?.isDynamicEntry) {
  throw new Error('Terminal renderer must remain a dynamic entry.');
}

const liveRouteSource = 'src/routes/+page.svelte';
const liveRoutePath = resolve(cwd(), liveRouteSource);
const liveRouteEntries = [];
for (const [entryKey, entry] of manifestEntries) {
  if (entry?.src === liveRouteSource) {
    liveRouteEntries.push([entryKey, entry]);
    continue;
  }
  if (!entry?.src?.startsWith('.svelte-kit/generated/client-optimized/nodes/')) continue;

  const generatedEntryPath = resolve(cwd(), entry.src);
  const generatedEntrySource = await readFile(generatedEntryPath, 'utf8');
  const componentReexport = generatedEntrySource.match(
    /export\s*\{\s*default\s+as\s+component\s*\}\s*from\s*["']([^"']+)["']/
  );
  if (
    componentReexport &&
    resolve(dirname(generatedEntryPath), componentReexport[1]) === liveRoutePath
  ) {
    liveRouteEntries.push([entryKey, entry]);
  }
}

// SvelteKit identifies routes in Vite through generated nodes whose numeric keys can
// shift whenever routes change. Follow the generated component re-export so this
// evidence stays tied to the exact source route, not chunk order or display names.
if (liveRouteEntries.length !== 1) {
  throw new Error(
    `Expected exactly one client manifest entry for ${liveRouteSource}; found ${liveRouteEntries.length}.`
  );
}
const [liveRouteEntryKey] = liveRouteEntries[0];

function collectStaticImports(entryKey) {
  const visited = new Set();
  const pending = [entryKey];
  while (pending.length > 0) {
    const importedKey = pending.pop();
    if (visited.has(importedKey)) continue;

    const entry = manifestEntries.get(importedKey);
    if (!entry) {
      throw new Error(`Client manifest contains an unresolved static import: ${importedKey}`);
    }
    visited.add(importedKey);
    pending.push(...(entry.imports ?? []));
  }
  return visited;
}

const liveRouteStaticClosure = collectStaticImports(liveRouteEntryKey);
const rendererEdgesFromLiveRoute = [...liveRouteStaticClosure].filter((entryKey) =>
  (manifestEntries.get(entryKey)?.dynamicImports ?? []).includes(rendererKey)
);
if (rendererEdgesFromLiveRoute.length === 0) {
  throw new Error(`The ${liveRouteSource} import graph must dynamically import the terminal renderer.`);
}

// Vite can record extracted CSS and WASM only on an importer. Validate both
// module identity and every emitted css/assets reference from the route closure.
assertTerminalLazyBoundary(liveRouteStaticClosure, manifestEntries);

for (const key of [
  'node_modules/@wterm/dom/dist/index.js',
  'node_modules/@wterm/ghostty/dist/index.js',
  'node_modules/@wterm/ghostty/wasm/ghostty-vt.wasm?url'
]) {
  if (!manifestEntries.get(key)?.isDynamicEntry) {
    throw new Error(`Terminal-only dependency must remain dynamic: ${key}`);
  }
}

console.log('static build evidence: index, 200.html, manifest, service worker, and lazy terminal chunk boundaries verified; no server output');
