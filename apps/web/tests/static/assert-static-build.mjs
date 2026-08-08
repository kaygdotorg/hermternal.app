import { access, readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { cwd } from 'node:process';

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
const rendererEntry = manifestEntries.get('src/lib/terminal/renderer.ts');
if (!rendererEntry?.isDynamicEntry) {
  throw new Error('Terminal renderer must remain a dynamic entry.');
}

const workspaceEntry = [...manifestEntries.entries()].find(([, entry]) => entry?.name === 'WorkspacePreview');
if (!workspaceEntry) {
  throw new Error('WorkspacePreview must be present in the client manifest.');
}

function collectStaticImports(entryKey, visited = new Set()) {
  if (visited.has(entryKey)) return visited;
  visited.add(entryKey);
  const entry = manifestEntries.get(entryKey);
  for (const importedKey of entry?.imports ?? []) collectStaticImports(importedKey, visited);
  return visited;
}

const workspaceStaticClosure = collectStaticImports(workspaceEntry[0]);
if (workspaceStaticClosure.has('src/lib/terminal/renderer.ts')) {
  throw new Error('WorkspacePreview statically imports the terminal renderer.');
}
if (!(workspaceEntry[1].dynamicImports ?? []).includes('src/lib/terminal/renderer.ts')) {
  throw new Error('WorkspacePreview must dynamically import the terminal renderer.');
}

for (const key of [
  'node_modules/@wterm/dom/dist/index.js',
  'node_modules/@wterm/ghostty/dist/index.js',
  'node_modules/@wterm/ghostty/wasm/ghostty-vt.wasm?url',
  'node_modules/@wterm/dom/src/terminal.css',
  'src/lib/terminal/terminal.css'
]) {
  if (workspaceStaticClosure.has(key)) {
    throw new Error(`Terminal-only asset entered the initial WorkspacePreview closure: ${key}`);
  }
}

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
