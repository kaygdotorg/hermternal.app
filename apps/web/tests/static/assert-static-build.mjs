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

console.log('static build evidence: index, 200.html, manifest, and service worker present; no server output');
