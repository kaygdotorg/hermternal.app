import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const appCssPath = fileURLToPath(new URL('../../src/app.css', import.meta.url));
const manifestPath = fileURLToPath(
  new URL('../../../../contracts/design-tokens/web/artboards.json', import.meta.url)
);
const [css, manifestText] = await Promise.all([
  readFile(appCssPath, 'utf8'),
  readFile(manifestPath, 'utf8')
]);
const manifest = JSON.parse(manifestText);
const presentationTokenSetIds = new Set(['runtime', 'runtime-gate', 'auth']);
const runtimeTokenNames = new Set(
  manifest.token_sets
    .filter((tokenSet) => presentationTokenSetIds.has(tokenSet.id))
    .flatMap((tokenSet) => tokenSet.tokens)
);
const canonicalValues = new Map(
  manifest.tokens.map((token) => [token.name, String(token.value).trim()])
);
const declarations = new Map();
for (const match of css.matchAll(/^\s*(--[A-Za-z0-9_-]+)\s*:\s*([^;]+);/gm)) {
  if (!declarations.has(match[1])) {
    declarations.set(match[1], match[2].trim());
  }
}

if (runtimeTokenNames.size === 0) {
  throw new Error('The canonical Paper manifest has no shipped presentation token sets.');
}

for (const tokenName of runtimeTokenNames) {
  const actualValue = declarations.get(tokenName);
  const expectedValue = canonicalValues.get(tokenName);
  if (actualValue === undefined || expectedValue === undefined) {
    throw new Error(`Missing canonical presentation token declaration: ${tokenName}`);
  }
  if (actualValue !== expectedValue) {
    throw new Error(
      `Canonical token drift for ${tokenName}: expected ${expectedValue}, got ${actualValue}`
    );
  }
}

for (const tokenName of declarations.keys()) {
  if (!runtimeTokenNames.has(tokenName)) {
    throw new Error(`Invented or stale CSS token is not in a shipped presentation Paper set: ${tokenName}`);
  }
}

console.log(
  `CSS token evidence: ${runtimeTokenNames.size} shipped presentation Paper tokens match ${manifest.paper.token_content_hash}`
);
