import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const PARENT_COMMIT = 'a98b3ad901292ff3434f19e8a17f9e9b1eab4d65';
const LEDGER_PATH = 'apps/web/tests/live/live-proof-ledger.mjs';
const probeDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(probeDirectory, '../../../..');
const childLedgerPath = join(repositoryRoot, LEDGER_PATH);
const HMAC_TAG_PATTERN = /^h1:[0-9a-f]{64}$/u;

/**
 * Load the exact parent module from the local Git object database. A data URL
 * keeps the parent source out of the worktree and makes this probe independent
 * of package managers, browser runners, and live Hermes services.
 */
function loadExactParentLedger() {
  const source = execFileSync(
    'git',
    ['show', `${PARENT_COMMIT}:${LEDGER_PATH}`],
    { cwd: repositoryRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
  );
  return import(`data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`);
}

function loadChildLedger() {
  // Read the file before importing so the probe fails clearly if the child
  // source is moved outside the focused live-proof surface.
  readFileSync(childLedgerPath, 'utf8');
  return import(pathToFileURL(childLedgerPath).href);
}

function expectAccepted(label, operation) {
  try {
    return operation();
  } catch (error) {
    throw new Error(`${label} was rejected: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function expectRejected(label, operation) {
  assert.throws(operation, undefined, `${label} was accepted`);
}

function malformedHistoryRows() {
  const descriptor = {
    id: 1,
    role: 'assistant',
    content: 'answer',
    toolCalls: { present: true, value: null }
  };
  Object.defineProperty(descriptor.toolCalls, 'present', {
    configurable: true,
    enumerable: true,
    get: () => true
  });

  return [
    {
      name: 'accessor optional descriptor',
      row: descriptor
    },
    {
      name: 'optional wrapper extra',
      row: {
        id: 1,
        role: 'assistant',
        content: 'answer',
        toolCalls: { present: false, value: null }
      }
    },
    {
      name: 'malformed canonical fallback',
      row: {
        id: 1,
        role: 'assistant',
        content: 'answer',
        toolCalls: { present: 'yes' },
        tool_calls: null
      }
    },
    {
      name: 'fractional timestamp',
      row: {
        id: 1,
        role: 'assistant',
        content: 'answer',
        timestamp: 1.5
      }
    }
  ];
}

const [parent, child] = await Promise.all([loadExactParentLedger(), loadChildLedger()]);

// The parent had an implicit Node crypto boundary. The child deliberately
// removes it: production tags must arrive from the page-local Web Crypto key.
const parentLedger = expectAccepted('parent default Node HMAC ledger', () => parent.createLiveProofLedger());
const parentIdentityTag = parentLedger.identityTag('parent-session');
assert.match(parentIdentityTag, HMAC_TAG_PATTERN);
const parentProjectionTag = parentLedger.messageProjectionTag([
  { id: 1, role: 'assistant', content: 'answer' }
]);
assert.match(parentProjectionTag, HMAC_TAG_PATTERN);
expectRejected('child omitted page signer', () => child.createLiveProofLedger());

const childTestLedger = child.createLiveProofLedger(256, {
  signer: child.createLiveProofTestSigner(),
  allowTestSigner: true
});

for (const { name, row } of malformedHistoryRows()) {
  expectAccepted(`parent ${name}`, () => parentLedger.messageProjectionTag([row]));
  expectRejected(`child ${name}`, () => childTestLedger.messageProjectionTag([row]));
}

console.log(
  `live-proof-parent-compat: ${PARENT_COMMIT.slice(0, 12)} parent Node-HMAC/default and lenient projection behavior contrasted with strict child rejection`
);
