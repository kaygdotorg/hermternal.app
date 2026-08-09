import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const PARENT_COMMIT = 'a7d43f636424dcd02bf65743966db30e5aeb30f0';
const BRIDGE_PARENT_COMMIT = '4c1cd74f6d703a99a29ef85a08142df45234e9f5';
const LEDGER_PATH = 'apps/web/tests/live/live-proof-ledger.mjs';
const BRIDGE_PATH = 'apps/web/tests/live/live-proof-page-bridge.mjs';
const probeDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(probeDirectory, '../../../..');
const childLedgerPath = join(repositoryRoot, LEDGER_PATH);
const childBridgePath = join(repositoryRoot, BRIDGE_PATH);
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

/**
 * Run an isolated browser-realm bridge probe in a child Node process. The exact
 * 4c1 bridge is loaded from the local Git object database; the child bridge is
 * loaded from this worktree. A fresh process is required because installation
 * deliberately replaces page globals and creates a non-configurable bridge.
 *
 * @param {'parent'|'child'|'registration-child'} mode
 */
function runBridgeProbe(mode) {
  const script = `
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const mode = process.argv[2];
const repositoryRoot = ${JSON.stringify(repositoryRoot)};
const bridgePath = ${JSON.stringify(BRIDGE_PATH)};
const childBridgePath = ${JSON.stringify(childBridgePath)};
const parentCommit = ${JSON.stringify(BRIDGE_PARENT_COMMIT)};
const source = mode === 'parent'
  ? execFileSync('git', ['show', parentCommit + ':' + bridgePath], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe']
    })
  : readFileSync(childBridgePath, 'utf8');
const bridge = await import(
  mode === 'parent'
    ? 'data:text/javascript;base64,' + Buffer.from(source, 'utf8').toString('base64')
    : pathToFileURL(childBridgePath).href
);
if (globalThis.crypto === undefined) {
  Object.defineProperty(globalThis, 'crypto', {
    configurable: true,
    enumerable: false,
    writable: true,
    value: webcrypto
  });
}
globalThis.location = { href: 'https://app.example.test/' };
globalThis.fetch = async () => {
  throw new Error('not used');
};
class FakeWebSocket {
  static constructed = 0;
  static closed = 0;
  constructor() {
    FakeWebSocket.constructed += 1;
    this.listeners = new Map();
    this.closed = false;
  }
  addEventListener(type, listener) {
    if (mode === 'registration-child' && type === 'message') {
      throw new Error('synthetic registration failure');
    }
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }
  send() {}
  close() {
    if (this.closed) return;
    this.closed = true;
    FakeWebSocket.closed += 1;
    for (const listener of this.listeners.get('close') ?? []) listener();
  }
}
globalThis.WebSocket = FakeWebSocket;
bridge.installLiveProofPageBridge({ prompt: 'prompt', marker: 'marker' });
const url = 'wss://app.example.test/api/ws?ticket=boundedTicket';
let rejected = false;
if (mode === 'registration-child') {
  try {
    new globalThis.WebSocket(url);
  } catch (error) {
    rejected = error instanceof Error && error.message === 'live proof page bridge WebSocket observation setup failed';
  }
} else {
  for (let index = 0; index < 512; index += 1) {
    const socket = new globalThis.WebSocket(url);
    socket.close();
    await bridge.drainLiveProofPageEvents();
  }
  try {
    new globalThis.WebSocket(url);
  } catch {
    rejected = true;
  }
}
console.log(JSON.stringify({
  constructed: FakeWebSocket.constructed,
  closed: FakeWebSocket.closed,
  rejected,
  state: bridge.readLiveProofPageState()
}));
`;
  const output = execFileSync(process.execPath, ['--input-type=module', '-', mode], {
    cwd: repositoryRoot,
    encoding: 'utf8',
    input: script,
    stdio: ['pipe', 'pipe', 'pipe']
  });
  return JSON.parse(output.trim().split('\n').at(-1));
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

function proofMessages() {
  return [
    { id: 10, role: 'system', content: null },
    { id: 11, role: 'assistant', content: 'prior answer' },
    { id: 12, role: 'user', content: 'Reply with exactly: Hermternal live proof complete.' },
    { id: 13, role: 'assistant', content: 'Hermternal live proof complete.' }
  ];
}

function historyEvent(ledger, phase, messages) {
  return {
    phase,
    status: 200,
    sessionId: 'stored-1',
    historyComplete: true,
    watermarkEstablished: phase === 'pre-send',
    prefixStable: phase === 'post-completion',
    postFenceMatched: phase === 'post-completion',
    promptMatches: phase === 'post-completion',
    assistantMarkerMatches: phase === 'post-completion',
    candidateUserCount: phase === 'post-completion' ? 1 : 0,
    candidateAssistantCount: phase === 'post-completion' ? 1 : 0,
    messageCount: messages.length,
    historyProjectionTag: ledger.messageProjectionTag(messages),
    prefixProjectionTag: ledger.messageProjectionTag(
      phase === 'pre-send' ? messages : messages.slice(0, 2)
    )
  };
}

/**
 * The exact a7d parent only retained route/ticket booleans and same-ID response
 * tags. This synthetic sequence models an attacker-origin socket that forged
 * every later fixed projection. Response fields are deliberately supplied to
 * the parent boundary but are discarded by its same-ID-only recorder.
 *
 * @param {any} module
 * @param {Record<string, unknown>} [responseFields]
 */
function forgedParentSequence(module, responseFields = {}) {
  const ledger = module.createLiveProofLedger(256, {
    signer: module.createLiveProofTestSigner(),
    allowTestSigner: true
  });
  const preMessages = proofMessages().slice(0, 2);
  const postMessages = proofMessages();
  ledger.recordWebSocketOpen({
    route: '/api/ws',
    ticketOnly: true,
    originBound: false
  });
  ledger.recordWebSocketReceived({ event: 'gateway.ready' });
  ledger.recordGatewayReady();
  ledger.recordSessionAction({
    method: 'session.resume',
    requestId: 'create-1',
    sessionId: 'ephemeral-1',
    storedSessionId: 'stored-1'
  });
  ledger.recordHistoryResponse(historyEvent(ledger, 'pre-send', preMessages));
  ledger.recordPrompt({ requestId: 'prompt-1', sessionId: 'ephemeral-1', promptMatches: true });
  // The parent treats every same-ID response as an acknowledgement. The
  // supplied error/result fields model the raw frame shape, but the parent
  // recorder discards them before matching.
  ledger.recordWebSocketReceived({
    event: 'response',
    requestId: 'prompt-1',
    ...responseFields
  });
  ledger.recordDelta({ sessionId: 'ephemeral-1' });
  ledger.recordCompletion({
    sessionId: 'ephemeral-1',
    status: 'complete',
    markerMatches: true
  });
  ledger.recordHistoryResponse(historyEvent(ledger, 'post-completion', postMessages));
  return {
    events: ledger.snapshot(),
    expected: {
      sessionTag: ledger.identityTag('stored-1'),
      promptRequestTag: ledger.identityTag('prompt-1'),
      promptSessionTag: ledger.identityTag('ephemeral-1')
    }
  };
}

const [parent, child] = await Promise.all([loadExactParentLedger(), loadChildLedger()]);

// Both parent and child require an explicit test signer in this exact parent;
// neither path may silently restore a Node production signer.
const parentLedger = expectAccepted('parent explicit test signer', () => parent.createLiveProofLedger(256, {
  signer: parent.createLiveProofTestSigner(),
  allowTestSigner: true
}));
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

const hostileCases = [
  { name: 'resultless response', fields: {} },
  { name: 'JSON-RPC error response', fields: { error: { code: -32000, message: 'error' } } },
  { name: 'malformed result response', fields: { result: { accepted: 'yes' } } }
];

for (const { name, fields } of hostileCases) {
  const hostileCase = forgedParentSequence(parent, fields);
  const parentProof = expectAccepted(`exact a7d parent ${name}`, () =>
    parent.matchLiveProofLedger(hostileCase.events, hostileCase.expected)
  );
  assert.equal(parentProof.ordered, true);
  assert.equal(parentProof.websocketOpen, true);
  assert.equal(parentProof.promptAcknowledgement, true);
  assert.equal(parentProof.history, true);
}

const hostile = forgedParentSequence(parent);
const childProof = child.matchLiveProofLedger(hostile.events, hostile.expected);
assert.equal(childProof.websocketOpen, false);
assert.equal(childProof.promptAcknowledgement, false);
assert.equal(childProof.ordered, false);
// A forged history projection may still be structurally valid in isolation;
// the causal proof remains rejected because origin and acknowledgement gates fail.
assert.equal(childProof.history, true);

expectRejected('child unbound WebSocket projection', () => childTestLedger.recordWebSocketOpen({
  route: '/api/ws',
  ticketOnly: true,
  originBound: false
}));
expectRejected('child resultless response projection', () => childTestLedger.recordWebSocketReceived({
  event: 'response',
  requestId: 'prompt-1'
}));
expectRejected('child error response projection', () => childTestLedger.recordWebSocketReceived({
  event: 'response',
  requestId: 'prompt-1',
  acknowledgement: false,
  error: { code: -32000 }
}));
expectRejected('child malformed result projection', () => childTestLedger.recordWebSocketReceived({
  event: 'response',
  requestId: 'prompt-1',
  acknowledgement: true,
  result: { accepted: 'yes' }
}));
expectRejected('child extra response projection', () => childTestLedger.recordWebSocketReceived({
  event: 'response',
  requestId: 'prompt-1',
  acknowledgement: true,
  extra: true
}));

const parentBridgeProbe = runBridgeProbe('parent');
assert.equal(parentBridgeProbe.rejected, true);
assert.equal(parentBridgeProbe.constructed, 513);
assert.equal(parentBridgeProbe.closed, 512);
assert.equal(parentBridgeProbe.state.websocketOpenCount, 512);
assert.equal(parentBridgeProbe.state.websocketCloseCount, 512);

const childBridgeProbe = runBridgeProbe('child');
assert.equal(childBridgeProbe.rejected, true);
assert.equal(childBridgeProbe.constructed, 512);
assert.equal(childBridgeProbe.closed, 512);
assert.equal(childBridgeProbe.state.websocketOpenCount, 512);
assert.equal(childBridgeProbe.state.websocketCloseCount, 512);

const registrationCleanupProbe = runBridgeProbe('registration-child');
assert.equal(registrationCleanupProbe.rejected, true);
assert.equal(registrationCleanupProbe.constructed, 1);
assert.equal(registrationCleanupProbe.closed, 1);
assert.equal(registrationCleanupProbe.state.websocketOpenCount, 0);
assert.equal(registrationCleanupProbe.state.websocketCloseCount, 0);

console.log(
  `live-proof-parent-compat: ${PARENT_COMMIT.slice(0, 12)} ledger gates and ${BRIDGE_PARENT_COMMIT.slice(0, 12)} bridge lifetime bound regressions pass; child rejects attacker-origin, unsafe acknowledgements, 513th construction, and registration leaks`
);
