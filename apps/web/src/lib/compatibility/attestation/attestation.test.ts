import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  JSON_RPC_EVENT_METHOD,
  JSON_RPC_GATEWAY_READY_EVENT,
  type JsonRpcChatOptions,
  type JsonRpcChatTransport,
  type JsonRpcCompatibilityEvidence,
  type JsonRpcCompatibilityGate,
  type JsonRpcWebSocket
} from '../../chat/json-rpc-chat';
import {
  createBehavioralProbeGate,
  createCanonicalFixtureTrustContext,
  createCompatibilityAttestationGate,
  evaluateCompatibilityAttestation
} from './attestation';

const FIXTURE_ROOT = resolve(process.cwd(), '../../contracts/fixtures/compatibility-attestation');
const CANONICAL_ATTESTATION_TEXT = readFileSync(
  resolve(FIXTURE_ROOT, 'revision_attestation.json'),
  'utf8'
);
const CANONICAL_ATTESTATION = JSON.parse(CANONICAL_ATTESTATION_TEXT) as Record<string, unknown>;
const CASES = JSON.parse(readFileSync(resolve(FIXTURE_ROOT, 'cases.json'), 'utf8')) as {
  cases: Array<{
    id: string;
    input: {
      attestation: string;
      revision: string;
      route_manifest: string;
      source_review: string;
      proxy_proof: string;
      behavioral_probe: 'not_run' | 'passed' | 'failed';
      dashboard_metadata: string;
    };
    expected: {
      attestation_result: 'verified' | 'blocked';
      runtime_gate: 'blocked_pending_probe' | 'separate_probe_gate' | 'blocked_incompatible';
    };
  }>;
};

const RUNTIME_EVIDENCE: JsonRpcCompatibilityEvidence = {
  contract: 'dashboard-v0.0.1',
  hermesSourceSha: 'f5be9236e00ddf2f2a412697f267078fc4ee068e',
  websocketPath: '/api/ws',
  deployment: {
    identity: 'synthetic-deployment-001',
    trustChannel: 'release-channel',
    scope: 'fixture_only'
  },
  routeManifest: {
    path: 'contracts/hermes-dashboard/manifest.md',
    revision: 'dashboard-v0.0.1',
    sha256: '680e1ef387c403538a8fa0959243f7414ad12c4d33cecae4fb1081a509c3f1b5',
    sizeBytes: 18_163
  },
  sourceReview: {
    path: 'contracts/fixtures/source-audit/planning-reconciliation/planning_review.json',
    sha256: '0a84cba82e6e966ab35de187f560fd38d6e10c43dd2204062d6ebf2bc5c32077',
    sizeBytes: 20_045
  },
  proxyProof: {
    path: 'docs/deployment/proof-matrix.md',
    sha256: '99945f3193f5ea9aa72c00c786d4c447c117774803ac036b1617575f0da8944d',
    sizeBytes: 18_047
  },
  gatewayReadyPayload: Object.create(null) as Record<string, never>
};

const COMPATIBILITY_EVIDENCE: JsonRpcChatOptions['compatibilityEvidence'] = {
  deployment: RUNTIME_EVIDENCE.deployment,
  routeManifest: RUNTIME_EVIDENCE.routeManifest,
  sourceReview: RUNTIME_EVIDENCE.sourceReview,
  proxyProof: RUNTIME_EVIDENCE.proxyProof
};

class FakeWebSocket implements JsonRpcWebSocket {
  onopen: ((event?: unknown) => void) | null = null;
  onmessage: ((event: { readonly data: unknown }) => void) | null = null;
  onerror: ((event?: unknown) => void) | null = null;
  onclose: ((event?: { readonly code?: number; readonly reason?: string }) => void) | null = null;
  closed: { readonly code?: number; readonly reason?: string } | undefined;

  send(): void {}

  close(code?: number, reason?: string): void {
    if (this.closed) return;
    this.closed = { code, reason };
    this.onclose?.(this.closed);
  }

  emitOpen(): void {
    this.onopen?.();
  }

  emitGatewayReady(payload: Record<string, unknown> = {}): void {
    this.onmessage?.({
      data: JSON.stringify({
        jsonrpc: '2.0',
        method: JSON_RPC_EVENT_METHOD,
        params: { type: JSON_RPC_GATEWAY_READY_EVENT, payload }
      })
    });
  }
}

async function flush(): Promise<void> {
  for (let index = 0; index < 32; index += 1) await Promise.resolve();
}

function cloneAttestation(): Record<string, unknown> {
  return structuredClone(CANONICAL_ATTESTATION);
}

function nested(record: Record<string, unknown>, key: string): Record<string, unknown> {
  return record[key] as Record<string, unknown>;
}

function fixtureInput(caseInput: (typeof CASES.cases)[number]['input']): unknown {
  if (caseInput.attestation === 'missing') return undefined;
  if (caseInput.attestation === 'empty') return '';
  if (caseInput.attestation === 'malformed') return '{"schema":';

  const record = cloneAttestation();
  if (caseInput.revision === 'unknown') nested(record, 'hermes').source_sha = 'unknown';
  if (caseInput.revision === 'abbreviated') nested(record, 'hermes').source_sha = 'f5be9236';
  if (caseInput.revision === 'mismatched') {
    nested(record, 'hermes').source_sha = '0000000000000000000000000000000000000000';
  }
  if (caseInput.route_manifest === 'mismatch') {
    nested(record, 'route_manifest').sha256 = '0'.repeat(64);
  }
  if (caseInput.source_review === 'mismatch')
    nested(record, 'source_review').sha256 = '0'.repeat(64);
  if (caseInput.proxy_proof === 'mismatch') nested(record, 'proxy_proof').sha256 = '0'.repeat(64);
  if (caseInput.dashboard_metadata === 'unexpected') {
    nested(record, 'dashboard_metadata').source_revision_observable = true;
  }
  return record;
}

function makeTransport(
  input: unknown,
  behavioralProbe: JsonRpcChatOptions['runBehavioralProbe'],
  signal?: AbortSignal
): {
  readonly transport: JsonRpcChatTransport;
  readonly socket: FakeWebSocket;
  readonly connection: Promise<void>;
} {
  const socket = new FakeWebSocket();
  const attestation = createCompatibilityAttestationGate(
    input,
    createCanonicalFixtureTrustContext()
  );
  const factory = attestation.pairWithBehavioralProbe(
    createBehavioralProbeGate(behavioralProbe ?? (async () => false))
  );
  const transport = factory.createTransport({
    ticketProvider: async () => 'synthetic-ticket',
    createWebSocket: () => socket,
    compatibilityEvidence: COMPATIBILITY_EVIDENCE,
    compatibilityGateTimeoutMs: 10_000
  });
  const connection = transport.connect(signal);
  return { transport, socket, connection };
}

describe('fixture-driven compatibility attestation', () => {
  it('implements every C-04 attestation and runtime_gate result through the transport', async () => {
    for (const fixtureCase of CASES.cases) {
      const probe = vi.fn(
        fixtureCase.input.behavioral_probe === 'not_run'
          ? () => new Promise<boolean>(() => undefined)
          : async () => fixtureCase.input.behavioral_probe === 'passed'
      );
      const controller = new AbortController();
      const harness = makeTransport(fixtureInput(fixtureCase.input), probe, controller.signal);
      await flush();
      harness.socket.emitOpen();
      harness.socket.emitGatewayReady();
      await flush();

      if (fixtureCase.expected.runtime_gate === 'separate_probe_gate') {
        await expect(harness.connection, fixtureCase.id).resolves.toBeUndefined();
        expect(harness.transport.state.status, fixtureCase.id).toBe('ready');
        expect(probe, fixtureCase.id).toHaveBeenCalledTimes(1);
      } else if (fixtureCase.expected.runtime_gate === 'blocked_pending_probe') {
        expect(harness.transport.state.status, fixtureCase.id).toBe('handshaking');
        expect(probe, fixtureCase.id).toHaveBeenCalledTimes(1);
        controller.abort();
        await expect(harness.connection, fixtureCase.id).rejects.toMatchObject({
          code: 'aborted'
        });
        expect(harness.transport.state.status, fixtureCase.id).toBe('offline');
      } else {
        await expect(harness.connection, fixtureCase.id).rejects.toMatchObject({
          code: 'incompatible'
        });
        expect(harness.transport.state.status, fixtureCase.id).toBe('incompatible');
        expect(probe, fixtureCase.id).toHaveBeenCalledTimes(
          fixtureCase.expected.attestation_result === 'verified' ? 1 : 0
        );
      }
    }
  });

  it('never exposes or reuses an attestation callback as a behavioral probe', async () => {
    const attestation = createCompatibilityAttestationGate(
      CANONICAL_ATTESTATION_TEXT,
      createCanonicalFixtureTrustContext()
    );
    // @ts-expect-error The nominal attestation wrapper is not a behavioral-probe callback.
    const invalidProbe: JsonRpcChatOptions['runBehavioralProbe'] = attestation;
    expect(invalidProbe).toBe(attestation);
    expect(() => {
      // @ts-expect-error A structural lookalike lacks the private nominal marker.
      attestation.pairWithBehavioralProbe({ kind: 'behavioral-probe' });
    }).toThrowError('A canonical behavioral-probe wrapper is required.');

    const probeGate = createBehavioralProbeGate(async () => false);
    const factory = attestation.pairWithBehavioralProbe(probeGate);
    expect(Reflect.ownKeys(factory)).toEqual(['kind', 'createTransport']);
    expect('verifyAttestation' in factory).toBe(false);
    expect('runBehavioralProbe' in factory).toBe(false);
    // @ts-expect-error The transport factory never exposes the attestation callback.
    const extracted = factory.verifyAttestation;
    expect(extracted).toBeUndefined();
    expect(() => createBehavioralProbeGate(extracted)).toThrowError(
      'An independent behavioral-probe callback is required.'
    );
    expect(() =>
      attestation.pairWithBehavioralProbe(createBehavioralProbeGate(async () => true))
    ).toThrowError('Compatibility gate wrappers can be paired only once.');
    const secondAttestation = createCompatibilityAttestationGate(
      CANONICAL_ATTESTATION_TEXT,
      createCanonicalFixtureTrustContext()
    );
    expect(() => secondAttestation.pairWithBehavioralProbe(probeGate)).toThrowError(
      'Compatibility gate wrappers can be paired only once.'
    );

    const roleLookalikes = [
      factory.createTransport as unknown as JsonRpcCompatibilityGate,
      factory.createTransport.bind(factory) as unknown as JsonRpcCompatibilityGate,
      ((...args: Parameters<JsonRpcCompatibilityGate>) =>
        (factory.createTransport as unknown as JsonRpcCompatibilityGate)(
          ...args
        )) as JsonRpcCompatibilityGate,
      new Proxy(factory.createTransport, {}) as unknown as JsonRpcCompatibilityGate
    ];
    for (const callback of roleLookalikes) {
      const harness = makeTransport(CANONICAL_ATTESTATION_TEXT, callback);
      await flush();
      harness.socket.emitOpen();
      harness.socket.emitGatewayReady();
      await expect(harness.connection).rejects.toMatchObject({ code: 'incompatible' });
      expect(harness.transport.state.status).toBe('incompatible');
    }

    for (const result of [false, { passed: false }] as const) {
      const harness = makeTransport(CANONICAL_ATTESTATION_TEXT, async () => result);
      await flush();
      harness.socket.emitOpen();
      harness.socket.emitGatewayReady();
      await expect(harness.connection).rejects.toMatchObject({ code: 'incompatible' });
      expect(harness.transport.state.status).toBe('incompatible');
    }
  });

  it('consumes the transport factory before concurrent or reentrant reuse', async () => {
    let attestationCalls = 0;
    const input = new Proxy(cloneAttestation(), {
      ownKeys(target) {
        attestationCalls += 1;
        return Reflect.ownKeys(target);
      }
    });
    const probe = vi.fn(async () => true);
    const factory = createCompatibilityAttestationGate(
      input,
      createCanonicalFixtureTrustContext()
    ).pairWithBehavioralProbe(createBehavioralProbeGate(probe));
    const sockets: FakeWebSocket[] = [];
    const options = {
      ticketProvider: async () => 'synthetic-ticket',
      createWebSocket: () => {
        const socket = new FakeWebSocket();
        sockets.push(socket);
        return socket;
      },
      compatibilityEvidence: COMPATIBILITY_EVIDENCE,
      compatibilityGateTimeoutMs: 10_000
    };

    const attempts = await Promise.allSettled([
      Promise.resolve().then(() => factory.createTransport(options)),
      Promise.resolve().then(() => factory.createTransport(options))
    ]);
    const fulfilled = attempts.filter(
      (attempt): attempt is PromiseFulfilledResult<JsonRpcChatTransport> =>
        attempt.status === 'fulfilled'
    );
    const rejected = attempts.filter(
      (attempt): attempt is PromiseRejectedResult => attempt.status === 'rejected'
    );
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(String(rejected[0]?.reason)).toBe(
      'TypeError: Compatibility transport factory has already been consumed.'
    );
    expect(String(rejected[0]?.reason)).not.toContain('synthetic-ticket');
    expect(String(rejected[0]?.reason)).not.toContain('verifyAttestation');
    expect(String(rejected[0]?.reason)).not.toContain('runBehavioralProbe');
    expect(sockets).toHaveLength(0);
    expect(probe).not.toHaveBeenCalled();
    expect(attestationCalls).toBe(0);

    const transport = fulfilled[0]!.value;
    const connection = transport.connect();
    await flush();
    expect(sockets).toHaveLength(1);
    sockets[0]!.emitOpen();
    sockets[0]!.emitGatewayReady();
    await expect(connection).resolves.toBeUndefined();
    expect(transport.state.status).toBe('ready');
    expect(probe).toHaveBeenCalledTimes(1);
    expect(attestationCalls).toBe(1);
    expect(() => factory.createTransport(options)).toThrowError(
      'Compatibility transport factory has already been consumed.'
    );
    expect(sockets).toHaveLength(1);
    expect(probe).toHaveBeenCalledTimes(1);
    expect(attestationCalls).toBe(1);

    const reentrantProbe = vi.fn(async () => true);
    const reentrantFactory = createCompatibilityAttestationGate(
      CANONICAL_ATTESTATION_TEXT,
      createCanonicalFixtureTrustContext()
    ).pairWithBehavioralProbe(createBehavioralProbeGate(reentrantProbe));
    let reentrantSockets = 0;
    const reentrantOptions = {
      createWebSocket: () => {
        reentrantSockets += 1;
        return new FakeWebSocket();
      },
      compatibilityEvidence: COMPATIBILITY_EVIDENCE
    } as Record<string, unknown>;
    Object.defineProperty(reentrantOptions, 'ticketProvider', {
      enumerable: true,
      get() {
        reentrantFactory.createTransport(
          reentrantOptions as Parameters<typeof reentrantFactory.createTransport>[0]
        );
        return async () => 'synthetic-ticket';
      }
    });
    expect(() =>
      reentrantFactory.createTransport(
        reentrantOptions as Parameters<typeof reentrantFactory.createTransport>[0]
      )
    ).toThrowError('Compatibility transport factory has already been consumed.');
    expect(reentrantSockets).toBe(0);
    expect(reentrantProbe).not.toHaveBeenCalled();
    expect(() =>
      reentrantFactory.createTransport(
        reentrantOptions as Parameters<typeof reentrantFactory.createTransport>[0]
      )
    ).toThrowError('Compatibility transport factory has already been consumed.');
  });

  it('cancels a pending separate probe without claiming readiness', async () => {
    const controller = new AbortController();
    const harness = makeTransport(
      CANONICAL_ATTESTATION_TEXT,
      () => new Promise<boolean>(() => undefined),
      controller.signal
    );
    await flush();
    harness.socket.emitOpen();
    harness.socket.emitGatewayReady();
    await flush();
    expect(harness.transport.state.status).toBe('handshaking');
    controller.abort();
    await expect(harness.connection).rejects.toMatchObject({ code: 'aborted' });
    expect(harness.transport.state.status).toBe('offline');
  });

  it('pins canonical deployment fields and rejects attacker-controlled matching context', () => {
    const trusted = createCanonicalFixtureTrustContext();
    expect(
      evaluateCompatibilityAttestation(CANONICAL_ATTESTATION, trusted, RUNTIME_EVIDENCE)
    ).toEqual({ passed: true, code: 'verified' });

    const matchingButUntrusted = {
      status: 'trusted',
      channel: 'release-channel',
      deploymentIdentity: 'synthetic-deployment-001',
      scope: 'fixture_only'
    };
    expect(
      evaluateCompatibilityAttestation(
        CANONICAL_ATTESTATION,
        matchingButUntrusted,
        RUNTIME_EVIDENCE
      )
    ).toEqual({ passed: false, code: 'untrusted-source' });

    for (const [section, key, value] of [
      ['deployment', 'identity', 'attacker-controlled'],
      ['deployment', 'trust_channel', 'attacker-channel'],
      ['deployment', 'scope', 'live']
    ] as const) {
      const changed = cloneAttestation();
      nested(changed, section)[key] = value;
      expect(evaluateCompatibilityAttestation(changed, trusted, RUNTIME_EVIDENCE), key).toEqual({
        passed: false,
        code: 'evidence-mismatch'
      });
    }
  });

  it('rejects duplicate, reordered, additive, and non-finite attestation JSON', () => {
    const canonicalJson = JSON.stringify(CANONICAL_ATTESTATION);
    const duplicateSchema = canonicalJson.replace(
      '"schema":"hermternal.revision-attestation.v1",',
      '"schema":"hermternal.revision-attestation.v1","schema":"hermternal.revision-attestation.v1",'
    );
    const reordered = cloneAttestation();
    const schema = reordered.schema;
    delete reordered.schema;
    reordered.schema = schema;
    const additive = cloneAttestation();
    additive.compatible = true;

    for (const input of [
      duplicateSchema,
      reordered,
      additive,
      canonicalJson.replace('18163', '1e9999')
    ]) {
      expect(
        evaluateCompatibilityAttestation(
          input,
          createCanonicalFixtureTrustContext(),
          RUNTIME_EVIDENCE
        ).passed
      ).toBe(false);
    }
  });

  it('rejects normalized, punctuated, prefixed, and suffixed server-version metadata', () => {
    for (const key of [
      'protocol_version',
      'protocolVersion',
      ' protocol version ',
      '...protocol-version!!!',
      'x protocol version',
      'xProtocolVersionSuffix',
      'prefixprotocolversionsuffix',
      'protocol version suffix',
      '--server-source-sha--',
      'prefix.revision-from-response'
    ]) {
      const evidence: JsonRpcCompatibilityEvidence = {
        ...RUNTIME_EVIDENCE,
        gatewayReadyPayload: { nested: { [key]: 'dashboard-v0.0.1' } }
      };
      expect(
        evaluateCompatibilityAttestation(
          CANONICAL_ATTESTATION,
          createCanonicalFixtureTrustContext(),
          evidence
        ),
        key
      ).toEqual({ passed: false, code: 'server-metadata-rejected' });
    }
  });

  it('bounds whitespace, object strings, and million-entry arrays without throwing', () => {
    const trusted = createCanonicalFixtureTrustContext();
    expect(() =>
      evaluateCompatibilityAttestation(' '.repeat(1_000_000), trusted, RUNTIME_EVIDENCE)
    ).not.toThrow();
    expect(
      evaluateCompatibilityAttestation(' '.repeat(1_000_000), trusted, RUNTIME_EVIDENCE)
    ).toEqual({ passed: false, code: 'malformed' });

    const oversizedObject = cloneAttestation();
    oversizedObject.schema = 'x'.repeat(1_000_000);
    expect(() =>
      evaluateCompatibilityAttestation(oversizedObject, trusted, RUNTIME_EVIDENCE)
    ).not.toThrow();
    expect(
      evaluateCompatibilityAttestation(oversizedObject, trusted, RUNTIME_EVIDENCE).passed
    ).toBe(false);

    const millionEntries = new Array<null>(1_000_000).fill(null);
    const evidence = {
      ...RUNTIME_EVIDENCE,
      gatewayReadyPayload: millionEntries
    };
    expect(() =>
      evaluateCompatibilityAttestation(CANONICAL_ATTESTATION, trusted, evidence)
    ).not.toThrow();
    expect(evaluateCompatibilityAttestation(CANONICAL_ATTESTATION, trusted, evidence)).toEqual({
      passed: false,
      code: 'evidence-mismatch'
    });
  });

  it('rejects additive, symbol, non-enumerable, and accessor runtime evidence', () => {
    const trusted = createCanonicalFixtureTrustContext();
    const mutations: Array<(evidence: Record<string, unknown>) => void> = [
      (evidence) => {
        evidence.additive = true;
      },
      (evidence) => {
        Object.defineProperty(evidence, Symbol('hidden'), {
          value: true,
          enumerable: true
        });
      },
      (evidence) => {
        Object.defineProperty(evidence, 'hidden', {
          value: true,
          enumerable: false
        });
      },
      (evidence) => {
        Object.defineProperty(evidence, 'contract', {
          enumerable: true,
          get: () => 'dashboard-v0.0.1'
        });
      },
      (evidence) => {
        Object.defineProperty(evidence.deployment as object, 'identity', {
          enumerable: true,
          get: () => 'synthetic-deployment-001'
        });
      },
      (evidence) => {
        Object.defineProperty(evidence.proxyProof as object, 'additive', {
          value: true,
          enumerable: true
        });
      }
    ];

    for (const mutate of mutations) {
      const evidence = structuredClone(RUNTIME_EVIDENCE) as unknown as Record<string, unknown>;
      mutate(evidence);
      expect(() =>
        evaluateCompatibilityAttestation(CANONICAL_ATTESTATION, trusted, evidence)
      ).not.toThrow();
      expect(
        evaluateCompatibilityAttestation(CANONICAL_ATTESTATION, trusted, evidence).passed
      ).toBe(false);
    }
  });

  it('snapshots inert data before validation and preserves cancellation', () => {
    const trusted = createCanonicalFixtureTrustContext();
    let reads = 0;
    const evidence = structuredClone(RUNTIME_EVIDENCE) as unknown as Record<string, unknown>;
    Object.defineProperty(evidence, 'contract', {
      enumerable: true,
      get: () => {
        reads += 1;
        return 'dashboard-v0.0.1';
      }
    });
    expect(evaluateCompatibilityAttestation(CANONICAL_ATTESTATION, trusted, evidence).passed).toBe(
      false
    );
    expect(reads).toBe(0);

    let proxyReads = 0;
    const proxiedArray = new Proxy([], {
      get(target, property, receiver) {
        proxyReads += 1;
        return Reflect.get(target, property, receiver);
      }
    });
    expect(
      evaluateCompatibilityAttestation(CANONICAL_ATTESTATION, trusted, {
        ...RUNTIME_EVIDENCE,
        gatewayReadyPayload: proxiedArray
      })
    ).toEqual({ passed: true, code: 'verified' });
    expect(proxyReads).toBe(0);

    const controller = new AbortController();
    controller.abort();
    expect(
      evaluateCompatibilityAttestation(
        CANONICAL_ATTESTATION,
        trusted,
        RUNTIME_EVIDENCE,
        controller.signal
      )
    ).toEqual({ passed: false, code: 'aborted' });
  });
});
