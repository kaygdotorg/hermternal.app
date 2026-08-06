import behavioralProbeFixture from '../../../../../../contracts/fixtures/behavioral-probe/probe-fixtures.json';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  behavioralProbeFixtureDigestForTest,
  createBehavioralProbeFixtureEvidence,
  evaluateBehavioralProbeGate,
  sha256ForTest,
  validateBehavioralProbeFixtureForTest,
  type BehavioralProbeEvidence,
  type BehavioralProbeStateId
} from './behavioral-probe-gate';
import { CANONICAL_ROUTE_MANIFEST_BYTES } from './canonical-route-manifest';

const repositoryRoot = process.cwd().endsWith('/apps/web')
  ? resolve(process.cwd(), '../..')
  : process.cwd();
const routeManifestBytes = readFileSync(
  resolve(repositoryRoot, 'contracts/hermes-dashboard/manifest.md'),
  'utf8'
);

function parseEvidence(evidenceJson: string): BehavioralProbeEvidence {
  return JSON.parse(evidenceJson) as BehavioralProbeEvidence;
}

function serializeEvidence(value: unknown): string {
  const canonicalize = (candidate: unknown): unknown => {
    if (candidate === null || typeof candidate !== 'object') return candidate;
    if (Array.isArray(candidate)) return candidate.map(canonicalize);
    return Object.fromEntries(
      Object.keys(candidate as Record<string, unknown>).sort().map((key) => [
        key,
        canonicalize((candidate as Record<string, unknown>)[key])
      ])
    );
  };
  return JSON.stringify(canonicalize(value));
}

function cloneEvidence(evidenceJson: string): BehavioralProbeEvidence {
  return structuredClone(parseEvidence(evidenceJson));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('evaluateBehavioralProbeGate', () => {
  it('validates all 64 canonical cases but blocks a synthetic success from a live claim', () => {
    const evidenceJson = createBehavioralProbeFixtureEvidence('success');
    const evidence = parseEvidence(evidenceJson);

    expect(evidence.caseResults).toHaveLength(64);
    expect(evaluateBehavioralProbeGate(evidenceJson)).toEqual({
      status: 'blocked',
      state: 'success',
      evidenceState: 'synthetic_fixture_validated',
      gateDecision: 'blocked_live_compatibility',
      safeState: 'artifact_only_no_live_claim',
      retryPolicy: 'not_applicable',
      compatible: false,
      liveRun: false,
      fixtureValidated: true,
      requiresSourceStateReread: false,
      reason: 'fixture-state'
    });
  });

  const blockedStates = [
    ['pending', 'collection_in_progress', 'wait_or_cancel', false],
    ['empty', 'no_observations', 'collect_required_evidence', false],
    ['failure', 'required_case_failed', 'idempotent_collection_only', false],
    ['cancelled', 'cancelled_before_completion', 'resume_after_source_state_reread', true],
    ['unknown', 'result_unavailable', 'reread_source_state_before_retry', true]
  ] satisfies ReadonlyArray<readonly [BehavioralProbeStateId, string, string, boolean]>;

  it.each(blockedStates)(
    'keeps the %s fixture state blocked with its reviewed recovery policy',
    (state, evidenceState, retryPolicy, requiresSourceStateReread) => {
      expect(evaluateBehavioralProbeGate(createBehavioralProbeFixtureEvidence(state))).toMatchObject({
        status: 'blocked',
        state,
        evidenceState,
        gateDecision: 'blocked',
        retryPolicy,
        compatible: false,
        liveRun: false,
        fixtureValidated: false,
        requiresSourceStateReread,
        reason: 'fixture-state'
      });
    }
  );

  it('uses no browser network or persistence API while building and evaluating fixtures', () => {
    const fetchMock = vi.fn();
    const webSocketMock = vi.fn();
    const storageGetMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    vi.stubGlobal('WebSocket', webSocketMock);
    vi.stubGlobal('localStorage', { getItem: storageGetMock });

    evaluateBehavioralProbeGate(createBehavioralProbeFixtureEvidence('success'));

    expect(fetchMock).not.toHaveBeenCalled();
    expect(webSocketMock).not.toHaveBeenCalled();
    expect(storageGetMock).not.toHaveBeenCalled();
  });

  it.each([
    ['wrong contract', (evidence: BehavioralProbeEvidence) => ({ ...evidence, contract: 'unknown-contract' })],
    ['wrong Hermes source', (evidence: BehavioralProbeEvidence) => ({ ...evidence, hermesSourceSha: '0'.repeat(40) })],
    ['wrong manifest digest', (evidence: BehavioralProbeEvidence) => ({ ...evidence, routeManifestSha256: '0'.repeat(64) })],
    ['live result', (evidence: BehavioralProbeEvidence) => ({ ...evidence, liveRun: true })],
    ['non-synthetic result', (evidence: BehavioralProbeEvidence) => ({ ...evidence, syntheticOnly: false })]
  ])('fails closed for a %s binding', (_label, mutate) => {
    const evidence = mutate(parseEvidence(createBehavioralProbeFixtureEvidence('success')));

    expect(evaluateBehavioralProbeGate(serializeEvidence(evidence))).toEqual(incompatibleResult());
  });

  it('fails closed when one canonical case result changes', () => {
    const evidence = cloneEvidence(createBehavioralProbeFixtureEvidence('success'));
    const first = evidence.caseResults[0];
    if (!first) {
      throw new Error('Expected the canonical case inventory.');
    }
    const changed = {
      ...evidence,
      caseResults: [{ ...first, observed: { unexpected: 'allow' } }, ...evidence.caseResults.slice(1)]
    };

    expect(evaluateBehavioralProbeGate(serializeEvidence(changed))).toEqual(incompatibleResult());
  });

  it('fails closed when a required case or requirement is missing or duplicated', () => {
    const evidence = parseEvidence(createBehavioralProbeFixtureEvidence('success'));
    const missingCase = { ...evidence, caseResults: evidence.caseResults.slice(1) };
    const duplicateCase = {
      ...evidence,
      caseResults: [...evidence.caseResults.slice(0, -1), evidence.caseResults[0]]
    };
    const missingRequirement = {
      ...evidence,
      requirementResults: evidence.requirementResults.slice(1)
    };

    expect(evaluateBehavioralProbeGate(serializeEvidence(missingCase))).toEqual(incompatibleResult());
    expect(evaluateBehavioralProbeGate(serializeEvidence(duplicateCase))).toEqual(incompatibleResult());
    expect(evaluateBehavioralProbeGate(serializeEvidence(missingRequirement))).toEqual(incompatibleResult());
  });

  it.each(['reverse', 'adjacent-swap', 'arbitrary-reorder'] as const)(
    'rejects %s ordering of both canonical evidence inventories',
    (mutation) => {
      const canonical = parseEvidence(createBehavioralProbeFixtureEvidence('success'));
      const reorder = <T>(items: readonly T[]): T[] => {
        if (mutation === 'reverse') return [...items].reverse();
        if (mutation === 'adjacent-swap') {
          const result = [...items];
          [result[0], result[1]] = [result[1]!, result[0]!];
          return result;
        }
        return [...items.slice(2), ...items.slice(0, 2)];
      };

      expect(evaluateBehavioralProbeGate(serializeEvidence({
        ...canonical,
        caseResults: reorder(canonical.caseResults)
      }))).toEqual(incompatibleResult());
      expect(evaluateBehavioralProbeGate(serializeEvidence({
        ...canonical,
        requirementResults: reorder(canonical.requirementResults)
      }))).toEqual(incompatibleResult());
    }
  );

  it('fails closed when success evidence has a false requirement', () => {
    const evidence = parseEvidence(createBehavioralProbeFixtureEvidence('success'));
    const first = evidence.requirementResults[0];
    if (!first) {
      throw new Error('Expected the canonical requirement inventory.');
    }
    const changed = {
      ...evidence,
      requirementResults: [{ ...first, passed: false }, ...evidence.requirementResults.slice(1)]
    };

    expect(evaluateBehavioralProbeGate(serializeEvidence(changed))).toEqual(incompatibleResult());
  });

  it.each([null, {}, [], 'unknown', 7, '', '{', 'null', '[]'])('fails closed with one fixed redacted result for malformed evidence %j', (evidence) => {
    expect(evaluateBehavioralProbeGate(evidence)).toEqual(incompatibleResult());
  });

  it('fails closed for an unknown state and additive top-level evidence', () => {
    const evidence = parseEvidence(createBehavioralProbeFixtureEvidence('pending'));

    expect(evaluateBehavioralProbeGate(serializeEvidence({ ...evidence, state: 'future-state' }))).toEqual(
      incompatibleResult()
    );
    expect(evaluateBehavioralProbeGate(serializeEvidence({ ...evidence, unreviewed: true }))).toEqual(
      incompatibleResult()
    );
  });

  it.each(['getPrototypeOf', 'ownKeys', 'getOwnPropertyDescriptor'] as const)(
    'rejects a hostile Proxy before invoking its %s trap',
    (trap) => {
      let calls = 0;
      const hostile = new Proxy({}, {
        [trap]() {
          calls += 1;
          throw new Error('untrusted trap');
        }
      });

      expect(evaluateBehavioralProbeGate(hostile)).toEqual(incompatibleResult());
      expect(calls).toBe(0);
    }
  );

  it.each(['getPrototypeOf', 'ownKeys', 'getOwnPropertyDescriptor'] as const)(
    'terminates without invoking a non-returning %s trap in a subprocess',
    (trap) => {
      const script = `
        import { evaluateBehavioralProbeGate } from './src/lib/compatibility/probe/behavioral-probe-gate.ts';
        let calls = 0;
        const hostile = new Proxy({}, { ${trap}() { calls += 1; while (true) {} } });
        const result = evaluateBehavioralProbeGate(hostile);
        console.log(JSON.stringify({ calls, result }));
      `;
      const child = spawnSync('bun', ['-e', script], {
        cwd: resolve(repositoryRoot, 'apps/web'),
        encoding: 'utf8',
        timeout: 1_000
      });

      expect(child.error).toBeUndefined();
      expect(child.status).toBe(0);
      expect(JSON.parse(child.stdout)).toEqual({ calls: 0, result: incompatibleResult() });
    },
    2_000
  );

  it('never invokes hanging, delayed, network, or storage Proxy side effects', () => {
    const fetchMock = vi.fn();
    const storageSetMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    vi.stubGlobal('localStorage', { setItem: storageSetMock });
    let calls = 0;
    const hostile = new Proxy({}, {
      getOwnPropertyDescriptor() {
        calls += 1;
        fetchMock('synthetic');
        storageSetMock('synthetic', 'synthetic');
        const deadline = performance.now() + 300;
        while (performance.now() < deadline) { /* would block if invoked */ }
        return undefined;
      },
      ownKeys() {
        calls += 1;
        return [];
      },
      getPrototypeOf() {
        calls += 1;
        return null;
      }
    });
    const started = performance.now();

    expect(evaluateBehavioralProbeGate(hostile)).toEqual(incompatibleResult());
    expect(performance.now() - started).toBeLessThan(50);
    expect(calls).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(storageSetMock).not.toHaveBeenCalled();
  });

  it('rejects getters and cyclic objects before reading or traversing them', () => {
    let reads = 0;
    const cyclic: Record<string, unknown> = {};
    Object.defineProperty(cyclic, 'state', {
      enumerable: true,
      get() {
        reads += 1;
        return 'success';
      }
    });
    cyclic.self = cyclic;

    expect(evaluateBehavioralProbeGate(cyclic)).toEqual(incompatibleResult());
    expect(reads).toBe(0);
  });

  it.each([
    ['duplicate key', '{"a":1,"a":2}'],
    ['noncanonical key order', '{"b":1,"a":2}'],
    ['noncanonical whitespace', '{ "a":1}'],
    ['noncanonical number', '{"a":1.0}'],
    ['nonfinite number', '{"a":1e999}'],
    ['unsafe integer', '{"a":9007199254740992}'],
    ['lone surrogate', '{"a":"\\ud800"}'],
    ['array bound', `[${Array.from({ length: 501 }, () => 'null').join(',')}]`],
    ['object bound', `{${Array.from({ length: 129 }, (_, index) => `"k${String(index).padStart(3, '0')}":null`).join(',')}}`],
    ['depth bound', `${'['.repeat(26)}null${']'.repeat(26)}`],
    ['string bound', `{"a":"${'a'.repeat(8_193)}"}`],
    ['total UTF-8 bound', 'a'.repeat(262_145)]
  ])('rejects the serialized %s bound with the fixed result', (_label, evidenceJson) => {
    expect(evaluateBehavioralProbeGate(evidenceJson)).toEqual(incompatibleResult());
  });

  it.each(['top', 'case', 'requirement', 'case-array'])(
    'rejects symbol and non-enumerable additions at the %s evidence level',
    (level) => {
      for (const hiddenKey of [Symbol('hidden'), 'hidden']) {
        const evidence = cloneEvidence(createBehavioralProbeFixtureEvidence('success'));
        const target =
          level === 'top'
            ? evidence
            : level === 'case'
              ? evidence.caseResults[0]
              : level === 'requirement'
                ? evidence.requirementResults[0]
                : evidence.caseResults;
        if (!target) throw new Error('Expected canonical evidence target.');
        Object.defineProperty(target, hiddenKey, {
          value: 'unreviewed',
          enumerable: false,
          configurable: true
        });
        expect(evaluateBehavioralProbeGate(evidence)).toEqual(incompatibleResult());
      }
    }
  );
});

describe('canonical fixture bindings', () => {
  it('uses the reviewed SHA-256 implementation', () => {
    expect(CANONICAL_ROUTE_MANIFEST_BYTES).toBe(routeManifestBytes);
    expect(sha256ForTest('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(sha256ForTest(routeManifestBytes)).toBe('3c6b44dc8dd90836f4fc5c5158d459959c569fb811db4b198e87d78ea5010197');
    expect(behavioralProbeFixtureDigestForTest(behavioralProbeFixture)).toBe('293756e6b2573f59b7747c38cc0cda0f6602236ed93aae442f0022ad850d40e7');
  });

  it('accepts only the checked-in fixture and exact route-manifest bytes', () => {
    expect(validateBehavioralProbeFixtureForTest(behavioralProbeFixture, routeManifestBytes)).toBe(true);
    expect(validateBehavioralProbeFixtureForTest(behavioralProbeFixture, `${routeManifestBytes}\n`)).toBe(false);
  });

  it.each([
    ['case id', (fixture: FixtureDocument) => { fixture.cases[0].id = 'changed-case-id'; }],
    ['case kind', (fixture: FixtureDocument) => { fixture.cases[0].kind = 'negative'; }],
    ['case surface', (fixture: FixtureDocument) => { fixture.cases[0].surface = 'edge'; }],
    ['request route', (fixture: FixtureDocument) => { fixture.cases[0].request.path = '/api/changed'; }],
    ['allow decision', (fixture: FixtureDocument) => { fixture.cases[0].expected.decision = 'deny'; }],
    ['requirement id', (fixture: FixtureDocument) => { fixture.evidence_requirements[0] = 'changed_requirement'; }],
    ['manifest path', (fixture: FixtureDocument) => { fixture.route_manifest = 'contracts/changed.md'; }]
  ])('rejects a coordinated %s mutation even when the rest remains internally consistent', (_label, mutate) => {
    const fixture = structuredClone(behavioralProbeFixture) as unknown as FixtureDocument;
    mutate(fixture);
    expect(validateBehavioralProbeFixtureForTest(fixture, routeManifestBytes)).toBe(false);
  });
});

type FixtureDocument = {
  route_manifest: string;
  evidence_requirements: string[];
  cases: Array<{
    id: string;
    kind: string;
    surface: string;
    request: { path: string };
    expected: { decision: string };
  }>;
};

function incompatibleResult() {
  return {
    status: 'blocked',
    state: 'incompatible',
    evidenceState: 'untrusted_or_malformed',
    gateDecision: 'blocked',
    safeState: 'no_success_claim',
    retryPolicy: 'reread_source_state_before_retry',
    compatible: false,
    liveRun: false,
    fixtureValidated: false,
    requiresSourceStateReread: true,
    reason: 'incompatible-evidence'
  } as const;
}
