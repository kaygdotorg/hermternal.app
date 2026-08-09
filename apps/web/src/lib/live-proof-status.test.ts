import { describe, expect, it } from 'vitest';
import {
  LIVE_PROOF_DELIVERY_ANNOTATION,
  LIVE_PROOF_PHASE_ANNOTATION,
  assertLiveProofStatus,
  formatLiveProofFailureStatus,
  readLiveProofStatus,
  setLiveProofStatus
} from '../../tests/live/live-proof-status.mjs';

describe('live proof reporter status channel', () => {
  it('updates the fixed phase and delivery projection before and after submission', () => {
    const testInfo = { annotations: [] as Array<Record<string, unknown>> };

    setLiveProofStatus(testInfo, { phase: 'ready-no-submit', delivery: 'not-submitted' });
    expect(readLiveProofStatus(testInfo.annotations)).toEqual({
      phase: 'ready-no-submit',
      delivery: 'not-submitted'
    });

    setLiveProofStatus(testInfo, { phase: 'submitted', delivery: 'submitted' });
    expect(readLiveProofStatus(testInfo.annotations)).toEqual({
      phase: 'submitted',
      delivery: 'submitted'
    });
    expect(testInfo.annotations).toHaveLength(2);
  });

  it('rejects arbitrary phases, delivery values, extra status fields, and duplicates', () => {
    expect(() => assertLiveProofStatus({ phase: 'free-form', delivery: 'submitted' })).toThrow(
      'not allowlisted'
    );
    expect(() => assertLiveProofStatus({ phase: 'submitted', delivery: 'maybe' })).toThrow(
      'not allowlisted'
    );
    expect(() =>
      assertLiveProofStatus(
        { phase: 'submitted', delivery: 'submitted', detail: 'unsafe' } as unknown as {
          phase: string;
          delivery: string;
        }
      )
    ).toThrow('not allowlisted');

    const valid = [
      { type: LIVE_PROOF_PHASE_ANNOTATION, description: 'submitted' },
      { type: LIVE_PROOF_DELIVERY_ANNOTATION, description: 'submitted' }
    ];
    expect(() => readLiveProofStatus([...valid, valid[0]])).toThrow('duplicated');
    expect(() =>
      readLiveProofStatus([
        { type: LIVE_PROOF_PHASE_ANNOTATION, description: 'submitted', extra: 'unsafe' },
        valid[1]
      ])
    ).toThrow('shape is not approved');
    expect(() =>
      readLiveProofStatus([
        { type: LIVE_PROOF_PHASE_ANNOTATION, description: 'free-form' },
        valid[1]
      ])
    ).toThrow('not allowlisted');
  });

  it('formats only the fixed failure projection', () => {
    expect(formatLiveProofFailureStatus({ phase: 'completed', delivery: 'completed' })).toBe(
      'live proof failure\tphase=completed\tdelivery=completed'
    );
  });
});
