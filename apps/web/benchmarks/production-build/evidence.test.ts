import { describe, expect, test } from 'bun:test';
import { resolve } from 'node:path';

const evidencePath = resolve(import.meta.dir, 'evidence/benchmark-evidence.json');
const validatorPath = resolve(import.meta.dir, '../../../../contracts/benchmarks/validate.py');

function validate(optimized: boolean): { exitCode: number; stdout: string; stderr: string } {
  const command = ['python3', ...(optimized ? ['-O'] : []), validatorPath, '--evidence', evidencePath, '--skip-baseline'];
  const result = Bun.spawnSync(command, { stdout: 'pipe', stderr: 'pipe' });
  return {
    exitCode: result.exitCode,
    stdout: new TextDecoder().decode(result.stdout),
    stderr: new TextDecoder().decode(result.stderr)
  };
}

describe('checked-in production-build evidence', () => {
  for (const optimized of [false, true]) {
    test(`passes the canonical B-01 validator${optimized ? ' under python -O' : ''}`, () => {
      const result = validate(optimized);
      expect(result.exitCode).toBe(0);
      expect(result.stderr).toBe('');
      expect(JSON.parse(result.stdout)).toEqual({
        ok: true,
        schema: 'hermternal.benchmark-evidence.v1',
        evidence_id: 'web-production-build-baseline',
        run_count: 2,
        baseline_checked: false
      });
    });
  }
});
