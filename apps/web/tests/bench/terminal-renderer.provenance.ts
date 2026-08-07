const FULL_COMMIT_SHA = /^[0-9a-f]{40}$/iu;

/** Validate the explicit source revision required for a reproducible trace. */
export function validateFullCommit(value: string | undefined): string {
  const commit = value?.trim() ?? '';
  if (!FULL_COMMIT_SHA.test(commit)) {
    throw new Error('GIT_COMMIT must be an explicit 40-character commit SHA');
  }
  return commit.toLowerCase();
}

/** Keep the trace tied to the checkout that supplied its execution inputs. */
export function assertCommitMatchesHead(commit: string, head: string): void {
  if (commit.toLowerCase() !== head.trim().toLowerCase()) {
    throw new Error(`GIT_COMMIT ${commit} does not match checkout HEAD ${head.trim()}`);
  }
}

/** Refuse evidence from a dirty renderer or benchmark harness checkout. */
export function assertCleanExecutionInputs(status: string): void {
  const dirty = status.trim();
  if (dirty) {
    throw new Error(`execution-critical benchmark inputs are dirty:\n${dirty}`);
  }
}
