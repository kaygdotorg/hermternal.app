import { formatLiveProofFailureStatus, readLiveProofStatus } from './live-proof-status.mjs';

const FAILURE_STATUSES = new Set(['failed', 'timedOut', 'interrupted']);

/**
 * A deliberately minimal reporter for the credential-bearing live lane. The
 * standard Playwright reporters can print locator call logs and DOM snippets;
 * this reporter emits only the fixed proof phase and delivery projection on a
 * failure. Unknown annotations degrade to the fixed uncertain state without
 * forwarding any diagnostic text.
 */
export default class SafeLiveReporter {
  onTestEnd(_test, result) {
    if (!FAILURE_STATUSES.has(result.status)) return;
    let status;
    try {
      status = readLiveProofStatus(result.annotations);
    } catch {
      status = { phase: 'uncertain', delivery: 'uncertain' };
    }
    console.log(formatLiveProofFailureStatus(status));
  }

  onEnd(result) {
    console.log(`live proof\t${result.status}`);
  }
}
