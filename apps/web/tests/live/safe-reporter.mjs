import { liveCredentialValues, redactLiveText } from './live-artifact-policy.mjs';

/**
 * A deliberately minimal reporter for the credential-bearing live lane. The
 * standard Playwright reporters can print locator call logs and DOM snippets;
 * this reporter emits only safe test names and statuses, never error details.
 */
export default class SafeLiveReporter {
  onTestEnd(test, result) {
    const title = redactLiveText(test.title, liveCredentialValues());
    console.log(`${result.status}\t${title}`);
  }

  onEnd(result) {
    console.log(`live proof\t${result.status}`);
  }
}
