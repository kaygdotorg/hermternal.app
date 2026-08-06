import { MOCK_FIXTURE_IDS, SUCCESS_FIXTURE } from './fixtures';
import type { MockTransport, MockTransportOptions, MockWorkspaceState } from './types';

export class MockTransportError extends Error {
  readonly code = 'mock-failure';

  constructor(message = 'The deterministic mock reported a failure.') {
    super(message);
    this.name = 'MockTransportError';
  }
}

function abortError(): Error {
  const error = new Error('The deterministic mock request was cancelled.');
  error.name = 'AbortError';
  return error;
}

function wait(delayMs: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    return Promise.reject(abortError());
  }

  if (delayMs === 0) {
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, delayMs);

    function onAbort(): void {
      clearTimeout(timeout);
      reject(abortError());
    }

    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * In-memory fixture transport. It must not grow a fetch call: no-network
 * tests use this boundary to prove that the scaffold cannot contact Hermes,
 * a provider, an auth endpoint, or any other live service.
 */
export function createMockTransport(options: MockTransportOptions = {}): MockTransport {
  const delayMs = Math.max(0, options.delayMs ?? 0);
  const scenario = options.scenario ?? 'success';

  return {
    async getWorkspace(signal?: AbortSignal): Promise<MockWorkspaceState> {
      await wait(delayMs, signal);

      if (scenario === 'failure') {
        throw new MockTransportError();
      }

      if (scenario === 'empty') {
        return {
          status: 'empty',
          fixtureId: MOCK_FIXTURE_IDS.empty
        };
      }

      return {
        status: 'success',
        ...SUCCESS_FIXTURE
      };
    }
  };
}
