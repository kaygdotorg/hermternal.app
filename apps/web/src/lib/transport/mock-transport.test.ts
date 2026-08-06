import { describe, expect, it, vi } from 'vitest';
import { MOCK_FIXTURE_IDS } from './fixtures';
import { MockTransportError, createMockTransport } from './mock-transport';

describe('createMockTransport', () => {
  it('returns the deterministic success fixture without using fetch', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    await expect(createMockTransport().getWorkspace()).resolves.toEqual({
      status: 'success',
      fixtureId: MOCK_FIXTURE_IDS.success,
      workspaceLabel: 'Synthetic workspace',
      detail: 'No provider, account, credential, or live session state is loaded.'
    });
    expect(fetchMock).not.toHaveBeenCalled();

    vi.unstubAllGlobals();
  });

  it('keeps an empty fixture explicit', async () => {
    await expect(createMockTransport({ scenario: 'empty' }).getWorkspace()).resolves.toEqual({
      status: 'empty',
      fixtureId: MOCK_FIXTURE_IDS.empty
    });
  });

  it('fails closed with a typed mock error', async () => {
    await expect(createMockTransport({ scenario: 'failure' }).getWorkspace()).rejects.toBeInstanceOf(
      MockTransportError
    );
  });

  it('cancels delayed work without producing a result', async () => {
    const controller = new AbortController();
    const request = createMockTransport({ delayMs: 20 }).getWorkspace(controller.signal);

    controller.abort();

    await expect(request).rejects.toMatchObject({ name: 'AbortError' });
  });
});
