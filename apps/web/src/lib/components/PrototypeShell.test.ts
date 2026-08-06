import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import PrototypeShell from './PrototypeShell.svelte';
import { MOCK_FIXTURE_IDS, createMockTransport } from '$lib/transport';
import type { MockTransport, MockWorkspaceState } from '$lib/transport';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function successState(fixtureId: string): MockWorkspaceState {
  return {
    status: 'success',
    fixtureId,
    workspaceLabel: 'Synthetic workspace',
    detail: 'No provider, account, credential, or live session state is loaded.'
  };
}

describe('PrototypeShell', () => {
  it('labels the screen as a prototype and renders success evidence', async () => {
    render(PrototypeShell, { transport: createMockTransport() });

    expect(screen.getByTestId('prototype-label')).toHaveTextContent('Prototype only');
    await waitFor(() => expect(screen.getByTestId('status-success')).toBeInTheDocument());
    expect(screen.getByTestId('fixture-id')).toHaveTextContent(MOCK_FIXTURE_IDS.success);
  });

  it('exposes an empty fixture state without inventing a result', async () => {
    render(PrototypeShell, { transport: createMockTransport({ scenario: 'empty' }) });

    await waitFor(() => expect(screen.getByTestId('status-empty')).toBeInTheDocument());
    expect(screen.getByTestId('fixture-id')).toHaveTextContent(MOCK_FIXTURE_IDS.empty);
  });

  it('renders a failure state with a deterministic failure identity', async () => {
    render(PrototypeShell, { transport: createMockTransport({ scenario: 'failure' }) });

    await waitFor(() => expect(screen.getByTestId('status-failure')).toBeInTheDocument());
    expect(screen.getByTestId('fixture-id')).toHaveTextContent(MOCK_FIXTURE_IDS.failure);
    expect(screen.getByRole('button', { name: 'Re-run mock check' })).toBeEnabled();
  });

  it('transitions pending to cancelled and then retries safely', async () => {
    const first = deferred<MockWorkspaceState>();
    const second = deferred<MockWorkspaceState>();
    const signals: AbortSignal[] = [];
    let callNumber = 0;
    const transport: MockTransport = {
      getWorkspace(signal) {
        signals.push(signal as AbortSignal);
        callNumber += 1;
        return callNumber === 1 ? first.promise : second.promise;
      }
    };

    render(PrototypeShell, { transport });
    await waitFor(() => expect(screen.getByTestId('status-pending')).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel mock check' }));

    expect(signals[0]?.aborted).toBe(true);
    expect(screen.getByTestId('status-cancelled')).toBeInTheDocument();
    expect(screen.getByTestId('fixture-id')).toHaveTextContent(MOCK_FIXTURE_IDS.cancelled);

    await fireEvent.click(screen.getByRole('button', { name: 'Retry mock check' }));
    expect(screen.getByTestId('status-pending')).toBeInTheDocument();
    second.resolve(successState(MOCK_FIXTURE_IDS.success));
    await waitFor(() => expect(screen.getByTestId('status-success')).toBeInTheDocument());
  });

  it('aborts a pending request on retry and suppresses stale completion', async () => {
    const first = deferred<MockWorkspaceState>();
    const second = deferred<MockWorkspaceState>();
    const signals: AbortSignal[] = [];
    let callNumber = 0;
    const transport: MockTransport = {
      getWorkspace(signal) {
        signals.push(signal as AbortSignal);
        callNumber += 1;
        return callNumber === 1 ? first.promise : second.promise;
      }
    };

    render(PrototypeShell, { transport });
    await waitFor(() => expect(screen.getByTestId('status-pending')).toBeInTheDocument());
    await fireEvent.click(screen.getByRole('button', { name: 'Re-run mock check' }));

    expect(signals[0]?.aborted).toBe(true);
    expect(screen.getByTestId('status-pending')).toBeInTheDocument();
    first.resolve(successState('w01-stale-v1'));
    await Promise.resolve();
    expect(screen.getByTestId('status-pending')).toBeInTheDocument();

    second.resolve(successState('w01-current-v1'));
    await waitFor(() => expect(screen.getByTestId('fixture-id')).toHaveTextContent('w01-current-v1'));
  });

  it('aborts work on unmount and suppresses a late completion', async () => {
    const pending = deferred<MockWorkspaceState>();
    let signal: AbortSignal | undefined;
    const transport: MockTransport = {
      getWorkspace(nextSignal) {
        signal = nextSignal;
        return pending.promise;
      }
    };
    const { unmount } = render(PrototypeShell, { transport });

    await waitFor(() => expect(screen.getByTestId('status-pending')).toBeInTheDocument());
    unmount();
    expect(signal?.aborted).toBe(true);

    pending.resolve(successState('w01-after-unmount-v1'));
    await Promise.resolve();
    expect(screen.queryByTestId('status-success')).not.toBeInTheDocument();
  });

  it('keeps retry available after an unknown failure', async () => {
    const transport: MockTransport = {
      getWorkspace: vi.fn(async () => {
        throw new Error('unknown mock failure');
      })
    };

    render(PrototypeShell, { transport });
    await waitFor(() => expect(screen.getByTestId('status-failure')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: 'Re-run mock check' })).toBeEnabled();
  });
});
