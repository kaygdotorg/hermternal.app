import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import AuthPreview from './AuthPreview.svelte';

describe('AuthPreview', () => {
  it('renders provider selection without exposing search or deep-link controls', () => {
    render(AuthPreview, { state: 'provider-selection' });

    expect(screen.getByRole('heading', { name: 'Connect to Hermes' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Nous' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Hermes password' })).toBeInTheDocument();
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
    expect(screen.queryByText(/deep link/i)).not.toBeInTheDocument();
    expect(screen.getByText(/no discovery request is made/i)).toBeInTheDocument();
  });

  it('submits a credential-free fixture action once and resets the form immediately', async () => {
    const onAction = vi.fn();
    render(AuthPreview, { state: 'password', onAction });

    fireEvent.input(screen.getByLabelText('Username'), { target: { value: 'sam' } });
    fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'not-a-secret-fixture' } });
    const form = screen.getByRole('form', { name: 'Hermes password sign in' });
    fireEvent.submit(form);
    fireEvent.submit(form);

    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction).toHaveBeenCalledWith({ type: 'submit-password-fixture' });
    expect(JSON.stringify(onAction.mock.calls)).not.toContain('not-a-secret-fixture');
    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''));
  });

  it('rejects blank credentials and clears the uncontrolled form on cancel and state changes', async () => {
    const onAction = vi.fn();
    const view = render(AuthPreview, { state: 'password', onAction });
    const form = screen.getByRole('form', { name: 'Hermes password sign in' });

    fireEvent.submit(form);
    expect(onAction).not.toHaveBeenCalled();

    fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'temporary-fixture' } });
    fireEvent.click(screen.getByRole('button', { name: 'Back to providers' }));
    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''));

    await view.rerender({ state: 'password' });
    fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'state-change-fixture' } });
    await view.rerender({ state: 'provider-selection' });
    await view.rerender({ state: 'password' });

    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''));
    expect(onAction).toHaveBeenCalledWith({ type: 'back-to-providers' });
    expect(JSON.stringify(onAction.mock.calls)).not.toContain('state-change-fixture');
  });

  it('disables provider controls during discovery and exposes retryable failure actions', () => {
    const pending = render(AuthPreview, { state: 'discovery-pending' });
    expect(screen.getByRole('button', { name: 'Nous, loading' })).toBeDisabled();
    pending.unmount();

    const onAction = vi.fn();
    render(AuthPreview, { state: 'failure', onAction });
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));

    expect(onAction).toHaveBeenCalledWith({ type: 'retry-authentication' });
  });

  it('renders live success, pending, empty, malformed, unavailable, aborted, and retry states truthfully', () => {
    const liveProviders = [
      {
        id: 'codex',
        name: 'Codex',
        monogram: 'C',
        kind: 'oauth' as const,
        description: 'OAuth provider · same-origin browser boundary'
      }
    ];
    const live = render(AuthPreview, {
      discoveryMode: 'live',
      providers: liveProviders,
      state: 'provider-selection'
    });
    expect(screen.getByText(/live same-origin discovery/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Codex' })).toBeInTheDocument();
    live.unmount();

    const pendingAction = vi.fn();
    const pending = render(AuthPreview, { discoveryMode: 'live', state: 'discovery-pending', onAction: pendingAction });
    expect(screen.getByText(/same-origin GET \/api\/auth\/providers request is pending/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Nous, loading' })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel discovery' }));
    expect(pendingAction).toHaveBeenCalledWith({ type: 'cancel-discovery' });
    pending.unmount();

    const states = [
      ['discovery-empty', 'No sign-in methods available'],
      ['discovery-malformed', 'Provider discovery returned incompatible data'],
      ['provider-unavailable', 'Provider discovery stopped'],
      ['discovery-aborted', 'Provider discovery was cancelled'],
      ['discovery-retry', 'Retry provider discovery']
    ] as const;

    for (const [state, heading] of states) {
      const view = render(AuthPreview, { discoveryMode: 'live', state });
      expect(screen.getByRole('heading', { name: heading })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Retry discovery' })).toBeInTheDocument();
      view.unmount();
    }
  });
});
