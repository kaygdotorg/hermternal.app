import { fireEvent, render, screen } from '@testing-library/svelte';
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
  });

  it('submits synthetic password values through the typed action boundary', () => {
    const onAction = vi.fn();
    render(AuthPreview, { state: 'password', onAction });

    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    fireEvent.input(username, { target: { value: 'sam' } });
    fireEvent.input(password, { target: { value: 'not-a-secret-fixture' } });
    fireEvent.submit(screen.getByRole('form', { name: 'Hermes password sign in' }));

    expect(onAction).toHaveBeenCalledWith({
      type: 'submit-password',
      username: 'sam',
      password: 'not-a-secret-fixture'
    });
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
});
