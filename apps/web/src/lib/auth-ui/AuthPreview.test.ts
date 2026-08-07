import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import AuthPreview from './AuthPreview.svelte';
import { DEFAULT_PROVIDERS } from './fixtures';

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

  it.each([
    ['empty', []],
    ['duplicate IDs', [DEFAULT_PROVIDERS[0], { ...DEFAULT_PROVIDERS[1], id: DEFAULT_PROVIDERS[0].id }]],
    ['missing kind', [{ ...DEFAULT_PROVIDERS[0], kind: undefined }]],
    ['future kind', [{ ...DEFAULT_PROVIDERS[0], kind: 'device-code' }]],
    ['malformed entry', [null]]
  ])('fails closed when provider fixtures contain %s', async (_label, providers) => {
    render(AuthPreview, { state: 'provider-selection', providers: providers as never });

    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-unavailable');
    expect(screen.getByRole('alert')).toHaveTextContent('No sign-in method is available');
    expect(screen.queryByRole('button', { name: 'Nous' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Hermes password' })).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Provider discovery stopped' })).toHaveFocus());
  });

  it('marks the synthetic password form so password managers do not treat it as reusable credentials', () => {
    render(AuthPreview, { state: 'password' });

    const form = screen.getByRole('form', { name: 'Hermes password sign in' });
    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    expect(form).toHaveAttribute('autocomplete', 'off');
    expect(form).toHaveAttribute('data-form-type', 'other');
    expect(form).toHaveAttribute('method', 'dialog');
    for (const field of [username, password]) {
      expect(field).toHaveAttribute('autocomplete', 'off');
      expect(field).toHaveAttribute('data-1p-ignore');
      expect(field).toHaveAttribute('data-lpignore', 'true');
      expect(field).not.toHaveAttribute('name');
      expect(field).toHaveAttribute('data-fixture-field');
    }
    expect(username).toHaveValue('');
    expect(username).toHaveAttribute('placeholder', 'Enter username');
    expect(password).toHaveAttribute('placeholder', 'Enter password');
    expect(screen.getByRole('button', { name: 'Sign in' })).toHaveAttribute('type', 'reset');
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

  it('moves focus to each entered task and exposes state-specific live semantics', async () => {
    const view = render(AuthPreview, { state: 'provider-selection' });

    await view.rerender({ state: 'password' });
    await waitFor(() => expect(screen.getByLabelText('Username')).toHaveFocus());

    await view.rerender({ state: 'password-submitting' });
    const submitting = screen.getByRole('status');
    expect(submitting).toHaveAttribute('aria-live', 'polite');
    expect(submitting).toHaveAttribute('aria-atomic', 'true');
    expect(submitting).toHaveTextContent('Signing in');
    expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByLabelText('Username')).toHaveAttribute('placeholder', 'Cleared');
    expect(screen.getByLabelText('Password')).toHaveAttribute('placeholder', 'Cleared');
    expect(screen.getByText('Hidden')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Signing in to Hermes' })).toHaveFocus());

    await view.rerender({ state: 'failure' });
    const failure = screen.getByRole('alert');
    expect(failure).toHaveAttribute('aria-live', 'assertive');
    expect(failure).toHaveTextContent('Sign-in did not complete');
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Sign-in did not complete' })).toHaveFocus());

    await view.rerender({ state: 'session-expired' });
    expect(screen.getByRole('alert')).toHaveTextContent('Session expired');
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Session expired' })).toHaveFocus());

    await view.rerender({ state: 'discovery-retry' });
    expect(screen.getByRole('status')).toHaveTextContent('Provider discovery can be retried');
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Retry provider discovery' })).toHaveFocus());
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
