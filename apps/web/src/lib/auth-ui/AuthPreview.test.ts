import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import AuthPreview from './AuthPreview.svelte';
import { DEFAULT_PROVIDERS } from './fixtures';

const APPROVED_PARENT = 'd88cd9adfcef94980ae674f40d99c65e1cf9b666';

function parentAuthPreviewSource(): string {
  return execFileSync(
    'git',
    ['show', `${APPROVED_PARENT}:apps/web/src/lib/auth-ui/AuthPreview.svelte`],
    { cwd: resolve(process.cwd(), '../..'), encoding: 'utf8' }
  );
}

describe('AuthPreview', () => {
  it('renders the approved provider actions, descriptions, footer, and no search controls', () => {
    render(AuthPreview, { state: 'provider-selection' });

    expect(screen.getByRole('heading', { name: 'Connect to Hermes' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Continue with Nous' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Hermes password' })).toBeInTheDocument();
    expect(screen.getByText('OAuth · opens the provider')).toBeInTheDocument();
    expect(screen.getByText('Username and password supported')).toBeInTheDocument();
    expect(screen.getByText(/Only providers reported by Hermes are shown/)).toBeInTheDocument();
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
    expect(screen.queryByText(/deep link/i)).not.toBeInTheDocument();
  });

  it('proves the exact approved parent lacked the corrected Paper contract', () => {
    const parent = parentAuthPreviewSource();

    // These are the parent implementation's old strings. If the manifest head
    // is silently moved, this evidence test fails instead of becoming a generic
    // assertion that only checks the new branch's rendered output.
    expect(parent).toContain('Choose one synthetic sign-in method.');
    expect(parent).toContain('Static callback state only. No provider response is read');
    expect(parent).not.toContain('Checking the provider response and creating a protected browser session.');

    render(AuthPreview, { state: 'provider-selection' });
    expect(screen.getByRole('button', { name: 'Continue with Nous' })).toBeInTheDocument();
    expect(screen.getByText('OAuth · opens the provider')).toBeInTheDocument();
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
    expect(screen.getByRole('alert')).toHaveTextContent('Provider discovery stopped');
    expect(screen.queryByRole('button', { name: 'Continue with Nous' })).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Provider discovery stopped' })).toHaveFocus());
  });

  it('renders every mocked capability, including an unavailable provider row', () => {
    render(AuthPreview, {
      state: 'provider-selection',
      providers: [
        ...DEFAULT_PROVIDERS,
        {
          id: 'provider-neutral',
          name: 'Provider Neutral',
          monogram: 'P',
          kind: 'unavailable',
          description: 'Provider reported without a reviewed browser sign-in capability'
        }
      ]
    });

    const unavailable = screen.getByRole('button', { name: 'Provider Neutral, unavailable' });
    expect(unavailable).toBeDisabled();
    expect(screen.getByText(/without a reviewed browser sign-in capability/i)).toBeInTheDocument();
  });

  it('marks the synthetic password form so password managers do not treat it as reusable credentials', async () => {
    render(AuthPreview, { state: 'password' });

    const form = screen.getByRole('form', { name: 'Hermes password sign in' });
    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    await waitFor(() => expect(form).toHaveAttribute('data-field-ownership', 'ready'));
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
    expect(username).toHaveAttribute('placeholder', 'Enter username');
    expect(password).toHaveAttribute('placeholder', 'Enter password');
    expect(screen.getByRole('button', { name: 'Sign in' })).toHaveAttribute('type', 'reset');
  });

  it('fences live fields until hydration owns focus and keeps live autocomplete semantics', async () => {
    render(AuthPreview, { discoveryMode: 'live', state: 'password' });

    const form = screen.getByRole('form', { name: 'Hermes password sign in' });
    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    expect(form).toHaveAttribute('data-field-ownership', 'pending');
    expect(username).toHaveAttribute('readonly');
    expect(password).toHaveAttribute('readonly');
    expect(username).toHaveAttribute('autocomplete', 'username');
    expect(password).toHaveAttribute('autocomplete', 'current-password');
    expect(username).toHaveAttribute('name', 'username');
    expect(password).toHaveAttribute('name', 'password');
    await waitFor(() => expect(form).toHaveAttribute('data-field-ownership', 'ready'));
    expect(username).not.toHaveAttribute('readonly');
    expect(username).toHaveFocus();
  });

  it('clears credentials synchronously before one fixture pointer action', async () => {
    const onAction = vi.fn();
    render(AuthPreview, { state: 'password', onAction });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));

    const username = screen.getByLabelText('Username');
    const password = screen.getByLabelText('Password');
    const signIn = screen.getByRole('button', { name: 'Sign in' });
    fireEvent.input(username, { target: { value: 'fixture-user' } });
    fireEvent.input(password, { target: { value: 'fixture-password' } });
    fireEvent.pointerDown(signIn, { button: 0, pointerType: 'mouse' });

    expect(username).toHaveValue('');
    expect(password).toHaveValue('');
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction).toHaveBeenCalledWith({ type: 'submit-password-fixture' });
    expect(JSON.stringify(onAction.mock.calls)).not.toContain('fixture-password');

    fireEvent.pointerUp(signIn, { button: 0, pointerType: 'mouse' });
    fireEvent.click(signIn, { detail: 1 });
    expect(onAction).toHaveBeenCalledTimes(1);
  });

  it('passes live credentials only to the transient callback and clears the form', async () => {
    const onAction = vi.fn();
    const onPasswordSubmit = vi.fn();
    render(AuthPreview, { discoveryMode: 'live', state: 'password', onAction, onPasswordSubmit });
    await waitFor(() => expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('data-field-ownership', 'ready'));

    fireEvent.input(screen.getByLabelText('Username'), { target: { value: 'synthetic-user' } });
    fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'transient-password' } });
    fireEvent.submit(screen.getByRole('form', { name: 'Hermes password sign in' }));

    expect(onPasswordSubmit).toHaveBeenCalledWith({ username: 'synthetic-user', password: 'transient-password' });
    expect(onAction).not.toHaveBeenCalledWith({ type: 'submit-password-fixture' });
    expect(JSON.stringify(onAction.mock.calls)).not.toContain('transient-password');
    await waitFor(() => expect(screen.getByLabelText('Password')).toHaveValue(''));
  });

  it('renders the seven families and password submitting as an interaction prop', async () => {
    const view = render(AuthPreview, { state: 'provider-selection' });

    await view.rerender({ state: 'password' });
    await waitFor(() => expect(screen.getByLabelText('Username')).toHaveFocus());

    await view.rerender({ state: 'password', passwordSubmitting: true });
    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password');
    expect(screen.getByRole('status')).toHaveTextContent('Signing in to Hermes');
    expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toHaveAttribute('aria-busy', 'true');
    expect(screen.getByLabelText('Username')).toHaveAttribute('placeholder', 'Cleared');
    await waitFor(() => expect(screen.getByRole('heading', { name: 'Signing in to Hermes' })).toHaveFocus());

    for (const [state, heading, text] of [
      ['callback', 'Completing sign-in', 'Checking the provider response and creating a protected browser session.'],
      ['failure', 'Sign-in did not complete', 'Hermes rejected this attempt. No session was created'],
      ['session-expired', 'Session expired', 'Your draft stays on this device'],
      ['discovery-pending', 'Discovering sign-in methods', 'No fallback is guessed.']
    ] as const) {
      await view.rerender({ state, passwordSubmitting: false });
      expect(screen.getByRole('heading', { name: heading })).toBeInTheDocument();
      expect(screen.getAllByText(new RegExp(text)).length).toBeGreaterThanOrEqual(1);
      await waitFor(() => expect(screen.getByRole('heading', { name: heading })).toHaveFocus());
    }
  });

  it('renders retry and unavailable discovery outcomes inside one discovery family', async () => {
    const view = render(AuthPreview, { state: 'discovery-retry' });
    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'discovery-retry');
    expect(screen.getByRole('heading', { name: 'Retry provider discovery' })).toBeInTheDocument();
    expect(screen.getByText('The previous result was unknown. A fresh user action is required before another lookup.')).toBeInTheDocument();

    for (const state of ['discovery-empty', 'discovery-malformed', 'discovery-aborted', 'provider-unavailable'] as const) {
      await view.rerender({ state });
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', state);
      expect(screen.getByRole('heading', { name: 'Provider discovery stopped' })).toBeInTheDocument();
      expect(screen.getByText('No usable provider list was returned. The client fails closed and does not invent a fallback.')).toBeInTheDocument();
      expect(screen.getByText('Empty or malformed provider data was rejected before sign-in choices were shown.')).toBeInTheDocument();
    }
  });

  it('shows exact retained-draft session expiry actions', () => {
    const onAction = vi.fn();
    render(AuthPreview, { state: 'session-expired', onAction });

    expect(screen.getByText('Sign in again to continue. Your draft stays on this device until authentication completes.')).toBeInTheDocument();
    expect(screen.getByText('Mocked session gate · draft retained locally. No prompt was sent after the session expired.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Sign in again' }));
    expect(onAction).toHaveBeenCalledWith({ type: 'sign-in-again' });
    fireEvent.click(screen.getByRole('button', { name: 'Discard draft' }));
    expect(onAction).toHaveBeenCalledWith({ type: 'discard-draft' });
  });
});
