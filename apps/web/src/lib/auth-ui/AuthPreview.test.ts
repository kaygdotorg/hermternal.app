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
    expect(screen.getByText('Synthetic fixture only · provider choices are local presentation data; no discovery request is made.')).toBeInTheDocument();
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

  it('fails closed for live pending discovery and never renders fixture providers', () => {
    render(AuthPreview, { state: 'discovery-pending', discoveryMode: 'live', providers: DEFAULT_PROVIDERS });

    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-discovery-mode', 'live');
    expect(screen.getByText('Waiting for the configured Hermes deployment to report provider capabilities. No fallback is guessed.')).toBeInTheDocument();
    expect(screen.getByText('Live discovery · no provider action until the list is valid.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Checking provider manifest, loading' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Validating provider entries, loading' })).toBeDisabled();
    expect(screen.getByText('Loading · no sign-in action yet', { selector: '.pill-description' })).toBeInTheDocument();
    expect(screen.getByText('Waiting for a complete response', { selector: '.pill-description' })).toBeInTheDocument();
    expect(screen.getByText('Provider manifest', { selector: '.mobile-label' })).toBeInTheDocument();
    expect(screen.getByText('Provider entries', { selector: '.mobile-label' })).toBeInTheDocument();
    expect(screen.getByText('Loading · no sign-in action yet', { selector: '.mobile-description' })).toBeInTheDocument();
    expect(screen.getByText('Waiting for a complete response', { selector: '.mobile-description' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Nous/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Hermes password/ })).not.toBeInTheDocument();
    expect(screen.getByText('Live discovery · provider discovery is pending; controls stay unavailable until a valid list arrives.')).toBeInTheDocument();
  });

  it('keeps live source labels distinct from fixture copy', async () => {
    const view = render(AuthPreview, { state: 'provider-selection', discoveryMode: 'live' });
    expect(screen.getByText('Connected to the configured HTTPS origin. Only providers reported by Hermes are shown.')).toBeInTheDocument();
    expect(screen.queryByText(/Synthetic fixture only/)).not.toBeInTheDocument();

    await view.rerender({ state: 'discovery-malformed' });
    expect(screen.getByText('Live boundary · malformed response · no credentials')).toBeInTheDocument();
    expect(screen.queryByText(/Mocked fixture/)).not.toBeInTheDocument();
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
      ['callback', 'Completing sign-in', 'Static callback state only. No provider response is read and no browser session is created.'],
      ['failure', 'Sign-in did not complete', 'Static failure state only. No session was created'],
      ['session-expired', 'Session expired', 'This fixture keeps a bounded local draft in memory'],
      ['discovery-pending', 'Discovering sign-in methods', 'No fallback is guessed.']
    ] as const) {
      await view.rerender({ state, passwordSubmitting: false });
      expect(screen.getByRole('heading', { name: heading })).toBeInTheDocument();
      expect(screen.getAllByText(new RegExp(text)).length).toBeGreaterThanOrEqual(1);
      await waitFor(() => expect(screen.getByRole('heading', { name: heading })).toHaveFocus());
    }
  });

  it('keeps live callback and failure copy tied to the live boundary', async () => {
    const view = render(AuthPreview, {
      state: 'callback',
      discoveryMode: 'live',
      failureCode: 'network',
      failureMessage: 'Authentication is unavailable.'
    });

    expect(screen.getByText('Checking the provider response and creating a protected browser session.')).toBeInTheDocument();
    expect(screen.getByText('Do not close this tab. Callback parameters are checked once and are never shown in the interface.')).toBeInTheDocument();

    await view.rerender({ state: 'failure', discoveryMode: 'live' });
    expect(screen.getByText('Authentication is unavailable.')).toBeInTheDocument();
    expect(screen.getByText('network')).toBeInTheDocument();
    expect(screen.queryByText(/Static failure state only/)).not.toBeInTheDocument();
  });

  it('renders distinct recovery copy for every discovery leaf', async () => {
    const view = render(AuthPreview, { state: 'discovery-retry' });
    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'discovery-retry');
    expect(screen.getByRole('heading', { name: 'Retry provider discovery' })).toBeInTheDocument();
    expect(screen.getByText('The previous result was unknown. A fresh user action is required before another lookup.')).toBeInTheDocument();
    expect(screen.getByText('Ready to retry provider discovery')).toBeInTheDocument();
    expect(screen.getByText('Retry is idempotent; duplicate submits stay blocked until the result returns.')).toBeInTheDocument();

    for (const outcome of [
      {
        state: 'discovery-empty',
        heading: 'No sign-in methods available',
        copy: 'A successful empty provider registry is outside the pinned response contract. The preview fails closed and exposes no invented provider.',
        detail: 'invalid_empty_provider_registry',
        detailCopy: 'Retry discovery after Hermes reports the reviewed provider registry or exact unavailable response.',
        metadata: 'Mocked fixture · empty registry · no credentials'
      },
      {
        state: 'discovery-malformed',
        heading: 'Provider discovery returned incompatible data',
        copy: 'The provider response did not match the reviewed schema. The preview fails closed and exposes no invented sign-in method.',
        detail: 'invalid_response',
        detailCopy: 'Unknown fields are ignored only after bounded strict parsing; malformed or unsafe data is rejected.',
        metadata: 'Mocked fixture · malformed response · no credentials'
      },
      {
        state: 'discovery-aborted',
        heading: 'Provider discovery was cancelled',
        copy: 'The provider discovery request was cancelled before a usable registry was received. No provider action is available.',
        detail: 'aborted',
        detailCopy: 'Cancellation leaves no provider list and does not expose response data.',
        metadata: 'Mocked fixture · cancelled · no credentials'
      },
      {
        state: 'provider-unavailable',
        heading: 'Provider discovery stopped',
        copy: 'No usable provider list was returned. The client fails closed and does not invent a fallback.',
        detail: 'provider_unavailable',
        detailCopy: 'The endpoint did not provide a usable provider registry. No fallback provider is invented.',
        metadata: 'Mocked fixture · provider unavailable · no credentials'
      }
    ] as const) {
      await view.rerender({ state: outcome.state });
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', outcome.state);
      expect(screen.getByRole('heading', { name: outcome.heading })).toBeInTheDocument();
      expect(screen.getByText(outcome.copy, { exact: true })).toBeInTheDocument();
      expect(screen.getByText(outcome.detail, { exact: true })).toBeInTheDocument();
      expect(screen.getByText(outcome.detailCopy, { exact: true })).toBeInTheDocument();
      expect(screen.getByText(outcome.metadata, { exact: true })).toBeInTheDocument();
    }
  });

  it('shows exact retained-draft session expiry actions', () => {
    const onAction = vi.fn();
    render(AuthPreview, { state: 'session-expired', onAction });

    expect(screen.getByText('Sign in again to continue. This fixture keeps a bounded local draft in memory until authentication completes.')).toBeInTheDocument();
    expect(screen.getByText('Mocked session gate · draft retained locally. No prompt was sent after the session expired.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Sign in again' }));
    expect(onAction).toHaveBeenCalledWith({ type: 'sign-in-again' });
    fireEvent.click(screen.getByRole('button', { name: 'Discard draft' }));
    expect(onAction).toHaveBeenCalledWith({ type: 'discard-draft' });
  });
});
