import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import { authStateForProviderKind } from '$lib/auth-ui/types';
import PreviewPage from './+page.svelte';

describe('ui preview route', () => {
  it('provides the seven Authentication families and runtime selectors', async () => {
    render(PreviewPage);

    const runtimeSelect = screen.getByRole('combobox', { name: 'Runtime state' });
    const authSelect = screen.getByRole('combobox', { name: 'Authentication state' });
    expect(screen.getByRole('heading', { name: 'Runtime and authentication states' })).toBeInTheDocument();
    expect(Array.from(authSelect.querySelectorAll('option')).map((option) => option.value)).toEqual([
      'provider-selection',
      'password',
      'password-submitting',
      'callback',
      'failure',
      'session-expired',
      'discovery-pending',
      'discovery-retry',
      'discovery-empty',
      'discovery-malformed',
      'discovery-aborted',
      'provider-unavailable'
    ]);

    fireEvent.change(runtimeSelect, { target: { value: 'offline' } });
    fireEvent.change(authSelect, { target: { value: 'failure' } });

    await waitFor(() => {
      expect(screen.getByTestId('runtime-preview')).toHaveAttribute('data-state', 'offline');
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'failure');
    });
  });

  it.each([undefined, null, '', 'device-code', 'oauth-v2'])('fails closed for an unknown provider kind: %s', (providerKind) => {
    expect(authStateForProviderKind(providerKind)).toBe('provider-unavailable');
  });

  it('routes provider choices with one credential-free action and exact provider labels', async () => {
    render(PreviewPage);

    const oauth = screen.getByRole('button', { name: 'Continue with Nous' });
    fireEvent.pointerDown(oauth, { button: 0, pointerType: 'mouse' });
    fireEvent.click(oauth, { detail: 1 });
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'callback'));
    expect(screen.getByText('choose-provider', { exact: true })).toHaveAttribute('data-auth-action-count', '1');

    await fireEvent.click(screen.getByRole('button', { name: 'Cancel and return to providers' }));
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection'));

    await fireEvent.click(screen.getByRole('button', { name: 'Hermes password' }));
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'password'));
    expect(screen.getByRole('form', { name: 'Hermes password sign in' })).toBeInTheDocument();
  });

  it('renders both approved compatibility gates from the runtime selector', async () => {
    render(PreviewPage);
    const runtimeSelect = screen.getByRole('combobox', { name: 'Runtime state' });

    await fireEvent.change(runtimeSelect, { target: { value: 'compatibility-check-failed' } });
    expect(await screen.findByRole('heading', { name: 'Compatibility check failed' })).toBeInTheDocument();

    await fireEvent.change(runtimeSelect, { target: { value: 'unsupported-version' } });
    expect(await screen.findByRole('heading', { name: 'Unsupported Hermes revision' })).toBeInTheDocument();
  });

  it('returns to provider selection from callback cancellation and draft discard', async () => {
    render(PreviewPage);

    const authSelect = screen.getByRole('combobox', { name: 'Authentication state' });
    await fireEvent.change(authSelect, { target: { value: 'callback' } });
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'callback'));
    await fireEvent.click(screen.getByRole('button', { name: 'Cancel and return to providers' }));
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection'));

    await fireEvent.change(authSelect, { target: { value: 'session-expired' } });
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'session-expired'));
    const authNote = screen.getByText(/draft retained locally/, { selector: 'p[data-auth-action-count]' });
    expect(authNote).toHaveAttribute('data-draft-state', 'retained');
    expect(screen.getByText(/fixture keeps a bounded local draft in memory/)).toBeInTheDocument();

    await fireEvent.click(screen.getByRole('button', { name: 'Sign in again' }));
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection'));
    expect(screen.getByText(/sign-in-again/)).toHaveAttribute('data-draft-state', 'retained');

    await fireEvent.change(authSelect, { target: { value: 'session-expired' } });
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'session-expired'));
    await fireEvent.click(screen.getByRole('button', { name: 'Discard draft' }));
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection'));
    expect(screen.getByText('discard-draft')).toHaveAttribute('data-draft-state', 'empty');
  });

  it('resolves fixture provider-discovery retry directly to provider selection', async () => {
    render(PreviewPage);

    const authSelect = screen.getByRole('combobox', { name: 'Authentication state' });
    await fireEvent.change(authSelect, { target: { value: 'discovery-retry' } });
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'discovery-retry'));

    await fireEvent.click(screen.getByRole('button', { name: 'Retry discovery' }));

    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection'));
    expect(screen.getByRole('button', { name: 'Continue with Nous' })).toBeInTheDocument();
  });

  it('clears the in-memory draft at explicit fixture success and logout boundaries', async () => {
    render(PreviewPage);

    const authSelect = screen.getByRole('combobox', { name: 'Authentication state' });
    const runtimeSelect = screen.getByRole('combobox', { name: 'Runtime state' });
    await fireEvent.change(authSelect, { target: { value: 'session-expired' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in again' }));
    expect(screen.getByText(/sign-in-again/)).toHaveAttribute('data-draft-state', 'retained');

    await fireEvent.change(runtimeSelect, { target: { value: 'ready' } });
    const editor = screen.getByRole('textbox', { name: 'Message Hermes' });
    expect(editor).toHaveValue('A pending fixture draft for the current Hermes conversation.');
    await fireEvent.click(screen.getByRole('button', { name: 'Add an attachment' }));
    expect(screen.getByText(/sign-in-again/)).toHaveAttribute('data-draft-attachment-count', '1');
    await fireEvent.input(editor, { target: { value: 'send the current fixture draft' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Send message' }));
    expect(screen.getByText(/sign-in-again/)).toHaveAttribute('data-draft-state', 'empty');

    await fireEvent.change(authSelect, { target: { value: 'session-expired' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Sign in again' }));
    await fireEvent.change(runtimeSelect, { target: { value: 'permanent-error' } });
    await fireEvent.click(screen.getByRole('button', { name: 'Back to sessions' }));
    expect(screen.getByText('sign-in-again')).toHaveAttribute('data-draft-state', 'empty');
  });

  it('switches both preview surfaces to the explicit dark appearance', async () => {
    render(PreviewPage);

    fireEvent.change(screen.getByRole('combobox', { name: 'Appearance' }), { target: { value: 'dark' } });

    await waitFor(() => {
      expect(screen.getByTestId('runtime-preview')).toHaveAttribute('data-appearance', 'dark');
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-appearance', 'dark');
    });
  });

  it('fails closed when live discovery is requested without the explicit build gate', async () => {
    const originalPath = `${window.location.pathname}${window.location.search}`;
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    window.history.pushState({}, '', '/ui-preview?authDiscovery=live');

    render(PreviewPage);

    await waitFor(() => {
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-discovery-mode', 'live');
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-unavailable');
    });
    const liveStateOutput = screen.getByRole('combobox', { name: 'Authentication state' });
    expect(liveStateOutput).toBeDisabled();
    expect(screen.getByText('live-discovery-disabled')).toBeInTheDocument();

    fireEvent.change(liveStateOutput, { target: { value: 'provider-selection' } });
    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-unavailable');

    await fireEvent.click(screen.getByRole('button', { name: 'Retry discovery' }));

    expect(fetchSpy).not.toHaveBeenCalled();
    expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-unavailable');
    expect(screen.getByText('live-discovery-disabled')).toBeInTheDocument();

    fetchSpy.mockRestore();
    window.history.replaceState({}, '', originalPath);
  });
});
