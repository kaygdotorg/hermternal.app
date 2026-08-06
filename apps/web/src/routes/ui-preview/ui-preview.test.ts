import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import { authStateForProviderKind } from '$lib/auth-ui/types';
import PreviewPage from './+page.svelte';

describe('ui preview route', () => {
  it('provides local selectors for runtime and authentication state variants', async () => {
    render(PreviewPage);

    const runtimeSelect = screen.getByRole('combobox', { name: 'Runtime state' });
    const authSelect = screen.getByRole('combobox', { name: 'Authentication state' });
    expect(screen.getByRole('heading', { name: 'Runtime and authentication states' })).toBeInTheDocument();

    fireEvent.change(runtimeSelect, { target: { value: 'offline' } });
    fireEvent.change(authSelect, { target: { value: 'failure' } });

    await waitFor(() => {
      expect(screen.getByTestId('runtime-preview')).toHaveAttribute('data-state', 'offline');
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'failure');
    });
  });

  it.each([undefined, null, '', 'device-code', 'oauth-v2']) (
    'fails closed for an unknown provider kind: %s',
    (providerKind) => {
      expect(authStateForProviderKind(providerKind)).toBe('provider-unavailable');
    }
  );

  it('routes provider choices deterministically without a network or credential payload', async () => {
    render(PreviewPage);

    const oauth = screen.getByRole('button', { name: 'Nous' });
    await fireEvent.pointerDown(oauth, { button: 0, pointerType: 'mouse' });
    await fireEvent.click(oauth);
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'callback'));
    expect(screen.getAllByText('choose-provider').length).toBeGreaterThan(0);

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
    await fireEvent.click(screen.getByRole('button', { name: 'Discard draft' }));
    await waitFor(() => expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-selection'));
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
    window.history.pushState({}, '', '/ui-preview?authDiscovery=live');

    render(PreviewPage);

    await waitFor(() => {
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-discovery-mode', 'live');
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-state', 'provider-unavailable');
    });
    expect(screen.getByText('live-discovery-disabled')).toBeInTheDocument();

    window.history.replaceState({}, '', originalPath);
  });
});
