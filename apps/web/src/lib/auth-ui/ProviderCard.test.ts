import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import ProviderCard from './ProviderCard.svelte';
import type { AuthProvider } from './types';

const provider: AuthProvider = {
  id: 'nous',
  name: 'Nous',
  monogram: 'N',
  kind: 'oauth',
  description: 'OAuth · opens the provider',
  mobileDescription: 'OAuth provider'
};

describe('ProviderCard', () => {
  it('exposes the exact action, description, keyboard target, and one pointer action', () => {
    const onAction = vi.fn();
    render(ProviderCard, { provider, onAction });

    const button = screen.getByRole('button', { name: 'Continue with Nous' });
    expect(button).toBeEnabled();
    expect(screen.getByText('OAuth · opens the provider')).toBeInTheDocument();
    expect(Number.parseFloat(getComputedStyle(button).minHeight)).toBeGreaterThanOrEqual(44);
    expect(button.getAttribute('title')).toBe('Continue with Nous');

    button.focus();
    expect(button).toHaveFocus();
    fireEvent.keyDown(button, { key: 'Enter', code: 'Enter' });
    fireEvent.click(button, { detail: 0 });
    fireEvent.keyDown(button, { key: ' ', code: 'Space' });
    fireEvent.click(button, { detail: 0 });
    expect(onAction).toHaveBeenCalledTimes(2);

    fireEvent.pointerDown(button, { button: 0, pointerType: 'mouse' });
    fireEvent.pointerUp(button, { button: 0, pointerType: 'mouse' });
    fireEvent.click(button, { detail: 1 });
    expect(onAction).toHaveBeenCalledTimes(3);
    expect(onAction).toHaveBeenLastCalledWith({ type: 'choose-provider', providerId: 'nous', providerKind: 'oauth' });
  });

  it('fails closed while provider discovery is pending with exact desktop and narrow copy', () => {
    render(ProviderCard, { provider, pending: true, disabled: true });

    const button = screen.getByRole('button', { name: 'Checking provider manifest, loading' });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('title', 'Checking provider manifest, loading');
    expect(screen.getByText('Checking provider manifest', { selector: '.pill-label' })).toBeInTheDocument();
    expect(screen.getByText('Loading · no sign-in action yet', { selector: '.pill-description' })).toBeInTheDocument();
    expect(screen.getByText('Provider manifest', { selector: '.mobile-label' })).toBeInTheDocument();
    expect(screen.getByText('Loading · no sign-in action yet', { selector: '.mobile-description' })).toBeInTheDocument();
  });

  it('renders unavailable capabilities as visible disabled rows', () => {
    const unavailable: AuthProvider = {
      id: 'provider-neutral',
      name: 'Provider Neutral',
      monogram: 'P',
      kind: 'unavailable',
      description: 'Provider reported without a reviewed browser sign-in capability'
    };
    render(ProviderCard, { provider: unavailable });

    const button = screen.getByRole('button', { name: 'Provider Neutral, unavailable' });
    expect(button).toBeDisabled();
    expect(screen.getByText(unavailable.description)).toBeInTheDocument();
    // Narrow layouts keep the full capability explanation in the Pill rather
    // than replacing real provider data with the compact pending overlay.
    expect(screen.queryByText(unavailable.description, { selector: '.mobile-description' })).not.toBeInTheDocument();
  });
});
