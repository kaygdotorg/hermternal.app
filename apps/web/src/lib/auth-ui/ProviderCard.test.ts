import { render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import ProviderCard from './ProviderCard.svelte';
import type { AuthProvider } from './types';

const provider: AuthProvider = {
  id: 'nous',
  name: 'Nous',
  monogram: 'N',
  kind: 'oauth',
  description: 'OAuth · opens the provider'
};

describe('ProviderCard', () => {
  it('exposes a keyboard- and pointer-activatable provider target', async () => {
    const onAction = vi.fn();
    render(ProviderCard, { provider, onAction });

    const button = screen.getByRole('button', { name: 'Nous' });
    expect(button).toBeEnabled();
    expect(button.getBoundingClientRect().height).toBeGreaterThanOrEqual(0);

    button.focus();
    expect(button).toHaveFocus();
    button.click();

    expect(onAction).toHaveBeenCalledWith({ type: 'choose-provider', providerId: 'nous' });
  });

  it('fails closed while provider discovery is pending', () => {
    render(ProviderCard, { provider, pending: true, disabled: true });

    const button = screen.getByRole('button', { name: 'Nous, loading' });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('title', 'Nous, loading');
  });
});
