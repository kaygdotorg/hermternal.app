import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
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

  it('switches both preview surfaces to the explicit dark appearance', async () => {
    render(PreviewPage);

    fireEvent.change(screen.getByRole('combobox', { name: 'Appearance' }), { target: { value: 'dark' } });

    await waitFor(() => {
      expect(screen.getByTestId('runtime-preview')).toHaveAttribute('data-appearance', 'dark');
      expect(screen.getByTestId('auth-preview')).toHaveAttribute('data-appearance', 'dark');
    });
  });
});
