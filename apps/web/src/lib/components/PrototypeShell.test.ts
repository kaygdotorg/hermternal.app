import { render, screen, waitFor } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import PrototypeShell from './PrototypeShell.svelte';
import { createMockTransport } from '$lib/transport';

describe('PrototypeShell', () => {
  it('labels the screen as a prototype and renders success evidence', async () => {
    render(PrototypeShell, { transport: createMockTransport() });

    expect(screen.getByTestId('prototype-label')).toHaveTextContent('Prototype only');
    await waitFor(() => expect(screen.getByTestId('status-success')).toBeInTheDocument());
    expect(screen.getByTestId('fixture-id')).toHaveTextContent('w01-success-v1');
  });

  it('exposes an empty fixture state without inventing a result', async () => {
    render(PrototypeShell, { transport: createMockTransport({ scenario: 'empty' }) });

    await waitFor(() => expect(screen.getByTestId('status-empty')).toBeInTheDocument());
    expect(screen.getByTestId('fixture-id')).toHaveTextContent('w01-empty-v1');
  });

  it('renders a failure state and keeps retry available', async () => {
    render(PrototypeShell, { transport: createMockTransport({ scenario: 'failure' }) });

    await waitFor(() => expect(screen.getByTestId('status-failure')).toBeInTheDocument());
    expect(screen.getByRole('button', { name: 'Re-run mock check' })).toBeEnabled();
  });
});
