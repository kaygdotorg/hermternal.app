import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import Pill from './Pill.svelte';

describe('Pill', () => {
  it('native-disables no-handler controls with a truthful deferred title and no false toggle aria', () => {
    render(Pill, { label: 'Workspace options', icon: 'menu', iconOnly: true });

    const button = screen.getByRole('button', { name: 'Workspace options' });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('title', 'Deferred in this preview');
    expect(button).not.toHaveAttribute('aria-pressed');
    expect(button).not.toHaveAttribute('aria-expanded');

    fireEvent.pointerDown(button, { button: 0, pointerType: 'mouse' });
    fireEvent.click(button);
    expect(button).toHaveAccessibleName('Workspace options');
  });

  it('activates on pointer down once, suppresses the follow-up click, and can repeat after cancel', () => {
    const onActivate = vi.fn();
    render(Pill, { label: 'Send', icon: 'send', onActivate });

    const button = screen.getByRole('button', { name: 'Send' });
    fireEvent.pointerDown(button, { button: 0, pointerType: 'mouse' });
    expect(onActivate).toHaveBeenCalledTimes(1);

    fireEvent.click(button);
    expect(onActivate).toHaveBeenCalledTimes(1);

    fireEvent.pointerCancel(button);
    fireEvent.pointerDown(button, { button: 0, pointerType: 'mouse' });
    expect(onActivate).toHaveBeenCalledTimes(2);
  });

  it('only exposes pressed and expanded semantics for opted-in controls', () => {
    render(Pill, {
      ariaControls: 'provider-panel',
      expandable: true,
      expanded: true,
      label: 'Provider',
      selected: true,
      toggleable: true,
      onActivate: vi.fn()
    });

    const button = screen.getByRole('button', { name: 'Provider' });
    expect(button).toHaveAttribute('aria-pressed', 'true');
    expect(button).toHaveAttribute('aria-expanded', 'true');
    expect(button).toHaveAttribute('aria-controls', 'provider-panel');
  });
});
