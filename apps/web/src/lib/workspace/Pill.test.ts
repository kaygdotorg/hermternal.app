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

    fireEvent.click(button, { detail: 1 });
    expect(onActivate).toHaveBeenCalledTimes(1);

    fireEvent.pointerCancel(button);
    fireEvent.pointerDown(button, { button: 0, pointerType: 'mouse' });
    expect(onActivate).toHaveBeenCalledTimes(2);
  });

  it('suppresses leave/re-entry compatibility clicks while retaining keyboard activation', () => {
    const onActivate = vi.fn();
    render(Pill, { label: 'Open', onActivate });

    const button = screen.getByRole('button', { name: 'Open' });
    fireEvent.pointerDown(button, { button: 0, pointerType: 'mouse' });
    fireEvent.pointerLeave(button, { pointerType: 'mouse' });
    fireEvent.pointerEnter(button, { pointerType: 'mouse' });
    fireEvent.pointerUp(button, { button: 0, pointerType: 'mouse' });
    fireEvent.click(button, { detail: 1 });
    expect(onActivate).toHaveBeenCalledTimes(1);

    fireEvent.keyDown(button, { key: 'Enter' });
    fireEvent.click(button, { detail: 0 });
    expect(onActivate).toHaveBeenCalledTimes(2);
  });

  it('suppresses a forced compatibility click after pointer cancellation', () => {
    const onActivate = vi.fn();
    render(Pill, { label: 'Retry', onActivate });

    const button = screen.getByRole('button', { name: 'Retry' });
    fireEvent.pointerDown(button, { button: 0, pointerType: 'mouse' });
    fireEvent.pointerCancel(button, { pointerType: 'mouse' });
    fireEvent.click(button, { detail: 1 });
    expect(onActivate).toHaveBeenCalledTimes(1);

    fireEvent.click(button, { detail: 0 });
    expect(onActivate).toHaveBeenCalledTimes(2);
  });

  it('keeps a cancelled pointer compatibility click suppressed after keyboard activation', () => {
    const onActivate = vi.fn();
    render(Pill, { label: 'Account', onActivate });

    const button = screen.getByRole('button', { name: 'Account' });
    fireEvent.pointerDown(button, { button: 0, pointerType: 'touch' });
    fireEvent.pointerCancel(button, { pointerType: 'touch' });
    fireEvent.click(button, { detail: 0 });
    expect(onActivate).toHaveBeenCalledTimes(2);

    fireEvent.click(button, { detail: 1 });
    expect(onActivate).toHaveBeenCalledTimes(2);
  });

  it.each([
    { label: 'A then B', order: ['A', 'B'] },
    { label: 'B then A', order: ['B', 'A'] }
  ])('suppresses delayed compatibility clicks for cancelled A and re-gesture B in either order ($label)', ({ order }) => {
    const onActivate = vi.fn();
    render(Pill, { label: 'Rapid', onActivate });

    const button = screen.getByRole('button', { name: 'Rapid' });
    fireEvent.pointerDown(button, { button: 0, pointerId: 41, pointerType: 'mouse' });
    fireEvent.pointerCancel(button, { pointerId: 41, pointerType: 'mouse' });
    fireEvent.pointerDown(button, { button: 0, pointerId: 42, pointerType: 'mouse' });
    expect(onActivate).toHaveBeenCalledTimes(2);
    expect(onActivate.mock.calls.map(([event]) => event?.type)).toEqual(['pointerdown', 'pointerdown']);

    // Compatibility clicks do not expose their originating pointer ID. The
    // queued gesture owner must suppress either delivery order without
    // dropping the second pointer's immediate activation.
    for (const _pointer of order) fireEvent.click(button, { detail: 1 });
    expect(onActivate).toHaveBeenCalledTimes(2);

    // detail=0 remains a legitimate keyboard/assistive-technology activation,
    // even while delayed compatibility suppression is being drained.
    fireEvent.click(button, { detail: 0 });
    expect(onActivate).toHaveBeenCalledTimes(3);
    expect(onActivate.mock.calls.at(-1)?.[0]).toMatchObject({ type: 'click' });
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
