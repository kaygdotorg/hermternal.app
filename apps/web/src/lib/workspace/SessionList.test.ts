import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import SessionList from './SessionList.svelte';

describe('SessionList', () => {
  it('uses the Paper wordmark typography without changing its accessible name', () => {
    render(SessionList);

    const wordmark = screen.getByText('hermternal');
    const style = getComputedStyle(wordmark);

    expect(wordmark).toHaveClass('brand-mark');
    expect(style.fontFamily).toContain('Dancing Script');
    expect(style.fontSize).toBe('27px');
    expect(style.fontWeight).toBe('600');
    expect(style.lineHeight).toBe('31px');
    // jsdom resolves the Paper -0.02em value against the 27px font size.
    expect(style.letterSpacing).toBe('-0.54px');
  });
});
