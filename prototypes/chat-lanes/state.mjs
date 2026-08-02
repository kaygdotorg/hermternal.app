/** Ordered lane ids are stable because the picker persists a one-based index. */
export const VARIANTS = Object.freeze(['continuous', 'stacks', 'focus']);

/** Themes are visual fixtures only; they never alter geometry or behavior. */
export const THEMES = Object.freeze([
  'system',
  'nord',
  'dracula',
  'gruvbox',
  'solarized',
  'catppuccin',
  'tokyo-night',
  'rose-pine',
  'one-dark',
  'monokai',
]);

export function resolveVariant(value) {
  const index = Number.parseInt(value, 10) - 1;
  return Number.isInteger(index) && index >= 0 && index < VARIANTS.length
    ? index
    : 0;
}

export function stepVariant(current, delta) {
  return (current + delta + VARIANTS.length) % VARIANTS.length;
}

export function normalizeDraft(value) {
  return value.trim();
}

export function canSend(value) {
  return normalizeDraft(value).length > 0;
}
