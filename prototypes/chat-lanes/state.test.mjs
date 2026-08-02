import test from 'node:test';
import assert from 'node:assert/strict';

import {
  canSend,
  normalizeDraft,
  resolveVariant,
  stepVariant,
} from './state.mjs';

test('invalid picker input resolves to the first lane', () => {
  assert.equal(resolveVariant('0'), 0);
  assert.equal(resolveVariant('4'), 0);
  assert.equal(resolveVariant('word'), 0);
});

test('variant stepping wraps in both directions', () => {
  assert.equal(stepVariant(2, 1), 0);
  assert.equal(stepVariant(0, -1), 2);
});

test('draft normalization rejects whitespace-only sends', () => {
  assert.equal(normalizeDraft('  hello  '), 'hello');
  assert.equal(canSend('   '), false);
  assert.equal(canSend('hello'), true);
});
