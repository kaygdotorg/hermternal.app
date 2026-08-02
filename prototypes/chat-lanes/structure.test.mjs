import test from 'node:test';
import assert from 'node:assert/strict';

import {
  renderPicker,
  renderThemeOptions,
  renderVariant,
} from './view.mjs';

test('each lane renders the same conversation content through a distinct container model', () => {
  const continuous = renderVariant('continuous');
  const stacks = renderVariant('stacks');
  const focus = renderVariant('focus');

  for (const [lane, markup] of Object.entries({ continuous, stacks, focus })) {
    assert.match(markup, new RegExp(`data-lane="${lane}"`));
    assert.match(markup, /Plan a calm product launch/);
    assert.match(markup, /Reviewing launch-notes\.md/);
    assert.match(markup, /Allow once/);
  }

  assert.match(continuous, /lane-continuous/);
  assert.match(stacks, /lane-stacks/);
  assert.match(focus, /lane-focus/);
});

test('picker exposes exactly three named lane controls', () => {
  const picker = renderPicker();
  assert.equal((picker.match(/data-variant-index=/g) ?? []).length, 3);
  assert.match(picker, /aria-label="Continuous Canvas">Canvas</);
  assert.match(picker, /aria-label="Turn Stacks">Stacks</);
  assert.match(picker, /aria-label="Focus Lane">Focus</);
});

test('theme menu exposes all ten theme fixtures as named controls', () => {
  const options = renderThemeOptions();
  assert.equal((options.match(/data-theme-value=/g) ?? []).length, 10);
  assert.match(options, />System</);
  assert.match(options, />Monokai</);
});
