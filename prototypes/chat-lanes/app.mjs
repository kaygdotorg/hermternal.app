import { resolveVariant, stepVariant } from './state.mjs';
import { renderPicker, renderThemeOptions, renderVariant } from './view.mjs';

const stage = document.querySelector('#stage');
const pickerRoot = document.querySelector('[data-picker-root]');
let current = resolveVariant(new URLSearchParams(location.search).get('v'));

pickerRoot.innerHTML = renderPicker();
document.querySelector('[data-theme-options]').innerHTML = renderThemeOptions();

const picker = document.querySelector('.proto-picker');
const highlight = picker.querySelector('.proto-picker-highlight');
const items = [...picker.querySelectorAll('[data-variant-index]')];
const replay = picker.querySelector('.proto-picker-replay');

function moveHighlight() {
  const item = items[current];
  highlight.style.width = `${item.offsetWidth}px`;
  highlight.style.transform = `translateX(${item.offsetLeft}px)`;
}

export function mountVariant(index = current) {
  stage.replaceChildren();
  requestAnimationFrame(() => {
    stage.innerHTML = renderVariant(['continuous', 'stacks', 'focus'][index]);
  });
}

function setActive(index) {
  if (index < 0 || index >= items.length) return;
  current = index;
  items.forEach((item, itemIndex) => {
    const active = itemIndex === current;
    item.toggleAttribute('data-active', active);
    if (active) item.setAttribute('aria-current', 'true');
    else item.removeAttribute('aria-current');
  });
  moveHighlight();
  const url = new URL(location.href);
  url.searchParams.set('v', String(current + 1));
  history.replaceState(null, '', url);
  mountVariant(current);
}

items.forEach((item, index) => item.addEventListener('click', () => setActive(index)));
replay.addEventListener('click', () => mountVariant(current));
window.addEventListener('resize', moveHighlight);

document.addEventListener('keydown', (event) => {
  if (/^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target.isContentEditable) return;
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  const number = Number.parseInt(event.key, 10);
  if (number >= 1 && number <= items.length) setActive(number - 1);
  else if (event.key === 'ArrowRight') setActive(stepVariant(current, 1));
  else if (event.key === 'ArrowLeft') setActive(stepVariant(current, -1));
  else if (event.key === 'r' || event.key === 'R') mountVariant(current);
});

setActive(current);
requestAnimationFrame(() => requestAnimationFrame(() => picker.setAttribute('data-ready', '')));
