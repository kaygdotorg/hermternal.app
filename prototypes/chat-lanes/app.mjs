import {
  canSend,
  normalizeDraft,
  resolveVariant,
  stepVariant,
  THEMES,
} from './state.mjs';
import {
  renderLocalExchange,
  renderPicker,
  renderThemeOptions,
  renderVariant,
} from './view.mjs';

const stage = document.querySelector('#stage');
const pickerRoot = document.querySelector('[data-picker-root]');
let current = resolveVariant(new URLSearchParams(location.search).get('v'));

pickerRoot.innerHTML = renderPicker();
document.querySelector('[data-theme-options]').innerHTML = renderThemeOptions();

const picker = document.querySelector('.proto-picker');
const highlight = picker.querySelector('.proto-picker-highlight');
const items = [...picker.querySelectorAll('[data-variant-index]')];
const MAGNETIC_STRENGTH = 0.18;
const MAGNETIC_MAX = 7;
const MENU_ENTER_MS = 180;
const MENU_EXIT_MS = 130;
const TOAST_EXIT_MS = 140;
const REDUCED_MOTION_MS = 120;
let magneticFrame = 0;
let lastInputModality = 'pointer';

document.addEventListener('keydown', () => {
  lastInputModality = 'keyboard';
}, { capture: true });
document.addEventListener('pointerdown', () => {
  lastInputModality = 'pointer';
}, { capture: true });

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
window.addEventListener('resize', moveHighlight);

document.addEventListener('keydown', (event) => {
  if (/^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target.isContentEditable) return;
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  const number = Number.parseInt(event.key, 10);
  if (number >= 1 && number <= items.length) setActive(number - 1);
  else if (event.key === 'ArrowRight') setActive(stepVariant(current, 1));
  else if (event.key === 'ArrowLeft') setActive(stepVariant(current, -1));
});

setActive(current);
requestAnimationFrame(() => requestAnimationFrame(() => picker.setAttribute('data-ready', '')));

const root = document.documentElement;
const composer = document.querySelector('.composer');
const expandButton = document.querySelector('[data-expand]');
const prompt = document.querySelector('#prompt');
const sendButton = document.querySelector('.send-button');
const toast = document.querySelector('[data-toast]');
const sidebar = document.querySelector('#sidebar');
const sidebarTrigger = document.querySelector('[data-sidebar-open]');
const conversation = document.querySelector('#conversation');
const mobileToolbar = document.querySelector('.mobile-toolbar');
const attachmentStatus = document.querySelector('[data-attachment-status]');
const recordTime = document.querySelector('[data-record-time]');
const searchInput = document.querySelector('[data-search-history]');
const historyItems = [...document.querySelectorAll('[data-history-item]')];
const historyGroups = [...document.querySelectorAll('[data-history-group]')];
const historyEmpty = document.querySelector('[data-history-empty]');
let lastDrawerFocus = null;
let recordingTimer = null;
let recordingSeconds = 0;
let toastTimer = null;
let toastHideTimer = null;

function announce(message) {
  const shouldAnimate = lastInputModality !== 'keyboard';
  window.clearTimeout(toastTimer);
  window.clearTimeout(toastHideTimer);
  toast.textContent = message;
  toast.hidden = false;
  toast.classList.toggle('motion-immediate', !shouldAnimate);
  if (shouldAnimate) requestAnimationFrame(() => toast.classList.add('is-visible'));
  else toast.classList.add('is-visible');
  toastTimer = window.setTimeout(() => {
    toast.classList.remove('is-visible');
    if (!shouldAnimate) {
      toast.hidden = true;
      return;
    }
    toastHideTimer = window.setTimeout(() => {
      toast.hidden = true;
    }, TOAST_EXIT_MS);
  }, 2600);
}

export function setTheme(theme) {
  if (!THEMES.includes(theme)) return;
  root.dataset.theme = theme;
  const option = document.querySelector(`[data-theme-value="${theme}"]`);
  document.querySelectorAll('[data-theme-value]').forEach((item) => {
    item.setAttribute('aria-checked', String(item === option));
  });
}

export function setSidebar(open) {
  document.body.classList.toggle('sidebar-open', open);
  sidebarTrigger.setAttribute('aria-expanded', String(open));
  document.body.style.overflow = open ? 'hidden' : '';
  // The drawer is a modal navigation surface on narrow screens. Inerting the
  // page behind it keeps keyboard and assistive-technology focus in one place.
  conversation.inert = open;
  mobileToolbar.inert = open;
  if (open) {
    lastDrawerFocus = document.activeElement;
    sidebar.focus({ preventScroll: true });
  } else if (lastDrawerFocus instanceof HTMLElement) {
    lastDrawerFocus.focus({ preventScroll: true });
  }
}

function animateMenu(menu, shouldOpen) {
  const isKeyboardAction = lastInputModality === 'keyboard';
  const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const wasHidden = menu.hidden;
  const renderedStyle = wasHidden ? null : getComputedStyle(menu);
  const currentOpacity = renderedStyle?.opacity ?? '0';
  const currentTransform = renderedStyle?.transform === 'none' ? 'scale(1)' : renderedStyle?.transform;
  menu.getAnimations().forEach((animation) => animation.cancel());
  menu.dataset.state = shouldOpen ? 'open' : 'closed';

  if (shouldOpen) {
    menu.hidden = false;
    if (isKeyboardAction) return;
    menu.animate(
      reduceMotion
        ? [{ opacity: wasHidden ? 0 : currentOpacity }, { opacity: 1 }]
        : [{ opacity: wasHidden ? 0 : currentOpacity, transform: wasHidden ? 'scale(.97)' : currentTransform }, { opacity: 1, transform: 'scale(1)' }],
      { duration: reduceMotion ? REDUCED_MOTION_MS : MENU_ENTER_MS, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' },
    );
    return;
  }

  if (menu.hidden) return;
  if (isKeyboardAction) {
    menu.hidden = true;
    return;
  }
  const animation = menu.animate(
    reduceMotion
      ? [{ opacity: currentOpacity }, { opacity: 0 }]
      : [{ opacity: currentOpacity, transform: currentTransform }, { opacity: 0, transform: 'scale(.97)' }],
    { duration: reduceMotion ? REDUCED_MOTION_MS : MENU_EXIT_MS, easing: 'cubic-bezier(0.23, 1, 0.32, 1)' },
  );
  animation.finished.then(() => {
    if (menu.dataset.state === 'closed') menu.hidden = true;
  }).catch(() => {});
}

function positionFloatingMenu(menu, trigger) {
  const isMobileThemeSheet = menu.dataset.menu === 'theme' && matchMedia('(max-width: 820px)').matches;
  if (isMobileThemeSheet) {
    menu.style.removeProperty('left');
    menu.style.removeProperty('right');
    menu.style.removeProperty('bottom');
    return;
  }

  const triggerRect = trigger.getBoundingClientRect();
  const menuWidth = menu.dataset.menu === 'theme' ? 352 : 240;
  const viewportGutter = 16;
  const preferredLeft = menu.dataset.menu === 'theme'
    ? triggerRect.right - 64
    : triggerRect.right - menuWidth;
  const left = Math.min(
    innerWidth - menuWidth - viewportGutter,
    Math.max(viewportGutter, preferredLeft),
  );
  menu.style.left = `${left}px`;
  menu.style.right = 'auto';
  menu.style.bottom = `${innerHeight - triggerRect.top + 8}px`;
}

function focusMenuItem(menu) {
  const item = menu.querySelector('[aria-checked="true"]')
    ?? menu.querySelector('[role^="menuitem"]');
  item?.focus({ preventScroll: true });
}

function moveMenuFocus(event) {
  const menu = event.target.closest('[role="menu"]');
  if (!menu) return false;
  const items = [...menu.querySelectorAll('[role^="menuitem"]')]
    .filter((item) => !item.hidden && getComputedStyle(item).display !== 'none');
  if (!items.length) return false;

  const currentIndex = Math.max(0, items.indexOf(document.activeElement));
  const nextIndex = event.key === 'ArrowDown'
    ? (currentIndex + 1) % items.length
    : event.key === 'ArrowUp'
      ? (currentIndex - 1 + items.length) % items.length
      : event.key === 'Home'
        ? 0
        : event.key === 'End'
          ? items.length - 1
          : -1;
  if (nextIndex < 0) return false;
  event.preventDefault();
  items[nextIndex].focus({ preventScroll: true });
  return true;
}

export function setMenu(name, open) {
  const previouslyOpenTrigger = document.querySelector('[data-menu-trigger][aria-expanded="true"]');
  document.querySelectorAll('[data-menu]').forEach((menu) => {
    const shouldOpen = menu.dataset.menu === name && open;
    const trigger = document.querySelector(`[data-menu-trigger="${menu.dataset.menu}"]`);
    if (shouldOpen && trigger) positionFloatingMenu(menu, trigger);
    animateMenu(menu, shouldOpen);
    if (shouldOpen && lastInputModality === 'keyboard') {
      requestAnimationFrame(() => {
        if (!menu.hidden) focusMenuItem(menu);
      });
    }
  });
  document.querySelectorAll('[data-menu-trigger]').forEach((trigger) => {
    trigger.setAttribute('aria-expanded', String(trigger.dataset.menuTrigger === name && open));
  });
  if (!open && previouslyOpenTrigger && lastInputModality === 'keyboard') {
    previouslyOpenTrigger.focus({ preventScroll: true });
  }
}

window.addEventListener('resize', () => {
  const trigger = document.querySelector('[data-menu-trigger][aria-expanded="true"]');
  if (!trigger) return;
  const menu = document.querySelector(`[data-menu="${trigger.dataset.menuTrigger}"]`);
  if (menu) positionFloatingMenu(menu, trigger);
});

function closeTopLayer() {
  const openTrigger = document.querySelector('[data-menu-trigger][aria-expanded="true"]');
  if (openTrigger) {
    setMenu('', false);
    openTrigger.focus();
    return true;
  }
  if (document.body.classList.contains('sidebar-open')) {
    setSidebar(false);
    return true;
  }
  return false;
}

function updateSendState() {
  sendButton.disabled = !canSend(prompt.value);
}

function resizePrompt() {
  // Measure intrinsic wrapping without the compact row's minimum height. The
  // expand affordance is meaningful only once a draft genuinely reaches two lines.
  const priorHeight = prompt.style.height;
  const priorMinHeight = prompt.style.minHeight;
  prompt.style.minHeight = '0';
  prompt.style.height = '0px';
  const measuredStyle = getComputedStyle(prompt);
  const intrinsicHeight = prompt.scrollHeight;
  const verticalPadding = Number.parseFloat(measuredStyle.paddingTop) + Number.parseFloat(measuredStyle.paddingBottom);
  const visualLines = Math.max(1, Math.ceil((intrinsicHeight - verticalPadding) / Number.parseFloat(measuredStyle.lineHeight)));
  prompt.style.height = priorHeight;
  prompt.style.minHeight = priorMinHeight;

  prompt.style.height = 'auto';
  const style = getComputedStyle(prompt);
  const maxHeight = composer.classList.contains('expanded')
    ? prompt.scrollHeight
    : Number.parseFloat(style.maxHeight);
  const nextHeight = Math.min(prompt.scrollHeight, maxHeight);
  prompt.style.height = `${nextHeight}px`;
  prompt.style.overflowY = prompt.scrollHeight > maxHeight ? 'auto' : 'hidden';
  expandButton.hidden = !composer.classList.contains('expanded') && visualLines < 2;
}

function filterHistory() {
  const query = searchInput.value.trim().toLocaleLowerCase();
  let visibleCount = 0;
  historyItems.forEach((item) => {
    const matches = !query || item.textContent.toLocaleLowerCase().includes(query);
    item.hidden = !matches;
    if (matches) visibleCount += 1;
  });
  historyGroups.forEach((group) => {
    group.hidden = query.length > 0 && !group.querySelector('[data-history-item]:not([hidden])');
  });
  historyEmpty.hidden = visibleCount > 0 || !query;
}

function startNewConversation() {
  setMenu('', false);
  setSidebar(false);
  mountVariant(current);
  composer.classList.remove('expanded');
  document.querySelector('[data-expand]').setAttribute('aria-expanded', 'false');
  attachmentStatus.hidden = true;
  prompt.value = '';
  resizePrompt();
  updateSendState();
  searchInput.value = '';
  filterHistory();
  prompt.focus({ preventScroll: true });
  announce('New conversation started locally.');
}

function stopStreaming(button) {
  const message = button.closest('.streaming-message');
  if (!message) return;
  message.classList.add('is-complete');
  button.disabled = true;
  button.textContent = 'Stopped';
  message.querySelector('[data-stream-caption]').textContent = 'Local response stopped';
  const status = message.querySelector('.stream-status');
  status?.replaceChildren(document.createTextNode('Stopped'));
  announce('Mock response stopped locally.');
}

function trapDrawerFocus(event) {
  if (event.key !== 'Tab') return;
  const openMenu = [...document.querySelectorAll('[data-menu][data-state="open"]')]
    .find((menu) => !menu.hidden);
  const layer = openMenu ?? (document.body.classList.contains('sidebar-open') ? sidebar : null);
  if (!layer) return;
  const focusable = [...layer.querySelectorAll('a[href], button:not([disabled]), input, [tabindex]:not([tabindex="-1"])')];
  if (!focusable.length) {
    event.preventDefault();
    layer.focus({ preventScroll: true });
    return;
  }
  const first = focusable[0];
  const last = focusable.at(-1);
  if (!layer.contains(document.activeElement)) {
    event.preventDefault();
    first.focus({ preventScroll: true });
  } else if (event.shiftKey && (document.activeElement === first || document.activeElement === layer)) {
    event.preventDefault();
    last.focus({ preventScroll: true });
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus({ preventScroll: true });
  }
}

export function submitDraft() {
  const value = normalizeDraft(prompt.value);
  if (!canSend(value)) return false;
  stage.querySelector('.transcript-flow').insertAdjacentHTML('beforeend', renderLocalExchange(value));
  const motionClass = lastInputModality !== 'keyboard' ? '' : ' motion-immediate';
  const localTurn = stage.querySelector('.local-turn:last-child');
  if (motionClass) localTurn?.classList.add('motion-immediate');
  prompt.value = '';
  resizePrompt();
  updateSendState();
  localTurn?.scrollIntoView({ block: 'center' });
  announce('Added locally. Nothing was sent.');
  return true;
}

function toggleRecording(button) {
  const recording = !button.classList.contains('recording');
  button.classList.toggle('recording', recording);
  button.setAttribute('aria-label', recording ? 'Stop voice recording' : 'Record a voice note');
  recordTime.hidden = !recording;
  window.clearInterval(recordingTimer);
  if (!recording) {
    announce('Mock voice note kept locally.');
    return;
  }
  recordingSeconds = 0;
  recordTime.textContent = '0:00';
  recordingTimer = window.setInterval(() => {
    recordingSeconds += 1;
    recordTime.textContent = `0:${String(recordingSeconds).padStart(2, '0')}`;
  }, 1000);
}

document.addEventListener('click', (event) => {
  const menuTrigger = event.target.closest('[data-menu-trigger]');
  if (menuTrigger) {
    setMenu(menuTrigger.dataset.menuTrigger, menuTrigger.getAttribute('aria-expanded') !== 'true');
    return;
  }

  const themeOption = event.target.closest('[data-theme-value]');
  if (themeOption) {
    setTheme(themeOption.dataset.themeValue);
    setMenu('', false);
    announce(`${themeOption.querySelector('span:nth-child(2)').textContent} theme selected.`);
    return;
  }

  const modelOption = event.target.closest('[data-model]');
  if (modelOption) {
    document.querySelector('[data-model-label]').textContent = modelOption.dataset.model;
    document.querySelectorAll('[data-model]').forEach((item) => {
      item.setAttribute('aria-checked', String(item === modelOption));
    });
    setMenu('', false);
    announce(`${modelOption.dataset.model} selected.`);
    return;
  }

  if (event.target.closest('[data-sidebar-open]')) setSidebar(true);
  if (event.target.closest('[data-sidebar-close]')) setSidebar(false);

  if (event.target.closest('[data-new-conversation]')) {
    startNewConversation();
    return;
  }

  const expand = event.target.closest('[data-expand]');
  if (expand) {
    const expanded = !composer.classList.contains('expanded');
    composer.classList.toggle('expanded', expanded);
    expand.setAttribute('aria-expanded', String(expanded));
    resizePrompt();
    prompt.focus();
  }

  if (event.target.closest('[data-attach]')) {
    attachmentStatus.hidden = false;
    announce('Mock attachment added locally.');
  }
  if (event.target.closest('[data-attachment-remove]')) attachmentStatus.hidden = true;
  if (event.target.closest('[data-context]')) announce('Context controls are mocked locally.');

  const voice = event.target.closest('[data-voice]');
  if (voice) toggleRecording(voice);

  const toolToggle = event.target.closest('[data-tool-toggle]');
  if (toolToggle) {
    const detail = toolToggle.closest('.event-row').querySelector('.tool-detail');
    detail.hidden = !detail.hidden;
    toolToggle.setAttribute('aria-expanded', String(!detail.hidden));
  }

  const approval = event.target.closest('[data-approval]');
  if (approval) {
    const motionClass = lastInputModality !== 'keyboard' ? '' : ' motion-immediate';
    approval.closest('.approval-actions').innerHTML = `<span class="approval-result${motionClass}">${approval.dataset.approval === 'allow' ? 'Allowed once' : 'Skipped'}</span>`;
    announce(approval.dataset.approval === 'allow' ? 'Mock context allowed once.' : 'Mock context skipped.');
  }

  const stop = event.target.closest('[data-stop-stream]');
  if (stop) stopStreaming(stop);

  if (!menuTrigger && !event.target.closest('[data-menu]')) {
    const openMenu = document.querySelector('[data-menu-trigger][aria-expanded="true"]');
    if (openMenu) setMenu('', false);
  }
});

document.addEventListener('keydown', (event) => {
  trapDrawerFocus(event);
  if (moveMenuFocus(event)) return;
  if (event.key === 'Escape' && closeTopLayer()) return;
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'n') {
    event.preventDefault();
    startNewConversation();
    return;
  }
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
    event.preventDefault();
    submitDraft();
  }
});

composer.addEventListener('submit', (event) => {
  event.preventDefault();
  submitDraft();
});
prompt.addEventListener('input', () => {
  resizePrompt();
  updateSendState();
});
searchInput.addEventListener('input', filterHistory);

document.addEventListener('pointermove', (event) => {
  if (!matchMedia('(hover: hover) and (pointer: fine)').matches) return;
  if (event.pointerType === 'touch' || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const target = event.target.closest('.magnetic');
  if (!target) return;
  const rect = target.getBoundingClientRect();
  const x = Math.max(-MAGNETIC_MAX, Math.min(MAGNETIC_MAX, (event.clientX - rect.left - rect.width / 2) * MAGNETIC_STRENGTH));
  const y = Math.max(-MAGNETIC_MAX, Math.min(MAGNETIC_MAX, (event.clientY - rect.top - rect.height / 2) * MAGNETIC_STRENGTH));
  cancelAnimationFrame(magneticFrame);
  magneticFrame = requestAnimationFrame(() => {
    target.classList.add('is-magnetic-following');
    // Individual translate composes with the shared press-scale transform.
    target.style.translate = `${x}px ${y}px`;
  });
});

document.addEventListener('pointerout', (event) => {
  const target = event.target.closest('.magnetic');
  if (!target || target.contains(event.relatedTarget)) return;
  cancelAnimationFrame(magneticFrame);
  target.classList.remove('is-magnetic-following');
  target.style.translate = '';
});

setTheme('system');
resizePrompt();
