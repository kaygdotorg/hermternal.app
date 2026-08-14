import { createHash } from 'node:crypto';

export const OFFICIAL_HERMES_IMAGE =
  'docker.io/nousresearch/hermes-agent:v2026.8.3@sha256:16788311e2fa3035456bdc1bafb8ec2b1777db64ebf020af9bb7eb73c3712c9e';
export const LIVE_SCREENSHOT_COMMAND =
  'bun run --cwd apps/web test:e2e:live --grep "browser UI reaches the official Hermes gateway through completion"';
export const LIVE_SCREENSHOT_ISSUE = 'https://github.com/kaygdotorg/hermternal/issues/353';
export const LIVE_SCREENSHOT_CAPTURE_STATE =
  'authenticated-chat-message-complete-rest-reconciled-stable-v1';
export const LIVE_SCREENSHOT_VARIANTS = Object.freeze([
  Object.freeze({ name: 'desktop', width: 1440, height: 960 }),
  Object.freeze({ name: 'narrow', width: 390, height: 844 })
]);

const MAX_PUBLIC_PNG_BYTES = 20 * 1024 * 1024;

export const LIVE_SCREENSHOT_PUBLIC_CONTRACT = Object.freeze({
  schema: 'hermternal.live-chat-screenshot-contract.v1',
  issue: LIVE_SCREENSHOT_ISSUE,
  route: '/',
  browser: 'chromium',
  device_pixel_ratio: 1,
  browser_zoom: 1,
  theme: 'light',
  reduced_motion: 'reduce',
  locale: 'en-US',
  timezone: 'UTC',
  capture_state: LIVE_SCREENSHOT_CAPTURE_STATE,
  variants: LIVE_SCREENSHOT_VARIANTS
});

/** @param {Buffer | string} bytes */
function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/** @param {Buffer} bytes @param {{ width: number, height: number }} expected */
export function inspectPublicPng(bytes, expected) {
  if (
    !Buffer.isBuffer(bytes) ||
    bytes.length < 33 ||
    bytes.length > MAX_PUBLIC_PNG_BYTES
  ) {
    throw new Error('screenshot is not a bounded PNG');
  }
  if (!bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
    throw new Error('screenshot PNG signature changed');
  }
  const width = bytes.readUInt32BE(16);
  const height = bytes.readUInt32BE(20);
  if (width !== expected.width || height !== expected.height) {
    throw new Error(`screenshot dimensions were ${width}x${height}; expected ${expected.width}x${expected.height}`);
  }
  let offset = 8;
  /** @type {string[]} */
  const chunks = [];
  while (offset < bytes.length) {
    if (offset + 12 > bytes.length) throw new Error('screenshot PNG chunk was truncated');
    const length = bytes.readUInt32BE(offset);
    const end = offset + 12 + length;
    if (end > bytes.length) throw new Error('screenshot PNG chunk exceeded the file');
    const type = bytes.subarray(offset + 4, offset + 8).toString('ascii');
    if (!['IHDR', 'IDAT', 'IEND'].includes(type)) {
      throw new Error(`screenshot PNG contained disallowed ${type} metadata`);
    }
    if (
      (type === 'IHDR' && (chunks.length !== 0 || length !== 13)) ||
      (type === 'IDAT' && (chunks[0] !== 'IHDR' || chunks.includes('IEND'))) ||
      (type === 'IEND' && (length !== 0 || chunks.includes('IEND')))
    ) {
      throw new Error('screenshot PNG chunk order was invalid');
    }
    chunks.push(type);
    offset = end;
  }
  if (
    chunks[0] !== 'IHDR' ||
    chunks.at(-1) !== 'IEND' ||
    !chunks.includes('IDAT') ||
    chunks.filter((type) => type === 'IHDR').length !== 1
  ) {
    throw new Error('screenshot PNG chunk order was invalid');
  }
  return Object.freeze({
    width,
    height,
    sha256: sha256(bytes),
    chunks: Object.freeze([...new Set(chunks)])
  });
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {{ width: number, height: number }} expectedVariant
 */
export async function assertStableLiveCaptureState(page, expectedVariant) {
  const state = await page.evaluate(() => ({
    pathname: location.pathname,
    search: location.search,
    hash: location.hash,
    width: innerWidth,
    height: innerHeight,
    dpr: devicePixelRatio,
    zoom: visualViewport?.scale ?? 1,
    locale: navigator.language,
    themeDark: matchMedia('(prefers-color-scheme: dark)').matches,
    reducedMotion: matchMedia('(prefers-reduced-motion: reduce)').matches,
    readyState: document.readyState,
    workspaceState: document.querySelector('[data-testid="runtime-preview"]')?.getAttribute('data-state'),
    composerPresent: document.querySelector('[aria-label="Message Hermes"]') !== null
  }));
  if (state.pathname !== '/' || state.search !== '' || state.hash !== '') {
    throw new Error('live screenshot route was not the exact root route');
  }
  if (state.width !== expectedVariant.width || state.height !== expectedVariant.height) {
    throw new Error('live screenshot viewport did not match the public contract');
  }
  if (state.dpr !== 1 || state.zoom !== 1) throw new Error('live screenshot DPR or zoom changed');
  if (state.locale !== 'en-US') throw new Error('live screenshot locale changed');
  if (state.themeDark || !state.reducedMotion) throw new Error('live screenshot media state changed');
  if (state.readyState !== 'complete') throw new Error('live screenshot document was not stable');
  if (
    (state.workspaceState !== 'empty' && state.workspaceState !== 'ready') ||
    !state.composerPresent
  ) {
    throw new Error('live screenshot UI was not in the reviewed stable Chat state');
  }
  await page.evaluate(async () => {
    await document.fonts.ready;
    await new Promise((resolveFrame) => requestAnimationFrame(() => requestAnimationFrame(resolveFrame)));
  });
}

/**
 * @param {{
 *   clientCommit: string,
 *   blocker: 'issue-327-missing-authenticated-inference-capability'
 * }} options
 */
export function blockedLiveScreenshotManifest({ clientCommit, blocker }) {
  if (!/^[0-9a-f]{40}$/.test(clientCommit)) throw new Error('client commit must be an exact SHA');
  if (blocker !== 'issue-327-missing-authenticated-inference-capability') {
    throw new Error('live screenshot blocker was not the reviewed closed value');
  }
  return {
    ...LIVE_SCREENSHOT_PUBLIC_CONTRACT,
    status: 'blocked',
    client_commit: clientCommit,
    official_hermes_image: OFFICIAL_HERMES_IMAGE,
    command: LIVE_SCREENSHOT_COMMAND,
    blocker,
    images: []
  };
}
