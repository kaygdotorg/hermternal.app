import '../app.css';

/**
 * These exports keep W-01 a static, client-only SvelteKit build. Browser-only
 * lifecycle work lives in +layout.svelte, where production startup can register
 * the worker without side effects during SSR, build evaluation, development, or
 * module import. The D-15W Paper manifest is merged; Runtime and authentication
 * UI remain separate in #267.
 */
export const ssr = false;
export const prerender = true;
export const trailingSlash = 'always';
