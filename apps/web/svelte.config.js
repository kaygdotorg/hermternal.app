import adapter from '@sveltejs/adapter-static';

/**
 * The web prototype is a static SPA. The fallback keeps client-side routes
 * reloadable without introducing an application server or SSR boundary.
 */
const config = {
  kit: {
    adapter: adapter({ fallback: 'index.html' })
  }
};

export default config;
