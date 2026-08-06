import adapter from '@sveltejs/adapter-static';

/**
 * The web prototype is a static SPA. The distinct 200.html fallback is used
 * only by the documented static-host rule for private client routes; it does
 * not create an application server or SSR boundary.
 */
const config = {
  kit: {
    adapter: adapter({ fallback: '200.html' })
  }
};

export default config;
