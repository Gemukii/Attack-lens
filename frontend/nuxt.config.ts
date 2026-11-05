export default defineNuxtConfig({
  devtools: {
    enabled: true,
  },

  css: [
    '@fontsource/ibm-plex-mono/400.css',
    '@fontsource/ibm-plex-mono/500.css',
    '@fontsource/ibm-plex-mono/600.css',
    '@fontsource/barlow-condensed/500.css',
    '@fontsource/barlow-condensed/600.css',
    '~/assets/css/main.css',
  ],

  // Overridden at runtime by NUXT_API_INTERNAL_BASE, NUXT_API_KEY, NUXT_ALLOWED_HOSTS,
  // and NUXT_PUBLIC_SCAN_TARGET. Only the `public` section reaches the browser.
  runtimeConfig: {
    apiInternalBase: 'http://127.0.0.1:8000',
    apiKey: '',
    allowedHosts: 'localhost,127.0.0.1',

    public: {
      scanTarget: '127.0.0.1',
    },
  },
})
