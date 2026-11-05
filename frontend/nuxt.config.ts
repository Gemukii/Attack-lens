export default defineNuxtConfig({
  devtools: {
    enabled: true,
  },

  css: [
    '@fontsource-variable/newsreader/opsz.css',
    '@fontsource-variable/newsreader/opsz-italic.css',
    '@fontsource-variable/hanken-grotesk/wght.css',
    '~/assets/css/main.css',
  ],

  // Overridden at runtime by NUXT_API_INTERNAL_BASE, NUXT_API_KEY, NUXT_ALLOWED_HOSTS,
  // NUXT_DASHBOARD_PASSWORD, and NUXT_PUBLIC_SCAN_TARGET. Only the `public` section reaches the browser.
  runtimeConfig: {
    apiInternalBase: 'http://127.0.0.1:8000',
    apiKey: '',
    allowedHosts: 'localhost,127.0.0.1',
    dashboardPassword: '',

    public: {
      scanTarget: '127.0.0.1',
    },
  },
})
