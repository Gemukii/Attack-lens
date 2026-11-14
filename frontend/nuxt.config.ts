// Demo mode answers API calls from fixtures/demo-*.json. It only exists in development:
// `$development` is dropped by `nuxt build`, so the handler, the banner and the fixtures
// never reach a production bundle, whatever the environment says.
const demo = process.env.ATTACKLENS_DEMO === '1'

export default defineNuxtConfig({
  devtools: {
    enabled: true,
  },

  css: [
    // Typefaces are bundled with the application rather than fetched: see ADR-0010.
    '~/assets/css/tokens/fonts.css',
    // Tokens first: primitives, then what they mean, then per-component decisions.
    '~/assets/css/tokens/primitives.css',
    '~/assets/css/tokens/semantic.css',
    '~/assets/css/tokens/components.css',
    '~/assets/css/tokens/typography.css',
    '~/assets/css/tokens/spacing.css',
    '~/assets/css/tokens/motion.css',
    // Then the styles, one file per part of the interface.
    '~/assets/css/base.css',
    '~/assets/css/frame.css',
    '~/assets/css/brief.css',
    '~/assets/css/lists.css',
    '~/assets/css/drawer.css',
    '~/assets/css/states.css',
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

  $development: demo
    ? {
        css: ['~~/demo/banner.css'],
        plugins: ['~~/demo/banner.client.ts'],
        serverHandlers: [{ middleware: true, handler: '~~/demo/handler.ts' }],
      }
    : undefined,
})
