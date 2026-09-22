export default defineNuxtConfig({
  devtools: {
    enabled: true,
  },

  css: ['~/assets/css/main.css'],

  runtimeConfig: {
    apiInternalBase:
      (globalThis as {
        process?: { env?: Record<string, string | undefined> }
      }).process?.env?.API_INTERNAL_BASE || 'http://api:8000',

    public: {
      apiBase:
        (globalThis as {
          process?: { env?: Record<string, string | undefined> }
        }).process?.env?.NUXT_PUBLIC_API_BASE || 'http://localhost:8000',

      scanTarget:
        (globalThis as {
          process?: { env?: Record<string, string | undefined> }
        }).process?.env?.NUXT_PUBLIC_SCAN_TARGET || '127.0.0.1',
    },
  },
})

