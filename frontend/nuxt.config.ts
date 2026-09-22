export default defineNuxtConfig({
  devtools: {
    enabled: true,
  },

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
    },
  },
})