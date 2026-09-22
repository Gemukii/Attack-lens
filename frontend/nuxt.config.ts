export default defineNuxtConfig({
  devtools: {
    enabled: true,
  },

  runtimeConfig: {
    public: {
      apiBase: (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.NUXT_PUBLIC_API_BASE || 'http://localhost:8000',
    },
  },
})