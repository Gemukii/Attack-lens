<script setup lang="ts">
import plexMono400 from '~/assets/fonts/ibm-plex-mono-latin-400-normal.woff2?url'
import plexMono500 from '~/assets/fonts/ibm-plex-mono-latin-500-normal.woff2?url'
import plexSans400 from '~/assets/fonts/ibm-plex-sans-latin-400-normal.woff2?url'
import plexSans500 from '~/assets/fonts/ibm-plex-sans-latin-500-normal.woff2?url'

useHead({
  title: 'AttackLens',
  htmlAttrs: { lang: 'en' },
  // A meta tag cannot read a CSS variable: this is --bg-base, written once more on purpose.
  meta: [{ name: 'theme-color', content: '#0b0a09' }],
  link: [
    { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' },
    // Fetched before the first paint, so that text never re-flows when a font arrives.
    ...[plexSans400, plexSans500, plexMono400, plexMono500].map((href) => ({ rel: 'preload', as: 'font' as const, type: 'font/woff2', href, crossorigin: 'anonymous' as const })),
  ],
})
</script>

<template>
  <NuxtPage />
</template>
