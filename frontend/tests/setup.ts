import { config } from '@vue/test-utils'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'

import SeverityMark from '~/components/SeverityMark.vue'
import { formatDate } from '~/utils/format'

// Nuxt provides these automatically. Plain Vitest needs them spelled out.
Object.assign(globalThis, { computed, formatDate, nextTick, onBeforeUnmount, onMounted, ref, watch })

config.global.mocks = { formatDate }
config.global.components = { SeverityMark }

globalThis.ResizeObserver ??= class {
  observe() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

window.matchMedia = ((query: string) => ({ matches: false, media: query })) as typeof window.matchMedia
