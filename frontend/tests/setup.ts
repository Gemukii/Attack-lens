import { config } from '@vue/test-utils'
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'

import { formatDate } from '~/utils/format'

// Nuxt provides these automatically. Plain Vitest needs them spelled out.
Object.assign(globalThis, { computed, formatDate, nextTick, onBeforeUnmount, onMounted, ref, watch })

config.global.mocks = { formatDate }
config.global.stubs = { SeverityMark: { template: '<i class="mark" />' } }

window.matchMedia = ((query: string) => ({ matches: false, media: query })) as typeof window.matchMedia
