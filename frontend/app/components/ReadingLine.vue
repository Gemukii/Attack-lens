<script setup lang="ts">
import { motionDuration } from '~/utils/motion'
import type { ReadingItem } from '~/utils/reading'

// The reading line: always there, same place and same height on every screen. It answers
// "can I trust this data" next to whatever the screen claims.
const props = defineProps<{
  items: ReadingItem[]
  loading?: boolean
}>()

// When what stands behind a value changes (a new reading, an agent that went quiet), the
// value keeps a tint for a moment. A clock that ticks ("2 h ago", "3 h ago") is not a change.
const changed = ref(new Set<string>())
let known = new Map<string, string>()
let primed = false
let timer: ReturnType<typeof setTimeout> | undefined

watch(() => props.items.map((item) => [item.id, item.stamp] as [string, string]), (stamps) => {
  const fresh = stamps.filter(([id, stamp]) => known.get(id) !== stamp).map(([id]) => id)
  known = new Map(stamps)
  // The first values are not a change: they are the page arriving.
  if (props.loading || !primed) {
    primed = !props.loading
    return
  }
  if (!fresh.length) return
  // Two facts replaced one after the other both keep their tint until the last one fades.
  changed.value = new Set([...changed.value, ...fresh])
  clearTimeout(timer)
  timer = setTimeout(() => (changed.value = new Set()), motionDuration('--dur-flash'))
}, { immediate: true })

onBeforeUnmount(() => clearTimeout(timer))
</script>

<template>
  <div class="reading-line" :aria-busy="loading || undefined">
    <dl class="shell reading" aria-label="About this reading">
      <div
        v-for="item in items"
        :key="item.id"
        :class="['reading-item', `reading-${item.id}`, { alert: item.alert && !loading, changed: changed.has(item.id) }]"
      >
        <dt class="t-label">{{ item.label }}</dt>
        <dd v-if="loading"><span class="skeleton skeleton-value" /></dd>
        <dd v-else :class="item.mono ? 't-data' : 't-body-s'" :title="item.title">
          <span v-if="item.lamp" :class="['lamp', `lamp-${item.lamp}`]" aria-hidden="true" />{{ item.value }}
        </dd>
      </div>
    </dl>
  </div>
</template>
