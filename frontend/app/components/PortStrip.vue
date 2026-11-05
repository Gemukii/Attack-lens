<script setup lang="ts">
import type { ScanService } from '~/types/scan'

// One perforation per scanned port, like the edge of a film strip.
const props = defineProps<{
  states: Record<string, string>
  services: ScanService[]
}>()

const focused = ref<string | null>(null)

const cells = computed(() =>
  Object.entries(props.states)
    .map(([port, state]) => ({ port: Number(port), state }))
    .sort((a, b) => a.port - b.port),
)

const count = (state: string) => cells.value.filter((cell) => cell.state === state).length

const describe = (cell: { port: number; state: string }) => {
  const service = props.services.find((item) => item.port === cell.port)
  return `${cell.port}/tcp ${cell.state}${service ? ` · ${service.name}` : ''}`
}
</script>

<template>
  <div class="port-strip">
    <div class="port-cells" :style="{ '--ports': cells.length }">
      <button
        v-for="(cell, index) in cells"
        :key="cell.port"
        type="button"
        :class="['port-cell', cell.state]"
        :style="{ '--i': index }"
        :aria-label="describe(cell)"
        :title="describe(cell)"
        @mouseenter="focused = describe(cell)"
        @mouseleave="focused = null"
        @focus="focused = describe(cell)"
        @blur="focused = null"
      />
    </div>
    <div class="port-key">
      <ul>
        <li><i class="open" /> {{ count('open') }} open</li>
        <li><i /> {{ count('closed') }} closed</li>
        <li><i class="filtered" /> {{ count('filtered') }} filtered</li>
      </ul>
      <span class="port-focus" aria-live="polite">{{ focused ?? `${cells.length} common TCP ports` }}</span>
    </div>
  </div>
</template>
