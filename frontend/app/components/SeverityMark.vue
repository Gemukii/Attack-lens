<script setup lang="ts">
// Severity is an intensity: four cells, lit from the left, and red only when all four are.
// It always comes with its word.
const props = withDefaults(defineProps<{
  severity?: string
  labelled?: boolean
}>(), { labelled: true })

const LEVELS: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

const level = computed(() => props.severity?.toLowerCase() ?? 'info')
const lit = computed(() => LEVELS[level.value] ?? 0)
const word = computed(() => level.value.charAt(0).toUpperCase() + level.value.slice(1))
</script>

<template>
  <span :class="['severity', `severity-${level}`]">
    <svg class="severity-mark" viewBox="0 0 22.5 9" width="22.5" height="9" :aria-hidden="labelled ? 'true' : undefined" :aria-label="labelled ? undefined : word" role="img">
      <title>{{ word }}</title>
      <rect v-for="index in 4" :key="index" :x="(index - 1) * 6" y="0" width="4.5" height="9" :class="{ lit: index <= lit }" />
    </svg>
    <span v-if="labelled" class="severity-word">{{ word }}</span>
  </span>
</template>
