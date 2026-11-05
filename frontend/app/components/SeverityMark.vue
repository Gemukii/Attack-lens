<script setup lang="ts">
// Severity reads like an aperture: the more open the circle is filled, the worse it is.
const props = defineProps<{
  severity?: string
  labelled?: boolean
}>()

const level = computed(() => props.severity?.toLowerCase() ?? 'info')
const word = computed(() => level.value.charAt(0).toUpperCase() + level.value.slice(1))
</script>

<template>
  <span class="severity">
    <svg viewBox="0 0 14 14" width="14" height="14" :aria-hidden="labelled ? 'true' : undefined" :aria-label="labelled ? undefined : level" role="img">
      <title>{{ word }}</title>
      <circle v-if="level === 'critical'" cx="7" cy="7" r="6" fill="var(--safelight)" />
      <circle v-else-if="level === 'info'" cx="7" cy="7" r="2" fill="var(--paper-dim)" />
      <circle v-else cx="7" cy="7" r="5.5" fill="none" stroke="var(--mark)" />
      <circle v-if="level === 'high'" cx="7" cy="7" r="3.6" fill="var(--safelight)" />
      <path v-else-if="level === 'medium'" d="M7 3.4a3.6 3.6 0 0 1 0 7.2z" fill="var(--safelight)" />
    </svg>
    <span v-if="labelled">{{ word }}</span>
  </span>
</template>
