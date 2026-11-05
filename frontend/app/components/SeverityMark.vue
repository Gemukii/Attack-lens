<script setup lang="ts">
const props = defineProps<{
  severity?: string
  labelled?: boolean
}>()

const level = computed(() => props.severity?.toLowerCase() ?? 'info')
</script>

<template>
  <span class="mark" :class="level" :aria-hidden="labelled ? 'true' : undefined" :aria-label="labelled ? undefined : level" />
  <span v-if="labelled" class="severity-label">{{ level }}</span>
</template>
