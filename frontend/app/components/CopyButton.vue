<script setup lang="ts">
import { noticeDuration } from '~/utils/motion'

// Copies a command, and says so: the label gives way to "Copied" for a moment. Both labels
// share one cell, so the button keeps its width and nothing beside it moves.
const props = withDefaults(defineProps<{
  text: string
  label?: string
}>(), { label: 'Copy' })

const copied = ref(false)

const copy = async () => {
  await navigator.clipboard.writeText(props.text)
  copied.value = true
  setTimeout(() => (copied.value = false), noticeDuration())
}
</script>

<template>
  <button :class="['btn btn-small copy', { done: copied }]" type="button" @click="copy">
    <span class="labels">
      <span :class="{ shown: !copied }" :aria-hidden="copied || undefined">{{ label }}</span>
      <span :class="{ shown: copied }" :aria-hidden="!copied || undefined" role="status">Copied</span>
    </span>
  </button>
</template>
