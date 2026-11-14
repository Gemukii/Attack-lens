<script setup lang="ts">
// One column per reading, on the fixed scale of the score (0 to 100). Exact, and readable
// at a small size, where a line is not. When the period changes, columns that stay slide to
// their new place and grow or shrink there: only transforms and opacity move.
export interface ScoreColumn {
  key: string
  value: number
  title?: string
}

const props = withDefaults(defineProps<{
  columns: ScoreColumn[]
  alert?: boolean
  label: string
  tall?: boolean
}>(), { alert: false, tall: false })

const bars = computed(() => props.columns.map((column, index) => ({
  ...column,
  share: Math.max(0.04, Math.min(1, column.value / 100)),
  last: index === props.columns.length - 1,
})))
</script>

<template>
  <TransitionGroup v-if="bars.length > 1" name="columns" tag="span" :class="['score-columns', { tall }]" role="img" :aria-label="label">
    <span v-for="(bar, index) in bars" :key="bar.key" class="score-column" :title="bar.title" :style="{ '--i': index }">
      <i :class="{ last: bar.last, alert: bar.last && alert }" :style="{ transform: `scaleY(${bar.share})` }" />
    </span>
  </TransitionGroup>
</template>
