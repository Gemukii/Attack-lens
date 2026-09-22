```vue
<script setup lang="ts">
defineProps<{
  label: string
  title: string
  value: number | string
  description: string
  variant?: 'critical' | 'high' | 'neutral'
}>()
</script>

<template>
  <article :class="['stat-card', variant ?? 'neutral']">
    <div class="stat-top">
      <span class="card-label">{{ label }}</span>
      <span class="stat-indicator" />
    </div>

    <div class="stat-value">
      {{ value }}
    </div>

    <div class="stat-bottom">
      <strong>{{ title }}</strong>
      <span>{{ description }}</span>
    </div>
  </article>
</template>
```
