```vue
<script setup lang="ts">
import type { Finding } from '~/types/scan'

const props = defineProps<{
  finding: Finding
}>()

const emit = defineEmits<{
  view: [finding: Finding]
}>()

const severityClass = computed(() => {
  switch (props.finding.severity?.toLowerCase()) {
    case 'critical':
      return 'critical'
    case 'high':
      return 'high'
    case 'medium':
      return 'medium'
    case 'low':
      return 'low'
    default:
      return 'unknown'
  }
})

const severityIcon = computed(() => {
  switch (props.finding.severity?.toLowerCase()) {
    case 'critical':
      return '●'
    case 'high':
      return '▲'
    case 'medium':
      return '◆'
    case 'low':
      return '●'
    default:
      return '•'
  }
})
</script>

<template>
  <article class="finding-card">
    <div :class="['finding-severity', severityClass]">
      {{ severityIcon }}
    </div>

    <div class="finding-content">
      <div class="finding-heading">
        <div>
          <span :class="['severity-badge', severityClass]">
            {{ finding.severity ?? 'Unknown' }}
          </span>

          <span v-if="finding.cve" class="cve">
            {{ finding.cve }}
          </span>
        </div>

        <span v-if="finding.cvss !== undefined" class="cvss">
          CVSS {{ finding.cvss }}
        </span>
      </div>

      <h4>
        {{ finding.title ?? finding.description ?? 'Security finding' }}
      </h4>

      <div class="finding-meta">
        <span v-if="finding.service">
          {{ finding.service }}
        </span>

        <span v-if="finding.port">
          Port {{ finding.port }}
        </span>

        <span v-if="finding.version">
          {{ finding.version }}
        </span>
      </div>

      <p v-if="finding.risk_reason" class="finding-reason">
        {{ finding.risk_reason }}
      </p>
    </div>

    <button
      class="finding-action"
      type="button"
      :aria-label="`View details for ${finding.title ?? 'security finding'}`"
      @click="emit('view', finding)"
    >
      View
      <span>→</span>
    </button>
  </article>
</template>
```
