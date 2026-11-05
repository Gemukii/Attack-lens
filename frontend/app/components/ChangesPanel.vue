<script setup lang="ts">
import type { Alert, ScanComparison, ScanHistory } from '~/types/scan'

const props = defineProps<{
  alerts: Alert[]
  history: ScanHistory
  comparison: ScanComparison | null
  currentScanId?: string
}>()

const emit = defineEmits<{
  compare: [scanId: string]
}>()

const selected = ref('')

const previousScans = computed(() =>
  props.history.filter((scan) => scan.scan_id !== props.currentScanId),
)

const delta = computed(() => {
  const value = props.comparison?.score_delta
  if (value === null || value === undefined) return '—'
  return `${value > 0 ? '+' : ''}${value}`
})
</script>

<template>
  <div class="changes">
    <section>
      <div class="panel-head">
        <div>
          <span class="eyebrow">Changes</span>
          <h2 class="section-title">Since last time</h2>
        </div>
      </div>

      <ul v-if="alerts.length">
        <li v-for="alert in alerts.slice(0, 4)" :key="alert.alert_id" class="alert-item">
          <strong>{{ alert.findings.length }} new on {{ alert.target }}</strong>
          <time :datetime="alert.created_at">{{ formatDate(alert.created_at) }}</time>
          <span v-for="finding in alert.findings.slice(0, 3)" :key="finding.finding_id">{{ finding.title }}</span>
        </li>
      </ul>
      <p v-else class="note">Nothing new since the first scan of each target.</p>
    </section>

    <section>
      <span class="eyebrow">Compare with</span>

      <form v-if="currentScanId && previousScans.length" class="compare-form" @submit.prevent="selected && emit('compare', selected)">
        <select v-model="selected" aria-label="Previous scan to compare">
          <option disabled value="">A previous scan</option>
          <option v-for="scan in previousScans" :key="scan.scan_id" :value="scan.scan_id">
            {{ formatDate(scan.completed_at) }}
          </option>
        </select>
        <button class="button small" type="submit" :disabled="!selected">Compare</button>
      </form>
      <p v-else class="note">Run a second scan of this target to compare.</p>

      <div v-if="comparison" class="compare-result">
        <div><strong>{{ delta }}</strong><span>score</span></div>
        <div><strong>{{ comparison.new_findings.length }}</strong><span>new</span></div>
        <div><strong>{{ comparison.fixed_findings.length }}</strong><span>fixed</span></div>
        <p>
          Ports added: {{ comparison.ports_added.join(', ') || 'none' }}.
          Removed: {{ comparison.ports_removed.join(', ') || 'none' }}.
        </p>
      </div>
    </section>
  </div>
</template>
