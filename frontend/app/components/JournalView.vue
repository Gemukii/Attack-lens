<script setup lang="ts">
import type { Alert, AuditEntry, ScanComparison, ScanHistory } from '~/types/scan'

const props = defineProps<{
  alerts: Alert[]
  audit: AuditEntry[]
  history: ScanHistory
  comparison: ScanComparison | null
  currentScanId?: string
}>()

const emit = defineEmits<{
  compare: [scanId: string]
}>()

const selected = ref('')
const previous = computed(() => props.history.filter((scan) => scan.scan_id !== props.currentScanId))

const ACTIONS: Record<string, string> = {
  scan_ordered: 'Scan requested',
  finding_accepted: 'Risk accepted',
  finding_false_positive: 'Marked as a false positive',
  finding_reopened: 'Finding reopened',
  agent_enrolled: 'Machine enrolled',
  agent_revoked: 'Machine revoked',
  enrollment_code_created: 'Enrollment code created',
  enrollment_refused: 'Enrollment refused',
  report_generated: 'Report generated',
  report_refused: 'Report refused',
  backup_created: 'Backup created',
  backup_failed: 'Backup failed',
  engagement_created: 'Engagement recorded',
  scan_refused: 'Scan refused',
}

const delta = computed(() => {
  const value = props.comparison?.score_delta
  if (value === null || value === undefined) return 'no score'
  return `${value > 0 ? '+' : ''}${value}`
})
</script>

<template>
  <div class="journal">
    <header class="page-head">
      <h1>What changed</h1>
      <p class="lead">Everything new since the first reading, and every decision taken here.</p>
    </header>

    <div class="journal-grid">
      <section aria-labelledby="changes-title">
        <h2 id="changes-title">Changes</h2>
        <ol v-if="alerts.length" class="timeline">
          <li v-for="alert in alerts.slice(0, 8)" :key="alert.alert_id">
            <time :datetime="alert.created_at">{{ formatDate(alert.created_at) }}</time>
            <p>{{ alert.findings.length ? alert.findings[0]?.title : alert.message.replace('AttackLens: ', '') }}</p>
            <p v-if="alert.findings.length > 1" class="note">and {{ alert.findings.length - 1 }} more on {{ alert.target }}</p>
          </li>
        </ol>
        <p v-else class="note">Nothing new so far.</p>

        <form v-if="currentScanId && previous.length" class="compare" @submit.prevent="selected && emit('compare', selected)">
          <label for="compare-with">Compare the last reading with</label>
          <div>
            <select id="compare-with" v-model="selected">
              <option disabled value="">a previous one</option>
              <option v-for="scan in previous" :key="scan.scan_id" :value="scan.scan_id">{{ formatDate(scan.completed_at) }}</option>
            </select>
            <button class="link" type="submit" :disabled="!selected">Compare</button>
          </div>
          <p v-if="comparison" class="note">
            Score {{ delta }}. {{ comparison.new_findings.length }} new, {{ comparison.fixed_findings.length }} fixed.
            Ports opened: {{ comparison.ports_added.join(', ') || 'none' }}. Closed: {{ comparison.ports_removed.join(', ') || 'none' }}.
          </p>
        </form>
      </section>

      <section aria-labelledby="log-title">
        <h2 id="log-title">Decisions</h2>
        <ol v-if="audit.length" class="log">
          <li v-for="entry in audit" :key="entry.entry_id">
            <span>{{ ACTIONS[entry.action] ?? entry.action }}</span>
            <time class="note" :datetime="entry.at">{{ formatDate(entry.at) }}</time>
          </li>
        </ol>
        <p v-else class="note">Nothing yet.</p>
      </section>
    </div>
  </div>
</template>
