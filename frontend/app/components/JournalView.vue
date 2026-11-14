<script setup lang="ts">
import { useIndicator } from '~/composables/useIndicator'
import type { Alert, AuditEntry, ScanComparison, ScanHistory } from '~/types/scan'
import { SCORE_DROP_ALERT } from '~/utils/brief'
import { ago, signed } from '~/utils/format'

// What changed since last time, who decided what, and whether the score is getting better
// or worse.
const props = withDefaults(defineProps<{
  alerts: Alert[]
  fresh?: Set<number>
  audit: AuditEntry[]
  history: ScanHistory
  comparison: ScanComparison | null
  currentScanId?: string
  loading?: boolean
  now?: number
}>(), { loading: false, now: () => Date.now() })

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

// The score over time. Three readings are not a trend, and the screen says so.
const PERIODS = [
  { id: 5, label: 'Last 5' },
  { id: 10, label: 'Last 10' },
  { id: 0, label: 'All' },
]
const MIN_READINGS_FOR_TREND = 4
const period = ref(10)

// The thumb of the period control slides from one choice to the next.
const periodElement = ref<HTMLElement | null>(null)
const { style: periodIndicator, ready: periodReady } = useIndicator(periodElement, '[aria-pressed="true"]', () => [period.value, props.loading])

const scored = computed(() => [...props.history]
  .filter((scan) => typeof scan.score === 'number' && scan.completed_at)
  .sort((a, b) => (a.completed_at ?? '').localeCompare(b.completed_at ?? '')))
const shown = computed(() => (period.value ? scored.value.slice(-period.value) : scored.value))
const columns = computed(() => shown.value.map((scan, index) => ({
  key: scan.scan_id ?? `${scan.completed_at}-${index}`,
  value: scan.score as number,
  title: `${scan.score} of 100, ${formatDate(scan.completed_at)}`,
})))
const last = computed(() => shown.value.at(-1))
const before = computed(() => shown.value.at(-2))
const scoreDelta = computed(() => (last.value && before.value ? (last.value.score as number) - (before.value.score as number) : null))
const dropped = computed(() => scoreDelta.value !== null && scoreDelta.value <= -SCORE_DROP_ALERT)
const span = computed(() => {
  const first = shown.value[0]
  if (!first || !last.value || shown.value.length < 2) return ''
  return `${shown.value.length} readings, from ${ago(first.completed_at, props.now)} to ${ago(last.value.completed_at, props.now)}`
})

const delta = computed(() => {
  const value = props.comparison?.score_delta
  return value === null || value === undefined ? 'Not scored' : signed(value)
})
const scoreDropped = computed(() => (props.comparison?.score_delta ?? 0) <= -SCORE_DROP_ALERT)
</script>

<template>
  <div v-if="loading" class="journal" aria-busy="true" aria-label="Loading the journal">
    <header class="page-head">
      <span class="skeleton skeleton-title" />
      <span class="skeleton skeleton-line" />
    </header>
    <span class="skeleton skeleton-trend" />
    <div class="grid">
      <div class="span-8"><span v-for="index in 6" :key="index" class="skeleton skeleton-row" /></div>
      <div class="span-4"><span v-for="index in 6" :key="index" class="skeleton skeleton-row" /></div>
    </div>
  </div>

  <div v-else class="journal settled">
    <header class="page-head">
      <h1 class="t-heading-l">What changed</h1>
      <p class="t-body-m text-secondary">Everything new since the first reading, and every decision taken here.</p>
    </header>

    <section class="trend" aria-labelledby="trend-title">
      <div class="trend-head">
        <h2 id="trend-title" class="t-label">Network score</h2>
        <div v-if="scored.length > 1" ref="periodElement" :class="['segments', { 'has-indicator': periodReady }]" role="group" aria-label="Period">
          <span class="indicator" :style="periodIndicator" aria-hidden="true" />
          <button
            v-for="item in PERIODS"
            :key="item.id"
            type="button"
            class="segment t-body-s"
            :aria-pressed="period === item.id"
            @click="period = item.id"
          >
            {{ item.label }}
          </button>
        </div>
      </div>
      <div v-if="last" class="trend-body">
        <p class="trend-figure">
          <span class="t-display">{{ last.score }}</span>
          <span class="trend-notes">
            <span class="t-body-s text-muted">of 100, higher is better</span>
            <span v-if="scoreDelta !== null" :class="['t-heading-m', dropped ? 'text-alert' : 'text-muted']">{{ signed(scoreDelta) }} since the reading before</span>
          </span>
        </p>
        <div class="trend-chart">
          <ScoreColumns tall :columns="columns" :alert="dropped" :label="`Network score over ${columns.length} readings, on a scale of 100. Last: ${last.score}.`" />
          <p class="t-body-s text-muted">
            {{ span || 'One reading so far.' }}<template v-if="shown.length > 1 && shown.length < MIN_READINGS_FOR_TREND">. Too few to call it a trend.</template>
          </p>
        </div>
      </div>
      <p v-else class="t-body-m text-muted">No scored reading yet.</p>
    </section>

    <div class="grid">
      <section class="span-8" aria-labelledby="changes-title">
        <h2 id="changes-title" class="t-label section-rule">Changes</h2>
        <!-- A new line slides in at the top, and keeps a tint for a moment. -->
        <TransitionGroup v-if="alerts.length" name="rows" tag="ol" class="timeline">
          <li v-for="(alert, index) in alerts.slice(0, 8)" :key="alert.alert_id" :class="{ arrived: fresh?.has(alert.alert_id) }" :style="{ '--i': index }">
            <time class="t-body-s text-muted" :datetime="alert.created_at" :title="formatDate(alert.created_at)">{{ ago(alert.created_at, now) }}</time>
            <span class="t-body-m">
              {{ alert.findings.length ? alert.findings[0]?.title : alert.message.replace('AttackLens: ', '') }}
              <span v-if="alert.findings.length > 1" class="text-muted">and {{ alert.findings.length - 1 }} more</span>
            </span>
            <span class="t-data text-muted timeline-target">{{ alert.target }}</span>
          </li>
        </TransitionGroup>
        <p v-else class="t-body-m text-muted">Nothing new so far.</p>

        <form v-if="currentScanId && previous.length" class="compare" @submit.prevent="selected && emit('compare', selected)">
          <label for="compare-with" class="t-label">Compare the last reading with</label>
          <div class="compare-row">
            <select id="compare-with" v-model="selected" class="field t-body-s">
              <option disabled value="">a previous one</option>
              <option v-for="scan in previous" :key="scan.scan_id" :value="scan.scan_id">{{ formatDate(scan.completed_at) }}</option>
            </select>
            <button class="btn" type="submit" :disabled="!selected">Compare</button>
          </div>
          <dl v-if="comparison" class="compare-result">
            <div><dt class="t-label">Score</dt><dd :class="['t-data-l', { 'text-alert': scoreDropped }]">{{ delta }}</dd></div>
            <div><dt class="t-label">New</dt><dd class="t-data-l">{{ comparison.new_findings.length }}</dd></div>
            <div><dt class="t-label">Fixed</dt><dd class="t-data-l">{{ comparison.fixed_findings.length }}</dd></div>
            <div><dt class="t-label">Ports opened</dt><dd class="t-data">{{ comparison.ports_added.join(', ') || 'none' }}</dd></div>
            <div><dt class="t-label">Ports closed</dt><dd class="t-data">{{ comparison.ports_removed.join(', ') || 'none' }}</dd></div>
          </dl>
        </form>
      </section>

      <section class="span-4" aria-labelledby="log-title">
        <h2 id="log-title" class="t-label section-rule">Audit log</h2>
        <ol v-if="audit.length" class="log">
          <li v-for="(entry, index) in audit" :key="entry.entry_id" class="t-body-s" :style="{ '--i': index }">
            <span>{{ ACTIONS[entry.action] ?? entry.action }}<span v-if="entry.detail" class="text-muted">, {{ entry.detail }}</span></span>
            <time class="t-body-s text-muted" :datetime="entry.at" :title="formatDate(entry.at)">{{ ago(entry.at, now) }}</time>
          </li>
        </ol>
        <p v-else class="t-body-m text-muted">Nothing yet.</p>
      </section>
    </div>
  </div>
</template>
