```vue
<script setup lang="ts">
import type { Finding } from '~/types/scan'
import { useScan } from '~/composables/useScan'

const { results: scan, history, comparison, status, error, loadResults, loadHistory, compareScans, runScan } = useScan()
const config = useRuntimeConfig()
const target = ref(String(config.public.scanTarget || 'host.docker.internal'))
const showAllFindings = ref(false)
const selectedFinding = ref<Finding | null>(null)
const comparisonTarget = ref('')

onMounted(() => Promise.all([loadResults(), loadHistory()]))

const findings = computed<Finding[]>(() => scan.value?.findings ?? [])

const criticalCount = computed(() =>
  findings.value.filter(
    (finding) => finding.severity?.toLowerCase() === 'critical',
  ).length,
)

const highCount = computed(() =>
  findings.value.filter(
    (finding) => finding.severity?.toLowerCase() === 'high',
  ).length,
)

const mediumCount = computed(() =>
  findings.value.filter(
    (finding) => finding.severity?.toLowerCase() === 'medium',
  ).length,
)

const lowCount = computed(() =>
  findings.value.filter(
    (finding) => finding.severity?.toLowerCase() === 'low',
  ).length,
)

const openPorts = computed(() => {
  return scan.value?.open_ports?.length ?? 0
})

const score = computed(() => {
  return scan.value?.score ?? 0
})

const scoreLabel = computed(() => {
  if (!scan.value) return 'No scan yet'
  if (score.value >= 80) return 'Good'
  if (score.value >= 60) return 'Warning'
  return 'At risk'
})

const scoreClass = computed(() => {
  if (score.value >= 80) return 'good'
  if (score.value >= 60) return 'warning'
  return 'danger'
})

const scoreRingStyle = computed(() => ({
  '--score-angle': `${score.value * 3.6}deg`,
}))

const topFindings = computed(() => {
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  }

  return [...findings.value]
    .sort(
      (a, b) =>
        (severityOrder[a.severity?.toLowerCase() ?? 'low'] ?? 4) -
        (severityOrder[b.severity?.toLowerCase() ?? 'low'] ?? 4),
    )
    .slice(0, showAllFindings.value ? undefined : 5)
})

const lastScan = computed(() => scan.value?.completed_at ?? null)

const formattedDate = computed(() => {
  if (!lastScan.value) {
    return 'No scan completed'
  }

  const date = new Date(lastScan.value)

  if (Number.isNaN(date.getTime())) {
    return String(lastScan.value)
  }

  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
})

const formattedDuration = computed(() => {
  if (scan.value?.duration_seconds === undefined) {
    return '—'
  }

  return `${scan.value.duration_seconds.toFixed(1)}s`
})
const refreshScan = () => Promise.all([loadResults(), loadHistory()])

const compareWithSelectedScan = () => {
  if (comparisonTarget.value && scan.value?.scan_id) {
    return compareScans(comparisonTarget.value, scan.value.scan_id)
  }
}
const scanStatusLabel = computed(() => ({
  idle: 'Ready',
  loading: 'Loading results',
  running: 'Scanning...',
  completed: 'Completed',
  failed: 'Failed',
}[status.value]))

const startScan = async () => {
  await runScan(target.value.trim() || String(config.public.scanTarget || 'host.docker.internal'))
}

</script>

<template>
  <main class="dashboard">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">
          <span />
          <span />
          <span />
        </div>

        <div>
          <h1>AttackLens</h1>
          <p>Security overview</p>
        </div>
      </div>

      <div class="topbar-actions">
        <div class="scan-status">
          <span :class="['status-dot', { running: status === 'running' } ]" />
          <span>{{ scanStatusLabel }}</span>
        </div>

        <button class="refresh-button" type="button" @click="refreshScan">
          <span>↻</span>
          Refresh
        </button>

        <button
          class="run-button"
          type="button"
          :disabled="status === 'running'"
          @click="startScan"
        >
          {{ status === 'running' ? 'Scanning...' : 'Run scan' }}
        </button>
      </div>
    </header>

    <section class="hero">
      <div>
        <p class="eyebrow">SECURITY OVERVIEW</p>
        <h2>Your security at a glance.</h2>
        <p class="hero-description">
          Monitor vulnerabilities, exposed services and the overall security
          posture of your target.
        </p>
      </div>

      <div class="target-card">
        <span class="target-label">TARGET</span>
        <input v-model="target" aria-label="Scan target" :disabled="status === 'running'" />
        <small v-if="scan">Last scan: {{ scan.target }}</small>
      </div>
    </section>

    <div v-if="error" class="error-banner">
      <div>
        <strong>Unable to load scan results</strong>
        <span>
          {{ error }}
        </span>
      </div>

      <button type="button" @click="refreshScan">
        Retry
      </button>
    </div>

    <div v-if="status === 'loading'" class="loading-banner">
      Loading the latest scan results...
    </div>

    <section class="overview-grid">
      <article :class="['score-card', scoreClass]">
        <div class="card-heading">
          <div>
            <span class="card-label">SECURITY SCORE</span>
            <h3>Overall posture</h3>
          </div>

          <span :class="['score-status', scoreClass]">
            {{ scoreLabel }}
          </span>
        </div>

        <div class="score-content">
          <div class="score-ring" :class="scoreClass" :style="scoreRingStyle">
            <div>
              <strong>{{ score }}</strong>
              <span>/ 100</span>
            </div>
          </div>

          <div class="score-info">
            <p>
              Based on the vulnerabilities and network exposure detected during
              the latest scan.
            </p>

            <div class="score-bar">
              <span
                :style="{ width: `${score}%` }"
              />
            </div>
          </div>
        </div>
      </article>

      <StatCard
        label="Critical"
        title="Immediate action"
        :value="criticalCount"
        variant="critical"
        description="Critical findings"
      />

      <StatCard
        label="High"
        title="High priority"
        :value="highCount"
        variant="high"
        description="High severity findings"
      />

      <StatCard
        label="Open ports"
        title="Network exposure"
        :value="openPorts"
        variant="neutral"
        description="Detected open ports"
      />
    </section>

    <section class="content-grid">
      <article class="panel findings-panel">
        <div class="panel-header">
          <div>
            <span class="card-label">PRIORITY</span>
            <h3>Security findings</h3>
          </div>

          <span class="count-badge">
            {{ findings.length }} total
          </span>
        </div>

        <div v-if="topFindings.length" class="findings-list">
          <FindingCard
            v-for="(finding, index) in topFindings"
            :key="finding.id ?? finding.cve ?? index"
            :finding="finding"
            @view="selectedFinding = $event"
          />
        </div>

        <button
          v-if="findings.length > 5"
          class="show-all-button"
          type="button"
          @click="showAllFindings = !showAllFindings"
        >
          {{ showAllFindings ? 'Show priority findings' : 'View all findings' }}
        </button>

        <div v-else-if="!scan" class="empty-state">
          <div class="empty-icon">—</div>
          <strong>No scan available</strong>
          <p>Run a scan to build the first security overview.</p>
        </div>

        <div v-else class="empty-state">
          <div class="empty-icon">✓</div>
          <strong>No findings detected</strong>
          <p>
            AttackLens did not report any vulnerabilities for this scan.
          </p>
        </div>
      </article>

      <article class="panel distribution-panel">
        <div class="panel-header">
          <div>
            <span class="card-label">BREAKDOWN</span>
            <h3>Severity distribution</h3>
          </div>
        </div>

        <div class="severity-list">
          <div class="severity-row">
            <div class="severity-name">
              <span class="severity-dot critical" />
              <span>Critical</span>
            </div>

            <strong>{{ criticalCount }}</strong>
          </div>

          <div class="severity-track">
            <span
              class="critical"
              :style="{
                width: `${findings.length ? (criticalCount / findings.length) * 100 : 0}%`,
              }"
            />
          </div>

          <div class="severity-row">
            <div class="severity-name">
              <span class="severity-dot high" />
              <span>High</span>
            </div>

            <strong>{{ highCount }}</strong>
          </div>

          <div class="severity-track">
            <span
              class="high"
              :style="{
                width: `${findings.length ? (highCount / findings.length) * 100 : 0}%`,
              }"
            />
          </div>

          <div class="severity-row">
            <div class="severity-name">
              <span class="severity-dot medium" />
              <span>Medium</span>
            </div>

            <strong>{{ mediumCount }}</strong>
          </div>

          <div class="severity-track">
            <span
              class="medium"
              :style="{
                width: `${findings.length ? (mediumCount / findings.length) * 100 : 0}%`,
              }"
            />
          </div>

          <div class="severity-row">
            <div class="severity-name">
              <span class="severity-dot low" />
              <span>Low</span>
            </div>

            <strong>{{ lowCount }}</strong>
          </div>

          <div class="severity-track">
            <span
              class="low"
              :style="{
                width: `${findings.length ? (lowCount / findings.length) * 100 : 0}%`,
              }"
            />
          </div>
        </div>
      </article>
    </section>

    <section class="bottom-grid">
      <article class="panel">
        <div class="panel-header">
          <div>
            <span class="card-label">NETWORK</span>
            <h3>Exposure overview</h3>
          </div>
        </div>

        <div class="network-stat">
          <div class="network-number">
            {{ openPorts }}
          </div>

          <div>
            <strong>Open ports detected</strong>
            <p>
              Review exposed services and make sure only required services are
              reachable.
            </p>
          </div>
        </div>

        <div class="network-footer">
          <span>Network surface</span>
          <strong>
            {{ openPorts ? `${openPorts} exposed service${openPorts === 1 ? '' : 's'}` : 'No open ports detected' }}
          </strong>
        </div>

        <ul v-if="scan?.services?.length" class="service-list">
          <li v-for="service in scan.services" :key="`${service.name}-${service.port}`">
            <span>{{ service.name }}</span>
            <span>{{ service.protocol?.toUpperCase() ?? 'TCP' }} / {{ service.port }}</span>
          </li>
        </ul>
      </article>

      <article class="panel">
        <div class="panel-header">
          <div>
            <span class="card-label">SCAN</span>
            <h3>Latest scan</h3>
          </div>
        </div>

        <dl class="scan-details">
          <div>
            <dt>Target</dt>
            <dd>{{ scan?.target ?? '—' }}</dd>
          </div>

          <div>
            <dt>Completed</dt>
            <dd>{{ formattedDate }}</dd>
          </div>

          <div>
            <dt>Duration</dt>
            <dd>{{ formattedDuration }}</dd>
          </div>

          <div>
            <dt>Findings</dt>
            <dd>{{ findings.length }}</dd>
          </div>
        </dl>
      </article>

      <article class="panel comparison-panel">
        <div class="panel-header">
          <div>
            <span class="card-label">CHANGE ANALYSIS</span>
            <h3>Compare with a previous scan</h3>
          </div>
        </div>

        <div v-if="scan?.scan_id && history.length > 1" class="comparison-controls">
          <select v-model="comparisonTarget" aria-label="Previous scan to compare">
            <option disabled value="">Select a previous scan</option>
            <option
              v-for="item in history.filter((entry) => entry.scan_id !== scan?.scan_id)"
              :key="item.scan_id"
              :value="item.scan_id"
            >
              {{ item.completed_at ? new Date(item.completed_at).toLocaleString() : item.scan_id }}
            </option>
          </select>
          <button class="show-all-button" type="button" :disabled="!comparisonTarget" @click="compareWithSelectedScan">
            Compare
          </button>
        </div>

        <div v-if="comparison" class="comparison-summary">
          <div><strong>{{ comparison.score_delta > 0 ? '+' : '' }}{{ comparison.score_delta }}</strong><span>score change</span></div>
          <div><strong>{{ comparison.new_findings.length }}</strong><span>new findings</span></div>
          <div><strong>{{ comparison.fixed_findings.length }}</strong><span>fixed findings</span></div>
          <div><strong>{{ comparison.persistent_findings.length }}</strong><span>still present</span></div>
          <p>Ports added: {{ comparison.ports_added.length ? comparison.ports_added.join(', ') : 'none' }}. Ports removed: {{ comparison.ports_removed.length ? comparison.ports_removed.join(', ') : 'none' }}.</p>
        </div>

        <div v-else class="history-empty">
          Run at least two scans to compare changes over time.
        </div>
      </article>
    </section>

    <div
      v-if="selectedFinding"
      class="modal-backdrop"
      role="presentation"
      @click.self="selectedFinding = null"
    >
      <article
        class="finding-modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-modal-title"
      >
        <div class="modal-header">
          <div>
            <span :class="['severity-badge', selectedFinding.severity?.toLowerCase() ?? 'unknown']">
              {{ selectedFinding.severity ?? 'Unknown' }}
            </span>
            <h3 id="finding-modal-title">
              {{ selectedFinding.title ?? 'Security finding' }}
            </h3>
          </div>
          <button class="modal-close" type="button" aria-label="Close details" @click="selectedFinding = null">
            ×
          </button>
        </div>

        <p class="modal-description">
          {{ selectedFinding.description ?? 'No description provided.' }}
        </p>

        <div v-if="selectedFinding.risk_reason" class="risk-summary">
          <span class="card-label">WHY IT MATTERS</span>
          <p>{{ selectedFinding.risk_reason }}</p>
        </div>

        <dl class="finding-details">
          <div v-if="selectedFinding.cve">
            <dt>CVE</dt>
            <dd>{{ selectedFinding.cve }}</dd>
          </div>
          <div v-if="selectedFinding.cvss !== undefined">
            <dt>CVSS</dt>
            <dd>{{ selectedFinding.cvss }}</dd>
          </div>
          <div v-if="selectedFinding.service">
            <dt>Service</dt>
            <dd>{{ selectedFinding.service }}</dd>
          </div>
          <div v-if="selectedFinding.port">
            <dt>Port</dt>
            <dd>{{ selectedFinding.port }}</dd>
          </div>
          <div v-if="selectedFinding.version">
            <dt>Version</dt>
            <dd>{{ selectedFinding.version }}</dd>
          </div>
          <div v-if="selectedFinding.evidence">
            <dt>Evidence</dt>
            <dd>{{ selectedFinding.evidence }}</dd>
          </div>
          <div v-if="selectedFinding.banner">
            <dt>Banner</dt>
            <dd>{{ selectedFinding.banner }}</dd>
          </div>
        </dl>

        <div v-if="selectedFinding.remediation" class="remediation">
          <span class="card-label">RECOMMENDATION</span>
          <p>{{ selectedFinding.remediation }}</p>
        </div>
      </article>
    </div>

    <footer>
      <span>AttackLens</span>
      <span>Network security scanner</span>
    </footer>
  </main>
</template>
```
