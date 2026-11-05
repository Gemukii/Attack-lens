<script setup lang="ts">
import type { Finding, TriageStatus } from '~/types/scan'
import { useScan } from '~/composables/useScan'

const { results: scan, history, comparison, inventory, vulnerabilities, posture, hostReport, alerts, agent, status, error, loadAll, loadAgents, compareScans, runScan, setTriage } = useScan()
const config = useRuntimeConfig()
const dockerTarget = String(config.public.scanTarget)

const target = ref('')
const selectedFinding = ref<Finding | null>(null)
const copied = ref(false)
const scanning = computed(() => status.value === 'running')
const AGENT_COMMAND = 'attacklens agent --watch --api-url http://127.0.0.1:8000'

let agentTimer: ReturnType<typeof setInterval> | undefined

onMounted(() => {
  loadAll()
  agentTimer = setInterval(loadAgents, 4000)
})
onBeforeUnmount(() => clearInterval(agentTimer))

const findings = computed<Finding[]>(() => scan.value?.findings ?? [])
const isOpen = (finding: Finding) => (finding.triage_status ?? 'open') === 'open'
const openFindings = computed(() => findings.value.filter(isOpen))
const noResponse = computed(() => scan.value?.status === 'no_response')
const score = computed(() => scan.value?.score ?? null)
const animatedScore = useAnimatedNumber(score)

const severityCount = (severity: string) =>
  openFindings.value.filter((finding) => finding.severity?.toLowerCase() === severity).length

const tally = computed(() =>
  ['critical', 'high', 'medium', 'low'].map((severity) => ({ severity, count: severityCount(severity) })),
)

const verdict = computed(() => {
  if (!scan.value) return 'No reading'
  if (noResponse.value) return 'No response'
  if (score.value === null) return 'Not scored'
  if (score.value >= 80) return 'Contained'
  if (score.value >= 60) return 'Watch'
  return 'At risk'
})

const verdictAlarm = computed(() => score.value !== null && score.value < 60)

const summary = computed(() => {
  if (!scan.value) return 'No exposure reading yet. Run a scan to take the first one.'
  if (noResponse.value) return 'No port answered. The target is down or fully filtered, so nothing was observed. This is not a clean result.'
  const coverage = scan.value.coverage
  const opened = coverage?.ports_open ?? scan.value.open_ports?.length ?? 0
  const urgent = severityCount('critical') + severityCount('high')
  const reading = coverage?.ports_checked
    ? `${opened} of ${coverage.ports_checked} common ports accepted a connection.`
    : `${opened} ports accepted a connection.`
  const priority = urgent ? ` ${urgent} need${urgent === 1 ? 's' : ''} attention first.` : ''
  const dismissed = findings.value.length - openFindings.value.length
  const excluded = dismissed ? ` ${dismissed} dismissed, not counted.` : ''
  return `${reading}${priority}${excluded}`
})

const vantage = computed(() => {
  const value = scan.value?.vantage
  if (value === 'host') return 'Scanned from the machine itself'
  if (value === 'container') return 'Scanned from the Docker container'
  return value ? `Scanned from ${value}` : 'Scan origin not recorded'
})

const emptyTitle = computed(() => {
  if (!scan.value) return 'No scan yet'
  return noResponse.value ? `No response from ${scan.value.target}` : 'Nothing exposed'
})

const emptyText = computed(() => {
  if (!scan.value) return 'Run a scan to take the first reading.'
  if (noResponse.value) return 'The target is down or fully filtered.'
  return openFindings.value.length === findings.value.length
    ? 'None of the common ports accepted a connection.'
    : 'Every finding has been dismissed.'
})

const firewallWeak = computed(() => ['disabled', 'partial'].includes(hostReport.value?.firewall.status ?? ''))
const listenersBeyondLoopback = computed(() =>
  hostReport.value?.listeners.items.filter((listener) => listener.exposure !== 'loopback').length ?? 0,
)

const vulnerabilityLabel = computed(() => {
  const report = hostReport.value?.vulnerabilities
  if (!report) return '—'
  return {
    complete: `${report.advisories_found} advisories`,
    partial: `${report.advisories_found} advisories`,
    unavailable: 'Unavailable',
    disabled: 'Lookup off',
    not_covered: 'Not covered',
  }[report.status]
})

const scanLabel = computed(() => {
  if (scanning.value) return 'Scanning…'
  return agent.value ? 'Run scan' : 'Scan from Docker'
})

const startScan = () => runScan(target.value.trim(), dockerTarget)

const decide = async (decision: TriageStatus, reason: string) => {
  if (!selectedFinding.value?.finding_id) return
  await setTriage(selectedFinding.value.finding_id, decision, reason)
  selectedFinding.value = null
}

const compareWith = (scanId: string) => {
  if (scan.value?.scan_id) return compareScans(scanId, scan.value.scan_id)
}

const copyCommand = async () => {
  await navigator.clipboard.writeText(AGENT_COMMAND)
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}
</script>

<template>
  <div :class="['room', { scanning }]">
    <header class="bar">
      <div class="brand">
        <svg viewBox="-12 -12 24 24" aria-hidden="true">
          <circle r="11" fill="none" stroke="var(--paper)" stroke-width="1.5" />
          <polygon points="0,-5 4.8,-1.5 3,4 -3,4 -4.8,-1.5" fill="var(--safelight)" />
        </svg>
        AttackLens
      </div>

      <div class="agent-state" role="status">
        <span :class="['agent-dot', { online: agent }]" />
        <span>{{ agent ? `Agent connected · ${agent.hostname}` : 'Agent offline' }}</span>
      </div>

      <form class="controls" @submit.prevent="startScan">
        <label class="target-field">
          <span class="eyebrow">Target</span>
          <input
            v-model="target"
            :disabled="scanning"
            :placeholder="agent ? 'this machine' : dockerTarget"
            aria-label="Scan target"
            autocomplete="off"
            spellcheck="false"
          />
        </label>
        <button class="button" type="button" :disabled="scanning" @click="loadAll">Refresh</button>
        <button class="button primary" type="submit" :disabled="scanning">{{ scanLabel }}</button>
      </form>
    </header>

    <div v-if="error" class="notice alert" role="alert">
      <strong>Something went wrong</strong>
      <span>{{ error }}</span>
      <button class="button small" type="button" @click="loadAll">Retry</button>
    </div>

    <div v-if="!agent" class="notice">
      <strong>The agent is not running.</strong>
      <span>Start it on this machine to scan from here: <code>{{ AGENT_COMMAND }}</code></span>
      <button class="button small" type="button" @click="copyCommand">{{ copied ? 'Copied' : 'Copy' }}</button>
    </div>

    <main>
      <section class="exposure develop" aria-label="Network exposure">
        <ApertureDial :score="score" :scanning="scanning" />

        <div class="reading">
          <span class="eyebrow">Network exposure{{ scan ? ` · ${scan.target}` : '' }}</span>

          <div class="score-line">
            <span :class="['score', { empty: score === null }]">{{ score === null ? '—' : animatedScore }}</span>
            <span class="score-unit">/ 100</span>
            <span :class="['verdict', { alarm: verdictAlarm }]">{{ verdict }}</span>
          </div>

          <p class="summary" aria-live="polite">{{ scanning ? 'Taking a reading…' : summary }}</p>

          <PortStrip v-if="scan?.port_states" :states="scan.port_states" :services="scan.services ?? []" />

          <p v-if="scan" class="provenance">
            <span>{{ vantage }}</span>
            <span>{{ formatDate(scan.completed_at) }}</span>
            <span v-if="scan.duration_seconds !== undefined">{{ scan.duration_seconds.toFixed(1) }} s</span>
          </p>
        </div>
      </section>

      <dl class="tally develop" style="--i: 1">
        <div v-for="item in tally" :key="item.severity" :class="{ zero: !item.count }">
          <dt><SeverityMark :severity="item.severity" labelled /></dt>
          <dd>{{ item.count }}</dd>
        </div>
      </dl>

      <dl v-if="hostReport" class="readouts develop" style="--i: 2">
        <div>
          <dt class="eyebrow">Firewall</dt>
          <dd :class="{ warning: firewallWeak }">{{ hostReport.firewall.status }}</dd>
        </div>
        <div>
          <dt class="eyebrow">Beyond loopback</dt>
          <dd>{{ listenersBeyondLoopback }} of {{ hostReport.listeners.items.length }} listeners</dd>
        </div>
        <div>
          <dt class="eyebrow">Installed software</dt>
          <dd>{{ hostReport.packages.items.length }}</dd>
        </div>
        <div>
          <dt class="eyebrow">Known vulnerabilities</dt>
          <dd>{{ vulnerabilityLabel }}</dd>
        </div>
      </dl>

      <section class="desk develop" style="--i: 3">
        <FindingLedger
          :network="findings"
          :host="hostReport?.findings ?? []"
          :host-name="hostReport?.target"
          :empty-title="emptyTitle"
          :empty-text="emptyText"
          @view="selectedFinding = $event"
        />
        <ChangesPanel
          :alerts="alerts"
          :history="history"
          :comparison="comparison"
          :current-scan-id="scan?.scan_id"
          @compare="compareWith"
        />
      </section>

      <RuntimePanel :inventory="inventory" :vulnerabilities="vulnerabilities" :posture="posture" />
    </main>

    <FindingDrawer :finding="selectedFinding" @close="selectedFinding = null" @decide="decide" />

    <footer>
      <span>AttackLens</span>
      <span>Listening on an interface does not prove a service is reachable from other machines.</span>
    </footer>
  </div>
</template>
