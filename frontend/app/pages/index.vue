<script setup lang="ts">
import type { Finding, TriageStatus } from '~/types/scan'
import { useScan } from '~/composables/useScan'

const { results: scan, history, comparison, inventory, vulnerabilities, posture, hostReport, alerts, agent, silentAgent, paths, exposure, audit, status, error, loadAll, loadAgents, compareScans, runScan, setTriage, createEnrollmentCode } = useScan()
const config = useRuntimeConfig()
const dockerTarget = String(config.public.scanTarget)

type View = 'brief' | 'findings' | 'machine' | 'journal'

const VIEWS: Array<{ id: View; label: string }> = [
  { id: 'brief', label: 'Brief' },
  { id: 'findings', label: 'Findings' },
  { id: 'machine', label: 'Machine' },
  { id: 'journal', label: 'Journal' },
]

const view = ref<View>('brief')
const target = ref('')
const selectedFinding = ref<Finding | null>(null)
const enrollCommand = ref<string | null>(null)
const copied = ref(false)
const scanning = computed(() => status.value === 'running')

let agentTimer: ReturnType<typeof setInterval> | undefined

onMounted(() => {
  loadAll()
  agentTimer = setInterval(loadAgents, 4000)
})
onBeforeUnmount(() => clearInterval(agentTimer))

const findings = computed<Finding[]>(() => scan.value?.findings ?? [])
const noResponse = computed(() => scan.value?.status === 'no_response')

const emptyTitle = computed(() => {
  if (!scan.value) return 'No reading yet.'
  return noResponse.value ? `No response from ${scan.value.target}.` : 'Nothing answered.'
})

const emptyText = computed(() => {
  if (!scan.value) return 'Run a scan to take the first one.'
  if (noResponse.value) return 'The target is down, or filters everything.'
  return 'None of the common ports accepted a connection.'
})

const agentLine = computed(() => {
  if (agent.value) return `Watching ${agent.value.hostname}`
  if (silentAgent.value) return 'The agent went quiet'
  return 'Agent not connected'
})

const startScan = () => runScan(target.value.trim(), dockerTarget)

const decide = async (decision: TriageStatus, reason: string, days: number) => {
  if (!selectedFinding.value?.finding_id) return
  await setTriage(selectedFinding.value.finding_id, decision, reason, days || undefined)
  selectedFinding.value = null
}

const compareWith = (scanId: string) => {
  if (scan.value?.scan_id) return compareScans(scanId, scan.value.scan_id)
}

const prepareEnrollment = async () => {
  const code = await createEnrollmentCode()
  if (code) enrollCommand.value = `attacklens enroll ${code}`
}

const copyCommand = async () => {
  if (!enrollCommand.value) return
  await navigator.clipboard.writeText(enrollCommand.value)
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}
</script>

<template>
  <div :class="['page', { scanning }]">
    <header class="masthead">
      <a class="wordmark" href="/" aria-label="AttackLens, home">Attack<em>Lens</em></a>

      <nav aria-label="Views">
        <button
          v-for="item in VIEWS"
          :key="item.id"
          type="button"
          :aria-current="view === item.id ? 'page' : undefined"
          @click="view = item.id"
        >
          {{ item.label }}
        </button>
      </nav>

      <form class="scan" @submit.prevent="startScan">
        <label for="scan-target">Scan</label>
        <input
          id="scan-target"
          v-model="target"
          :disabled="scanning"
          :placeholder="agent ? 'this machine' : dockerTarget"
          autocomplete="off"
          spellcheck="false"
        />
        <button class="shutter" type="submit" :disabled="scanning" :aria-label="scanning ? 'Scanning' : 'Start the scan'" />
      </form>
    </header>

    <p v-if="error" class="banner" role="alert">
      {{ error }}
      <button class="link" type="button" @click="loadAll">Try again</button>
    </p>

    <p v-if="!agent" class="banner">
      <template v-if="enrollCommand">
        On the other machine, run <code>{{ enrollCommand }}</code>
        <button class="link" type="button" @click="copyCommand">{{ copied ? 'Copied' : 'Copy' }}</button>
      </template>
      <template v-else>
        {{ silentAgent ? 'This machine is no longer watched.' : 'Scans run from Docker for now.' }}
        Launch with <code>attacklens start</code> to see the machine from the inside.
        <button class="link" type="button" @click="prepareEnrollment">Add another machine</button>
      </template>
    </p>

    <main>
      <BriefView
        v-if="view === 'brief'"
        :scan="scan"
        :host="hostReport"
        :paths="paths"
        :exposure="exposure"
        :scanning="scanning"
        :alerts="alerts"
        @view="selectedFinding = $event"
      />
      <FindingLedger
        v-else-if="view === 'findings'"
        :network="findings"
        :host="hostReport?.findings ?? []"
        :host-name="hostReport?.target"
        :empty-title="emptyTitle"
        :empty-text="emptyText"
        @view="selectedFinding = $event"
      />
      <MachineView
        v-else-if="view === 'machine'"
        :host="hostReport"
        :exposure="exposure"
        :inventory="inventory"
        :posture="posture"
        :vulnerabilities="vulnerabilities"
      />
      <JournalView
        v-else
        :alerts="alerts"
        :audit="audit"
        :history="history"
        :comparison="comparison"
        :current-scan-id="scan?.scan_id"
        @compare="compareWith"
      />
    </main>

    <footer>
      <span class="agent-line" role="status">{{ agentLine }}</span>
      <a v-if="scan" :href="`/api/report${hostReport ? `?target=${encodeURIComponent(hostReport.target)}` : ''}`" target="_blank" rel="noopener">Printable report</a>
      <button class="link" type="button" @click="loadAll">Refresh</button>
    </footer>

    <FindingDrawer :finding="selectedFinding" @close="selectedFinding = null" @decide="decide" />
  </div>
</template>
