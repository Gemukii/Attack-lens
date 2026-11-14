<script setup lang="ts">
import type { Finding, TriageStatus } from '~/types/scan'
import { useScan } from '~/composables/useScan'
import { useIndicator } from '~/composables/useIndicator'
import { withViewTransition } from '~/utils/motion'
import { buildReading } from '~/utils/reading'

const { results: scan, history, comparison, inventory, vulnerabilities, posture, hostReport, alerts, freshAlertIds, agent, silentAgent, paths, exposure, audit, status, error, syncedAt, syncFailed, loadAll, loadAgents, compareScans, runScan, setTriage, createEnrollmentCode } = useScan()
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
const now = ref(Date.now())
const scanning = computed(() => status.value === 'running')

// Until the first answer the page shows the skeleton, on the server too: the empty state
// must never flash before the data, or everything below it would jump.
const booted = ref(false)
const loading = computed(() => !booted.value || (status.value === 'loading' && !scan.value))

// A change of view cross-fades and slides a few pixels the way one is going: towards the
// right for a view further along, towards the left to come back. The frame stays in place.
const showView = (next: View) => {
  if (next === view.value) return
  const order = VIEWS.map((item) => item.id)
  document.documentElement.style.setProperty('--nav-direction', order.indexOf(next) > order.indexOf(view.value) ? '1' : '-1')
  withViewTransition(() => { view.value = next })
}

// The underline of the current view slides from one to the next.
const viewsElement = ref<HTMLElement | null>(null)
const { style: viewsIndicator, ready: viewsReady } = useIndicator(viewsElement, '[aria-current="page"]', view)

let agentTimer: ReturnType<typeof setInterval> | undefined
let clockTimer: ReturnType<typeof setInterval> | undefined

onMounted(() => {
  loadAll().finally(() => (booted.value = true))
  agentTimer = setInterval(loadAgents, 4000)
  clockTimer = setInterval(() => (now.value = Date.now()), 5000)
})
onBeforeUnmount(() => {
  clearInterval(agentTimer)
  clearInterval(clockTimer)
})

const findings = computed<Finding[]>(() => scan.value?.findings ?? [])
const noResponse = computed(() => scan.value?.status === 'no_response')

// The API is down and nothing was ever loaded: nothing is known, and no view may pretend
// otherwise with "never", "nothing new" or an empty list.
const unknown = computed(() => booted.value && syncFailed.value && !scan.value)

const emptyTitle = computed(() => {
  if (!scan.value) return 'No reading yet.'
  return noResponse.value ? `No response from ${scan.value.target}.` : 'Nothing to deal with.'
})

const emptyText = computed(() => {
  if (!scan.value) return 'Run a scan to take the first one.'
  if (noResponse.value) return 'The target is down, or filters everything.'
  return 'No open finding in the last reading.'
})

// The reading line: who measured what, when, from where. Shown on every view.
const reading = computed(() => buildReading({
  scan: scan.value,
  exposure: exposure.value,
  agent: agent.value,
  silentAgent: silentAgent.value,
  unreachable: syncFailed.value,
  syncedAt: syncedAt.value,
  now: now.value,
}))

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
</script>

<template>
  <div class="page">
    <header class="topbar">
      <div class="shell topbar-inner">
        <a class="wordmark" href="/" aria-label="AttackLens, home">AttackLens</a>

        <nav ref="viewsElement" :class="['views', { 'has-indicator': viewsReady }]" aria-label="Views">
          <button
            v-for="item in VIEWS"
            :key="item.id"
            type="button"
            :aria-current="view === item.id ? 'page' : undefined"
            @click="showView(item.id)"
          >
            {{ item.label }}
          </button>
          <span class="indicator" :style="viewsIndicator" aria-hidden="true" />
        </nav>

        <form class="scan" @submit.prevent="startScan">
          <label for="scan-target" class="visually-hidden">Scan target</label>
          <input
            id="scan-target"
            v-model="target"
            class="field t-data"
            :disabled="scanning"
            :placeholder="agent ? 'this machine' : dockerTarget"
            autocomplete="off"
            spellcheck="false"
          />
          <button class="btn btn-primary" type="submit" :disabled="scanning">
            <span class="labels">
              <span :class="{ shown: !scanning }" :aria-hidden="scanning || undefined">Scan</span>
              <span :class="{ shown: scanning }" :aria-hidden="!scanning || undefined"><span class="busy" aria-hidden="true" />Scanning</span>
            </span>
          </button>
        </form>
      </div>
    </header>

    <ReadingLine :items="reading" :loading="!booted" />

    <main class="shell page-main">
      <!-- Notices sit inside the page and arrive with its content, so they push nothing that was already there. -->
      <div v-if="error && booted" class="notice notice-error" role="alert">
        <span class="lamp lamp-off" aria-hidden="true" />
        <span class="notice-text t-body-s">{{ error }}</span>
        <button class="btn btn-small" type="button" @click="loadAll">Try again</button>
      </div>
      <div v-if="enrollCommand" class="notice">
        <span class="notice-text t-body-s">On the other machine, run <code class="command t-data">{{ enrollCommand }}</code></span>
        <CopyButton :text="enrollCommand" />
      </div>

      <section v-if="unknown" class="unmeasured unknown settled" aria-labelledby="unknown-title">
        <p class="t-label">{{ VIEWS.find((item) => item.id === view)?.label }}</p>
        <h1 id="unknown-title" class="t-heading-l unmeasured-state">Not known</h1>
        <p class="t-body-m text-secondary">The API is not answering, so nothing can be shown here. This says nothing about the machine, good or bad.</p>
      </section>
      <BriefView
        v-else-if="view === 'brief'"
        :scan="scan"
        :host="hostReport"
        :paths="paths"
        :exposure="exposure"
        :history="history"
        :scanning="scanning"
        :loading="loading"
        :alerts="alerts"
        :now="now"
        @view="selectedFinding = $event"
      />
      <FindingLedger
        v-else-if="view === 'findings'"
        :network="findings"
        :host="hostReport?.findings ?? []"
        :alerts="alerts"
        :paths="paths"
        :loading="loading"
        :empty-title="emptyTitle"
        :empty-text="emptyText"
        :now="now"
        @view="selectedFinding = $event"
      />
      <MachineView
        v-else-if="view === 'machine'"
        :host="hostReport"
        :scan="scan"
        :exposure="exposure"
        :inventory="inventory"
        :posture="posture"
        :vulnerabilities="vulnerabilities"
        :loading="loading"
        :now="now"
      />
      <JournalView
        v-else
        :alerts="alerts"
        :fresh="freshAlertIds"
        :audit="audit"
        :history="history"
        :comparison="comparison"
        :current-scan-id="scan?.scan_id"
        :loading="loading"
        :now="now"
        @compare="compareWith"
      />
    </main>

    <!-- Shown once the first answer is in, so that it never slides while the page fills. -->
    <footer v-if="booted" class="shell footer t-body-s">
      <a v-if="scan" class="link" :href="`/api/report${hostReport ? `?target=${encodeURIComponent(hostReport.target)}` : ''}`" target="_blank" rel="noopener">Printable report</a>
      <button class="link" type="button" @click="prepareEnrollment">Add another machine</button>
      <button class="link" type="button" @click="loadAll">Refresh</button>
    </footer>

    <FindingDrawer :finding="selectedFinding" @close="selectedFinding = null" @decide="decide" />
  </div>
</template>
