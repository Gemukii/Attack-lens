<script setup lang="ts">
import type { Finding } from '~/types/scan'
import { byRisk, isOpen, REACHABILITY_LABELS, splitHostFindings } from '~/utils/findings'

const props = defineProps<{
  network: Finding[]
  host: Finding[]
  hostName?: string
  emptyTitle: string
  emptyText: string
}>()

const emit = defineEmits<{
  view: [finding: Finding]
}>()

type Tab = 'network' | 'machine' | 'software' | 'autostart' | 'dismissed'

const tab = ref<Tab>('network')
const showInfo = ref(false)

const hostGroups = computed(() => splitHostFindings(props.host))
const networkOpen = computed(() => props.network.filter(isOpen).sort(byRisk))
const machineOpen = computed(() => hostGroups.value.machine.filter(isOpen).sort(byRisk))
const machineVisible = computed(() =>
  showInfo.value ? machineOpen.value : machineOpen.value.filter((finding) => finding.severity !== 'info'),
)
const machineInfoCount = computed(() => machineOpen.value.filter((finding) => finding.severity === 'info').length)
const software = computed(() => hostGroups.value.software.filter(isOpen).sort(byRisk))
const autostart = computed(() => hostGroups.value.autostart.filter(isOpen).sort(byRisk))
const dismissed = computed(() => [...props.network, ...props.host].filter((finding) => !isOpen(finding)).sort(byRisk))

const tabs = computed(() => [
  { id: 'network' as Tab, label: 'Network', count: networkOpen.value.length },
  { id: 'machine' as Tab, label: props.hostName ?? 'This machine', count: machineOpen.value.length },
  { id: 'software' as Tab, label: 'Updates', count: software.value.length },
  { id: 'autostart' as Tab, label: 'Autostart', count: autostart.value.length },
  { id: 'dismissed' as Tab, label: 'Dismissed', count: dismissed.value.length },
])

const rows = computed(() => ({
  network: networkOpen.value,
  machine: machineVisible.value,
  software: software.value,
  autostart: autostart.value,
  dismissed: dismissed.value,
}[tab.value]))

const EXPOSURE: Record<string, string> = {
  all: 'all interfaces',
  interface: 'specific interfaces',
  loopback: 'this machine only',
}

const detail = (finding: Finding) => {
  if (finding.category === 'network') return finding.version ?? finding.banner?.slice(0, 64) ?? ''
  if (finding.exposure) return `bound to ${EXPOSURE[finding.exposure]}`
  return finding.evidence ?? ''
}

const heading = (finding: Finding) => {
  if (finding.category === 'network') return finding.service ?? finding.title
  if (finding.category === 'listener') return finding.process ?? finding.title
  return finding.title
}

const portLabel = (finding: Finding) => {
  if (finding.port) return String(finding.port)
  return finding.category === 'listener' ? 'dynamic' : '—'
}
</script>

<template>
  <div class="ledger">
    <div class="panel-head">
      <div>
        <span class="eyebrow">Findings</span>
        <h2 class="section-title">What the scan found</h2>
      </div>
    </div>

    <div class="tabs" role="tablist" aria-label="Findings view">
      <button
        v-for="item in tabs"
        :key="item.id"
        class="tab"
        role="tab"
        type="button"
        :aria-selected="tab === item.id"
        @click="tab = item.id"
      >
        {{ item.label }} {{ item.count }}
      </button>
    </div>

    <ul v-if="rows.length" :key="tab" class="ledger-rows">
      <li v-for="(finding, index) in rows" :key="finding.finding_id ?? index" :style="{ '--i': index }">
        <button type="button" :class="['ledger-row', { dismissed: !isOpen(finding) }]" @click="emit('view', finding)">
          <span class="ledger-severity"><SeverityMark :severity="finding.severity" labelled /></span>
          <span class="ledger-port">{{ portLabel(finding) }}</span>
          <span class="ledger-title">
            <strong>{{ heading(finding) }}</strong>
            <span>{{ detail(finding) }}</span>
          </span>
          <span class="ledger-tags">
            <span v-if="finding.risk?.priority === 'now'" class="tag urgent">now</span>
            <span v-if="finding.verification === 'confirmed'" class="tag">proved</span>
            <span v-if="finding.known_exploited" class="tag urgent">exploited</span>
            <span v-if="finding.reachability" class="tag">{{ REACHABILITY_LABELS[finding.reachability] }}</span>
            <span v-if="finding.triage_lapsed" class="tag">reopened</span>
            <span v-if="!isOpen(finding)" class="tag">{{ finding.triage_status === 'accepted' ? 'accepted' : 'false positive' }}</span>
          </span>
        </button>
      </li>
    </ul>

    <div v-else class="empty">
      <template v-if="tab === 'network'">
        <strong>{{ emptyTitle }}</strong>
        <p>{{ emptyText }}</p>
      </template>
      <template v-else-if="tab === 'dismissed'">
        <strong>Nothing dismissed</strong>
        <p>Accepted risks and false positives appear here.</p>
      </template>
      <template v-else>
        <strong>Nothing here</strong>
        <p>{{ host.length ? 'No open finding in this view.' : 'Start the agent on this machine to fill this view.' }}</p>
      </template>
    </div>

    <button v-if="tab === 'machine' && machineInfoCount" class="text-button" type="button" @click="showInfo = !showInfo">
      {{ showInfo ? 'Hide informational findings' : `Show ${machineInfoCount} informational findings` }}
    </button>
  </div>
</template>
