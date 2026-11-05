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
  { id: 'machine' as Tab, label: 'Machine', count: machineOpen.value.length },
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
  all: 'open to every network',
  interface: 'open to some networks',
  loopback: 'this machine only',
}

const detail = (finding: Finding) => {
  if (finding.category === 'network') return finding.version ?? finding.banner?.slice(0, 64) ?? ''
  if (finding.exposure) return EXPOSURE[finding.exposure]
  return finding.evidence ?? ''
}

const heading = (finding: Finding) => {
  if (finding.category === 'network') return finding.service ?? finding.title
  if (finding.category === 'listener') return finding.process ?? finding.title
  return finding.title
}

const status = (finding: Finding) => {
  if (!isOpen(finding)) return finding.triage_status === 'accepted' ? 'Accepted' : 'False positive'
  if (finding.triage_lapsed) return 'Reopened'
  if (finding.known_exploited) return 'Exploited in the wild'
  if (finding.verification === 'confirmed') return 'Confirmed'
  return finding.reachability ? REACHABILITY_LABELS[finding.reachability] : ''
}
</script>

<template>
  <div class="findings">
    <header class="page-head">
      <h1>Everything found</h1>
      <p class="lead">Sorted by what deserves your time first.</p>
    </header>

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
        {{ item.label }}<sup>{{ item.count }}</sup>
      </button>
    </div>

    <ul v-if="rows.length" :key="tab" class="rows">
      <li v-for="(finding, index) in rows" :key="finding.finding_id ?? index" :style="{ '--i': index }">
        <button type="button" :class="['row', { quiet: !isOpen(finding) }]" @click="emit('view', finding)">
          <SeverityMark :severity="finding.severity" />
          <span class="row-port">{{ finding.port ?? '' }}</span>
          <span class="row-title">
            <span>{{ heading(finding) }}</span>
            <small>{{ detail(finding) }}</small>
          </span>
          <span class="row-status">{{ status(finding) }}</span>
        </button>
      </li>
    </ul>

    <div v-else class="empty">
      <template v-if="tab === 'network'">
        <p class="empty-title">{{ emptyTitle }}</p>
        <p class="note">{{ emptyText }}</p>
      </template>
      <template v-else-if="tab === 'dismissed'">
        <p class="empty-title">Nothing dismissed.</p>
        <p class="note">Accepted risks and false positives appear here.</p>
      </template>
      <template v-else>
        <p class="empty-title">Nothing here.</p>
        <p class="note">{{ host.length ? 'No open finding in this view.' : 'Run a scan with the agent connected to fill this view.' }}</p>
      </template>
    </div>

    <button v-if="tab === 'machine' && machineInfoCount" class="link more" type="button" @click="showInfo = !showInfo">
      {{ showInfo ? 'Hide informational findings' : `Show ${machineInfoCount} informational findings` }}
    </button>
  </div>
</template>
