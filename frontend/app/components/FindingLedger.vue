<script setup lang="ts">
import type { Finding } from '~/types/scan'

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

type Tab = 'network' | 'host' | 'dismissed'

const tab = ref<Tab>('network')
const showInfo = ref(false)

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const isOpen = (finding: Finding) => (finding.triage_status ?? 'open') === 'open'
const bySeverity = (a: Finding, b: Finding) =>
  (SEVERITY_RANK[a.severity ?? 'info'] ?? 5) - (SEVERITY_RANK[b.severity ?? 'info'] ?? 5)
  || (a.port ?? 99999) - (b.port ?? 99999)

const networkOpen = computed(() => props.network.filter(isOpen).sort(bySeverity))
const hostOpen = computed(() => props.host.filter(isOpen).sort(bySeverity))
const hostVisible = computed(() =>
  showInfo.value ? hostOpen.value : hostOpen.value.filter((finding) => finding.severity !== 'info'),
)
const hostInfoCount = computed(() => hostOpen.value.length - hostOpen.value.filter((finding) => finding.severity !== 'info').length)
const dismissed = computed(() => [...props.network, ...props.host].filter((finding) => !isOpen(finding)).sort(bySeverity))

const rows = computed(() => ({
  network: networkOpen.value,
  host: hostVisible.value,
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
  return finding.process ?? finding.title
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
      <button class="tab" role="tab" type="button" :aria-selected="tab === 'network'" @click="tab = 'network'">
        Network {{ networkOpen.length }}
      </button>
      <button class="tab" role="tab" type="button" :aria-selected="tab === 'host'" @click="tab = 'host'">
        {{ hostName ?? 'This machine' }} {{ hostOpen.length }}
      </button>
      <button class="tab" role="tab" type="button" :aria-selected="tab === 'dismissed'" @click="tab = 'dismissed'">
        Dismissed {{ dismissed.length }}
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
          <span v-if="!isOpen(finding)" class="tag">{{ finding.triage_status === 'accepted' ? 'accepted' : 'false positive' }}</span>
          <span v-else class="ledger-open" aria-hidden="true">→</span>
        </button>
      </li>
    </ul>

    <div v-else class="empty">
      <template v-if="tab === 'network'">
        <strong>{{ emptyTitle }}</strong>
        <p>{{ emptyText }}</p>
      </template>
      <template v-else-if="tab === 'host'">
        <strong>No host report</strong>
        <p>Start the agent on this machine to see its listening services.</p>
      </template>
      <template v-else>
        <strong>Nothing dismissed</strong>
        <p>Accepted risks and false positives appear here.</p>
      </template>
    </div>

    <button v-if="tab === 'host' && hostInfoCount" class="text-button" type="button" @click="showInfo = !showInfo">
      {{ showInfo ? 'Hide loopback services' : `Show ${hostInfoCount} loopback services` }}
    </button>
  </div>
</template>
