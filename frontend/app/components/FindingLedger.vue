<script setup lang="ts">
import { useIndicator } from '~/composables/useIndicator'
import type { Alert, AttackPathReport, Finding } from '~/types/scan'
import { byRisk, firstSeen, isCritical, isOpen, proofLabel, splitHostFindings, uniqueByPort, whereText } from '~/utils/findings'
import { ago } from '~/utils/format'

// One list, sorted by risk: a row reads left to right as severity, what and where, proof,
// since when, and risk.
const props = withDefaults(defineProps<{
  network: Finding[]
  host: Finding[]
  alerts?: Alert[]
  paths?: AttackPathReport | null
  loading?: boolean
  emptyTitle: string
  emptyText: string
  now?: number
}>(), { alerts: () => [], paths: null, loading: false, now: () => Date.now() })

const emit = defineEmits<{
  view: [finding: Finding]
}>()

type Tab = 'todo' | 'software' | 'autostart' | 'dismissed'

// A finding first seen less than this long ago is called new.
const NEW_MS = 6 * 60 * 60 * 1000

const tab = ref<Tab>('todo')
const showInfo = ref(false)

// The underline of the current tab slides from one to the next. The counts change the
// width of a tab, so they are watched too.
const tabsElement = ref<HTMLElement | null>(null)
const { style: tabsIndicator, ready: tabsReady } = useIndicator(tabsElement, '[aria-selected="true"]', () => [tab.value, props.loading, props.network.length, props.host.length])

const hostGroups = computed(() => splitHostFindings(props.host))
// The network scan and the agent can report the same port: it appears once.
const open = computed(() => uniqueByPort([...props.network, ...hostGroups.value.machine].filter(isOpen)))
const todo = computed(() => (showInfo.value ? open.value : open.value.filter((finding) => finding.severity !== 'info')))
const infoCount = computed(() => open.value.filter((finding) => finding.severity === 'info').length)
const software = computed(() => hostGroups.value.software.filter(isOpen).sort(byRisk))
const autostart = computed(() => hostGroups.value.autostart.filter(isOpen).sort(byRisk))
const dismissed = computed(() => [...props.network, ...props.host].filter((finding) => !isOpen(finding)).sort(byRisk))

const tabs = computed(() => [
  { id: 'todo' as Tab, label: 'To deal with', count: todo.value.length },
  { id: 'software' as Tab, label: 'Updates', count: software.value.length },
  { id: 'autostart' as Tab, label: 'Autostart', count: autostart.value.length },
  { id: 'dismissed' as Tab, label: 'Dismissed', count: dismissed.value.length },
])

const rows = computed(() => ({
  todo: todo.value,
  software: software.value,
  autostart: autostart.value,
  dismissed: dismissed.value,
}[tab.value]))

const seen = computed(() => firstSeen(props.alerts))
const since = (finding: Finding) => {
  const at = finding.finding_id ? seen.value.get(finding.finding_id) : undefined
  if (!at) return null
  return { text: ago(at, props.now), fresh: props.now - Date.parse(at) < NEW_MS }
}

// A finding reachable from outside that starts an attack path is a proved way in: the same
// thing the bench draws in the accent, under the same name.
const entries = computed(() => new Set((props.paths?.paths ?? []).flatMap((path) => path.entries ?? [])))
const wayIn = (finding: Finding) => isOpen(finding) && finding.reachability === 'exposed' && entries.value.has(finding.finding_id ?? '')
const proved = (finding: Finding) => isOpen(finding) && (Boolean(finding.known_exploited) || finding.verification === 'confirmed' || wayIn(finding))
const proof = (finding: Finding) => (wayIn(finding) && !finding.known_exploited && finding.verification !== 'confirmed' ? 'Proved way in' : proofLabel(finding))
const riskScore = (finding: Finding) => Math.round(finding.risk?.score ?? 0)
const rowKey = (finding: Finding, index: number) => finding.finding_id ?? `${finding.title}-${index}`
</script>

<template>
  <div class="findings">
    <header class="page-head">
      <h1 class="t-heading-l">{{ loading ? 'Findings' : `${todo.length} ${todo.length === 1 ? 'finding' : 'findings'} to deal with` }}</h1>
      <p class="t-body-m text-secondary">Sorted by risk, highest first.</p>
    </header>

    <div ref="tabsElement" :class="['tabs', { 'has-indicator': tabsReady }]" role="tablist" aria-label="Findings">
      <button
        v-for="item in tabs"
        :key="item.id"
        class="tab t-body-s"
        role="tab"
        type="button"
        :aria-selected="tab === item.id"
        @click="tab = item.id"
      >
        {{ item.label }}<span class="tab-count t-data">{{ loading ? '' : item.count }}</span>
      </button>
      <span class="indicator" :style="tabsIndicator" aria-hidden="true" />
    </div>

    <section class="table">
      <div class="row-head t-label" aria-hidden="true">
        <span>Severity</span>
        <span>Finding</span>
        <span>Proof</span>
        <span>Since</span>
        <span class="num">Risk</span>
      </div>

      <div v-if="loading" class="rows" aria-busy="true" aria-label="Loading findings">
        <div v-for="index in 8" :key="index" class="row-skeleton">
          <span class="skeleton skeleton-cell" />
          <span class="skeleton skeleton-cell wide" />
          <span class="skeleton skeleton-cell" />
          <span class="skeleton skeleton-cell" />
          <span class="skeleton skeleton-cell" />
        </div>
      </div>

      <!-- Rows slide to their new place when the list changes, and those that leave fade out. -->
      <TransitionGroup v-else-if="rows.length" :key="tab" name="rows" tag="ul" class="rows">
        <li v-for="(finding, index) in rows" :key="rowKey(finding, index)" :style="{ '--i': index }">
          <button
            type="button"
            :class="['row', { quiet: !isOpen(finding), critical: isCritical(finding) }]"
            @click="emit('view', finding)"
          >
            <SeverityMark :severity="finding.severity" />
            <span class="row-what">
              <span class="row-title t-body-m">{{ finding.title }}</span>
              <span class="row-where t-data">{{ whereText(finding) }}</span>
            </span>
            <span :class="['row-proof t-body-s', { 'text-alert': proved(finding) }]">{{ proof(finding) }}</span>
            <span class="row-since t-body-s">
              <template v-if="since(finding)"><b v-if="since(finding)?.fresh">New </b>{{ since(finding)?.text }}</template>
              <span v-else class="text-muted">Not known</span>
            </span>
            <span class="row-risk t-data num">{{ finding.risk ? riskScore(finding) : 'Not rated' }}</span>
          </button>
        </li>
      </TransitionGroup>

      <div v-else class="empty">
        <template v-if="tab === 'todo'">
          <p class="t-heading-m">{{ emptyTitle }}</p>
          <p class="t-body-m text-muted">{{ emptyText }}</p>
        </template>
        <template v-else-if="tab === 'dismissed'">
          <p class="t-heading-m">Nothing dismissed.</p>
          <p class="t-body-m text-muted">Accepted risks and false positives appear here.</p>
        </template>
        <template v-else>
          <p class="t-heading-m">Nothing here.</p>
          <p class="t-body-m text-muted">{{ host.length ? 'No open finding in this list.' : 'This list needs the agent: it is filled from the inside of the machine.' }}</p>
        </template>
      </div>
    </section>

    <p v-if="tab === 'todo' && infoCount && !loading" class="t-body-s text-muted after-table">
      {{ showInfo ? `${infoCount} informational findings are shown.` : `${infoCount} informational findings are hidden.` }}
      <button class="link more" type="button" @click="showInfo = !showInfo">{{ showInfo ? 'Hide them' : 'Show them' }}</button>
    </p>
  </div>
</template>
