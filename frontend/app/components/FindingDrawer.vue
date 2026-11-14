<script setup lang="ts">
import type { Finding, TriageStatus } from '~/types/scan'
import { LAPSE_LABELS } from '~/utils/findings'

// The detail of one finding: what it is, why it matters, what to do, and the decision.
const props = defineProps<{
  finding: Finding | null
}>()

const emit = defineEmits<{
  close: []
  decide: [status: TriageStatus, reason: string, days: number]
}>()

const PRIORITY: Record<string, string> = { now: 'Now', soon: 'Soon', later: 'When you have time' }
const REACH: Record<string, string> = {
  exposed: 'Yes, proved from outside',
  unverified: 'Not proved either way',
  shielded: 'No, blocked from outside',
  local: 'Only from this machine',
  'no network path': 'Not through the network',
}
const EXPLOIT: Record<string, string> = {
  assumed: 'Assumed, not tested',
  'confirmed by an active check': 'Yes, confirmed by a test',
  'mitigated, checked actively': 'Protected, confirmed by a test',
  'exploited in the wild (CISA KEV)': 'Yes, attackers are using it',
}

const reason = ref('')
const days = ref(90)
const closeButton = ref<HTMLButtonElement | null>(null)

const isOpen = computed(() => (props.finding?.triage_status ?? 'open') === 'open')

// Raw data is set in monospace: ports, versions, banners, identifiers.
const RAW = new Set(['Process', 'Port', 'Version', 'Evidence', 'Banner', 'CVE', 'CVSS', 'Target'])

const facts = computed(() => {
  const finding = props.finding
  if (!finding) return []
  return [
    ['Target', finding.target],
    ['Process', finding.process],
    ['Bound to', finding.exposure],
    ['Service', finding.service],
    ['Port', finding.port],
    ['Version', finding.version],
    ['Evidence', finding.evidence],
    ['Banner', finding.banner],
    ['CVE', finding.cve],
    ['CVSS', finding.cvss],
  ].filter(([, value]) => value !== null && value !== undefined && value !== '')
})

const onKey = (event: KeyboardEvent) => {
  if (event.key === 'Escape' && props.finding) emit('close')
}

watch(() => props.finding, async (finding) => {
  reason.value = finding?.triage_reason ?? ''
  if (finding) {
    await nextTick()
    closeButton.value?.focus()
  }
})

onMounted(() => window.addEventListener('keydown', onKey))
onBeforeUnmount(() => window.removeEventListener('keydown', onKey))
</script>

<template>
  <Transition name="loupe">
    <div v-if="finding" class="drawer-backdrop" @click.self="emit('close')">
      <aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
        <div class="drawer-head">
          <SeverityMark :severity="finding.severity" labelled />
          <button ref="closeButton" class="btn btn-small" type="button" @click="emit('close')">Close</button>
        </div>

        <h2 id="drawer-title" class="t-heading-m drawer-title">{{ finding.title ?? 'Security finding' }}</h2>
        <p class="t-body-m text-secondary">{{ finding.description }}</p>
        <p v-if="finding.triage_lapsed" class="t-body-s text-muted">{{ LAPSE_LABELS[finding.triage_lapsed] }}</p>

        <div v-if="finding.remediation" class="drawer-block">
          <h3 class="t-label">What to do</h3>
          <p class="t-body-m">{{ finding.remediation }}</p>
        </div>

        <dl v-if="finding.risk" class="facts">
          <div><dt class="t-body-s text-muted">When to deal with it</dt><dd class="t-body-s">{{ PRIORITY[finding.risk.priority] }}</dd></div>
          <div><dt class="t-body-s text-muted">Can it be reached</dt><dd class="t-body-s">{{ REACH[finding.risk.reachability] ?? finding.risk.reachability }}</dd></div>
          <div><dt class="t-body-s text-muted">Can it be used</dt><dd class="t-body-s">{{ EXPLOIT[finding.risk.exploitability] ?? finding.risk.exploitability }}</dd></div>
        </dl>

        <div v-if="finding.risk_reason" class="drawer-block">
          <h3 class="t-label">Why it matters</h3>
          <p class="t-body-m text-secondary">{{ finding.risk_reason }}</p>
        </div>

        <dl class="facts">
          <div v-for="[name, value] in facts" :key="String(name)">
            <dt class="t-body-s text-muted">{{ name }}</dt>
            <dd :class="RAW.has(String(name)) ? 't-data' : 't-body-s'">{{ value }}</dd>
          </div>
        </dl>

        <div v-if="finding.finding_id" class="drawer-block">
          <h3 class="t-label">Your decision</h3>
          <template v-if="isOpen">
            <input v-model="reason" class="field t-body-s" aria-label="Reason for this decision" maxlength="500" placeholder="Reason (optional)" />
            <label class="duration t-body-s">
              <span class="text-muted">Review again in</span>
              <select v-model.number="days" class="field t-body-s" aria-label="Validity of this decision">
                <option :value="30">30 days</option>
                <option :value="90">90 days</option>
                <option :value="365">1 year</option>
              </select>
            </label>
            <div class="drawer-actions">
              <button class="btn" type="button" @click="emit('decide', 'accepted', reason, days)">Accept the risk</button>
              <button class="btn" type="button" @click="emit('decide', 'false_positive', reason, days)">It is a false positive</button>
            </div>
          </template>
          <template v-else>
            <p class="t-body-m text-secondary">
              {{ finding.triage_status === 'accepted' ? 'Risk accepted' : 'Marked as false positive' }}{{ finding.triage_reason ? `: ${finding.triage_reason}` : '.' }}
              <template v-if="finding.triage_expires_at">Until {{ formatDate(finding.triage_expires_at) }}.</template>
            </p>
            <div class="drawer-actions">
              <button class="btn" type="button" @click="emit('decide', 'open', '', 0)">Reopen</button>
            </div>
          </template>
        </div>
      </aside>
    </div>
  </Transition>
</template>
