<script setup lang="ts">
import type { Finding, TriageStatus } from '~/types/scan'

const props = defineProps<{
  finding: Finding | null
}>()

const emit = defineEmits<{
  close: []
  decide: [status: TriageStatus, reason: string]
}>()

const reason = ref('')
const closeButton = ref<HTMLButtonElement | null>(null)

const isOpen = computed(() => (props.finding?.triage_status ?? 'open') === 'open')

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
          <span class="ledger-severity"><SeverityMark :severity="finding.severity" labelled /></span>
          <button ref="closeButton" class="button small" type="button" @click="emit('close')">Close</button>
        </div>

        <h2 id="drawer-title">{{ finding.title ?? 'Security finding' }}</h2>
        <p class="note">{{ finding.description }}</p>

        <div v-if="finding.risk_reason" class="drawer-block why">
          <span class="eyebrow">Why it matters</span>
          <p>{{ finding.risk_reason }}</p>
        </div>

        <dl class="facts">
          <div v-for="[name, value] in facts" :key="String(name)">
            <dt>{{ name }}</dt>
            <dd>{{ value }}</dd>
          </div>
        </dl>

        <div v-if="finding.remediation" class="drawer-block">
          <span class="eyebrow">What to do</span>
          <p>{{ finding.remediation }}</p>
        </div>

        <div v-if="finding.finding_id" class="drawer-block">
          <span class="eyebrow">Decision</span>
          <template v-if="isOpen">
            <input v-model="reason" aria-label="Reason for this decision" maxlength="500" placeholder="Reason (optional)" />
            <div class="drawer-actions">
              <button class="button small" type="button" @click="emit('decide', 'accepted', reason)">Accept risk</button>
              <button class="button small" type="button" @click="emit('decide', 'false_positive', reason)">False positive</button>
            </div>
          </template>
          <template v-else>
            <p>
              {{ finding.triage_status === 'accepted' ? 'Risk accepted' : 'Marked as false positive' }}{{ finding.triage_reason ? `: ${finding.triage_reason}` : '.' }}
            </p>
            <div class="drawer-actions">
              <button class="button small" type="button" @click="emit('decide', 'open', '')">Reopen</button>
            </div>
          </template>
        </div>
      </aside>
    </div>
  </Transition>
</template>
