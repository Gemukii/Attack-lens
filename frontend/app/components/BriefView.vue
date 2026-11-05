<script setup lang="ts">
import type { Alert, AttackPathReport, ExposureReport, Finding, HostReport, ScanResults } from '~/types/scan'
import { pickActions, writeBrief } from '~/utils/brief'
import type { Ray } from '~/utils/bench'
import { buildBench } from '~/utils/bench'

const props = defineProps<{
  scan: ScanResults | null
  host: HostReport | null
  paths: AttackPathReport | null
  exposure: ExposureReport | null
  scanning: boolean
  agentName?: string
  alerts: Alert[]
}>()

const emit = defineEmits<{
  view: [finding: Finding]
}>()

const networkFindings = computed(() => props.scan?.findings ?? [])
const hostFindings = computed(() => props.host?.findings ?? [])
const brief = computed(() => writeBrief(props.scan, props.paths, props.exposure, Boolean(props.host)))
const bench = computed(() => buildBench(networkFindings.value, hostFindings.value, props.host, props.paths, Boolean(props.scan)))
const actions = computed(() => pickActions(networkFindings.value, hostFindings.value, props.paths))

const vantage = computed(() => {
  const value = props.scan?.vantage
  if (value === 'host') return 'from the machine itself'
  if (value === 'container') return 'from the Docker container'
  return value ? `from ${value}` : ''
})

const select = (ray: Ray) => emit('view', ray.finding)

const latestChange = computed(() => props.alerts[0] ?? null)
const changeText = computed(() => {
  const alert = latestChange.value
  if (!alert) return ''
  const first = alert.findings[0]?.title
  return first ?? alert.message.replace('AttackLens: ', '')
})
</script>

<template>
  <div class="brief">
    <header class="brief-head">
      <div class="brief-text">
        <h1>{{ scanning ? 'Taking a reading.' : brief.headline }}</h1>
        <p class="lead">{{ scanning ? 'This takes a few seconds.' : brief.lead }}</p>
      </div>

      <dl v-if="scan" class="marginalia">
        <div>
          <dt>Network score</dt>
          <dd><strong>{{ scan.score ?? '—' }}</strong> out of 100</dd>
        </div>
        <div>
          <dt>{{ scan.target }}</dt>
          <dd>Read {{ formatDate(scan.completed_at) }},<br>{{ vantage }}</dd>
        </div>
      </dl>
    </header>

    <OpticalBench :bench="bench" :scanning="scanning" @select="select" />
    <div class="desk">
    <section v-if="actions.length" class="actions" aria-labelledby="actions-title">
      <h2 id="actions-title">What to do</h2>
      <ol>
        <li v-for="(action, index) in actions" :key="action.finding.finding_id ?? index" :style="{ '--i': index }">
          <button type="button" class="action" @click="emit('view', action.finding)">
            <span class="action-number">{{ index + 1 }}</span>
            <span class="action-body">
              <span class="action-text">{{ action.text }}</span>
              <span class="action-reason">
                {{ action.reason }}<template v-if="action.breaks">. Closes {{ action.breaks === 1 ? 'one way in' : `${action.breaks} ways in` }}.</template>
              </span>
            </span>
          </button>
        </li>
      </ol>
    </section>

    <aside v-if="scan" class="notes">
      <section>
        <h2>Reading the drawing</h2>
        <ul class="key-list">
          <li class="key solid">Proved from outside</li>
          <li class="key dashed">Not proved yet</li>
          <li class="key lit">Leads to full control</li>
        </ul>
      </section>
      <section v-if="latestChange">
        <h2>Last change</h2>
        <p>{{ changeText }}</p>
        <p class="note">{{ formatDate(latestChange.created_at) }}</p>
      </section>
    </aside>
    </div>
  </div>
</template>
