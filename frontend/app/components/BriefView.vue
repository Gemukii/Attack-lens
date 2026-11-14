<script setup lang="ts">
import type { Alert, AttackPathReport, ExposureReport, Finding, HostReport, ScanHistory, ScanResults } from '~/types/scan'
import type { Ray } from '~/utils/bench'
import { buildBench, waysNotDrawn } from '~/utils/bench'
import { countWaysIn, pickActions, scoreTrend, writeBrief } from '~/utils/brief'
import { ago, signed } from '~/utils/format'
import { motionDuration } from '~/utils/motion'
import { isStale } from '~/utils/reading'

// The brief answers two questions, in this order: am I exposed right now, and what do I
// fix first. The bench beside them is the picture that explains the answer.
const props = withDefaults(defineProps<{
  scan: ScanResults | null
  host: HostReport | null
  paths: AttackPathReport | null
  exposure: ExposureReport | null
  history?: ScanHistory
  scanning: boolean
  loading?: boolean
  alerts: Alert[]
  now?: number
}>(), { history: () => [], loading: false, now: () => Date.now() })

const emit = defineEmits<{
  view: [finding: Finding]
}>()

const START_COMMAND = 'attacklens start'

const seenFromInside = computed(() => Boolean(props.host))
const networkFindings = computed(() => props.scan?.findings ?? [])
const hostFindings = computed(() => props.host?.findings ?? [])
const brief = computed(() => writeBrief(props.scan, props.paths, props.exposure, seenFromInside.value))
const waysIn = computed(() => countWaysIn(props.scan, props.paths, props.exposure, seenFromInside.value))
const trend = computed(() => scoreTrend(props.history))
const scoreColumns = computed(() => trend.value.values.map((value, index) => ({ key: String(index), value })))
const bench = computed(() => buildBench(networkFindings.value, hostFindings.value, props.host, props.paths, Boolean(props.scan)))
const actions = computed(() => pickActions(networkFindings.value, hostFindings.value, props.paths))
const first = computed(() => actions.value[0] ?? null)
const next = computed(() => actions.value.slice(1))
const stale = computed(() => isStale(props.scan, props.now))

// Without the view from inside, the number of ways in is not measured. What the network
// scan did see is still said, and an urgent finding is never muted by it.
const measured = computed(() => waysIn.value.value !== null)
const answering = computed(() => props.scan?.coverage?.ports_open ?? props.scan?.open_ports?.length ?? null)
const checked = computed(() => props.scan?.coverage?.ports_checked ?? null)
const urgent = computed(() => networkFindings.value.filter((finding) => finding.risk?.priority === 'now').length)
const verified = computed(() => props.exposure?.status === 'verified')
const reachable = computed(() => (verified.value ? props.exposure?.summary.exposed ?? 0 : null))

// The two gaps between the picture and the figures are said in words, never left to be guessed.
const notDrawn = computed(() => waysNotDrawn(props.paths))
// Services that answer and have no ray: those beyond the seven the picture holds, and those
// with no open finding (dismissed here, or nothing was found on them).
const hidden = computed(() => (answering.value === null ? 0 : Math.max(0, answering.value - bench.value.rays.length)))
const beyond = computed(() => Math.min(hidden.value, Math.max(0, (bench.value.services ?? 0) - bench.value.rays.length)))
const quietServices = computed(() => hidden.value - beyond.value)

// One cell per port: the counts are small, so they are shown exactly.
const verdicts = computed(() => {
  if (!props.exposure || props.exposure.status === 'no_host_report') return null
  const summary = props.exposure.summary
  return [
    { id: 'exposed', label: 'Reachable from outside', value: summary.exposed ?? 0 },
    { id: 'unverified', label: 'Not proved either way', value: summary.unverified ?? 0 },
    { id: 'shielded', label: 'Blocked from outside', value: summary.shielded ?? 0 },
    { id: 'local', label: 'This machine only', value: summary.local ?? 0 },
  ]
})

const latestChange = computed(() => props.alerts[0] ?? null)
const changeText = computed(() => {
  const alert = latestChange.value
  if (!alert) return ''
  return alert.findings[0]?.title ?? alert.message.replace('AttackLens: ', '')
})

const select = (ray: Ray) => emit('view', ray.finding)

// The actions and the bench point at each other: an action lights its ray, a ray marks its
// action. A port is the same service whichever view reported it.
const pointedFinding = ref<Finding | null>(null)
const pointedRay = ref<Ray | null>(null)
const sameService = (finding: Finding, ray: Ray) =>
  Boolean(finding.finding_id && finding.finding_id === ray.finding.finding_id) || (finding.port != null && finding.port === ray.port)
const highlight = computed(() => {
  const finding = pointedFinding.value
  return finding ? bench.value.rays.find((ray) => sameService(finding, ray))?.id ?? null : null
})
const linked = (finding: Finding) => Boolean(pointedRay.value && sameService(finding, pointedRay.value))

// The verdict is swapped, old out then new in, whenever what it says changes.
const verdictKey = computed(() => `${waysIn.value.value}|${waysIn.value.note}|${brief.value.headline}`)

// When a new reading brings a significant drop, the score keeps a tint for a moment.
const flash = ref(false)
watch(() => props.scan?.scan_id, (id, previous) => {
  if (!previous || id === previous || !trend.value.alert) return
  flash.value = true
  setTimeout(() => (flash.value = false), motionDuration('--dur-flash'))
})
</script>

<template>
  <div v-if="loading" class="brief" aria-busy="true" aria-label="Loading the last reading">
    <!-- Same boxes as the brief below: the verdict and the first action, the bench, then two columns. -->
    <section class="hero grid">
      <div class="hero-verdict span-4">
        <div class="verdict">
          <span class="skeleton skeleton-label" />
          <span class="skeleton skeleton-figure" />
          <span class="skeleton skeleton-title" />
          <span class="skeleton skeleton-line" />
        </div>
        <div class="first">
          <span class="skeleton skeleton-label" />
          <span class="skeleton skeleton-action" />
        </div>
      </div>
      <div class="hero-bench span-8">
        <span class="skeleton skeleton-label" />
        <span class="skeleton skeleton-bench" />
      </div>
    </section>
    <div class="grid lower">
      <div class="span-7"><span v-for="index in 3" :key="index" class="skeleton skeleton-row" /></div>
      <div class="span-5"><span v-for="index in 3" :key="index" class="skeleton skeleton-row" /></div>
    </div>
  </div>

  <div v-else class="brief settled">
    <section class="hero grid">
      <div class="hero-verdict span-4">
        <!--
          A scan never takes the verdict away: the last reading stays in place, with a word
          beside its label, so nothing under it moves. The verdict is swapped only when
          what it says changes.
        -->
        <Transition name="swap" mode="out-in">
        <div v-if="!measured" class="verdict unmeasured">
          <p class="t-label verdict-label">
            <span>Ways to full control</span>
            <Transition name="swap">
              <span v-if="scanning" class="verdict-status" role="status"><span class="busy" aria-hidden="true" />Taking a reading</span>
              <span v-else-if="stale && scan" class="verdict-age text-alert">Read {{ ago(scan.completed_at, now) }}</span>
            </Transition>
          </p>
          <h1 class="t-heading-l unmeasured-state">Not measured</h1>
          <p class="t-body-m text-secondary">
            <template v-if="!scan">Nothing has been read yet. Run a first scan, then start the agent to see this machine from the inside.</template>
            <template v-else-if="scan.status === 'no_response'">{{ scan.target }} did not answer. It is down, or filters everything: this says nothing about its safety.</template>
            <template v-else>No agent is connected, so attack paths, the firewall and the account are not visible.</template>
          </p>
          <p class="unmeasured-action">
            <code class="command t-data">{{ START_COMMAND }}</code>
            <CopyButton :text="START_COMMAND" label="Copy the command" />
          </p>
          <p v-if="scan && scan.status !== 'no_response'" class="outside">
            <span class="t-label">Seen from the network only</span>
            <span class="t-heading-m">
              {{ answering ?? 0 }} {{ answering === 1 ? 'service answers' : 'services answer' }}<template v-if="urgent">, <span class="text-alert">{{ urgent }} critical</span></template>.
            </span>
          </p>
        </div>

        <div v-else :key="verdictKey" :class="['verdict', { old: stale }]">
          <p class="t-label verdict-label">
            <span>Ways to full control</span>
            <Transition name="swap">
              <span v-if="scanning" class="verdict-status" role="status"><span class="busy" aria-hidden="true" />Taking a reading</span>
              <span v-else-if="stale && scan" class="verdict-age text-alert">Read {{ ago(scan.completed_at, now) }}</span>
            </Transition>
          </p>
          <p class="figure" :aria-label="`${waysIn.value}, ${waysIn.note}`">
            <span class="t-display" aria-hidden="true">{{ waysIn.value }}</span>
            <span :class="['t-heading-m', waysIn.alert ? 'text-alert' : 'text-muted']" aria-hidden="true">{{ waysIn.note }}</span>
          </p>
          <h1 class="t-heading-l">{{ brief.headline }}</h1>
          <p class="t-body-m text-secondary">{{ brief.lead }}</p>
        </div>
        </Transition>

        <p v-if="stale && scan" class="stale t-body-s" role="status">
          This reading is {{ ago(scan.completed_at, now).replace(' ago', '') }} old. Scan again before acting on it.
        </p>

        <section v-if="first" class="first" aria-labelledby="first-title">
          <h2 id="first-title" class="t-label">Fix first</h2>
          <button
            type="button"
            :class="['first-action', { critical: first.finding.risk?.priority === 'now', linked: linked(first.finding) }]"
            @mouseenter="pointedFinding = first.finding"
            @mouseleave="pointedFinding = null"
            @focus="pointedFinding = first.finding"
            @blur="pointedFinding = null"
            @click="emit('view', first.finding)"
          >
            <SeverityMark :severity="first.finding.severity" />
            <span class="t-heading-m first-text">{{ first.text }}</span>
            <span class="t-body-s text-secondary">
              {{ first.reason }}<template v-if="first.finding.port"> · <span class="t-data">{{ first.finding.port }}/tcp</span></template><template v-if="first.breaks">. Closes {{ first.breaks === 1 ? 'one way in' : `${first.breaks} ways in` }}</template>.
            </span>
          </button>
        </section>
        <section v-else class="first">
          <h2 class="t-label">Fix first</h2>
          <p class="t-body-m text-muted">{{ scan ? 'Nothing to fix in the last reading.' : 'Nothing to do before a first reading.' }}</p>
        </section>
      </div>

      <section class="hero-bench span-8" aria-labelledby="bench-title">
        <header class="section-head">
          <h2 id="bench-title" class="t-label">From the network to full control</h2>
          <ul v-if="bench.rays.length" class="legend t-body-s" aria-label="Legend">
            <li><span class="swatch field-hot-3" aria-hidden="true">####</span>Proved way to full control</li>
            <li><span class="swatch field-3" aria-hidden="true">====</span>Proved from outside</li>
            <li><span class="swatch field-2" aria-hidden="true">-- --</span>Not proved yet</li>
            <li><span class="swatch field-2" aria-hidden="true">---+</span>Stopped by the firewall</li>
          </ul>
        </header>
        <GlyphBench v-if="scan" :bench="bench" :highlight="highlight" :scanning="scanning" @select="select" @point="pointedRay = $event" />
        <p v-else class="t-body-m text-muted">No service has been read yet, so there is nothing to draw.</p>
        <p v-if="!seenFromInside && scan" class="t-body-s text-muted bench-note">
          Without the agent, the firewall and the account are not measured: no ray can be followed past the services.
        </p>
        <p v-if="notDrawn.length" class="t-body-s text-muted bench-note">
          {{ notDrawn.length === 1 ? 'One more way in does' : `${notDrawn.length} more ways in do` }} not go through the network, so
          {{ notDrawn.length === 1 ? 'it is' : 'they are' }} not drawn: {{ notDrawn.map((title) => title.charAt(0).toLowerCase() + title.slice(1)).join('; ') }}.
        </p>
        <p v-if="hidden" class="t-body-s text-muted bench-note">
          {{ answering }} services answer, {{ bench.rays.length }} are drawn.
          <template v-if="quietServices">{{ quietServices === 1 ? 'One has' : `${quietServices} have` }} no open finding, dismissed or with nothing found.</template>
          <template v-if="beyond">{{ beyond === 1 ? 'One more is' : `${beyond} more are` }} in the findings: the picture stops at seven.</template>
        </p>
      </section>
    </section>

    <div class="grid lower">
      <div class="span-7 side">
      <section class="then" aria-labelledby="then-title">
        <h2 id="then-title" class="t-label section-rule">Then</h2>
        <ol v-if="next.length" class="actions" start="2">
          <li v-for="(action, index) in next" :key="action.finding.finding_id ?? index" :style="{ '--i': index }">
            <button
              type="button"
              :class="['action', { linked: linked(action.finding) }]"
              @mouseenter="pointedFinding = action.finding"
              @mouseleave="pointedFinding = null"
              @focus="pointedFinding = action.finding"
              @blur="pointedFinding = null"
              @click="emit('view', action.finding)"
            >
              <span class="action-number t-data">{{ String(index + 2).padStart(2, '0') }}</span>
              <span class="action-body">
                <span class="t-body-m action-title">{{ action.text }}</span>
                <span class="t-body-s text-muted">
                  {{ action.reason }}<template v-if="action.finding.port"> · <span class="t-data">{{ action.finding.port }}/tcp</span></template><template v-if="action.breaks"> · closes {{ action.breaks === 1 ? 'one way in' : `${action.breaks} ways in` }}</template>
                </span>
              </span>
              <SeverityMark :severity="action.finding.severity" />
            </button>
          </li>
        </ol>
        <p v-else class="t-body-m text-muted">{{ first ? 'Nothing else in the last reading.' : 'Nothing to list yet.' }}</p>
      </section>

      <section v-if="latestChange" aria-labelledby="change-title">
        <h2 id="change-title" class="t-label section-rule">Last change</h2>
        <p class="t-body-m">
          {{ changeText }}<span v-if="latestChange.findings.length > 1" class="text-muted"> and {{ latestChange.findings.length - 1 }} more</span>
        </p>
        <p class="t-body-s text-muted">
          <time :datetime="latestChange.created_at" :title="formatDate(latestChange.created_at)">{{ ago(latestChange.created_at, now) }}</time> on <span class="t-data">{{ latestChange.target }}</span>
        </p>
      </section>
      </div>

      <aside class="span-5 side">
        <dl class="data">
          <div :class="['datum', { flash }]">
            <dt class="t-label">Network score</dt>
            <dd v-if="typeof scan?.score === 'number'">
              <span class="t-data-l">{{ scan.score }}</span>
              <span class="t-body-s text-muted">of 100, higher is better</span>
              <span v-if="trend.delta !== null" :class="['t-data', trend.alert ? 'text-alert' : 'text-muted']">{{ signed(trend.delta) }}</span>
            </dd>
            <dd v-else class="t-body-m text-muted">Not scored</dd>
            <dd v-if="trend.values.length > 1" class="datum-chart">
              <ScoreColumns :columns="scoreColumns" :alert="trend.alert" :label="`Network score over the last ${trend.values.length} readings, on a scale of 100`" />
              <span class="t-body-s text-muted">{{ trend.values.length }} readings</span>
            </dd>
          </div>
          <div class="datum">
            <dt class="t-label">Services answering</dt>
            <dd>
              <span v-if="answering !== null" class="t-data-l">{{ answering }}</span>
              <span v-else class="t-body-m text-muted">Not read</span>
              <span v-if="checked" class="t-body-s text-muted">of {{ checked }} ports checked</span>
            </dd>
          </div>
          <div class="datum">
            <dt class="t-label">Proved reachable</dt>
            <dd>
              <span v-if="reachable !== null" class="t-data-l">{{ reachable }}</span>
              <span v-else class="t-body-m text-muted">Not proved</span>
              <span class="t-body-s text-muted">{{ verified ? `probe ${ago(exposure?.probe?.completed_at, now)}` : 'no probe from outside yet' }}</span>
            </dd>
          </div>
        </dl>

        <section aria-labelledby="reach-title">
          <h2 id="reach-title" class="t-label section-rule">Reachability, one cell per listening port</h2>
          <ul v-if="verdicts" class="cell-rows">
            <li v-for="(row, index) in verdicts" :key="row.id" :style="{ '--i': index }">
              <span class="t-body-s">{{ row.label }}</span>
              <span :class="['cells', row.id]" aria-hidden="true"><i v-for="index in row.value" :key="index" /></span>
              <span class="t-data">{{ row.value }}</span>
            </li>
          </ul>
          <p v-else class="t-body-s text-muted">Not measured without the agent.</p>
        </section>
      </aside>
    </div>
  </div>
</template>
