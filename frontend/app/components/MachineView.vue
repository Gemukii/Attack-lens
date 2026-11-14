<script setup lang="ts">
import type { ExposureReport, HostInventory, HostReport, PostureReport, ScanResults, VulnerabilityReport } from '~/types/scan'
import { ago } from '~/utils/format'

// What this machine offers to others, as the agent sees it from the inside, and whether a
// probe from another machine agrees.
const props = withDefaults(defineProps<{
  host: HostReport | null
  scan?: ScanResults | null
  exposure: ExposureReport | null
  inventory: HostInventory | null
  posture: PostureReport | null
  vulnerabilities: VulnerabilityReport | null
  loading?: boolean
  now?: number
}>(), { scan: null, loading: false, now: () => Date.now() })

const START_COMMAND = 'attacklens start'

const beyond = computed(() =>
  (props.host?.listeners.items ?? [])
    .filter((item) => item.exposure !== 'loopback')
    .sort((a, b) => a.port - b.port),
)
const local = computed(() => (props.host?.listeners.items.length ?? 0) - beyond.value.length)

// What a probe from outside found for each port, read from the network findings.
const reach = computed(() => new Map((props.scan?.findings ?? []).map((finding) => [finding.port, finding.reachability])))

const OPEN_TO: Record<string, string> = { all: 'Every network', interface: 'Some networks' }
const OUTSIDE: Record<string, string> = { exposed: 'Reachable', shielded: 'Blocked', unverified: 'Not proved', local: 'This machine only' }
const FIREWALL: Record<string, string> = { enabled: 'On', disabled: 'Off', partial: 'Partial', unknown: 'Not measured' }

const POSTURE: Record<string, string> = {
  pass: 'Passed',
  fail: 'Failed',
  warn: 'Warning',
  unknown: 'Unknown',
  not_checked: 'Not checked',
}

</script>

<template>
  <div v-if="loading" class="machine" aria-busy="true" aria-label="Loading the machine">
    <header class="page-head">
      <span class="skeleton skeleton-title" />
      <span class="skeleton skeleton-line" />
    </header>
    <div class="grid">
      <div class="span-8"><span v-for="index in 8" :key="index" class="skeleton skeleton-row" /></div>
      <div class="span-4"><span v-for="index in 3" :key="index" class="skeleton skeleton-row" /></div>
    </div>
  </div>

  <div v-else class="machine settled">
    <header class="page-head">
      <h1 class="t-heading-l">{{ host?.target ?? 'This machine' }}</h1>
      <p v-if="host" class="t-body-m text-secondary">
        {{ host.os.system }} {{ host.os.release }} <span class="t-data">{{ host.os.version }}</span>, seen from the inside {{ ago(host.completed_at, now) }}.
      </p>
    </header>

    <div v-if="host" class="grid">
      <section class="span-8" aria-labelledby="ports-title">
        <h2 id="ports-title" class="t-label">Listening beyond this machine</h2>
        <p class="figure">
          <span class="t-display">{{ beyond.length }}</span>
          <span class="t-body-m text-muted figure-note">of {{ host.listeners.items.length }} listening ports. {{ local }} only accept this machine, which others cannot reach.</span>
        </p>
        <table v-if="beyond.length" class="ports">
          <thead>
            <tr class="t-label"><th scope="col" class="num">Port</th><th scope="col">Program</th><th scope="col">Open to</th><th scope="col">From outside</th></tr>
          </thead>
          <tbody>
            <tr v-for="(item, index) in beyond" :key="`${item.port}-${item.process}`" :style="{ '--i': index }">
              <td class="t-data num">{{ item.port }}</td>
              <td class="t-data">{{ item.process }}</td>
              <td class="t-body-s text-secondary">{{ OPEN_TO[item.exposure] }}</td>
              <td :class="['t-body-s', reach.get(item.port) === 'exposed' ? 'text-strong' : 'text-secondary']">{{ OUTSIDE[reach.get(item.port) ?? ''] ?? 'Not tested' }}</td>
            </tr>
          </tbody>
        </table>
        <p v-else class="t-body-m text-muted">Nothing listens beyond this machine.</p>
      </section>

      <aside class="span-4 side">
        <section aria-labelledby="firewall-title">
          <h2 id="firewall-title" class="t-label section-rule">Firewall</h2>
          <p class="state">
            <span :class="['t-heading-m', { 'text-alert': host.firewall.status === 'disabled' }]">{{ FIREWALL[host.firewall.status] ?? host.firewall.status }}</span>
            <span class="t-data text-muted">{{ host.firewall.source }}</span>
          </p>
        </section>

        <section aria-labelledby="proof-title">
          <h2 id="proof-title" class="t-label section-rule">Proof from outside</h2>
          <p v-if="exposure?.status === 'verified'" class="t-body-m">
            A probe of <span class="t-data">{{ exposure.probe?.target }}</span>, {{ ago(exposure.probe?.completed_at, now) }}, found
            <span class="text-strong">{{ exposure.summary.exposed ?? 0 }} reachable</span>, {{ exposure.summary.shielded ?? 0 }} blocked and {{ exposure.summary.unverified ?? 0 }} not tested.
          </p>
          <template v-else>
            <p class="t-body-m text-secondary">
              Not proved yet. Connecting to your own address skips your firewall, so everything here comes from the inside. Run this on
              another machine of the same network, then <code class="t-data">attacklens import probe.json</code> here.
            </p>
            <p v-if="exposure?.probe_command" class="command-line">
              <code class="command t-data">{{ exposure.probe_command }}</code>
              <CopyButton :text="exposure.probe_command" />
            </p>
          </template>
        </section>

        <section aria-labelledby="software-title">
          <h2 id="software-title" class="t-label section-rule">Software</h2>
          <dl class="facts">
            <div><dt class="t-body-s text-secondary">Updates waiting</dt><dd class="t-data">{{ host.outdated_count ?? 'Not counted' }} of {{ host.packages.items.length }}</dd></div>
            <div><dt class="t-body-s text-secondary">Starts by itself</dt><dd class="t-data">{{ host.autorun_count ?? 'Not counted' }}</dd></div>
            <div><dt class="t-body-s text-secondary">Known flaws</dt><dd class="t-data">{{ host.vulnerabilities.advisories_found }}</dd></div>
          </dl>
        </section>
      </aside>
    </div>

    <section v-else class="unmeasured" aria-labelledby="machine-state">
      <p class="t-label">Seen from the inside</p>
      <h2 id="machine-state" class="t-heading-l unmeasured-state">Not measured</h2>
      <p class="t-body-m text-secondary">No agent has reported from this machine, so its listening ports, its firewall and its software are not visible. Start the agent on it:</p>
      <p class="command-line">
        <code class="command t-data">{{ START_COMMAND }}</code>
        <CopyButton :text="START_COMMAND" label="Copy the command" />
      </p>
    </section>

    <details class="runtime">
      <summary class="t-body-s">Where AttackLens itself runs</summary>
      <p class="t-body-s text-muted">
        This describes the {{ inventory?.scope === 'container' ? 'Docker container' : 'process' }} of the API, not your machine.
      </p>
      <ul class="checks">
        <li v-for="check in posture?.checks ?? []" :key="check.id" class="t-body-s">
          <span>{{ check.title }}</span>
          <span :class="check.status === 'fail' ? 'text-strong' : 'text-muted'">{{ POSTURE[check.status] ?? check.status }}</span>
        </li>
      </ul>
      <p v-if="vulnerabilities?.status === 'disabled'" class="t-body-s text-muted">
        Package lookup is off. Set <code class="t-data">ATTACKLENS_ENABLE_OSV=true</code> to send package names to the public OSV database.
      </p>
    </details>
  </div>
</template>
