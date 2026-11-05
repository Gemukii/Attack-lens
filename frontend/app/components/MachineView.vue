<script setup lang="ts">
import type { ExposureReport, HostInventory, HostReport, PostureReport, VulnerabilityReport } from '~/types/scan'

const props = defineProps<{
  host: HostReport | null
  exposure: ExposureReport | null
  inventory: HostInventory | null
  posture: PostureReport | null
  vulnerabilities: VulnerabilityReport | null
}>()

const copied = ref(false)

const beyond = computed(() =>
  (props.host?.listeners.items ?? [])
    .filter((item) => item.exposure !== 'loopback')
    .sort((a, b) => a.port - b.port),
)
const local = computed(() => (props.host?.listeners.items.length ?? 0) - beyond.value.length)

const EXPOSURE: Record<string, string> = {
  all: 'every network',
  interface: 'some networks',
}

const copy = async () => {
  if (!props.exposure?.probe_command) return
  await navigator.clipboard.writeText(props.exposure.probe_command)
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}
</script>

<template>
  <div class="machine">
    <header class="page-head">
      <h1>{{ host?.target ?? 'This machine' }}</h1>
      <p v-if="host" class="lead">
        {{ host.os.system }} {{ host.os.release }}, seen from the inside on {{ formatDate(host.completed_at) }}.
      </p>
      <p v-else class="lead">Start AttackLens with <code>attacklens start</code> to see this machine from the inside.</p>
    </header>

    <template v-if="host">
      <dl class="facts-grid">
        <div>
          <dt>Firewall</dt>
          <dd>{{ host.firewall.status === 'enabled' ? 'On' : host.firewall.status === 'unknown' ? 'Unknown' : 'Weak' }}</dd>
        </div>
        <div>
          <dt>Listening beyond this machine</dt>
          <dd>{{ beyond.length }} <small>of {{ host.listeners.items.length }}</small></dd>
        </div>
        <div>
          <dt>Updates waiting</dt>
          <dd>{{ host.outdated_count ?? '—' }} <small>of {{ host.packages.items.length }} programs</small></dd>
        </div>
        <div>
          <dt>Starts by itself</dt>
          <dd>{{ host.autorun_count ?? '—' }} <small>programs</small></dd>
        </div>
      </dl>

      <div class="machine-grid">
      <section class="proof" aria-labelledby="proof-title">
        <h2 id="proof-title">Proof from outside</h2>
        <template v-if="exposure?.status === 'verified'">
          <p>
            A probe of {{ exposure.probe?.target }} on {{ formatDate(exposure.probe?.completed_at) }} found
            {{ exposure.summary.exposed }} reachable, {{ exposure.summary.shielded }} blocked,
            and {{ exposure.summary.unverified }} not tested.
          </p>
        </template>
        <template v-else>
          <p>
            Connecting to your own address skips your firewall, so everything above comes from the
            inside. To know what others can really reach, run this on another machine on the same network,
            then <code>attacklens import probe.json</code> here.
          </p>
          <div class="command">
            <code>{{ exposure?.probe_command }}</code>
            <button class="link" type="button" @click="copy">{{ copied ? 'Copied' : 'Copy' }}</button>
          </div>
        </template>
      </section>

      <section aria-labelledby="ports-title">
        <h2 id="ports-title">What listens</h2>
        <table class="table">
          <thead>
            <tr><th scope="col" class="num">Port</th><th scope="col">Program</th><th scope="col">Open to</th></tr>
          </thead>
          <tbody>
            <tr v-for="item in beyond" :key="`${item.port}-${item.process}`">
              <td class="num">{{ item.port }}</td>
              <td>{{ item.process }}</td>
              <td>{{ EXPOSURE[item.exposure] }}</td>
            </tr>
          </tbody>
        </table>
        <p class="note">{{ local }} more listen only on this machine, which other machines cannot reach.</p>
      </section>
      </div>
    </template>

    <details class="runtime">
      <summary>Where AttackLens itself runs</summary>
      <p class="note">
        This describes the {{ inventory?.scope === 'container' ? 'Docker container' : 'process' }} of the API, not your machine.
      </p>
      <ul class="checks">
        <li v-for="check in posture?.checks ?? []" :key="check.id">
          <span>{{ check.title }}</span>
          <span class="note">{{ check.status.replace('_', ' ') }}</span>
        </li>
      </ul>
      <p v-if="vulnerabilities?.status === 'disabled'" class="note">
        Package lookup is off. Set <code>ATTACKLENS_ENABLE_OSV=true</code> to send package names to the public OSV database.
      </p>
    </details>
  </div>
</template>
