<script setup lang="ts">
import type { ExposureReport } from '~/types/scan'

const props = defineProps<{
  report: ExposureReport | null
}>()

const copied = ref(false)

const copy = async () => {
  if (!props.report?.probe_command) return
  await navigator.clipboard.writeText(props.report.probe_command)
  copied.value = true
  setTimeout(() => (copied.value = false), 1600)
}
</script>

<template>
  <section v-if="report && report.status !== 'no_host_report'">
    <span class="eyebrow">Proof from outside</span>

    <dl v-if="report.status === 'verified'" class="compare-result">
      <div><dd><strong>{{ report.summary.exposed }}</strong></dd><dt>exposed</dt></div>
      <div><dd><strong>{{ report.summary.shielded }}</strong></dd><dt>shielded</dt></div>
      <div><dd><strong>{{ report.summary.unverified }}</strong></dd><dt>not tested</dt></div>
      <p>Probe of {{ report.probe?.target }}, {{ formatDate(report.probe?.completed_at) }}.</p>
    </dl>

    <template v-else>
      <p class="note">
        Connecting to your own address skips your firewall, so nothing here proves what other
        machines can reach. Run this from another machine on the network:
      </p>
      <code class="command">{{ report.probe_command }}</code>
      <button class="button small" type="button" @click="copy">{{ copied ? 'Copied' : 'Copy' }}</button>
      <p class="note">Then here: <code>attacklens import probe.json</code></p>
    </template>
  </section>
</template>
