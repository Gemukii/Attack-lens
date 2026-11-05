<script setup lang="ts">
import type { AttackPathReport } from '~/types/scan'

defineProps<{
  report: AttackPathReport | null
}>()
</script>

<template>
  <section class="paths" aria-label="Attack paths">
    <div class="panel-head">
      <div>
        <span class="eyebrow">Attack paths</span>
        <h2 class="section-title">How this machine could fall</h2>
      </div>
      <p v-if="report?.best_cut" class="best-cut">
        <span class="eyebrow">Fix first</span>
        <strong>{{ report.best_cut.title }}</strong>
        <span class="note">Breaks {{ report.best_cut.paths_broken }} path{{ report.best_cut.paths_broken === 1 ? '' : 's' }}. {{ report.best_cut.remediation }}</span>
      </p>
    </div>

    <p v-if="!report?.paths.length" class="note">
      No complete attack path with the current evidence. A path needs every link backed by a finding.
    </p>

    <article v-for="path in report?.paths ?? []" :key="path.id" class="path">
      <header>
        <span class="ledger-severity"><SeverityMark :severity="path.severity" labelled /></span>
        <h3>{{ path.title }}</h3>
        <span class="tag">{{ path.certainty }}</span>
      </header>
      <ol class="chain">
        <li v-for="(step, index) in path.steps" :key="index" :style="{ '--i': index }">
          <span class="eyebrow">{{ step.stage }}</span>
          <span>{{ step.label }}</span>
        </li>
      </ol>
    </article>
  </section>
</template>
