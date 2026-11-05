<script setup lang="ts">
import type { HostInventory, PostureReport, VulnerabilityReport } from '~/types/scan'

defineProps<{
  inventory: HostInventory | null
  vulnerabilities: VulnerabilityReport | null
  posture: PostureReport | null
}>()
</script>

<template>
  <details class="runtime">
    <summary>
      <h2 class="section-title">AttackLens runtime</h2>
      <span class="note">Where the API runs{{ inventory?.scope === 'container' ? ': the Docker container, not your machine.' : '.' }}</span>
    </summary>

    <div class="runtime-grid">
      <section v-if="inventory">
        <h3 class="eyebrow">Environment</h3>
        <dl class="facts">
          <div><dt>Scope</dt><dd>{{ inventory.scope }}</dd></div>
          <div><dt>Hostname</dt><dd>{{ inventory.hostname }}</dd></div>
          <div><dt>System</dt><dd>{{ inventory.os.system }} {{ inventory.os.release }}</dd></div>
          <div><dt>User</dt><dd>{{ inventory.current_user }}</dd></div>
          <div><dt>Memory</dt><dd>{{ inventory.memory.percent_used }}% used</dd></div>
          <div><dt>Python packages</dt><dd>{{ inventory.packages.length }}</dd></div>
        </dl>
      </section>

      <section v-if="posture">
        <h3 class="eyebrow">Configuration</h3>
        <div v-for="check in posture.checks" :key="check.id" class="check">
          <span>{{ check.status.replace('_', ' ') }} · {{ check.title }}</span>
          <p>{{ check.description }}</p>
        </div>
      </section>

      <section v-if="vulnerabilities">
        <h3 class="eyebrow">Package vulnerabilities</h3>
        <p v-if="vulnerabilities.status === 'disabled'" class="note">
          Lookup disabled. Set <code>ATTACKLENS_ENABLE_OSV=true</code> to send package names and versions to the public OSV database.
        </p>
        <p v-else-if="vulnerabilities.status === 'unavailable'" class="note">
          The vulnerability database could not be reached.
        </p>
        <template v-else>
          <p v-if="!vulnerabilities.vulnerabilities.length" class="note">
            {{ vulnerabilities.packages_checked }} packages checked, none affected.
          </p>
          <div v-for="item in vulnerabilities.vulnerabilities.slice(0, 6)" :key="`${item.id}-${item.package}`" class="check">
            <span>{{ item.id }} · {{ item.package }} {{ item.version }}</span>
            <p>{{ item.summary || item.remediation }}</p>
            <a v-if="item.references[0]" :href="item.references[0]" target="_blank" rel="noopener noreferrer">Advisory</a>
          </div>
        </template>
      </section>
    </div>
  </details>
</template>
