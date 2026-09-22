<script setup lang="ts">
interface Finding {
  category: string
  severity: string
  title: string
  description: string
  evidence: string
  remediation: string
  references: string[]
}

interface ScanResults {
  target: string
  scan_type: string
  findings: Finding[]
}

const config = useRuntimeConfig()

const { data, error } = await useFetch<ScanResults>(
  '/api/results',
  {
    baseURL: config.public.apiBase,
  },
)

const findings = computed(() => data.value?.findings ?? [])

function severityCount(severity: string): number {
  return findings.value.filter(
    (finding) => finding.severity === severity,
  ).length
}
</script>

<template>
  <div class="dashboard">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">A</div>

        <div>
          <strong>AttackLens</strong>
          <span>Security Scanner</span>
        </div>
      </div>

      <nav>
        <a class="active">Overview</a>
        <a>Findings</a>
        <a>Scans</a>
        <a>Network</a>
        <a>System</a>
        <a>Docker</a>
      </nav>

      <div class="sidebar-footer">
        <span class="status-dot"></span>
        Scanner online
      </div>
    </aside>

    <main class="content">
      <header class="header">
        <div>
          <p class="eyebrow">SECURITY OVERVIEW</p>
          <h1>Dashboard</h1>
        </div>

        <div class="target">
          <span>Target</span>
          <strong>{{ data?.target ?? 'Unknown' }}</strong>
        </div>
      </header>

      <div v-if="error" class="error">
        Unable to load scan results.
      </div>

      <template v-else>
        <section class="cards">
          <article class="card">
            <span>Total findings</span>
            <strong>{{ findings.length }}</strong>
          </article>

          <article class="card critical">
            <span>Critical</span>
            <strong>{{ severityCount('critical') }}</strong>
          </article>

          <article class="card high">
            <span>High</span>
            <strong>{{ severityCount('high') }}</strong>
          </article>

          <article class="card medium">
            <span>Medium</span>
            <strong>{{ severityCount('medium') }}</strong>
          </article>
        </section>

        <section class="panel">
          <div class="panel-header">
            <div>
              <p class="eyebrow">LATEST SCAN</p>
              <h2>Findings</h2>
            </div>

            <span class="scan-type">
              {{ data?.scan_type ?? 'unknown' }}
            </span>
          </div>

          <div
            v-if="findings.length === 0"
            class="empty"
          >
            No findings detected.
          </div>

          <div v-else class="findings">
            <article
              v-for="finding in findings"
              :key="`${finding.title}-${finding.evidence}`"
              class="finding"
            >
              <div
                class="severity"
                :class="finding.severity"
              >
                {{ finding.severity }}
              </div>

              <div class="finding-content">
                <h3>{{ finding.title }}</h3>
                <p>{{ finding.description }}</p>
                <code>{{ finding.evidence }}</code>
              </div>
            </article>
          </div>
        </section>
      </template>
    </main>
  </div>
</template>

<style scoped>
.dashboard {
  min-height: 100vh;
  display: flex;
  background: #f5f7f8;
  color: #17211b;
}

.sidebar {
  width: 240px;
  min-height: 100vh;
  padding: 28px 20px;
  display: flex;
  flex-direction: column;
  background: #14231b;
  color: #f4f7f5;
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 48px;
}

.brand-mark {
  width: 36px;
  height: 36px;
  display: grid;
  place-items: center;
  border-radius: 10px;
  background: #dfe9df;
  color: #14231b;
  font-weight: 800;
}

.brand strong,
.brand span {
  display: block;
}

.brand span {
  margin-top: 3px;
  font-size: 11px;
  opacity: 0.55;
}

nav {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

nav a {
  padding: 11px 12px;
  border-radius: 8px;
  color: #b9c5be;
  font-size: 14px;
}

nav a.active {
  background: #26392d;
  color: white;
}

.sidebar-footer {
  margin-top: auto;
  font-size: 12px;
  color: #9cab9f;
}

.status-dot {
  display: inline-block;
  width: 7px;
  height: 7px;
  margin-right: 7px;
  border-radius: 50%;
  background: #74b883;
}

.content {
  flex: 1;
  max-width: 1400px;
  padding: 42px 48px;
}

.header {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  margin-bottom: 32px;
}

.eyebrow {
  margin: 0 0 6px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.12em;
  color: #718078;
}

h1 {
  margin: 0;
  font-size: 32px;
}

.target {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
}

.target span {
  font-size: 11px;
  color: #78847d;
}

.target strong {
  font-family: monospace;
  font-size: 13px;
}

.cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 24px;
}

.card {
  padding: 22px;
  border: 1px solid #e1e6e3;
  border-radius: 14px;
  background: white;
}

.card span {
  display: block;
  margin-bottom: 12px;
  color: #738078;
  font-size: 13px;
}

.card strong {
  font-size: 30px;
}

.card.critical {
  border-left: 4px solid #8c4c4c;
}

.card.high {
  border-left: 4px solid #b87852;
}

.card.medium {
  border-left: 4px solid #b49a54;
}

.panel {
  border: 1px solid #e1e6e3;
  border-radius: 14px;
  background: white;
  overflow: hidden;
}

.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 22px 24px;
  border-bottom: 1px solid #e8ece9;
}

.panel-header h2 {
  margin: 0;
}

.scan-type {
  padding: 6px 10px;
  border-radius: 6px;
  background: #edf2ee;
  font-family: monospace;
  font-size: 12px;
}

.finding {
  display: flex;
  gap: 18px;
  padding: 20px 24px;
  border-bottom: 1px solid #edf0ee;
}

.finding:last-child {
  border-bottom: 0;
}

.severity {
  width: 75px;
  height: fit-content;
  padding: 5px 8px;
  border-radius: 5px;
  text-align: center;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
}

.severity.info {
  background: #e9eef0;
  color: #536269;
}

.severity.medium {
  background: #f1ead8;
  color: #806d38;
}

.severity.high {
  background: #f2e1d8;
  color: #8d5337;
}

.severity.critical {
  background: #ead8d8;
  color: #7c3d3d;
}

.finding-content {
  flex: 1;
}

.finding h3 {
  margin: 0 0 6px;
  font-size: 15px;
}

.finding p {
  margin: 0 0 10px;
  color: #69766f;
  font-size: 13px;
}

code {
  color: #53635a;
  font-size: 12px;
}

.empty,
.error {
  padding: 40px;
  text-align: center;
  color: #718078;
}

@media (max-width: 900px) {
  .sidebar {
    width: 190px;
  }

  .content {
    padding: 30px;
  }

  .cards {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>