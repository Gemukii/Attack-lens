import type { Finding } from '~/types/scan'

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export const isOpen = (finding: Finding) => (finding.triage_status ?? 'open') === 'open'

// Risk comes first: it knows about reachability and exploitation, severity does not.
export const byRisk = (a: Finding, b: Finding) =>
  (b.risk?.score ?? 0) - (a.risk?.score ?? 0)
  || (SEVERITY_RANK[a.severity ?? 'info'] ?? 5) - (SEVERITY_RANK[b.severity ?? 'info'] ?? 5)
  || (a.port ?? 99999) - (b.port ?? 99999)

export const REACHABILITY_LABELS: Record<string, string> = {
  exposed: 'reachable',
  shielded: 'blocked',
  local: 'local',
  unverified: 'not proved',
}

export const LAPSE_LABELS: Record<string, string> = {
  expired: 'Your earlier decision expired.',
  changed: 'This changed since your decision, so it is open again.',
}

export const splitHostFindings = (findings: Finding[]) => ({
  machine: findings.filter((item) => !['software', 'persistence'].includes(item.category ?? '')),
  software: findings.filter((item) => item.category === 'software'),
  autostart: findings.filter((item) => item.category === 'persistence'),
})
