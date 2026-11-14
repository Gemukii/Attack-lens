import type { Alert, Finding } from '~/types/scan'

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export const isOpen = (finding: Finding) => (finding.triage_status ?? 'open') === 'open'

// Risk comes first: it knows about reachability and exploitation, severity does not.
export const byRisk = (a: Finding, b: Finding) =>
  (b.risk?.score ?? 0) - (a.risk?.score ?? 0)
  || (SEVERITY_RANK[a.severity ?? 'info'] ?? 5) - (SEVERITY_RANK[b.severity ?? 'info'] ?? 5)
  || (a.port ?? 99999) - (b.port ?? 99999)

export const REACHABILITY_LABELS: Record<string, string> = {
  exposed: 'Reachable',
  shielded: 'Blocked',
  local: 'This machine only',
  unverified: 'Not proved',
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

// A critical row stays tinted: critical severity, or exploited by attackers right now.
export const isCritical = (finding: Finding) => isOpen(finding) && (finding.severity === 'critical' || Boolean(finding.known_exploited))

// Both views report the same port: keep the line with the higher risk, as the brief does.
export const uniqueByPort = (findings: Finding[]): Finding[] => {
  const seen = new Set<number>()
  return [...findings].sort(byRisk).filter((finding) => {
    if (!finding.port) return true
    if (seen.has(finding.port)) return false
    seen.add(finding.port)
    return true
  })
}

// What is known about a finding, in plain words.
export const proofLabel = (finding: Finding): string => {
  if (!isOpen(finding)) return finding.triage_status === 'accepted' ? 'Accepted' : 'False positive'
  if (finding.triage_lapsed) return 'Reopened'
  if (finding.known_exploited) return 'Exploited in the wild'
  if (finding.verification === 'confirmed') return 'Confirmed by a test'
  if (finding.reachability) return REACHABILITY_LABELS[finding.reachability] ?? finding.reachability
  return finding.port ? 'Not measured' : 'No network path'
}

// Where a finding is: its port and program, or the evidence that points at it.
export const whereText = (finding: Finding): string => {
  if (finding.port) return `${finding.port}/tcp${finding.process ? ` · ${finding.process}` : finding.version ? ` · ${finding.version}` : ''}`
  return finding.evidence ?? finding.cve ?? ''
}

// "Since when" is not in the API: it is read from the alert that first carried the finding.
export const firstSeen = (alerts: Alert[]): Map<string, string> => {
  const seen = new Map<string, string>()
  for (const alert of [...alerts].sort((a, b) => a.created_at.localeCompare(b.created_at))) {
    for (const finding of alert.findings) {
      if (finding.finding_id && !seen.has(finding.finding_id)) seen.set(finding.finding_id, alert.created_at)
    }
  }
  return seen
}
