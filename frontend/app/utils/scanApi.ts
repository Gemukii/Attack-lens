import type { Agent, Alert, AttackPathReport, AuditEntry, ExposureReport, HostInventory, HostReport, PostureReport, ScanComparison, ScanHistory, ScanJob, ScanRequest, ScanResults, TriageStatus, VulnerabilityReport } from '~/types/scan'

// Calls stay on the dashboard origin: server/api/[...path].ts forwards them to the API.
export const createScanApi = () => ({
  getResults: () => $fetch<ScanResults>('/api/results'),
  getHistory: (target?: string) => $fetch<ScanHistory>('/api/scans', {
    query: { scan_type: 'network', target },
  }),
  getHostReport: () => $fetch<HostReport>('/api/host'),
  getAlerts: () => $fetch<Alert[]>('/api/alerts'),
  getAgents: () => $fetch<Agent[]>('/api/agents'),
  getPaths: () => $fetch<AttackPathReport>('/api/paths'),
  getExposure: () => $fetch<ExposureReport>('/api/exposure'),
  getAudit: () => $fetch<AuditEntry[]>('/api/audit', { query: { limit: 12 } }),
  createEnrollmentCode: () => $fetch<{ code: string; expires_at: string }>('/api/agents/enrollment', { method: 'POST' }),
  getInventory: () => $fetch<HostInventory>('/api/inventory'),
  getVulnerabilities: () => $fetch<VulnerabilityReport>('/api/vulnerabilities'),
  getPosture: () => $fetch<PostureReport>('/api/posture'),
  compareScans: (beforeId: string, afterId: string) => $fetch<ScanComparison>('/api/scans/compare', {
    query: { before_id: beforeId, after_id: afterId },
  }),
  runScan: (body: ScanRequest) => $fetch<ScanResults>('/api/scan', {
    method: 'POST',
    body,
  }),
  createJob: (target: string | null) => $fetch<ScanJob>('/api/jobs', {
    method: 'POST',
    body: { target },
  }),
  getJob: (jobId: string) => $fetch<ScanJob>(`/api/jobs/${jobId}`),
  setTriage: (findingId: string, status: TriageStatus, reason?: string, days?: number) => $fetch(`/api/findings/${findingId}/triage`, {
    method: 'PUT',
    body: { status, reason: reason || null, days: days ?? null },
  }),
})
