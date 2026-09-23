export type ScanStatus = 'idle' | 'loading' | 'running' | 'completed' | 'failed'

export interface Finding {
  id?: string
  category?: string
  severity?: string
  title?: string
  description?: string
  evidence?: string
  remediation?: string
  risk_reason?: string
  references?: string[]
  cve?: string
  cvss?: number
  port?: number
  service?: string
  protocol?: string
  version?: string
  banner?: string
}

export interface ScanService {
  name: string
  port?: number
  protocol?: string
  version?: string
  banner?: string
  evidence?: string
}

export interface ScanResults {
  scan_id?: string
  target: string
  scan_type: string
  findings: Finding[]
  completed_at?: string
  duration_seconds?: number
  score?: number
  open_ports?: number[]
  services?: ScanService[]
}

export interface ScanRequest {
  target: string
}

export type ScanHistory = ScanResults[]

export interface ScanComparison {
  before_id: string
  after_id: string
  score_delta: number
  finding_count_delta: number
  new_findings: Finding[]
  fixed_findings: Finding[]
  persistent_findings: Finding[]
  ports_added: number[]
  ports_removed: number[]
}