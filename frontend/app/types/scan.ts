export type ScanStatus = 'idle' | 'loading' | 'running' | 'completed' | 'failed'

export interface Finding {
  id?: string
  category?: string
  severity?: string
  title?: string
  description?: string
  evidence?: string
  remediation?: string
  references?: string[]
  cve?: string
  cvss?: number
  port?: number
  service?: string
}

export interface ScanService {
  name: string
  port?: number
  protocol?: string
  evidence?: string
}

export interface ScanResults {
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