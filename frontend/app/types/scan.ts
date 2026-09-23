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

export interface HostInventory {
  collected_at: string
  scope: string
  hostname: string
  current_user: string
  os: {
    system: string
    release: string
    version: string
    machine: string
    python: string
  }
  cpu: {
    logical_count?: number
    physical_count?: number
    percent_used: number
  }
  memory: {
    total_bytes: number
    available_bytes: number
    percent_used: number
  }
  disks: Array<{
    device: string
    mountpoint: string
    filesystem: string
    total_bytes: number
    used_bytes: number
    free_bytes: number
    percent_used: number
  }>
  network_addresses: Array<{
    interface: string
    family: string
    address: string
  }>
  processes: Array<{
    pid: number
    name: string
    username?: string
    status?: string
  }>
  packages: Array<{
    name: string
    version: string
  }>
  python_path: string
}

export interface VulnerabilityReport {
  status: 'complete' | 'unavailable'
  packages_checked: number
  vulnerabilities: Array<{
    id?: string
    aliases: string[]
    summary: string
    details: string
    modified?: string
    package: string
    version: string
    fixed_versions: string[]
    references: string[]
    severity?: string
    remediation: string
  }>
}

export interface PostureReport {
  scope: string
  checks: Array<{
    id: string
    title: string
    status: 'pass' | 'fail' | 'warn' | 'unknown' | 'not_checked'
    severity: string
    description: string
    remediation: string
    evidence?: string[]
  }>
  summary: {
    failures: number
    warnings: number
    unknown: number
  }
}