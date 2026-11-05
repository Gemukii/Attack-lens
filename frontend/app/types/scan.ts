export type ScanStatus = 'idle' | 'loading' | 'running' | 'completed' | 'failed'

export type TriageStatus = 'open' | 'accepted' | 'false_positive'

export interface Agent {
  hostname: string
  platform: string
  version: string
  address: string
  last_seen: string
  online: boolean
}

export interface ScanJob {
  job_id: string
  agent: string
  target: string | null
  status: 'queued' | 'running' | 'done' | 'failed'
  error: string | null
  scan_id: string | null
}

export interface Finding {
  finding_id?: string
  target?: string
  category?: string
  severity?: string
  title?: string
  description?: string
  evidence?: string
  remediation?: string
  risk_reason?: string
  references?: string[]
  cve?: string | null
  cvss?: number | null
  port?: number | null
  service?: string | null
  protocol?: string | null
  version?: string | null
  banner?: string | null
  process?: string | null
  exposure?: 'loopback' | 'interface' | 'all' | null
  triage_status?: TriageStatus
  triage_reason?: string | null
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
  status?: 'complete' | 'partial' | 'no_response'
  findings: Finding[]
  completed_at?: string
  duration_seconds?: number
  score?: number | null
  raw_score?: number
  coverage?: {
    ports_checked?: number
    ports_open?: number
    ports_closed?: number
    ports_filtered?: number
  }
  open_ports?: number[]
  services?: ScanService[]
  port_states?: Record<string, string>
  vantage?: string
}

export interface HostReport extends ScanResults {
  os: {
    system: string
    release: string
    version: string
  }
  listeners: {
    status: string
    items: Array<{
      port: number
      protocol: string
      process: string
      addresses: string[]
      exposure: 'loopback' | 'interface' | 'all'
    }>
  }
  firewall: {
    status: 'enabled' | 'disabled' | 'partial' | 'unknown'
    source: string
  }
  packages: {
    status: string
    source: string
    ecosystem?: string | null
    items: Array<{ name: string; version: string }>
  }
  vulnerabilities: {
    status: 'complete' | 'partial' | 'unavailable' | 'disabled' | 'not_covered'
    packages_checked: number
    advisories_found: number
    fixable: number
  }
}

export interface Alert {
  alert_id: number
  scan_id: string
  target: string
  created_at: string
  message: string
  findings: Finding[]
  delivered: boolean
}

export interface ScanRequest {
  target: string
}

export type ScanHistory = ScanResults[]

export interface ScanComparison {
  before_id: string
  after_id: string
  score_delta: number | null
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
  status: 'complete' | 'partial' | 'unavailable' | 'disabled'
  packages_checked: number
  advisories_found?: number
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
    severity?: string | null
    cvss_vector?: string | null
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