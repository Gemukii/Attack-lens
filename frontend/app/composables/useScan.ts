import type { Agent, Alert, AttackPathReport, AuditEntry, ExposureReport, HostInventory, HostReport, PostureReport, ScanComparison, ScanHistory, ScanResults, ScanStatus, TriageStatus, VulnerabilityReport } from '~/types/scan'
import { createScanApi } from '~/utils/scanApi'

const JOB_POLL_MS = 800
const JOB_TIMEOUT_MS = 200_000

const getApiErrorMessage = (cause: unknown, fallback: string) => {
  const error = cause as {
    data?: { detail?: string }
    response?: { _data?: { detail?: string }; status?: number }
    statusCode?: number
    message?: string
  }
  // The proxy answers 502 to 504 when the API behind it is down: say so in plain words.
  const status = error.response?.status ?? error.statusCode
  if (status && status >= 502 && status <= 504) return 'The API is not answering. Is attacklens start still running?'
  return error.data?.detail
    ?? error.response?._data?.detail
    ?? error.message
    ?? fallback
}

const pause = (milliseconds: number) => new Promise((resolve) => setTimeout(resolve, milliseconds))

export const useScan = () => {
  const api = createScanApi()
  const results = ref<ScanResults | null>(null)
  const history = ref<ScanHistory>([])
  const status = ref<ScanStatus>('idle')
  const error = ref<string | null>(null)
  const comparison = ref<ScanComparison | null>(null)
  const inventory = ref<HostInventory | null>(null)
  const vulnerabilities = ref<VulnerabilityReport | null>(null)
  const posture = ref<PostureReport | null>(null)
  const hostReport = ref<HostReport | null>(null)
  const alerts = ref<Alert[]>([])
  const agents = ref<Agent[]>([])
  const agent = computed(() => agents.value.find((item) => item.online) ?? null)
  const silentAgent = computed(() => agents.value.find((item) => item.silent_since) ?? null)
  const paths = ref<AttackPathReport | null>(null)
  const exposure = ref<ExposureReport | null>(null)
  const audit = ref<AuditEntry[]>([])
  // When the API last answered, and whether its last poll failed: the freshness indicator.
  const syncedAt = ref<number | null>(null)
  const syncFailed = ref(false)
  // Alerts that arrived after the first load, so the journal can show them arriving.
  const freshAlertIds = ref<Set<number>>(new Set())
  let alertsPrimed = false

  const loadResults = async () => {
    try {
      results.value = await api.getResults()
      if (status.value !== 'running') status.value = 'completed'
    } catch (cause: unknown) {
      if ((cause as { response?: { status?: number } })?.response?.status === 404) {
        results.value = null
        status.value = 'idle'
        return
      }
      error.value = getApiErrorMessage(cause, 'Unable to load scan results.')
      status.value = 'failed'
    }
  }

  const loadHistory = async () => {
    try {
      history.value = await api.getHistory(results.value?.target)
    } catch {
      history.value = []
    }
  }

  const loadHostReport = async () => {
    try {
      hostReport.value = await api.getHostReport()
    } catch {
      hostReport.value = null
    }
  }

  const loadAnalysis = async () => {
    const [nextPaths, nextExposure, nextAudit] = await Promise.allSettled([api.getPaths(), api.getExposure(), api.getAudit()])
    paths.value = nextPaths.status === 'fulfilled' ? nextPaths.value : null
    exposure.value = nextExposure.status === 'fulfilled' ? nextExposure.value : null
    audit.value = nextAudit.status === 'fulfilled' ? nextAudit.value : []
  }

  const createEnrollmentCode = async () => {
    try {
      return (await api.createEnrollmentCode()).code
    } catch (cause: unknown) {
      error.value = getApiErrorMessage(cause, 'Unable to create an enrollment code.')
      return null
    }
  }

  const loadAlerts = async () => {
    try {
      const next = await api.getAlerts()
      if (alertsPrimed) {
        const known = new Set(alerts.value.map((alert) => alert.alert_id))
        freshAlertIds.value = new Set(next.filter((alert) => !known.has(alert.alert_id)).map((alert) => alert.alert_id))
      }
      alertsPrimed = true
      alerts.value = next
    } catch {
      alerts.value = []
    }
  }

  const loadAgents = async () => {
    const wasOnline = Boolean(agent.value)
    try {
      agents.value = await api.getAgents()
      syncedAt.value = Date.now()
      syncFailed.value = false
    } catch {
      agents.value = []
      syncFailed.value = true
    }
    // The agent sends a host report when it starts: show it without a manual refresh.
    if (!wasOnline && agent.value) await loadHostReport()
  }

  const loadInventory = async () => {
    try {
      inventory.value = await api.getInventory()
    } catch {
      inventory.value = null
    }
  }

  const loadVulnerabilities = async () => {
    try {
      vulnerabilities.value = await api.getVulnerabilities()
    } catch {
      vulnerabilities.value = { status: 'unavailable', packages_checked: 0, vulnerabilities: [] }
    }
  }

  const loadPosture = async () => {
    try {
      posture.value = await api.getPosture()
    } catch {
      posture.value = null
    }
  }

  const loadAll = async () => {
    error.value = null
    if (status.value !== 'running') status.value = 'loading'
    await loadResults()
    await Promise.all([loadHistory(), loadHostReport(), loadAlerts(), loadAgents(), loadAnalysis(), loadInventory(), loadVulnerabilities(), loadPosture()])
  }

  const waitForJob = async (jobId: string) => {
    const deadline = Date.now() + JOB_TIMEOUT_MS
    while (Date.now() < deadline) {
      const job = await api.getJob(jobId)
      if (job.status === 'done') return
      if (job.status === 'failed') throw new Error(job.error ?? 'The agent could not run this scan.')
      await pause(JOB_POLL_MS)
    }
    throw new Error('The agent did not answer in time.')
  }

  // With a connected agent the scan runs on the host. Otherwise it runs from the API.
  const runScan = async (target: string, fallbackTarget: string) => {
    status.value = 'running'
    error.value = null
    comparison.value = null
    try {
      if (agent.value) {
        const job = await api.createJob(target || null)
        await waitForJob(job.job_id)
      } else {
        await api.runScan({ target: target || fallbackTarget })
      }
      status.value = 'completed'
      await Promise.all([loadResults(), loadHostReport(), loadAlerts(), loadAnalysis()])
      await loadHistory()
    } catch (cause: unknown) {
      error.value = getApiErrorMessage(cause, 'The scan failed.')
      status.value = 'failed'
    }
  }

  const compareScans = async (beforeId: string, afterId: string) => {
    try {
      comparison.value = await api.compareScans(beforeId, afterId)
    } catch (cause: unknown) {
      error.value = getApiErrorMessage(cause, 'Unable to compare scans.')
      comparison.value = null
    }
  }

  const setTriage = async (findingId: string, triageStatus: TriageStatus, reason?: string, days?: number) => {
    try {
      await api.setTriage(findingId, triageStatus, reason, days)
      await Promise.all([loadResults(), loadHostReport(), loadAnalysis()])
    } catch (cause: unknown) {
      error.value = getApiErrorMessage(cause, 'Unable to save this decision.')
    }
  }

  return { results, history, comparison, inventory, vulnerabilities, posture, hostReport, alerts, freshAlertIds, agent, silentAgent, paths, exposure, audit, status, error, syncedAt, syncFailed, loadAll, loadAgents, compareScans, runScan, setTriage, createEnrollmentCode }
}
