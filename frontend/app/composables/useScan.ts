import type { Agent, Alert, HostInventory, HostReport, PostureReport, ScanComparison, ScanHistory, ScanResults, ScanStatus, TriageStatus, VulnerabilityReport } from '~/types/scan'
import { createScanApi } from '~/utils/scanApi'

const JOB_POLL_MS = 800
const JOB_TIMEOUT_MS = 200_000

const getApiErrorMessage = (cause: unknown, fallback: string) => {
  const error = cause as {
    data?: { detail?: string }
    response?: { _data?: { detail?: string }; status?: number }
    message?: string
  }
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

  const loadAlerts = async () => {
    try {
      alerts.value = await api.getAlerts()
    } catch {
      alerts.value = []
    }
  }

  const loadAgents = async () => {
    const wasOnline = Boolean(agent.value)
    try {
      agents.value = await api.getAgents()
    } catch {
      agents.value = []
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
    await Promise.all([loadHistory(), loadHostReport(), loadAlerts(), loadAgents(), loadInventory(), loadVulnerabilities(), loadPosture()])
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
      await Promise.all([loadResults(), loadHostReport(), loadAlerts()])
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

  const setTriage = async (findingId: string, triageStatus: TriageStatus, reason?: string) => {
    try {
      await api.setTriage(findingId, triageStatus, reason)
      await Promise.all([loadResults(), loadHostReport()])
    } catch (cause: unknown) {
      error.value = getApiErrorMessage(cause, 'Unable to save this decision.')
    }
  }

  return { results, history, comparison, inventory, vulnerabilities, posture, hostReport, alerts, agent, status, error, loadAll, loadAgents, compareScans, runScan, setTriage }
}
