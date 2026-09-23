import type { HostInventory, PostureReport, ScanComparison, ScanHistory, ScanResults, ScanStatus, VulnerabilityReport } from '~/types/scan'
import { createScanApi } from '~/utils/scanApi'

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

export const useScan = () => {
  const config = useRuntimeConfig()
  const apiBase = import.meta.server ? config.apiInternalBase : config.public.apiBase
  const api = createScanApi(apiBase as string | undefined)
  const results = ref<ScanResults | null>(null)
  const history = ref<ScanHistory>([])
  const status = ref<ScanStatus>('idle')
  const error = ref<string | null>(null)
  const comparison = ref<ScanComparison | null>(null)
  const inventory = ref<HostInventory | null>(null)
  const vulnerabilities = ref<VulnerabilityReport | null>(null)
  const posture = ref<PostureReport | null>(null)

  const loadResults = async () => {
    status.value = 'loading'
    error.value = null
    try {
      results.value = await api.getResults()
      status.value = 'completed'
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

  const runScan = async (target: string) => {
    status.value = 'running'
    error.value = null
    comparison.value = null
    try {
      results.value = await api.runScan({ target })
      history.value = [results.value, ...history.value.filter((item) => item.scan_id !== results.value?.scan_id)]
      status.value = 'completed'
    } catch (cause: unknown) {
      error.value = getApiErrorMessage(cause, 'The scan failed.')
      status.value = 'failed'
    }
  }

  const loadHistory = async () => {
    try {
      history.value = await api.getHistory()
    } catch {
      history.value = []
    }
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

  const compareScans = async (beforeId: string, afterId: string) => {
    try {
      comparison.value = await api.compareScans(beforeId, afterId)
    } catch (cause: unknown) {
      error.value = getApiErrorMessage(cause, 'Unable to compare scans.')
      comparison.value = null
    }
  }

  return { results, history, comparison, inventory, vulnerabilities, posture, status, error, loadResults, loadHistory, loadInventory, loadVulnerabilities, loadPosture, compareScans, runScan }
}