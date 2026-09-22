import type { ScanResults, ScanStatus } from '~/types/scan'
import { createScanApi } from '~/utils/scanApi'

export const useScan = () => {
  const config = useRuntimeConfig()
  const apiBase = import.meta.server ? config.apiInternalBase : config.public.apiBase
  const api = createScanApi(apiBase as string | undefined)
  const results = ref<ScanResults | null>(null)
  const status = ref<ScanStatus>('idle')
  const error = ref<string | null>(null)

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
      error.value = cause instanceof Error ? cause.message : 'Unable to load scan results.'
      status.value = 'failed'
    }
  }

  const runScan = async (target: string) => {
    status.value = 'running'
    error.value = null
    try {
      results.value = await api.runScan({ target })
      status.value = 'completed'
    } catch (cause: unknown) {
      error.value = cause instanceof Error ? cause.message : 'The scan failed.'
      status.value = 'failed'
    }
  }

  return { results, status, error, loadResults, runScan }
}