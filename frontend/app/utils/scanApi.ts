import type { ScanComparison, ScanHistory, ScanRequest, ScanResults } from '~/types/scan'

export const createScanApi = (baseURL?: string) => {
  const request = <T>(url: string, options?: Parameters<typeof $fetch<T>>[1]) =>
    $fetch<T>(url, { baseURL, ...options })

  return {
    getResults: () => request<ScanResults>('/api/results'),
    getHistory: () => request<ScanHistory>('/api/scans'),
    compareScans: (beforeId: string, afterId: string) => request<ScanComparison>('/api/scans/compare', {
      query: { before_id: beforeId, after_id: afterId },
    }),
    runScan: (body: ScanRequest) => request<ScanResults>('/api/scan', {
      method: 'POST',
      body,
    }),
  }
}