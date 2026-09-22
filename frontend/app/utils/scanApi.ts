import type { ScanRequest, ScanResults } from '~/types/scan'

export const createScanApi = (baseURL?: string) => {
  const request = <T>(url: string, options?: Parameters<typeof $fetch<T>>[1]) =>
    $fetch<T>(url, { baseURL, ...options })

  return {
    getResults: () => request<ScanResults>('/api/results'),
    runScan: (body: ScanRequest) => request<ScanResults>('/api/scan', {
      method: 'POST',
      body,
    }),
  }
}