import type { Agent, ExposureReport, ScanResults } from '~/types/scan'
import { ago, formatDate } from '~/utils/format'

// The reading line: when, from where, by what, and what was not seen. It travels with every
// screen, because a figure is only worth what is known about how it was measured.

// Beyond this a reading is called stale: the machine may have changed since.
export const STALE_READING_MS = 7 * 24 * 60 * 60 * 1000

export interface ReadingItem {
  id: 'agent' | 'read' | 'from' | 'probe' | 'coverage' | 'target'
  label: string
  value: string
  // What stands behind the value. It changes when the fact changes, not when a clock ticks:
  // "2 h ago" becoming "3 h ago" is the same reading.
  stamp: string
  title?: string
  mono?: boolean
  // The agent lamp: answering, gone quiet, or never connected.
  lamp?: 'on' | 'off' | 'none'
  // Something about the feed is broken or out of date.
  alert?: boolean
}

export interface ReadingSource {
  scan: ScanResults | null
  exposure: ExposureReport | null
  agent: Agent | null
  silentAgent: Agent | null
  unreachable: boolean
  syncedAt: number | null
  now: number
}

export const isStale = (scan: ScanResults | null, now: number) => {
  const read = scan?.completed_at ? Date.parse(scan.completed_at) : Number.NaN
  return !Number.isNaN(read) && now - read > STALE_READING_MS
}

const feed = ({ agent, silentAgent, unreachable, syncedAt, now }: ReadingSource): ReadingItem => {
  if (unreachable) {
    return { id: 'agent', label: 'API', value: syncedAt ? `Unreachable, last answer ${ago(syncedAt, now)}` : 'Unreachable', stamp: 'unreachable', lamp: 'off', alert: true }
  }
  if (agent) return { id: 'agent', label: 'Agent', value: `${agent.hostname} online`, stamp: `on ${agent.hostname}`, lamp: 'on' }
  if (silentAgent) {
    return { id: 'agent', label: 'Agent', value: `${silentAgent.hostname} quiet, ${ago(silentAgent.silent_since, now)}`, stamp: `off ${silentAgent.hostname}`, lamp: 'off', alert: true }
  }
  return { id: 'agent', label: 'Agent', value: 'None connected', stamp: 'none', lamp: 'none' }
}

const VANTAGE: Record<string, string> = { host: 'The machine itself', container: 'The Docker container' }

export const buildReading = (source: ReadingSource): ReadingItem[] => {
  const { scan, exposure, now } = source
  // With the API down and nothing loaded, "never" and "none yet" would be claims: it is not known.
  const unknown = source.unreachable && !scan
  const stale = isStale(scan, now)
  const probed = exposure?.status === 'verified' ? exposure.probe?.completed_at : undefined
  const checked = scan?.coverage?.ports_checked
  return [
    feed(source),
    {
      id: 'read',
      label: 'Read',
      value: scan?.completed_at ? `${ago(scan.completed_at, now)}${stale ? ', stale' : ''}` : unknown ? 'Not known' : 'Never',
      stamp: `${scan?.completed_at ?? ''} ${stale}`,
      title: scan?.completed_at ? formatDate(scan.completed_at) : undefined,
      alert: stale,
    },
    { id: 'from', label: 'From', value: scan?.vantage ? VANTAGE[scan.vantage] ?? scan.vantage : unknown ? 'Not known' : 'Not read', stamp: scan?.vantage ?? '' },
    { id: 'probe', label: 'Probe', value: probed ? `${ago(probed, now)}, from outside` : unknown ? 'Not known' : 'None yet', stamp: probed ?? '' },
    { id: 'coverage', label: 'Coverage', value: checked ? `${checked} ports checked` : unknown ? 'Not known' : 'Not read', stamp: String(checked ?? '') },
    { id: 'target', label: 'Target', value: scan?.target ?? (unknown ? 'Not known' : 'None yet'), stamp: scan?.target ?? '', mono: true },
  ]
}
