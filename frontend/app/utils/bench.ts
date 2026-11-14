import type { AttackPathReport, Finding, HostReport } from '~/types/scan'
import { byRisk, isOpen } from '~/utils/findings'

// The optical bench: every service is a ray leaving the network. The firewall is the
// aperture stop, services and the user account are lenses, and the focus is what an
// attacker is after. A ray reaching the focus is an attack path.
// This file says what is on the bench. utils/glyphField.ts draws it.

export type RayState = 'proved' | 'unproved' | 'stopped'

export interface Ray {
  id: string
  label: string
  port: number | null
  state: RayState
  reaches: boolean
  finding: Finding
}

export interface SideRay {
  id: string
  label: string
  reaches: boolean
}

export interface Bench {
  rays: Ray[]
  side: SideRay[]
  firewall: string
  services: number | null
  admin: boolean | null
  focused: boolean
}

const MAX_RAYS = 7

const stateOf = (finding: Finding): RayState => {
  if (finding.reachability === 'exposed') return 'proved'
  if (finding.reachability === 'shielded' || finding.reachability === 'local') return 'stopped'
  return 'unproved'
}

export const buildBench = (
  findings: Finding[],
  hostFindings: Finding[],
  host: HostReport | null,
  paths: AttackPathReport | null,
  measured = true,
): Bench => {
  const entries = new Set((paths?.paths ?? []).flatMap((path) => path.entries ?? []))
  const open = findings.filter((finding) => finding.port && isOpen(finding)).sort(byRisk)

  const rays = open.slice(0, MAX_RAYS).map((finding) => {
    const state = stateOf(finding)
    return {
      id: finding.finding_id ?? String(finding.port),
      label: finding.service ?? `Port ${finding.port}`,
      port: finding.port ?? null,
      state,
      reaches: state !== 'stopped' && entries.has(finding.finding_id ?? ''),
      finding,
    }
  })

  const side: SideRay[] = []
  if (paths?.paths.some((path) => path.id === 'malware-chain')) {
    side.push({ id: 'file', label: 'A file you open', reaches: true })
  }

  const admin = hostFindings.some((finding) => finding.title === 'The daily account is an administrator' && isOpen(finding))

  return {
    rays,
    side,
    firewall: host?.firewall.status ?? 'unknown',
    services: measured ? open.length : null,
    admin: host ? admin : null,
    focused: rays.some((ray) => ray.reaches) || side.some((ray) => ray.reaches),
  }
}

// A ray is a proved way in when it is reachable from outside and leads to full control.
// It is the only thing on the bench drawn in the accent.
export const isProvedWay = (ray: Pick<Ray, 'state' | 'reaches'>) => ray.reaches && ray.state === 'proved'

// Ways in that do not go through the network cannot be drawn as rays: they are named instead.
export const waysNotDrawn = (paths: AttackPathReport | null): string[] =>
  (paths?.paths ?? [])
    .filter((path) => !(path.entries ?? []).length && path.id !== 'malware-chain')
    .map((path) => path.title)

export const describeRay = (ray: Ray) => {
  const name = `${ray.label}, port ${ray.port}`
  if (ray.state === 'stopped') return `${name}: blocked before it reaches this machine.`
  const access = ray.state === 'proved' ? 'proved reachable from outside' : 'not proved reachable from outside'
  return `${name}: ${access}${ray.reaches ? ', and it leads to full control.' : ', with no known path beyond it.'}`
}
