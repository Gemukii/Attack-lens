import type { AttackPathReport, Finding, HostReport } from '~/types/scan'
import { byRisk, isOpen } from '~/utils/findings'

// The optical bench: every service is a ray leaving the network. The firewall is the
// aperture stop, services and the user account are lenses, and the focus is what an
// attacker is after. A ray reaching the focus is an attack path.

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

export const STATIONS = { source: 0, stop: 0.27, service: 0.5, account: 0.73, focus: 0.955 }

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

export const STOP_OPENING = 0.68

// Like real rays from afar, they arrive parallel to the axis. Rays that get through
// pass inside the opening of the stop, and blocked ones strike its blades.
export const rayHeights = (rays: Array<Pick<Ray, 'state'>>): number[] => {
  const passing = rays.filter((ray) => ray.state !== 'stopped').length
  let passed = 0
  let blocked = 0
  return rays.map((ray) => {
    if (ray.state === 'stopped') {
      const side = blocked % 2 === 0 ? -1 : 1
      const row = Math.floor(blocked / 2)
      blocked += 1
      return side * (STOP_OPENING + 0.09 + row * 0.1)
    }
    passed += 1
    if (passing === 1) return -0.3
    return -0.56 + (1.12 * (passed - 1)) / (passing - 1)
  })
}

export const rayPoints = (height: number, ray: Pick<Ray, 'state' | 'reaches'>): Array<[number, number]> => {
  if (ray.state === 'stopped') {
    return [[STATIONS.source, height], [STATIONS.stop, height]]
  }
  if (!ray.reaches) {
    // It gets through, but no known path leads anywhere from there.
    return [[STATIONS.source, height], [STATIONS.service, height], [0.585, height * 0.86]]
  }
  return [
    [STATIONS.source, height],
    [STATIONS.service, height],
    [STATIONS.account, height * 0.52],
    [STATIONS.focus, 0],
  ]
}

// A file you open comes in behind the firewall: that is the point of drawing it.
export const SIDE_START: [number, number] = [0.6, 1]

export const sideRayPoints = (index: number): Array<[number, number]> => [
  [SIDE_START[0] + index * 0.04, SIDE_START[1]],
  [STATIONS.account, 0.3],
  [STATIONS.focus, 0],
]

export const describeRay = (ray: Ray) => {
  const name = `${ray.label}, port ${ray.port}`
  if (ray.state === 'stopped') return `${name}: blocked before it reaches this machine.`
  const access = ray.state === 'proved' ? 'proved reachable from outside' : 'not proved reachable from outside'
  return `${name}: ${access}${ray.reaches ? ', and it leads to full control.' : ', with no known path beyond it.'}`
}
