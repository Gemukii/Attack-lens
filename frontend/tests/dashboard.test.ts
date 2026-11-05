import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import FindingLedger from '~/components/FindingLedger.vue'
import OpticalBench from '~/components/OpticalBench.vue'
import SeverityMark from '~/components/SeverityMark.vue'
import type { AttackPathReport, Finding, HostReport, ScanResults } from '~/types/scan'
import { STOP_OPENING, buildBench, describeRay, rayHeights, rayPoints } from '~/utils/bench'
import { pickActions, writeBrief } from '~/utils/brief'
import { byRisk, isOpen, splitHostFindings } from '~/utils/findings'
import { formatDate } from '~/utils/format'

const risk = (score: number, priority: 'now' | 'soon' | 'later' = 'soon') => ({
  score,
  priority,
  impact: 0.8,
  reachability: 'unverified',
  exploitability: 'assumed',
})

const finding = (fields: Partial<Finding>): Finding => ({
  finding_id: String(Math.random()),
  category: 'network',
  severity: 'high',
  title: 'SMB service detected',
  remediation: 'Restrict SMB.',
  ...fields,
})

const paths = (ids: string[], certainty: 'confirmed' | 'potential' = 'potential', entries: string[] = []): AttackPathReport => ({
  paths: ids.map((id) => ({ id, title: id, severity: 'high', certainty, steps: [], entries })),
  best_cut: null,
})

const host = { firewall: { status: 'enabled', source: 'windows' } } as HostReport

const scan = (fields: Partial<ScanResults> = {}): ScanResults => ({
  target: 'pc',
  scan_type: 'network',
  findings: [],
  status: 'complete',
  ...fields,
})

describe('the brief says what a person would say', () => {
  it('admits there is no measure yet', () => {
    expect(writeBrief(null, null, null).headline).toBe('Nothing has been measured yet.')
  })

  it('does not call a silent host safe', () => {
    const brief = writeBrief(scan({ status: 'no_response', target: '192.168.1.50' }), null, null)

    expect(brief.headline).toBe('192.168.1.50 did not answer.')
    expect(brief.lead).toContain('says nothing about its safety')
  })

  it('separates what is proved from what is possible', () => {
    expect(writeBrief(scan(), paths(['a', 'b']), null).headline).toBe('Two ways this machine could fall, none proved.')
    expect(writeBrief(scan(), paths(['a'], 'confirmed'), null).headline).toBe('One confirmed way in.')
  })

  it('does not read the absence of an inside view as safety', () => {
    const answering = scan({ coverage: { ports_open: 6, ports_checked: 36 } })

    const brief = writeBrief(answering, paths([]), null, false)

    expect(brief.headline).toBe('Six services answer, and that is all we know.')
    expect(brief.headline).not.toContain('No way in')
  })

  it('stays careful without a probe', () => {
    const brief = writeBrief(scan(), paths([]), { status: 'unverified', summary: {}, probe: null })

    expect(brief.lead).toContain('Only a probe from another one can prove it')
  })
})

describe('what to do', () => {
  it('puts what is urgent before the most efficient fix', () => {
    const urgent = finding({ title: 'Redis', port: 6379, risk: risk(80, 'now') })
    const cut = finding({ title: 'Admin', category: 'posture', severity: 'low', risk: risk(9, 'later') })
    const report: AttackPathReport = {
      paths: [],
      best_cut: { finding_id: cut.finding_id ?? '', title: 'Admin', remediation: 'x', paths_broken: 2 },
    }

    const actions = pickActions([urgent], [cut], report)

    expect(actions.map((action) => action.reason)).toEqual(['Redis', 'Admin'])
    expect(actions[1]?.breaks).toBe(2)
  })

  it('starts with the most efficient fix when nothing is urgent', () => {
    const plain = finding({ title: 'SMB', port: 445, risk: risk(34) })
    const cut = finding({ title: 'Admin', category: 'posture', risk: risk(9, 'later') })
    const report: AttackPathReport = {
      paths: [],
      best_cut: { finding_id: cut.finding_id ?? '', title: 'Admin', remediation: 'x', paths_broken: 2 },
    }

    expect(pickActions([plain], [cut], report)[0]?.reason).toBe('Admin')
  })

  it('does not repeat a port seen by both views', () => {
    const fromScan = finding({ port: 445, risk: risk(34) })
    const fromAgent = finding({ port: 445, category: 'listener', risk: risk(30) })

    expect(pickActions([fromScan], [fromAgent], null)).toHaveLength(1)
  })

  it('leaves out updates, autostart, and information', () => {
    const noise = [
      finding({ category: 'software' }),
      finding({ category: 'persistence', severity: 'info' }),
      finding({ severity: 'info', port: 22 }),
    ]

    expect(pickActions([], noise, null)).toEqual([])
  })
})

describe('the optical bench', () => {
  it('turns each open service into a ray', () => {
    const bench = buildBench([finding({ port: 445, service: 'SMB' })], [], host, null)

    expect(bench.rays).toHaveLength(1)
    expect(bench.rays[0]?.label).toBe('SMB')
    expect(bench.rays[0]?.state).toBe('unproved')
  })

  it('leaves dismissed findings out', () => {
    expect(buildBench([finding({ port: 445, triage_status: 'accepted' })], [], host, null).rays).toEqual([])
  })

  it('only lets a ray reach the focus along a real path', () => {
    const entry = finding({ port: 445, finding_id: 'entry' })
    const other = finding({ port: 902, finding_id: 'other' })

    const bench = buildBench([entry, other], [], host, paths(['remote-takeover'], 'potential', ['entry']))

    expect(bench.rays.find((ray) => ray.port === 445)?.reaches).toBe(true)
    expect(bench.rays.find((ray) => ray.port === 902)?.reaches).toBe(false)
    expect(bench.focused).toBe(true)
  })

  it('never lets a blocked ray reach the focus', () => {
    const blocked = finding({ port: 445, finding_id: 'x', reachability: 'shielded' })

    const bench = buildBench([blocked], [], host, paths(['remote-takeover'], 'potential', ['x']))

    expect(bench.rays[0]?.reaches).toBe(false)
    expect(bench.focused).toBe(false)
  })

  it('says it knows nothing rather than guess', () => {
    const bench = buildBench([], [], null, null, false)

    expect(bench.admin).toBeNull()
    expect(bench.services).toBeNull()
    expect(bench.firewall).toBe('unknown')
  })

  it('draws a file coming in behind the firewall', () => {
    expect(buildBench([], [], host, paths(['malware-chain'])).side[0]?.label).toBe('A file you open')
  })

  it('makes blocked rays strike the blades and others pass the opening', () => {
    const heights = rayHeights([{ state: 'stopped' }, { state: 'proved' }, { state: 'unproved' }, { state: 'stopped' }])

    expect(Math.abs(heights[0] ?? 0)).toBeGreaterThan(STOP_OPENING)
    expect(Math.abs(heights[3] ?? 0)).toBeGreaterThan(STOP_OPENING)
    expect(Math.abs(heights[1] ?? 1)).toBeLessThan(STOP_OPENING)
    expect(Math.abs(heights[2] ?? 1)).toBeLessThan(STOP_OPENING)
  })

  it('ends each ray where it should', () => {
    expect(rayPoints(0.8, { state: 'stopped', reaches: false }).at(-1)?.[0]).toBeLessThan(0.3)
    expect(rayPoints(0.3, { state: 'proved', reaches: true }).at(-1)).toEqual([0.955, 0])
    expect(rayPoints(0.3, { state: 'proved', reaches: false }).at(-1)?.[0]).toBeLessThan(0.7)
  })

  it('explains a ray in words', () => {
    const ray = { id: 'a', label: 'SMB', port: 445, state: 'unproved' as const, reaches: true, finding: finding({}) }

    expect(describeRay(ray)).toBe('SMB, port 445: not proved reachable from outside, and it leads to full control.')
    expect(describeRay({ ...ray, state: 'stopped' })).toContain('blocked')
  })

  it('renders rays, and hands the finding over when one is selected', async () => {
    const item = finding({ port: 445, service: 'SMB' })
    const wrapper = mount(OpticalBench, { props: { bench: buildBench([item], [], host, null), scanning: false } })

    expect(wrapper.text()).toContain('SMB')
    expect(wrapper.text()).toContain('Full control')
    await wrapper.find('.hit').trigger('click')
    expect((wrapper.emitted('select')?.[0]?.[0] as { finding: Finding }).finding.finding_id).toBe(item.finding_id)
  })

  it('draws what is not proved as a dashed line, which pathLength would turn solid', () => {
    const unproved = finding({ port: 445, service: 'SMB' })
    const proved = finding({ port: 902, reachability: 'exposed' })
    const wrapper = mount(OpticalBench, { props: { bench: buildBench([unproved, proved], [], host, null), scanning: false } })

    expect(wrapper.find('.ray.unproved polyline').attributes('pathLength')).toBeUndefined()
    expect(wrapper.find('.ray.proved polyline').attributes('pathLength')).toBe('1')
  })

  it('reads a ray aloud on hover', async () => {
    const wrapper = mount(OpticalBench, {
      props: { bench: buildBench([finding({ port: 445, service: 'SMB' })], [], host, null), scanning: false },
    })

    await wrapper.find('.hit').trigger('mouseenter')

    expect(wrapper.find('figcaption').text()).toContain('SMB, port 445')
  })
})

describe('severity marks', () => {
  it('uses shape, so that color is never the only signal', () => {
    const critical = mount(SeverityMark, { props: { severity: 'critical' } })
    const high = mount(SeverityMark, { props: { severity: 'high' } })

    expect(critical.html()).not.toBe(high.html())
    expect(critical.find('title').text()).toBe('Critical')
  })
})

describe('finding order', () => {
  it('puts risk before severity', () => {
    const shielded = finding({ severity: 'critical', risk: risk(20) })
    const exposed = finding({ severity: 'high', risk: risk(80, 'now') })

    expect([shielded, exposed].sort(byRisk)[0]).toBe(exposed)
  })

  it('treats a finding without a decision as open', () => {
    expect(isOpen(finding({}))).toBe(true)
    expect(isOpen(finding({ triage_status: 'accepted' }))).toBe(false)
  })

  it('separates updates and autostart entries from the machine findings', () => {
    const groups = splitHostFindings([
      finding({ category: 'software' }),
      finding({ category: 'persistence' }),
      finding({ category: 'listener' }),
      finding({ category: 'posture' }),
    ])

    expect(groups.software).toHaveLength(1)
    expect(groups.autostart).toHaveLength(1)
    expect(groups.machine).toHaveLength(2)
  })
})

describe('FindingLedger', () => {
  const ledger = (network: Finding[] = [], hostFindings: Finding[] = []) => mount(FindingLedger, {
    props: { network, host: hostFindings, emptyTitle: 'Nothing answered.', emptyText: 'No port answered.' },
  })

  it('never shows the empty state next to findings', () => {
    const wrapper = ledger([finding({}), finding({ title: 'Other' })])

    expect(wrapper.findAll('.row')).toHaveLength(2)
    expect(wrapper.text()).not.toContain('Nothing answered.')
  })

  it('shows the empty state of a scan without findings', () => {
    expect(ledger().text()).toContain('Nothing answered.')
  })

  it('moves dismissed findings to their own tab', async () => {
    const wrapper = ledger([finding({ triage_status: 'accepted' })])

    expect(wrapper.findAll('.row')).toHaveLength(0)
    await wrapper.findAll('.tab')[4]!.trigger('click')
    expect(wrapper.findAll('.row')).toHaveLength(1)
    expect(wrapper.text()).toContain('Accepted')
  })

  it('hides informational machine findings behind a button', async () => {
    const wrapper = ledger([], [finding({ category: 'posture', severity: 'info' }), finding({ category: 'posture' })])

    await wrapper.findAll('.tab')[1]!.trigger('click')
    expect(wrapper.findAll('.row')).toHaveLength(1)
    await wrapper.find('.more').trigger('click')
    expect(wrapper.findAll('.row')).toHaveLength(2)
  })

  it('states what is known about a finding, in plain words', () => {
    expect(ledger([finding({ verification: 'confirmed' })]).text()).toContain('Confirmed')
    expect(ledger([finding({ reachability: 'shielded' })]).text()).toContain('Blocked')
    expect(ledger([finding({ triage_lapsed: 'changed' })]).text()).toContain('Reopened')
  })

  it('emits the finding to open', async () => {
    const item = finding({})
    const wrapper = ledger([item])

    await wrapper.find('.row').trigger('click')

    expect(wrapper.emitted('view')?.[0]).toEqual([item])
  })
})

describe('formatDate', () => {
  it('never crashes on missing or invalid dates', () => {
    expect(formatDate(undefined)).toBe('—')
    expect(formatDate('not a date')).toBe('not a date')
  })
})
