import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import BriefView from '~/components/BriefView.vue'
import CopyButton from '~/components/CopyButton.vue'
import FindingLedger from '~/components/FindingLedger.vue'
import GlyphBench from '~/components/GlyphBench.vue'
import ScoreColumns from '~/components/ScoreColumns.vue'
import SeverityMark from '~/components/SeverityMark.vue'
import ReadingLine from '~/components/ReadingLine.vue'
import type { Agent, Alert, AttackPathReport, Finding, HostReport, ScanResults } from '~/types/scan'
import { glyph, tint } from '~/utils/ascii'
import { benchStations, buildBench, describeRay, isProvedWay, rayStateText, rayTrace, waysNotDrawn } from '~/utils/bench'
import { countWaysIn, pickActions, scoreTrend, writeBrief } from '~/utils/brief'
import { byRisk, firstSeen, isOpen, proofLabel, splitHostFindings, uniqueByPort } from '~/utils/findings'
import { ago, formatDate } from '~/utils/format'
import { buildGlyphField, renderGlyphLines } from '~/utils/glyphField'
import { buildReading, isStale } from '~/utils/reading'

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
    // The sentence counts what the figure counts: every way in, then how many are confirmed.
    const mixed = { paths: [...paths(['a', 'b'], 'confirmed').paths, ...paths(['c', 'd', 'e']).paths], best_cut: null }
    expect(writeBrief(scan(), mixed, null).headline).toBe('Five ways in, two confirmed.')
    expect(countWaysIn(scan(), mixed, null, true)).toMatchObject({ value: 5, note: '2 confirmed' })
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

  it('explains a ray in words', () => {
    const ray = { id: 'a', label: 'SMB', port: 445, state: 'unproved' as const, reaches: true, finding: finding({}) }

    expect(describeRay(ray)).toBe('SMB, port 445: not proved reachable from outside, and it leads to full control.')
    expect(describeRay({ ...ray, state: 'stopped' })).toContain('blocked')
  })

  it('names the ways in that are not rays, rather than leave a gap', () => {
    const report = paths(['device-theft', 'malware-chain'])
    report.paths.push({ id: 'remote-takeover', title: 'remote', severity: 'high', certainty: 'confirmed', steps: [], entries: ['x'] })

    expect(waysNotDrawn(report)).toEqual(['device-theft'])
  })

  it('renders each ray as a button, and hands the finding over when one is selected', async () => {
    const item = finding({ port: 445, service: 'SMB' })
    const wrapper = mount(GlyphBench, { props: { bench: buildBench([item], [], host, null) } })

    expect(wrapper.text()).toContain('SMB')
    expect(wrapper.text()).toContain('Full control')
    await wrapper.find('.glyph-ray').trigger('click')
    expect((wrapper.emitted('select')?.[0]?.[0] as { finding: Finding }).finding.finding_id).toBe(item.finding_id)
  })

  it('lists the same rays for a phone, each with its stroke and its state in words', async () => {
    const redis = finding({ finding_id: 'redis', port: 6379, service: 'Redis', reachability: 'exposed', risk: risk(60, 'now') })
    const smb = finding({ finding_id: 'smb', port: 445, service: 'SMB', reachability: 'shielded', risk: risk(40) })
    const bench = buildBench([redis, smb], [], host, paths(['p'], 'confirmed', ['redis']))
    const wrapper = mount(GlyphBench, { props: { bench, highlight: 'smb' } })
    const rows = wrapper.findAll('.ray-list button.ray')

    expect(rows).toHaveLength(2)
    expect(rows[0]?.text()).toContain('Redis')
    expect(rows[0]?.find('.ray-state').text()).toBe('Proved way to full control')
    expect(rows[0]?.find('.ray-state').classes()).toContain('text-alert')
    expect(rows[0]?.find('.ray-trace').classes()).toContain('field-hot-3')
    expect(rows[1]?.find('.ray-state').text()).toBe('Blocked before this machine')
    expect(rows[1]?.classes()).toContain('linked')
    expect(wrapper.find('.stations').text()).toContain('2 listed')
    await rows[1]?.trigger('click')
    expect((wrapper.emitted('select')?.[0]?.[0] as { finding: Finding }).finding.finding_id).toBe('smb')
  })

  it('says the state of a ray in words, and never calls an unproved one proved', () => {
    expect(rayStateText({ state: 'proved', reaches: true })).toBe('Proved way to full control')
    expect(rayStateText({ state: 'proved', reaches: false })).toBe('Reachable, no known path beyond')
    expect(rayStateText({ state: 'unproved', reaches: true })).toBe('Not proved yet, would lead to full control')
    expect(rayStateText({ state: 'unproved', reaches: false })).toBe('Not proved yet')
    expect(rayStateText({ state: 'stopped', reaches: false })).toBe('Blocked before this machine')
    expect(rayTrace({ state: 'unproved', reaches: true }).tone).not.toMatch(/hot/)
  })

  it('says not measured for a station that was not, and flags a firewall that is off', () => {
    const unknown = benchStations(buildBench([], [], null, null, false))
    const off = benchStations(buildBench([], [], { firewall: { status: 'disabled', source: 'windows' } } as HostReport, null))

    expect(unknown.map((station) => station.value)).toEqual(['Not measured', 'Not read yet', 'Not measured'])
    expect(off[0]).toMatchObject({ value: 'Off', alert: true })
  })

  it('reads a ray aloud on hover', async () => {
    const wrapper = mount(GlyphBench, { props: { bench: buildBench([finding({ port: 445, service: 'SMB' })], [], host, null) } })

    await wrapper.find('.glyph-ray').trigger('mouseenter')

    expect(wrapper.find('figcaption').text()).toContain('SMB, port 445')
  })

  it('hides the picture from assistive technology and says what it shows', () => {
    const wrapper = mount(GlyphBench, { props: { bench: buildBench([finding({ port: 445, service: 'SMB' })], [], host, null) } })

    expect(wrapper.find('pre').attributes('aria-hidden')).toBe('true')
    expect(wrapper.find('.glyph-field').attributes('aria-label')).toContain('1 services drawn')
  })
})

describe('severity marks', () => {
  it('always pairs the intensity of the red with its word', () => {
    const critical = mount(SeverityMark, { props: { severity: 'critical' } })
    const high = mount(SeverityMark, { props: { severity: 'high' } })

    expect(critical.html()).not.toBe(high.html())
    expect(critical.find('title').text()).toBe('Critical')
    expect(critical.find('.severity-word').text()).toBe('Critical')
    expect(high.find('.severity-word').text()).toBe('High')
  })
})

describe('the main figure', () => {
  it('stays empty rather than zero when nothing was seen from inside', () => {
    expect(countWaysIn(null, null, null, true).value).toBeNull()
    expect(countWaysIn(scan({ status: 'no_response' }), null, null, true).value).toBeNull()
    expect(countWaysIn(scan(), paths([]), null, false).value).toBeNull()
  })

  it('only turns red for a confirmed way in', () => {
    expect(countWaysIn(scan(), paths(['a', 'b']), null, true)).toEqual({ value: 2, note: 'None proved', alert: false })
    expect(countWaysIn(scan(), paths(['a'], 'confirmed'), null, true)).toEqual({ value: 1, note: '1 confirmed', alert: true })
  })

  it('says a zero is not proved without a probe', () => {
    expect(countWaysIn(scan(), paths([]), null, true).note).toBe('Not proved by a probe')
  })
})

describe('the brief on screen', () => {
  const brief = (props: Record<string, unknown> = {}) => mount(BriefView, {
    props: { scan: scan({ coverage: { ports_open: 4, ports_checked: 36 } }), host: null, paths: null, exposure: null, scanning: false, alerts: [], ...props },
    global: { components: { CopyButton, GlyphBench, ScoreColumns } },
  })

  it('says not measured in words without the agent, never with a zero or a dash', () => {
    const wrapper = brief()

    expect(wrapper.find('.unmeasured-state').text()).toBe('Not measured')
    expect(wrapper.find('.verdict .t-display').exists()).toBe(false)
    expect(wrapper.find('.verdict').text()).not.toMatch(/[—–]/)
    expect(wrapper.find('.verdict').text()).toContain('4 services answer')
  })

  it('does not let the missing agent mute an urgent finding', () => {
    const urgent = finding({ port: 6379, service: 'Redis', severity: 'critical', risk: risk(60, 'now') })
    const wrapper = brief({ scan: scan({ findings: [urgent], coverage: { ports_open: 1, ports_checked: 36 } }) })

    expect(wrapper.find('.verdict').text()).toContain('1 critical')
    expect(wrapper.find('.first-action').classes()).toContain('critical')
  })

  it('shows a zero only once the machine was seen from the inside', () => {
    const wrapper = brief({ host, paths: paths([]) })

    expect(wrapper.find('.verdict .t-display').text()).toBe('0')
    expect(wrapper.find('.verdict').text()).toContain('Not proved by a probe')
  })

  it('keeps the last verdict in place while a scan runs, and says a reading is being taken', async () => {
    const wrapper = brief({ host, paths: paths([]) })

    expect(wrapper.find('.verdict-status').exists()).toBe(false)
    await wrapper.setProps({ scanning: true })
    expect(wrapper.find('.verdict-status').text()).toBe('Taking a reading')
    expect(wrapper.find('.verdict .t-display').text()).toBe('0')
    expect(wrapper.findComponent(GlyphBench).props('scanning')).toBe(true)
  })

  it('shows the legend of the rays only when a ray is drawn', () => {
    const smb = finding({ port: 445, service: 'SMB', risk: risk(40) })

    expect(brief({ scan: null }).find('.legend').exists()).toBe(false)
    expect(brief({ scan: scan({ findings: [smb], coverage: { ports_open: 1, ports_checked: 36 } }) }).find('.legend').exists()).toBe(true)
  })

  it('gives way to one line when nothing was read, and draws no empty bench', () => {
    const wrapper = brief({ scan: null })

    expect(wrapper.findComponent(GlyphBench).exists()).toBe(false)
    expect(wrapper.find('.hero-bench').text()).toContain('No service has been read yet')
  })

  it('lets an old verdict step back and carry its age', () => {
    const old = scan({ completed_at: '2026-10-20T10:00:00Z' })
    const wrapper = brief({ scan: old, host, paths: paths([]), now: Date.parse('2026-11-12T10:00:00Z') })

    expect(wrapper.find('.verdict').classes()).toContain('old')
    expect(wrapper.find('.verdict-age').text()).toBe('Read 23 d ago')
    expect(brief({ scan: old, host, paths: paths([]), now: Date.parse('2026-10-21T10:00:00Z') }).find('.verdict').classes()).not.toContain('old')
  })

  it('says when a reading is too old to act on', () => {
    const old = scan({ completed_at: '2026-10-20T10:00:00Z' })

    expect(brief({ scan: old, now: Date.parse('2026-11-12T10:00:00Z') }).find('.stale').text()).toContain('23 d old')
    expect(brief({ scan: old, now: Date.parse('2026-10-21T10:00:00Z') }).find('.stale').exists()).toBe(false)
  })
})

describe('the actions and the bench point at each other', () => {
  const redis = finding({ finding_id: 'redis', port: 6379, service: 'Redis', severity: 'critical', risk: risk(60, 'now') })
  const smb = finding({ finding_id: 'smb', port: 445, service: 'SMB', risk: risk(40) })
  const brief = () => mount(BriefView, {
    props: { scan: scan({ findings: [redis, smb], coverage: { ports_open: 2, ports_checked: 36 } }), host, paths: paths([]), exposure: null, scanning: false, alerts: [] },
    global: { components: { CopyButton, GlyphBench, ScoreColumns } },
  })

  it('lights the ray of the action under the pointer, and lets go when it leaves', async () => {
    const wrapper = brief()
    const bench = wrapper.findComponent(GlyphBench)
    const ray = bench.props('bench').rays.find((entry: { port: number | null }) => entry.port === 6379)

    expect(bench.props('highlight')).toBeNull()
    await wrapper.find('.first-action').trigger('mouseenter')
    expect(bench.props('highlight')).toBe(ray.id)
    expect(wrapper.find('.glyph-ray.linked').exists()).toBe(true)
    await wrapper.find('.first-action').trigger('mouseleave')
    expect(bench.props('highlight')).toBeNull()
  })

  it('marks the action of the ray under the pointer', async () => {
    const wrapper = brief()
    const bench = wrapper.findComponent(GlyphBench)
    const ray = bench.props('bench').rays.find((entry: { port: number | null }) => entry.port === 6379)

    expect(wrapper.find('.first-action').classes()).not.toContain('linked')
    bench.vm.$emit('point', ray)
    await wrapper.vm.$nextTick()
    expect(wrapper.find('.first-action').classes()).toContain('linked')
    expect(wrapper.findAll('.action.linked')).toHaveLength(0)
  })
})

describe('the score trend', () => {
  const reading = (score: number | null, day: number) => scan({ score, completed_at: `2026-11-${String(day).padStart(2, '0')}T10:00:00Z` })

  it('orders readings in time and compares the last two', () => {
    const trend = scoreTrend([reading(70, 3), reading(80, 1), reading(75, 2)])

    expect(trend.values).toEqual([80, 75, 70])
    expect(trend.delta).toBe(-5)
    expect(trend.alert).toBe(false)
  })

  it('only flags a significant drop', () => {
    expect(scoreTrend([reading(80, 1), reading(68, 2)]).alert).toBe(true)
    expect(scoreTrend([reading(60, 1), reading(90, 2)]).alert).toBe(false)
  })

  it('has no delta without two scored readings', () => {
    expect(scoreTrend([reading(80, 1), reading(null, 2)]).delta).toBeNull()
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
    await wrapper.findAll('.tab')[3]!.trigger('click')
    expect(wrapper.findAll('.row')).toHaveLength(1)
    expect(wrapper.text()).toContain('Accepted')
  })

  it('hides informational machine findings behind a button', async () => {
    const wrapper = ledger([], [finding({ category: 'posture', severity: 'info' }), finding({ category: 'posture' })])

    expect(wrapper.findAll('.row')).toHaveLength(1)
    await wrapper.find('.more').trigger('click')
    expect(wrapper.findAll('.row')).toHaveLength(2)
  })

  it('states what is known about a finding, in plain words', () => {
    expect(ledger([finding({ verification: 'confirmed' })]).text()).toContain('Confirmed')
    expect(ledger([finding({ reachability: 'shielded' })]).text()).toContain('Blocked')
    expect(ledger([finding({ triage_lapsed: 'changed' })]).text()).toContain('Reopened')
  })

  it('shows a port once when the scan and the agent both report it', () => {
    const wrapper = ledger([finding({ port: 445, risk: risk(34) })], [finding({ port: 445, category: 'listener', risk: risk(30) })])

    expect(wrapper.findAll('.row')).toHaveLength(1)
  })

  it('says since when a finding is known, from the alert that first carried it', () => {
    const item = finding({ finding_id: 'known' })
    const alert = { alert_id: 1, scan_id: 's', target: 'pc', created_at: '2026-11-01T10:00:00Z', message: '', delivered: true, findings: [item] } as Alert
    const wrapper = mount(FindingLedger, {
      props: { network: [item, finding({ title: 'Other' })], host: [], alerts: [alert], emptyTitle: '', emptyText: '', now: Date.parse('2026-11-03T10:00:00Z') },
    })

    expect(wrapper.findAll('.row-since')[0]?.text()).toBe('2 d ago')
    expect(wrapper.findAll('.row-since')[1]?.text()).toBe('Not known')
  })

  it('names a proved way in as the bench does', () => {
    const rdp = finding({ finding_id: 'rdp', port: 3389, reachability: 'exposed', risk: risk(48) })
    const ssh = finding({ finding_id: 'ssh', port: 22, reachability: 'exposed', risk: risk(30) })
    const wrapper = mount(FindingLedger, {
      props: { network: [rdp, ssh], host: [], paths: paths(['p'], 'confirmed', ['rdp']), emptyTitle: '', emptyText: '' },
    })
    const proofs = wrapper.findAll('.row-proof')

    expect(proofs[0]?.text()).toBe('Proved way in')
    expect(proofs[0]?.classes()).toContain('text-alert')
    expect(proofs[1]?.text()).toBe('Reachable')
    expect(proofs[1]?.classes()).not.toContain('text-alert')
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
    expect(formatDate(undefined)).toBe('Not known')
    expect(formatDate('not a date')).toBe('not a date')
  })
})

describe('the glyph field', () => {
  const field = (network: Finding[], report: AttackPathReport | null = null) => buildGlyphField(buildBench(network, [], host, report), 138)
  const entry = (fields: Partial<Finding> = {}) => finding({ port: 445, service: 'SMB', finding_id: 'entry', ...fields })

  it('turns nothing red when nothing is a proved way in', () => {
    expect(field([entry(), finding({ port: 135, reachability: 'shielded' })]).hotCells).toBe(0)
    // Reaching full control is not enough: it must also be proved from outside.
    expect(field([entry()], paths(['remote-takeover'], 'potential', ['entry'])).hotCells).toBe(0)
  })

  it('turns red the ray that is proved from outside and reaches full control', () => {
    const proved = field([entry({ reachability: 'exposed' })], paths(['remote-takeover'], 'confirmed', ['entry']))

    expect(proved.hotCells).toBeGreaterThan(0)
    expect(isProvedWay({ state: 'proved', reaches: true })).toBe(true)
    expect(isProvedWay({ state: 'unproved', reaches: true })).toBe(false)
    expect(isProvedWay({ state: 'stopped', reaches: false })).toBe(false)
  })

  it('never puts a glyph under a label', () => {
    const drawn = field([entry({ reachability: 'exposed' }), finding({ port: 135, service: 'MS-RPC', reachability: 'shielded' })], paths(['remote-takeover'], 'confirmed', ['entry']))
    const text = (row: number) => drawn.lines[row]!.map((run) => run.text).join('')

    for (const label of drawn.labels.filter((item) => item.kind === 'ray')) {
      expect(text(label.row).slice(0, label.text.length + 2).trim()).toBe('')
    }
    // A caption may sit between two rows of the field: both are left blank.
    for (const label of drawn.labels.filter((item) => item.kind === 'caption' || item.kind === 'state')) {
      for (const row of [Math.floor(label.row), Math.ceil(label.row)]) expect(text(row).trim()).toBe('')
    }
  })

  it('follows the bench: one label per ray, and its height grows with them', () => {
    const one = field([entry()])
    const three = field([entry(), finding({ port: 22, service: 'SSH' }), finding({ port: 3389, service: 'RDP' })])

    expect(one.labels.filter((label) => label.kind === 'ray')).toHaveLength(1)
    expect(three.labels.filter((label) => label.kind === 'ray')).toHaveLength(3)
    expect(three.rows).toBeGreaterThan(one.rows)
  })

  it('says in words what it shows, and never calls an unmeasured firewall on or off', () => {
    const blind = buildGlyphField(buildBench([entry()], [], null, null), 138)

    expect(blind.summary).toContain('None reaches full control')
    expect(blind.labels.filter((label) => label.kind === 'state').map((label) => label.text)).toContain('Not measured')
  })

  describe('in motion', () => {
    const text = (lines: ReturnType<typeof renderGlyphLines>) => lines.map((line) => line.map((run) => run.text).join('')).join('\n')
    const hot = (lines: ReturnType<typeof renderGlyphLines>) => lines.flat().filter((run) => run.tone.startsWith('field-hot')).reduce((sum, run) => sum + run.text.length, 0)
    const moments = [0, 0.4, 1.1, 2.3, 3.7, 5.2].map((time) => ({ time, speed: 250 }))

    it('is the still picture when no moment is given', () => {
      const drawn = field([entry()])

      expect(text(renderGlyphLines(drawn))).toBe(text(drawn.lines))
    })

    it('makes light travel along a ray: the picture changes from one moment to the next', () => {
      const drawn = field([entry()])

      expect(text(renderGlyphLines(drawn, moments[1]))).not.toBe(text(renderGlyphLines(drawn, moments[3])))
    })

    it('never turns anything red by moving', () => {
      const unproved = field([entry()], paths(['remote-takeover'], 'potential', ['entry']))

      for (const moment of moments) expect(hot(renderGlyphLines(unproved, moment))).toBe(0)
    })

    it('never puts a moving glyph under a label', () => {
      const drawn = field([entry({ reachability: 'exposed' })], paths(['remote-takeover'], 'confirmed', ['entry']))
      const label = drawn.labels.find((item) => item.kind === 'ray')!

      for (const moment of moments) {
        const row = renderGlyphLines(drawn, moment)[label.row]!.map((run) => run.text).join('')
        expect(row.slice(0, label.text.length + 2).trim()).toBe('')
      }
    })

    it('develops from the left: nothing is drawn beyond the edge', () => {
      const drawn = field([entry({ reachability: 'exposed' })], paths(['remote-takeover'], 'confirmed', ['entry']))
      const half = renderGlyphLines(drawn, { time: 0, speed: 250, reveal: 0.5 })

      for (const line of half) expect(line.map((run) => run.text).join('').slice(Math.ceil(drawn.cols * 0.5) + 1).trim()).toBe('')
      expect(text(half).trim()).not.toBe('')
    })

    it('lets the ray under the pointer stand out by dimming the others', () => {
      const drawn = field([entry(), finding({ port: 22, service: 'SSH', finding_id: 'other' })])
      const bright = (lines: ReturnType<typeof renderGlyphLines>) => lines.flat().filter((run) => run.tone === 'field-3' || run.tone === 'field-4').reduce((sum, run) => sum + run.text.length, 0)

      expect(bright(renderGlyphLines(drawn, { highlight: 'entry' }))).toBeLessThan(bright(renderGlyphLines(drawn)))
    })
  })

  it('maps values to denser glyphs, and blanks the empty ones', () => {
    expect(glyph(0)).toBe(' ')
    expect(glyph(1)).toBe('@')
    expect(glyph(0.5)).not.toBe(glyph(0.9))
  })

  it('names tones rather than colours, and keeps the hot ones apart', () => {
    expect(tint(1, false)).not.toMatch(/hot/)
    expect(tint(1, true)).toMatch(/hot/)
  })
})

describe('the reading line', () => {
  const NOW = Date.parse('2026-11-12T12:00:00Z')
  const base = { scan: null, exposure: null, agent: null, silentAgent: null, unreachable: false, syncedAt: null, now: NOW }
  const agent = (fields: Partial<Agent> = {}): Agent => ({ hostname: 'desk-07', platform: '', version: '', address: '', last_seen: '', online: true, ...fields })
  const item = (source: Partial<typeof base> & Record<string, unknown>, id: string) => buildReading({ ...base, ...source } as Parameters<typeof buildReading>[0]).find((entry) => entry.id === id)

  it('says who is measuring, and flags a feed that stopped', () => {
    expect(item({ agent: agent() }, 'agent')).toMatchObject({ value: 'desk-07 online', lamp: 'on' })
    expect(item({}, 'agent')).toMatchObject({ value: 'None connected', lamp: 'none' })
    expect(item({ silentAgent: agent({ online: false, silent_since: '2026-11-10T12:00:00Z' }) }, 'agent')).toMatchObject({ lamp: 'off', alert: true })
    expect(item({ unreachable: true }, 'agent')).toMatchObject({ label: 'API', alert: true })
  })

  it('calls a reading stale after a week, and never before', () => {
    const fresh = scan({ completed_at: '2026-11-12T10:00:00Z' })
    const old = scan({ completed_at: '2026-10-20T10:00:00Z' })

    expect(isStale(fresh, NOW)).toBe(false)
    expect(isStale(old, NOW)).toBe(true)
    expect(isStale(null, NOW)).toBe(false)
    expect(item({ scan: old }, 'read')).toMatchObject({ value: '23 d ago, stale', alert: true })
    expect(item({ scan: fresh }, 'read')?.alert).toBe(false)
  })

  it('marks a fact that was replaced, and not a clock that ticks', async () => {
    const reading = (source: Record<string, unknown>) => buildReading({ ...base, ...source } as Parameters<typeof buildReading>[0])
    const first = scan({ completed_at: '2026-11-12T10:00:00Z' })
    const wrapper = mount(ReadingLine, { props: { items: reading({ scan: first }), loading: false } })

    expect(wrapper.findAll('.changed')).toHaveLength(0)
    await wrapper.setProps({ items: reading({ scan: first, now: NOW + 60 * 60 * 1000 }) })
    expect(wrapper.find('.reading-read dd').text()).toBe('3 h ago')
    expect(wrapper.findAll('.changed')).toHaveLength(0)
    await wrapper.setProps({ items: reading({ scan: scan({ completed_at: '2026-11-12T12:30:00Z' }), now: NOW + 60 * 60 * 1000 }) })
    expect(wrapper.findAll('.changed').map((node) => node.classes().find((name) => name.startsWith('reading-') && name !== 'reading-item'))).toEqual(['reading-read'])
  })

  it('says in words what was not measured, never a zero and never an abbreviation', () => {
    expect(item({}, 'coverage')?.value).toBe('Not read')
    expect(item({}, 'from')?.value).toBe('Not read')
    expect(item({}, 'target')?.value).toBe('None yet')
    expect(buildReading({ ...base, unreachable: true }).map((entry) => entry.value).join(' ')).not.toMatch(/n\/a|\b0\b/)
    expect(item({}, 'read')?.value).toBe('Never')
    expect(item({}, 'probe')?.value).toBe('None yet')
  })

  it('does not claim "never" when the API is down and nothing was loaded', () => {
    expect(item({ unreachable: true }, 'read')?.value).toBe('Not known')
    expect(item({ unreachable: true }, 'probe')?.value).toBe('Not known')
    expect(item({ unreachable: true, scan: scan({ completed_at: '2026-11-12T10:00:00Z' }) }, 'read')?.value).toBe('2 h ago')
  })
})

describe('display helpers', () => {
  it('tells how long ago in the largest unit that fits', () => {
    const now = Date.parse('2026-11-12T12:00:00Z')

    expect(ago('2026-11-12T11:59:30Z', now)).toBe('just now')
    expect(ago('2026-11-12T11:25:00Z', now)).toBe('35 min ago')
    expect(ago('2026-11-12T10:00:00Z', now)).toBe('2 h ago')
    expect(ago('2026-10-20T12:00:00Z', now)).toBe('23 d ago')
    expect(ago(undefined, now)).toBe('Not known')
  })

  it('keeps the earliest alert as the first time a finding was seen', () => {
    const alert = (id: number, at: string, ids: string[]) => ({ alert_id: id, scan_id: '', target: '', created_at: at, message: '', delivered: true, findings: ids.map((finding_id) => ({ finding_id })) }) as Alert
    const seen = firstSeen([alert(2, '2026-11-10T00:00:00Z', ['a', 'b']), alert(1, '2026-11-01T00:00:00Z', ['a'])])

    expect(seen.get('a')).toBe('2026-11-01T00:00:00Z')
    expect(seen.get('b')).toBe('2026-11-10T00:00:00Z')
  })

  it('keeps the riskier of two findings on the same port', () => {
    const kept = uniqueByPort([finding({ port: 445, title: 'low', risk: risk(10) }), finding({ port: 445, title: 'high', risk: risk(60) }), finding({ title: 'no port' })])

    expect(kept.map((item) => item.title)).toEqual(['high', 'no port'])
  })

  it('says what is known about a finding without a network path', () => {
    expect(proofLabel(finding({ category: 'posture' }))).toBe('No network path')
    expect(proofLabel(finding({ port: 445 }))).toBe('Not measured')
    expect(proofLabel(finding({ known_exploited: true }))).toBe('Exploited in the wild')
  })
})
