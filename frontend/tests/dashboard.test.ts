import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, nextTick, ref } from 'vue'

import ApertureDial from '~/components/ApertureDial.vue'
import AttackPaths from '~/components/AttackPaths.vue'
import ExposurePanel from '~/components/ExposurePanel.vue'
import FindingLedger from '~/components/FindingLedger.vue'
import PortStrip from '~/components/PortStrip.vue'
import { useAnimatedNumber } from '~/composables/useAnimatedNumber'
import type { Finding } from '~/types/scan'
import { byRisk, isOpen, splitHostFindings } from '~/utils/findings'
import { formatDate } from '~/utils/format'

const ledger = (network: Finding[] = [], host: Finding[] = []) => mount(FindingLedger, {
  props: { network, host, emptyTitle: 'Nothing exposed', emptyText: 'No port answered.' },
})

const finding = (fields: Partial<Finding>): Finding => ({
  finding_id: String(Math.random()),
  category: 'network',
  severity: 'high',
  title: 'SMB service detected',
  ...fields,
})

describe('finding order', () => {
  it('puts risk before severity', () => {
    const shielded = finding({ severity: 'critical', risk: { score: 20, priority: 'soon', impact: 1, reachability: 'shielded', exploitability: 'assumed' } })
    const exposed = finding({ severity: 'high', risk: { score: 80, priority: 'now', impact: 0.8, reachability: 'exposed', exploitability: 'proved' } })

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
  it('never shows the empty state next to findings', () => {
    const wrapper = ledger([finding({}), finding({ title: 'Other' })])

    expect(wrapper.findAll('.ledger-row')).toHaveLength(2)
    expect(wrapper.text()).not.toContain('Nothing exposed')
  })

  it('shows the empty state of a scan without findings', () => {
    expect(ledger().text()).toContain('Nothing exposed')
  })

  it('moves dismissed findings to their own tab', async () => {
    const wrapper = ledger([finding({ triage_status: 'accepted' })])

    expect(wrapper.findAll('.ledger-row')).toHaveLength(0)
    await wrapper.findAll('.tab')[4]!.trigger('click')
    expect(wrapper.findAll('.ledger-row')).toHaveLength(1)
    expect(wrapper.text()).toContain('accepted')
  })

  it('hides informational machine findings behind a button', async () => {
    const wrapper = ledger([], [finding({ category: 'posture', severity: 'info' }), finding({ category: 'posture' })])

    await wrapper.findAll('.tab')[1]!.trigger('click')
    expect(wrapper.findAll('.ledger-row')).toHaveLength(1)
    await wrapper.find('.text-button').trigger('click')
    expect(wrapper.findAll('.ledger-row')).toHaveLength(2)
  })

  it('says when a finding is reachable, proved, or reopened', () => {
    const wrapper = ledger([finding({ reachability: 'exposed', verification: 'confirmed', triage_lapsed: 'changed' })])

    expect(wrapper.text()).toContain('reachable')
    expect(wrapper.text()).toContain('proved')
    expect(wrapper.text()).toContain('reopened')
  })

  it('emits the finding to open', async () => {
    const item = finding({})
    const wrapper = ledger([item])

    await wrapper.find('.ledger-row').trigger('click')

    expect(wrapper.emitted('view')?.[0]).toEqual([item])
  })
})

describe('PortStrip', () => {
  it('draws one cell per port, in order, with the right state', () => {
    const wrapper = mount(PortStrip, {
      props: { states: { 445: 'open', 22: 'closed', 80: 'filtered' }, services: [{ name: 'SMB', port: 445 }] },
    })

    const cells = wrapper.findAll('.port-cell')
    expect(cells.map((cell) => cell.attributes('aria-label'))).toEqual([
      '22/tcp closed',
      '80/tcp filtered',
      '445/tcp open · SMB',
    ])
    expect(wrapper.text()).toContain('1 open')
  })
})

describe('ApertureDial', () => {
  it('states the score to assistive technology', () => {
    const wrapper = mount(ApertureDial, { props: { score: 20, scanning: false } })

    expect(wrapper.attributes('aria-label')).toContain('20 out of 100')
  })

  it('stays closed and says so without a reading', () => {
    const wrapper = mount(ApertureDial, { props: { score: null, scanning: false } })

    expect(wrapper.attributes('aria-label')).toContain('no exposure reading')
  })
})

describe('AttackPaths', () => {
  it('names the fix that breaks the most paths', () => {
    const wrapper = mount(AttackPaths, {
      props: {
        report: {
          paths: [{
            id: 'x',
            title: 'Remote takeover',
            severity: 'high',
            certainty: 'potential',
            steps: [{ stage: 'Entry', label: 'Reach SMB', finding_id: 'a' }, { stage: 'Impact', label: 'Control', finding_id: null }],
          }],
          best_cut: { finding_id: 'a', title: 'Stop SMB', remediation: 'Disable it', paths_broken: 2 },
        },
      },
    })

    expect(wrapper.text()).toContain('Stop SMB')
    expect(wrapper.text()).toContain('Breaks 2 paths')
    expect(wrapper.findAll('.chain li')).toHaveLength(2)
  })

  it('does not invent a story without evidence', () => {
    const wrapper = mount(AttackPaths, { props: { report: { paths: [], best_cut: null } } })

    expect(wrapper.text()).toContain('No complete attack path')
  })
})

describe('ExposurePanel', () => {
  it('explains why the local scan proves nothing and gives the command', () => {
    const wrapper = mount(ExposurePanel, {
      props: { report: { status: 'unverified', summary: {}, probe: null, probe_command: 'attacklens probe 10.0.0.5' } },
    })

    expect(wrapper.text()).toContain('skips your firewall')
    expect(wrapper.text()).toContain('attacklens probe 10.0.0.5')
  })

  it('shows the verdict once a probe exists', () => {
    const wrapper = mount(ExposurePanel, {
      props: { report: { status: 'verified', summary: { exposed: 1, shielded: 4, unverified: 2 }, probe: { target: '10.0.0.5' } } },
    })

    expect(wrapper.text()).toContain('shielded')
    expect(wrapper.text()).not.toContain('attacklens probe')
  })
})

describe('useAnimatedNumber', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  const harness = (value: number | null) => {
    const source = ref(value)
    let shown = ref(0)
    const wrapper = mount(defineComponent({
      setup() {
        shown = useAnimatedNumber(source)
        return () => h('span', shown.value)
      },
    }))
    return { source, wrapper }
  }

  it('lands on the real value even when no animation frame ever fires', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('requestAnimationFrame', () => 1)
    vi.stubGlobal('cancelAnimationFrame', () => undefined)

    const { wrapper } = harness(20)
    vi.advanceTimersByTime(2000)
    await nextTick()

    expect(wrapper.text()).toBe('20')
  })

  it('shows the value at once on a hidden page', async () => {
    vi.spyOn(document, 'hidden', 'get').mockReturnValue(true)

    const { wrapper } = harness(42)
    await nextTick()

    expect(wrapper.text()).toBe('42')
    vi.restoreAllMocks()
  })
})

describe('formatDate', () => {
  it('never crashes on missing or invalid dates', () => {
    expect(formatDate(undefined)).toBe('—')
    expect(formatDate('not a date')).toBe('not a date')
  })
})
