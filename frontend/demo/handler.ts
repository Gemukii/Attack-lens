// Demo mode: answers every /api call from fixtures/demo-*.json instead of the real API.
//
// This file is only registered by nuxt.config.ts in development, and only when
// ATTACKLENS_DEMO=1. It is never part of a production build.
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

import { defineEventHandler, getCookie, getMethod, getRouterParam, readBody, setResponseHeader, setResponseStatus } from 'h3'

export const DEMO_COOKIE = 'attacklens_demo'
const DEFAULT_SCENARIO = 'exposed'
const FIXTURES = join(process.cwd(), 'fixtures')

type Json = null | boolean | number | string | Json[] | { [key: string]: Json }
type Responses = Record<string, Json>

interface Fixture {
  id: string
  label: string
  description: string
  extends?: string
  shift?: string
  fail?: number
  responses: Responses
  afterScan?: { alerts?: Json[]; findings?: Json[] }
}

interface Triage {
  status: string
  reason: string | null
  expires: string | null
}

// What the visitor did since the dev server started: decisions, scans, pending jobs.
interface Session {
  triage: Map<string, Triage>
  audit: Json[]
  scannedAt: string | null
  jobs: Map<string, number>
}

const sessions = new Map<string, Session>()

const session = (id: string): Session => {
  let current = sessions.get(id)
  if (!current) {
    current = { triage: new Map(), audit: [], scannedAt: null, jobs: new Map() }
    sessions.set(id, current)
  }
  return current
}

// Fixtures are read on every call, so editing one shows on the next refresh.
const readFixtures = (): Map<string, Fixture> => {
  const fixtures = new Map<string, Fixture>()
  for (const file of readdirSync(FIXTURES)) {
    if (!/^demo-.+\.json$/.test(file)) continue
    const fixture = JSON.parse(readFileSync(join(FIXTURES, file), 'utf8')) as Fixture
    fixtures.set(fixture.id, fixture)
  }
  return fixtures
}

// A scenario may extend another one: its responses replace the parent's, key by key.
const resolveFixture = (fixtures: Map<string, Fixture>, id: string): Fixture => {
  const fixture = fixtures.get(id) ?? fixtures.get(DEFAULT_SCENARIO)
  if (!fixture) throw new Error(`No demo fixture named "${id}" in ${FIXTURES}`)
  if (!fixture.extends) return fixture
  const parent = resolveFixture(fixtures, fixture.extends)
  return {
    ...parent,
    ...fixture,
    responses: { ...parent.responses, ...fixture.responses },
    afterScan: fixture.afterScan ?? parent.afterScan,
  }
}

const UNIT_MS: Record<string, number> = { s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 }
const OFFSET = /^@?([+-])(\d+)([smhdw])$/

const offsetMs = (text: string | undefined) => {
  const match = text ? OFFSET.exec(text) : null
  if (!match) return 0
  return (match[1] === '-' ? -1 : 1) * Number(match[2]) * (UNIT_MS[match[3]!] ?? 0)
}

// Dates are written relative to now ("@-2h", "@+84d") so that a fixture never goes out of date.
const resolveTimes = (value: Json, now: number, shift: number): Json => {
  if (typeof value === 'string') {
    return value.startsWith('@') && OFFSET.test(value) ? new Date(now + shift + offsetMs(value)).toISOString() : value
  }
  if (Array.isArray(value)) return value.map((item) => resolveTimes(item, now, shift))
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, resolveTimes(item, now, shift)]))
  }
  return value
}

const AUDIT_ACTIONS: Record<string, string> = {
  accepted: 'finding_accepted',
  false_positive: 'finding_false_positive',
  open: 'finding_reopened',
}

type Document = { [key: string]: Json }

const withFindings = (document: Json, state: Session, extra: Json[] = []): Json => {
  if (!document || typeof document !== 'object' || Array.isArray(document)) return document
  const scan = document as Document
  const findings = [...(Array.isArray(scan.findings) ? scan.findings : []), ...extra].map((item) => {
    const finding = item as Document
    const decision = state.triage.get(String(finding.finding_id))
    if (!decision) return finding
    return { ...finding, triage_status: decision.status, triage_reason: decision.reason, triage_expires_at: decision.expires }
  })
  return { ...scan, findings }
}

export default defineEventHandler(async (event) => {
  const path = event.path.split('?')[0] ?? ''
  if (!path.startsWith('/api/')) return

  const method = getMethod(event)
  const fixtures = readFixtures()
  const requested = getCookie(event, DEMO_COOKIE) ?? DEFAULT_SCENARIO
  const fixture = resolveFixture(fixtures, requested)
  const state = session(fixture.id)
  const now = Date.now()
  const resolve = (value: Json) => resolveTimes(value, now, offsetMs(fixture.shift))
  const route = path.slice('/api/'.length)

  setResponseHeader(event, 'X-AttackLens-Demo', fixture.id)

  // The banner's own calls: they work in every scenario, including the failing one.
  if (route === 'demo') {
    return {
      current: fixture.id,
      scenarios: [...fixtures.values()].map(({ id, label, description }) => ({ id, label, description })),
    }
  }
  if (route === 'demo/reset' && method === 'POST') {
    sessions.delete(fixture.id)
    return { reset: fixture.id }
  }

  if (fixture.fail) {
    setResponseStatus(event, fixture.fail)
    return { detail: 'Demo mode: the API is unreachable in this scenario.' }
  }

  const notFound = (detail = 'Not found') => {
    setResponseStatus(event, 404)
    return { detail }
  }
  const respond = (key: string) => {
    const value = fixture.responses[key]
    return value === null || value === undefined ? notFound() : resolve(value)
  }

  const scanned = state.scannedAt
  const added = scanned ? fixture.afterScan?.findings ?? [] : []

  const results = () => {
    const value = fixture.responses.results
    if (!value) return notFound('No scan has run yet.')
    const scan = withFindings(resolve(value), state, added) as Document
    if (!scanned) return scan
    const coverage = (scan.coverage ?? {}) as Document
    return {
      ...scan,
      completed_at: scanned,
      coverage: { ...coverage, ports_open: Number(coverage.ports_open ?? 0) + added.length },
    }
  }

  const finishScan = () => {
    state.scannedAt = new Date().toISOString()
    state.audit.unshift({ entry_id: 9000 + state.audit.length, at: state.scannedAt, actor: 'dashboard', action: 'scan_ordered', detail: 'demo' })
  }

  if (method === 'GET') {
    if (route === 'results') return results()
    if (route === 'host') {
      const value = fixture.responses.host
      return value ? withFindings(resolve(value), state) : notFound('No host report yet.')
    }
    if (route === 'alerts') {
      const base = resolve(fixture.responses.alerts ?? []) as Json[]
      const fresh = scanned ? (resolveTimes(fixture.afterScan?.alerts ?? [], Date.parse(scanned), 0) as Json[]) : []
      return [...fresh, ...base]
    }
    if (route === 'audit') return [...state.audit, ...(resolve(fixture.responses.audit ?? []) as Json[])].slice(0, 12)
    if (route === 'scans') {
      const scans = resolve(fixture.responses.scans ?? []) as Document[]
      return scanned && scans[0] ? [{ ...scans[0], completed_at: scanned }, ...scans.slice(1)] : scans
    }
    if (route === 'scans/compare') return respond('compare')
    if (route === 'health') return { status: 'ok', demo: true }
    if (route === 'report') {
      setResponseHeader(event, 'Content-Type', 'text/html; charset=utf-8')
      return '<!doctype html><title>Demo mode</title><p>The printable report is not available in demo mode.</p>'
    }
    if (route.startsWith('jobs/')) {
      const jobId = route.slice('jobs/'.length)
      const polls = (state.jobs.get(jobId) ?? 0) + 1
      state.jobs.set(jobId, polls)
      const done = polls >= 3
      if (done && !state.scannedAt) finishScan()
      return { job_id: jobId, agent: 'demo', target: null, status: done ? 'done' : 'running', error: null, scan_id: done ? 'demo-scan-11' : null }
    }
    if (['agents', 'paths', 'exposure', 'inventory', 'vulnerabilities', 'posture'].includes(route)) return respond(route)
    return notFound('This endpoint is not part of the demo.')
  }

  if (method === 'POST' && route === 'scan') {
    // A real scan takes a few seconds: keep the wait, so the running state can be seen.
    await new Promise((done) => setTimeout(done, 1800))
    finishScan()
    return results()
  }
  if (method === 'POST' && route === 'jobs') {
    const jobId = `demo-job-${state.jobs.size + 1}`
    state.jobs.set(jobId, 0)
    state.scannedAt = null
    setResponseStatus(event, 202)
    return { job_id: jobId, agent: 'demo', target: null, status: 'queued', error: null, scan_id: null }
  }
  if (method === 'POST' && route === 'agents/enrollment') {
    return { code: 'DEMO-7Q4K-2M9X', expires_at: new Date(now + 10 * UNIT_MS.m!).toISOString() }
  }
  if (method === 'PUT' && /^findings\/[^/]+\/triage$/.test(route)) {
    const findingId = decodeURIComponent(route.split('/')[1] ?? getRouterParam(event, 'id') ?? '')
    const body = (await readBody(event)) as { status?: string; reason?: string | null; days?: number | null }
    const status = body.status ?? 'open'
    if (status === 'open') state.triage.set(findingId, { status, reason: null, expires: null })
    else {
      const expires = body.days ? new Date(now + body.days * UNIT_MS.d!).toISOString() : null
      state.triage.set(findingId, { status, reason: body.reason ?? null, expires })
    }
    state.audit.unshift({ entry_id: 9000 + state.audit.length, at: new Date(now).toISOString(), actor: 'dashboard', action: AUDIT_ACTIONS[status] ?? status, detail: findingId })
    return { finding_id: findingId, status }
  }

  setResponseStatus(event, 405)
  return { detail: 'Demo mode does not change anything on this endpoint.' }
})
