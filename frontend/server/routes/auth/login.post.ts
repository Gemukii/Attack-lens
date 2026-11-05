import { createHash, timingSafeEqual } from 'node:crypto'

const MAX_FAILURES = 5
const WINDOW_MS = 60_000
const failures = new Map<string, { count: number; since: number }>()

const digest = (value: string) => createHash('sha256').update(value).digest()

export default defineEventHandler(async (event) => {
  const { dashboardPassword } = useRuntimeConfig(event)
  if (!dashboardPassword) return { authenticated: true }

  const client = getRequestIP(event) ?? 'unknown'
  const record = failures.get(client)
  const now = Date.now()
  if (record && now - record.since < WINDOW_MS && record.count >= MAX_FAILURES) {
    throw createError({ statusCode: 429, statusMessage: 'Too many attempts. Wait a minute.' })
  }

  const body = await readBody<{ password?: string }>(event)
  const valid = timingSafeEqual(digest(String(body?.password ?? '')), digest(dashboardPassword))
  if (!valid) {
    const current = record && now - record.since < WINDOW_MS ? record : { count: 0, since: now }
    failures.set(client, { ...current, count: current.count + 1 })
    throw createError({ statusCode: 401, statusMessage: 'Wrong password' })
  }

  failures.delete(client)
  const session = await useSession(event, sessionConfig())
  await session.update({ authenticated: true })
  return { authenticated: true }
})
