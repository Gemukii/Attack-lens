// With a password set, nothing but the login page is served to anonymous visitors.
const PUBLIC_PATHS = ['/login', '/auth/', '/_nuxt/', '/favicon.svg', '/favicon.ico']

export default defineEventHandler(async (event) => {
  const { dashboardPassword } = useRuntimeConfig(event)
  if (!dashboardPassword) return

  const path = event.path.split('?')[0] ?? ''
  if (PUBLIC_PATHS.some((prefix) => path === prefix || (prefix.endsWith('/') && path.startsWith(prefix)))) return

  const session = await useSession(event, sessionConfig())
  if (session.data.authenticated) return

  if (path.startsWith('/api/')) {
    throw createError({ statusCode: 401, statusMessage: 'Login required' })
  }
  return sendRedirect(event, '/login')
})
