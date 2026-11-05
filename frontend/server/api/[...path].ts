// Forwards browser calls to the API and adds the key on the server side, so that the
// key never reaches the browser. The host and origin checks keep a malicious web page
// from reaching this proxy through DNS rebinding or a cross-site request.
export default defineEventHandler((event) => {
  const config = useRuntimeConfig(event)
  const allowedHosts = config.allowedHosts
    .split(',')
    .map((host: string) => host.trim())
    .filter(Boolean)
  const stripPort = (host: string) => host.replace(/:\d+$/, '')

  if (!allowedHosts.includes(stripPort(getRequestHost(event)))) {
    throw createError({ statusCode: 403, statusMessage: 'Host not allowed' })
  }

  const origin = getRequestHeader(event, 'origin')
  if (origin && !allowedHosts.includes(stripPort(new URL(origin).host))) {
    throw createError({ statusCode: 403, statusMessage: 'Origin not allowed' })
  }

  return proxyRequest(event, `${config.apiInternalBase}${event.path}`, {
    headers: config.apiKey ? { 'X-API-Key': config.apiKey } : {},
  })
})
