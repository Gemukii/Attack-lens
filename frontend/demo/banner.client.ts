// Demo mode banner: always on screen, on every page, so invented data is never taken for real.
//
// Registered by nuxt.config.ts in development only, when ATTACKLENS_DEMO=1. Built with plain
// DOM calls on purpose: nothing of the demo lives in app/, so nothing can leak into production.
const COOKIE = 'attacklens_demo'

interface DemoState {
  current: string
  scenarios: Array<{ id: string; label: string; description: string }>
}

const choose = (id: string) => {
  document.cookie = `${COOKIE}=${encodeURIComponent(id)}; path=/; SameSite=Lax`
}

export default defineNuxtPlugin(() => {
  // `?demo=stale` picks a scenario from the address bar. Read before the first API call.
  const requested = new URL(window.location.href).searchParams.get('demo')
  if (requested) choose(requested)

  // Reload without `?demo=`, or the address bar would win over the choice just made.
  const reload = () => {
    const url = new URL(window.location.href)
    url.searchParams.delete('demo')
    if (url.href === window.location.href) window.location.reload()
    else window.location.assign(url)
  }

  const banner = document.createElement('aside')
  banner.className = 'demo-banner'
  banner.setAttribute('aria-label', 'Demo mode')

  const title = document.createElement('strong')
  title.textContent = 'Demo mode'

  const note = document.createElement('span')
  note.className = 'demo-banner-note'
  note.textContent = 'Invented data. Nothing here describes a real machine.'

  const label = document.createElement('label')
  label.className = 'demo-banner-field'
  const labelText = document.createElement('span')
  labelText.textContent = 'Scenario'
  const select = document.createElement('select')
  select.setAttribute('aria-label', 'Scenario')
  select.addEventListener('change', () => {
    choose(select.value)
    reload()
  })
  label.append(labelText, select)

  const reset = document.createElement('button')
  reset.type = 'button'
  reset.textContent = 'Reset'
  reset.title = 'Forget the scans and decisions made in this scenario'
  reset.addEventListener('click', async () => {
    await fetch('/api/demo/reset', { method: 'POST' })
    reload()
  })

  banner.append(title, note, label, reset)
  document.body.append(banner)

  fetch('/api/demo')
    .then((response) => response.json() as Promise<DemoState>)
    .then(({ current, scenarios }) => {
      for (const scenario of scenarios) {
        const option = document.createElement('option')
        option.value = scenario.id
        option.textContent = scenario.label
        option.title = scenario.description
        select.append(option)
      }
      select.value = current
    })
    .catch(() => {
      note.textContent = 'Invented data. The list of scenarios could not be loaded.'
    })
})
