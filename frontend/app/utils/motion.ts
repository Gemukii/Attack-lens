// Motion helpers. Durations are never written here: they are read from the CSS tokens
// (assets/css/tokens/motion.css), so that the styles and the scripts cannot disagree.

const FALLBACK_MS = 0

// "120ms" or "1.5s", as a number of milliseconds.
export const parseDuration = (value: string): number => {
  const text = value.trim()
  if (text.endsWith('ms')) return Number.parseFloat(text)
  if (text.endsWith('s')) return Number.parseFloat(text) * 1000
  return Number.isFinite(Number(text)) ? Number(text) : FALLBACK_MS
}

// The duration of a motion token, for example `--dur-flash`. Zero under reduced motion,
// and on the server.
export const motionDuration = (token: string): number => {
  if (typeof window === 'undefined') return FALLBACK_MS
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return FALLBACK_MS
  return parseDuration(getComputedStyle(document.documentElement).getPropertyValue(token)) || FALLBACK_MS
}

// How long a short notice ("Copied") stays before it clears itself. It is the same fade
// as a value that just changed, and it stays readable under reduced motion.
export const noticeDuration = (): number => {
  if (typeof window === 'undefined') return FALLBACK_MS
  return parseDuration(getComputedStyle(document.documentElement).getPropertyValue('--dur-flash')) || FALLBACK_MS
}

type ViewTransitionDocument = Document & { startViewTransition?: (update: () => void | Promise<void>) => unknown }

// Runs a change of view as a cross-fade where the browser supports it, and at once elsewhere.
export const withViewTransition = (update: () => void | Promise<void>): void => {
  const target = typeof document === 'undefined' ? null : (document as ViewTransitionDocument)
  if (!target?.startViewTransition || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    void update()
    return
  }
  target.startViewTransition(update)
}

// A colour token as the browser resolved it, for canvases and charts: no colour is ever
// written in a script.
export const tokenColour = (element: Element, token: string): string =>
  getComputedStyle(element).getPropertyValue(`--${token}`).trim()
