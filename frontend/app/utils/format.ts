// A date that is missing is not known: said in words, never abbreviated.
const NOT_AVAILABLE = 'Not known'

export const formatDate = (value?: string) => {
  if (!value) return NOT_AVAILABLE
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(date)
}

// How long ago, in the largest unit that fits: "just now", "35 min ago", "2 h ago", "23 d ago".
export const ago = (value: string | number | undefined | null, now: number = Date.now()) => {
  const then = typeof value === 'number' ? value : value ? Date.parse(value) : Number.NaN
  if (Number.isNaN(then)) return NOT_AVAILABLE
  const seconds = Math.max(0, Math.round((now - then) / 1000))
  if (seconds < 90) return 'just now'
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours} h ago`
  return `${Math.round(hours / 24)} d ago`
}

export const signed = (value: number) => `${value > 0 ? '+' : value < 0 ? '−' : '±'}${Math.abs(value)}`
