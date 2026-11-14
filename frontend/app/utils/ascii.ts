// Characters as an image: the ramp of glyphs, their tones, and the waves of the login and
// error pages. The bench itself is drawn by utils/glyphField.ts.

export const RAMP = ' .·:-=+*#%@'

// Cheap integer hash, stable for a cell.
export const hash = (x: number, y: number, z = 0) => {
  let h = (x * 374761393 + y * 668265263 + z * 2147483647) | 0
  h = Math.imul(h ^ (h >>> 13), 1274126177)
  return ((h ^ (h >>> 16)) >>> 0) / 4294967295
}

// For the login and error pages: interfering waves, nothing to report, so no red.
export const sampleWaves = (x: number, y: number, t: number) => {
  const wave = (Math.sin(x * 1.1 + t * 0.35) + Math.sin(y * 1.9 - t * 0.27) + Math.sin((x + y) * 0.7 + t * 0.18)) / 6 + 0.5
  return Math.max(0, wave - 0.5) * 2
}

export const glyph = (value: number) => {
  if (value < 0.07) return ' '
  return RAMP[Math.min(RAMP.length - 1, Math.round(value * (RAMP.length - 1)))]!
}

// Tones are token names, not colours: components read the colours from the CSS
// (assets/css/tokens/semantic.css), so no colour is written in a script.
export const FIELD_TONES = ['field-1', 'field-2', 'field-3', 'field-4'] as const
export const FIELD_HOT_TONES = ['field-hot-1', 'field-hot-2', 'field-hot-3'] as const
export type FieldTone = (typeof FIELD_TONES)[number] | (typeof FIELD_HOT_TONES)[number]

export const tint = (value: number, hot: boolean): FieldTone => {
  if (hot) return FIELD_HOT_TONES[value < 0.35 ? 0 : value < 0.65 ? 1 : 2]!
  return FIELD_TONES[value < 0.25 ? 0 : value < 0.5 ? 1 : value < 0.8 ? 2 : 3]!
}
