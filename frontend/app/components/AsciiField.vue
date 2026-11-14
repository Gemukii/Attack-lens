<script setup lang="ts">
import type { FieldTone } from '~/utils/ascii'
import { FIELD_TONES, glyph, sampleWaves, tint } from '~/utils/ascii'
import { motionDuration, tokenColour } from '~/utils/motion'

// A field of characters behind the login and error pages: the signature of the interface,
// where there is nothing to report. Slow waves drift across it. It pauses when the page is
// hidden and is still under reduced motion. Decorative, so hidden from assistive technology;
// no text sits on it, the form has its own opaque panel.
const props = withDefaults(defineProps<{
  cell?: number
}>(), { cell: 14 })

const root = ref<HTMLElement | null>(null)
const canvas = ref<HTMLCanvasElement | null>(null)

// Few frames on purpose: characters change in place, they do not slide.
const FRAMES_PER_SECOND = 12
// Where the waves stand when they are still.
const REST = 4

let context: CanvasRenderingContext2D | null = null
let columns = 0
let rows = 0
let frame = 0
let last = 0
let started = 0
// Seconds for one swell to pass. Zero means still.
let flow = 0
let resizer: ResizeObserver | undefined
const colours = new Map<FieldTone, string>()
let typeface = 'monospace'

const readTokens = () => {
  if (!root.value) return
  for (const tone of FIELD_TONES) colours.set(tone, tokenColour(root.value, tone))
  typeface = tokenColour(root.value, 'font-mono') || typeface
}

const resize = () => {
  const element = canvas.value
  const box = root.value
  if (!element || !box) return
  const ratio = Math.min(window.devicePixelRatio || 1, 2)
  const { width, height } = box.getBoundingClientRect()
  element.width = Math.max(1, Math.round(width * ratio))
  element.height = Math.max(1, Math.round(height * ratio))
  context = element.getContext('2d')
  if (!context) return
  context.setTransform(ratio, 0, 0, ratio, 0, 0)
  context.font = `${props.cell}px ${typeface}`
  context.textBaseline = 'top'
  columns = Math.ceil(width / (props.cell * 0.62))
  rows = Math.ceil(height / props.cell)
}

const draw = (t: number) => {
  if (!context || !canvas.value) return
  const step = props.cell * 0.62
  const { width, height } = canvas.value.getBoundingClientRect()
  context.clearRect(0, 0, width, height)
  // Coordinates in units of half the height, so shapes keep their proportions.
  const span = (width / height) * 2
  let colour = ''
  for (let row = 0; row < rows; row += 1) {
    const y = ((row + 0.5) / rows) * 2 - 1
    for (let column = 0; column < columns; column += 1) {
      const x = ((column + 0.5) / columns) * span
      const value = sampleWaves(x * 5.5, y * 5.5, t) * 0.95
      const character = glyph(value)
      if (character === ' ') continue
      const next = colours.get(tint(value, false)) ?? ''
      if (next !== colour) {
        context.fillStyle = next
        colour = next
      }
      context.fillText(character, column * step, row * props.cell)
    }
  }
}

// One unit of wave time per swell: the drift is slow, like breathing.
const moment = (now: number) => REST + (flow ? (now - started) / 1000 / flow : 0)

const loop = (now: number) => {
  frame = requestAnimationFrame(loop)
  if (now - last < 1000 / FRAMES_PER_SECOND) return
  last = now
  draw(moment(now))
}

const run = () => {
  cancelAnimationFrame(frame)
  if (!flow || document.hidden) return
  frame = requestAnimationFrame(loop)
}

onMounted(async () => {
  await document.fonts?.ready
  readTokens()
  resize()
  flow = motionDuration('--dur-flow') / 1000
  started = performance.now()
  draw(REST)
  resizer = new ResizeObserver(() => {
    resize()
    draw(moment(performance.now()))
  })
  if (root.value) resizer.observe(root.value)
  document.addEventListener('visibilitychange', run)
  run()
})

onBeforeUnmount(() => {
  cancelAnimationFrame(frame)
  resizer?.disconnect()
  document.removeEventListener('visibilitychange', run)
})
</script>

<template>
  <div ref="root" class="ascii-field" aria-hidden="true">
    <canvas ref="canvas" />
  </div>
</template>
