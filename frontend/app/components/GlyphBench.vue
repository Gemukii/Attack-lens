<script setup lang="ts">
import type { FieldTone } from '~/utils/ascii'
import { FIELD_HOT_TONES, FIELD_TONES } from '~/utils/ascii'
import type { Bench, Ray } from '~/utils/bench'
import { describeRay } from '~/utils/bench'
import type { FieldLabel, GlyphField } from '~/utils/glyphField'
import { buildGlyphField, renderGlyphLines } from '~/utils/glyphField'
import { motionDuration, tokenColour } from '~/utils/motion'

// The optical bench, drawn in characters. The picture is hidden from assistive technology
// and described in words; the rays are real buttons, placed on cells left blank for them.
//
// It moves, and the motion says something: light travels along each ray the way an attacker
// would, stops where the ray stops, and gathers on the focus only when something reaches it.
// It develops once when it appears, pauses when it is out of sight, and is still under
// reduced motion.
//
// The still picture is text, rendered by the server. Once in the browser the same picture
// is painted on a canvas laid over it, so that a frame never moves anything in the page.
const props = withDefaults(defineProps<{
  bench: Bench
  // A ray pointed at from elsewhere in the page, for example from the list of actions.
  highlight?: string | null
  // A scan is running: the picture steps back, then develops again with the new reading.
  scanning?: boolean
}>(), { highlight: null, scanning: false })

const emit = defineEmits<{
  select: [ray: Ray]
  // The ray under the pointer, or null: the page can answer by marking what it relates to.
  point: [ray: Ray | null]
}>()

type LayoutId = 'wide' | 'narrow'

// Two widths: the columns always fit their container, and a phone gets fewer of them.
const WIDE_COLUMNS = 138
const NARROW_COLUMNS = 52
const NARROW_SCREEN = '(max-width: 640px)'
// Few frames on purpose: characters change in place, they do not slide.
const FRAMES_PER_SECOND = 12
// A cell is 0.6 of the type size wide and 1.1 high, as in the stylesheet.
const CELL_WIDTH = 0.6
const CELL_HEIGHT = 1.1

const wide = computed(() => buildGlyphField(props.bench, WIDE_COLUMNS, false))
const narrow = computed(() => buildGlyphField(props.bench, NARROW_COLUMNS, true))
const layouts = computed<Array<{ id: LayoutId; field: GlyphField }>>(() => [
  { id: 'wide', field: wide.value },
  { id: 'narrow', field: narrow.value },
])

const hovered = ref<Ray | null>(null)
const note = computed(() => {
  if (hovered.value) return describeRay(hovered.value)
  return props.bench.rays.length ? 'Each band is a service. Point at its name to read it, select it for the detail.' : 'No service drawn yet.'
})

const root = ref<HTMLElement | null>(null)
const canvases = ref<Partial<Record<LayoutId, HTMLCanvasElement>>>({})
// True once the canvas has taken over from the text.
const painted = ref(false)

const colours = new Map<FieldTone, string>()
let typeface = 'monospace'
let frame = 0
let last = 0
let started = 0
let inView = true
// Seconds for light to cross the picture, and ms for the picture to develop. Zero means still.
let flow = 0
let develop = 0
let narrowScreen = false
let watcher: IntersectionObserver | undefined
let resizer: ResizeObserver | undefined
let screen: MediaQueryList | undefined

const current = () => (narrowScreen ? { id: 'narrow' as LayoutId, field: narrow.value } : { id: 'wide' as LayoutId, field: wide.value })

// Paints one moment of the layout that is on screen. Returns false when there is no canvas to paint on.
const paint = (now: number) => {
  const { id, field } = current()
  const canvas = canvases.value[id]
  const box = canvas?.parentElement
  const context = canvas?.getContext('2d')
  if (!canvas || !box || !context) return false

  const width = box.clientWidth
  if (!width) return false
  const cell = width / (field.cols * CELL_WIDTH)
  const height = field.rows * cell * CELL_HEIGHT
  const ratio = Math.min(window.devicePixelRatio || 1, 2)
  if (canvas.width !== Math.round(width * ratio) || canvas.height !== Math.round(height * ratio)) {
    canvas.width = Math.round(width * ratio)
    canvas.height = Math.round(height * ratio)
  }
  context.setTransform(ratio, 0, 0, ratio, 0, 0)
  context.clearRect(0, 0, width, height)
  context.font = `${cell}px ${typeface}`
  context.textBaseline = 'middle'

  const elapsed = now - started
  const lines = renderGlyphLines(field, {
    time: flow ? elapsed / 1000 : undefined,
    speed: flow ? field.width / flow : undefined,
    highlight: hovered.value?.id ?? props.highlight,
    reveal: develop && elapsed < develop ? elapsed / develop : undefined,
  })
  lines.forEach((line, row) => {
    let column = 0
    for (const run of line) {
      if (run.tone) {
        context.fillStyle = colours.get(run.tone) ?? ''
        context.fillText(run.text, column * cell * CELL_WIDTH, (row + 0.5) * cell * CELL_HEIGHT)
      }
      column += run.text.length
    }
  })
  return true
}

const loop = (now: number) => {
  frame = requestAnimationFrame(loop)
  // While the picture develops it is painted on every frame: the entrance is short, and it
  // has to be smooth. After that the characters change in place, twelve times a second.
  const developing = develop > 0 && now - started < develop
  if (!developing && now - last < 1000 / FRAMES_PER_SECOND) return
  last = now
  paint(now)
}

// Runs the loop while the picture can be seen and may move. Otherwise it is painted once.
const run = () => {
  cancelAnimationFrame(frame)
  if (flow && inView && !document.hidden) frame = requestAnimationFrame(loop)
  else if (painted.value) paint(performance.now())
}

const onScreenChange = (event: MediaQueryListEvent) => {
  narrowScreen = event.matches
  paint(performance.now())
}

onMounted(async () => {
  await document.fonts?.ready
  if (!root.value) return
  for (const tone of [...FIELD_TONES, ...FIELD_HOT_TONES]) colours.set(tone, tokenColour(root.value, tone))
  typeface = tokenColour(root.value, 'font-mono') || typeface
  flow = motionDuration('--dur-flow') / 1000
  // What happens once lasts 400 ms at most: the entrance takes the slow duration, no more.
  develop = motionDuration('--dur-slow')
  screen = window.matchMedia(NARROW_SCREEN)
  narrowScreen = screen.matches
  screen.addEventListener?.('change', onScreenChange)
  started = performance.now()
  painted.value = paint(started)
  if (!painted.value) return

  resizer = new ResizeObserver(() => paint(performance.now()))
  resizer.observe(root.value)
  if (typeof IntersectionObserver !== 'undefined') {
    watcher = new IntersectionObserver(([entry]) => {
      inView = entry?.isIntersecting ?? true
      run()
    })
    watcher.observe(root.value)
  }
  document.addEventListener('visibilitychange', run)
  run()
})

// New data, or a ray pointed at: the picture is painted again at once, moving or not.
watch([wide, narrow, hovered, () => props.highlight], () => {
  if (painted.value) paint(performance.now())
})

watch(hovered, (ray) => emit('point', ray))

// When a scan ends, the picture develops again from the left: a new reading has arrived.
watch(() => props.scanning, (now, before) => {
  if (!before || now || !painted.value) return
  started = performance.now()
  run()
})

onBeforeUnmount(() => {
  cancelAnimationFrame(frame)
  watcher?.disconnect()
  resizer?.disconnect()
  screen?.removeEventListener?.('change', onScreenChange)
  document.removeEventListener('visibilitychange', run)
})

const place = (label: FieldLabel) => ({ '--r': label.row, '--c': label.col })
const setCanvas = (id: LayoutId) => (element: unknown) => {
  if (element) canvases.value[id] = element as HTMLCanvasElement
}
</script>

<template>
  <figure ref="root" :class="['glyph-bench', { painted, scanning }]">
    <div
      v-for="layout in layouts"
      :key="layout.id"
      :class="['glyph-field', `only-${layout.id}`]"
      role="group"
      :aria-label="layout.field.summary"
      :style="{ '--cols': layout.field.cols, '--rows': layout.field.rows }"
    >
      <div class="glyph-field-wrap">
        <pre aria-hidden="true"><template v-for="(line, row) in layout.field.lines" :key="row"><span v-for="(run, index) in line" :key="index" :class="run.tone">{{ run.text }}</span>{{ '\n' }}</template></pre>
        <canvas :ref="setCanvas(layout.id)" aria-hidden="true" />
        <template v-for="(label, index) in layout.field.labels" :key="index">
          <button
            v-if="label.ray"
            type="button"
            :class="['glyph-label glyph-ray', { linked: label.ray.id === highlight }]"
            :style="place(label)"
            :aria-label="describeRay(label.ray)"
            @mouseenter="hovered = label.ray"
            @mouseleave="hovered = null"
            @focus="hovered = label.ray"
            @blur="hovered = null"
            @click="emit('select', label.ray)"
          >
            <b>{{ label.text }}</b><i>{{ label.port }}</i>
          </button>
          <span v-else :class="['glyph-label', `glyph-${label.kind}`, `align-${label.align}`, { alert: label.alert }]" :style="place(label)">{{ label.text }}</span>
        </template>
      </div>
    </div>
    <figcaption class="t-body-s" aria-live="polite">{{ note }}</figcaption>
  </figure>
</template>
