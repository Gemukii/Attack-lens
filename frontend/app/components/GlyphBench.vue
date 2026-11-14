<script setup lang="ts">
import type { FieldTone } from '~/utils/ascii'
import { FIELD_HOT_TONES, FIELD_TONES } from '~/utils/ascii'
import type { Bench, Ray } from '~/utils/bench'
import { benchStations, describeRay, isProvedWay, rayStateText, rayTrace } from '~/utils/bench'
import type { FieldLabel } from '~/utils/glyphField'
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
//
// On a phone the picture cannot be read: seven rays do not fit in 360 px. The same rays are
// then a list, one line each, with the stroke of the legend and the state in words.
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

const COLUMNS = 138
// Few frames on purpose: characters change in place, they do not slide.
const FRAMES_PER_SECOND = 12
// A cell is 0.6 of the type size wide and 1.1 high, as in the stylesheet.
const CELL_WIDTH = 0.6
const CELL_HEIGHT = 1.1

const field = computed(() => buildGlyphField(props.bench, COLUMNS, false))
const stations = computed(() => benchStations(props.bench))

const hovered = ref<Ray | null>(null)
const note = computed(() => {
  if (hovered.value) return describeRay(hovered.value)
  return props.bench.rays.length ? 'Each band is a service. Point at its name to read it, select it for the detail.' : 'No service drawn yet.'
})

const root = ref<HTMLElement | null>(null)
const canvas = ref<HTMLCanvasElement | null>(null)
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
let watcher: IntersectionObserver | undefined
let resizer: ResizeObserver | undefined

// Paints one moment. Returns false when there is nothing to paint on: no canvas yet, or a
// phone, where the picture is not shown.
const paint = (now: number) => {
  const box = canvas.value?.parentElement
  const context = canvas.value?.getContext('2d')
  if (!canvas.value || !box || !context) return false

  const width = box.clientWidth
  if (!width) return false
  const cell = width / (field.value.cols * CELL_WIDTH)
  const height = field.value.rows * cell * CELL_HEIGHT
  const ratio = Math.min(window.devicePixelRatio || 1, 2)
  if (canvas.value.width !== Math.round(width * ratio) || canvas.value.height !== Math.round(height * ratio)) {
    canvas.value.width = Math.round(width * ratio)
    canvas.value.height = Math.round(height * ratio)
  }
  context.setTransform(ratio, 0, 0, ratio, 0, 0)
  context.clearRect(0, 0, width, height)
  context.font = `${cell}px ${typeface}`
  context.textBaseline = 'middle'

  const elapsed = now - started
  const lines = renderGlyphLines(field.value, {
    time: flow ? elapsed / 1000 : undefined,
    speed: flow ? field.value.width / flow : undefined,
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
  if (!painted.value) return
  if (flow && inView && !document.hidden) frame = requestAnimationFrame(loop)
  else paint(performance.now())
}

// The picture may not be on screen when the page arrives (a phone shows the list), and
// come later when the window widens: it develops the first time it can be painted.
const show = () => {
  const now = performance.now()
  if (!painted.value) started = now
  if (!paint(now) || painted.value) return
  painted.value = true
  run()
}

onMounted(async () => {
  await document.fonts?.ready
  if (!root.value) return
  for (const tone of [...FIELD_TONES, ...FIELD_HOT_TONES]) colours.set(tone, tokenColour(root.value, tone))
  typeface = tokenColour(root.value, 'font-mono') || typeface
  flow = motionDuration('--dur-flow') / 1000
  // What happens once lasts 400 ms at most: the entrance takes the slow duration, no more.
  develop = motionDuration('--dur-slow')
  show()

  resizer = new ResizeObserver(show)
  resizer.observe(root.value)
  if (typeof IntersectionObserver !== 'undefined') {
    watcher = new IntersectionObserver(([entry]) => {
      inView = entry?.isIntersecting ?? true
      run()
    })
    watcher.observe(root.value)
  }
  document.addEventListener('visibilitychange', run)
})

// New data, or a ray pointed at: the picture is painted again at once, moving or not.
watch([field, hovered, () => props.highlight], () => {
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
  document.removeEventListener('visibilitychange', run)
})

const place = (label: FieldLabel) => ({ '--r': label.row, '--c': label.col })
</script>

<template>
  <figure ref="root" :class="['glyph-bench', { painted, scanning }]">
    <div
      class="glyph-field only-wide"
      role="group"
      :aria-label="field.summary"
      :style="{ '--cols': field.cols, '--rows': field.rows }"
    >
      <div class="glyph-field-wrap">
        <pre aria-hidden="true"><template v-for="(line, row) in field.lines" :key="row"><span v-for="(run, index) in line" :key="index" :class="run.tone">{{ run.text }}</span>{{ '\n' }}</template></pre>
        <canvas ref="canvas" aria-hidden="true" />
        <template v-for="(label, index) in field.labels" :key="index">
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

    <!-- On a phone: the same rays as a list. Each keeps the stroke it has in the picture. -->
    <div class="ray-list only-narrow" role="group" :aria-label="field.summary">
      <ul v-if="bench.rays.length || bench.side.length" class="rays">
        <li v-for="(ray, index) in bench.rays" :key="ray.id" :style="{ '--i': index }">
          <button
            type="button"
            :class="['ray', { linked: ray.id === highlight }]"
            :aria-label="describeRay(ray)"
            @click="emit('select', ray)"
          >
            <span class="ray-name"><b>{{ ray.label }}</b><i>{{ ray.port }}</i></span>
            <span :class="['ray-trace', rayTrace(ray).tone]" aria-hidden="true">{{ rayTrace(ray).text }}</span>
            <span :class="['ray-state t-body-s', { 'text-alert': isProvedWay(ray) }]">{{ rayStateText(ray) }}</span>
          </button>
        </li>
        <li v-for="(side, index) in bench.side" :key="side.id" :style="{ '--i': bench.rays.length + index }">
          <p class="ray">
            <span class="ray-name"><b>{{ side.label }}</b></span>
            <span class="ray-trace field-3" aria-hidden="true">· · *</span>
            <span class="ray-state t-body-s">Leads to full control, not through the network</span>
          </p>
        </li>
      </ul>
      <dl class="stations">
        <div v-for="station in stations" :key="station.label">
          <dt class="t-label">{{ station.label }}</dt>
          <dd :class="['t-body-s', { 'text-alert': station.alert }]">{{ station.value }}</dd>
        </div>
      </dl>
    </div>

    <figcaption class="t-body-s" aria-live="polite">
      <span class="only-wide">{{ note }}</span>
      <span class="only-narrow">{{ bench.rays.length ? 'Each line is a service. Select it for the detail.' : 'No service listed yet.' }}</span>
    </figcaption>
  </figure>
</template>
