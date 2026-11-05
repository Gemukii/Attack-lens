<script setup lang="ts">
// A lens iris driven by the data: the more exposed the target, the wider it opens and
// the more safelight comes through. Scanning makes it hunt for focus.
const props = defineProps<{
  score: number | null
  scanning: boolean
}>()

const BLADES = 9
const BARREL = 150
const CLOSED = 12
const OPEN = 122
const TAU = Math.PI * 2

const radius = ref(CLOSED)
const rotation = ref(0)

const openingFor = (score: number | null) =>
  score === null ? CLOSED : CLOSED + ((100 - score) / 100) * (OPEN - CLOSED)

const point = (angle: number, distance: number) => ({
  x: Math.cos(angle) * distance,
  y: Math.sin(angle) * distance,
})

const toBarrel = (from: { x: number; y: number }, to: { x: number; y: number }) => {
  const length = Math.hypot(to.x - from.x, to.y - from.y) || 1
  const dx = (to.x - from.x) / length
  const dy = (to.y - from.y) / length
  const projection = to.x * dx + to.y * dy
  const reach = -projection + Math.sqrt(projection ** 2 - (to.x ** 2 + to.y ** 2 - BARREL ** 2))
  return { x: to.x + dx * reach, y: to.y + dy * reach }
}

const geometry = computed(() => {
  const vertices = Array.from({ length: BLADES }, (_, index) =>
    point(rotation.value + (index * TAU) / BLADES, radius.value),
  )
  const edges = vertices.map((vertex, index) =>
    toBarrel(vertex, vertices[(index + 1) % BLADES]!),
  )
  const blades = vertices.map((_, index) => {
    const pivot = vertices[(index + 1) % BLADES]!
    const next = vertices[(index + 2) % BLADES]!
    const start = edges[index]!
    const end = edges[(index + 1) % BLADES]!
    return {
      path: `M${pivot.x} ${pivot.y}L${start.x} ${start.y}A${BARREL} ${BARREL} 0 0 1 ${end.x} ${end.y}L${next.x} ${next.y}Z`,
      shade: 0.05 + (index % 3) * 0.03,
    }
  })
  return {
    hole: vertices.map(({ x, y }) => `${x},${y}`).join(' '),
    blades,
  }
})

// The barrel scale runs over the top three quarters, like a lens ring.
const SCALE_START = (135 * Math.PI) / 180
const SCALE_SWEEP = (270 * Math.PI) / 180
const scaleAngle = (value: number) => SCALE_START + (value / 100) * SCALE_SWEEP

const ticks = Array.from({ length: 51 }, (_, index) => {
  const value = index * 2
  const major = value % 25 === 0
  const inner = point(scaleAngle(value), major ? 164 : 168)
  const outer = point(scaleAngle(value), 174)
  return { ...{ x1: inner.x, y1: inner.y, x2: outer.x, y2: outer.y }, major }
})

const labels = [0, 25, 50, 75, 100].map((value) => ({
  value,
  ...point(scaleAngle(value), 187),
}))

const pointer = computed(() => {
  if (props.score === null) return null
  const angle = scaleAngle(props.score)
  const tip = point(angle, 161)
  const left = point(angle - 0.035, 151)
  const right = point(angle + 0.035, 151)
  return `${tip.x},${tip.y} ${left.x},${left.y} ${right.x},${right.y}`
})

const label = computed(() =>
  props.score === null
    ? 'Aperture closed: no exposure reading.'
    : `Aperture open in proportion to exposure. Network score ${props.score} out of 100.`,
)

let frame = 0
let startedAt = 0

const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches

const animate = (now: number) => {
  const target = openingFor(props.score)
  let settled = false

  if (props.scanning) {
    const time = (now - startedAt) / 1000
    const hunt = 46 + Math.sin(time * 2.1) * 26 + Math.sin(time * 5.3) * 7
    radius.value += (hunt - radius.value) * 0.09
    rotation.value += 0.006
  } else {
    radius.value += (target - radius.value) * 0.07
    rotation.value += ((target / OPEN) * 0.9 - rotation.value) * 0.07
    settled = Math.abs(target - radius.value) < 0.05
  }

  if (settled) {
    radius.value = target
    frame = 0
    return
  }
  frame = requestAnimationFrame(animate)
}

const wake = () => {
  if (reducedMotion()) {
    radius.value = openingFor(props.score)
    return
  }
  if (!frame) {
    startedAt = performance.now()
    frame = requestAnimationFrame(animate)
  }
}

onMounted(wake)
watch(() => [props.score, props.scanning], wake)
onBeforeUnmount(() => cancelAnimationFrame(frame))
</script>

<template>
  <svg class="aperture" viewBox="-205 -205 410 410" role="img" :aria-label="label">
    <defs>
      <radialGradient id="light">
        <stop offset="0" stop-color="var(--safelight)" />
        <stop offset="0.72" stop-color="var(--safelight)" />
        <stop offset="1" stop-color="var(--safelight)" stop-opacity="0.72" />
      </radialGradient>
    </defs>

    <circle r="178" fill="none" stroke="var(--rule)" />
    <line
      v-for="(tick, index) in ticks"
      :key="index"
      :x1="tick.x1"
      :y1="tick.y1"
      :x2="tick.x2"
      :y2="tick.y2"
      :stroke="tick.major ? 'var(--paper-soft)' : 'var(--rule-strong)'"
    />
    <text v-for="item in labels" :key="item.value" :x="item.x" :y="item.y">{{ item.value }}</text>

    <circle :r="BARREL" fill="var(--ink)" stroke="var(--rule-strong)" />
    <polygon :points="geometry.hole" fill="url(#light)" />
    <path
      v-for="(blade, index) in geometry.blades"
      :key="index"
      :d="blade.path"
      fill="var(--paper)"
      :fill-opacity="blade.shade"
      stroke="var(--ink)"
      stroke-width="1.5"
    />
    <polygon :points="geometry.hole" fill="none" stroke="var(--ink)" stroke-width="2" />
    <circle :r="BARREL" fill="none" stroke="var(--rule-strong)" />
    <polygon v-if="pointer" :points="pointer" fill="var(--paper)" />
  </svg>
</template>
