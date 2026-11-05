<script setup lang="ts">
import type { Bench, Ray } from '~/utils/bench'
import { SIDE_START, STATIONS, STOP_OPENING, describeRay, rayHeights, rayPoints, sideRayPoints } from '~/utils/bench'

const props = defineProps<{
  bench: Bench
  scanning: boolean
}>()

const emit = defineEmits<{
  select: [ray: Ray]
}>()

const root = ref<HTMLElement | null>(null)
const width = ref(1120)
const hovered = ref<string | null>(null)

const compact = computed(() => width.value < 620)
const height = computed(() => (compact.value ? 350 : Math.max(400, Math.min(540, width.value * 0.4))))
const reach = computed(() => height.value / 2 - (compact.value ? 50 : 58))
const axis = computed(() => height.value / 2 - 14)

// t runs along the optical axis, s across it.
const place = (t: number, s: number) => ({ x: t * width.value, y: axis.value + s * reach.value })

const line = (points: Array<[number, number]>) =>
  points.map(([t, s]) => {
    const { x, y } = place(t, s)
    return `${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')

const rays = computed(() => {
  const heights = rayHeights(props.bench.rays)
  return props.bench.rays.map((ray, index) => {
    const spread = heights[index] ?? 0
    return {
      ray,
      points: line(rayPoints(spread, ray)),
      start: place(STATIONS.source, spread),
      end: ray.state === 'stopped' ? place(STATIONS.stop, spread) : null,
      delay: index * 90,
    }
  })
})

const sideRays = computed(() => props.bench.side.map((ray, index) => ({
  ray,
  points: line(sideRayPoints(index)),
  start: place(SIDE_START[0] + index * 0.04, SIDE_START[1]),
})))

const hoveredRay = computed(() => props.bench.rays.find((ray) => ray.id === hovered.value) ?? null)
const note = computed(() => {
  if (hoveredRay.value) return describeRay(hoveredRay.value)
  return props.bench.rays.length ? 'Each line is a service. Point at one to read it, select it for the detail.' : ''
})

const lens = (t: number, half: number, bulge: number) => {
  const top = place(t, -half)
  const bottom = place(t, half)
  const right = place(t + bulge, 0)
  const left = place(t - bulge, 0)
  return `M${top.x} ${top.y}Q${right.x} ${right.y} ${bottom.x} ${bottom.y}Q${left.x} ${left.y} ${top.x} ${top.y}Z`
}

// The stop is drawn like a section through metal: a solid, hatched blade on each side.
const blades = computed(() => {
  const thickness = compact.value ? 7 : 10
  const blade = (from: number, to: number) => {
    const a = place(STATIONS.stop, from)
    const b = place(STATIONS.stop, to)
    return { x: a.x - thickness / 2, y: Math.min(a.y, b.y), width: thickness, height: Math.abs(b.y - a.y) }
  }
  return [blade(-1.08, -STOP_OPENING), blade(STOP_OPENING, 1.08)]
})

const firewallOn = computed(() => ['enabled', 'partial'].includes(props.bench.firewall))
const focus = computed(() => place(STATIONS.focus, 0))

const accountText = computed(() => {
  if (props.bench.admin === null) return 'Unknown'
  if (!props.bench.admin) return 'Standard user'
  return compact.value ? 'Admin' : 'Administrator'
})

const captions = computed(() => [
  { t: STATIONS.stop, title: 'Firewall', text: props.bench.firewall === 'unknown' ? 'State unknown' : `Turned ${firewallOn.value ? 'on' : 'off'}` },
  { t: STATIONS.service, title: 'Services', text: props.bench.services === null ? 'Not read yet' : `${props.bench.services} answering` },
  { t: STATIONS.account, title: compact.value ? 'Account' : 'Your account', text: accountText.value },
])

let observer: ResizeObserver | undefined

onMounted(() => {
  if (!root.value) return
  width.value = root.value.clientWidth
  observer = new ResizeObserver(([entry]) => {
    if (entry) width.value = entry.contentRect.width
  })
  observer.observe(root.value)
})
onBeforeUnmount(() => observer?.disconnect())
</script>

<template>
  <figure ref="root" :class="['bench', { compact }]">
    <svg
      :viewBox="`0 0 ${width} ${height}`"
      :width="width"
      :height="height"
      role="img"
      :aria-label="`${bench.rays.length} services drawn as rays. ${bench.focused ? 'At least one reaches full control of the machine.' : 'None reaches full control of the machine.'}`"
    >
      <defs>
        <pattern id="hatch" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <line x1="0" y1="0" x2="0" y2="5" stroke="var(--paper)" stroke-opacity="0.2" />
        </pattern>
        <pattern id="hatch-dense" width="3.5" height="3.5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
          <line x1="0" y1="0" x2="0" y2="3.5" stroke="var(--paper)" stroke-opacity="0.75" />
        </pattern>
      </defs>

      <line class="axis" :x1="0" :y1="axis" :x2="width" :y2="axis" />

      <g :class="['stop', { open: !firewallOn }]">
        <rect v-for="(blade, index) in blades" :key="index" v-bind="blade" fill="url(#hatch-dense)" />
      </g>

      <path class="lens" :d="lens(STATIONS.service, 0.72, 0.022)" fill="url(#hatch)" />
      <path :class="['lens', { faint: bench.admin !== true }]" :d="lens(STATIONS.account, 0.5, 0.03)" fill="url(#hatch)" />

      <g
        v-for="item in rays"
        :key="item.ray.id"
        :class="['ray', item.ray.state, { reaches: item.ray.reaches, dimmed: hovered && hovered !== item.ray.id }]"
        :style="{ '--delay': `${item.delay}ms` }"
      >
        <!-- pathLength rescales dashes too, so it is only set on rays drawn as solid lines. -->
        <polyline :points="item.points" :pathLength="item.ray.state === 'unproved' ? undefined : 1" />
        <polyline
          class="hit"
          :points="item.points"
          tabindex="0"
          role="button"
          :aria-label="describeRay(item.ray)"
          @mouseenter="hovered = item.ray.id"
          @mouseleave="hovered = null"
          @focus="hovered = item.ray.id"
          @blur="hovered = null"
          @click="emit('select', item.ray)"
          @keydown.enter="emit('select', item.ray)"
        />
        <circle v-if="item.end" class="impact" :cx="item.end.x" :cy="item.end.y" r="2.5" />
        <text :x="item.start.x" :y="item.start.y - 8">
          <tspan class="ray-name">{{ item.ray.label }}</tspan>
          <tspan class="ray-port" dx="6">{{ item.ray.port }}</tspan>
        </text>
      </g>

      <g v-for="item in sideRays" :key="item.ray.id" class="ray side unproved reaches">
        <polyline :points="item.points" />
        <text :x="item.start.x - 10" :y="item.start.y + 4" text-anchor="end">
          <tspan class="ray-name">{{ item.ray.label }}</tspan>
        </text>
      </g>

      <g :class="['focus', { lit: bench.focused }]">
        <circle class="halo" :cx="focus.x" :cy="focus.y" :r="compact ? 11 : 15" />
        <circle class="point" :cx="focus.x" :cy="focus.y" r="3.5" />
      </g>

      <text class="focus-label" :x="width" :y="focus.y + (compact ? -20 : 34)" text-anchor="end">Full control</text>

      <g v-for="caption in captions" :key="caption.title" class="caption" text-anchor="middle">
        <text :x="place(caption.t, 0).x" :y="height - 26" class="caption-title">{{ caption.title }}</text>
        <text :x="place(caption.t, 0).x" :y="height - 9" class="caption-text">{{ caption.text }}</text>
      </g>
    </svg>
    <figcaption aria-live="polite">{{ note }}</figcaption>
  </figure>
</template>
