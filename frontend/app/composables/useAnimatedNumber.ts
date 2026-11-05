// Counts towards a value, unless the visitor asked for reduced motion. A hidden page gets
// no animation frames, so it takes the value at once: the display must never stay wrong.
export const useAnimatedNumber = (source: Ref<number | null>, duration = 1100) => {
  const value = ref(0)
  let frame = 0
  let fallback: ReturnType<typeof setTimeout> | undefined

  const run = (to: number) => {
    cancelAnimationFrame(frame)
    clearTimeout(fallback)
    if (document.hidden || window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      value.value = to
      return
    }
    const from = value.value
    const startedAt = performance.now()
    const step = (now: number) => {
      const progress = Math.min(1, (now - startedAt) / duration)
      const eased = 1 - (1 - progress) ** 4
      value.value = Math.round(from + (to - from) * eased)
      if (progress < 1) frame = requestAnimationFrame(step)
    }
    frame = requestAnimationFrame(step)
    // Frames stop if the page gets hidden mid-count: land on the value regardless.
    fallback = setTimeout(() => {
      cancelAnimationFrame(frame)
      value.value = to
    }, duration + 200)
  }

  onMounted(() => {
    watch(source, (to) => {
      if (to !== null) run(to)
    }, { immediate: true })
  })
  onBeforeUnmount(() => {
    cancelAnimationFrame(frame)
    clearTimeout(fallback)
  })

  return value
}
