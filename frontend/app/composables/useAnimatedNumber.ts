// Counts towards a value, unless the visitor asked for reduced motion.
export const useAnimatedNumber = (source: Ref<number | null>, duration = 1100) => {
  const value = ref(0)
  let frame = 0

  const run = (to: number) => {
    cancelAnimationFrame(frame)
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
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
  }

  onMounted(() => {
    watch(source, (to) => {
      if (to !== null) run(to)
    }, { immediate: true })
  })
  onBeforeUnmount(() => cancelAnimationFrame(frame))

  return value
}
