import type { Ref, WatchSource } from 'vue'

// An indicator that slides from one option to the next: the underline of the views and of
// the tabs, the thumb of the period control. It is one element as wide as its container,
// moved and scaled with a transform, so that nothing is laid out again when it moves.
//
// Until it has been measured in the browser, `ready` stays false and the options keep their
// own static mark: the server render and a browser without layout are never left bare.
export const useIndicator = (container: Ref<HTMLElement | null>, selector: string, active: WatchSource) => {
  const style = ref<Record<string, string>>({})
  const ready = ref(false)
  let resizer: ResizeObserver | undefined
  let watched: HTMLElement | null = null
  let frame = 0

  const measure = () => {
    const box = container.value
    const target = box?.querySelector<HTMLElement>(selector)
    if (!box || !target || !box.clientWidth || !target.offsetWidth) return false
    style.value = { transform: `translateX(${target.offsetLeft}px) scaleX(${target.offsetWidth / box.clientWidth})` }
    return true
  }

  // Places the indicator. The first placement is not a move: the transition only starts
  // one frame later. The container may appear after the page, once its data is there.
  const sync = () => {
    if (typeof window === 'undefined' || !measure()) return
    if (!ready.value) frame = requestAnimationFrame(() => (ready.value = true))
    if (container.value && container.value !== watched) {
      resizer?.disconnect()
      resizer = new ResizeObserver(() => measure())
      resizer.observe(container.value)
      watched = container.value
    }
  }

  onMounted(async () => {
    await document.fonts?.ready
    sync()
  })

  watch([container, active], () => nextTick(sync))

  onBeforeUnmount(() => {
    cancelAnimationFrame(frame)
    resizer?.disconnect()
  })

  return { style, ready }
}
