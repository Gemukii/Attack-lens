import type { FieldTone } from '~/utils/ascii'
import { RAMP, hash } from '~/utils/ascii'
import type { Bench, Ray } from '~/utils/bench'
import { isProvedWay } from '~/utils/bench'

// The optical bench as a field of characters: the one image of the interface.
//
// It is data, not decoration. Every glyph comes from the bench: rays, firewall, lenses and
// focus. Red only appears on a ray that is proved from outside and reaches full control,
// and on the light it gathers. No text ever sits on a glyph: the cells under every label
// are blanked.
//
// The field is built once (buildGlyphField), then drawn for a moment in time
// (renderGlyphLines). Its motion means something: light travels along a ray in the
// direction an attacker would, stops where the ray stops, and gathers on the focus only
// when something reaches it. Without a moment, the picture is still.

// Size of a cell in px at 11px with a line-height of 1.1, used for geometry only.
const CW = 6.6
const CH = 12.1

// How long a pulse of light is, and the dark stretch that follows it, in px.
const PULSE_LENGTH = 70
const PULSE_GAP = 520

export interface FieldRun {
  tone: FieldTone | ''
  text: string
}

export interface FieldLabel {
  kind: 'ray' | 'focus' | 'side' | 'caption' | 'state'
  row: number
  col: number
  align: 'start' | 'center' | 'end'
  text: string
  port?: number | null
  ray?: Ray
  alert?: boolean
}

// What a cell is made of. `owner` is the ray it belongs to, `along` how far it lies on
// that ray, `core` how close to the heart of the focus it is.
interface FieldCells {
  value: Float32Array[]
  hot: Uint8Array[]
  fixed: string[][]
  owner: Int16Array[]
  along: Float32Array[]
  core: Float32Array[]
}

export interface GlyphField {
  cols: number
  rows: number
  // The still picture.
  lines: FieldRun[][]
  labels: FieldLabel[]
  hotCells: number
  summary: string
  // Width of the picture in px, to turn a duration into a speed.
  width: number
  // The ray of each owner index, for highlighting.
  owners: string[]
  cells: FieldCells
}

// A moment of the field.
export interface FieldMoment {
  // Seconds since the field started.
  time?: number
  // Px per second of the light.
  speed?: number
  // The ray under the pointer: the others step back.
  highlight?: string | null
  // From 0 to 1 while the picture develops, left to right.
  reveal?: number
}

type Point = [number, number]

// Distance in px from a point to a polyline, and how far along it the closest point lies.
const nearest = (px: number, py: number, points: Point[]) => {
  let best = Infinity
  let along = 0
  let walked = 0
  for (let index = 0; index < points.length - 1; index += 1) {
    const [ax, ay] = points[index]!
    const [bx, by] = points[index + 1]!
    const length = Math.hypot(bx - ax, by - ay) || 1
    const t = Math.max(0, Math.min(1, ((px - ax) * (bx - ax) + (py - ay) * (by - ay)) / (length * length)))
    const distance = Math.hypot(px - (ax + t * (bx - ax)), py - (ay + t * (by - ay)))
    if (distance < best) {
      best = distance
      along = walked + t * length
    }
    walked += length
  }
  return { distance: best, along }
}

const toneOf = (value: number, hot: boolean): FieldTone | '' => {
  if (value < 0.06) return ''
  if (hot) return value < 0.3 ? 'field-hot-1' : value < 0.62 ? 'field-hot-2' : 'field-hot-3'
  return value < 0.2 ? 'field-1' : value < 0.45 ? 'field-2' : value < 0.7 ? 'field-3' : 'field-4'
}

const rampGlyph = (value: number) => RAMP[Math.min(RAMP.length - 1, Math.max(1, Math.round(value * (RAMP.length - 1))))]!

// Draws the field for one moment. With no moment, it draws the still picture.
export const renderGlyphLines = (field: Pick<GlyphField, 'cols' | 'rows' | 'cells' | 'owners'>, moment: FieldMoment = {}): FieldRun[][] => {
  const { value, hot, fixed, owner, along, core } = field.cells
  const moving = moment.time !== undefined && moment.speed !== undefined
  const travelled = moving ? moment.time! * moment.speed! : 0
  const lit = moment.highlight ? field.owners.indexOf(moment.highlight) : -1
  const edge = moment.reveal === undefined ? Infinity : moment.reveal * field.cols
  const breath = moving ? 0.86 + 0.14 * Math.sin(moment.time! * 2.2) : 1

  const lines: FieldRun[][] = []
  for (let r = 0; r < field.rows; r += 1) {
    const line: FieldRun[] = []
    for (let c = 0; c < field.cols; c += 1) {
      let v = value[r]![c]!
      let glyph = fixed[r]![c]!
      const who = owner[r]![c]!

      if (c > edge) v = 0
      else {
        // The ray under the pointer stays, the others step back.
        if (lit >= 0 && who >= 0 && who !== lit) v *= 0.4
        // Light travels along the ray, each ray out of step with its neighbours.
        if (moving && who >= 0 && v > 0) {
          const offset = ((travelled + who * 190 - along[r]![c]!) % (PULSE_LENGTH + PULSE_GAP) + PULSE_LENGTH + PULSE_GAP) % (PULSE_LENGTH + PULSE_GAP)
          if (offset < PULSE_LENGTH) {
            const boost = Math.sin((offset / PULSE_LENGTH) * Math.PI)
            v = Math.min(1, v + boost * 0.4)
            if (boost > 0.35) glyph = ''
          }
        }
        // The focus breathes when something reaches it.
        if (moving && core[r]![c]! > 0) v *= 1 - core[r]![c]! * (1 - breath)
      }

      const tone = toneOf(v, hot[r]![c] === 1)
      const text = tone ? glyph || rampGlyph(v) : ' '
      const last = line.at(-1)
      if (last && last.tone === tone) last.text += text
      else line.push({ tone, text })
    }
    lines.push(line)
  }
  return lines
}

export const buildGlyphField = (bench: Bench, cols: number, compact = false): GlyphField => {
  const stopped = bench.rays.filter((ray) => ray.state === 'stopped')
  const passing = bench.rays.filter((ray) => ray.state !== 'stopped')
  const above = stopped.filter((_, index) => index % 2 === 0).reverse()
  const below = stopped.filter((_, index) => index % 2 === 1)

  // Rows. A blocked ray is a thin line under its label. A ray proved from outside is a
  // band of light three rows high. Without blocked rays above, room is left for the blade.
  let row = above.length ? 1 : 3
  const rayRow = new Map<string, number>()
  const labels: FieldLabel[] = []
  const place = (ray: Ray, offset: number, span: number) => {
    labels.push({ kind: 'ray', row, col: 0, align: 'start', text: ray.label, port: ray.port, ray })
    rayRow.set(ray.id, row + offset)
    row += span
  }
  above.forEach((ray) => place(ray, 1, 2))
  if (above.length) row += 1
  passing.forEach((ray) => (ray.state === 'proved' ? place(ray, 2, 4) : place(ray, 1, 3)))
  below.forEach((ray) => place(ray, 1, 2))

  const passRows = passing.map((ray) => rayRow.get(ray.id)!)
  const axis = passRows.length ? (passRows[0]! + passRows.at(-1)!) / 2 : Math.max(5, row / 2)
  const lensHalf = passRows.length ? (passRows.at(-1)! - passRows[0]!) / 2 + 3 : 3
  const openTop = passRows.length ? passRows[0]! - 2.5 : axis - 1.5
  const openBottom = passRows.length ? passRows.at(-1)! + 1.5 : axis + 1.5
  let bottom = Math.ceil(Math.max(row, axis + lensHalf + 1, 2 * axis))

  const x = {
    stop: Math.round(cols * 0.26),
    service: Math.round(cols * 0.48),
    account: Math.round(cols * 0.7),
    focus: Math.round(cols * (compact ? 0.86 : 0.91)),
  }
  const sides = bench.side.map((ray, index) => {
    bottom += 2
    return { ray, row: bottom - 1, col: Math.round(cols * (0.6 + index * 0.05)) }
  })
  // Two lines of captions under the picture, with air between them.
  const captionRow = bottom + 1
  const stateRow = captionRow + 1.5
  const rows = captionRow + 3

  const cells: FieldCells = {
    value: Array.from({ length: rows }, () => new Float32Array(cols)),
    hot: Array.from({ length: rows }, () => new Uint8Array(cols)),
    fixed: Array.from({ length: rows }, () => new Array<string>(cols).fill('')),
    owner: Array.from({ length: rows }, () => new Int16Array(cols).fill(-1)),
    along: Array.from({ length: rows }, () => new Float32Array(cols)),
    core: Array.from({ length: rows }, () => new Float32Array(cols)),
  }
  const owners = [...bench.rays.map((ray) => ray.id), ...bench.side.map((ray) => ray.id)]

  // The brightest thing wins a cell. `who` and `far` say which ray it is and how far along.
  const put = (r: number, c: number, v: number, isHot = false, glyph = '', who = -1, far = 0) => {
    if (r < 0 || r >= rows || c < 0 || c >= cols || v < cells.value[r]![c]!) return
    cells.value[r]![c] = v
    cells.fixed[r]![c] = glyph
    cells.hot[r]![c] = isHot ? 1 : 0
    cells.owner[r]![c] = who
    cells.along[r]![c] = far
  }

  // Grain, right of the firewall only: the empty left side is where the labels live.
  for (let r = 0; r < bottom; r += 1) {
    for (let c = x.stop + 3; c < cols; c += 1) if (hash(c, r) > 0.988) put(r, c, 0.09)
  }

  // The optical axis.
  if (Number.isInteger(axis)) for (let c = x.stop + 2; c < cols; c += 4) put(axis, c, 0.1, false, '·')

  // The firewall: two hatched blades, with an opening for what gets through.
  const known = ['enabled', 'partial', 'disabled'].includes(bench.firewall)
  const on = ['enabled', 'partial'].includes(bench.firewall)
  const bladeTop = Math.min(above.length ? rayRow.get(above[0]!.id)! - 1 : Infinity, Math.floor(openTop) - 2)
  const bladeBottom = Math.max(below.length ? rayRow.get(below.at(-1)!.id)! + 1 : -Infinity, Math.ceil(openBottom) + 2)
  for (let r = Math.max(0, bladeTop); r <= bladeBottom; r += 1) {
    if (r > openTop && r < openBottom) continue
    for (let c = x.stop; c < x.stop + (compact ? 2 : 3); c += 1) {
      if (!known) put(r, c, r % 2 ? 0.3 : 0, false, ':')
      else if (on) put(r, c, 0.66, false, (r + c) % 2 ? '#' : '%')
      else put(r, c, 0.22, false, '.')
    }
  }

  // Lenses: shaded glass inside a brighter rim. A dotted rim when the state is not known.
  const lens = (cx: number, half: number, state: 'solid' | 'faint' | 'unknown') => {
    const hpx = half * CH
    const wpx = Math.max(compact ? 14 : 22, hpx * 0.26)
    for (let r = Math.floor(axis - half) - 1; r <= Math.ceil(axis + half) + 1; r += 1) {
      for (let c = cx - 7; c <= cx + 7; c += 1) {
        const d = Math.hypot(((c - cx) * CW) / wpx, ((r - axis) * CH) / hpx)
        const rim = Math.abs(d - 1) < 0.16
        if (state === 'solid') {
          if (d < 1) put(r, c, 0.14 + 0.3 * (1 - d * d) * (0.8 - (((c - cx) * CW) / wpx) * 0.35))
          if (rim) put(r, c, 0.56)
        } else if (rim && (state === 'faint' || (r + c) % 2 === 0)) {
          put(r, c, state === 'faint' ? 0.34 : 0.26, false, state === 'faint' ? '' : ':')
        }
      }
    }
  }
  lens(x.service, lensHalf, 'solid')
  lens(x.account, lensHalf * 0.62, bench.admin === true ? 'solid' : bench.admin === false ? 'faint' : 'unknown')

  // Rays: a bright core and a soft edge. Each cell remembers its ray and how far along it is.
  const at = (c: number, r: number): Point => [c * CW, r * CH]
  const beam = (points: Point[], from: number, to: number, strength: number, hotRay: boolean, dashed: boolean, who: number, start: number) => {
    const rMin = Math.floor(Math.min(...points.map((p) => p[1])) / CH) - 2
    const rMax = Math.ceil(Math.max(...points.map((p) => p[1])) / CH) + 2
    for (let r = rMin; r <= rMax; r += 1) {
      for (let c = from; c <= to; c += 1) {
        const { distance, along } = nearest(c * CW, r * CH, points)
        if (dashed && Math.floor(along / 20) % 3 === 2) continue
        if (distance < 4.2) put(r, c, strength * (1 - distance / 14), hotRay, '', who, start + along)
        else if (!dashed && distance < 17) put(r, c, (hotRay ? 0.42 : 0.26) * (1 - distance / 17), hotRay, '', who, start + along)
      }
    }
  }
  bench.rays.forEach((ray, who) => {
    const r = rayRow.get(ray.id)!
    if (ray.state === 'stopped') {
      for (let c = 0; c < x.stop - 1; c += 1) put(r, c, 0.36, false, '-', who, c * CW)
      put(r, x.stop - 1, 0.6, false, '+', who, (x.stop - 1) * CW)
      return
    }
    const proved = ray.state === 'proved'
    const way = isProvedWay(ray)
    for (let c = 0; c <= x.service; c += 1) {
      if (!proved && c % 6 > 3) continue
      put(r, c, way ? 0.92 : proved ? 0.72 : 0.5, way, way ? '#' : proved ? '=' : '-', who, c * CW)
      if (proved) {
        put(r - 1, c, way ? 0.3 : 0.2, way, (c + r) % 2 ? ':' : '·', who, c * CW)
        put(r + 1, c, way ? 0.3 : 0.2, way, (c + r) % 2 ? '·' : ':', who, c * CW)
      }
    }
    if (ray.reaches) {
      beam([at(x.service, r), at(x.account, axis + (r - axis) * 0.5), at(x.focus, axis)], x.service + 1, x.focus, way ? 0.95 : 0.62, way, !proved, who, x.service * CW)
    } else {
      const end = x.service + Math.round(cols * 0.07)
      beam([at(x.service, r), at(end, axis + (r - axis) * 0.84)], x.service + 1, end, 0.5, false, !proved, who, x.service * CW)
      put(Math.round(axis + (r - axis) * 0.84), end + 1, 0.5, false, 'o')
    }
  })
  sides.forEach((side, index) => {
    beam([at(side.col + 1, side.row), at(x.account, axis + lensHalf * 0.4), at(x.focus, axis)], side.col + 1, x.focus, 0.74, false, true, bench.rays.length + index, 0)
  })

  // Light gathering between the lens and the focus, only for what really reaches it.
  const hotRows = bench.rays.filter(isProvedWay).map((ray) => rayRow.get(ray.id)!)
  if (hotRows.length) {
    const spread = Math.max(...hotRows.map((r) => Math.abs(r - axis)))
    for (let c = x.service + 1; c < x.focus; c += 1) {
      const share = (c - x.service) / (x.focus - x.service)
      const reach = share < 0.5 ? spread * (1 - share) : spread * 0.5 * (1 - (share - 0.5) * 2) + 0.4
      for (let r = Math.floor(axis - reach); r <= Math.ceil(axis + reach); r += 1) {
        if (Math.abs(r - axis) <= reach) put(r, c, 0.14 + 0.34 * share * share, true)
      }
    }
  }

  // The focus: full control of the machine.
  const focusHot = hotRows.length > 0
  for (let r = Math.floor(axis) - 5; r <= Math.ceil(axis) + 5; r += 1) {
    for (let c = x.focus - 7; c <= Math.min(cols - 1, x.focus + 7); c += 1) {
      const d = Math.hypot((c - x.focus) * CW, (r - axis) * CH)
      if (bench.focused) {
        if (d < 11) put(r, c, 1, focusHot, '@')
        else if (d < 21) put(r, c, 0.86, focusHot)
        else if (d < 33) put(r, c, 0.5 * (1 - (d - 21) / 16), focusHot)
        // The halo breathes more than the heart.
        if (d < 33 && r >= 0 && r < rows && c >= 0) cells.core[r]![c] = Math.min(1, d / 33)
      } else if (d < 8) put(r, c, 0.5, false, 'o')
      else if (Math.abs(d - 30) < 3.5 && (r + c) % 2) put(r, c, 0.2, false, '·')
    }
  }

  // Text never sits on a glyph: blank what lies under every label.
  const focusRow = Math.round(axis) + 5
  const clear = (r: number, from: number, to: number) => {
    if (r < 0 || r >= rows) return
    for (let c = Math.max(0, from); c < Math.min(cols, to); c += 1) {
      cells.value[r]![c] = 0
      cells.fixed[r]![c] = ''
      cells.owner[r]![c] = -1
      cells.core[r]![c] = 0
    }
  }
  for (const label of labels) clear(label.row, 0, label.text.length + String(label.port ?? '').length + 6)
  clear(focusRow, x.focus - 12, cols)
  for (const side of sides) clear(side.row, side.col - 18, side.col + 1)
  for (let r = captionRow; r < rows; r += 1) clear(r, 0, cols)

  const accountText = bench.admin === null ? 'Not measured' : bench.admin ? (compact ? 'Admin' : 'Administrator') : 'Standard user'
  labels.push(
    { kind: 'focus', row: focusRow, col: cols, align: 'end', text: 'Full control' },
    ...sides.map((side): FieldLabel => ({ kind: 'side', row: side.row, col: side.col - 1, align: 'end', text: side.ray.label })),
    { kind: 'caption', row: captionRow, col: x.stop, align: 'center', text: 'Firewall' },
    { kind: 'state', row: stateRow, col: x.stop, align: 'center', text: known ? (on ? 'On' : 'Off') : 'Not measured', alert: known && !on },
    { kind: 'caption', row: captionRow, col: x.service, align: 'center', text: 'Services' },
    { kind: 'state', row: stateRow, col: x.service, align: 'center', text: bench.services === null ? 'Not read yet' : `${bench.rays.length} drawn` },
    { kind: 'caption', row: captionRow, col: x.account, align: 'center', text: compact ? 'Account' : 'Your account' },
    { kind: 'state', row: stateRow, col: x.account, align: 'center', text: accountText },
  )

  const still = { cols, rows, cells, owners }
  const lines = renderGlyphLines(still)
  const hotCells = lines.flat().filter((run) => run.tone.startsWith('field-hot')).reduce((sum, run) => sum + run.text.length, 0)

  const ways = bench.rays.filter(isProvedWay).length
  const summary = `${bench.rays.length} services drawn as rays of light. ${
    ways ? `${ways} ${ways === 1 ? 'is' : 'are'} proved from outside and ${ways === 1 ? 'reaches' : 'reach'} full control of the machine.`
      : bench.focused ? 'Some could reach full control of the machine, none is proved.'
        : 'None reaches full control of the machine.'}`

  return { cols, rows, lines, labels, hotCells, summary, width: cols * CW, owners, cells }
}
