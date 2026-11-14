# Design tokens

The foundations of the interface, as decided in [ADR-0018](../adr/0018-instrument-interface.md).
The source of truth is the code: `frontend/app/assets/css/tokens/`. This page says what is there,
why, and how to check that nothing bypasses it.

## Files

| File | Holds |
| --- | --- |
| `tokens/primitives.css` | Level 1, global: the colour ramps. The only place where a colour value is written |
| `tokens/semantic.css` | Level 2, alias: what a colour does. The only colour vocabulary of components |
| `tokens/components.css` | Level 3, component: one decision about one component |
| `tokens/typography.css` | Families, sizes, weights, leading, tracking, and the named styles |
| `tokens/fonts.css` | The `@font-face` rules of the bundled typefaces |
| `tokens/spacing.css` | Spacing scale, grid, sizes of controls and rows, rule width, radius |
| `tokens/motion.css` | Durations, curves, keyframes, view transitions, reduced motion |
| `base.css` | Reset, page shell, grid, text helpers, controls, shared motion |
| `frame.css` | Top bar, reading line, notices, footer |
| `brief.css` | Verdict, first action, the glyph field, figures |
| `lists.css` | Severity, tabs, findings, ports, journal, score trend |
| `drawer.css` | The finding drawer |
| `states.css` | Skeletons, login and error pages |

They are loaded in that order by `nuxt.config.ts`.

`main.css` is gone since step 4: its 1790 lines became the six files above, 871 lines in all.

## Colour

Direction D, "Glyph field": near-black with a trace of warmth, and one colour.

### Level 1, global

Ramps are built in HSL around a base: about ten points of lightness per step, more saturation away
from 50 % lightness, a slight shift of hue. Only the steps with a role are shipped. The full ramps,
with the steps that were built and not shipped, are in `directions/tokens.md`, section D.

| Token | HSL | Hex | Role |
| --- | --- | --- | --- |
| `--neutral-50` | hsl(36 12% 94%) | `#f2f0ee` | Primary text, brightest glyphs |
| `--neutral-200` | hsl(34 8% 74%) | `#c2bdb7` | Secondary text |
| `--neutral-400` | hsl(32 6% 58%) | `#9a948d` | Muted text, labels |
| `--neutral-500` | hsl(30 6% 34%) | `#5c5751` | Strong rule, dim marks |
| `--neutral-600` | hsl(30 7% 19%) | `#34302d` | Subtle rule |
| `--neutral-700` | hsl(30 8% 11%) | `#1e1c1a` | Hovered row, drawer |
| `--neutral-800` | hsl(30 9% 7%) | `#131210` | Raised surface |
| `--neutral-900` | hsl(30 10% 4%) | `#0b0a09` | Page background |
| `--red-400` | hsl(10 86% 65%) | `#f37359` | Accent as text |
| `--red-500` | hsl(8 84% 56%) | `#ed4a31` | Accent as a mark. The base colour |
| `--red-600` | hsl(6 78% 47%) | `#d52d1a` | Mid hot glyphs |
| `--red-800` | hsl(2 70% 27%) | `#751815` | Dim hot glyphs |

Eight greys, each with one role. Their saturation is 6 to 12 %, lower in the middle of the ramp than
the 8 to 20 % of the method: more warmth turned the black brown.

### Level 2, alias

| Alias | Points at | Use |
| --- | --- | --- |
| `--bg-base` | `neutral-900` | Page |
| `--bg-elevated` | `neutral-800` | Panels, the agent strip |
| `--bg-overlay` | `neutral-700` | Hovered row, skeleton |
| `--bg-active` | Half `neutral-600`, half `neutral-700` | A surface under the finger, a fact just replaced. Muted text on it measures 5.0 |
| `--bg-critical` | 14 % of `red-500` over `neutral-900` | Critical row, a line that just arrived |
| `--bg-scrim` | 72 % of `neutral-900` | Behind the drawer |
| `--fg-primary` | `neutral-50` | Text |
| `--fg-secondary` | `neutral-200` | Secondary text |
| `--fg-muted` | `neutral-400` | Labels, units, what was not measured |
| `--fg-inverted` | `neutral-900` | Text on the primary button |
| `--border-subtle` | `neutral-600` | Rules between rows and blocks |
| `--border-strong` | `neutral-500` | Borders of controls, dim marks |
| `--accent` | `red-500` | A mark: dot, bar, ray |
| `--accent-fg` | `red-400` | The same meaning as text |
| `--severity-critical` | `red-500` | |
| `--severity-high` | `neutral-50` | |
| `--severity-medium` | `neutral-200` | |
| `--severity-low` | `neutral-400` | |
| `--field-1` to `--field-4` | `neutral-500`, `400`, `200`, `50` | The glyph field, from dim to bright |
| `--field-hot-1` to `--field-hot-3` | `red-800`, `600`, `500` | The glyph field, where a ray reaches full control |
| `--shadow-floating` | | The drawer only |

The accent has one meaning on every screen: a proved way to full control, or a critical or exploited
finding. It is never an action and never a decoration. Severity is an intensity, and red only at the
top.

There is one theme. A dark room is what the glyph field needs, and a light counterpart was not asked
for. The structure allows one: a second block that rewires the aliases, with no change to a
component.

### Level 3, component

Named `category-property-element-variant-state`.

| Token | Points at |
| --- | --- |
| `--color-outline-focus` | `fg-primary`. Focus is neutral: the accent reports a threat, not where the keyboard is |
| `--color-bg-button-primary`, `-hover`, `--color-fg-button-primary` | `fg-primary`, `fg-secondary`, `fg-inverted`. Never the accent |
| `--color-bg-row-hover`, `-pressed`, `-critical`, `-new` | `bg-overlay`, `bg-active`, `bg-critical`, `bg-critical` |
| `--color-bg-button-pressed`, `--color-bg-button-primary-pressed` | `bg-overlay`, `fg-muted` |
| `--color-bg-indicator`, `-segment` | `fg-primary`, `fg-secondary` |
| `--color-bg-reading-changed` | `bg-active` |
| `--color-fg-kpi-delta`, `-alert` | `fg-muted`, `accent-fg` |
| `--color-bg-skeleton` | `bg-overlay` |
| `--color-bg-lamp-online`, `-offline` | `fg-primary`, `accent` |
| `--color-stroke-bench-line`, `-ray`, `-ray-stopped`, `-ray-reaches` | `border-strong`, `fg-secondary`, `border-strong`, `accent` |

### Contrast

Measured by script on the running application, in demo mode: every text node, its colour against the
first opaque background behind it, at 1440 and 390 px, on the four views and in four scenarios.

| | Before | After |
| --- | --- | --- |
| Text nodes measured | | 933 |
| Lowest ratio | 4.47 (muted text on a hovered row) | 5.66 (the same case) |
| Under AA (4.5) | 1 pair | none |

Details: `step3/after/contrast-rendered.json`. Disabled controls are left out, as WCAG does.

## Typography

IBM Plex Sans for reading, IBM Plex Mono for raw data and for the glyph field. Two weights, 400 and
500. Tabular figures everywhere. The four files are in `frontend/app/assets/fonts/` with their
licence (SIL OFL 1.1), declared in `tokens/fonts.css` and preloaded by `app.vue`. Nothing is fetched
from a third party.

| Style | Class | Size | Weight | Leading | Use |
| --- | --- | --- | --- | --- | --- |
| display | `.t-display` | 136 px (104 on a phone) | 500 | 0.9 | The main figure |
| heading-l | `.t-heading-l` | 30 px (26 on a phone) | 500 | 1.2 | The verdict, page titles |
| heading-m | `.t-heading-m` | 19 px | 500 | 1.2 | The first thing to fix, drawer title |
| data-l | `.t-data-l` | 24 px | 500 | 1.2 | Secondary figures |
| body-m | `.t-body-m` | 14 px | 400 | 1.5 | Text |
| body-s | `.t-body-s` | 13 px | 400 | 1.5 | Rows, secondary text |
| data | `.t-data` | 13 px mono | 400 | 1.4 | Ports, addresses, commands, timestamps |
| label | `.t-label` | 11 px, uppercase, tracked 0.08 em | 500 | 1.4 | Section and column labels |

Two departures from the brief, on purpose:

- **`data-l` is an eighth style.** Secondary figures need a size between a heading and body text.
- **The display leading is 0.9**, under the 1.1 to 1.2 asked for. It is one line of figures, and a
  tight leading keeps the note attached to its number.

The existing component classes already take their sizes from these tokens. They are replaced by the
`.t-*` classes as each component is rewritten in step 4.

## Spacing and sizes

| Token | Value | | Token | Value |
| --- | --- | --- | --- | --- |
| `--space-half` | 2 px | | `--space-6` | 24 px |
| `--space-1` | 4 px | | `--space-7` | 28 px |
| `--space-2` | 8 px | | `--space-8` | 32 px |
| `--space-3` | 12 px | | `--space-10` | 40 px |
| `--space-4` | 16 px | | `--space-11` | 44 px |
| `--space-5` | 20 px | | `--space-12` | 48 px |

Grid: 12 columns in a container of `--size-container` (1440 px) at most, `--gutter` 24 px, 16 px on a
phone. Beyond 1440 px only the margins grow.

Sizes: `--size-target` 24 px (the smallest thing a finger or a pointer has to hit), `--size-control` 32 px, `--size-control-s` 28 px, `--size-row` 36 px, `--size-row-head` 32 px,
`--size-topbar` 56 px, `--border-width` 1 px, `--radius` 2 px.

Every margin, padding and gap of the stylesheets is a step of the scale. Values that were off the
scale were moved to the next step: 6 to 8, 10 to 12, 14 to 16, 18 to 20. Rows are 2 to 4 px taller
than before as a result.

What is still written in pixels in the stylesheets: the width or height of a specific element (a grid
column, the drawer, a skeleton block) and the stroke widths of the bench drawing. These are
dimensions of one object, not spacing.

## Motion

| Token | Value | Use |
| --- | --- | --- |
| `--dur-fast` | 120 ms | Hover, focus, colour |
| `--dur-base` | 200 ms | Appearing, the drawer, content replacing a skeleton |
| `--dur-slow` | 320 ms | Change of view, rows finding their place |
| `--ease-out` | cubic-bezier(.2, .8, .2, 1) | Entrances |
| `--ease-in-out` | cubic-bezier(.4, 0, .2, 1) | Moves |
| `--dur-flash` | 1.5 s | The tint of a value that changed significantly, fading out |
| `--dur-tint` | 2 s | The tint of a line that just arrived, fading out |
| `--dur-pulse` | 2 s | The agent lamp and the scan in progress |
| `--dur-flow` | 3.6 s | Light crossing the glyph field; a swell crossing the login page |
| `--dur-stagger` | 20 ms | Between two rows, two columns or two blocks of the drawer arriving one after the other |
| `--motion-distance` | 8 px | How far the drawer and a view travel while they fade |
| `--opacity-bench-scanning` | 0.4 | The field while a scan runs. Its labels keep full opacity |

What is in place:

| Moment | Treatment | Checked |
| --- | --- | --- |
| Change of view | `document.startViewTransition`. The old view leaves in `--dur-fast`, the new one settles in `--dur-slow`, both travelling `--motion-distance` the way one is going (`--nav-direction`, set by the page). The top bar and the reading line keep their place. Falls back to an instant change | `view-out` 120 ms and `view-in` 320 ms observed; direction 1 forwards, -1 back |
| Current view, tab, period | One indicator per control slides to the current option in `--dur-base`: a transform on a single element (`useIndicator`). Static mark until measured | Indicator matches the current option to the pixel after each change, at 1440 and 390 |
| Pointing at an action or a ray | The ray of the action lights on the bench; the action of the ray takes the hover surface. Titles take a rule in `--dur-fast` | One ray linked for "Fix first"; one action linked for its ray |
| Pressing | One step of surface: `--color-bg-button-pressed`, `--color-bg-button-primary-pressed`, `--color-bg-row-pressed`. No movement | |
| Copy, Scan | Both labels share one cell and cross-fade in `--dur-fast`; the button keeps one width | Width unchanged; clipboard holds the command |
| Scan in progress, on the brief | The verdict stays; "Taking a reading" appears beside its label; the field fades to `--opacity-bench-scanning` in `--dur-slow` and develops again at the end | Layout shift 0 through a scan |
| Verdict that changes | The old one fades out in `--dur-fast`, the new one rises in `--dur-base` | |
| Reading line | A replaced fact fades in again in `--dur-slow`, under a neutral tint that fades out in `--dur-flash` | "Read" and "Probe" marked after a scan; nothing marked when only the clock moved |
| Drawer | Opacity and an 8 px translation in `--dur-base`; its blocks rise one after the other, `--dur-stagger` apart, 320 ms in all | `opacity` and `transform`, 200 ms; delays 0 to 120 ms |
| A new line in the journal | Fades in, under a tint whose opacity fades out in `--dur-tint`. The tint used to animate a background colour | |
| Skeleton to content | The content fades in, in `--dur-base`. The skeleton no longer pulses | |
| Scan in progress | One dot that breathes, in place of a character spinner driven by a timer | |
| Hover and focus | Colour, background colour and border colour in `--dur-fast`. Never a size or a position | |
| The glyph field | Light travels along each ray and gathers on the focus; the ray under the pointer stands out. Painted on a canvas at 12 frames per second, paused out of sight | Moving; no frame over 17.4 ms; layout shift 0.0001 |
| First display | The field develops from the left in `--dur-slow`, painted on every frame; rows arrive one after the other in under 300 ms; score columns grow from their base | 19 repaints in 400 ms, then 12 per second; no frame over 34 ms |
| Login and error pages | Slow waves drift across the field | Moving; no frame over 17.1 ms |
| Reduced motion | Every animation and transition lasts 1 ms, view transitions included. The field and the waves are still | No animation running, no view transition started, both fields unchanged over time |

Only `opacity` and `transform` move in the page. Colour transitions on hover and under the finger
(text, background, border and the rule under a title) are the one exception, as the brief allows. The field is not a CSS animation: it is drawn frame by frame, from the data.

Scripts do not carry durations: `utils/motion.ts` reads them from the tokens.

## Layout stability

Measured on load, in demo mode (`step3/before` and `step3/after`, `measurements.json`).

| Scenario | Before | After |
| --- | --- | --- |
| Agent online, 1440 px | 0.0745 | 0.0001 |
| Agent online, 390 px | 0.1228 | 0 |
| No agent, 1440 px | 0.0625 | 0.0001 |
| No agent, 390 px | 0.0321 | 0 |

The audit had measured 0.03 on a nearly empty database. With real data it was up to 0.12. Four
causes, all removed:

1. The server rendered the empty state, then the browser replaced it by the skeleton, then by the
   data. The skeleton is now what the server renders, until the first answer.
2. The strip about the agent appeared or disappeared once the agent state was known. It is now always
   there, at a constant height.
3. The skeleton did not have the shape of the content. It now has the same boxes: figure, sentence,
   three figures, the bench, two columns.
4. The footer slid down as the page filled. It is shown once the first answer is in.

The remaining 0.0001 at 1440 px is under the smallest shift the browser reports individually.

## Checking that nothing bypasses the tokens

Run from `frontend/`. Each search must return nothing, apart from the exceptions listed.

```bash
grep -rnE "#[0-9a-fA-F]{3,8}\b|rgba?\(" app demo --include=*.css --include=*.vue --include=*.ts | grep -v "app/assets/css/tokens/"
```

```bash
grep -rnE "var\(--(neutral|red)-[0-9]+\)" app demo --include=*.css --include=*.vue --include=*.ts | grep -v "app/assets/css/tokens/"
```

```bash
grep -nE "[0-9.]+m?s\b|cubic-bezier|ease-in|ease-out" app/assets/css/*.css demo/banner.css | grep -v "var(--"
```

```bash
grep -nE "^\s*(padding|margin|gap|inset|top|right|bottom|left)[a-z-]*:.*[0-9]px" app/assets/css/*.css demo/banner.css
```

Exceptions, each one on purpose:

- `app/app.vue`: the `theme-color` meta tag repeats `--bg-base`, because a meta tag cannot read a
  CSS variable.
- `public/favicon.svg`: a static file, drawn with the three colours of the palette.

## Done in step 4

- The glyph field is the bench: still, computed from the data, with no text on a glyph
  (`utils/glyphField.ts`, `GlyphBench.vue`). On the login and error pages it settles once in under a
  second, then stays still.
- An unknown value is the "not measured" state in the hero and words in cells ("Not known", "Not read", "Not rated"). No dash and, since step 5, no abbreviation is left.
- The agent strip became the reading line, on every view.
- Measured again on the rebuilt application (`step4/measurements.json`, `step4/contrast-rendered.json`):
  layout shift 0 on a phone and 0.0001 at 1440 px in six scenarios, the unreachable API included;
  lowest contrast 5.66 over 1,216 text nodes; no horizontal overflow at 390 px.

Still open: the `@fontsource/ibm-plex-sans` and `@fontsource/ibm-plex-mono` packages are no longer
used, and can be removed from `package.json`.
