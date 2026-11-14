# ADR-0017: Visual language, monochrome and vermilion

**Status:** Accepted. The palette, the typography, the blueprint grid, the rendering of an unknown
value and the animated ASCII fields are superseded by [ADR-0018](0018-instrument-interface.md)
**Date:** 2026-11-11
**Deciders:** Gemukii
**Supersedes:** the "Visual language" part of [ADR-0014](0014-optical-bench-interface.md). The optical bench
itself stays.

## Context

The paper and safelight look of ADR-0014 read like a printed brief, but numbers were hard to scan and
red had no scale: everything that mattered was the same red. New design guidelines set a stricter
system, written for a dashboard of attack data.

## Decision

- **Palette.** Eight greys from `#0A0A0A` to `#F2F2F2`, never pure black or white, and one accent,
  vermilion `#FF3B2F`. Vermilion only marks what signals something: a confirmed way in, an exploited
  finding, a score drop of 10 points or more, a firewall turned off, a broken feed, the keyboard focus.
- **Severity** is the intensity of the red (`signal`, `signal-700`, `signal-900`, grey), always next to
  its word. Only `signal` colours text.
- **Type.** IBM Plex Sans for the interface, IBM Plex Mono for raw data (ports, addresses, processes,
  commands, timestamps), weights 400 and 500, tabular figures everywhere. Bundled locally through
  Fontsource rather than Google Fonts, per [ADR-0010](0010-external-services-by-consent.md).
- **Shapes.** 2px radius, 1px borders, no shadow except on the floating drawer, no gradient or blur.
  A blueprint grid on the page background only.
- **Layout.** A hero with one main figure (ways to full control) and three smaller ones, the bench at
  full width, then two unequal columns. Tables with 36px rows instead of cards; they become lists on a
  phone.
- **Motion.** A new change fades in tinted and settles in 2 s. Skeletons pulse while loading.
- **ASCII fields** (added the same day, on request, to stand apart from generic dashboards). The brief's
  hero redraws the bench in characters on a canvas: shaded lens, firewall blades, rays, a light cone and
  a halo on the focus. It follows the data through `sceneFromBench`: a cell only turns red on a ray that
  reaches full control, or on the focus when something reaches it, and tests check that nothing turns red
  otherwise. The login and error pages get a field of interfering waves, grey only. The hero figure and
  headline decode from glyphs when they change, and the Scan button shows a character spinner.
- **Restraint.** Fields pause off-screen and on hidden pages, cap at 18 frames per second, and draw one
  still frame under `prefers-reduced-motion`; the decoding text lands on the real value at once in that
  case, and by a timer if frames stop. The canvases are `aria-hidden`: the text and the bench carry the
  meaning.

## Deviations from the guidelines

| Guideline | Here | Why |
| --- | --- | --- |
| `ink-400` = `#7A7A7A` | `#858585` | `#7A7A7A` fails AA on `ink-900` (4.29:1) and on the grid lines; `#858585` passes everywhere, including `signal-950` |
| Google Fonts | Fontsource, bundled | No call to a third party without consent |
| Tailwind config | CSS custom properties | The dashboard has no Tailwind; same tokens, same bans |
| ASCII only on the 404 and first-load screens, one animation | ASCII in the hero, login and error pages, more motion | Asked for explicitly, to make the page less generic; kept data-driven and paused when unseen |
| Honeypot sections (timeline, heatmap, countries, sessions) | Not applicable | AttackLens has no attack traffic; the bench, actions and reachability take their place |
| Period selector | Not applicable | Scans run on demand, there is no time series to filter |

## Consequences

- **Easier:** scanning numbers, and telling at a glance what is urgent from what is not.
- **Hero type.** The main figure goes up to 128px with -0.06em tracking and overlaps the field, and the
  headline is set at 28px with -0.03em: larger than the guidelines' 48px, for the same reason.
- **Harder:** the main figure must never read as reassurance. It stays `—`, never `0`, without the view
  from inside, and a `0` always says whether a probe agrees. Tests guard both.
