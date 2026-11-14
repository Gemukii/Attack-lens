# ADR-0018: Interface as a measuring instrument

**Status:** Accepted. Completed step by step during the interface redesign
**Date:** 2026-11-11
**Deciders:** Gemukii
**Supersedes:** in [ADR-0017](0017-monochrome-and-vermilion.md), the ASCII fields, the rendering of an
unknown value, the palette and the typography. The optical bench of
[ADR-0014](0014-optical-bench-interface.md) stays.

## Context

The audit of the interface (`docs/design/audit.md`) measured what ADR-0017 left behind: an animated
ASCII canvas behind the main figure, text that decodes from random glyphs, an em dash set at 128 px
when the agent is absent, two textures at once, pure greys with a fully saturated accent, tokens on a
single level, and a bench that keeps 400 to 540 px of height for two services.

The aim is restated. The interface must answer three questions, in this order: am I exposed right
now, what do I fix first, can I trust this data. It should feel like a measuring instrument: one
looks, knows, and acts. No spectacle, and no "hacker" scenery.

## Decision

### Taken

- **Reading order.** Each screen has one focal point and a fixed reading order, written down in
  `docs/design/hierarchy.md` before any visual work. Trust information (date of the reading, vantage
  point, agent state, what was not seen) travels with the claim it qualifies.
- **Unknown value.** The principle of ADR-0017 stays: never `0` without the view from inside. The
  rendering changes. The hero shows a "not measured" state: a medium-size sentence in muted text, one
  line saying what is not visible, and the action that installs or reconnects the agent. Data cells
  show `n/a` in muted text. Tests check "never `0` without the agent" instead of the presence of a
  dash.
- **Glyph field.** The field of characters is the one image of the interface, and it is the bench
  itself: every glyph is computed from the rays, the firewall, the lenses and the focus. No text ever
  sits on a glyph, and it is the only texture. It moves, and the motion says something: light travels
  along each ray the way an attacker would, stops where the ray stops, and gathers on the focus only
  when something reaches it. It pauses out of sight and is still under reduced motion. It also stays on the login page and on
  the 404 page. This replaces the first version of this decision, which removed it from the hero:
  the first three directions were judged flat and generic, and the field is what gives the interface
  an image of its own. The glyph-decoding effect (`useScramble`) is removed everywhere.
- **Tokens.** Three levels: global ramps, aliases named after what they do, component tokens where
  useful. Components only use aliases or component tokens. Tokens live in their own files, outside
  `main.css`.
- **Motion.** Motion says something: that a thing arrived, changed, or is alive. Three durations and
  two curves, as tokens. Only `opacity` and `transform` are animated. What happens once lasts 400 ms
  at most; what lasts longer is slow on purpose (a tint fading, the lamp of the agent, the light of
  the field). Nothing runs on scroll.
  Vue's `<Transition>` and `<TransitionGroup>` and the View Transitions support of Nuxt are preferred
  to hand-written code.
- **Stack.** Plain CSS with custom properties, no Tailwind.
- **Demo mode.** Invented data lives in `frontend/fixtures/demo-*.json` and covers every state: each
  severity, agent present and absent, recent and stale readings, a filled journal, a score trend over
  several weeks, the empty state and an unreachable API. It is switched on by `ATTACKLENS_DEMO=1` in
  development only, shows a "Demo mode" banner at all times, and is registered under `$development`
  so that it cannot reach a production build. Addresses come from the documentation ranges and host
  names from `example.com`.

### Decided at the end of step 2: direction D, "Glyph field"

- **Palette.** Near-black with a trace of warmth, eight greys from `#0b0a09` to `#f2f0ee`, and one
  colour, vermilion `#ed4a31`. The accent has one meaning on every screen: a proved way to full
  control, or a critical or exploited finding. Severity is an intensity, red only at the top. Focus
  is neutral. One theme: the field needs a dark room.
- **Typography.** IBM Plex Sans for reading, IBM Plex Mono for raw data and for the field, weights
  400 and 500, bundled with the application. Eight named styles, from `display` to `label`.
- **Texture.** The glyph field only. The blueprint grid is removed.

The values, their roles and the measurements are in `docs/design/tokens.md`.

## Consequences

- **Easier:** telling what is urgent and how far it can be trusted; adding a theme without touching a
  component; showing every state of the interface without a real machine.
- **Harder:** nothing. One constraint is added: every new state needs a fixture.
- **Superseded:** in ADR-0017, the palette, the typography, the blueprint grid, the rendering of an
  unknown value and the animated ASCII fields.

## Journal of decisions

| Step | Decision |
| --- | --- |
| 1 | Audit delivered. Sources: `design-anti-ia.md` and the design-system notes, since `attack-lens-design.md` does not exist |
| 2a | Reading order per screen written. The file is named `hierarchy.md`, in English like the rest of the repository |
| 2b | Demo mode built as a development-only server middleware and client plugin, both outside `app/` and `server/` |
| 2c | Three directions built as static prototypes from the demo fixtures and the application's own display logic, rather than three versions of the components. See `docs/design/directions.md` |
| 2c | One list of findings sorted by risk replaces the split between network and machine tabs. A port reported by both views appears once, with the higher risk |
| 2c | "Since" is read from the alert that first carried a finding, and shows `n/a` when no alert exists. The API is not changed |
| 2c | The bench is laid out in rows of 30 px, so its height follows the number of services |
| 2d | Contrast is measured twice by script: from the tokens, and on every rendered text node |
| 2d | An independent review of A, B and C is kept unedited in `docs/design/directions-review.md` |
| 2d | A, B and C were judged flat, generic and too close to each other. They are kept as a record and not pursued |
| 2d | Direction D, "Glyph field", is proposed: the bench rendered in characters, still, computed from the bench data, with no text on a glyph. It reverses the first ASCII decision for the bench. Approved on 2026-11-12 |
| 2d | In D, red has one meaning on every screen: a proved way to full control, or a critical or exploited finding. Reachability is set in weight |
| 3 | Tokens on three levels, in `frontend/app/assets/css/tokens/`. `main.css` no longer names a raw colour, a duration, a curve or a spacing value |
| 3 | Spacing off the 4 px scale was moved to the next step (6 to 8, 10 to 12, 14 to 16, 18 to 20), so rows are slightly taller |
| 3 | Typefaces are four files in the application, preloaded, with `font-display: swap`. `optional` was tried and rejected: when a font was late the page stayed in the fallback typeface |
| 3 | Layout shift on load goes from 0.03 to 0.12 down to 0.0001 at most: the server renders the skeleton, the agent strip has a constant height, the footer waits for the first answer |
| 3 | The agent strip is always shown. It is the first version of the reading line, finished in step 4 |
| 3 | Focus is drawn in the primary text colour, no longer in the accent |
| 3 | A skeleton is still. The character spinner is replaced by one dot that breathes |
| 3 | Colours of the canvas are read from the CSS tokens: `tint()` returns a token name, not a colour |
| 3 | `main.css` is not split yet. It will be, one file per component, as each one is rewritten in step 4 |
| 4 | The bench is `GlyphBench.vue`, drawn by `utils/glyphField.ts`. The SVG bench, the sparkline and the geometry helpers that only served them are removed. Each ray is a real button placed on blank cells; the picture is hidden from assistive technology and described in words |
| 4 | The accent has three uses, and no other: a proved way to full control, a critical or exploited finding, and a broken feed (agent quiet, API unreachable, reading older than seven days). The last one follows the brief: an agent that stopped is shown in the alert colour |
| 4 | Not measured is a state in words: muted heading, what is not visible, and the command to start the agent with a copy button. There is no "Connect" button, because the dashboard cannot start an agent |
| 4 | Without the agent, what the network scan saw is still said, and an urgent finding is named in the accent: the missing agent never mutes it |
| 4 | A reading older than seven days is called stale, in the reading line and under the verdict |
| 4 | The reading line replaces the agent strip and the "Updated n s ago" indicator. Its columns are fixed, so a value arriving never moves its neighbours |
| 4 | Findings are one list sorted by risk, with tabs for updates, autostart and dismissed. A port seen by both views appears once |
| 4 | The score trend is a panel at the top of the journal: one column per reading on the fixed scale of 100, a period control (last 5, last 10, all), and a sentence when there are too few readings to call it a trend |
| 4 | Errors and the enrollment command are notices inside the page, so they never push what is already on screen |
| 4 | `main.css` is replaced by six files: `base`, `frame`, `brief`, `lists`, `drawer`, `states` |
| 4 | Tests follow the display: the field replaces the SVG bench, and four new ones check that the brief says "not measured" in words, never a zero or a dash, without the agent |
| 4 | **The field moves again.** A still interface was judged lifeless. Light now travels along each ray, the focus breathes when something reaches it, and the ray under the pointer stands out. This reverses "the field is still" and the limit of 1.5 s on the login and error pages. What is kept: the motion is computed from the data, no text sits on a glyph, it pauses out of sight, and it is still under reduced motion |
| 4 | The moving field is painted on a canvas laid over the text rendered by the server. Animating the text itself moved thousands of text nodes on every frame, which the browser counted as layout shift (0.02 to 0.04) |
| 4 | Entrances: the field develops from left to right once, rows arrive one after the other in under 300 ms, the columns of the score grow from their base, the verdict rises before the first action |
| 4 | Twelve frames per second for the field: characters change in place, they do not slide. Measured: no frame over 17.4 ms, layout shift unchanged |
| 4 | **The page answers the hand.** Motion only in the field left the rest of the page inert. Eight small answers are added, each one tied to something the reader did or to a fact that changed: nothing moves on its own outside the field |
| 4 | An action and its ray point at each other: pointing at "Fix first" or at an item of "Then" lights its ray on the bench, pointing at a ray marks its action. A port is the same service whichever view reported it |
| 4 | The mark of the current choice slides: the rule under a view and under a tab, the thumb of the period control. It is one element moved and scaled with a transform (`useIndicator`). Until it has been measured in the browser, each option keeps its static mark |
| 4 | A control answers under the finger with one step of surface, never a movement. A button with two labels ("Copy" then "Copied", "Scan" then "Scanning") keeps the width of the longer one (`CopyButton`, `.labels`) |
| 4 | What opens something takes a rule under its title when pointed at: a finding row, an action, a ray |
| 4 | **A scan no longer takes the verdict away.** The last verdict stays in place with "Taking a reading" beside its label, the field steps back to 40 % and develops again when the new reading is in. The verdict is swapped, old out then new in, only when what it says changes. Replacing it by a waiting message shifted the layout at the end of every scan (0.02 at 1440, 0.08 on a phone) |
| 4 | A fact of the reading line that was replaced fades in again under a neutral tint. A clock that ticks ("2 h ago", then "3 h ago") is not a change: each item carries a `stamp` of what stands behind its value |
| 4 | A change of view travels 8 px the way one is going: the old view leaves in `--dur-fast`, the new one settles in `--dur-slow` |
| 4 | The content of the drawer follows it in, one block after the other, the whole in 320 ms |
| 4 | Measured with these in place: layout shift 0 to 0.0001 through a whole session (hover, tabs, drawer, scan, copy) at 1440 and 390, lowest rendered contrast 5.66 over 1,216 texts, no horizontal overflow at 390. Under reduced motion no view transition and no indicator animation run |
| 5 | Every view of the six demo scenarios was captured at 1440 and 390 and read against `hierarchy.md` and the thirty points. Seven defects were fixed; the list, the measurements and the checklists are in `docs/design/verification.md` |
| 5 | **With the API down and nothing loaded, nothing is known.** Every view says "Not known" and the reading line says `n/a`. Before, the screen said "Never", "None yet" and "Nothing new so far", which it could not know. With data already loaded, the last reading stays under "API unreachable, last answer n ago" |
| 5 | The legend of the rays is shown only when a ray is drawn. "Last change" sits under the actions. On a phone the ports table keeps one line per row and stacked columns take the gap of sections |
| 5 | A control that stands alone is at least 24 px tall (`--size-target`): footer links, the wordmark, the disclosure of the machine view |
| 5 | The field develops in `--dur-slow` (320 ms), no longer in 640 ms, which broke the limit of 400 ms for what happens once. It is painted on every frame while it develops, then twelve times a second |
| 5 | No ffmpeg was installed, so the videos are replaced by contact sheets made from the browser screencast, in `docs/design/step5/motion/`, with and without motion |
| 5 | An independent review, kept unedited in `docs/design/step5/review.md`, found four blocking defects. All four were treated; the table of every finding and its outcome is in `verification.md` |
| 5 | The sentence of the verdict counts what its figure counts: "Five ways in, three confirmed." The figure said 5 while the sentence said three |
| 5 | **No abbreviation for what was not measured.** `n/a` is gone: "Not known", "Not read", "Not scored", "Not rated", "Not proved", "Not tested", "Not counted", each where it fits |
| 5 | One vocabulary across views: a finding that the bench draws as a proved way in is called "Proved way in" in the findings list, in the accent |
| 5 | An old reading is not a verdict: past seven days the figure and the sentence take the muted colour and the age sits beside the label |
| 5 | With nothing read the bench is not drawn: one line says so, as `hierarchy.md` asked. The caption under the bench says what is not drawn and why, instead of guessing |
| 5 | The log of the journal says what each line was about and is headed "Audit log" |
| 5 | Kept against the review: the field in the hero and the backdrop of the login page, both chosen on purpose. `hierarchy.md` is amended for the first |
| 5 | **On a phone the bench is a list.** Under 640 px the picture could not be read: labels met glyphs and the targets were small. The same rays are listed in the order of risk, one line each, with the stroke of the legend and the state in words, then the three stations. The compact picture is gone; the canvas is not painted on a phone and takes over when the window widens. The glyph field stays the image of the interface from 640 px up |
| 5 | Measured at the end: 75 tests pass; layout shift 0 to 0.0001 on load; through a session 0, or 0.004 at 1440 when a scan adds a service and the bench gains a row; lowest contrast 5.66 over 3,144 rendered texts; no overflow at 390; a focus ring on every keyboard stop; no demo code in the production build |
