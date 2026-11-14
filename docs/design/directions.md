# Directions (steps 2c and 2d)

Three directions (A, B, C) were applied to the same screens with the same demo data, checked, and
then judged flat and generic. A fourth, D, was built from that feedback and is the one recommended:
see "After the feedback" at the end. One has to be chosen before step 3.

- Side by side: open `docs/design/directions/index.html`. Composite images are in
  `docs/design/directions/compare/`.
- Live pages: `docs/design/directions/{a,b,c,d}-{brief-agent,brief-no-agent,findings,machine}.html`.
- Captures at 1440 and 390 px: `docs/design/directions/captures/`.
- Ramps, roles, aliases and contrast, generated: `docs/design/directions/tokens.md`.

## How they were made

The pages are prototypes, not the application. Rewriting the Nuxt components three times would have
left two dead versions in the code. Instead `directions/build.mjs` renders static pages from
`frontend/fixtures/demo-*.json`, and computes the brief, the actions and the bench with the
application's own display logic (`frontend/app/utils`, bundled on the fly). The content is therefore
the real one. Only the layout and the dress change.

All three share what was decided before: the reading order of `hierarchy.md`, the "not measured"
state, `n/a` in cells, no ASCII, three levels of tokens, a bench whose height follows the number of
services (327 px for seven services at 1440 px, against 400 to 540 px today), and one list of findings
sorted by risk with a "Since" column read from the alerts.

Calibration, from the five references that were approved: the machine state as first-class data
(Tailscale), mono data and hairlines (Oxide), the anatomy of a finding row (Sentry), restraint and
one accent (Linear), every figure with its basis (Stripe).

## The three directions

| | A. Graphite and vermilion | B. Steel and amber | C. Whiteprint |
| --- | --- | --- | --- |
| Kind | Solid | Solid | Bold |
| Theme | Dark, warm | Dark, cool | Light |
| Intent | A dark bench instrument: warm graphite everywhere, and one red lamp that lights only for what is confirmed or critical | A control-room console: steel surfaces, one continuous status line, warning lamps in amber and red kept for the critical few | The reading as an engineering drawing: ink on drafting film, a title block that says who measured what and when, red pencil for what must be corrected |
| Base colour, and why | Vermilion `#ed4a31`, hsl(8 84% 56%). Red is read as "stop and look" before any word | Steel blue for the surfaces: the colour of trusted equipment, it recedes behind data. Amber `#ea9d2a`, hsl(36 82% 54%), for the signal, like a warning lamp. That leaves red to mean critical | Prussian blue ink `#131a30`, hsl(224 44% 13%): the colour of the drawings one builds from. Red `#e63519`, hsl(8 80% 50%), is the reviewer's pencil: a redline marks what has to change |
| Neutrals | 8 warm greys, hue 18 to 34, saturation 8 to 22 % | 8 steel greys, hue 208 to 218, saturation 10 to 30 % | 8 blue greys, hue 214 to 224, saturation 13 to 44 % |
| Severity | Intensity: a four-bar level, red only when all four are lit | Three desaturated colours with their word: red, amber, grey-blue. Low is hollow | Redline: filled red square, red outline, then ink |
| Typefaces | IBM Plex Sans and IBM Plex Mono | Atkinson Hyperlegible Next and Mono | Barlow, Barlow Semi Condensed for labels, JetBrains Mono |
| Why these | Drawn for technical documentation, with a mono sibling of the same proportions | Designed so that no two characters can be confused (0 and O, 1, l and I), which matters for ports, addresses and hashes | Barlow descends from plate and road lettering, close to the lettering of technical drawings |
| Texture | Blueprint grid on the page background only, 4 % | None | Drafting grid under the bench drawing only, 6 % |
| Composition of the brief | Panels. Verdict and data on the left, "Fix first" on the right, bench and reachability below | No panels. A status line under the top bar, a rail with the verdict and the data, a console with "Fix first" then the bench | A sheet. Verdict and title block on top, the bench as the drawing, "Redlines" below |
| Where trust lives (Q3) | In the top bar and in a reading line under the verdict | In the status line, on every screen, always the same place | In the title block, on every screen |
| Motion | Dry and short: state changes at once, only a new line keeps a tint for two seconds | Steady: values are replaced in place, lists slide, nothing else moves | Almost still: a view cross-fades, a new line slides in |
| Other theme | A light counterpart is possible by rewiring the aliases | Same | A dark "blueprint" counterpart is possible the same way |

All typefaces are under the SIL Open Font Licence and are self-hosted (`directions/fonts/`).

Ramps are built from 50 to 900 around the base colour. Only the steps that have a role are meant to
ship as tokens: the others are listed in `tokens.md` as built, not shipped.

## Measured contrast

Two measurements, both by script.

**From the tokens** (every text alias on every surface it can meet, including the tinted critical row
and the texture line). Lowest ratio per text alias:

| Text alias | A | B | C |
| --- | --- | --- | --- |
| `fg-primary` | 13.29 | 13.05 | 12.53 |
| `fg-secondary` | 8.35 | 8.52 | 7.76 |
| `fg-muted` | 5.20 | 5.30 | 5.29 |
| `accent-fg` | 5.19 | 7.87 | 5.80 |
| critical as text | same as accent | 5.44 | same as accent |
| Primary button label | 17.32 | 16.92 | 16.06 |

`fg-muted` on a hovered row, which failed at 4.47 in the audit, is now 5.53 (A), 5.60 (B) and 5.29 (C).

**As rendered** (every text node of the 24 page and width combinations, text colour against the first
opaque background behind it): 2,149 text nodes measured, none under 4.5. Lowest: 5.19 (A), 5.30 (B),
6.00 (C). Details in `directions/captures/contrast-rendered.json`.

No page overflows horizontally at 390 px (`directions/captures/measurements.json`).

## Five-second test

What a first screen of 1440 by 900 px tells in five seconds. A direction fails a line when the answer
is not on that first screen or has to be searched for.

| Capture | Security state | Priority number one | Result |
| --- | --- | --- | --- |
| A, agent online | "5", "3 confirmed" in red, "Three confirmed ways in." | The red box at the right: bind Redis, critical | Pass |
| A, no agent | "Not measured", with the reason and the button. It is quiet by design, and the eye lands on the red box first | The same red box | Pass, with a reservation: the state is read second |
| B, agent online | Same figure and sentence, top left. The status line already says the agent is online and the reading is two hours old | The tinted block at the top of the console | Pass |
| B, no agent | "Not measured", and "None connected" in the status line just above it | The tinted block | Pass, same reservation as A |
| C, agent online | The figure, the sentence, and three red rays reaching "Full control" in the drawing | **Not on the first screen.** "Redlines" starts at 846 px, under the drawing | **Fails on priority** |
| C, no agent | "Not measured", and a drawing that visibly stops at the services | The red box starts at 741 px: on screen, but low | Pass, weak |

On the phone captures all three follow the same order after correction: verdict, fix first, bench,
then the data.

## My own critique

- **A** is the nearest to what exists. It is correct everywhere and surprising nowhere: dark panels
  with one red accent are also what most security dashboards look like. Its accent discipline is the
  strictest of the three, and the four-bar level reads without colour.
- **B** has the best composition for the three questions: the status line makes trust a fixed place
  on every screen, and the rail keeps the verdict visible beside the actions. Two weaknesses. Amber
  appears on every "High" mark and on every "New", so the findings list carries five to seven amber
  marks: the signal is less rare. And cool dark grey-blue with a system-like sans is close to the
  default look of developer tools.
- **C** is the only one that does not look like a security dashboard, and the title block is the best
  answer to "can I trust this data" of the three. It fails the five-second test on priority, because
  the drawing takes the first screen. A light theme is also a real choice for people who work in dark
  rooms. Its risk is the costume: it stays honest only as long as the drawing metaphor is limited to
  the title block, the ink and the redline.

## Independent review

A reviewer that had not seen the work was given the 30 captures of A, B and C, the checklist of
`design-anti-ia.md` and the three questions, and nothing else. Its report is in
`docs/design/directions-review.md`, unedited. Its ranking: A, then B, then C.

The captures of A, B and C in the folder are the ones the reviewer saw. Two corrections made
afterwards (the first action moved up in C, less amber in B) are in the live pages only.

Answer, point by point:

| Point raised | Answer |
| --- | --- |
| The bench says 7 services, the metric says 8; the figure says 5 ways in, the bench draws 4 | Correct, and it damages trust. Both gaps are real data: one service is accepted and not drawn, two ways in do not go through the network. D says so in words under the picture |
| Vocabulary drifts between "confirmed", "proved reachable", "reachable" | Correct. The words come from the backend and the existing interface. A glossary is needed in step 4: "proved" for reachability, "confirmed" for an attack path or an active test |
| The brief and the findings list do not put fixes in the same order | Correct. The brief orders by urgency and by the number of ways in a fix closes, the list by risk. This is the application's logic and is out of scope. The sentence that claimed the first line is the first thing to fix is removed |
| "58 / 100" does not say which way is good | Fixed in D: "of 100, higher is better" |
| "Not measured" in grey understates a critical finding on the same screen | Agreed. D keeps the muted state, as decided, and adds "4 services answer, 1 critical" under it, the critical count in the accent |
| "Connect the agent" competes with the critical finding | Agreed. In D it is a secondary button |
| C puts the drawing before the action | Agreed, it was my own finding too. In D the first action sits under the verdict, on the first screen |
| Red changes meaning between screens | Agreed. D has one rule: red is a proved way to full control, or a critical or exploited finding. "Reachable" is set in weight, not in red |
| A repeats the same fact in red four times | Agreed. In D the reachable count, its cells and the score columns are neutral, except a drop of ten points |
| B uses amber for things that are not threats, and three hues | Agreed. B is dropped |
| B looks like a stock developer-tool theme, A's cards lean towards bento, C's pink box is a stock alert | Agreed on all three. D has no cards and no tinted box: the first action is set large under a red rule |
| Tabs wrap on a phone | Fixed for all: the tabs scroll |
| Ghost firewall stubs, axis running out of a label, captions far from their shapes | The stubs and the axis are fixed in D. Captions still sit under the picture: to refine in step 4 |
| Four-bar level: two and three bars are hard to tell apart | D uses four equal cells, wider apart |
| A sparkline of three readings is not a trend | D draws one column per reading and states the number of readings |
| Small, faint mono evidence in rows; wide gap between columns | Not fixed in the prototypes. For step 4 |

Not accepted: the reviewer reads the red beams of A as "edging towards a laser threat map". The beams
are the product's own metaphor and they are computed from the data. The point is taken as a warning
against making them theatrical.

## After the feedback: direction D, "Glyph field"

A, B and C were judged flat, generic, too close to each other and not bold enough, and the login
page of the existing interface, with its field of characters, was pointed at as the look to aim for.
D starts from that.

| | D. Glyph field |
| --- | --- |
| Intent | An instrument that shows what it sees: the optical bench is rendered in characters, light for what gets through and red where it reaches full control. Everything else stays black and quiet |
| Base colour, and why | Near-black with a trace of warmth, hsl(30 10% 4%), because the image is made of light and needs a dark room. Vermilion `#ed4a31` is the only colour: a proved way to full control, a critical finding, nothing else |
| Neutrals | 8 greys, hue 30 to 36, saturation 6 to 12 %. Lower than the 8 to 20 % asked for in the middle of the ramp: more warmth turned the black brown, as A showed |
| Severity | Intensity: four cells, red only when all four are lit |
| Typefaces | IBM Plex Sans and IBM Plex Mono. The field is set in the mono, so the data and the image share one typeface |
| Texture | The glyph field, and only where it means something: the bench, the login page, the 404 page. No grid and no grain elsewhere |
| Composition | The reading line of B under the top bar. A hero without a box: on the left the figure at 136 px, the sentence and the first thing to fix; on the right the bench. Below, ruled columns, no cards |
| Motion | The field is still. It may resolve once on first load, in under a second. Values are replaced in place, a new line slides in |

How it differs from the ASCII hero that the audit removed:

- It is the bench itself, not a backdrop: every glyph comes from the rays, the firewall, the lenses
  and the focus of `buildBench`.
- It does not move.
- No text sits on a glyph. Labels are placed on cells that are blanked for them, on phone too.
- It is the only texture.

This reverses one decision of the brief ("ASCII removed from the hero and from any area that carries
text"). It is recorded as such in ADR-0018, and it needs an explicit yes.

Measurements for D: contrast from the tokens, lowest 5.66 for muted text on a hovered row; as
rendered, 721 text nodes, lowest 5.82. The glyphs are an image, hidden from assistive technology and
described by a text alternative, so they are left out of the text measurement. No horizontal
overflow at 390 px.

Five-second test for D, on a first screen of 1440 by 900 px:

| Capture | Security state | Priority number one | Result |
| --- | --- | --- | --- |
| D, agent online | "5" at 136 px, "3 confirmed" in red, three red beams gathering on "Full control" | "Fix first", under the verdict, from 521 to 699 px | Pass |
| D, no agent | "Not measured", then "4 services answer, 1 critical" | "Fix first", from 439 to 617 px | Pass |

Known weaknesses of D: the focus is small at the right edge and the dashed ray of "A file you open"
is thin; the left column of the hero is long when the first action wraps; a field of characters is
harder to read exactly than a line drawing, so the rows of the findings stay the place where one
reads precisely.

## Recommendation

**D.** It is the only one with an image of its own, it comes from the part of the existing interface
that was liked, and it keeps what the review found best in the others: the reading line and the
ruled, card-free structure of B, and the single, rare accent of A. A, B and C stay in the folder as
a record.
