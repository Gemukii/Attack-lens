# Verification of the redesign (step 5)

What was checked on the rebuilt interface, how, and what came out. Everything here was measured on
the real application in demo mode (`npm run dev:demo`), in a Chromium browser driven by Playwright,
at 1440 x 900 and 390 x 844.

The record is in `docs/design/step5/`. Only the written documents are versioned: captures, contact
sheets, measurements and prototypes are kept out of the repository by `.gitignore` and stay on the
machine that made them. The same holds for the image folders named in `audit.md` and `tokens.md`.

| Folder or file | Content |
| --- | --- |
| `after/` | Every view of every demo scenario at both widths, the drawer, loading, login, 404, and the first screen of each brief |
| `before-after/` | The captures of the step 1 audit beside those of step 5 |
| `motion/` | Contact sheets of the key moments, with and without motion |
| `contrast-rendered.json` | Contrast of every rendered text |
| `keyboard-and-targets.json` | Focus rings and target sizes |
| `review.md` | The independent review, unedited |

## Results

| Check | Result |
| --- | --- |
| Unit tests | 72 pass |
| Production build | Succeeds; no demo string in `.output` |
| Layout shift on load | 0 at 390, 0 to 0.0001 at 1440, in the six scenarios |
| Layout shift through a session (hover, tabs, drawer, scan, copy) | 0 at 390 and at 1440 when the scan brings nothing new. 0.004 at 1440 when it adds a service: the bench gains a row and what is under it moves. This is new data arriving, and it stays far under the 0.1 that counts as a poor score, but it is not zero |
| Horizontal overflow at 390 | None, on the four views of the six scenarios |
| Contrast, WCAG AA | Lowest 5.66 over 3,142 rendered texts (4.5 required). Lowest case: muted text on a hovered row |
| Keyboard | Every stop shows a focus ring: 20 on the brief, 26 on findings, 10 on the machine, 13 on the journal |
| Target size | No control under 24 px, except "Show them", a link inside a sentence (WCAG 2.2 exempts it) |
| Reduced motion | No view transition starts, no indicator animates, the field is still |
| Raw colours, ramp steps, durations outside the tokens | None (see "Checking that nothing bypasses the tokens" in `tokens.md`) |
| Em dashes in the interface text | None |

Scenarios: `exposed`, `clear`, `no-agent`, `stale`, `empty`, `api-error`. Views: brief, findings,
machine, journal.

## Defects found by looking at the captures, and fixed

The captures were read one by one against `hierarchy.md` and the thirty points of
`design-anti-ia.md`. Seven defects came out. Each was fixed and captured again.

| | Defect | Fix |
| --- | --- | --- |
| 1 | **With the API down, the screen made claims it could not support**: "Read: Never", "Probe: None yet", "Nothing has been read yet", "Nothing new so far", an empty findings list | When the API does not answer and nothing was ever loaded, every view says "Not known" and why. So does the reading line. With data already loaded, the last reading stays on screen under "API unreachable, last answer n ago" |
| 2 | The legend of the rays was shown when no ray was drawn | Shown only when there is a ray |
| 3 | With no way in and a probe, the verdict said "A probe agrees" twice, under the figure and in the sentence | The sentence now says "Seen from inside the machine, and checked from another one." |
| 4 | Under the hero the left column stopped halfway while the right one went on | "Last change" moved under the actions |
| 5 | On a phone, every row of the ports table wrapped on two lines | The two verdicts never wrap; only a long program name may |
| 6 | On a phone, columns that stack were closer together than sections | Stacked columns take the gap of sections |
| 7 | Footer links, the wordmark and "Where AttackLens itself runs" were 20 or 21 px tall | A link that stands alone is at least 24 px tall (`--size-target`) |

Found in step 4 while adding the interactions, and kept here because it is a layout defect: a scan
replaced the verdict by a waiting message, which shifted the page when the scan ended (0.02 at 1440,
0.08 at 390). The verdict now stays in place.

## The thirty points

Checked on the captures and by search in `frontend/app`.

| # | Point | Verdict |
| --- | --- | --- |
| 1 | Garish gradients | None. No gradient at all |
| 2 | Pure white background | Near-black `#0b0a09`, not pure black |
| 3 | Rainbow colours | Eight greys and one red |
| 4 | Purple and black | No purple |
| 5 | Neon colours | The red is a vermilion, `#ed4a31` |
| 6 | Basic pastels | None |
| 7 | Inter, Geist, Space Grotesk | IBM Plex Sans and IBM Plex Mono |
| 8 | Em dashes | None in the interface text |
| 9 | "It is not X, it is Y" | One was found by the review ("The evidence is there, not just the theory.") and rewritten. None left |
| 10 | Emoji | None |
| 11 | Check-mark bullets | None |
| 12 | Three feature cards in a row | No cards. The three figures of the brief are a ruled list of data, set small |
| 13 | Bento grid | Twelve columns, unequal, ruled |
| 14 | Coloured band on the left of cards | None. The first action has a rule above it, in the accent only when critical |
| 15 | Fake terminal window | None. Commands are inline code with a copy button |
| 16 | Three price tiers | Not applicable |
| 17 | Fake testimonials | Not applicable |
| 18 | No real demo | Demo mode runs the real interface on invented data, under a banner that says so |
| 19 | Very rounded corners | 2 px everywhere, round only for the lamp |
| 20 | Shadows everywhere | One shadow, on the drawer, which floats |
| 21 | Glass | None, no blur |
| 22 | Orbs and halos | None |
| 23 | Dot grid background | None. The one texture is the glyph field, computed from the bench data |
| 24 | Sparkle icons | None |
| 25 | Lucide icons | No icon library. The one drawn mark is the four-cell severity scale |
| 26 | Animated arrows | None |
| 27 | Hover animations everywhere | Hover changes a colour or a rule in 120 ms. See the note below |
| 28 | No skeleton | Skeletons take the shape of each view, rendered by the server |
| 29, 30 | Legal notice, privacy policy | Not applicable: a private tool behind a password |

Note on point 27. The brief asked for few animations; the still interface was then judged lifeless,
and motion was added on purpose in step 4 (ADR-0018, journal). What keeps it away from the "demo"
look the point warns about: nothing moves on its own outside the field, every other motion answers a
gesture or a fact that changed, each lasts 400 ms at most, and all of it stops under reduced motion.

## Other rules of the brief

| Rule | Verdict |
| --- | --- |
| No button in the alert colour | Buttons are neutral; the primary one is light on dark |
| The accent means a proved way to full control, a critical or exploited finding, or a broken feed | Checked on every capture. A stale reading counts as a broken feed: still open, see below |
| Not measured is said in words, never `0`, never a dash | "Not measured", "Not known", "Not read", "Not scored", "Not rated", "Not proved". No abbreviation is left. Covered by tests |
| No invented content outside demo mode | Fixtures use documentation addresses and `example.com`; demo mode needs `ATTACKLENS_DEMO=1` in development and is absent from the production build |
| Only opacity and transform move | True, with the stated exception of colour on hover and under the finger |
| One-off motion lasts 400 ms at most | Longest: 320 ms (change of view, rows, the drawer and its content, the field developing). The field took 640 ms to develop: found here and brought down to 320 ms, painted on every frame (19 repaints in 400 ms, no frame over 34 ms) |
| No motion on scroll | None |

## Motion, in pictures

There is no ffmpeg on this machine and none was installed, so the videos the brief asked for are
replaced by contact sheets: the browser screencast records every frame painted after a gesture, and
a sheet shows the first 450 ms, then the settled screen, each frame with its time.

| Sheet | Moment |
| --- | --- |
| `navigation-forward-*`, `navigation-back-*` | Change of view, both ways |
| `rows-*` | Informational findings join the list, rows find their place |
| `tabs-*` | Change of tab |
| `drawer-open-*`, `drawer-close-*` | The drawer |
| `reading-arrives-*` | A scan ends: reading line, verdict and bench take the new reading |
| `journal-*` | The journal after the scan |

Each exists at 1440 and 390, and at 1440 under reduced motion. Under reduced motion a gesture paints
3 to 13 frames in under 300 ms, against 40 to 75 frames with motion: the change is immediate.

## The independent review

A reviewer with no knowledge of the project read the captures and the source, starting with a
five-second test on four first screens. Its report is kept unedited in `step5/review.md`. Its
verdict: a designed instrument, not a template, with four blocking defects. What was done with each
finding:

| | Finding | Outcome |
| --- | --- | --- |
| B1 | The figure said 5 and the sentence "Three confirmed ways in" | Fixed. The sentence counts what the figure counts: "Five ways in, three confirmed." |
| B2 | "Confirmed" and the red meant different things on the brief and in the findings | Fixed in part. A finding that the bench draws as a proved way in is now called "Proved way in" in the list, in the accent. Whether a way in that needs physical access belongs in the main figure is a product decision, left open |
| B3 | `n/a` stood for values that were not measured, in about fifteen places, and a test required it | Fixed. Each place says it in words that fit, and the tests require the words |
| B4 | A 23-day-old verdict was shown at full strength, and the agent state was cut off on a phone | Fixed. The figure and the sentence step back to the muted colour, the age sits beside the label of the verdict, and the agent state is shorter |
| S1 | The field pulls the eye before the verdict, against `hierarchy.md` | Kept on purpose: the field in the hero is direction D, chosen at the end of step 2. `hierarchy.md` now says so |
| S2 | The counts of services did not add up, and the caption guessed | Fixed. The caption says how many are drawn, how many have no open finding, and how many are beyond the seven the picture holds. The cells are labelled "one cell per listening port" |
| S3 | Finding titles undersell the flaw ("Redis service detected") | Not fixed: titles and "why it matters" come from the API |
| S4 | The first action can be less severe than the second | Not fixed: the order comes from the risk score, which is not display work |
| S5 | The red marks a drop of the score, which is not in the list of what red may mean | Left open: `hierarchy.md` allows it, ADR-0018 does not list it. One rule is needed |
| S6 | The scan field shows another address than the target | Not fixed: the placeholder comes from the runtime configuration, and the mismatch is an effect of the demo fixtures |
| S7 | One marketing sentence and one vague note in the verdict | Fixed: "Each confirmed one has evidence behind it." and "Checked by an outside probe" |
| S8 | The empty state still drew a field | Fixed: with nothing read, the bench gives way to one line. Scan stays enabled while the API is down, since it is also how one tries again |
| S9 | The field is hard to read at 390 px | Left open: a list of rays under 640 px is a design decision |
| S10 | The journal did not say what each decision was about | Fixed: each line carries its subject, and the heading is "Audit log", since backups and scans are in it. The author is not shown: every entry of the fixtures is "dashboard" or "api" |
| S11 | The backdrop of the login and error pages is at full contrast | Kept on purpose: it is the look that was asked for |

## Not done, and why

- **Videos.** Replaced by the contact sheets above.
- **The check scripts are not in the repository.** They need `playwright-core`, which is not a
  dependency of the project. Adding them is a decision to take.
- **The bench on a phone** is dense: seven rays in 358 px. It is readable, not comfortable.
