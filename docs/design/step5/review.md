# Step 5 review: AttackLens interface after the redesign

Independent review of the demo-mode screenshots in `docs/design/step5/after/`, the motion stills in `docs/design/step4/motion/`, and the visual layer in `frontend/app/`.

## Verdict

This reads as a designed instrument, not a template: one red, Plex, hairline rules, a real reading line, honest empty and error states.
It fails its own core question on the main screen: the big figure says 5, the headline says three, and "confirmed" means something different on the brief than in the findings table.
The rule "never n/a, never a dash, say it in words" is broken in about fifteen places, and a unit test enforces the breach.
The glyph field is the identity and also the main liability: on the first screen it outshouts the verdict, and at 390 px it is unreadable.
Fix the four blocking items before anything cosmetic.

## 1. Five-second test (done before reading hierarchy.md or the source)

### `exposed-brief-first-screen.png`

- Eye: 1) the giant white "5"; 2) the red mass of the glyph field on the right; 3) the red "3 confirmed" under the 5. The fix-first block came fourth.
- Q1, exposed? Yes, clearly. But how much: 5 or 3? The figure says 5, the red note says 3 confirmed, the headline says "Three confirmed ways in." I could not tell from a glance what the 5 counts. I had to read the small grey text under the field ("2 more ways in do not go through the network") to reconstruct 3 + 2 = 5.
- Q2, what first? "Bind Redis to the loopback address and require a password." Clear, specific, findable in about three seconds, but only after the field.
- Q3, trust? The reading line is there (read 2 h ago, probe 1 d ago, 37 ports, target). I read it only after looking for it; it is quiet, which is right.
- Could not work out: what "Full control" floating at the right edge is attached to; what "A file you open" with its little trail of asterisks means; why "Unknown" is a service name.

### `no-agent-brief-first-screen.png`

- Eye: 1) "Not measured" (grey, medium); 2) the glyph field, which is now mostly dashes; 3) the red "1 critical".
- Q1: "Not measured", then "4 services answer, 1 critical." Honest and fast. Good.
- Q2: Bind Redis. Clear.
- Q3: "Agent: None connected", "Probe: None yet", "From: The Docker container". Clear.
- Could not work out: why the legend still offers a red "Proved way to full control" swatch when the text says no ray can be followed.

### `clear-brief-first-screen.png`

- Eye: 1) the giant "0"; 2) "No way in, as far as we can see."; 3) the fix-first title.
- Q1: Not exposed. Clear.
- Q2: The fix-first item is Medium, and the first item under "Then" is High. At a glance this looks like a sorting bug. No risk number is shown on the brief to explain it.
- Q3: "A probe agrees" under the 0. Agrees with what, when, from where? The probe line in the frame says 3 d ago, but the note does not connect to it.
- Large empty region under the two-band field.

### `stale-brief-first-screen.png`

- Eye: 1) the "5"; 2) the red field; 3) the red agent state in the frame ("quiet since 23 d ago").
- Q1: Reads as "exposed", at the same weight as the live case. The verdict is not demoted at all; only a red-outlined sentence under it says the reading is 23 days old.
- Q2: Same as exposed.
- Q3: The red frame items do their job. The stale sentence is the fourth thing read, after a full-strength verdict.
- Also: the scan input says `127.0.0.1` while the target is `desk-07.example.com`. Which one does Scan hit?

## 2. Hierarchy against `hierarchy.md`

- **Brief, order 1 vs the bench.** hierarchy.md puts the bench "Below" and says it "is no longer the second thing read". In every brief screenshot the bench is in the hero, top right, takes about 60 % of the first screen, and is the most saturated mass on the page. In the five-second test it was the second thing read every time. Either the document is out of date (ADR 0018 may have moved it; if so update hierarchy.md) or the layout breaks it. As shipped, the field competes with the verdict.
- **Brief, order 1 internally.** Three statements of the verdict compete: the figure "5", the red "3 confirmed", the h1 "Three confirmed ways in." hierarchy.md asks for one sentence with its figure. Here the figure and the sentence disagree.
- **Brief, order 2.** "It sits next to the verdict, not below the fold": respected at 1440. At 390 it is above the field: good.
- **Brief, secondary.** Network score, services answering, proved reachable are small and aligned, as asked. The red "−16" and red last column make the score delta the loudest thing in the secondary column (see red rules below).
- **Bench, empty.** "With nothing measured the bench is not drawn empty: it gives way to one line." `empty-brief-1440.png` draws the three stations, the scattered dots and "Full control", plus "No service drawn yet." Breach.
- **Frame, order 2.** "Age of the last reading, and of the last answer from the API." The API answer age is not shown anywhere; in `api-error-brief-1440.png` the frame shows "Read n/a" instead of the time the API last answered.
- **Findings.** Row order, tint only on critical or exploited, risk right-aligned: all respected. Focal point is the first row: yes, thanks to the tint. The h1 "11 findings to deal with" is large but acceptable.
- **Machine.** The "8" is set as large as the brief verdict. hierarchy.md says "the count, then the table"; fine, but at the same size as the brief figure it shouts more than a count of listening ports should. Firewall "On" is correctly quiet.
- **Journal.** hierarchy.md puts "the most recent change" first. In `exposed-journal-1440.png` the first thing read is the huge "58" and the red "−16 since the reading before". The score trend panel was meant to be at the top of the journal, but it is set as the focal point, above the changes, at hero size.

## 3. Findings ranked by severity

### Blocking

**B1. The main figure contradicts the headline.**
Evidence: `exposed-brief-first-screen.png`, `stale-brief-first-screen.png`, `exposed-brief-390.png`. Source: `frontend/app/utils/brief.ts:88` returns `value: chains.length` (5) with `note: "3 confirmed"`, while `brief.ts:57` writes the headline from `confirmed.length` (three).
A security reader gets two numbers for the same question in the first second. The 5 also silently includes two non-network items explained only in a grey paragraph under the field.
Suggestion: make the figure and the sentence the same number. Either figure 3 with a small "of 5 found" note, or headline "Five ways in, three confirmed." Do not leave the reconciliation to the field caption.

**B2. "Confirmed" and the red mean different things on different screens.**
Evidence: on the brief, Redis, RDP and SSH are drawn as red rays, legend "Proved way to full control", and counted in "3 confirmed". In `exposed-findings-1440.png` only Redis says "Confirmed by a test" in red; RDP and SSH say "Reachable" in neutral grey, RDP is High, SSH is Medium with risk 30. In `exposed-machine-1440.png` they are just "Reachable".
A professional will read "confirmed way to full control" as "someone proved RDP gives admin". Nothing on screen supports that for RDP or SSH; it is reachable service plus an admin account, which is a path, not a proof.
Also, the 5 includes "a stolen laptop gives up its data" (`frontend/fixtures/demo-exposed.json:543`): physical theft of an unencrypted disk is not a way to full control of a running machine in the same sense as a network path. It inflates the headline figure.
Suggestion: one vocabulary across views. If a path is confirmed because each link is proved (reachable from outside + admin account), say so on the ray and in the findings proof column ("Reachable, leads to admin"). Keep red on the ray only when the whole chain is proved. Count physical-access risks separately or not in "ways to full control".

**B3. "n/a" is used for values that were not measured.**
The brief's rule: a value that was not measured must be said in words. "n/a" is an abbreviation, and it says "not applicable", which is the wrong meaning: these values are unknown, not irrelevant.
Evidence: `empty-brief-1440.png` (From n/a, Coverage n/a, Target n/a, Network score n/a, Services answering n/a, Proved reachable n/a), `api-error-brief-1440.png` (whole frame), `no-agent-brief-1440.png` (Proved reachable n/a), `exposed-findings-1440.png` (Since column: n/a on six rows).
Source: `frontend/app/utils/format.ts:1`, `utils/reading.ts:65-73`, `components/BriefView.vue:279, 289, 297`, `components/FindingLedger.vue:128, 130`, `components/MachineView.vue:80, 117, 118`, `components/JournalView.vue:78`. The test `frontend/tests/dashboard.test.ts:599` is literally named "says n/a for what was not measured, never a zero", so the breach is locked in.
Suggestion: words per context. Frame: "Not known" (API down), "No scan yet". Score: "No reading yet". Since: "Before tracking began" or leave empty as hierarchy.md open point 1 says. Machine: "Not reported by the agent". Change the test.

**B4. A stale verdict is shown at full strength.**
Evidence: `stale-brief-first-screen.png`, `stale-brief-390.png`. The 5, the red "3 confirmed" and the h1 are identical to the live case. The only qualifier is a sentence below the h1. On 390 the most important trust datum is truncated: "desk-07 quiet since 23 ..." (frame, `stale-brief-390.png`).
hierarchy.md: "A three-week-old verdict is not a verdict."
Suggestion: when stale, set the figure and h1 in muted text, put "23 days old" in the verdict itself ("Three confirmed ways in, 23 days ago."), and let the frame item wrap instead of truncating at 390.

### Should fix

**S1. The glyph field outshouts the verdict on the first screen.**
Evidence: all `*-brief-first-screen.png` with rays. The red `####@@@@` bands are the densest, most saturated area of the page; they pull the eye before "3 confirmed" and long before the fix-first item.
Suggestion: lower the hot glyph density (fewer `#@%`, more `:` and `-` in the red), shrink the bench height to the number of rays as hierarchy.md asks, and let the fix-first item carry the second-strongest weight. Or update hierarchy.md if the bench in the hero is a deliberate decision.

**S2. Counts on one screen do not reconcile, and a caption guesses.**
Evidence: `exposed-brief-1440.png`: "8 services answer", "Services 7 drawn", reachability cells 3 + 1 + 4 + 2 = 10, "Proved reachable 3", "37 ports checked". `exposed-machine-1440.png` says "8 of 10 listening ports". A reader can reconstruct it, but not in seconds.
The caption "One is not drawn: the risk was accepted, or the picture is full." (`components/BriefView.vue:225`) offers two explanations for one fact. The app knows which: port 902 is in Dismissed.
Suggestion: name it ("vmware-authd on 902 is not drawn: risk accepted 6 d ago."). Label the reachability block "10 listening ports" so its total is visible.

**S3. Finding titles undersell the finding.**
Evidence: `exposed-findings-1440.png`, `exposed-drawer-1440.png`. The critical row is titled "Redis service detected"; the drawer body says "Redis answers commands without a password", banner `+PONG`. The title describes an observation, the finding is the missing authentication. Same pattern for "RDP service detected", "SSH service detected".
"Why it matters: A database exposed on the network increases the risk of data compromise." is generic boilerplate; for unauthenticated Redis the honest line is that anyone who reaches the port can read, write and often execute.
Suggestion: title the flaw, not the service. Write the reason for the specific case.

**S4. Fix-first is Medium while the next action is High, with no explanation.**
Evidence: `clear-brief-1440.png`. "Block inbound RPC" (Medium) sits above "Restrict SMB" (High). The order is by risk score, which the brief does not show.
Suggestion: show the risk number next to each action on the brief, or one word of why ("closes the only reachable port").

**S5. The red is used for a score drop.**
Evidence: `exposed-brief-1440.png` (−16 and the last score column in red), `exposed-journal-1440.png` ("−16 since the reading before" at h2 size in red), `no-agent-brief-1440.png` (−14). Source: `assets/css/brief.css:194`, `tokens/components.css:25`.
The brief restricts the red to a proved way to full control, a critical or exploited finding, a broken feed. hierarchy.md (score trend, order 1) allows red for a 10-point drop. The two documents disagree; the screens follow hierarchy.md.
Suggestion: pick one rule. I would keep the score delta in primary white with a bold weight: a score drop is a consequence of the findings that already carry the red.

**S6. The scan input does not match the target on screen.**
Evidence: `stale-brief-first-screen.png` and `no-agent-brief-first-screen.png` show `127.0.0.1` in the input while the frame says `desk-07.example.com` and `host.docker.internal`. The exposed and clear scenarios show "this machine".
A reader cannot tell what the Scan button will scan. If `127.0.0.1` is a placeholder, it looks like a value.
Suggestion: prefill the input with the current target, or show the placeholder in muted text that cannot be mistaken for a value.

**S7. Marketing and vague sentences in the verdict.**
- "The evidence is there, not just the theory." (`utils/brief.ts:58`). This is the banned "not X, it is Y" pattern (point 9) and it says nothing measurable.
- "A probe agrees" (`utils/brief.ts:92`). Agrees with what, from where, when?
- "No way in, as far as we can see." is fine; "as far as we can see" is honest.
Suggestion: replace with facts. "Redis, RDP and SSH answer from outside, and the daily account is an administrator." / "Probe from 192.0.2.14, 3 d ago: nothing reachable."

**S8. Empty and error states break two hierarchy rules.**
- `empty-brief-1440.png`: the bench is drawn empty (stations, dots, "Full control") although hierarchy.md says it gives way to one line.
- `api-error-brief-1440.png`: the frame does not say when the API last answered; Scan stays enabled although the API is down.
Suggestion: drop the field when nothing is measured; add "API last answered" to the frame; disable Scan with a reason when the API is unreachable.

**S9. The field is unreadable at 390 px.**
Evidence: `exposed-brief-390.png`, `stale-brief-390.png`, `no-agent-brief-390.png`. Labels collide with glyphs ("Unknown 9090" sits on `%%%#`), "Full control" overlaps the rays, the station labels squeeze into three narrow columns. The ray names are the tap targets and are about 16 px tall.
Suggestion: below 640 px, replace the field with a list of rays (name, port, where it stops, red mark only for the proved ones). Keep the field as decoration only if it is not interactive there.

**S10. Journal decisions do not say what or who.**
Evidence: `exposed-journal-1440.png`. "Risk accepted 6 d ago", "Marked as a false positive 21 d ago", "Finding reopened 14 d ago": on which finding, by whom? hierarchy.md asks "who decided what". "Backup failed" is an event, not a decision.
Suggestion: add the finding and the author in each row; move system events to Changes.

**S11. Login and 404 backdrop is the one place that looks like scenery.**
Evidence: `login-1440.png`, `404-1440.png`. Full-contrast ASCII blobs fill the page around a small panel. It is the nearest the product gets to "hacker movie", and it ignores the texture rule of the anti-AI guide (3 to 8 % opacity behind content).
Suggestion: drop the field to very low contrast, or keep it only in a band, so the password field is the only thing that reads.

### Minor

- Four wordings for one state: "Not proved" (findings), "Not proved either way" (brief), "not tested" (machine), "Not proved yet" (legend). Pick one.
- "Unknown 9090" reads as a product called Unknown. Use "Unknown service 9090".
- The fix-first title is capped at 30ch (`assets/css/brief.css:53`); in `clear-brief-1440.png` it wraps to three lines and leaves half the column empty.
- `exposed-findings-390.png`: the tab row is cut at "Dismis" with no sign that it scrolls.
- `exposed-machine-390.png`: program names break mid-word ("vmware-" / "authd.exe", "redis-" / "server.exe").
- `exposed-brief-390.png`: "−16" falls alone on its own line under the score.
- Journal target column mixes `desk-07` and `desk-07.example.com` for the same machine.
- The legend shows the red "Proved way to full control" swatch in scenarios where no ray can be proved (`no-agent-*`, `clear-*`).
- `exposed-machine-1440.png`: "4 of 12" is set in mono, the other counts in the same block are not.
- Motion: the hero rises with a stagger, score columns grow in sequence, the field develops, the agent lamp breathes forever (`assets/css/base.css:262, 275`). Each is reasonable, together they exceed "one useful animation". The lamp also makes the dot look grey in some captures and white in others.
- At 390 the nav tabs and footer links look shorter than 44 px. Worth measuring.
- Demo bar: it hides the decision controls of the drawer at 390 (`exposed-drawer-390.png`) and the "Services answering" value on the 1440 first screen. Demo only, but every review capture is affected.

## 4. Other rules of the brief

| Rule | Result | Evidence |
| --- | --- | --- |
| No button in the alert colour | Pass | Scan is light, all other buttons are outlined neutrals; `tokens/components.css:12` |
| Red only for proved way, critical or exploited, broken feed | Fail | Score delta and last score column in red (S5); red rays for RDP and SSH that the findings call only "Reachable" (B2) |
| Not measured said in words, never 0, never dash | Fail | "n/a" everywhere (B3). No stray 0 found: zeros in `clear-*` are measured |
| No invented content outside demo mode | Pass as far as visible | All data is from `frontend/fixtures/`, behind the demo bar |

## 5. The 30 points of `design-anti-ia.md`

| # | Point | Verdict | Evidence |
| --- | --- | --- | --- |
| 1 | Loud gradients | Pass | No gradient in `assets/css` (grep) |
| 2 | Pure white background | Pass | `--neutral-900: #0b0a09`, `tokens/primitives.css:21` |
| 3 | Rainbow colours | Pass | Warm neutrals and one red ramp only |
| 4 | Violet and black | Pass | No violet |
| 5 | Neon | Pass, with a note | `--red-500 #ed4a31` is saturated; in the dense field it gets close to glowing |
| 6 | Basic pastels | Not applicable | No pastels |
| 7 | Inter, Geist, Space Grotesk | Pass | IBM Plex Sans and Mono, `tokens/fonts.css` |
| 8 | Em dashes | Pass | None in `frontend/app` (grep); "−16" uses a minus sign |
| 9 | "It is not X, it is Y" | Fail | "The evidence is there, not just the theory.", `utils/brief.ts:58` |
| 10 | Emoji | Pass | None |
| 11 | Check-mark bullets | Pass | None |
| 12 | Three feature cards in a row | Pass | Ruled columns, no cards |
| 13 | Bento grid | Pass | Two unequal columns, rules |
| 14 | Coloured left band on cards | Pass | Fix-first uses a top rule (`brief.css:52`); no left bands |
| 15 | Fake terminal window | Pass | `attacklens start` is a real command in a plain code chip |
| 16 | Three pricing tiers | Not applicable | |
| 17 | Fake testimonials | Not applicable | |
| 18 | No real demo | Not applicable | It is the product |
| 19 | Very rounded corners | Pass | `--radius: 2px`, `tokens/spacing.css:35`; 50 % only on the lamp dot |
| 20 | Shadows everywhere | Pass | One shadow, on the drawer only, `drawer.css:24` |
| 21 | Glassmorphism | Pass | No backdrop-filter, no blur |
| 22 | Blurred orbs and halos | Borderline | Login and 404 backdrop is a field of soft radial blobs drawn in glyphs at full contrast (`login-1440.png`) |
| 23 | Dot grids | Pass | Sparse dots in the field are not a grid |
| 24 | Sparkle icons | Pass | None |
| 25 | Lucide icons | Pass | No icon library imported |
| 26 | Animated arrows | Pass | None |
| 27 | Hover animations everywhere | Borderline | Several motion families on the brief plus an infinite lamp pulse; `prefers-reduced-motion` handled in `tokens/motion.css` and `utils/motion.ts` |
| 28 | No skeleton loaders | Pass | `loading-1440.png` skeletons follow the brief layout, frame included |
| 29 | No legal notice | Not applicable | Private tool behind a password |
| 30 | No privacy policy | Not applicable | Same |

## 6. Does it look generated?

No. It reads as a designed instrument: the reading line in the frame, the proof and since columns, the tinted critical rows, the outlined secondary buttons and the honest error copy are choices a template would not make.
The one thing that betrays it, in the other direction, is the glyph field: it is the signature, but at its current density the red ASCII bands read as data art before they read as measurement, and the floating labels ("A file you open", "Full control" alone at the edge) look placed for the picture rather than for the reader.

## 7. What works, do not touch

- The frame reading line: agent, read, from, probe, coverage, target, on every screen, red only when the feed is broken (`stale-*`, `api-error-*`).
- The API error copy: "This says nothing about the machine, good or bad." Exactly right.
- The no-agent verdict: "Not measured", one line on what is not visible, the command, then what the network did see, labelled as such.
- The findings table: severity mark and word, flaw in monospace, proof, since, right-aligned risk. Tint only on critical and exploited rows.
- The drawer's three questions: when to deal with it, can it be reached, can it be used, with banner evidence `+PONG`.
- The fix-first block: a top rule in red only when critical, the action phrased as a command.
- Skeletons that match the layout.
- IBM Plex, 2 px radii, no shadow but the drawer, warm near-black background, one red.
- Copy in plain verbs ("Bind Redis to the loopback address and require a password.").
