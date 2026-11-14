# Independent review of directions A, B and C

Written by a reviewer that had not seen how the screens were made. It was given three things only:
the 30 captures of `directions/captures/` (A, B and C), the checklist of `design-anti-ia.md`, and the
three questions the interface must answer. The text below is its report, unedited.

Direction D was built after this review and has not been reviewed independently yet.

---

DESIGN REVIEW: directions A, B, C

Scope: all 30 PNGs opened, plus the checklist. Nothing else read. From stills I cannot judge checklist points 26, 27, 28 (motion, hover, skeletons) or reduced-motion, and I cannot confirm font identity, only what the letterforms look like.

Issues common to all three (content, not styling):
- Numbers disagree. The bench says "Services, 7 answering" and draws 7 ports; the metric says "Services answering 8"; the machine view lists 8 (port 902 is missing from the bench). The hero says 5 ways to full control, but the bench draws 4 rays reaching it. A professional sees this at once, and it damages Q3.
- Vocabulary drifts: "confirmed", "proved reachable", "reachable", "Confirmed by a test". "Three confirmed ways in" on the brief, but only one finding row says "Confirmed by a test".
- Priority order disagrees. The brief puts the admin-account fix second; the findings list ("the first line is the first thing to fix") puts it fifth, behind RDP and WinRAR.
- "Network score 58 / 100" never says whether 100 is good or bad.

---

1. FIVE-SECOND TEST (brief, 1440)

a-brief-agent-1440: State is obvious: "5", "3 confirmed" in red, "Three confirmed ways in." Priority is obvious: the red Critical card under "Fix first" (bind Redis) sits top right, level with the state. Trust is visible in the header ("desk-07 online, Read 2 h ago"). Pass.

a-brief-no-agent-1440: State is not obvious. The headline is a dim grey "Not measured", while a Critical exposure, a score of 46 and four answering services sit on the same screen. It reads as "unknown", when the truth is "blind on the host and exposed on the network". Priority is mostly clear (Redis card), but the white "Connect the agent" button competes as a second call to action.

b-brief-agent-1440: State obvious (top left). Priority obvious (wide Critical band, top right). Trust is the best of the three: the AGENT / READ / FROM / PROBE / COVERAGE / TARGET strip sits directly under the nav. Everything, bench included, fits in about 900 px. Pass, and the fastest read.

b-brief-no-agent-1440: Same state ambiguity as A ("Not measured" in grey beside a Critical). The strip's "None connected" and "Probe: None yet" make the blindness clearer than in A. Priority obvious.

c-brief-agent-1440: State obvious (largest "5" of the three). Priority is not obvious. "Fix first" starts around y=830, under a 400 px tall drawing, so it is below the fold on a 900 px laptop screen. In five seconds you see red rays for Redis, RDP and SSH, which is where the exposure is, not what to do first.

c-brief-no-agent-1440: Fails both. State reads "Not measured". The strongest element is the navy "Connect the agent" button, so the perceived priority is connecting the agent. The Critical Redis card is at about y=770, at or under the fold, and easy to miss.

---

2. THE THREE QUESTIONS

Direction A
- Q1: Strong with an agent. Weak without (grey "Not measured" understates a Critical). On phone (a-brief-agent-390) the state is at the top of the first screen.
- Q2: Strong. Critical card plus numbered 02 to 04 list, each with its evidence line. On phone, "Fix first" starts around y=520, inside the first screen. The findings list (a-findings-1440, a-findings-390) is clear, and the phone version stacks well.
- Q3: Good. Agent and read age in the header on every page, plus the READ / FROM / PROBE / COVERAGE / TARGET row. "Proved reachable 3, probe 1 d ago" honestly shows that the proof is older than the read. The no-agent bench states what cannot be followed. Weakness: "Read 2 h ago" appears twice (header and row), and the row is buried mid-card under the headline.

Direction B
- Q1: Same as A. On phone the six-row context strip pushes the "5" down to about y=330 (versus about 190 in A and C), still on the first screen.
- Q2: Strongest on desktop. The fix list gets the wide column and long lines do not wrap. Phone: "Fix first" at about y=490.
- Q3: Best. The strip is persistent and identical on brief, findings and machine. Cost on phone: about 150 px on every page (b-findings-390, b-machine-390).

Direction C
- Q1: Strong with an agent, weak without.
- Q2: Weakest. The drawing is placed before the fix list on desktop and on phone. In c-brief-agent-390 "Fix first" starts around y=1110, more than one full screen down. The order shown is state, trust, picture, action, not the order required.
- Q3: Good. The boxed READING table is the most legible trust block, but the header carries no agent state, and the table changes shape between pages (2 columns on the brief, 6 on findings and machine).

---

3. CHECKLIST

Direction A
- Point 13 (bento), borderline: the brief is four bordered cards of unequal size on a patterned background (a-brief-agent-1440). This is the most "generated dark dashboard" trait in A.
- Point 9, borderline (all three): "The evidence is there, not just the theory."
- Point 23: the background is a fine line grid, not dots. Acceptable, faint, tied to the subject.
- Points 2, 3, 7, 14, 19, 20, 21, 22, 25: no violation seen. Warm graphite ground, one accent, a Plex-looking sans and mono, square corners, no shadows, no stock icons (the signal-bar severity mark looks custom).
- Hacker scenery: no terminal, no green. But the red beam fan on near-black in a-bench-1440 is the most theatrical image in the set and edges towards "laser threat map".

Direction B
- Point 3, violated: three hues carry meaning (red-orange, amber, steel-blue Medium dots). It is a traffic-light severity palette.
- Point 7, borderline: the sans reads as a neutral grotesque that is hard to tell from Inter or Geist at a glance. Slashed zeros in running prose and headings ("desk-07", "10 readings") are a tech affectation.
- Delivery checklist "one texture linked to the subject": none. B is completely flat.
- Point 9, borderline (shared).
- Points 13, 14, 19, 20: clean. Ruled columns, no cards. The best editorial structure of the three.
- Generic look: yes. Cool navy-black with coloured status dots is the stock developer-tool dark theme. B is the one most likely to be mistaken for a template.

Direction C
- Point 2, borderline: the surfaces are a cold near-white, the "clinical" look the checklist warns about, even if not pure #FFFFFF.
- Point 9, borderline (shared).
- Point 23: the blueprint grid is confined to the drawing. Correct use, labels stay legible.
- Generic traits: the pink-filled Critical box and the pink table rows (c-findings-1440) look like stock "danger alert" components.
- Costume: "DRAWING:", "REDLINES:", the READING title block. Mild engineering-drawing role-play, not hacker scenery, but "Redlines" is jargon for its own sake.
- Points 3, 7, 13, 14, 19, 20: no violation. Barlow-like condensed type, one hue, square corners.

---

4. ACCENT DISCIPLINE

No direction uses the accent on a button. Scan and "Connect the agent" are neutral in all three, as are the active tab and the links. Good.

Shared problem: red changes meaning between screens. On the bench it means "leads to full control". In the machine table it means "Reachable". In the findings table "Reachable" is neutral, and red means "Confirmed by a test" or "Exploited in the wild". RDP has a red ray on the brief and no red in the findings.

Direction A: One hue, always threat-related, but not rare on the agent brief. The same fact (3 reachable) is painted red at least four times: "3 confirmed", "Proved reachable 3", the "Reachable from outside" bar and count, three rays. Add the Critical card, the "-16" and the sparkline dot. Two red masses of similar weight compete: the Critical card and the beam fan. On a-brief-no-agent-1440, a-findings-1440 and a-machine-1440 it is rare and works. The no-agent legend shows a red "Leads to full control" swatch although no red ray exists.

Direction B: Fails the brief. Amber is a second accent and is used for things that are not threats: "New" (freshness, three times in b-findings-1440), the score delta, the sparkline dot. Amber dots mark every High row. The "A file you open" ray is dashed amber in b-bench-1440, an encoding absent from the legend. Blue-grey Medium dots add a third signal colour.

Direction C: One hue, but spread thin. Every High gets a red hollow square (five in c-findings-1440, three in the brief list), plus pink fills. Red on white is louder than on dark. Two reds are in use: darker crimson for text ("3 confirmed", "Reachable"), brighter vermilion for squares and rays. "Known flaws 1" is not red in c-machine-1440, though it is in A and B.

---

5. DEFECTS

All three
- Tabs wrap on phone, leaving "Dismissed 1" orphaned on a second line (a-findings-390, b-findings-390, c-findings-390).
- No-agent bench: the upper ghost firewall stub butts against the header rule or frame edge (a-, b-, c-brief-no-agent-1440; in c-brief-no-agent-390 it sits on the frame border). The stubs look like stray artefacts. The ghost account lens is barely visible in A.
- The dash-dot optical axis runs straight out of the "SSH 22" label, like a strikethrough continuing the text (all bench crops).
- At 390 the "Full control" label sits against the dashed ray and at the content edge (a-bench-390, c-bench-390).
- Stage captions (Firewall, Services, Your account) sit 100 to 250 px below the shapes they name.
- Legend: the "Proved from outside" swatch is brighter than the dim grey lines it describes, and "proved" reads as "proved reachable" when those lines are the blocked ones.
- Mono evidence text in finding rows ("DESK-07\m.rivers is a member of Administrators") is small and low contrast. The "Low" severity label and "n/a" are near the readability limit.
- Mono strings with wide word spacing look broken: "4 of 12", "2 h ago · desk-07.example.com".
- A sparkline of 3 readings (no-agent) is a bent line, not a trend.
- Wide dead gap between the Finding and Proof columns at 1440.

Direction A
- Card bottoms do not align: the bench card ends about 17 px below the right-hand stack (a-brief-agent-1440); same raggedness in a-machine-1440.
- Empty band under the metrics row in the top card (about y=480 to 540).
- Signal-bar icon: the difference between 2 and 3 bars is not distinguishable at that size; only the word carries severity.

Direction B
- Sparkline floats to the right of the score, detached from the number and from "10 readings" (b-brief-agent-1440).
- On phone the strip's "FROM" value is vertically centred against the two-line "PROBE" value, so the label-to-value gap is uneven (b-brief-agent-390, b-machine-390).
- Machine right column: section headings follow the previous content with little separation (b-machine-1440).

Direction C
- READING table has an empty cell to the right of COVERAGE, with a broken L-shaped border (c-brief-agent-1440 and all 390 captures). Same FROM misalignment as B on phone.
- Container inconsistency: the brief card has 24 px margins; the findings and machine cards run flush to the viewport edge (c-findings-1440, c-machine-1440, and the 390 versions).
- About 250 px of dead space in the lower left of c-brief-agent-1440, and about 100 px blank between the headline and the drawing label.
- Longest pages: about 1480 px for the desktop brief versus about 1015 (A) and 950 (B). Least dense.
- Sparkline about 70 px away from its number.
- Bench captions at 390 are about 8 to 9 px ("7 answering", "Not measured"): too small. Box inside box wastes width on phone.
- Condensed uppercase micro-labels are the hardest to read of the three.
- Active nav item has no visible underline at 1440.

---

6. RANKING

1. Direction A. It is the only one that meets the accent rule (one hue, threat only, never an action) and also answers Q1 and Q2 on the first screen at both widths, with Q3 in the header. Its warm graphite and Plex-like type are the least template-like dark treatment here.
   Biggest weakness: red is overworked on the agent brief. The same "3 reachable" fact is red four times, and the beam fan competes with the "Fix first" card, so the screen is less calm than an instrument should be. The boxed-card layout adds to that.

2. Direction B. It has the best skeleton: densest, flat ruled columns, persistent trust strip, fix list given the most room. It loses on the rule that matters most: amber as a second accent on non-threats, an unlabelled amber ray, three signal hues. It is also the most generic-looking and has no texture.

3. Direction C. The most distinctive and the calmest, and the drawing reads best on a light ground. But it puts the drawing ahead of the action: "Fix first" is below the fold on desktop and more than a screen down on phone, and in the no-agent state the Critical finding is easy to miss. It is also the least dense and has the most layout defects.

One improvement to note for whichever is chosen: B's context strip and ruled, card-free structure are what A lacks, and the no-agent headline needs to stop reading as "nothing known" when a Critical is on screen.
