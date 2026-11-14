# Reading order, screen by screen (step 2a)

Text only, written before any visual work. It fixes what each screen is for and in which order it is
read. The three directions of step 2c are judged against this document, not against taste.

## The three questions

Every element must serve one of them, in this order of priority. An element that serves none is
quiet, or goes.

| | Question | Carried by |
| --- | --- | --- |
| Q1 | Am I exposed right now? | The verdict of the brief, the bench |
| Q2 | What do I fix first? | The first action of the brief, the order of the findings |
| Q3 | Can I trust this data? | The reading line: when, from where, by what, and what was not seen |

Two rules follow, and they apply everywhere:

- **One focal point per screen.** If two things compete, the second one loses size, weight or position.
- **Q3 is never a separate page.** Trust travels with the claim it qualifies: a figure is always next to
  its date, its vantage point and its limits. A value that was not measured says so in words, never
  with a `0` and never with a dash.

## The frame, on every screen

Question: is what I am looking at current, and who measured it?

| Order | Element | Why |
| --- | --- | --- |
| 1 | Agent state: online, quiet since when, or absent | Decides how far every other number can be trusted (Q3) |
| 2 | Age of the last reading, and of the last answer from the API | A three-week-old verdict is not a verdict (Q3) |
| 3 | The Scan control | The only action that renews the data |
| Quiet | Product name, view switcher | Navigation, not information |
| On demand | Printable report, refresh, enrolling another machine | Rare actions, kept out of the reading path |

Today the agent state is a sentence in the footer and a banner that appears only when the agent is
missing. It moves into the frame and stays there in every state.

## Brief

Question: **am I exposed right now, and what do I do about it?** (Q1, then Q2)

| Order | Element | Content |
| --- | --- | --- |
| 1 | The verdict | One sentence in plain words ("Two confirmed ways in.") with its figure, the number of ways to full control. The accent appears here only when a way in is confirmed |
| 2 | The first thing to fix | The top action: what to do, on which service, and how many ways in it closes. It sits next to the verdict, not below the fold |
| 3 | The reading line | Target, time of the reading, vantage point (from the machine, from Docker), whether a probe from outside agrees, ports checked |
| Secondary | Network score and its trend, services answering, proved reachable | Context for the verdict. They are data, set small and aligned, not three more headlines |
| Secondary | Actions two to four, reachability breakdown, last change | Read after the decision is made |
| Below | The optical bench | The explanation of the verdict, see next section |

When the agent is absent the verdict cannot be given. The focal point becomes the **not measured**
state: a medium-size sentence in muted text, one line saying what is not visible (attack paths, the
firewall, the account), and the action that fixes it (start or reconnect the agent). What the network
scan did see (services answering, score) stays visible as secondary data, clearly labelled as the
view from outside.

Change from today: the actions move up beside the verdict, and the three KPIs lose their headline
size. The bench is no longer the second thing read.

Amended at the end of step 2 (direction D, "Glyph field"): the bench sits in the hero, to the right
of the verdict and the first action, not below them. It is the one image of the interface and it is
meant to be seen. The verdict keeps the first place by size and position; the independent review of
step 5 judged that the field still pulls the eye first, which is accepted.

## Optical bench

Question: **by which route does the network reach full control, and where is each service stopped?**
(the "why" behind Q1, and the target of Q2)

| Order | Element | Content |
| --- | --- | --- |
| 1 | Any ray that reaches "Full control" | The only place the accent is allowed on this figure |
| 2 | Where the other rays end | Stopped at the firewall, or through it with no known path beyond. Solid means proved from outside, dashed means not proved |
| 3 | The state of each station | Firewall on, off or unknown; services answering; the account, administrator or not |
| Secondary | Service names and ports on stopped rays, the caption | Needed to act, not to understand |
| On demand | The detail of a ray | Opens the finding |
| Hidden | Rays beyond seven | Replaced by a count and a link to the findings |

The height follows the number of rays instead of staying between 400 and 540 px. With nothing
measured the bench is not drawn empty: it gives way to one line saying that no service has been read.

## Findings

Question: **what is open, in the order I should deal with it?** (Q2)

A row is read left to right in one pass:

| Order | Element | Content |
| --- | --- | --- |
| 1 | Severity | Mark and word. A critical or exploited row is tinted, and it is the only tinted thing on the screen |
| 2 | What and where | Title, then port, process or target in monospace |
| 3 | Proof | Reachable, blocked, not proved, exploited in the wild, confirmed by a test |
| 4 | Since when | New since the last reading, or the date it first appeared |
| 5 | Risk | The number, right-aligned. It is the sort key, so it confirms the order rather than leading it |
| On demand | What to do, why it matters, evidence, decision | In the drawer |
| Secondary | Tab counts | Network, machine, updates, autostart, dismissed |
| Hidden | Informational findings, dismissed ones | Behind their tab or a control |

The list is already sorted by risk, so the first row is the answer to Q2. The focal point is that
first row, not the page title.

## Machine

Question: **what does this machine offer to others, and what did the agent actually see?** (Q1 from
the inside, and Q3)

| Order | Element | Content |
| --- | --- | --- |
| 1 | What listens beyond this machine | The count, then the table: port, program, open to which networks |
| 2 | The firewall | On, off, partial or unknown. Off is the one state that takes the accent |
| 3 | Proof from outside | Whether a probe from another machine has run, when, and what it found. If not, the command to run |
| Secondary | Updates waiting, programs that start by themselves | Counts that lead to the findings |
| Secondary | Operating system, date of the host report | The reading line of this screen |
| Hidden | Where AttackLens itself runs | Collapsed. It describes the tool, not the machine |

Without the agent this screen has nothing to show. Its focal point is then the same not-measured
state as the brief, with the same action.

## Journal

Question: **what changed since last time, and who decided what?** (Q1 over time, and Q3)

| Order | Element | Content |
| --- | --- | --- |
| 1 | The most recent change | A new finding, a port that opened, a score that dropped. Newest first |
| 2 | When and where | Timestamp and target, in monospace |
| 3 | Decisions | Risks accepted, false positives, scans requested, with their date |
| Secondary | The comparison of two readings | A tool, used on purpose |
| Hidden | Older entries | Beyond the first screen |

A new line arriving while the page is open is the only motion on this screen.

## Score trend

Question: **is it getting better or worse, and since when?** (Q1 over time)

| Order | Element | Content |
| --- | --- | --- |
| 1 | The direction of the last change | The delta between the last two readings. A drop of ten points or more takes the accent |
| 2 | The line over the period | With the reading where it changed |
| 3 | How much data stands behind it | Number of readings and the dates they span. Three readings are not a trend, and the screen says so |
| Secondary | The period control | |
| On demand | The value of each reading | On hover or focus, and as a table for screen readers |

## Open points

1. **"Since when" is not in the API.** A finding carries no first-seen date. It can be derived on the
   display side from the alert that introduced it, without touching the API. Where no alert exists the
   cell stays empty rather than guessing.
2. **The trend is a 120 px sparkline today**, inside a KPI. The history it needs is already loaded
   (`/api/scans`), so a period control is display work only. Proposal: keep the sparkline in the brief
   as secondary data, and give the full trend a panel at the top of the journal, where "what changed"
   lives, rather than a fifth view.
3. **The agent state moves into the frame.** This removes the grey banner that is on screen in every
   capture of the audit and pushes the content down.
