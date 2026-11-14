# Interface audit (step 1, read only)

Date: 2026-11-11. Scope: `frontend/` only. Nothing in the app was changed.

## 0. What differs from the brief

The brief describes a honeypot dashboard in HTML, Tailwind and vanilla JS. The repository is different, and
three decisions were taken with the owner before the audit:

| Brief | Repository | Decision |
| --- | --- | --- |
| `docs/design/design-web-anti-ia.md` | Missing. `../design-anti-ia.md` exists outside the repository | Use `../design-anti-ia.md` |
| `docs/design/attack-lens-design.md` (§ 5, 6, 7, 9, 11) | Missing everywhere. ADR-0017 records what was applied from it | Use the two PDFs next to the guide, plus ADR-0017 |
| Tailwind + vanilla JS | Nuxt 4, Vue 3, one plain CSS file with custom properties | Keep CSS and custom properties, no Tailwind |
| Timeline, heatmap, countries, sessions, period selector, live events | Not in the product (on-demand scanner) | Work on the existing views, mark the rest not applicable |

Sources actually read:

- `../design-anti-ia.md`, in full (30 points, texture catalogue, checklist).
- `../FREE sample - UI Design Systems Mastery.pdf`, text extracted in full (tokens, colour ramps, greys,
  limiting shades). It matches the "Méthode" section of the brief.
- `../free sample of web design mastery ebook.pdf`: **not read**. It has no text layer and no PDF renderer
  is installed on this machine. The brief's own rules (60-30-10, typography, grid) stand in for it.
- `docs/adr/0017-monochrome-and-vermilion.md` and `0014`, for the current visual language.

Consequence: § 5, 6, 7, 9 and 11 of `attack-lens-design.md` could not be checked line by line. Layout,
components, states and responsive are audited against the guide, the brief and ADR-0017. § 11 (hiding IP
addresses in public mode) has no counterpart in the code: there is no public mode, only a password gate
(`server/middleware/auth.ts`).

## 1. Map of the front end

| Item | Finding |
| --- | --- |
| Framework | Nuxt 4.6, Vue 3.5, TypeScript. Two pages: `pages/index.vue` (four views switched by a `ref`, no routes) and `pages/login.vue`, plus `error.vue` |
| Styling | One global file, `app/assets/css/main.css` (1790 lines). No Tailwind, no scoped styles, no preprocessor |
| Tokens | 12 colour variables, 2 font stacks, 4 sizes, in `:root` (`main.css:12-38`). One level only |
| Fonts | IBM Plex Sans and Mono, 400 and 500, bundled with Fontsource (`nuxt.config.ts:8-11`) |
| Charts | No library. Hand-written SVG (`OpticalBench.vue`, `Sparkline.vue`, `SeverityMark.vue`) and one canvas (`AsciiField.vue`) |
| Motion code | `AsciiField.vue` (canvas loop), `composables/useScramble.ts`, a spinner timer in `index.vue:31-39`, three keyframes in `main.css` |
| Data layer (not to touch) | `composables/useScan.ts`, `utils/scanApi.ts`, `server/` |
| Display logic | `utils/brief.ts`, `bench.ts`, `ascii.ts`, `findings.ts`, `format.ts` |
| Tests | `tests/dashboard.test.ts` (Vitest). Some guard display rules, for example the `—` placeholder at line 350 |

Components: `BriefView` (hero, KPIs, bench, actions, reachability, last change), `OpticalBench`,
`FindingLedger` (tabs and table), `FindingDrawer`, `MachineView`, `JournalView`, `SeverityMark`,
`Sparkline`, `AsciiField`.

## 2. Captures and measurements

Taken with Playwright (`playwright-core`, headless Chromium) against `nuxt dev`, with the API running on
a copy of the latest database backup, so nothing in the project data was written.

Files are in `docs/design/audit-captures/`: `brief`, `findings`, `machine`, `journal` at `-1440` and
`-390`, plus `drawer`, `focus`, `login`, `404`, `loading-1440`, `error-1440` and `measurements.json`.

Two caveats on the captures:

- The white pill at the bottom centre is the Nuxt DevTools button (`nuxt.config.ts:2-4`). It only exists
  in development.
- The backup holds a single network scan from Docker: two findings, no agent. Critical rows, the machine
  view, reachability bars, the journal and a real score trend are **not exercised**. Later steps need
  fixtures (`fixtures/demo-*.json`) and a visible demo mode to show them.

| Measurement | Result | Target |
| --- | --- | --- |
| Horizontal overflow at 390 px, four views | None (`scrollWidth` = 390) | None |
| CLS on load, 1440 px | 0.0013 | 0 |
| CLS on load, 390 px | 0.0297 | 0 |
| Running CSS animations under `prefers-reduced-motion` | 0, canvas still | 0 |
| Canvas redrawing without reduced motion | Yes, forever, 18 fps | Not allowed outside 404 and first load |
| Interactive targets under 24 px high | Footer links, 19 px | 44 px on a phone |

Contrast, computed from the token values (WCAG 2.1 formula):

| Text | Background | Ratio | AA (4.5) |
| --- | --- | --- | --- |
| `ink-50` | `ink-950` / `900` / `850` | 17.68 / 16.46 / 14.72 | Pass |
| `ink-200` | `ink-950` / `900` / `850` / `signal-950` | 9.66 / 8.98 / 8.04 / 8.13 | Pass |
| `ink-400` | `ink-950` / `900` / `signal-950` | 5.37 / 4.99 / 4.52 | Pass |
| `ink-400` | grid line (`#121212`) | 5.08 | Pass |
| `ink-400` | `ink-850` (hovered row) | **4.47** | **Fail** |
| `signal` | `ink-950` / `900` / `850` / `signal-950` | 5.58 / 5.19 / 4.65 / 4.70 | Pass |
| `ink-950` | `ink-50` (primary button) | 17.68 | Pass |
| Disabled button label (opacity 0.5) | `ink-900` | 3.16 | Exempt, but hard to read |
| `ink-400` label | over an ASCII glyph in `ink-600` (phone hero) | **2.02** | **Fail** |

## 3. Gaps, by visual impact

Rules are cited as G-n (point n of the anti-AI guide), G-T (its texture rules), B-Colour, B-Tokens,
B-Type, B-Grid, B-Motion (sections of the brief), and ADR-0017.

### High

| # | Gap | Where | Rule |
| --- | --- | --- | --- |
| H1 | An ASCII canvas runs permanently behind the hero, and again on the login page. It is the first thing seen and it never stops | `BriefView.vue:81,104`, `login.vue:23`, `AsciiField.vue:84-99`, `main.css:517-525` | B-Motion: ASCII only on 404 and first load, under 1.5 s. Banned: loops without meaning, decorative scan |
| H2 | The hero figure and headline "decode" from random glyphs each time they change, over 520 ms | `useScramble.ts:7-37`, `BriefView.vue:34-35` | B-Motion: no typewriter, no glitch, nothing over 400 ms, a KPI is replaced directly |
| H3 | With no agent, the main figure is an em dash set at 128 px. It reads as a white slab, not as a value | `BriefView.vue:34`, `main.css:556-561`, capture `brief-1440.png` | G-8, B-Type. Guarded by a test (`dashboard.test.ts`), so the replacement needs a decision |
| H4 | On a phone the ASCII band sits under the section label and the figure. Measured contrast 2.02 where a glyph is behind the label | `main.css:1660-1671`, capture `brief-390.png` | G-T 3 and 6: 3 to 8 % under text, AA over every texture |
| H5 | Two textures at once: the blueprint grid and the ASCII field | `main.css:296-299`, `AsciiField.vue` | G-T 1: one main texture |
| H6 | The bench takes 400 to 540 px of height whatever it holds. With two services, most of the panel is empty, and the page loses its density | `OpticalBench.vue:19`, `main.css:514` | Brief: dense and readable |
| H7 | Neutrals are pure grey (saturation 0) and the accent is at full saturation (`#ff3b2f`, S 100 %) | `main.css:13-27` | B-Colour: neutrals tinted from the base hue, 8 to 20 %. G-5: no neon, desaturated colours |
| H8 | Tokens have one level. Components use the raw ramp 150 times; there is no alias or component level, so a light theme cannot be wired | `main.css:12-38` and all of `main.css` | B-Tokens |

### Medium

| # | Gap | Where | Rule |
| --- | --- | --- | --- |
| M1 | No motion tokens. Durations and curves are written in place: `200ms ease-out`, `2s ease-out`, `1.6s ease-in-out`, `90` ms, `520` ms, `1600` ms | `main.css:1278-1279,1352`, `index.vue:37,114`, `useScramble.ts:7`, `MachineView.vue:46` | B-Motion: tokens only |
| M2 | The "arrived" row animates `background-color`, and the list does not move: the new row pushes the others at once | `main.css:1276-1295`, `JournalView.vue:57` | B-Motion: `opacity` and `transform` only, FLIP for insertions |
| M3 | The drawer declares `<Transition name="loupe">` but no `.loupe-*` class exists. It appears and disappears at once | `FindingDrawer.vue:72`, absent from `main.css` | B-Motion: menus fade and move 4 px in `--dur-fast` |
| M4 | Switching view replaces the content at once. No View Transition, no `view-transition-name` on the top bar | `index.vue:130,185-224`, `main.css:373-379` | B-Motion: view change |
| M5 | Skeletons do not have the shape of the content: a 120 by 48 block for a 128 px figure, five thin bars for a 400 px bench, nothing for the lower panels. Hence the layout shift (0.03 on a phone) | `BriefView.vue:78-99`, `main.css:1364-1400` | G-28, B-Motion: CLS 0 |
| M6 | Skeletons pulse forever, and the first load also shows the ASCII field sweeping | `main.css:1348-1362`, `BriefView.vue:81` | B-Motion: skeleton then a fade in `--dur-base` |
| M7 | Reduced motion uses `animation: none`, not the 1 ms rule of the brief, and does not cover view transitions | `main.css:1783-1790` | B-Motion |
| M8 | The focus ring is in the alert colour. On the login page the autofocused field looks like an error | `main.css:119-122`, capture `login-1440.png` | Brief: the alert colour marks a threat, not an action |
| M9 | Hex values are duplicated outside the token file, and the canvas does not read CSS variables | `utils/ascii.ts:180-181`, `app.vue:5`, `public/favicon.svg`, `main.css:35,297-298,1408,1532-1533` (raw `rgb()`) | B-Tokens: no hard-coded value, charts read `getComputedStyle` |
| M10 | No named type styles. 12 font sizes, 7 line heights and 4 trackings are written per selector. Titles use 1.35, the hero figure 0.82 | `main.css` (20 × 13 px, 20 × 12 px, 7 × 11 px, then 14, 15, 16, 20, 24, 28, 88, 72 to 128) | B-Type: `display`, `heading-l`, `heading-m`, `body-m`, `body-s`, `label`, `data`; 1.1 to 1.2 for titles |
| M11 | Secondary text on a hovered row falls to 4.47:1 | `main.css:854-856,1060-1062` with `.action-reason`, `.row-status`, `.row-title small` | B-Colour: AA everywhere |
| M12 | Em dash as the empty value in six other places | `format.ts:2`, `BriefView.vue:127,142,149`, `MachineView.vue:77,84` | G-8 |
| M13 | Sparkline, legend and reachability bars carry no skeleton and no "stale" treatment. Stale data is only a red sentence in the top bar | `index.vue:136-139`, `main.css:428-430` | Brief step 4: stale state |
| M14 | Bars are sized with inline `width`. Any future value change would animate `width` | `BriefView.vue:96,204`, `FindingLedger.vue:139` | B-Motion: `transform` only |

### Low

| # | Gap | Where | Rule |
| --- | --- | --- | --- |
| L1 | A 2 px band on the left of the command block | `main.css:1200` | G-14 |
| L2 | Section labels are numbered `(01)` to `(05)` on the brief only, not on the other views | `main.css:149-154`, `BriefView.vue:106,158,172,198,212` | Consistency |
| L3 | Active tab and view are drawn with `box-shadow: inset`. Harmless today, but it is the property a hover transition would animate | `main.css:405-415,1016-1025` | B-Motion |
| L4 | Footer links are 19 px high, buttons 28 to 32 px, on a phone too | `main.css:217-251,1508-1517` | Responsive, touch targets |
| L5 | The spinner is a Braille glyph cycled by a timer | `index.vue:31-39,153` | B-Motion: sober indeterminate indicator, token durations |
| L6 | `.hero` is declared twice; `.text-signal` needs `!important`; `--delay` is set on rays and never read | `main.css:499-507,185-187`, `OpticalBench.vue:41,136` | Hygiene |
| L7 | The 404 field is allowed, but it loops forever and also shows on other errors | `error.vue:13` | B-Motion: under 1.5 s, 404 only |
| L8 | `system-ui` is the fallback of the sans stack | `main.css:29` | G-7. Acceptable as a fallback, to confirm |

## 4. What already complies

- No gradient, glass, glow, emoji, Lucide icon, check mark, fake terminal bar or bento grid.
- One accent, used sparingly: on the captures it appears on severity dots, the error dot and the focus ring only.
- The primary button is light grey, never red (`main.css:234-245`).
- Radius 2 px everywhere, 1 px rules, a shadow on the floating drawer only.
- Severity always carries its word (`SeverityMark.vue`).
- 12 columns, 1440 px maximum, 24 px gutters, 16 px on a phone (`main.css:302-326,1623-1627`).
- Fonts: IBM Plex Sans and Mono, two weights, tabular figures on `body`.
- No horizontal overflow at 390 px; tables become lists.
- Error banner, empty states and loading skeletons exist.
- Canvas and scramble stop under `prefers-reduced-motion` and on hidden pages.
- No scroll animation, no `hover:scale`, no parallax.

## 5. Not applicable here

Timeline, heatmap, country list, captured sessions, period selector (24 h, 7 d, 30 d), live event feed
with grouping above 5 events per second, table sorting (the ledger has tabs, no sort), IP masking in a
public mode. Their motion rules apply to the nearest existing element: the journal list for insertions,
the ledger tabs for filtering, the hero KPIs for value updates.

## 6. Questions for step 2

1. The `—` placeholder is protected by tests and by ADR-0017 ("never `0` without the view from inside").
   Proposed replacement: the word "Unknown" in `heading-m` for the hero, and `n/a` in data cells.
2. The ASCII hero was requested explicitly in ADR-0017. The brief now bans it outside 404 and first load.
   The audit assumes the brief wins.
3. Fixtures and a demo mode are needed to show critical rows, the machine view and the journal.
