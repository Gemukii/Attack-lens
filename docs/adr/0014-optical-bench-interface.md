# ADR-0014: Interface, the optical bench

**Status:** Accepted. The visual language is superseded by [ADR-0017](0017-monochrome-and-vermilion.md)
**Date:** 2026-11-05
**Deciders:** Gemukii

## Context

Two versions of the dashboard were judged "AI-generated". The second changed the palette without
changing the structure: monospace everywhere, uppercase labels, condensed headings, grain, a big hero
number, a row of statistics. The problem was the template, not the colours.

A security tool also has a requirement of its own: **the interface must never falsely reassure**.

## Decision

**Concept.** The main view is an optical bench. Each service is a ray leaving the network, the
firewall is a diaphragm, services and the account are lenses, and the focus is "Full control". A
blocked ray hits the diaphragm, and an attack path reaches the focus.

**Visual language.**

- Three colours: ink `#15120E`, paper `#ECE4D3`, safelight red `#EB3F21`. Everything else is
  transparent paper, and red is reserved for what leads to danger and for the trigger.
- Newsreader for text and Hanken Grotesk for the interface, bundled locally. Monospace is reserved
  for commands.
- A summary sentence instead of number tiles.
- Solid line for proved, dashed for unproved.
- Severity is carried by shape, never by colour alone.
- Four views: Brief, Findings, Machine, Journal.
- All interface text is in English, like the backend messages.

## Options Considered

### Option A: data-driven optical bench (chosen)

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium: one custom SVG component |
| Cost | Design time |
| Scalability | Limited to 7 drawn rays |
| Team familiarity | Medium |

**Pros:** specific to the product, readable at a glance, the drawing is the data.
**Cons:** a concept to learn, hence the legend and the hover explanation.

### Option B: classic dashboard, cards and charts

| Dimension | Assessment |
| --- | --- |
| Complexity | Low |
| Cost | Low |
| Scalability | Good |
| Team familiarity | Good |

**Pros:** familiar and quick to produce.
**Cons:** rejected twice: indistinguishable from all the others.

### Option C: radar or node graph

| Dimension | Assessment |
| --- | --- |
| Complexity | Medium |
| Cost | Medium |
| Scalability | Medium |
| Team familiarity | Medium |

**Pros:** visually strong.
**Cons:** "cyber" clichés, with no link to the product's name.

## Trade-off Analysis

The drawing carries meaning, so it can lie. Two mistakes showed this: unproved rays drawn solid
because of `pathLength`, and the "No way in" heading shown without an agent, when nothing had been
looked at from the inside. Any visual change must check that the drawing and the text say the same
thing as the data, including without an agent or a probe.

The layout stays horizontal on mobile, because a vertical variant produced collisions.

## Consequences

- **Easier:** recognising the product and understanding a situation in a few seconds.
- **Harder:** showing many services: beyond 7, they are not drawn.

## Action Items

1. [x] Optical bench, separate views, and states without data, without an agent and without a
   response.
2. [x] Tests guaranteeing dashed lines and no false reassurance.
3. [ ] Show that there are more services than drawn rays.
