## Design Concept
This deck serves a technical/academic security briefing, merging the rigor of an academic defense with the polish of a high-end editorial cyber-research publication. The visual anchors are MIT Technology Review (for its strict grid and dark-mode editorial typography) and Edward Tufte (for high data-ink ratio and elimination of chartjunk). The color story honors the request: a deep midnight-navy canvas forms the base, establishing a quiet, terminal-like depth. Text is rendered in crisp slate-white, while bright cyan marks defensive controls and structural data, contrasted against a restrained amber for risk bands and caveats. We bypass the cliché of glowing matrix-green code rain and neon padlocks entirely; instead, the aesthetic relies on architectural precision, clean CSS-based geometric diagrams, and raw typographic hierarchy. The typographic voice pairs a technical, engineered sans-serif (Space Grotesk) for headings with an ultra-legible geometric sans (Inter) for dense research body text.

## Visual Language
- **Imagery**: Minimal and structural. The cover features a text-free, abstract geometric cybersecurity illustration (e.g., intersecting grid lines, layered planes). Content pages use no photography, relying entirely on CSS-built architecture diagrams and data charts.
- **Containers**: Grid-based and flush. Use hard-edged rectangles with thin 1px borders (`#334155`). Absolutely no rounded corners, drop shadows, or floating generic cards. 
- **Icons**: Razor-thin outline SVGs (1px stroke), used only as functional diagram nodes or metric labels. No decorative icons.
- **Dataviz**: Flat, high-contrast, and unshaded. Tables use thin horizontal rules (cyan for header, slate for body) with no vertical borders. Charts utilize cyan (`#06B6D4`) for defensive baseline metrics and amber (`#F59E0B`) for risk signals.
- **Motif**: A precise bracketed hex-index mark (e.g., `[ W-SHARK // SYS ]`) placed in the top-left corner at 12px, serving as a constant terminal-like orientation anchor across all slides.

## Layout Directives
- **Global**: 60px margins on all sides. Top-left motif, top-right slide number / total (e.g., `01 / 10`), bottom-left concise source citations. Strict left-alignment for all text and containers.
- **Cover**: Massive title and subtitle, left-aligned, anchored by the text-free structural cybersecurity illustration on the right half.
- **Literature Review / TOC**: Strict, grid-based list. No basic bullets; use large numbers and cyan dividers to separate prior work/topics.
- **Section Dividers**: Stark minimalism. A massive numeric index (e.g., `03`) with a horizontal cyan rule traversing the slide, followed by the section title.
- **Closing**: Echoes the cover's dark geometric illustration, emphasizing the final URL/repository link in bold cyan.

| id | pattern | image | density |
| :--- | :--- | :--- | :--- |
| cover | split title left, abstract illustration right | hero | low |
| introduction | side-by-side text block and list | none | medium |
| literature | 3-column comparative literature grid | none | high |
| problem | statement top, scope boundaries bottom | none | medium |
| methodology | horizontal process pipeline diagram | none | high |
| architecture | large central system block diagram | none | high |
| scoring | half-donut chart left, metric table right | none | high |
| results | dual-chart comparison (baseline vs validation) | none | high |
| conclusion | bulleted takeaways and next steps grid | none | medium |
| references | dense, 2-column numbered citation list | none | high |

## Design Tokens

| token | hex | usage |
| :--- | :--- | :--- |
| canvas-bg | #0B1120 | Deep midnight-navy slide background |
| surface-bg | #151E32 | Slightly elevated navy for diagram blocks and tables |
| text-main | #F8FAFC | Primary white/slate for headings and body |
| text-muted | #94A3B8 | Dim slate for captions, citations, and secondary text |
| border-rule | #334155 | Grid lines, table rows, and structural dividers |
| accent-cyan | #06B6D4 | Defensive controls, primary chart data, key highlights |
| accent-amber | #F59E0B | Risk indicators, caveats, warning data points |

| role | family | size (px) | applies_to |
| :--- | :--- | :--- | :--- |
| display | Space Grotesk | 48 | Cover title, major section numbers |
| heading | Space Grotesk | 32 | Slide titles, key takeaways |
| body | Inter | 18 | Paragraphs, diagram labels, literature details |
| caption | Inter | 14 | Source citations, footnotes, top-left motif |

## Guardrails
- **Forbidden**: Neon glow effects or drop shadows (violates the flat editorial strictness).
- **Forbidden**: Stock photography of hackers, padlocks, or binary code.
- **Forbidden**: Generic bullet point lists without grid/structural containment.
- **Forbidden**: Rounded corners on any container, chart, or table element.
- **Size floors**: Body text must never drop below 18px; citations/captions strict floor at 14px.
