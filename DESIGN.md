# Design System & UI Guidelines

A concise, product-agnostic reference for visual design, interaction patterns, and how design decisions should be documented and implemented across applications. Use this as a shared baseline for mobile, TV, and desktop clients unless a platform explicitly overrides it.

---

## 1. Principles

1. **Clarity over decoration** — Users should perceive primary actions and current state within one glance. Ornament must not compete with content.
2. **Consistent affordances** — Same visual language for the same behavior everywhere (e.g., one primary-action treatment, one card pattern).
3. **Progressive disclosure** — Show the minimal surface needed for the current task; move power-user or risky options behind an explicit “Advanced” or settings path.
4. **Respectful of context** — Input constraints (remote, touch, keyboard), privacy (sensitive fields), and system integrations (VPN, notifications) shape layout and copy, not the other way around.
5. **Accessible by default** — Contrast, touch targets, and semantic structure are requirements, not stretch goals.

---

## 2. Layout & structure

- **Spacing scale** — Use a small fixed set (e.g., 4 / 8 / 12 / 16 / 20 / 24 / 32) and apply it consistently. Avoid arbitrary one-off gaps.
- **Reading order** — Top to bottom: orientation (where am I?) → primary state → primary action → secondary actions and metadata.
- **Touch targets** — Minimum ~48×48 dp (or platform equivalent) for interactive elements; increase spacing between dense controls on small screens.
- **Cards & grouping** — Group related controls in rounded containers with subtle borders or elevation. One primary card per screen for the main task when possible.
- **Safe areas** — Respect system insets (notches, gesture bars, TV overscan). Do not place critical actions in unsafe regions.

---

## 3. Color

- **Semantic roles** — Define tokens for: background (base, elevated), surface (card), border (subtle, focus Primary text, secondary/muted, accent, success, warning, danger. Avoid hard-coding one-off hex values in components; map them to tokens.
- **Contrast** — Aim for **WCAG 2.1 AA** for body text (4.5:1) and large text (3:1). Test primary actions against both light-on-dark and dark-on-light if both exist.
- **Accent discipline** — Use one primary accent for “go / active / connected.” Secondary accents only for distinct semantic states (e.g., warning).
- **Dark UIs** — Prefer slightly **off-black** backgrounds and **elevated** surfaces that step up in lightness; avoid pure black next to harsh white text for long reading sessions.

### Suggested token names (example)

| Token            | Typical use                    |
|------------------|--------------------------------|
| `bg.app`         | Root screen background         |
| `bg.surface`     | Cards, sheets                  |
| `border.subtle`  | Dividers, card outlines        |
| `text.primary`   | Headings, values               |
| `text.secondary` | Captions, hints                |
| `text.accent`    | Labels, links (non-destructive)|
| `accent.primary` | Key CTAs, active indicators    |
| `state.success`  | Connected, completed           |
| `state.danger`   | Destructive / errors           |

---

## 4. Typography

- **Type scale** — Define a limited set: display / title / body / caption / overline (small caps labels). Do not exceed ~6 distinct sizes per platform.
- **Weights** — Use weight for hierarchy (e.g., semibold for titles, regular for body). Avoid ultra-light weights on small sizes.
- **Line length** — On phone-width layouts, favor full-width stacks; avoid multi-column text. On tablet/desktop, cap line length for readability (~60–75 characters) where applicable.
- **Locale** — Leave room for longer strings in translations; avoid fixed-height single-line labels for user-generated or localized copy.

---

## 5. Iconography & imagery

- Prefer **simple, recognizable** system or custom icons aligned to the same stroke/corner style.
- **Emoji as UI** — Acceptable for low-friction prototypes or informal apps; for production, prefer vector icons for accessibility and consistency across OS versions.
- **Status indicators** — Pair color with shape or text; do not rely on color alone (e.g., “Connected” + dot, not only a green dot).

---

## 6. Motion & feedback

- **Duration** — Short (100–200 ms) for micro-interactions; avoid long decorative animations blocking input.
- **Purpose** — Motion clarifies **state change** (expand/collapse, connect/disconnect), not brand vanity on every tap.
- **Reduced motion** — Respect OS “reduce motion” / accessibility settings; provide equivalent non-animated feedback.

---

## 7. Interaction patterns

- **Primary action** — One clear primary per view; visual weight (color, size) matches importance.
- **Destructive actions** — Require confirmation or an undo path when data loss or billing impact is possible.
- **Loading & errors** — Show explicit progress for operations &gt; ~1 s. Errors: what failed, what the user can do next, no raw stack traces in UI.
- **Forms** — Label fields; group server/identity vs. advanced transport; mask secrets with optional reveal; persist drafts where appropriate.

---

## 8. Content & voice

- **Tone** — Direct, calm, technical when needed, without blame (“Couldn’t connect” not “You failed”).
- **Titles** — Use sentence case unless brand guidelines specify otherwise.
- **Units & data** — Show meaningful precision (latency with ms, addresses with ports) and avoid fake metrics if the app cannot measure them.

---

## 9. Platform notes

- **Android (phone)** — Material 3 can underpin components; still align colors/spacing to this document’s tokens. Foreground services and VPN require clear ongoing status communication.
- **Android TV** — Declare **TV launcher** metadata (`LEANBACK_LAUNCHER`), banners, and `touchscreen required=false` so sideloaded apps appear in the launcher. Simplify navigation for D-pad.
- **Desktop / web** — Keyboard shortcuts, focus rings, and window resizing should behave predictably.

---

## 10. Design–engineering handoff

- **Single source of truth** — Tokens (color, type, radius, elevation) should live in code or a shared token file, not only in Figma.
- **Naming** — Use stable token names; avoid embedding hex in component names.
- **Screenshots & states** — Document default, loading, error, empty, and “connected / active” states for critical flows.
- **Accessibility checklist** — Contrast, focus order, screen reader labels for non-text controls, and configurable text scaling.

---

## 11. Review checklist (before ship)

- [ ] Primary task completable in minimal steps from cold start  
- [ ] Typography and spacing match the agreed scale  
- [ ] Colors map to tokens; contrast checked on real devices  
- [ ] Touch targets and hit slop verified  
- [ ] Settings / advanced options discoverable but not noisy  
- [ ] Copy reviewed for clarity and localization headroom  
- [ ] Motion respects reduced-motion settings  
- [ ] Platform-specific entry points (TV launcher, notifications) covered  

---

## 12. Evolution

- Version this document when **breaking** visual or behavioral conventions change.
- Deprecate tokens instead of silently redefining them; migrate screens in batches to avoid a fragmented UI.

---

*This guide is intentionally general. Product-specific flows (e.g., VPN lifecycle, server profiles) should extend it with appendices or linked specs rather than bloating the core document.*
