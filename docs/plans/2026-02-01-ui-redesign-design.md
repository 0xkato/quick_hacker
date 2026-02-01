# UI Redesign: Futuristic-Retro Terminal Aesthetic

**Date:** 2026-02-01
**Status:** Ready for Implementation

## Overview

Redesign the security auditing tool UI to have a futuristic-retro terminal aesthetic. Clean, minimal, high-contrast dark theme with subtle CRT touches. The goal is to make it pleasant to read while maintaining a professional security tool identity.

**Key Principles:**
- Dark theme with warm undertones (blue-black base)
- Monospace typography throughout (JetBrains Mono)
- High contrast for readability, not flashiness
- Severity indicators that stand out at a glance
- Subtle retro touches (scanlines, glow effects) without being gimmicky

## Color System

### Base Theme (Futuristic Dark with Warm Undertones)

```css
--bg-primary:    #0a0c10;   /* Deep blue-black */
--bg-secondary:  #12151c;   /* Panels, cards */
--bg-tertiary:   #1a1e28;   /* Elevated elements */
--border:        #2a3040;   /* Subtle, cool gray */
```

### Text

```css
--text-primary:   #e4e6eb;  /* Off-white */
--text-secondary: #8892a0;  /* Muted blue-gray */
--text-disabled:  #4a5568;  /* Dim */
```

### Severity (5 levels - danger indication)

```css
--sev-critical: #ff5f5f;  /* Soft coral red */
--sev-high:     #f0b429;  /* Warm amber */
--sev-medium:   #f59e0b;  /* Orange */
--sev-low:      #60a5fa;  /* Calm blue */
--sev-info:     #94a3b8;  /* Slate */
```

### Validation Status (4 states - triage flow)

```css
--status-confirmed:   #4ade80;  /* Green */
--status-needs-review:#fbbf24;  /* Yellow */
--status-rejected:    #f87171;  /* Red */
--status-unprocessed: #e4e6eb;  /* White/off-white */
```

### Diagram Node Colors

```css
--node-finding:  #ff5f5f;  /* Red - security finding */
--node-sink:     #fbbf24;  /* Yellow - dangerous sink */
--node-touched:  #60a5fa;  /* Blue - touched/entry point */
--node-normal:   #4ade80;  /* Green - normal node */
```

## Typography

### Font Stack

```css
font-family: 'JetBrains Mono', 'Fira Code', 'SF Mono', monospace;
```

### Type Scale

| Element       | Size     | Weight | Notes                          |
|---------------|----------|--------|--------------------------------|
| Heading 1     | 1.5rem   | 600    | letter-spacing: -0.02em        |
| Heading 2     | 1.25rem  | 600    |                                |
| Heading 3     | 1rem     | 600    |                                |
| Body          | 0.875rem | 400    |                                |
| Small/Labels  | 0.75rem  | 500    | uppercase, letter-spacing: 0.1em |
| Code/Data     | 0.8125rem| 400    |                                |

### Terminal Aesthetic

- Uppercase labels with `letter-spacing: 0.1em`
- `>` prefix on panel headers (e.g., `> FINDINGS`)
- Cursor blink animation on active inputs
- Subtle text-shadow glow on critical/high severity text

## Component Specifications

### Finding Cards

**Structure (in order):**
1. Title (primary text, weight 600)
2. Severity badge + Validation status badge
3. Location (file:line, secondary text)
4. Description (all context - code refs, function chain, etc.)

**Styling:**
- 4px left border in severity color
- Severity badge: full background color, subtle glow, icon + text (e.g., "CRITICAL")
- Critical/High get subtle pulse animation on hover
- Validation status: pill shape with dot prefix (e.g., "CONFIRMED", "NEEDS REVIEW")

**Severity Badges:**
```css
.severity-badge {
  padding: 0.375rem 0.75rem;
  font-size: 0.75rem;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.severity-badge.critical {
  background: var(--sev-critical);
  color: #0a0c10;
  box-shadow: 0 0 12px rgba(255, 95, 95, 0.4);
}
/* Similar for high, medium, low, info */
```

**Validation Status Badges:**
```css
.status-confirmed   { color: var(--status-confirmed); }
.status-needs-review{ color: var(--status-needs-review); }
.status-rejected    { color: var(--status-rejected); }
.status-unprocessed { color: var(--status-unprocessed); border: 1px solid; }
```

### Panel Styling

**Headers:**
```
> FINDINGS [12]
```
- Uppercase, monospace
- `>` prefix
- Count in brackets

**Borders:**
- 1px solid `var(--border)` default
- Accent color border for active/focused panels
- Subtle rounded corners (4px)

### Flow Diagram Nodes

**Node Structure:**
- Rounded rectangle with 1px border
- Border color indicates node type (finding/sink/normal)
- Subtle glow on finding and sink nodes
- Monospace text

**Colors:**
- Finding: Red border + glow (`#ff5f5f`)
- Dangerous Sink: Yellow border + glow (`#fbbf24`)
- Touched/Entry: Blue accent (`#60a5fa`)
- Normal: Muted or green (`#4ade80`)

**Edges:**
- Default: `#2a3040`
- Active/Animated: Accent blue with dash animation

### Activity Bar & Navigation

**Activity Bar (48px wide):**
- Lucide icons (Folder, Bug, Search, Network, Brain, Settings)
- Active: accent color + left border indicator
- Inactive: muted color (`var(--text-secondary)`)
- Hover: subtle glow

**Sidebar:**
- Panel headers: uppercase with `>` prefix
- File tree: standard expand/collapse arrows
- Files with findings: colored indicator + count badge

### Terminal/Retro Effects

**Scanlines (subtle):**
```css
.scanlines::after {
  content: '';
  position: fixed;
  inset: 0;
  pointer-events: none;
  background: repeating-linear-gradient(
    0deg,
    transparent,
    transparent 2px,
    rgba(0, 0, 0, 0.03) 2px,
    rgba(0, 0, 0, 0.03) 4px
  );
}
```

**CRT Glow:**
```css
.glow-critical { text-shadow: 0 0 10px rgba(255, 95, 95, 0.4); }
.glow-success  { text-shadow: 0 0 10px rgba(74, 222, 128, 0.3); }
.glow-accent   { text-shadow: 0 0 10px rgba(96, 165, 250, 0.3); }
```

**Background Texture:**
- Subtle noise overlay at 0.01-0.02 opacity

## Files to Modify

| File | Changes |
|------|---------|
| `frontend/tailwind.config.ts` | New color palette, font config |
| `frontend/app/globals.css` | Typography, effects, component styles |
| `frontend/components/FindingsPanel/FindingsList.tsx` | Card structure, badge styling |
| `frontend/components/ValidationBadge/ValidationBadge.tsx` | New status styling |
| `frontend/components/ValidationBadge/ValidationBadge.css` | Status colors |
| `frontend/components/FlowVisualization/FlowVisualization.tsx` | Node styling |
| `frontend/components/FlowVisualization/structuredTraceRisk.js` | Node colors |
| `frontend/app/page.tsx` | Layout class updates |
| Various components | Font/color class updates |

## What Stays the Same

- All functionality and features
- All data and content displayed
- Component structure and logic
- Diagram semantics and node types
- Storage and backend

## Implementation Notes

1. Start with `tailwind.config.ts` and `globals.css` to establish the design system
2. Update components incrementally, testing as we go
3. Keep existing class names where possible, just update the values
4. Add JetBrains Mono font via Google Fonts or local files
5. Scanlines and noise effects should be toggleable for accessibility
