# Findings Drawer UI Design

**Date:** 2026-01-17
**Status:** Approved
**Scope:** Visual presentation improvement - no new features

## Problem

The current findings display is cramped in a 256px sidebar, making it difficult to read detailed vulnerability information including code snippets, attack scenarios, proof checklists, and triage reasoning.

## Solution

Create an expandable overlay drawer that displays finding details in a comfortable 700px panel, while keeping the sidebar available for quick navigation between findings.

## Component Architecture

### New Component
- **`FindingDrawer.tsx`** - Overlay drawer component that displays a single finding's full details

### Modified Components
- **`FindingsList.tsx`** - Update click handler to open drawer instead of only navigating to file
- **`page.tsx`** - Add state management for drawer (selected finding, open/closed state)

### State Management

```typescript
// In page.tsx
const [selectedFindingForDrawer, setSelectedFindingForDrawer] = useState<Finding | null>(null);

// Pass to FindingsList
<FindingsList
  findings={filteredFindings}
  onFindingClick={(finding) => setSelectedFindingForDrawer(finding)}
/>

// Render drawer at page level (sibling to main layout)
{selectedFindingForDrawer && (
  <FindingDrawer
    finding={selectedFindingForDrawer}
    onClose={() => setSelectedFindingForDrawer(null)}
  />
)}
```

## Drawer Layout

### Dimensions
- **Width:** 700px (fixed)
- **Height:** 100vh (full screen height)
- **Position:** Fixed, right: 0
- **Background overlay:** rgba(0, 0, 0, 0.5)

### Structure

```
┌─────────────────────────────────────────┐
│ [X Close]                    Finding #1 │ ← Header (fixed, 60px)
│ ─────────────────────────────────────── │
│                                         │
│ [Disposition Badge] [Severity Badge]    │ ← Badges
│                                         │
│ SQL Injection in User Login            │ ← Title
│ src/auth/login.py:45                   │ ← File path
│                                         │
│ ─────────────────────────────────────── │
│                                         │
│ VULNERABILITY TYPE                      │ ← Scrollable
│ SQL Injection                           │   content
│                                         │
│ DESCRIPTION                             │
│ [Description text...]                   │
│                                         │
│ CODE                                    │
│ [Code snippet with highlighting]        │
│                                         │
│ ATTACK SCENARIO                         │
│ [Attack scenario text...]               │
│                                         │
│ RECOMMENDED FIX                         │
│ [Fix recommendations...]                │
│                                         │
│ CONFIDENCE                              │
│ [Progress bar] 85%                      │
│                                         │
│ TRIAGE REASONING                        │
│ • [Reason 1]                            │
│ • [Reason 2]                            │
│                                         │
│ PROOF CHECKLIST                         │
│ [ProofChecklistView component]          │
│                                         │
│ CLASSIFICATION/EXPLOIT CONFIDENCE       │
│ [Progress bars if present]              │
│                                         │
└─────────────────────────────────────────┘
```

### Content Styling

Reuse all existing section rendering from `FindingCard` expanded view (lines 196-320 in FindingsList.tsx), but with improved spacing:

- **Padding:** px-6 py-4 (vs current px-3 py-2)
- **Section spacing:** space-y-6 (vs current space-y-3)
- **All styling:** Keep existing VSCode theme colors, typography, badges, progress bars

## Animations and Interactions

### Entrance/Exit Animation

**Drawer panel:**
```css
Initial: transform: translateX(100%), opacity: 0
Open: transform: translateX(0), opacity: 1
Transition: 300ms ease-out
```

**Background overlay:**
```css
Initial: opacity: 0
Open: opacity: 1
Transition: 200ms ease-out
```

### User Interactions

| Action | Behavior |
|--------|----------|
| Click finding card in sidebar | Opens drawer with that finding |
| Click X button (top-right) | Closes drawer |
| Click background overlay | Closes drawer |
| Press ESC key | Closes drawer |
| Click "Go to file" button | Navigates to file/line AND closes drawer |

### Visual Details

- **Shadow:** shadow-2xl on drawer panel
- **Z-index layering:**
  - Main content: z-index: 1
  - Background overlay: z-index: 50
  - Drawer panel: z-index: 51
- **Focus trap:** User cannot tab to elements behind drawer
- **Scroll lock:** Body scroll disabled when drawer is open
- **Hover states:** Close button shows background highlight on hover

## Implementation Notes

### Reuse Existing Code
- Copy section rendering logic from `FindingCard` expanded view
- Reuse `ProofChecklistView` component as-is
- Keep all existing badge colors, severity icons, and styling
- No changes to data fetching or API calls

### Files to Modify
1. `frontend/components/FindingsPanel/FindingDrawer.tsx` (new)
2. `frontend/components/FindingsPanel/FindingsList.tsx` (update click handler)
3. `frontend/app/page.tsx` (add drawer state and rendering)

### No New Features
- No changes to triage logic
- No changes to filtering
- No changes to data structure
- No new API endpoints
- Pure visual/layout improvement only
